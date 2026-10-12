"""SandboxManager: the control plane's core. Runs as host root (it is part of the TCB, DESIGN.md §5.5).

Terminology, kept deliberately precise (DESIGN.md §4):
  * create_environment(image): writable btrfs snapshot of a read-only base
    image, plus fresh namespaces, a fresh cgroup, and a fresh PID 1.
  * fork(sandbox): ENVIRONMENT fork. Freeze the parent's cgroup, snapshot
    the parent's subvolume, thaw, then give the child fresh namespaces, a
    fresh cgroup, and a fresh process tree. Parent process memory is NOT
    copied. That would be CRIU-based process fork, a separate stretch goal.

Every sandbox has a state file that is written before any resource is
created. After a crash, reconcile() can then find and remove anything
half-built.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time

from . import btrfs, cgroups
from .config import Config

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(PKG_DIR)


class SandboxError(Exception):
    pass


def _ms(a_ns: int, b_ns: int) -> float:
    return round((b_ns - a_ns) / 1e6, 3)


def _proc_starttime(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
    except OSError:
        return None
    # comm may contain spaces/parens, so split after the last ')'.
    return int(data.rsplit(")", 1)[1].split()[19])


def _proc_cgroup(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            for line in f:
                if line.startswith("0::"):
                    return line[3:].strip()
    except OSError:
        return None
    return None


class SandboxManager:
    def __init__(self, config: Config | None = None):
        self.cfg = config or Config()
        self.cg = cgroups.CgroupTree(self.cfg.cgroup_root)
        self._lock = threading.RLock()  # protects _sandboxes, slots, state files
        self._sb_locks: dict[str, threading.RLock] = {}
        self._sandboxes: dict[str, dict] = {}
        self._pidfds: dict[str, int] = {}
        self._zygote: subprocess.Popen | None = None
        self._zsock: socket.socket | None = None
        self._zlock = threading.Lock()
        self.volume_info: dict = {}
        self.network = None  # set in start() when cfg.network

    # ------------------------------------------------------------------ paths

    @property
    def state_files(self) -> str:
        return os.path.join(self.cfg.state_dir, "state")

    def _state_path(self, sid: str) -> str:
        return os.path.join(self.state_files, sid + ".json")

    def subvol(self, sid: str) -> str:
        return os.path.join(self.cfg.volume, "sandboxes", sid)

    def image_subvol(self, name: str) -> str:
        if not name or "/" in name or name.startswith("."):
            raise SandboxError(f"bad image name {name!r}")
        return os.path.join(self.cfg.volume, "images", name)

    # ---------------------------------------------------------------- startup

    def start(self) -> dict:
        if os.geteuid() != 0:
            raise SandboxError("the control plane must run as root")
        for d in (self.cfg.state_dir, self.state_files, self.cfg.run_dir, os.path.join(self.cfg.run_dir, "stage")):
            os.makedirs(d, mode=0o700, exist_ok=True)
            os.chmod(d, 0o700)
        self.volume_info = btrfs.ensure_volume(self.cfg.volume, self.cfg.image_path, self.cfg.btrfs_device, self.cfg.btrfs_size_gb)
        self.cg.ensure()
        init_path = self._build_init()
        self._start_zygote(init_path)
        if self.cfg.network:
            from .network import EgressNetwork

            self.network = EgressNetwork(self.cfg)
            self.network.start()
        report = self.reconcile()
        return {"volume": self.volume_info, "reconcile": report}

    def _build_init(self) -> str:
        src = os.path.join(PKG_DIR, "init.c")
        with open(src, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()[:16]
        bindir = os.path.join(self.cfg.state_dir, "bin")
        os.makedirs(bindir, mode=0o700, exist_ok=True)
        out = os.path.join(bindir, f"sandbox-init-{digest}")
        if not os.path.exists(out):
            subprocess.run(["gcc", "-static", "-Os", "-o", out + ".tmp", src], check=True)
            os.rename(out + ".tmp", out)
        return out

    def _start_zygote(self, init_path: str) -> None:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PYTHONPATH": REPO_ROOT, "PYTHONDONTWRITEBYTECODE": "1"}
        self._zygote = subprocess.Popen(
            [sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[3]); from control_plane import zygote; zygote.main()",
             str(child.fileno()), init_path, REPO_ROOT],
            pass_fds=[child.fileno()],
            env=env,
            cwd="/",
        )
        child.close()
        self._zsock = parent

    def close(self) -> None:
        """Stop the zygote. Running sandboxes keep running (reconcile() re-adopts them)."""
        if self._zsock:
            self._zsock.close()
            self._zsock = None
        if self._zygote:
            try:
                self._zygote.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._zygote.kill()
                self._zygote.wait()
            self._zygote = None
        for fd in self._pidfds.values():
            os.close(fd)
        self._pidfds.clear()
        if self.network:
            self.network.close()

    # ------------------------------------------------------------ zygote I/O

    def _spawn(self, op: str, spec: dict, extra_fds: list[int] = ()) -> int:
        """Ask the zygote to fork a helper. Returns the read end of its result pipe."""
        r, w = os.pipe()
        try:
            with self._zlock:
                if not self._zsock:
                    raise SandboxError("control plane not started")
                socket.send_fds(self._zsock, [json.dumps({"op": op, "spec": spec}).encode()], [w, *extra_fds])
        finally:
            os.close(w)
        return r

    @staticmethod
    def _events(r: int, timeout: float):
        """Yield JSON events from a helper's result pipe until EOF or timeout."""
        deadline = time.monotonic() + timeout
        buf = b""
        sel = selectors.DefaultSelector()
        sel.register(r, selectors.EVENT_READ)
        try:
            while True:
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    yield json.loads(line)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                if not sel.select(remaining):
                    continue
                chunk = os.read(r, 65536)
                if not chunk:
                    return
                buf += chunk
        finally:
            sel.close()

    # ---------------------------------------------------------------- state

    def _sb_lock(self, sid: str) -> threading.RLock:
        with self._lock:
            return self._sb_locks.setdefault(sid, threading.RLock())

    def _save(self, rec: dict) -> None:
        path = self._state_path(rec["id"])
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(rec, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp, path)

    def _load_all(self) -> dict[str, dict]:
        out = {}
        for name in os.listdir(self.state_files):
            if name.endswith(".json"):
                try:
                    with open(os.path.join(self.state_files, name)) as f:
                        rec = json.load(f)
                    out[rec["id"]] = rec
                except (OSError, ValueError, KeyError):
                    # Corrupt state file (e.g. crash mid-write is prevented by rename, but be safe).
                    out[name[:-5]] = {"id": name[:-5], "state": "corrupt"}
            elif name.endswith(".json.tmp"):
                os.unlink(os.path.join(self.state_files, name))
        return out

    def _alloc_slot(self) -> int:
        used = {r.get("slot") for r in self._sandboxes.values()}
        for s in range(self.cfg.max_sandboxes):
            if s not in used:
                return s
        raise SandboxError("no free sandbox slots")

    def _new_record(self, kind: str, **kw) -> dict:
        with self._lock:
            sid = "sb-" + secrets.token_hex(6)
            slot = self._alloc_slot()
            rec = {
                "id": sid,
                "state": "creating",
                "kind": kind,
                "slot": slot,
                "uid_base": self.cfg.uid_base_start + slot * self.cfg.uid_size,
                "created_at": time.time(),
                **kw,
            }
            self._sandboxes[sid] = rec
            self._save(rec)
            return rec

    def _get(self, sid: str) -> dict:
        with self._lock:
            rec = self._sandboxes.get(sid)
        if not rec or rec["state"] not in ("running",):
            raise SandboxError(f"no running sandbox {sid!r}")
        return rec

    # ------------------------------------------------------------- images

    def import_image(self, name: str, tar_path: str) -> dict:
        """Import a rootfs tarball (e.g. `docker export`) as a read-only base subvolume.

        File ownership is kept numerically as-is (uid 0..65535 on disk). Each
        sandbox sees it through its own idmapped mount.
        """
        dst = self.image_subvol(name)
        if os.path.exists(dst):
            raise SandboxError(f"image {name!r} already exists")
        tmp = dst + ".importing"
        btrfs.delete_subvolume(tmp)
        btrfs.create_subvolume(tmp)
        try:
            subprocess.run(["tar", "--numeric-owner", "--xattrs", "--xattrs-include=*", "-xpf", tar_path, "-C", tmp], check=True)
            btrfs.snapshot(tmp, dst, readonly=True)
        finally:
            btrfs.delete_subvolume(tmp)
        return {"image": name, "subvol": dst}

    def list_images(self) -> list[str]:
        d = os.path.join(self.cfg.volume, "images")
        return sorted(n for n in os.listdir(d) if not n.endswith(".importing"))

    def delete_image(self, name: str) -> None:
        btrfs.delete_subvolume(self.image_subvol(name))

    # ------------------------------------------------------------- lifecycle

    def create_environment(self, image: str, limits: dict | None = None, fault: dict | None = None) -> dict:
        t0 = time.monotonic_ns()
        src = self.image_subvol(image)
        if not btrfs.is_subvolume(src):
            raise SandboxError(f"no such image {image!r}")
        rec = self._new_record("create", image=image, limits={**self.cfg.default_limits, **(limits or {})})
        sid = rec["id"]
        timings = {}
        try:
            with self._sb_lock(sid):
                t = time.monotonic_ns()
                btrfs.snapshot(src, self.subvol(sid))
                timings["snapshot_ms"] = _ms(t, time.monotonic_ns())
                self._bring_up(rec, timings, fault)
        except BaseException:
            self._teardown(sid)
            raise
        timings["total_ms"] = _ms(t0, time.monotonic_ns())
        rec["timings"] = timings
        return {"id": sid, "timings": timings}

    def fork(self, parent_id: str, limits: dict | None = None, fault: dict | None = None) -> dict:
        """Environment fork (NOT process-memory fork). See module docstring."""
        t0 = time.monotonic_ns()
        parent = self._get(parent_id)
        rec = self._new_record("fork", parent=parent_id, image=parent.get("image"),
                               limits={**parent["limits"], **(limits or {})}, forking_parent=parent_id)
        sid = rec["id"]
        timings = {}
        try:
            with self._sb_lock(parent_id):
                self._get(parent_id)  # still running?
                t = time.monotonic_ns()
                self.cg.freeze(parent_id)
                t_frozen = time.monotonic_ns()
                try:
                    self._maybe_fault(fault, "fork_while_frozen")
                    btrfs.snapshot(self.subvol(parent_id), self.subvol(sid))
                    t_snap = time.monotonic_ns()
                finally:
                    self.cg.thaw(parent_id)
                t_thawed = time.monotonic_ns()
                timings["freeze_ms"] = _ms(t, t_frozen)
                timings["snapshot_ms"] = _ms(t_frozen, t_snap)
                timings["thaw_ms"] = _ms(t_snap, t_thawed)
                timings["parent_frozen_window_ms"] = _ms(t, t_thawed)
            rec.pop("forking_parent", None)
            with self._sb_lock(sid):
                self._bring_up(rec, timings, fault)
        except BaseException:
            self._teardown(sid)
            raise
        timings["total_ms"] = _ms(t0, time.monotonic_ns())
        rec["timings"] = timings
        return {"id": sid, "timings": timings}

    def _maybe_fault(self, fault, point):
        if fault and self.cfg.allow_faults and fault.get("point") == point:
            if fault.get("action") == "hang":
                time.sleep(fault.get("seconds", 3600))
            elif fault.get("action") == "raise":
                raise SandboxError(f"injected fault at {point}")

    def _bring_up(self, rec: dict, timings: dict, fault: dict | None) -> None:
        sid = rec["id"]
        t = time.monotonic_ns()
        cgpath = self.cg.create(sid, rec["limits"])
        timings["cgroup_ms"] = _ms(t, time.monotonic_ns())
        stage = os.path.join(self.cfg.run_dir, "stage", sid)
        os.mkdir(stage, 0o700)
        try:
            spec = {
                "subvol": self.subvol(sid),
                "uid_base": rec["uid_base"],
                "uid_size": self.cfg.uid_size,
                "cgroup": cgpath,
                "hostname": sid,
                "stage_dir": stage,
            }
            if self.cfg.seccomp:
                from . import seccomp

                spec["seccomp"] = seccomp.default_policy()
            if fault and self.cfg.allow_faults:
                spec["fault"] = fault
            t_launch = time.monotonic_ns()
            r = self._spawn("launch", spec)
            init_pid, lt, helper = None, None, None
            try:
                for ev in self._events(r, timeout=(fault or {}).get("timeout", 30)):
                    if ev["event"] == "started":
                        helper = ev["pid"]
                        rec["launcher_pid"] = helper
                    elif ev["event"] == "ready":
                        init_pid, lt = ev["init_pid"], ev["t"]
                    elif ev["event"] == "error":
                        raise SandboxError(f"launch failed: {ev['msg']}")
            except TimeoutError:
                if helper:
                    try:
                        os.killpg(helper, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                raise SandboxError("launch timed out")
            finally:
                os.close(r)
            if init_pid is None:
                raise SandboxError("launcher died before the sandbox was ready")
        finally:
            try:
                os.rmdir(stage)
            except OSError:
                pass
        t_ready = time.monotonic_ns()
        timings["launch_ms"] = _ms(t_launch, t_ready)
        timings["launch_breakdown_ms"] = {
            "zygote_fork_to_launcher": _ms(t_launch, lt["launcher_start"]),
            "launcher_setup_to_userns": _ms(lt["launcher_start"], lt["userns_created"]),
            "idmap_write": _ms(lt["userns_created"], lt["idmap_written"]),
            "idmapped_rootfs_mount": _ms(lt["idmap_written"], lt["rootfs_idmapped"]),
            "namespaces_create": _ms(lt["c1_maps_seen"], lt["namespaces_created"]),
            "pivot_mounts_exec_init": _ms(lt["namespaces_created"], lt["init_exec_done"]),
        }
        pidfd = os.pidfd_open(init_pid)
        # Guard against PID reuse: the pid we hold a pidfd for must be in our cgroup.
        if _proc_cgroup(init_pid) != "/" + os.path.relpath(cgpath, cgroups.CGROUP_FS):
            os.close(pidfd)
            raise SandboxError(f"init pid {init_pid} is not in the sandbox cgroup")
        self._pidfds[sid] = pidfd
        rec.update(init_pid=init_pid, init_starttime=_proc_starttime(init_pid), cgroup=cgpath)
        rec["userns_inode"] = os.stat(f"/proc/{init_pid}/ns/user").st_ino
        rec["netns_inode"] = os.stat(f"/proc/{init_pid}/ns/net").st_ino
        if self.network:
            t = time.monotonic_ns()
            rec["net"] = self.network.attach(sid, rec["slot"], init_pid)
            timings["network_ms"] = _ms(t, time.monotonic_ns())
        rec["state"] = "running"
        self._save(rec)

    def exec(self, sid: str, cmd: list[str], env: dict | None = None, cwd: str = "/", timeout: float = 60.0,
             stdin: bytes | None = None, fault: dict | None = None) -> dict:
        if not cmd or not all(isinstance(c, str) for c in cmd):
            raise SandboxError("cmd must be a non-empty list of strings")
        rec = self._get(sid)
        t0 = time.monotonic_ns()
        pidfd = self._pidfds.get(sid)
        if pidfd is None:
            raise SandboxError(f"sandbox {sid} has no live init")
        spec = {"cgroup": rec["cgroup"], "cmd": cmd, "cwd": cwd}
        if env is not None:
            spec["env"] = env
        elif rec.get("net"):
            spec["env"] = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", **rec["net"]["env"]}
        if self.cfg.seccomp:
            from . import seccomp

            spec["seccomp"] = seccomp.default_policy()
        if fault and self.cfg.allow_faults:
            spec["fault"] = fault
        in_r, in_w = os.pipe()
        out_r, out_w = os.pipe()
        err_r, err_w = os.pipe()
        try:
            r = self._spawn("exec", spec, [pidfd, in_r, out_w, err_w])
        finally:
            for fd in (in_r, out_w, err_w):
                os.close(fd)
        if stdin:
            threading.Thread(target=self._feed, args=(in_w, stdin), daemon=True).start()
        else:
            os.close(in_w)
        return self._collect(r, out_r, err_r, timeout, t0)

    @staticmethod
    def _feed(fd, data):
        try:
            os.write(fd, data)
        except OSError:
            pass
        finally:
            os.close(fd)

    def _collect(self, r, out_r, err_r, timeout, t0) -> dict:
        cap = self.cfg.exec_output_cap
        bufs = {out_r: bytearray(), err_r: bytearray()}
        truncated = {out_r: False, err_r: False}
        sel = selectors.DefaultSelector()
        for fd in (r, out_r, err_r):
            sel.register(fd, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        helper, child, code, err, timed_out = None, None, None, None, False
        ev_buf = b""
        exit_seen_at = None
        try:
            while sel.get_map():
                now = time.monotonic()
                if exit_seen_at is not None and now - exit_seen_at > 0.2:
                    break  # background processes may hold stdout open forever
                if now > deadline:
                    timed_out = True
                    for pid in (child, helper):
                        if pid:
                            try:
                                os.killpg(pid, signal.SIGKILL) if pid == child else os.kill(pid, signal.SIGKILL)
                            except (ProcessLookupError, PermissionError):
                                pass
                    break
                for key, _ in sel.select(0.05):
                    fd = key.fd
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        sel.unregister(fd)
                        if fd == r and code is None and exit_seen_at is None:
                            exit_seen_at = time.monotonic()
                        continue
                    if fd == r:
                        ev_buf += chunk
                        while b"\n" in ev_buf:
                            line, ev_buf = ev_buf.split(b"\n", 1)
                            ev = json.loads(line)
                            if ev["event"] == "started":
                                helper = ev["pid"]
                            elif ev["event"] == "forked":
                                child = ev["pid"]
                            elif ev["event"] == "exit":
                                code = ev["code"]
                                exit_seen_at = time.monotonic()
                            elif ev["event"] == "error":
                                err = ev["msg"]
                    else:
                        b = bufs[fd]
                        room = cap - len(b)
                        if room > 0:
                            b += chunk[:room]
                        if len(chunk) > room:
                            truncated[fd] = True
        finally:
            sel.close()
            for fd in (r, out_r, err_r):
                os.close(fd)
        if err and code is None:
            raise SandboxError(f"exec failed: {err}")
        return {
            "exit_code": code,
            "stdout": bytes(bufs[out_r]),
            "stderr": bytes(bufs[err_r]),
            "timed_out": timed_out,
            "truncated": truncated[out_r] or truncated[err_r],
            # No exit status and no timeout: the helper itself was killed, e.g.
            # because the sandbox was destroyed (cgroup.kill) mid-exec.
            "killed": code is None and not timed_out,
            "elapsed_ms": _ms(t0, time.monotonic_ns()),
        }

    def destroy(self, sid: str) -> dict:
        with self._lock:
            if sid not in self._sandboxes:
                raise SandboxError(f"no sandbox {sid!r}")
        t0 = time.monotonic_ns()
        with self._sb_lock(sid):
            self._teardown(sid)
        return {"id": sid, "total_ms": _ms(t0, time.monotonic_ns())}

    def _teardown(self, sid: str) -> None:
        """Remove every resource a sandbox might own. Idempotent; safe on half-built sandboxes."""
        with self._lock:
            rec = self._sandboxes.get(sid) or {"id": sid}
            rec["state"] = "destroying"
            if os.path.exists(self._state_path(sid)) or sid in self._sandboxes:
                self._save(rec)
        errors = []
        # A crash mid-fork can leave a parent frozen; never leave it that way.
        parent = rec.get("forking_parent")
        if parent and self.cg.exists(parent):
            try:
                self.cg.thaw(parent)
            except OSError as e:
                errors.append(f"thaw parent {parent}: {e}")
        try:
            self.cg.remove(sid)  # cgroup.kill: every process, including a launcher stuck mid-setup
        except (OSError, TimeoutError) as e:
            errors.append(f"cgroup: {e}")
        lp = rec.get("launcher_pid")
        if lp:
            # The launcher itself is not in the sandbox cgroup (only C1 onward are).
            try:
                os.killpg(lp, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        fd = self._pidfds.pop(sid, None)
        if fd is not None:
            os.close(fd)
        if self.network:
            try:
                self.network.detach(sid, rec.get("slot"))
            except Exception as e:  # noqa: BLE001
                errors.append(f"network: {e}")
        deadline = time.monotonic() + 10
        while True:
            try:
                btrfs.delete_subvolume(self.subvol(sid))
                break
            except OSError as e:
                # The dying sandbox's mount namespace can briefly keep the subvolume busy.
                if e.errno != errno.EBUSY or time.monotonic() > deadline:
                    errors.append(f"subvolume: {e}")
                    break
                time.sleep(0.01)
        stage = os.path.join(self.cfg.run_dir, "stage", sid)
        if os.path.isdir(stage):
            try:
                os.rmdir(stage)
            except OSError as e:
                errors.append(f"stage dir: {e}")
        if errors:
            rec["state"] = "destroy_failed"
            rec["errors"] = errors
            self._save(rec)
            raise SandboxError(f"teardown of {sid} incomplete: {errors}")
        with self._lock:
            self._sandboxes.pop(sid, None)
            self._sb_locks.pop(sid, None)
            try:
                os.unlink(self._state_path(sid))
            except FileNotFoundError:
                pass

    # ---------------------------------------------------------------- queries

    def list_sandboxes(self) -> list[str]:
        with self._lock:
            return sorted(s for s, r in self._sandboxes.items() if r["state"] == "running")

    def snapshot_info(self, sid: str) -> dict:
        rec = self._get(sid)
        keys = ("id", "kind", "image", "parent", "created_at", "slot", "uid_base", "init_pid", "limits", "timings", "net")
        info = {k: rec.get(k) for k in keys}
        info["subvolume"] = self.subvol(sid)
        info["cgroup_stat"] = self.cg.stat(sid)
        return info

    # --------------------------------------------------------- crash recovery

    def reconcile(self) -> dict:
        """Bring host state in line with the state files after a crash or restart.

        * running sandboxes whose PID 1 is still alive (same pid, same
          start time, still in the sandbox cgroup) are re-adopted
        * everything else with a state file is torn down
        * cgroups and subvolumes with no state file at all are removed
        * no cgroup is left frozen
        """
        report = {"adopted": [], "removed": [], "orphan_cgroups": [], "orphan_subvolumes": [], "thawed": [], "errors": []}
        recs = self._load_all()
        with self._lock:
            for sid, rec in recs.items():
                if sid in self._sandboxes:
                    continue
                self._sandboxes[sid] = rec
        for sid, rec in recs.items():
            if sid in self._pidfds:
                continue
            pid = rec.get("init_pid")
            alive = (
                rec.get("state") == "running"
                and pid
                and _proc_starttime(pid) == rec.get("init_starttime")
                and self.cg.exists(sid)
                and pid in self.cg.procs(sid)
            )
            if alive:
                self._pidfds[sid] = os.pidfd_open(pid)
                if self.cg.is_frozen(sid):
                    self.cg.thaw(sid)
                    report["thawed"].append(sid)
                if self.network and rec.get("net"):
                    self.network.readopt(sid, rec)
                report["adopted"].append(sid)
            else:
                try:
                    self._teardown(sid)
                    report["removed"].append(sid)
                except SandboxError as e:
                    report["errors"].append(str(e))
        known = set(self._sandboxes)
        for sid in self.cg.list():
            if sid not in known:
                try:
                    self.cg.remove(sid)
                    report["orphan_cgroups"].append(sid)
                except (OSError, TimeoutError) as e:
                    report["errors"].append(f"cgroup {sid}: {e}")
            elif self.cg.is_frozen(sid) and sid not in report["thawed"]:
                self.cg.thaw(sid)
                report["thawed"].append(sid)
        sbdir = os.path.join(self.cfg.volume, "sandboxes")
        for name in os.listdir(sbdir):
            if name not in known:
                try:
                    btrfs.delete_subvolume(os.path.join(sbdir, name))
                    report["orphan_subvolumes"].append(name)
                except OSError as e:
                    report["errors"].append(f"subvolume {name}: {e}")
        stage_root = os.path.join(self.cfg.run_dir, "stage")
        for name in os.listdir(stage_root):
            if name not in known:
                try:
                    os.rmdir(os.path.join(stage_root, name))
                except OSError:
                    pass
        if self.network:
            report["network"] = self.network.reconcile(known)
        return report

    # ------------------------------------------------------------- auditing

    def audit(self, sid: str, userns_inode: int | None = None) -> list[str]:
        """Everything on the host that still references sandbox `sid`. Empty means fully cleaned up.

        Checks the mount table of EVERY process (not just ours), so a mount
        that survives in some forgotten mount namespace still counts.
        """
        leaks = []
        if self.cg.exists(sid):
            leaks.append(f"cgroup {self.cg.path(sid)} (procs={self.cg.procs(sid)})")
        if os.path.lexists(self.subvol(sid)):
            leaks.append(f"subvolume {self.subvol(sid)}")
        if os.path.exists(self._state_path(sid)):
            leaks.append(f"state file {self._state_path(sid)}")
        if os.path.exists(os.path.join(self.cfg.run_dir, "stage", sid)):
            leaks.append("stage dir")
        needle = f"/sandboxes/{sid}"
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/mountinfo") as f:
                    for line in f:
                        if needle in line:
                            leaks.append(f"mount in pid {pid}'s namespace: {line.strip()}")
                            break
                if userns_inode and os.stat(f"/proc/{pid}/ns/user").st_ino == userns_inode:
                    leaks.append(f"process {pid} still in the sandbox user namespace")
            except OSError:
                continue
        if self.network:
            leaks += self.network.audit(sid)
        return leaks
