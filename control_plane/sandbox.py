"""Sandbox lifecycle: create, fork, exec, destroy, and crash recovery.

"fork" here is an ENVIRONMENT fork (DESIGN.md §4): the parent's cgroup is
frozen, its filesystem is snapshotted, the parent is thawed, and the child
gets fresh namespaces, a fresh cgroup and a FRESH process tree. No process
memory is copied. Live process-memory fork (CRIU) is a separate stretch
goal and is not implemented here.

Crash safety: every sandbox has a state file that is written *before* any
resource is acquired and updated as each resource is added. If the control
plane dies at any point, ``reconcile()`` (run on every start) tears down
anything that is not a fully ready sandbox with a live PID 1, plus any
subvolume, cgroup, mount or veth that has no state file at all.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import re
import secrets
import select
import signal
import subprocess
import sys
import threading
import time

from . import cgroup as cgroup_mod
from .config import Config
from .network import Network
from .storage import open_store
from .util import (CommandError, is_mountpoint, ms, pid_alive, proc_start_time, read_json,
                   run, wait_until, write_json_atomic)

ID_RE = re.compile(r"^sbx-[0-9a-f]{12}$")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
NSINIT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nsinit.py")
PROXY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy.py")
PYTHON = sys.executable
MAX_OUTPUT = 8 * 1024 * 1024
HOLDER_READY_TIMEOUT = 15
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class SandboxError(Exception):
    pass


def _crashpoint(name: str) -> None:
    """Fault injection for the crash-cleanup tests (CLAUDE.md rule 4)."""
    if os.environ.get("AGENT_SANDBOX_CRASH_AT") == name:
        os.kill(os.getpid(), signal.SIGKILL)


class Manager:
    def __init__(self, cfg: Config):
        cfg.validate()
        self.cfg = cfg
        for d, mode in ((cfg.run_dir, 0o711), (self._dir("state"), 0o700),
                        (self._dir("mnt"), 0o711), (cfg.store_root, 0o700),
                        (self._store("images"), 0o700), (self._store("image-meta"), 0o700),
                        (self._store("sandboxes"), 0o700)):
            os.makedirs(d, exist_ok=True)
            os.chmod(d, mode)
        # One manager per run_dir: a second one reconciling would tear down
        # sandboxes the first is still creating.
        self._lockf = open(self._dir("lock"), "w")
        try:
            fcntl.flock(self._lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SandboxError(f"another control plane holds {cfg.run_dir}/lock") from None
        try:
            self.store = open_store(cfg.storage, cfg.store_root)
            self.cg = cgroup_mod.open_cgroups(cfg.cgroup_root, cfg.dev_mode)
            self.net = Network(self._netns_name(), cfg.proxy_port) if cfg.network else None
            self.lock = threading.RLock()
            self._procs: dict[str, subprocess.Popen] = {}
            if self.net:
                self.net.setup()
                self.net.setup_proxy_filter(cfg.proxy_uid, cfg.egress_allowlist)
                self._ensure_proxy()
            self.last_reconcile = self.reconcile()
        except BaseException:
            self._lockf.close()
            raise

    # ---- paths ---------------------------------------------------------
    def _dir(self, *p):
        return os.path.join(self.cfg.run_dir, *p)

    def _store(self, *p):
        return os.path.join(self.cfg.store_root, *p)

    def _netns_name(self):
        # Derived from run_dir so independent control planes (e.g. tests)
        # never share an egress netns.
        return "sbx-egress" if self.cfg.run_dir == "/run/agent-sandbox" else \
            "sbx-egress-" + hashlib.sha256(self.cfg.run_dir.encode()).hexdigest()[:6]

    def _state_path(self, sid):
        return self._dir("state", f"{sid}.json")

    def _check_id(self, sid) -> str:
        if not isinstance(sid, str) or not ID_RE.match(sid):
            raise SandboxError(f"invalid sandbox id {sid!r}")
        return sid

    def _load(self, sid) -> dict:
        self._check_id(sid)
        try:
            return read_json(self._state_path(sid))
        except FileNotFoundError:
            raise SandboxError(f"no such sandbox {sid}") from None

    def _save(self, st: dict) -> None:
        write_json_atomic(self._state_path(st["id"]), st)

    def _all_states(self) -> list[dict]:
        out = []
        for f in sorted(os.listdir(self._dir("state"))):
            if f.endswith(".json") and ID_RE.match(f[:-5]):
                try:
                    out.append(read_json(self._dir("state", f)))
                except (OSError, ValueError):
                    out.append({"id": f[:-5], "phase": "corrupt"})
        return out

    def close(self) -> None:
        self._lockf.close()

    # ---- images --------------------------------------------------------
    def import_image(self, name: str, docker_ref: str) -> dict:
        if not IMAGE_RE.match(name or ""):
            raise SandboxError(f"invalid image name {name!r}")
        dst = self._store("images", name)
        if os.path.lexists(dst):
            raise SandboxError(f"image {name} already exists")
        image_id = run(["docker", "image", "inspect", "-f", "{{.Id}}", docker_ref]).stdout.strip()
        cid = run(["docker", "create", docker_ref, "/bin/true"]).stdout.strip()
        try:
            exp = subprocess.Popen(["docker", "export", cid], stdout=subprocess.PIPE)
            try:
                self.store.import_tar(dst, exp.stdout)
            finally:
                exp.stdout.close()
                if exp.wait() != 0:
                    self.store.delete(dst)
                    raise SandboxError("docker export failed")
        finally:
            run(["docker", "rm", "-f", cid], check=False)
        meta = {"name": name, "docker_ref": docker_ref, "docker_image_id": image_id,
                "storage": self.store.name, "imported_at": time.time()}
        write_json_atomic(self._store("image-meta", f"{name}.json"), meta)
        return meta

    def list_images(self) -> list[dict]:
        out = []
        for f in sorted(os.listdir(self._store("image-meta"))):
            if f.endswith(".json"):
                out.append(read_json(self._store("image-meta", f)))
        return out

    # ---- create / fork -------------------------------------------------
    def _new_state(self, **extra) -> dict:
        used = {s.get("slot") for s in self._all_states()}
        slot = next((i for i in range(self.cfg.max_sandboxes) if i not in used), None)
        if slot is None:
            raise SandboxError("sandbox limit reached")
        sid = "sbx-" + secrets.token_hex(6)
        st = {"id": sid, "slot": slot, "phase": "creating", "created_at": time.time(),
              "host_uid_base": self.cfg.uid_base + slot * 65536,
              "subvol": self._store("sandboxes", sid), "storage": self.store.name,
              "cgroup_enforced": self.cg.enforced, "dev_mode": self.cfg.dev_mode,
              "holder_pid": None, "holder_start": None, "net": None, **extra}
        self._save(st)
        return st

    def create_environment(self, image: str) -> dict:
        if not IMAGE_RE.match(image or "") or not os.path.isdir(self._store("images", image)):
            raise SandboxError(f"no such image {image!r}")
        with self.lock:
            t0 = time.monotonic()
            st = self._new_state(image=image, parent_id=None)
            _crashpoint("create:after_state")
            timings = {}
            try:
                t = time.monotonic()
                self.store.snapshot(self._store("images", image), st["subvol"])
                timings["snapshot_ms"] = ms(t, time.monotonic())
                _crashpoint("create:after_snapshot")
                self._start(st, timings)
            except BaseException:
                self._teardown(st)
                raise
            timings["total_ms"] = ms(t0, time.monotonic())
            return {"sandbox_id": st["id"], "timings_ms": timings}

    def fork(self, parent_id: str) -> dict:
        """Environment fork. See module docstring: no process memory is copied."""
        with self.lock:
            parent = self._load(parent_id)
            if parent["phase"] != "ready":
                raise SandboxError(f"sandbox {parent_id} is {parent['phase']}")
            t0 = time.monotonic()
            st = self._new_state(image=parent.get("image"), parent_id=parent_id)
            _crashpoint("fork:after_state")
            timings = {}
            try:
                t = time.monotonic()
                self.cg.freeze(parent_id)
                t_frozen = time.monotonic()
                try:
                    _crashpoint("fork:while_frozen")
                    self.store.snapshot(parent["subvol"], st["subvol"])
                    t_snap = time.monotonic()
                finally:
                    self.cg.thaw(parent_id)
                t_thawed = time.monotonic()
                timings.update(freeze_ms=ms(t, t_frozen), snapshot_ms=ms(t_frozen, t_snap),
                               thaw_ms=ms(t_snap, t_thawed), freeze_window_ms=ms(t, t_thawed),
                               parent_frozen=self.cg.enforced)
                _crashpoint("fork:after_snapshot")
                self._start(st, timings)
            except BaseException:
                self._teardown(st)
                raise
            timings["total_ms"] = ms(t0, time.monotonic())
            return {"sandbox_id": st["id"], "parent_id": parent_id, "timings_ms": timings}

    def _start(self, st: dict, timings: dict) -> None:
        sid, base = st["id"], st["host_uid_base"]
        t = time.monotonic()
        cg = self.cg.create(sid, memory_max=self.cfg.memory_max,
                            memory_swap_max=self.cfg.memory_swap_max,
                            pids_max=self.cfg.pids_max, cpu_max=self.cfg.cpu_max)
        timings["cgroup_ms"] = ms(t, time.monotonic())
        _crashpoint("start:after_cgroup")

        # Idmapped bind mount: on-disk uid N appears as host uid base+N, which
        # the sandbox's user namespace maps back to N. Siblings therefore run
        # as disjoint host uids while sharing one on-disk image.
        t = time.monotonic()
        mnt = self._dir("mnt", sid)
        os.makedirs(mnt, exist_ok=True)
        idmap = f"u:0:{base}:65536 g:0:{base}:65536"
        run(["mount", "--bind", "-o", f"nosuid,nodev,X-mount.idmap={idmap}", st["subvol"], mnt])
        timings["rootfs_mount_ms"] = ms(t, time.monotonic())
        _crashpoint("start:after_mount")

        t = time.monotonic()
        proc = subprocess.Popen(
            [PYTHON, "-I", "-S", NSINIT, "holder", cg or "-", str(base), mnt, sid],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True, close_fds=True)
        self._procs[sid] = proc
        line = _readline(proc.stdout, HOLDER_READY_TIMEOUT)
        proc.stdout.close()
        if not line.startswith("READY "):
            raise SandboxError(f"sandbox init failed: {line.strip() or 'no output'}")
        pid = int(line.split()[1])
        st.update(holder_pid=pid, holder_start=proc_start_time(pid), launcher_pid=proc.pid)
        self._save(st)
        timings["namespaces_and_pivot_ms"] = ms(t, time.monotonic())
        _crashpoint("start:after_holder")

        # The sandbox holds its own copy of the mount; drop the host's.
        run(["umount", "-l", mnt])
        os.rmdir(mnt)

        if self.net:
            t = time.monotonic()
            st["net"] = self.net.attach(st["slot"], pid)
            timings["network_ms"] = ms(t, time.monotonic())
        _crashpoint("start:after_network")
        st["phase"] = "ready"
        self._save(st)

    # ---- exec ----------------------------------------------------------
    def exec(self, sandbox_id: str, cmd: list[str], timeout: float | None = None,
             stdin: str | None = None, env: dict | None = None, cwd: str | None = None) -> dict:
        st = self._load(sandbox_id)
        if st["phase"] != "ready":
            raise SandboxError(f"sandbox {sandbox_id} is {st['phase']}")
        if (not isinstance(cmd, list) or not cmd
                or not all(isinstance(c, str) and "\0" not in c for c in cmd)):
            raise SandboxError("cmd must be a non-empty list of strings")
        senv = {"PATH": DEFAULT_PATH, "HOME": "/root", "HOSTNAME": sandbox_id, "LANG": "C.UTF-8"}
        if st.get("net"):
            for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
                senv[k] = st["net"]["proxy"]
        for k, v in (env or {}).items():
            if not (isinstance(k, str) and isinstance(v, str) and k and "=" not in k
                    and "\0" not in k + v):
                raise SandboxError(f"invalid env entry {k!r}")
            senv[k] = v
        argv = [PYTHON, "-I", "-S", NSINIT, "exec", self.cg.path(sandbox_id) or "-",
                str(st["holder_pid"]), cwd or "/", "--", *cmd]
        t0 = time.monotonic()
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=senv,
                                start_new_session=True, close_fds=True)
        out, err = _capture(proc, stdin, timeout)
        timed_out = out is None
        if timed_out:
            out, err = b"", b""
        return {"exit_code": proc.returncode, "stdout": out.decode("utf-8", "replace"),
                "stderr": err.decode("utf-8", "replace"), "timed_out": timed_out,
                "duration_ms": ms(t0, time.monotonic())}

    # ---- info / list ---------------------------------------------------
    def snapshot_info(self, sandbox_id: str) -> dict:
        st = self._load(sandbox_id)
        info = {k: st.get(k) for k in ("id", "image", "parent_id", "created_at", "phase", "slot",
                                       "host_uid_base", "storage", "cgroup_enforced", "dev_mode", "net")}
        info["subvolume"] = self.store.info(st["subvol"]) if os.path.exists(st["subvol"]) else None
        info["cgroup"] = self.cg.stats(sandbox_id)
        return info

    def list_sandboxes(self) -> list[dict]:
        return [{k: s.get(k) for k in ("id", "image", "parent_id", "phase")} for s in self._all_states()]

    # ---- destroy / reconcile -------------------------------------------
    def destroy(self, sandbox_id: str) -> None:
        with self.lock:
            st = self._load(sandbox_id)
            self._teardown(st)

    def _teardown(self, st: dict) -> None:
        """Release everything a (possibly half-created) sandbox may hold. Idempotent."""
        sid = st["id"]
        st["phase"] = "destroying"
        if os.path.exists(self._state_path(sid)):
            self._save(st)
        # 1. processes: cgroup.kill gets every process in the sandbox; the
        #    pid-based kill covers dev mode and holders that never recorded a pid.
        self.cg.kill_and_remove(sid)
        pids = {st.get("launcher_pid"), st.get("holder_pid")} | set(_find_holders(sid))
        for pid in filter(None, pids):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        proc = self._procs.pop(sid, None)
        if proc:
            proc.wait(timeout=10)
        wait_until(lambda: not any(pid_alive(p, None) for p in filter(None, pids)), 10)
        # 2. network
        if self.net and st.get("slot") is not None:
            self.net.detach(st["slot"])
        # 3. host-side mount
        mnt = self._dir("mnt", sid)
        if is_mountpoint(mnt):
            run(["umount", "-l", mnt])
        if os.path.isdir(mnt):
            os.rmdir(mnt)
        # 4. filesystem. The sandbox's mount namespace dies with its last
        #    process, but give the kernel a moment before calling it busy.
        deadline = time.monotonic() + 10
        while True:
            try:
                self.store.delete(st.get("subvol") or self._store("sandboxes", sid))
                break
            except (CommandError, OSError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        try:
            os.unlink(self._state_path(sid))
        except FileNotFoundError:
            pass

    def reconcile(self) -> dict:
        """Tear down anything left behind by a crash. Returns what was cleaned."""
        report = {"torn_down": [], "orphan_subvols": [], "orphan_cgroups": [],
                  "orphan_mounts": [], "orphan_ifaces": [], "adopted": []}
        with self.lock:
            live_slots = set()
            for st in self._all_states():
                if st.get("phase") == "ready" and pid_alive(st.get("holder_pid"), st.get("holder_start")):
                    # A crash during fork can leave a parent frozen.
                    self.cg.thaw(st["id"])
                    report["adopted"].append(st["id"])
                    live_slots.add(st.get("slot"))
                    continue
                if "subvol" not in st:
                    st["subvol"] = self._store("sandboxes", st["id"])
                self._teardown(st)
                report["torn_down"].append(st["id"])
            known = set(report["adopted"])
            for sid in os.listdir(self._store("sandboxes")):
                if sid not in known:
                    self._teardown({"id": sid, "subvol": self._store("sandboxes", sid)})
                    report["orphan_subvols"].append(sid)
            for sid in self.cg.list():
                if sid not in known:
                    self.cg.kill_and_remove(sid)
                    report["orphan_cgroups"].append(sid)
            for sid in os.listdir(self._dir("mnt")):
                p = self._dir("mnt", sid)
                if is_mountpoint(p):
                    run(["umount", "-l", p])
                os.rmdir(p)
                report["orphan_mounts"].append(sid)
            if self.net:
                for name in self.net.host_ifaces():
                    slot = int(name[4:])
                    if slot not in live_slots:
                        self.net.detach(slot)
                        report["orphan_ifaces"].append(name)
        return report

    # ---- proxy ---------------------------------------------------------
    def _ensure_proxy(self) -> None:
        pidfile = self._dir("proxy.json")
        try:
            info = read_json(pidfile)
            if (pid_alive(info["pid"], info["start"]) and info["allow"] == self.cfg.egress_allowlist
                    and info.get("uid") == self.cfg.proxy_uid):
                return
            if pid_alive(info["pid"], info["start"]):
                os.kill(info["pid"], signal.SIGKILL)
                wait_until(lambda: not pid_alive(info["pid"], info["start"]), 5)
        except (FileNotFoundError, ValueError, KeyError):
            pass
        argv = [PYTHON, "-I", PROXY, "--netns", self.net.netns_path,
                "--port", str(self.cfg.proxy_port), "--uid", str(self.cfg.proxy_uid)]
        for a in self.cfg.egress_allowlist:
            argv += ["--allow", a]
        log = open(self._dir("proxy.log"), "a")
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                start_new_session=True, close_fds=True)
        log.close()
        ok = wait_until(lambda: '"listening"' in _tail(self._dir("proxy.log")) or proc.poll() is not None, 10)
        if not ok or proc.poll() is not None:
            raise SandboxError(f"egress proxy failed to start: {_tail(self._dir('proxy.log'))}")
        write_json_atomic(pidfile, {"pid": proc.pid, "start": proc_start_time(proc.pid),
                                    "allow": self.cfg.egress_allowlist, "uid": self.cfg.proxy_uid})


def _find_holders(sid: str) -> list[int]:
    """Holder processes for sid found by cmdline, for crashes before the pid was saved."""
    out = []
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            with open(f"/proc/{p}/cmdline", "rb") as f:
                args = f.read().split(b"\0")
        except OSError:
            continue
        if NSINIT.encode() in args and b"holder" in args and args[-2:-1] == [sid.encode()]:
            out.append(int(p))
    return out


def _readline(f, timeout: float) -> str:
    buf = b""
    deadline = time.monotonic() + timeout
    while not buf.endswith(b"\n"):
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([f], [], [], left)[0]:
            break
        ch = os.read(f.fileno(), 256)
        if not ch:
            break
        buf += ch
    return buf.decode("utf-8", "replace")


def _capture(proc: subprocess.Popen, stdin: str | None, timeout: float | None):
    """communicate() with an output cap, so a sandbox cannot exhaust our memory."""
    bufs = {proc.stdout: bytearray(), proc.stderr: bytearray()}

    def reader(f):
        b = bufs[f]
        while chunk := f.read(65536):
            if len(b) < MAX_OUTPUT:
                b.extend(chunk[: MAX_OUTPUT - len(b)])

    threads = [threading.Thread(target=reader, args=(f,), daemon=True) for f in bufs]
    for t in threads:
        t.start()
    if stdin is not None:
        try:
            proc.stdin.write(stdin.encode())
        except BrokenPipeError:
            pass
        proc.stdin.close()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # SIGTERM makes the in-sandbox supervisor kill the command's whole
        # process tree (it is a child subreaper, so setsid()/double-fork
        # cannot leave it). SIGKILL the wrapper's group only as a fallback.
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        for t in threads:
            t.join(1)
        return None, None
    for t in threads:
        t.join(5)
    return bytes(bufs[proc.stdout]), bytes(bufs[proc.stderr])


def _tail(path: str, n: int = 2000) -> str:
    try:
        with open(path) as f:
            return f.read()[-n:]
    except OSError:
        return ""
