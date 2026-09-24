#!/usr/bin/env python3
"""Phase 0 host check: verify the Linux primitives DESIGN.md assumes exist.

Linux only, must run as root, standard library only. Records what it
observes; it never asserts a number it did not measure on this host.

    sudo python3 scripts/host_check.py

Writes JSON to results/phase0-host-check/ and exits 0 only if every
required check passed.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import errno
import hashlib
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
MNT_DETACH = 2
USERNS_HOST_BASE = 100000
USERNS_RANGE = 65536

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if platform.system() == "Linux":
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p] * 3 + [ctypes.c_ulong, ctypes.c_char_p]
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.unshare.argtypes = [ctypes.c_int]


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(cmd)}"


def read(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def sys_mount(src, target, fstype, data="", flags=0):
    raw = data.encode() if isinstance(data, str) else data
    if libc.mount(src.encode(), target.encode(), fstype.encode(), flags, raw) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e), f"mount({fstype}, data_len={len(raw)})")


def sys_umount(target):
    if libc.umount2(target.encode(), 0) != 0:
        if libc.umount2(target.encode(), MNT_DETACH) != 0:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e), f"umount({target})")


def mounts_under(path):
    """Mount points at or below path, from this process's mount namespace."""
    prefix = os.path.realpath(path)
    found = []
    for line in read("/proc/self/mountinfo").splitlines():
        mp = line.split()[4].replace("\\040", " ")
        if mp == prefix or mp.startswith(prefix + os.sep):
            found.append(mp)
    return found


def safe_rmtree(path):
    """Refuse to delete through a live mount: rmtree on a mounted overlay
    would delete the lower layer's files via the merged view."""
    live = mounts_under(path)
    if live:
        raise RuntimeError(f"refusing to delete {path}: live mounts {live}")
    shutil.rmtree(path)


class Scratch:
    def __init__(self, base, prefix):
        self.dir = tempfile.mkdtemp(prefix=prefix, dir=base)
        self.mounts = []

    def mk(self, *names):
        paths = []
        for n in names:
            p = os.path.join(self.dir, n)
            os.makedirs(p, exist_ok=True)
            paths.append(p)
        return paths if len(paths) > 1 else paths[0]

    def overlay(self, target, lower, upper, work, extra=""):
        data = f"lowerdir={lower},upperdir={upper},workdir={work}{extra}"
        sys_mount("overlay", target, "overlay", data)
        self.mounts.append(target)

    def close(self):
        for m in reversed(self.mounts):
            try:
                sys_umount(m)
            except OSError:
                pass
        safe_rmtree(self.dir)


def put(path, text):
    with open(path, "w") as f:
        f.write(text)


def fs_type_of(path):
    rc, out, _ = run(["findmnt", "-no", "FSTYPE,SOURCE", "-T", path])
    if rc == 0 and out:
        return out
    rc, out, _ = run(["stat", "-f", "-c", "%T", path])
    return out if rc == 0 else "unknown"


# ---- checks: each returns (status, detail, data); status in pass/fail/info/skip


def check_host_info(ctx):
    meminfo = read("/proc/meminfo")
    mem_kb = next((int(l.split()[1]) for l in meminfo.splitlines() if l.startswith("MemTotal")), None)
    cpu_model = next((l.split(":", 1)[1].strip() for l in read("/proc/cpuinfo").splitlines()
                      if l.lower().startswith(("model name", "hardware"))), "unknown")
    osrel = {}
    for l in read("/etc/os-release").splitlines():
        if "=" in l:
            k, v = l.split("=", 1)
            osrel[k] = v.strip('"')
    data = {
        "kernel": platform.release(),
        "uname": " ".join(platform.uname()),
        "distro": osrel.get("PRETTY_NAME", "unknown"),
        "cpu_model": cpu_model,
        "cpu_count": os.cpu_count(),
        "mem_total_kb": mem_kb,
        "virt": run(["systemd-detect-virt"])[1] or "unknown",
        "dmi_vendor": read("/sys/class/dmi/id/sys_vendor", "n/a"),
        "dmi_product": read("/sys/class/dmi/id/product_name", "n/a"),
        "is_wsl": "microsoft" in read("/proc/version").lower(),
        "lsblk": run(["lsblk", "-d", "-o", "NAME,ROTA,TYPE,SIZE,MODEL"])[1],
        "workdir": ctx["workdir"],
        "workdir_fs": fs_type_of(ctx["workdir"]),
        "python": platform.python_version(),
    }
    ctx["is_wsl"] = data["is_wsl"]
    return "info", f"{data['distro']}, kernel {data['kernel']}, virt={data['virt']}, wsl={data['is_wsl']}", data


def check_overlay_registered(ctx):
    ok = any(l.split()[-1] == "overlay" for l in read("/proc/filesystems").splitlines() if l.strip())
    return ("pass" if ok else "fail"), "overlay listed in /proc/filesystems" if ok else "overlay not in /proc/filesystems", {}


def check_overlay_basic(ctx):
    s = Scratch(ctx["workdir"], "ovl-basic-")
    try:
        lower, upper, work, merged = s.mk("lower", "upper", "work", "merged")
        put(f"{lower}/a.txt", "lower")
        s.overlay(merged, lower, upper, work)
        assert open(f"{merged}/a.txt").read() == "lower", "merged view missing lower file"
        put(f"{merged}/a.txt", "changed")
        put(f"{merged}/new.txt", "new")
        assert open(f"{lower}/a.txt").read() == "lower", "write leaked into lower layer"
        assert open(f"{upper}/a.txt").read() == "changed", "copy-up did not land in upper"
        assert os.path.exists(f"{upper}/new.txt"), "new file not in upper"
        return "pass", "mount, read-through, copy-up, and lower-immutability all held", {}
    finally:
        s.close()


def _fork_pair(s):
    """Model DESIGN.md §3 fork: child lowerdir = parent's upper stacked over base."""
    base, p_up, p_work, p_mg, c_up, c_work, c_mg = s.mk("base", "p_up", "p_work", "p_mg", "c_up", "c_work", "c_mg")
    put(f"{base}/base.txt", "base")
    s.overlay(p_mg, base, p_up, p_work)
    put(f"{p_mg}/parent.txt", "parent-before-fork")
    s.overlay(c_mg, f"{p_up}:{base}", c_up, c_work)
    return p_mg, c_mg, p_up, c_up


def check_overlay_fork_stack(ctx):
    s = Scratch(ctx["workdir"], "ovl-fork-")
    try:
        p_mg, c_mg, p_up, c_up = _fork_pair(s)
        assert os.path.exists(f"{c_mg}/base.txt"), "child cannot see base"
        assert open(f"{c_mg}/parent.txt").read() == "parent-before-fork", "child cannot see pre-fork parent write"
        put(f"{c_mg}/child.txt", "child")
        assert os.path.exists(f"{c_up}/child.txt"), "child write not in child upper"
        assert not os.path.exists(f"{p_mg}/child.txt"), "child write visible in parent"
        return "pass", "child sees pre-fork state; child writes stay in child upper, invisible to parent", {}
    finally:
        s.close()


def check_overlay_parent_write_after_fork(ctx):
    s = Scratch(ctx["workdir"], "ovl-latewrite-")
    try:
        p_mg, c_mg, p_up, c_up = _fork_pair(s)
        put(f"{p_mg}/parent.txt", "parent-AFTER-fork")
        put(f"{p_mg}/late.txt", "late")
        child_content = open(f"{c_mg}/parent.txt").read()
        child_listing = sorted(os.listdir(c_mg))
        data = {
            "child_reads_parent_txt_as": child_content,
            "child_sees_late_txt": "late.txt" in child_listing,
            "child_listing": child_listing,
        }
        leaked = child_content != "parent-before-fork" or data["child_sees_late_txt"]
        detail = ("parent writes AFTER fork were visible in child (isolation broken)" if leaked
                  else "parent writes after fork were not visible in child on this kernel")
        detail += "; kernel docs call this undefined behavior, so this observation is not a guarantee"
        return "info", detail, data
    finally:
        s.close()


def _layer_probe(base, relative):
    s = Scratch(base, "ovl-layers-")
    cwd = os.getcwd()
    max_n = 1100
    try:
        for i in range(max_n):
            os.mkdir(os.path.join(s.dir, f"l{i}"))
        for n in ("u", "w", "m"):
            os.mkdir(os.path.join(s.dir, n))

        def attempt(n):
            if relative:
                os.chdir(s.dir)
                names, up, wk, mg = [f"l{i}" for i in range(n)], "u", "w", "m"
            else:
                names = [os.path.join(s.dir, f"l{i}") for i in range(n)]
                up, wk, mg = (os.path.join(s.dir, x) for x in ("u", "w", "m"))
            data = "lowerdir=" + ":".join(names) + f",upperdir={up},workdir={wk}"
            try:
                sys_mount("overlay", mg, "overlay", data)
                sys_umount(mg)
                return True, None, len(data)
            except OSError as e:
                return False, f"{errno.errorcode.get(e.errno, e.errno)}: {e.strerror}", len(data)

        lo, hi = 1, max_n
        if not attempt(1)[0]:
            return {"max_layers": 0, "reason": attempt(1)[1]}
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if attempt(mid)[0]:
                lo = mid
            else:
                hi = mid - 1
        ok_max = attempt(lo)
        fail_next = attempt(lo + 1) if lo < max_n else (None, "not reached", None)
        return {
            "max_layers": lo,
            "mount_data_len_at_max": ok_max[2],
            "next_layer_failure": fail_next[1],
            "mount_data_len_at_failure": fail_next[2],
            "ok_at_500": attempt(500)[0],
            "ok_at_501": attempt(501)[0],
            "layer_path_len_example": len(f"l{lo}") if relative else len(os.path.join(s.dir, f"l{lo}")),
            "search_ceiling": max_n,
        }
    finally:
        os.chdir(cwd)
        s.close()


def check_overlay_max_layers(ctx):
    rel = _layer_probe(ctx["workdir"], relative=True)
    ab = _layer_probe(ctx["workdir"], relative=False)
    detail = (f"max stacked lowerdirs via legacy mount(2): {rel['max_layers']} with short relative paths, "
              f"{ab['max_layers']} with absolute paths under {ctx['workdir']}")
    return "info", detail, {"relative_paths": rel, "absolute_paths": ab}


def check_namespaces(ctx):
    names = ["mnt", "uts", "ipc", "net", "pid"]
    host = {n: os.readlink(f"/proc/self/ns/{n}") for n in names}
    script = "for n in mnt uts ipc net pid; do echo $n $(readlink /proc/self/ns/$n); done; echo pid1 $$"
    rc, out, err = run(["unshare", "--mount", "--uts", "--ipc", "--net", "--pid", "--fork",
                        "--mount-proc", "sh", "-c", script])
    if rc != 0:
        return "fail", f"unshare failed rc={rc}: {err}", {}
    inner = dict(l.split(" ", 1) for l in out.splitlines())
    same = [n for n in names if inner.get(n) == host[n]]
    if same:
        return "fail", f"namespaces not isolated: {same}", {"host": host, "inner": inner}
    if inner.get("pid1") != "1":
        return "fail", f"child is not PID 1 in new pid ns (got {inner.get('pid1')})", {"inner": inner}
    return "pass", "mnt/uts/ipc/net/pid namespaces all distinct from host; child is PID 1", {}


def _userns_probe(scratch, with_overlay):
    os.chmod(scratch.dir, 0o755)  # mkdtemp is 0700; mapped uid must be able to traverse it
    host_file = os.path.join(scratch.dir, "hostfile")
    put(host_file, "x")
    ov = {}
    if with_overlay:
        lower, upper, work, merged = scratch.mk("ulower", "uupper", "uwork", "umerged")
        put(f"{lower}/a.txt", "lower")
        for p in (upper, work):
            os.chown(p, USERNS_HOST_BASE, USERNS_HOST_BASE)
        ov = dict(lower=lower, upper=upper, work=work, merged=merged)
    ready_r, ready_w = os.pipe()
    go_r, go_w = os.pipe()
    res_r, res_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        signal.alarm(20)
        sent_ready = False
        code = 0
        try:
            flags = CLONE_NEWUSER | (CLONE_NEWNS if with_overlay else 0)
            if libc.unshare(flags) != 0:
                e = ctypes.get_errno()
                raise OSError(e, os.strerror(e), "unshare")
            os.write(ready_w, b"1")
            sent_ready = True
            os.read(go_r, 1)
            # The creator's real uid (host 0) is outside the mapped range, so it reads as 65534
            # until the process switches to a mapped id. Runtimes do this after writing the map.
            os.setgroups([])
            os.setgid(0)
            os.setuid(0)
            res = {"uid": os.getuid(), "host_root_file_appears_as_uid": os.stat(host_file).st_uid}
            if with_overlay:
                res["overlay"] = {}
                for label, extra in (("plain", ""), ("userxattr", ",userxattr")):
                    try:
                        data = f"lowerdir={ov['lower']},upperdir={ov['upper']},workdir={ov['work']}{extra}"
                        sys_mount("overlay", ov["merged"], "overlay", data)
                        seen = open(f"{ov['merged']}/a.txt").read()
                        put(f"{ov['merged']}/new.txt", "n")
                        res["overlay"][label] = f"ok (read lower={seen!r}, create ok)"
                        sys_umount(ov["merged"])
                        break
                    except OSError as e:
                        res["overlay"][label] = f"{errno.errorcode.get(e.errno, e.errno)}: {e.strerror}"
            os.write(res_w, json.dumps(res).encode())
        except BaseException as e:
            os.write(res_w, json.dumps({"error": f"{type(e).__name__}: {e}"}).encode())
            if not sent_ready:
                os.write(ready_w, b"F")
            code = 1
        finally:
            os._exit(code)
    try:
        if os.read(ready_r, 1) == b"F":
            return json.loads(os.read(res_r, 65536).decode())
        for name in ("uid_map", "gid_map"):
            put(f"/proc/{pid}/{name}", f"0 {USERNS_HOST_BASE} {USERNS_RANGE}\n")
        os.write(go_w, b"1")
        return json.loads(os.read(res_r, 65536).decode())
    finally:
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        for fd in (ready_r, ready_w, go_r, go_w, res_r, res_w):
            os.close(fd)


def check_userns_mapping(ctx):
    s = Scratch(ctx["workdir"], "userns-")
    try:
        r = _userns_probe(s, with_overlay=False)
    finally:
        s.close()
    data = {
        "max_user_namespaces": read("/proc/sys/user/max_user_namespaces"),
        "apparmor_restrict_unprivileged_userns": read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "n/a"),
        "probe": r,
    }
    if "error" in r:
        return "fail", f"user namespace creation failed: {r['error']}", data
    ok = r["uid"] == 0 and r["host_root_file_appears_as_uid"] == 65534
    detail = (f"ns-root (uid 0) mapped to host uid {USERNS_HOST_BASE}; host-root-owned files show as uid 65534 inside"
              if ok else f"unexpected mapping result: {r}")
    return ("pass" if ok else "fail"), detail, data


def check_overlay_in_userns(ctx):
    s = Scratch(ctx["workdir"], "userns-ovl-")
    try:
        r = _userns_probe(s, with_overlay=True)
    finally:
        s.close()
    if "error" in r:
        return "fail", f"probe failed: {r['error']}", {"probe": r}
    ovl = r.get("overlay", {})
    worked = [k for k, v in ovl.items() if v.startswith("ok")]
    detail = (f"overlay mounted by userns-root succeeded ({worked[0]} options)" if worked
              else "overlay mount inside user namespace failed; control plane must mount it from outside (DESIGN §5.2)")
    return "info", detail, {"probe": r}


def check_cgroup_v2(ctx):
    root = "/sys/fs/cgroup"
    if not os.path.exists(f"{root}/cgroup.controllers"):
        return "fail", "no cgroup v2 unified hierarchy at /sys/fs/cgroup", {}
    need = ["cpu", "memory", "pids", "io"]
    avail = read(f"{root}/cgroup.controllers").split()
    delegated = read(f"{root}/cgroup.subtree_control").split()
    data = {"available": avail, "delegated_at_root": delegated}
    missing = [c for c in need if c not in avail]
    if missing:
        return "fail", f"controllers unavailable: {missing}", data
    undelegated = [c for c in need if c not in delegated]
    if undelegated:
        return "fail", (f"controllers not enabled in root subtree_control: {undelegated} "
                        "(not modified by this check; enable them or delegate via systemd)"), data
    parent = f"{root}/sbx-hostcheck-{os.getpid()}"
    leaf = f"{parent}/leaf"
    proc = None
    try:
        os.mkdir(parent)
        put(f"{parent}/cgroup.subtree_control", " ".join(f"+{c}" for c in need))
        os.mkdir(leaf)
        put(f"{leaf}/memory.max", str(256 * 1024 * 1024))
        put(f"{leaf}/pids.max", "64")
        put(f"{leaf}/cpu.max", "50000 100000")
        proc = subprocess.Popen(["sleep", "30"])
        put(f"{leaf}/cgroup.procs", str(proc.pid))
        placed = read(f"/proc/{proc.pid}/cgroup")
        if not placed.endswith(f"/sbx-hostcheck-{os.getpid()}/leaf"):
            return "fail", f"process not placed in leaf cgroup: {placed!r}", data
        data["knobs"] = {k: read(f"{leaf}/{k}") for k in ("memory.max", "pids.max", "cpu.max")}
        data["has_cgroup_freeze"] = os.path.exists(f"{leaf}/cgroup.freeze")
        data["has_cgroup_kill"] = os.path.exists(f"{leaf}/cgroup.kill")
        return "pass", "created nested cgroups, set memory/pids/cpu limits, placed a process in the leaf", data
    finally:
        if proc:
            proc.kill()
            proc.wait()
        for d in (leaf, parent):
            for _ in range(40):
                try:
                    os.rmdir(d)
                    break
                except FileNotFoundError:
                    break
                except OSError:
                    time.sleep(0.05)


def _ip(*args):
    rc, out, err = run(["ip", *args])
    if rc != 0:
        raise RuntimeError(f"ip {' '.join(args)} -> rc={rc}: {err}")
    return out


def check_veth_netns(ctx):
    ns = f"sbxchk{os.getpid()}"
    host_if, peer_if = f"vh{os.getpid() % 100000}", f"vp{os.getpid() % 100000}"
    try:
        _ip("netns", "add", ns)
        _ip("link", "add", host_if, "type", "veth", "peer", "name", peer_if)
        _ip("link", "set", peer_if, "netns", ns)
        _ip("addr", "add", "169.254.203.1/30", "dev", host_if)
        _ip("-n", ns, "addr", "add", "169.254.203.2/30", "dev", peer_if)
        _ip("link", "set", host_if, "up")
        _ip("-n", ns, "link", "set", peer_if, "up")
        _ip("-n", ns, "link", "set", "lo", "up")
        detail = "created netns + veth pair, addressed and brought up both ends"
        if shutil.which("ping"):
            rc, _, err = run(["ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "2", "169.254.203.1"])
            if rc != 0:
                return "fail", f"veth pair created but ping across it failed: {err}", {}
            detail += "; ping across the pair succeeded"
        else:
            detail += "; ping not installed so connectivity not verified"
        return "pass", detail, {}
    finally:
        run(["ip", "link", "del", host_if])
        run(["ip", "netns", "del", ns])


def check_nft(ctx):
    rc, ver, err = run(["nft", "--version"])
    if rc != 0:
        return "fail", f"nft not usable: {err}", {}
    ns = f"sbxnft{os.getpid()}"
    try:
        _ip("netns", "add", ns)
        rc, _, err = run(["ip", "netns", "exec", ns, "nft", "add", "table", "inet", "chk"])
        if rc != 0:
            return "fail", f"{ver}: could not create a table inside a netns: {err}", {}
        rc, out, _ = run(["ip", "netns", "exec", ns, "nft", "list", "tables"])
        return "pass", f"{ver}: created and listed a table inside a fresh netns", {"tables": out}
    finally:
        run(["ip", "netns", "del", ns])


def check_tools(ctx):
    tools = ["python3", "gcc", "rustc", "cargo", "ip", "nft", "iptables", "unshare", "nsenter",
             "ping", "criu", "docker", "btrfs", "mkfs.btrfs", "zfs", "losetup"]
    data = {}
    for t in tools:
        path = shutil.which(t)
        data[t] = {"path": path}
        if path and t in ("criu", "docker", "gcc", "rustc", "cargo", "btrfs", "nft"):
            data[t]["version"] = (run([t, "--version"])[1] or "").splitlines()[:1]
    if data["criu"]["path"]:
        rc, out, err = run(["criu", "check"])
        data["criu"]["check"] = {"rc": rc, "output": (out or err)[-600:]}
    if data["docker"]["path"]:
        rc, out, err = run(["docker", "info", "--format",
                            "{{.ServerVersion}}|{{.Driver}}|{{.CgroupVersion}}|{{.DriverStatus}}"])
        data["docker"]["info"] = out if rc == 0 else err[-300:]
    present = sorted(t for t, v in data.items() if v["path"])
    return "info", f"present: {', '.join(present)}", data


def check_btrfs_loopback(ctx):
    for t in ("mkfs.btrfs", "btrfs", "mount"):
        if not shutil.which(t):
            return "skip", f"{t} not installed (btrfs-progs); only matters if overlayfs fork fallback is needed", {}
    s = Scratch(ctx["workdir"], "btrfs-")
    try:
        img = os.path.join(s.dir, "img")
        with open(img, "wb") as f:
            f.truncate(256 * 1024 * 1024)
        mnt = s.mk("mnt")
        rc, _, err = run(["mkfs.btrfs", "-q", "-f", img])
        if rc != 0:
            return "fail", f"mkfs.btrfs failed: {err}", {}
        rc, _, err = run(["mount", "-o", "loop", img, mnt])
        if rc != 0:
            return "fail", f"loop-mounting btrfs failed: {err}", {}
        s.mounts.append(mnt)
        vol, snap = f"{mnt}/vol", f"{mnt}/snap"
        rc, _, err = run(["btrfs", "subvolume", "create", vol])
        if rc != 0:
            return "fail", f"subvolume create failed: {err}", {}
        put(f"{vol}/f.txt", "before")
        rc, _, err = run(["btrfs", "subvolume", "snapshot", vol, snap])
        if rc != 0:
            return "fail", f"snapshot failed: {err}", {}
        put(f"{vol}/f.txt", "after-snapshot")
        put(f"{vol}/late.txt", "late")
        seen = open(f"{snap}/f.txt").read()
        ok = seen == "before" and not os.path.exists(f"{snap}/late.txt")
        return ("pass" if ok else "fail"), (
            "btrfs snapshot stayed frozen while the source subvolume kept being written"
            if ok else f"snapshot saw post-snapshot writes: f.txt={seen!r}"), {}
    finally:
        s.close()


CHECKS = [
    # name, required, DESIGN.md reference, function
    ("host_info", False, "BENCHMARKS §3.6", check_host_info),
    ("overlay_registered", True, "§3", check_overlay_registered),
    ("overlay_basic", True, "§3", check_overlay_basic),
    ("overlay_fork_stack", True, "§3 fork mechanics", check_overlay_fork_stack),
    ("overlay_parent_write_after_fork", False, "§3 fork mechanics", check_overlay_parent_write_after_fork),
    ("overlay_max_layers", False, "§3 stacking limit", check_overlay_max_layers),
    ("namespaces", True, "§5.2", check_namespaces),
    ("userns_mapping", True, "§5.2", check_userns_mapping),
    ("overlay_in_userns", False, "§5.2", check_overlay_in_userns),
    ("cgroup_v2", True, "§5.2", check_cgroup_v2),
    ("veth_netns", True, "§5.4", check_veth_netns),
    ("nft", True, "§5.4", check_nft),
    ("tools", False, "§4, BENCHMARKS §2", check_tools),
    ("btrfs_loopback", False, "§3 fallback", check_btrfs_loopback),
]


def git_info():
    base = ["git", "-c", f"safe.directory={REPO_ROOT}", "-C", REPO_ROOT]
    rc, sha, _ = run(base + ["rev-parse", "HEAD"])
    if rc != 0:
        return {"commit": None, "dirty": None}
    return {"commit": sha, "dirty": bool(run(base + ["status", "--porcelain"])[1])}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workdir", default="/var/tmp", help="scratch base dir; should be on the disk the benchmarks will use")
    ap.add_argument("--out-dir", default=os.path.join(REPO_ROOT, "results", "phase0-host-check"))
    ap.add_argument("--no-write", action="store_true", help="print only; do not write a result file")
    args = ap.parse_args()

    if platform.system() != "Linux":
        print("error: Linux only", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("error: must run as root (sudo python3 scripts/host_check.py)", file=sys.stderr)
        return 2

    ctx = {"workdir": os.path.abspath(args.workdir)}
    started = dt.datetime.now(dt.timezone.utc)
    results = []
    for name, required, ref, fn in CHECKS:
        try:
            status, detail, data = fn(ctx)
        except Exception as e:
            status, detail, data = "fail", f"{type(e).__name__}: {e}", {"traceback": traceback.format_exc()}
        results.append({"name": name, "required": required, "design_ref": ref,
                        "status": status, "detail": detail, "data": data})
        print(f"[{status.upper():4}] {name}: {detail}")

    failed = [r["name"] for r in results if r["required"] and r["status"] != "pass"]
    with open(__file__, "rb") as f:
        script_sha = hashlib.sha256(f.read()).hexdigest()
    report = {
        "schema_version": 1,
        "started_utc": started.isoformat(),
        "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "command": " ".join([sys.executable] + sys.argv),
        "script_sha256": script_sha,
        "git": git_info(),
        "is_wsl": ctx.get("is_wsl"),
        "required_failed": failed,
        "checks": results,
    }
    if not args.no_write:
        os.makedirs(args.out_dir, exist_ok=True)
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
        out = os.path.join(args.out_dir, f"{stamp}-{report['hostname']}.json")
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
        print(f"\nwrote {out}")
    print(f"\nrequired checks failed: {failed if failed else 'none'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
