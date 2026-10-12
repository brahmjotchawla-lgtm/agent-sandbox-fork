"""The zygote: a single-threaded helper that forks sandbox launchers and exec helpers.

Why it exists. The control plane is multi-threaded, and fork() in a
multi-threaded process is unsafe. Starting a fresh Python interpreter for
every launch would put interpreter start-up into the critical path of
create/fork, which Claim 1 measures. So the control plane starts this process
once. For each request it gets over a SOCK_SEQPACKET socketpair (JSON plus
file descriptors via SCM_RIGHTS), it fork()s one child to do the work.

The zygote is a child subreaper. When a launcher's intermediate process exits,
the sandbox's PID 1 re-parents to the zygote, which reaps it, instead of
re-parenting to host PID 1.

Every child reports progress as newline-delimited JSON on a result pipe that
the control plane passed in. If that pipe reaches EOF without a final event,
the child died.

Process tree for a launch (see docs/phases/phase1.md for the reasoning):

    zygote
      └─ L  launcher: private mount ns, writes id maps, joins C1 to the
            │          cgroup, builds the idmapped rootfs mount
            └─ C1  new user ns -> setresuid(0) -> unshare(mnt,uts,ipc,net,pid,cgroup)
                 └─ C2 = sandbox PID 1: pivot_root, /proc, /dev, exec sandbox-init
"""
from __future__ import annotations

import fcntl
import json
import os
import signal
import socket
import sys
import time

from . import _sys

MSG_MAX = 1 << 16
DEVICES = ("null", "zero", "full", "random", "urandom", "tty")
ALL_NS = (
    _sys.CLONE_NEWUSER
    | _sys.CLONE_NEWNS
    | _sys.CLONE_NEWPID
    | _sys.CLONE_NEWNET
    | _sys.CLONE_NEWUTS
    | _sys.CLONE_NEWIPC
    | _sys.CLONE_NEWCGROUP
)
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _now() -> int:
    return time.monotonic_ns()


class _Emitter:
    def __init__(self, fd: int):
        self.fd = fd

    def __call__(self, event: str, **kw) -> None:
        kw["event"] = event
        line = (json.dumps(kw) + "\n").encode()
        os.write(self.fd, line)


def _fault(spec: dict, point: str) -> None:
    """Test-only fault injection. The control plane only sets `fault` when its
    config enables it, and tests use this to kill a launch at a precise point."""
    f = spec.get("fault")
    if f and f.get("point") == point:
        if f.get("action") == "hang":
            while True:
                time.sleep(3600)
        if f.get("action") == "exit":
            os._exit(99)


def _read_exact(fd: int, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = os.read(fd, n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _read_all(fd: int) -> bytes:
    chunks = []
    while True:
        c = os.read(fd, 65536)
        if not c:
            return b"".join(chunks)
        chunks.append(c)


# --------------------------------------------------------------------------- launch


def do_launch(spec: dict, fds: list[int], init_fd: int) -> int:
    result_w = fds[0]
    emit = _Emitter(result_w)
    t: dict[str, int] = {"launcher_start": _now()}
    emit("started", pid=os.getpid())
    os.setsid()
    # The launcher joins the sandbox cgroup itself, first thing. Then a
    # cgroup.kill during cleanup also catches a launcher stuck mid-setup, even
    # if the control plane crashed before it learned the launcher's PID.
    # C1 and C2 inherit the cgroup through fork.
    with open(os.path.join(spec["cgroup"], "cgroup.procs"), "w") as fh:
        fh.write(str(os.getpid()))
    _sys.close_fds_except([result_w, init_fd])

    # A private, throwaway mount namespace for the launcher. Nothing mounted
    # below is ever visible in the host's mount table.
    os.unshare(_sys.CLONE_NEWNS)
    _sys.mount(None, "/", None, _sys.MS_REC | _sys.MS_PRIVATE)
    stage = spec["stage_dir"]
    _sys.mount("tmpfs", stage, "tmpfs", _sys.MS_NOSUID | _sys.MS_NODEV | _sys.MS_NOEXEC, "mode=711,size=64k")
    root = os.path.join(stage, "root")
    os.mkdir(root, 0o700)

    to_c1_r, to_c1_w = os.pipe()
    from_c1_r, from_c1_w = os.pipe()
    exec_r, exec_w = os.pipe2(os.O_CLOEXEC)
    t["userns_fork"] = _now()
    c1 = os.fork()
    if c1 == 0:
        os.close(to_c1_w)
        os.close(from_c1_r)
        os.close(exec_r)
        _child_c1(spec, root, init_fd, to_c1_r, from_c1_w, exec_w, result_w)
        os._exit(1)  # unreachable
    os.close(to_c1_r)
    os.close(from_c1_w)
    os.close(exec_w)

    if _read_exact(from_c1_r, 1) != b"U":
        raise RuntimeError("C1 failed to create its user namespace")
    t["userns_created"] = _now()
    _fault(spec, "after_userns")

    # Map sandbox uid/gid 0..65535 onto this sandbox's private host range.
    # We write as host root (privileged), so setgroups stays allowed and
    # C1 can drop the host's supplementary groups.
    base, size = spec["uid_base"], spec["uid_size"]
    for f in ("uid_map", "gid_map"):
        with open(f"/proc/{c1}/{f}", "w") as fh:
            fh.write(f"0 {base} {size}\n")
    t["idmap_written"] = _now()

    _fault(spec, "after_cgroup")

    # Idmapped mount: on disk the rootfs is owned by uid 0..65535. Through
    # this mount it appears to the sandbox's user namespace as its own
    # 0..65535, which is host uid base..base+65535. No chown, so forks stay
    # O(1) in file count.
    userns_fd = os.open(f"/proc/{c1}/ns/user", os.O_RDONLY | os.O_CLOEXEC)
    tree = _sys.open_tree(spec["subvol"], _sys.OPEN_TREE_CLONE | _sys.OPEN_TREE_CLOEXEC)
    _sys.mount_setattr(tree, attr_set=_sys.MOUNT_ATTR_IDMAP, userns_fd=userns_fd)
    _sys.move_mount(tree, root)
    os.close(tree)
    os.close(userns_fd)
    t["rootfs_idmapped"] = _now()

    os.write(to_c1_w, b"M")
    os.close(to_c1_w)

    msg = _read_all(from_c1_r).decode()
    os.close(from_c1_r)
    _, st = os.waitpid(c1, 0)
    if not msg.startswith("P"):
        raise RuntimeError(f"C1 failed: {msg[1:] or 'died without a message'} (status {st})")
    init_pid = int(msg[1:].split(";")[0])
    c1_times = json.loads(msg.split(";", 1)[1])
    t.update(c1_times)

    err = _read_all(exec_r).decode()
    os.close(exec_r)
    if err:
        raise RuntimeError(f"sandbox PID 1 setup failed: {err}")
    try:
        exe = os.readlink(f"/proc/{init_pid}/exe")
    except OSError as e:
        raise RuntimeError(f"sandbox PID 1 ({init_pid}) is gone after exec: {e}")
    if not exe.startswith("/memfd:sandbox-init"):
        raise RuntimeError(f"sandbox PID 1 is running {exe!r}, expected the sandbox-init memfd")
    t["init_exec_done"] = _now()
    emit("ready", init_pid=init_pid, t=t)
    return 0


def _child_c1(spec, root, init_fd, to_c1_r, from_c1_w, exec_w, result_w) -> None:
    try:
        os.close(result_w)
        os.unshare(_sys.CLONE_NEWUSER)
        os.write(from_c1_w, b"U")
        if _read_exact(to_c1_r, 1) != b"M":
            os._exit(1)
        os.close(to_c1_r)
        t = {"c1_maps_seen": _now()}
        # Enter the rootfs while we are still host root: the staging path is
        # under a 0700 root-owned directory that the sandbox's host uid range
        # cannot traverse, by design. Everything after this is cwd-relative.
        os.chdir(root)
        # Host root's supplementary groups (gid 0!) would otherwise ride
        # along on every sandbox process's credentials.
        os.setgroups([])
        os.setresgid(0, 0, 0)
        os.setresuid(0, 0, 0)
        os.unshare(
            _sys.CLONE_NEWNS | _sys.CLONE_NEWUTS | _sys.CLONE_NEWIPC | _sys.CLONE_NEWNET | _sys.CLONE_NEWPID | _sys.CLONE_NEWCGROUP
        )
        t["namespaces_created"] = _now()
        c2 = os.fork()
        if c2 == 0:
            os.close(from_c1_w)
            _child_c2(spec, root, init_fd, exec_w)
            os._exit(1)  # unreachable
        os.write(from_c1_w, f"P{c2};{json.dumps(t)}".encode())
        os._exit(0)
    except BaseException as e:  # noqa: BLE001 - report everything to the launcher
        try:
            os.write(from_c1_w, f"E{type(e).__name__}: {e}".encode())
        finally:
            os._exit(1)


def _child_c2(spec, root, init_fd, exec_w) -> None:
    """PID 1 of the new PID namespace, before it becomes sandbox-init."""
    try:
        _fault(spec, "in_pid1")
        # Detached clones of the host device nodes. They are taken now,
        # while the host root is still reachable, and attached after
        # pivot_root by fd, so no path is ever resolved against host state
        # after the sandbox's rootfs is in place.
        devs = {d: _sys.open_tree(f"/dev/{d}", _sys.OPEN_TREE_CLONE | _sys.OPEN_TREE_CLOEXEC) for d in DEVICES}

        # The idmapped mount came from a more privileged mount namespace, so
        # it is MNT_LOCKED and pivot_root refuses it. A bind mount of it made
        # here is owned by our namespace (and keeps the idmapping).
        _sys.mount(".", ".", None, _sys.MS_BIND | _sys.MS_REC)
        # "." does not cross onto a mount stacked on the cwd; going up to the
        # staging tmpfs (mode 0711: traversable, not listable) and back down does.
        os.chdir("..")
        os.chdir("root")
        _sys.pivot_root(".", ".")
        _sys.umount2(".", _sys.MNT_DETACH)  # detach the old (host) root entirely
        os.chdir("/")
        _setup_mounts(devs)
        socket.sethostname(spec["hostname"])

        _sys.close_fds_except([init_fd, exec_w])
        os.execve(init_fd, ["sandbox-init"], {})
    except BaseException as e:  # noqa: BLE001
        try:
            os.write(exec_w, f"{type(e).__name__}: {e}".encode())
        finally:
            os._exit(1)


def _ensure_dir(path: str, mode: int = 0o755) -> None:
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        pass


def _setup_mounts(devs: dict[str, int]) -> None:
    # Everything below resolves inside the sandbox's own root. A symlink the
    # sandbox planted (e.g. /dev -> /etc) can only redirect a mount to
    # another place inside the sandbox.
    _ensure_dir("/proc", 0o555)
    _sys.mount("proc", "/proc", "proc", _sys.MS_NOSUID | _sys.MS_NODEV | _sys.MS_NOEXEC)
    _ensure_dir("/dev")
    _sys.mount("tmpfs", "/dev", "tmpfs", _sys.MS_NOSUID | _sys.MS_NOEXEC, "mode=755,size=64k")
    for name, fd in devs.items():
        p = f"/dev/{name}"
        os.close(os.open(p, os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC, 0o666))
        _sys.move_mount(fd, p)
        os.close(fd)
    os.mkdir("/dev/pts", 0o755)
    _sys.mount("devpts", "/dev/pts", "devpts", _sys.MS_NOSUID | _sys.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620")
    os.symlink("pts/ptmx", "/dev/ptmx")
    os.mkdir("/dev/shm", 0o1777)
    _sys.mount("tmpfs", "/dev/shm", "tmpfs", _sys.MS_NOSUID | _sys.MS_NODEV | _sys.MS_NOEXEC, "mode=1777,size=65536k")
    os.symlink("/proc/self/fd", "/dev/fd")
    for i, n in enumerate(("stdin", "stdout", "stderr")):
        os.symlink(f"/proc/self/fd/{i}", f"/dev/{n}")


# --------------------------------------------------------------------------- exec


def do_exec(spec: dict, fds: list[int]) -> int:
    result_w, pidfd, stdin_fd, stdout_fd, stderr_fd = fds
    emit = _Emitter(result_w)
    emit("started", pid=os.getpid())
    os.dup2(stdin_fd, 0)
    os.dup2(stdout_fd, 1)
    os.dup2(stderr_fd, 2)
    # Join the sandbox's cgroup first, while we are still plain host root.
    with open(os.path.join(spec["cgroup"], "cgroup.procs"), "w") as fh:
        fh.write(str(os.getpid()))
    # Non-dumpable: sandboxed root must not be able to ptrace or read /proc/<pid>/mem
    # of this process during the window where it is inside the sandbox's
    # namespaces but still a host-side helper. (It also is not in the sandbox's
    # PID namespace, so it is not visible there at all.)
    _sys.prctl(_sys.PR_SET_DUMPABLE, 0)
    _sys.close_fds_except([0, 1, 2, result_w, pidfd])
    _fault(spec, "exec_before_setns")
    os.setns(pidfd, ALL_NS)
    os.close(pidfd)
    os.setgroups([])
    uid, gid = spec.get("uid", 0), spec.get("gid", 0)
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    _sys.prctl(_sys.PR_SET_DUMPABLE, 0)  # changing uid resets dumpable; set it again
    os.chdir(spec.get("cwd") or "/")
    env = spec.get("env") or {"PATH": DEFAULT_PATH, "HOME": "/root"}
    cmd = spec["cmd"]
    f = os.fork()
    if f == 0:
        try:
            os.close(result_w)
            os.setsid()
            _sys.prctl(_sys.PR_SET_PDEATHSIG, signal.SIGKILL)
            os.execvpe(cmd[0], cmd, env)
        except OSError as e:
            os.write(2, f"sandboxd: cannot exec {cmd[0]!r}: {e.strerror}\n".encode())
        os._exit(127)
    emit("forked", pid=f)
    _, status = os.waitpid(f, 0)
    emit("exit", code=os.waitstatus_to_exitcode(status))
    return 0


# --------------------------------------------------------------------------- main


def load_init(path: str) -> int:
    """Copy sandbox-init into a sealed, read-only memfd.

    Sealing matters. Sandboxed root can open /proc/1/exe, and an unsealed
    memfd (mode 0777 by default) shared by every sandbox would let one
    sandbox rewrite the init of every future sandbox.
    """
    with open(path, "rb") as f:
        data = f.read()
    fd = os.memfd_create("sandbox-init", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(fd, data)
    os.fchmod(fd, 0o555)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
    return fd


def _reap(*_):
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def main() -> None:
    sock_fd, init_path = int(sys.argv[1]), sys.argv[2]
    _sys.prctl(_sys.PR_SET_PDEATHSIG, signal.SIGKILL)
    if os.getppid() == 1:
        sys.exit(0)
    _sys.prctl(_sys.PR_SET_CHILD_SUBREAPER, 1)
    _sys.set_name("sandboxd-zygote")
    init_fd = load_init(init_path)
    sock = socket.socket(fileno=sock_fd)
    signal.signal(signal.SIGCHLD, _reap)
    while True:
        msg, fds, _, _ = socket.recv_fds(sock, MSG_MAX, 16)
        if not msg:
            break
        req = json.loads(msg)
        pid = os.fork()
        if pid == 0:
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            sock.close()
            rc = 1
            try:
                if req["op"] == "launch":
                    rc = do_launch(req["spec"], fds, init_fd)
                elif req["op"] == "exec":
                    rc = do_exec(req["spec"], fds)
            except BaseException as e:  # noqa: BLE001
                try:
                    _Emitter(fds[0])("error", msg=f"{type(e).__name__}: {e}")
                except OSError:
                    pass
            os._exit(rc)
        for fd in fds:
            os.close(fd)


if __name__ == "__main__":
    main()
