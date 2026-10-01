"""Process-side half of the sandbox runtime: namespace setup and PID 1.

Run by the control plane as host root, directly as a script
(``python3 -I control_plane/nsinit.py ...``) so it imports nothing but the
stdlib. Two modes:

``holder``  Create a sandbox's namespaces and become its PID 1.
``exec``    Run one command in a sandbox (the control plane's ``exec``):
            join its cgroup and namespaces, then supervise the command as
            a child subreaper so a timeout can kill everything it started.
``enter``   Join the cgroup, apply seccomp, exec an arbitrary host command
            (used by tests to give the adversary host tools such as ip/nft
            with exactly sandbox-root privileges).

Both modes set no_new_privs and install the seccomp filter *before* any
sandbox code can run, so every process in a sandbox inherits them.

Holder sequence (host root -> sandbox root):

1. join the sandbox cgroup (so every descendant is accounted to it)
2. no_new_privs + seccomp
3. unshare(CLONE_NEWUSER); a helper child still in the host user namespace
   writes uid_map/gid_map mapping sandbox 0..65535 to a per-sandbox host
   range. After this we hold no capabilities in the host user namespace.
4. setresuid/setresgid to 0 (= the unprivileged host uid of this sandbox)
5. unshare mount, UTS, IPC, net, PID and cgroup namespaces
6. fork: the child is PID 1 of the new PID namespace. It builds the mount
   table on the idmapped rootfs, pivot_roots, prints READY, and reaps.
   The parent waits so its exit status reflects the sandbox's lifetime.
"""
import ctypes
import os
import signal
import struct
import sys

CLONE_NEWNS = 0x00020000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

MS_NOSUID = 0x2
MS_NODEV = 0x4
MS_NOEXEC = 0x8
MS_BIND = 0x1000
MS_REC = 0x4000
MS_PRIVATE = 1 << 18
MNT_DETACH = 2

PR_SET_PDEATHSIG = 1
PR_SET_DUMPABLE = 4
PR_SET_CHILD_SUBREAPER = 36
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# x86_64 syscall numbers; the control plane refuses to run on other arches.
SYS_pivot_root = 155
NR_ioctl = 16
AUDIT_ARCH_X86_64 = 0xC000003E
X32_SYSCALL_BIT = 0x40000000

# classic BPF opcodes
BPF_LD_W_ABS = 0x20
BPF_JEQ_K = 0x15
BPF_JGE_K = 0x35
BPF_AND_K = 0x54
BPF_RET_K = 0x06
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
EPERM = 1
BTRFS_IOCTL_MAGIC = 0x94

HOST_RANGE = 65536

libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_char_p]
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                       ctypes.c_ulong, ctypes.c_ulong]


def check(ret, what):
    if ret != 0:
        e = ctypes.get_errno()
        raise OSError(e, "%s: %s" % (what, os.strerror(e)))


def mount(src, dst, fstype, flags, data=None):
    check(libc.mount(src.encode() if src else None, dst.encode(),
                     fstype.encode() if fstype else None, flags,
                     data.encode() if data else None), "mount %s" % dst)


def seccomp_program():
    """Filter: kill non-x86_64 and x32 syscalls; EPERM any btrfs ioctl.

    btrfs ioctls all use type byte 0x94 in the request number (bits 8-15),
    so masking the second argument covers subvolume create/delete/snapshot,
    INO_LOOKUP, TREE_SEARCH, send, etc. The 32-bit (int 0x80) and x32 ABIs
    are killed outright because their syscall numbers differ and a filter
    keyed on x86_64 numbers would not see ioctl there.
    """
    def stmt(code, k, jt=0, jf=0):
        return struct.pack("HBBI", code, jt, jf, k)
    return b"".join([
        stmt(BPF_LD_W_ABS, 4),                                  # 0: A = arch
        stmt(BPF_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),               # 1
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),              # 2
        stmt(BPF_LD_W_ABS, 0),                                  # 3: A = nr
        stmt(BPF_JGE_K, X32_SYSCALL_BIT, 0, 1),                 # 4
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),              # 5
        stmt(BPF_JEQ_K, NR_ioctl, 0, 3),                        # 6
        stmt(BPF_LD_W_ABS, 24),                                 # 7: A = low32(args[1])
        stmt(BPF_AND_K, 0xFF00),                                # 8
        stmt(BPF_JEQ_K, BTRFS_IOCTL_MAGIC << 8, 1, 0),          # 9
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),                     # 10
        stmt(BPF_RET_K, SECCOMP_RET_ERRNO | EPERM),             # 11
    ])


def harden():
    """no_new_privs + seccomp. Inherited across fork and execve."""
    check(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "no_new_privs")
    prog = seccomp_program()
    buf = ctypes.create_string_buffer(prog, len(prog))
    fprog = ctypes.create_string_buffer(
        struct.pack("HxxxxxxQ", len(prog) // 8, ctypes.addressof(buf)))
    check(libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                     ctypes.addressof(fprog), 0, 0), "seccomp")


def join_cgroup(cgroup):
    if cgroup:
        with open(os.path.join(cgroup, "cgroup.procs"), "w") as f:
            f.write(str(os.getpid()))


def write_id_maps(pid, host_base):
    line = "0 %d %d\n" % (host_base, HOST_RANGE)
    for name in ("uid_map", "gid_map"):
        with open("/proc/%d/%s" % (pid, name), "w") as f:
            f.write(line)


def pid1(rootfs, hostname):
    """Runs as PID 1 of the sandbox, root in its user namespace."""
    host_pid = int(os.readlink("/proc/self"))  # still the host's procfs

    mount(None, "/", None, MS_REC | MS_PRIVATE)
    # The rootfs mount copied from the host namespace is locked (it came from
    # a more privileged mount namespace), so bind it again to get a mount this
    # namespace owns. The bind keeps the idmapping.
    mount(rootfs, rootfs, None, MS_BIND | MS_REC)

    proc = os.path.join(rootfs, "proc")
    os.makedirs(proc, exist_ok=True)
    mount("proc", proc, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)

    dev = os.path.join(rootfs, "dev")
    os.makedirs(dev, exist_ok=True)
    mount("tmpfs", dev, "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=755,size=64k")
    for name in ("null", "zero", "full", "random", "urandom", "tty"):
        target = os.path.join(dev, name)
        open(target, "w").close()
        mount("/dev/" + name, target, None, MS_BIND)
    os.makedirs(os.path.join(dev, "pts"))
    mount("devpts", os.path.join(dev, "pts"), "devpts", MS_NOSUID | MS_NOEXEC,
          "newinstance,ptmxmode=0666,mode=620")
    os.symlink("pts/ptmx", os.path.join(dev, "ptmx"))
    os.makedirs(os.path.join(dev, "shm"))
    mount("tmpfs", os.path.join(dev, "shm"), "tmpfs", MS_NOSUID | MS_NODEV,
          "mode=1777,size=64m")
    for fd, name in ((0, "stdin"), (1, "stdout"), (2, "stderr")):
        os.symlink("/proc/self/fd/%d" % fd, os.path.join(dev, name))

    check(libc.sethostname(hostname.encode(), len(hostname)), "sethostname")

    os.chdir(rootfs)
    check(libc.syscall(SYS_pivot_root, b".", b"."), "pivot_root")
    check(libc.umount2(b".", MNT_DETACH), "detach host root")
    os.chdir("/")

    sys.stdout.write("READY %d\n" % host_pid)
    sys.stdout.flush()
    devnull = os.open("/dev/null", os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)

    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    while True:
        try:
            os.wait()
        except ChildProcessError:
            signal.pause()


def holder(cgroup, host_base, rootfs, hostname):
    join_cgroup(cgroup)
    harden()

    r, w = os.pipe()
    mapper = os.fork()
    if mapper == 0:  # still host root in the host user namespace
        os.close(w)
        os.read(r, 1)
        write_id_maps(os.getppid(), host_base)
        os._exit(0)
    os.close(r)
    check(libc.unshare(CLONE_NEWUSER), "unshare user")
    os.write(w, b"x")
    os.close(w)
    _, status = os.waitpid(mapper, 0)
    if status != 0:
        raise RuntimeError("writing uid/gid maps failed")
    os.setgroups([0])
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)

    check(libc.unshare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET
                       | CLONE_NEWPID | CLONE_NEWCGROUP), "unshare namespaces")
    child = os.fork()
    if child == 0:
        try:
            check(libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0), "pdeathsig")
            pid1(rootfs, hostname)
        except BaseException as exc:
            sys.stdout.write("FAILED %r\n" % (exc,))
            sys.stdout.flush()
        os._exit(1)
    # Forward termination to the sandbox; our exit status mirrors PID 1's.
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda s, _f: os.kill(child, signal.SIGKILL))
    _, status = os.waitpid(child, 0)
    os._exit(os.waitstatus_to_exitcode(status) & 0xFF)


NS_ORDER = ("user", "mnt", "uts", "ipc", "net", "cgroup", "pid")


def exit_like(status):
    """Exit the way a child with this wait status did (signal or code)."""
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        signal.signal(sig, signal.SIG_DFL)
        os.kill(os.getpid(), sig)
    os._exit(os.waitstatus_to_exitcode(status) & 0xFF)


def descendants(root):
    """All live descendants of pid ``root`` (pids as seen in our /proc)."""
    parent = {}
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                with open("/proc/%s/stat" % p) as f:
                    parent[int(p)] = int(f.read().rsplit(")", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                pass
    out, frontier = [], [root]
    while frontier:
        kids = [p for p, pp in parent.items() if pp in frontier]
        out += kids
        frontier = kids
    return out


def kill_tree(rounds=200):
    """SIGKILL every descendant, repeating until none are left (a process
    may fork between our scan and our kill). Orphans re-parent to us because
    we are a child subreaper, so nothing can leave the tree by
    double-forking or setsid()."""
    me = os.getpid()
    for _ in range(rounds):
        victims = descendants(me)
        if not victims:
            return True
        for v in victims:
            try:
                os.kill(v, signal.SIGKILL)
            except ProcessLookupError:
                pass
        while True:
            try:
                if os.waitpid(-1, os.WNOHANG)[0] == 0:
                    break
            except ChildProcessError:
                break
    return False


def execvp_noimport(argv):
    """execvp without os.execvpe, which lazily imports stdlib modules that
    no longer exist once we are inside the sandbox's mount namespace.
    Returns the error if no candidate could be executed."""
    env = dict(os.environ)
    names = [argv[0]] if "/" in argv[0] else [
        d.rstrip("/") + "/" + argv[0] for d in env.get("PATH", "/usr/bin:/bin").split(":") if d]
    err = OSError(2, "No such file or directory")
    for path in names:
        try:
            os.execve(path, argv, env)
        except OSError as e:
            if e.errno != 2 or err.errno == 2:  # prefer EACCES etc. over ENOENT
                err = e
    return err


def supervise(argv):
    """Runs inside the sandbox PID namespace as the command's parent."""
    check(libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0), "subreaper")
    # If the host-side wrapper dies (e.g. SIGKILLed), take the tree down.
    check(libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0), "pdeathsig")

    def on_term(*_):
        kill_tree()
        os._exit(137)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, on_term)
    cmd = os.fork()
    if cmd == 0:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_DFL)
        e = execvp_noimport(argv)
        os.write(2, ("exec %s: %s\n" % (argv[0], e.strerror)).encode())
        os._exit(127 if e.errno == 2 else 126)
    while True:
        pid, status = os.wait()
        if pid == cmd:
            # Background processes the command started on purpose keep
            # running: when we exit they re-parent to the sandbox's PID 1.
            exit_like(status)


def sandbox_exec(cgroup, target, cwd, argv):
    """exec mode: host root -> sandbox root, then fork into its PID ns."""
    join_cgroup(cgroup)
    harden()
    fds = [(os.open("/proc/%d/ns/%s" % (target, n), os.O_RDONLY), n) for n in NS_ORDER]
    for fd, name in fds:  # user first: afterwards we hold no host capabilities
        check(libc.setns(fd, 0), "setns " + name)
        os.close(fd)
    os.setgroups([0])
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)
    # This process runs a host binary inside the sandbox's view; make sure
    # sandbox root cannot open its /proc/<pid>/{exe,mem,environ} or ptrace it.
    check(libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0), "dumpable")
    os.chdir(cwd)  # setns(mnt) already moved our root to the sandbox root
    child = os.fork()
    if child == 0:
        supervise(argv)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda s, _f: os.kill(child, signal.SIGTERM))
    _, status = os.waitpid(child, 0)
    exit_like(status)


def enter(cgroup, argv):
    join_cgroup(cgroup)
    harden()
    os.execvp(argv[0], argv)


def main(argv):
    try:
        if argv[0] == "holder":
            # holder CGROUP|- HOST_UID_BASE ROOTFS HOSTNAME
            cg = None if argv[1] == "-" else argv[1]
            holder(cg, int(argv[2]), argv[3], argv[4])
        elif argv[0] == "exec":
            # exec CGROUP|- HOLDER_PID CWD -- CMD...
            cg = None if argv[1] == "-" else argv[1]
            if argv[4] != "--" or len(argv) < 6:
                raise SystemExit("usage: exec CGROUP PID CWD -- CMD...")
            sandbox_exec(cg, int(argv[2]), argv[3], argv[5:])
        elif argv[0] == "enter":
            # enter CGROUP|- -- CMD...
            cg = None if argv[1] == "-" else argv[1]
            if argv[2] != "--":
                raise SystemExit("usage: enter CGROUP -- CMD...")
            enter(cg, argv[3:])
        else:
            raise SystemExit("unknown mode %r" % argv[0])
    except (OSError, RuntimeError) as exc:
        sys.stdout.write("FAILED %r\n" % (exc,))
        sys.stdout.flush()
        os._exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
