"""seccomp-bpf filter for sandbox processes, assembled here as classic BPF (no libseccomp).

It is a DENY-list on top of user-namespace confinement, not an allow-list.
That is weaker than Docker's default profile (an allow-list), and DESIGN.md
§5.3 says so. What it blocks, and why:

  * every non-native syscall ABI: wrong `arch` (e.g. i386 via int 0x80 on
    x86_64) -> kill; x32 syscall numbers -> EPERM. Otherwise a deny-list is
    trivially bypassed by calling the same syscall under another ABI.
  * btrfs ioctls (ioctl type 0x94) -> EPERM (DESIGN.md §3: subvolume
    create/snapshot/inode-lookup from inside the sandbox).
  * new user namespaces (unshare/clone with CLONE_NEWUSER) -> EPERM. clone3
    -> ENOSYS, because its flags live in memory that seccomp cannot inspect,
    and glibc falls back to clone() on ENOSYS (Docker does the same).
  * mounting and the new mount API: sandboxed root owns its mount
    namespace and could otherwise mount filesystems that are reachable from
    a user namespace. That is a large kernel attack surface.
  * io_uring: large kernel attack surface, and it bypasses syscall
    filtering for the operations it submits.
  * keyrings (not namespaced), bpf, perf_event_open, userfaultfd, kexec,
    module loading, open_by_handle_at, swap, reboot, acct, quotactl, syslog.
    Most of these already need capabilities in the initial user namespace.
    Blocking them is defense in depth.
"""
from __future__ import annotations

import ctypes
import errno
import platform
import struct

from . import _sys

AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
X32_SYSCALL_BIT = 0x40000000

RET_KILL_PROCESS = 0x80000000
RET_ALLOW = 0x7FFF0000


def RET_ERRNO(e: int) -> int:
    return 0x00050000 | (e & 0xFFFF)


_NR = {
    "x86_64": {
        "add_key": 248, "keyctl": 250, "request_key": 249, "bpf": 321, "perf_event_open": 298,
        "userfaultfd": 323, "kexec_load": 246, "kexec_file_load": 320, "init_module": 175,
        "finit_module": 313, "delete_module": 176, "open_by_handle_at": 304, "acct": 163,
        "swapon": 167, "swapoff": 168, "reboot": 169, "mount": 165, "umount2": 166,
        "pivot_root": 155, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433,
        "move_mount": 429, "open_tree": 428, "mount_setattr": 442, "io_uring_setup": 425,
        "io_uring_enter": 426, "io_uring_register": 427, "syslog": 103, "quotactl": 179,
        "unshare": 272, "clone": 56, "clone3": 435, "ioctl": 16,
    },
    "aarch64": {
        "add_key": 217, "keyctl": 219, "request_key": 218, "bpf": 280, "perf_event_open": 241,
        "userfaultfd": 282, "kexec_load": 104, "kexec_file_load": 294, "init_module": 105,
        "finit_module": 273, "delete_module": 106, "open_by_handle_at": 265, "acct": 89,
        "swapon": 224, "swapoff": 225, "reboot": 142, "mount": 40, "umount2": 39,
        "pivot_root": 41, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433,
        "move_mount": 429, "open_tree": 428, "mount_setattr": 442, "io_uring_setup": 425,
        "io_uring_enter": 426, "io_uring_register": 427, "syslog": 116, "quotactl": 60,
        "unshare": 97, "clone": 220, "clone3": 435, "ioctl": 29,
    },
}

DENY = [
    "add_key", "keyctl", "request_key", "bpf", "perf_event_open", "userfaultfd", "kexec_load",
    "kexec_file_load", "init_module", "finit_module", "delete_module", "open_by_handle_at", "acct",
    "swapon", "swapoff", "reboot", "mount", "umount2", "pivot_root", "fsopen", "fsconfig", "fsmount",
    "fspick", "move_mount", "open_tree", "mount_setattr", "io_uring_setup", "io_uring_enter",
    "io_uring_register", "syslog", "quotactl",
]
BTRFS_IOCTL_TYPE = 0x94
CLONE_NEWUSER = 0x10000000

# seccomp_data offsets
OFF_NR, OFF_ARCH = 0, 4


def OFF_ARG_LO(i: int) -> int:
    return 16 + 8 * i  # little-endian: low 32 bits first


# classic BPF opcodes
LD_W_ABS = 0x20
JEQ_K = 0x15
JGE_K = 0x35
JSET_K = 0x45
RET_K = 0x06
ALU_RSH_K = 0x74
ALU_AND_K = 0x54


class _Asm:
    """Minimal cBPF assembler with forward labels (cBPF jumps are forward-only, <= 255)."""

    def __init__(self):
        self.ins: list[tuple] = []
        self.labels: dict[str, int] = {}

    def label(self, name):
        self.labels[name] = len(self.ins)

    def stmt(self, code, k):
        self.ins.append((code, 0, 0, k))

    def jump(self, code, k, jt, jf):
        self.ins.append((code, jt, jf, k))  # jt/jf: label name or 0 (fall through)

    def assemble(self) -> list[tuple[int, int, int, int]]:
        out = []
        for i, (code, jt, jf, k) in enumerate(self.ins):
            def rel(t):
                if t == 0:
                    return 0
                off = self.labels[t] - i - 1
                if not 0 <= off <= 255:
                    raise ValueError(f"jump to {t} out of range ({off})")
                return off
            out.append((code, rel(jt), rel(jf), k))
        return out


def build(machine: str | None = None) -> list[tuple[int, int, int, int]]:
    machine = machine or platform.machine()
    nr = _NR[machine]
    a = _Asm()
    a.stmt(LD_W_ABS, OFF_ARCH)
    a.jump(JEQ_K, AUDIT_ARCH[machine], 0, "kill")
    a.stmt(LD_W_ABS, OFF_NR)
    if machine == "x86_64":
        a.jump(JGE_K, X32_SYSCALL_BIT, "eperm", 0)
    for name in DENY:
        a.jump(JEQ_K, nr[name], "eperm", 0)
    a.jump(JEQ_K, nr["clone3"], "enosys", 0)
    a.jump(JEQ_K, nr["unshare"], "check_newuser", 0)
    a.jump(JEQ_K, nr["clone"], "check_newuser", 0)
    a.jump(JEQ_K, nr["ioctl"], "check_ioctl", 0)
    a.stmt(RET_K, RET_ALLOW)

    a.label("check_newuser")  # arg0 = flags for both unshare(2) and clone(2)
    a.stmt(LD_W_ABS, OFF_ARG_LO(0))
    a.jump(JSET_K, CLONE_NEWUSER, "eperm", 0)
    a.stmt(RET_K, RET_ALLOW)

    a.label("check_ioctl")  # arg1 = request; _IOC_TYPE(request) = (request >> 8) & 0xff
    a.stmt(LD_W_ABS, OFF_ARG_LO(1))
    a.stmt(ALU_RSH_K, 8)
    a.stmt(ALU_AND_K, 0xFF)
    a.jump(JEQ_K, BTRFS_IOCTL_TYPE, "eperm", 0)
    a.stmt(RET_K, RET_ALLOW)

    a.label("eperm")
    a.stmt(RET_K, RET_ERRNO(errno.EPERM))
    a.label("enosys")
    a.stmt(RET_K, RET_ERRNO(errno.ENOSYS))
    a.label("kill")
    a.stmt(RET_K, RET_KILL_PROCESS)
    return a.assemble()


def default_policy() -> list[list[int]]:
    """JSON-serialisable program, passed from the control plane to launch/exec helpers."""
    return [list(i) for i in build()]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def install(prog: list) -> None:
    """Install the filter on the calling thread (inherited across fork and execve).

    Needs NO_NEW_PRIVS or CAP_SYS_ADMIN in the caller's user namespace. Callers
    set NO_NEW_PRIVS first.
    """
    raw = b"".join(struct.pack("HBBI", c, jt, jf, k) for c, jt, jf, k in prog)
    buf = ctypes.create_string_buffer(raw, len(raw))
    fprog = _SockFprog(len(prog), ctypes.cast(buf, ctypes.c_void_p).value)
    # SECCOMP_FILTER_FLAG_TSYNC (1) is unnecessary: helpers are single-threaded.
    _sys.seccomp_set_filter(ctypes.byref(fprog))
