"""Thin ctypes wrappers for the Linux syscalls Python's stdlib does not expose.

Everything here is a direct syscall or libc call. No sandbox toolkit is involved.
Python >= 3.12 already gives us os.unshare, os.setns, os.pidfd_open and
os.memfd_create; this file only covers the rest: mount(2), umount2(2),
pivot_root(2), the new mount API (open_tree / move_mount / mount_setattr),
prctl(2), and seccomp(2).
"""
from __future__ import annotations

import ctypes
import os
import platform

_libc = ctypes.CDLL(None, use_errno=True)
_libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
_libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
_libc.syscall.restype = ctypes.c_long
_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]

_MACHINE = platform.machine()
# open_tree, move_mount and mount_setattr use the unified syscall table (same
# number on every arch). pivot_root and seccomp do not.
_NR = {
    "x86_64": {"pivot_root": 155, "seccomp": 317},
    "aarch64": {"pivot_root": 41, "seccomp": 277},
}
if _MACHINE not in _NR:
    raise ImportError(f"unsupported architecture {_MACHINE!r} (x86_64 and aarch64 only)")
NR_PIVOT_ROOT = _NR[_MACHINE]["pivot_root"]
NR_SECCOMP = _NR[_MACHINE]["seccomp"]
NR_OPEN_TREE = 428
NR_MOVE_MOUNT = 429
NR_MOUNT_SETATTR = 442

# mount(2) flags
MS_RDONLY = 0x1
MS_NOSUID = 0x2
MS_NODEV = 0x4
MS_NOEXEC = 0x8
MS_REMOUNT = 0x20
MS_BIND = 0x1000
MS_REC = 0x4000
MS_PRIVATE = 1 << 18
MS_SLAVE = 1 << 19
MNT_DETACH = 2

# new mount API
AT_FDCWD = -100
AT_EMPTY_PATH = 0x1000
AT_RECURSIVE = 0x8000
OPEN_TREE_CLONE = 1
OPEN_TREE_CLOEXEC = os.O_CLOEXEC
MOVE_MOUNT_F_EMPTY_PATH = 0x4
MOUNT_ATTR_NOSUID = 0x2
MOUNT_ATTR_NODEV = 0x4
MOUNT_ATTR_IDMAP = 0x00100000

# prctl
PR_SET_PDEATHSIG = 1
PR_SET_DUMPABLE = 4
PR_SET_NAME = 15
PR_SET_SECCOMP = 22
PR_SET_NO_NEW_PRIVS = 38
PR_SET_CHILD_SUBREAPER = 36

CLONE_NEWNS = os.CLONE_NEWNS
CLONE_NEWUTS = os.CLONE_NEWUTS
CLONE_NEWIPC = os.CLONE_NEWIPC
CLONE_NEWUSER = os.CLONE_NEWUSER
CLONE_NEWPID = os.CLONE_NEWPID
CLONE_NEWNET = os.CLONE_NEWNET
CLONE_NEWCGROUP = os.CLONE_NEWCGROUP


class _MountAttr(ctypes.Structure):
    _fields_ = [
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    ]


def _check(ret, what):
    if ret < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"{what}: {os.strerror(e)}")
    return ret


def _b(s):
    if s is None:
        return None
    return s.encode() if isinstance(s, str) else s


def mount(source, target, fstype, flags=0, data=None):
    _check(_libc.mount(_b(source), _b(target), _b(fstype), flags, _b(data)), f"mount({source!r} -> {target!r}, {fstype!r})")


def umount2(target, flags=0):
    _check(_libc.umount2(_b(target), flags), f"umount2({target!r})")


def pivot_root(new_root, put_old):
    _check(_libc.syscall(NR_PIVOT_ROOT, _b(new_root), _b(put_old)), "pivot_root")


def open_tree(path, flags, dirfd=AT_FDCWD):
    return _check(_libc.syscall(NR_OPEN_TREE, ctypes.c_int(dirfd), _b(path), ctypes.c_uint(flags)), f"open_tree({path!r})")


def move_mount(from_fd, to_path, from_path="", to_dirfd=AT_FDCWD, flags=MOVE_MOUNT_F_EMPTY_PATH):
    _check(
        _libc.syscall(NR_MOVE_MOUNT, ctypes.c_int(from_fd), _b(from_path), ctypes.c_int(to_dirfd), _b(to_path), ctypes.c_uint(flags)),
        f"move_mount(-> {to_path!r})",
    )


def mount_setattr(fd, attr_set=0, attr_clr=0, userns_fd=0, flags=AT_EMPTY_PATH, path=""):
    attr = _MountAttr(attr_set, attr_clr, 0, userns_fd)
    _check(
        _libc.syscall(NR_MOUNT_SETATTR, ctypes.c_int(fd), _b(path), ctypes.c_uint(flags), ctypes.byref(attr), ctypes.c_size_t(ctypes.sizeof(attr))),
        "mount_setattr",
    )


def prctl(option, a2=0, a3=0, a4=0, a5=0):
    return _check(_libc.prctl(option, a2, a3, a4, a5), f"prctl({option})")


def set_name(name: str):
    buf = ctypes.create_string_buffer(name.encode()[:15])
    _check(_libc.prctl(PR_SET_NAME, ctypes.cast(buf, ctypes.c_void_p).value, 0, 0, 0), "prctl(PR_SET_NAME)")


def seccomp_set_filter(prog_ptr, flags=0):
    # SECCOMP_SET_MODE_FILTER = 1
    return _check(_libc.syscall(NR_SECCOMP, ctypes.c_uint(1), ctypes.c_uint(flags), prog_ptr), "seccomp(SET_MODE_FILTER)")


def close_fds_except(keep):
    """Close every fd except those in `keep` (used before entering a sandbox)."""
    # os.closerange uses close_range(2) on Linux, so a huge upper bound is cheap.
    lo = 0
    for k in sorted(set(keep)):
        if k > lo:  # closerange(n, n) becomes close_range(n, UINT_MAX): closes everything
            os.closerange(lo, k)
        lo = k + 1
    os.closerange(lo, 1 << 30)
