"""The sandbox-wide seccomp filter and no_new_privs (DESIGN.md §3, §5.3)."""
from __future__ import annotations

from conftest import py

IOCTL = r"""
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
fd = os.open('/', os.O_RDONLY)
def call(req):
    r = libc.ioctl(fd, ctypes.c_ulong(req), ctypes.c_void_p(0))
    return r, ctypes.get_errno()
# BTRFS_IOC_SUBVOL_CREATE = _IOW(0x94, 14, 4096-byte struct); also try a
# request with the 0x94 type byte in an otherwise odd encoding.
print(repr((call(0x5000940E), call(0x0000940E), call(0x00005401 | 0xFFFF0000))))
"""


def test_btrfs_ioctls_blocked(mgr, sandbox):
    out = py(mgr, sandbox, IOCTL)["stdout"]
    btrfs1, btrfs2, other = eval(out)
    assert btrfs1 == (-1, 1) and btrfs2 == (-1, 1)  # EPERM from seccomp
    assert other[1] != 1  # unrelated ioctls reach the kernel (ENOTTY etc.)


def test_no_new_privs_and_seccomp_on_every_process(mgr, sandbox):
    r = mgr.exec(sandbox, ["sh", "-c", "grep -E '^(NoNewPrivs|Seccomp):' /proc/1/status /proc/self/status"])
    lines = r["stdout"].split("\n")
    assert sum("NoNewPrivs:\t1" in l for l in lines) == 2, r["stdout"]
    assert sum("Seccomp:\t2" in l for l in lines) == 2, r["stdout"]
