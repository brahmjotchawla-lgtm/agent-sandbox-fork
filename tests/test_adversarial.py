"""Phase 4 adversarial suite, part 1: root inside the sandbox tries to reach
the host. Each test is one concrete attack. Coverage table: DESIGN.md §5.6.
"""
from __future__ import annotations

import os

from conftest import py


def run(mgr, sid, code):
    r = py(mgr, sid, code)
    assert r["exit_code"] == 0, r["stderr"]
    return r["stdout"].strip()


def test_cannot_see_host_processes(mgr, sandbox):
    out = run(mgr, sandbox, "import os; print(any(('py' + 'test') in open(f'/proc/{p}/cmdline').read() "
                            "for p in os.listdir('/proc') if p.isdigit()))")
    assert out == "False"


def test_chroot_breakout_stays_inside(mgr, sandbox):
    """Classic double-chroot escape. After pivot_root + detaching the old
    root there is no host tree left in this mount namespace to climb to."""
    code = r"""
import os
os.makedirs('/tmp/jail', exist_ok=True)
fd = os.open('/', os.O_RDONLY)
os.chroot('/tmp/jail'); os.fchdir(fd)
for _ in range(64): os.chdir('..')
os.chroot('.')
print(os.path.exists('/root/marker'), os.path.exists('/home/user/agent-sandbox-fork'))
"""
    mgr.exec(sandbox, ["touch", "/root/marker"])
    assert run(mgr, sandbox, code) == "True False"


def test_proc_1_root_is_sandbox_root(mgr, sandbox):
    assert run(mgr, sandbox, "import os; print(os.path.exists('/proc/1/root/home/user/agent-sandbox-fork'))") == "False"


def test_cannot_mknod_or_mount_host_devices(mgr, sandbox):
    code = r"""
import os, ctypes
libc = ctypes.CDLL(None, use_errno=True)
res = []
try:
    os.mknod('/tmp/vda', 0o600 | 0o60000, os.makedev(253, 0)); res.append('mknod-ok')
except OSError as e: res.append(e.errno)
r = libc.mount(b'/dev/vda', b'/mnt', b'ext4', 0, None); res.append(ctypes.get_errno() if r else 'mount-ok')
print(res)
"""
    out = eval(run(mgr, sandbox, code))
    assert "mknod-ok" not in out and "mount-ok" not in out


def test_cannot_load_kernel_modules(mgr, sandbox):
    code = r"""
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
print((libc.syscall(175, None, 0, b''), ctypes.get_errno()))   # init_module
"""
    r, err = eval(run(mgr, sandbox, code))
    assert r == -1 and err in (1, 38)  # EPERM, or ENOSYS on kernels without modules


def test_reboot_only_kills_own_sandbox(mgr, sandbox):
    """reboot(2) in a child PID namespace kills that namespace's init.
    It must take down this sandbox only: not a sibling, not the host."""
    other = mgr.create_environment("base")["sandbox_id"]
    py(mgr, sandbox, "import ctypes; ctypes.CDLL(None).syscall(169, 0xfee1dead, 672274793, 0x4321FEDC, None)")
    st = mgr._load(sandbox)
    from control_plane.util import pid_alive, wait_until
    assert wait_until(lambda: not pid_alive(st["holder_pid"], st["holder_start"]), 5)
    assert mgr.exec(other, ["true"])["exit_code"] == 0


def test_host_sysctls_and_sysrq_not_writable(mgr, sandbox):
    code = r"""
res = []
for p in ('/proc/sysrq-trigger', '/proc/sys/kernel/hostname', '/proc/sys/vm/drop_caches'):
    try:
        open(p, 'w').write('1'); res.append(p)
    except OSError as e: res.append(e.errno)
print(res)
"""
    sysrq, hostname, drop_caches = eval(run(mgr, sandbox, code))
    assert isinstance(sysrq, int) and isinstance(drop_caches, int)
    # kernel.hostname is per-UTS-namespace: writing it renames only this sandbox.
    assert os.uname().nodename != "1"


def test_nested_userns_cannot_map_host_root(mgr, sandbox):
    code = r"""
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
assert libc.unshare(0x10000000) == 0
try:
    open('/proc/self/uid_map', 'w').write('0 0 1\n'); print('mapped')
except OSError as e: print('refused', e.errno)
"""
    # Mapping inner 0 to outer 0 is fine *inside our own* userns (outer 0 is
    # sandbox root = unprivileged host uid). What matters is the host view:
    out = run(mgr, sandbox, code + "\nprint(open('/proc/self/uid_map').read().split())")
    assert "mapped" in out or "refused" in out
    st = mgr._load(sandbox)
    with open(f"/proc/{st['holder_pid']}/uid_map") as f:
        assert f.read().split()[:3] == ["0", str(st["host_uid_base"]), "65536"]


def test_kill_all_only_hits_sandbox(mgr, sandbox):
    mgr.exec(sandbox, ["sh", "-c", "kill -9 -1; true"])
    assert os.getpid() > 0  # we are alive
    # PID 1 ignores signals it has no handler for, so the sandbox survives.
    assert mgr.exec(sandbox, ["true"])["exit_code"] == 0


def test_control_socket_not_visible(mgr, sandbox):
    assert run(mgr, sandbox, f"import os; print(os.path.exists({mgr.cfg.run_dir!r}))") == "False"
