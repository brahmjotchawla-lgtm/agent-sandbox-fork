"""Phase 4 adversarial suite, part 2. Root inside the sandbox throughout.

Focus: the trusted control plane handling sandbox-controlled files, state
leaking across the exec boundary, cross-namespace IPC, and the proxy as a
shared service (DESIGN.md §5.3). Coverage table: DESIGN.md §5.6.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid

from conftest import py
from control_plane.util import wait_until


def out(mgr, sid, code, *args):
    r = mgr.exec(sid, ["python3", "-c", code, *args], timeout=60)
    assert r["exit_code"] == 0, r
    return r["stdout"].strip()


# ---- control plane touching sandbox-controlled files ------------------------

def test_symlinks_to_host_survive_fork_and_destroy(mgr, sandbox):
    """The sandbox plants symlinks aimed at a host directory. Snapshot/copy
    and destroy run as host root on the sandbox's files; none may follow
    them."""
    canary = f"/var/tmp/sbx-canary-{uuid.uuid4().hex[:8]}"
    os.makedirs(canary)
    with open(f"{canary}/keep", "w") as f:
        f.write("host data")
    try:
        mgr.exec(sandbox, ["sh", "-c", f"""
            ln -s {canary} /root/abs
            ln -s ../../../../../../..{canary} /root/rel
            mkdir -p /root/d && ln -s {canary}/keep /root/d/file
            ln -s /root/loop /root/loop
        """])
        child = mgr.fork(sandbox)["sandbox_id"]
        mgr.destroy(child)
        mgr.destroy(sandbox)
        assert open(f"{canary}/keep").read() == "host data"
        assert os.listdir(canary) == ["keep"]
    finally:
        shutil.rmtree(canary)


def test_sandbox_mounts_do_not_reach_forks_or_host(mgr, sandbox):
    """Mounts made by sandbox root live in its mount namespace only; a fork
    snapshots the on-disk tree, not the parent's mount table."""
    r = py(mgr, sandbox, r"""
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
os.makedirs('/root/m', exist_ok=True)
assert libc.mount(b'tmpfs', b'/root/m', b'tmpfs', 0, None) == 0, ctypes.get_errno()
open('/root/m/in-tmpfs', 'w').write('x')
""")
    assert r["exit_code"] == 0, r
    child = mgr.fork(sandbox)["sandbox_id"]
    assert mgr.exec(child, ["test", "-e", "/root/m/in-tmpfs"])["exit_code"] == 1
    with open("/proc/self/mountinfo") as f:
        assert "/root/m" not in f.read()


def test_hostile_filenames_do_not_break_destroy(mgr, sandbox):
    mgr.exec(sandbox, ["python3", "-c", r"""
import os
for n in ['a\nb', ' lead', '-rf', '..weird', 'x' * 255]:
    open(os.path.join('/root', n), 'w').close()
os.makedirs('/root/' + '/'.join(['d'] * 200), exist_ok=True)
os.chmod('/root', 0)
"""])
    subvol = mgr._load(sandbox)["subvol"]
    mgr.destroy(sandbox)
    assert not os.path.exists(subvol)


# ---- nothing crosses the exec boundary --------------------------------------

def test_exec_leaks_no_host_fds_or_env(mgr, sandbox, monkeypatch):
    monkeypatch.setenv("SBX_HOST_SECRET", "must-not-leak")
    keep = open("/etc/hostname")  # an fd the control plane holds open
    try:
        res = json.loads(out(mgr, sandbox, r"""
import json, os
print(json.dumps({"fds": sorted(int(f) for f in os.listdir('/proc/self/fd')),
                  "env": sorted(os.environ)}))
"""))
    finally:
        keep.close()
    assert res["fds"] == [0, 1, 2, 3], res  # 3 = the listdir handle itself
    assert "SBX_HOST_SECRET" not in res["env"]


def test_host_abstract_unix_socket_unreachable(mgr, sandbox):
    """Abstract unix sockets are scoped to the network namespace, a known
    container-escape channel when the netns is shared (e.g. CVE-2020-15257)."""
    name = f"sbx-host-{uuid.uuid4().hex[:8]}"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind("\0" + name)
    srv.listen(1)
    try:
        res = out(mgr, sandbox, r"""
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('\0' + sys.argv[1]); print('CONNECTED')
except OSError as e:
    print('BLOCKED', e.errno)
""", name)
        assert res.startswith("BLOCKED"), res
    finally:
        srv.close()


def test_sibling_ipc_isolated(mgr, sandbox):
    """SysV shared memory is per-IPC-namespace; a sibling cannot attach."""
    other = mgr.create_environment("base")["sandbox_id"]
    code = r"""
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
IPC_CREAT = 0o1000
key = 0x5B0C
if sys.argv[1] == 'create':
    print(libc.shmget(key, 4096, IPC_CREAT | 0o666) >= 0)
else:
    print(libc.shmget(key, 4096, 0o666), ctypes.get_errno())
"""
    assert out(mgr, sandbox, code, "create") == "True"
    shmid, err = out(mgr, other, code, "open").split()
    assert shmid == "-1" and err == "2"  # ENOENT


# ---- the proxy as a shared service -------------------------------------------

def _proxy(mgr, sid):
    return mgr._load(sid)["net"]["proxy"].split("//")[1]


PROXY_REQ = r"""
import socket, sys
h, p = sys.argv[1].split(':')
s = socket.create_connection((h, int(p)), timeout=5)
s.sendall(sys.argv[2].encode().decode('unicode_escape').encode('latin-1'))
data = b''
try:
    while c := s.recv(4096):
        data += c
except OSError:
    pass
print(data.decode(errors='replace').split('\r\n')[0] or 'CLOSED')
"""


def test_proxy_refuses_to_connect_to_itself(mgr, sandbox):
    gw = mgr._load(sandbox)["net"]["gateway"]
    port = mgr.cfg.proxy_port
    for target in (f"{gw}:{port}", f"127.0.0.1:{port}", f"localhost:{port}"):
        res = out(mgr, sandbox, PROXY_REQ, _proxy(mgr, sandbox), f"CONNECT {target} HTTP/1.1\\r\\n\\r\\n")
        assert "403" in res, (target, res)


def test_proxy_has_no_admin_surface(mgr, sandbox):
    for req in ("GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n", "GET /admin HTTP/1.1\\r\\n\\r\\n",
                "DELETE / HTTP/1.1\\r\\n\\r\\n", "OPTIONS * HTTP/1.1\\r\\n\\r\\n",
                "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"):
        res = out(mgr, sandbox, PROXY_REQ, _proxy(mgr, sandbox), req)
        assert res.startswith("HTTP/1.1 405"), (req, res)


def test_proxy_survives_malformed_and_oversized_requests(mgr, sandbox, upstream):
    for req in ("\\x00\\xff\\xfe garbage\\r\\n\\r\\n", "CONNECT\\r\\n\\r\\n",
                "CONNECT a:b:c HTTP/1.1\\r\\n\\r\\n", "CONNECT host:99999 HTTP/1.1\\r\\n\\r\\n",
                "CONNECT " + "a" * 20000 + ":443 HTTP/1.1\\r\\n\\r\\n"):
        out(mgr, sandbox, PROXY_REQ, _proxy(mgr, sandbox), req)
    ok = out(mgr, sandbox, PROXY_REQ, _proxy(mgr, sandbox),
             f"CONNECT 127.0.0.1:{upstream.port} HTTP/1.1\\r\\n\\r\\n")
    assert "200" in ok


HOG = r"""
import socket, sys, time
h, p = sys.argv[1].split(':')
socks, refused = [], 0
for _ in range(80):
    s = socket.create_connection((h, int(p)), timeout=5)
    socks.append(s)
time.sleep(0.5)
for s in socks:
    s.setblocking(False)
    try:
        if s.recv(1) == b'':
            refused += 1
    except BlockingIOError:
        pass
open('/tmp/hog', 'w').write(str(refused))
time.sleep(float(sys.argv[2]))
"""


def test_one_sandbox_cannot_starve_siblings_of_the_proxy(mgr, sandbox, upstream):
    """A holds idle half-open connections (slowloris). It is capped per peer,
    and a sibling still gets service while A's connections are held."""
    other = mgr.create_environment("base")["sandbox_id"]
    proxy = _proxy(mgr, sandbox)
    mgr.exec(sandbox, ["sh", "-c", f"python3 -c \"$0\" {proxy} 8 >/dev/null 2>&1 &", HOG])
    assert wait_until(lambda: mgr.exec(sandbox, ["test", "-e", "/tmp/hog"])["exit_code"] == 0, 15)
    refused = int(mgr.exec(sandbox, ["cat", "/tmp/hog"])["stdout"])
    assert refused >= 80 - 64, f"per-peer cap not applied ({refused} of 80 refused)"
    t = time.monotonic()
    res = out(mgr, other, PROXY_REQ, _proxy(mgr, other),
              f"CONNECT 127.0.0.1:{upstream.port} HTTP/1.1\\r\\n\\r\\n")
    assert "200" in res and time.monotonic() - t < 5, res


# ---- exec supervision --------------------------------------------------------

ESCAPER = r"""
import os, time
os.setsid()
if os.fork():           # double fork: the grandchild is orphaned immediately
    os._exit(0)
os.setsid()
if os.fork():
    os._exit(0)
open('/tmp/escaper.pid', 'w').write(str(os.getpid()))
while True:
    time.sleep(1)
"""


def test_exec_timeout_kills_setsid_and_double_forked_descendants(mgr, sandbox):
    t = time.monotonic()
    r = mgr.exec(sandbox, ["sh", "-c", f"python3 -c \"$0\"; sleep 600", ESCAPER], timeout=2)
    assert r["timed_out"] and time.monotonic() - t < 10
    pid = mgr.exec(sandbox, ["cat", "/tmp/escaper.pid"])["stdout"].strip()
    assert pid
    assert mgr.exec(sandbox, ["test", "-e", f"/proc/{pid}"])["exit_code"] == 1, \
        "escaped process survived the exec timeout"


def test_background_processes_survive_normal_exec_exit(mgr, sandbox):
    """Deliberate daemons (nohup x &) must outlive the exec that started them."""
    mgr.exec(sandbox, ["sh", "-c", "nohup sleep 600 >/dev/null 2>&1 & echo $! > /tmp/bg"])
    pid = mgr.exec(sandbox, ["cat", "/tmp/bg"])["stdout"].strip()
    time.sleep(0.3)
    assert mgr.exec(sandbox, ["test", "-e", f"/proc/{pid}"])["exit_code"] == 0


def test_host_side_helpers_not_inspectable_from_sandbox(mgr, sandbox):
    """PID 1 and the exec supervisor are host binaries running in the
    sandbox's PID namespace. Sandbox root must not be able to open their
    /proc/<pid>/exe, mem or environ (the CVE-2019-5736 class of attack)."""
    mgr.exec(sandbox, ["sh", "-c", "sleep 30 >/dev/null 2>&1 &"])
    code = r"""
import os, json
res = {}
for p in os.listdir('/proc'):
    if not p.isdigit() or int(p) == os.getpid():  # our own source mentions nsinit.py
        continue
    try:
        cmd = open(f'/proc/{p}/cmdline', 'rb').read()
    except OSError:
        continue
    if b'nsinit.py' not in cmd:
        continue
    for f in ('exe', 'mem', 'environ'):
        try:
            os.close(os.open(f'/proc/{p}/{f}', os.O_RDONLY)); res[f'{p}/{f}'] = 'OPENED'
        except OSError as e:
            res[f'{p}/{f}'] = e.errno
print(json.dumps(res))
"""
    res = json.loads(out(mgr, sandbox, code))
    assert len(res) >= 6, res  # PID 1 + the supervisor running this probe, 3 files each
    assert "OPENED" not in res.values(), res


# ---- a compromised proxy ----------------------------------------------------

AS_PROXY = r"""
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect((sys.argv[1], int(sys.argv[2]))); print('CONNECTED')
except OSError as e:
    print('BLOCKED', type(e).__name__)
"""


def _connect_as(uid, host, port):
    return subprocess.run([sys.executable, "-I", "-c", AS_PROXY, host, str(port)], user=uid,
                          group=uid, capture_output=True, text=True, timeout=30).stdout.strip()


def test_compromised_proxy_cannot_pivot_to_host_services(mgr, upstream):
    """Run attacker code as the proxy's uid in the host netns: what an RCE
    in the proxy would get. The kernel must hold it to the allowlist, while
    another uid can reach the same host services (control)."""
    uid = mgr.cfg.proxy_uid
    listener = socket.socket()
    listener.bind(("0.0.0.0", 0))
    listener.listen(16)
    port = listener.getsockname()[1]
    try:
        host_ip = next(ip for ip in subprocess.run(["hostname", "-I"], capture_output=True,
                                                   text=True).stdout.split() if ":" not in ip)
        for target in ("127.0.0.1", host_ip):
            assert _connect_as(65534, target, port) == "CONNECTED", "control failed"
            assert _connect_as(uid, target, port).startswith("BLOCKED"), target
        assert _connect_as(uid, "169.254.169.254", 80).startswith("BLOCKED")
        # ...while what the allowlist names still works.
        assert _connect_as(uid, "127.0.0.1", upstream.port) == "CONNECTED"
    finally:
        listener.close()
