"""Phase 4: adversarial tests. The attacker is root inside the sandbox.

Every test is one concrete attack against THIS project's sandbox (CLAUDE.md
rule 7) and asserts the secure outcome. A test that fails is a finding: it
gets documented in DESIGN.md §5.3/§5.6 as a known limitation and marked
xfail(strict=True) with the reason, never deleted or loosened (rule 5).

Runs on the same network + seccomp manager as test_containment.py (the
production configuration), against the workload image.

Not covered here, and why (listed in DESIGN.md §5.6):
  * syscalls through non-native ABIs (i386 int 0x80, x32): the filter
    handles them (control_plane/seccomp.py) but this suite has no test for it.
  * disk exhaustion: a known gap (no qgroups); filling the volume is not run.
  * kernel 0-days and side channels: out of scope (§5.3).
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

import pytest

from conftest import PY, create, pyjson


def sh(t, sid, script, timeout=30):
    return t.m.exec(sid, ["sh", "-c", script], timeout=timeout)


def init_pid(nmgr, sid) -> int:
    return nmgr._sandboxes[sid]["init_pid"]


def as_sandbox_root_net(nmgr, sid, argv):
    """Run a host tool (ip, nft) with exactly sandbox root's network powers:
    its user namespace (so capabilities only over namespaces it owns) and its
    net namespace. The workload image has no iproute2; this hands the
    attacker the tool without handing it any extra privilege."""
    pid = str(init_pid(nmgr, sid))
    return subprocess.run(["nsenter", "-t", pid, "-U", "-n", "--", *argv],
                          capture_output=True, text=True, timeout=30)


# ============================================================ host isolation


def test_host_processes_invisible(nsb):
    sid = create(nsb)
    res = pyjson(nsb, sid, r"""
import json, os
pids = [int(p) for p in os.listdir('/proc') if p.isdigit()]
cmds = []
for p in pids:
    try: cmds.append(open(f'/proc/{p}/cmdline','rb').read())
    except OSError: pass
print(json.dumps({"min": min(pids), "n": len(pids),
                  "host": any(b'control_plane' in c or b'sandboxd' in c for c in cmds)}))""")
    assert res["min"] == 1 and res["n"] < 10 and not res["host"], res


def test_kill_everything_hits_only_the_sandbox(nsb):
    a, b = create(nsb), create(nsb)
    sh(nsb, a, "kill -9 -1; true")
    # PID 1 installs no handlers, so signals from inside its own namespace are dropped.
    assert sh(nsb, a, "true")["exit_code"] == 0
    assert sh(nsb, b, "true")["exit_code"] == 0


def test_double_chroot_escape_stays_inside(nsb):
    sid = create(nsb)
    sh(nsb, sid, "touch /root/inside-marker")
    res = pyjson(nsb, sid, r"""
import json, os
os.makedirs('/tmp/jail', exist_ok=True)
fd = os.open('/', os.O_RDONLY)
os.chroot('/tmp/jail'); os.fchdir(fd)
for _ in range(64): os.chdir('..')
os.chroot('.')
print(json.dumps({"inside": os.path.exists('/root/inside-marker'),
                  "host_state": os.path.exists('/var/lib/sandboxd-net'),
                  "proc1_root_host": os.path.exists('/proc/1/root/var/lib/sandboxd-net')}))""")
    assert res == {"inside": True, "host_state": False, "proc1_root_host": False}, res


def test_no_dangerous_device_nodes_and_no_mknod(nsb):
    sid = create(nsb)
    res = pyjson(nsb, sid, r"""
import json, os, errno
devs = sorted(os.listdir('/dev'))
try:
    os.mknod('/tmp/blk', 0o600 | 0o60000, os.makedev(7, 0)); mk = "ok"
except OSError as e:
    mk = errno.errorcode[e.errno]
print(json.dumps({"devs": devs, "mknod": mk}))""")
    bad = {"mem", "kmem", "port", "kmsg", "sda", "vda", "nvme0n1", "loop0", "loop-control", "btrfs-control", "fuse"}
    assert not bad & set(res["devs"]), res["devs"]
    assert res["mknod"] != "ok", res


def test_host_kernel_knobs_not_writable(nsb):
    """core_pattern and uevent_helper are classic container-escape targets:
    a write there makes the HOST kernel execute an attacker-chosen path."""
    sid = create(nsb)
    res = pyjson(nsb, sid, r"""
import json, errno
out = {}
for p in ('/proc/sys/kernel/core_pattern', '/proc/sysrq-trigger', '/proc/sys/vm/drop_caches',
          '/proc/sys/kernel/modprobe', '/sys/kernel/uevent_helper'):
    try:
        with open(p, 'w') as f: f.write('|/tmp/x')
        out[p] = "WRITTEN"
    except OSError as e:
        out[p] = errno.errorcode.get(e.errno, str(e.errno))
print(json.dumps(out))""")
    assert "WRITTEN" not in res.values(), res


def test_dangerous_syscalls_refused(nsb):
    """One attempt per escape primitive the seccomp deny-list exists for.
    open_by_handle_at is the 'shocker' container escape; finit_module, reboot,
    bpf and perf_event_open are host-kernel attack surface."""
    sid = create(nsb)
    res = pyjson(nsb, sid, r"""
import ctypes, errno, json, os
libc = ctypes.CDLL(None, use_errno=True)
def raw(nr, *a):
    r = libc.syscall(nr, *a)
    return "ok" if r >= 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
handle = ctypes.create_string_buffer(8 + 128)
ctypes.memmove(handle, (128).to_bytes(4, 'little'), 4)
out = {
  "open_by_handle_at": raw(304, -100, handle, 0),
  "finit_module": raw(313, 0, b"", 0),
  "reboot": raw(169, 0xfee1dead, 672274793, 0x4321FEDC, None),
  "bpf": raw(321, 0, None, 0),
  "perf_event_open": raw(298, ctypes.create_string_buffer(128), 0, -1, -1, 0),
  "userfaultfd": raw(323, 0),
  "fsopen": raw(430, b"tmpfs", 0),
  "open_tree": raw(428, -100, b"/", 0),
}
print(json.dumps(out))""")
    assert all(v in ("EPERM", "ENOSYS") for v in res.values()), res


def test_btrfs_ioctls_refused(nsb):
    """Subvolume create/snapshot, inode lookup and tree search would let root
    inside walk or clone btrfs trees beyond its own subvolume."""
    sid = create(nsb)
    res = pyjson(nsb, sid, r"""
import errno, fcntl, json, os
fd = os.open('/', os.O_RDONLY)
reqs = {"SUBVOL_CREATE": 0x5000940E, "SNAP_CREATE_V2": 0x50009417,
        "INO_LOOKUP": 0xD0009412, "TREE_SEARCH": 0xD0009411, "SNAP_DESTROY": 0x5000940F}
out = {}
for name, req in reqs.items():
    try:
        fcntl.ioctl(fd, req, bytearray(4096)); out[name] = "ok"
    except OSError as e:
        out[name] = errno.errorcode.get(e.errno, str(e.errno))
print(json.dumps(out))""")
    assert set(res.values()) == {"EPERM"}, res


def test_cannot_reach_own_cgroup_controls(nsb):
    sid = create(nsb)
    res = pyjson(nsb, sid, r"""
import ctypes, errno, json, os
libc = ctypes.CDLL(None, use_errno=True)
r = libc.mount(b"none", b"/tmp", b"cgroup2", 0, None)
print(json.dumps({"mount_cgroup2": "ok" if r == 0 else errno.errorcode[ctypes.get_errno()],
                  "proc_self_cgroup": open('/proc/self/cgroup').read().strip(),
                  "sys_fs_cgroup": os.path.exists('/sys/fs/cgroup/cgroup.procs')}))""")
    assert res["mount_cgroup2"] != "ok", res
    assert res["proc_self_cgroup"] == "0::/", res  # own cgroup namespace: no host path
    assert not res["sys_fs_cgroup"], res


def test_pid1_binary_cannot_be_overwritten(nsb):
    """CVE-2019-5736 class: rewrite the binary behind /proc/<pid>/exe. PID 1
    runs from a sealed memfd, so there is no host file behind it."""
    sid = create(nsb)
    res = pyjson(nsb, sid, r"""
import errno, json, os
exe = os.readlink('/proc/1/exe')
out = {"exe": exe}
for flags in (os.O_WRONLY, os.O_RDWR, os.O_WRONLY | os.O_TRUNC):
    try:
        os.close(os.open('/proc/1/exe', flags)); out[str(flags)] = "OPENED"
    except OSError as e:
        out[str(flags)] = errno.errorcode.get(e.errno, str(e.errno))
print(json.dumps(out))""")
    assert res.pop("exe").startswith("/memfd:sandbox-init"), res
    assert "OPENED" not in res.values(), res


def test_control_socket_and_state_not_reachable(nsb, nmgr):
    sid = create(nsb)
    sock = os.path.join(nmgr.cfg.run_dir, "sandboxd.sock")
    res = pyjson(nsb, sid, f"""
import json, os
print(json.dumps([os.path.exists(p) for p in ({sock!r}, {nmgr.cfg.run_dir!r}, {nmgr.cfg.state_dir!r})]))""")
    assert res == [False, False, False], res


def test_host_abstract_unix_socket_unreachable(nsb):
    """Abstract unix sockets are scoped by network namespace; a shared netns
    made them an escape channel (CVE-2020-15257, containerd-shim)."""
    name = f"sbx-host-{uuid.uuid4().hex[:8]}"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind("\0" + name)
    srv.listen(1)
    try:
        sid = create(nsb)
        res = pyjson(nsb, sid, f"""
import json, socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('\\0{name}'); r = "CONNECTED"
except OSError as e:
    r = e.errno
print(json.dumps(r))""")
        assert res != "CONNECTED", res
    finally:
        srv.close()


# ============================================================ exec boundary


def test_exec_inherits_no_host_fds_or_env(nsb):
    sid = create(nsb)
    res = pyjson(nsb, sid, r"""
import json, os
print(json.dumps({"fds": sorted(int(f) for f in os.listdir('/proc/self/fd')),
                  "env": sorted(os.environ)}))""")
    assert res["fds"] == [0, 1, 2, 3], res  # 3 = the listdir handle itself
    expected = {"PATH", "HOME", "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy"}
    assert set(res["env"]) - {"LC_CTYPE"} <= expected, res["env"]


def test_exec_timeout_kills_detached_descendants(nsb):
    """A command that setsid()s and double-forks must not outlive its exec
    timeout (it would keep running, unaccounted to any caller, until destroy)."""
    sid = create(nsb)
    escaper = ("import os, time\nos.setsid()\nif os.fork(): os._exit(0)\nos.setsid()\n"
               "if os.fork(): os._exit(0)\nopen('/tmp/escaper.pid','w').write(str(os.getpid()))\n"
               "while True: time.sleep(1)\n")
    r = nsb.m.exec(sid, ["sh", "-c", f"cat > /tmp/esc.py; {PY} /tmp/esc.py; sleep 600"],
                   stdin=escaper.encode(), timeout=3)
    assert r["timed_out"]
    pid = sh(nsb, sid, "cat /tmp/escaper.pid")["stdout"].decode().strip()
    assert pid, "escaper never started"
    time.sleep(0.5)
    assert sh(nsb, sid, f"test -e /proc/{pid}")["exit_code"] == 1, "detached process survived the exec timeout"


def test_fork_bomb_contained_and_destroyable(nsb, nmgr):
    sid = create(nsb, limits={"pids_max": "64"})
    nsb.m.exec(sid, ["sh", "-c", "f() { f | f & }; f; sleep 3"], timeout=10)
    assert len(nmgr.cg.procs(sid)) <= 64
    other = create(nsb)
    assert sh(nsb, other, "true")["exit_code"] == 0  # siblings still get service
    nmgr.destroy(sid)  # cgroup.kill must take down a live fork bomb


# ============================================================ control plane vs sandbox-controlled files


def test_symlinks_to_host_survive_fork_and_destroy(nsb, nmgr):
    canary = f"/var/tmp/sbx-canary-{uuid.uuid4().hex[:8]}"
    os.makedirs(canary)
    with open(f"{canary}/keep", "w") as f:
        f.write("host data")
    try:
        sid = create(nsb)
        sh(nsb, sid, f"ln -s {canary} /root/abs; ln -s ../../../../../..{canary} /root/rel; "
                     f"ln -s {canary}/keep /root/file; ln -s /root/loop /root/loop")
        child = nsb.fork(sid)
        nmgr.destroy(child)
        nmgr.destroy(sid)
        assert open(f"{canary}/keep").read() == "host data"
        assert os.listdir(canary) == ["keep"]
    finally:
        shutil.rmtree(canary)


def test_hostile_tree_does_not_break_destroy(nsb, nmgr):
    sid = create(nsb)
    pyjson(nsb, sid, r"""
import json, os
for n in ['a\nb', ' lead', '-rf', '..weird', 'x' * 255]:
    open(os.path.join('/root', n), 'w').close()
os.makedirs('/root/' + '/'.join(['d'] * 200), exist_ok=True)
os.chmod('/root', 0)
print(json.dumps(True))""")
    nmgr.destroy(sid)
    assert not nmgr.audit(sid), nmgr.audit(sid)


def test_sibling_ipc_isolated(nsb):
    a, b = create(nsb), create(nsb)
    code = r"""
import ctypes, json, sys
libc = ctypes.CDLL(None, use_errno=True)
key = 0x5B0C
if sys.argv[1] == 'create':
    print(json.dumps(libc.shmget(key, 4096, 0o1000 | 0o666) >= 0))
else:
    print(json.dumps([libc.shmget(key, 4096, 0o666), ctypes.get_errno()]))
"""
    assert nsb.m.exec(a, [PY, "-c", code, "create"])["stdout"].strip() == b"true"
    shmid, err = json.loads(nsb.m.exec(b, [PY, "-c", code, "open"])["stdout"])
    assert shmid == -1 and err == 2, (shmid, err)  # ENOENT: b cannot see a's segment


# ============================================================ network


def test_root_rerouting_and_flushing_does_not_open_egress(nsb, nmgr):
    sid = create(nsb)
    gw = nmgr._sandboxes[sid]["net"]["gateway"]
    r = as_sandbox_root_net(nmgr, sid, ["ip", "route", "add", "default", "via", gw])
    assert r.returncode == 0, r.stderr  # it CAN rewrite its own routing...
    as_sandbox_root_net(nmgr, sid, ["nft", "flush", "ruleset"])
    res = pyjson(nsb, sid, r"""
import json, socket
out = {}
for ip, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
    try:
        socket.create_connection((ip, port), timeout=2).close(); out[ip] = "connected"
    except OSError as e:
        out[ip] = type(e).__name__
print(json.dumps(out))""")
    assert "connected" not in res.values(), res  # ...but the egress netns forwards nothing


def test_cannot_join_egress_or_host_netns(nsb, nmgr):
    sid = create(nsb)
    for target in (f"/run/netns/{nmgr.cfg.egress_netns}", "/proc/1/ns/net"):
        r = as_sandbox_root_net(nmgr, sid, ["nsenter", f"--net={target}", "true"])
        assert r.returncode != 0, (target, r.stderr)


def test_spoofing_a_sibling_address_is_dropped(nsb, nmgr):
    a, b = create(nsb), create(nsb)
    a_net, b_net = nmgr._sandboxes[a]["net"], nmgr._sandboxes[b]["net"]
    as_sandbox_root_net(nmgr, a, ["ip", "addr", "flush", "dev", "eth0"])
    as_sandbox_root_net(nmgr, a, ["ip", "addr", "add", f"{b_net['ip']}/16", "dev", "eth0"])
    res = pyjson(nsb, a, f"""
import json, socket
try:
    socket.create_connection(({a_net['gateway']!r}, {nmgr.cfg.proxy_port}), timeout=3).close(); r = "connected"
except OSError as e:
    r = type(e).__name__
print(json.dumps(r))""")
    assert res != "connected", res


PROXY_RAW = r"""
import json, os, socket, sys
host, port = os.environ["HTTPS_PROXY"].split("//")[1].split(":")
s = socket.create_connection((host, int(port)), timeout=5)
s.sendall(sys.argv[1].encode('latin-1'))
data = b""
try:
    while c := s.recv(4096):
        data += c
except OSError:
    pass
print(json.dumps(data.split(b"\r\n")[0].decode(errors="replace") or "CLOSED"))
"""


def proxy_raw(t, sid, request):
    r = t.m.exec(sid, [PY, "-c", PROXY_RAW, request], timeout=30)
    assert r["exit_code"] == 0, r["stderr"]
    return json.loads(r["stdout"])


def test_proxy_will_not_connect_to_itself_or_control_plane(nsb, nmgr):
    sid = create(nsb)
    gw = nmgr._sandboxes[sid]["net"]["gateway"]
    port = nmgr.cfg.proxy_port
    for target in (f"{gw}:{port}", f"127.0.0.1:{port}", f"localhost:{port}", "169.254.169.254:80",
                   "[::1]:80", "0.0.0.0:80"):
        status = proxy_raw(nsb, sid, f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n")
        assert not status.startswith("HTTP/1.1 200"), (target, status)


def test_proxy_has_no_other_surface(nsb):
    sid = create(nsb)
    for req in ("GET / HTTP/1.1\r\nHost: x\r\n\r\n", "GET /admin HTTP/1.1\r\n\r\n",
                "DELETE / HTTP/1.1\r\n\r\n", "OPTIONS * HTTP/1.1\r\n\r\n",
                "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        status = proxy_raw(nsb, sid, req)
        assert not status.startswith("HTTP/1.1 2"), (req, status)


def test_proxy_survives_malformed_input(nsb, echo_port):
    sid = create(nsb)
    for req in ("\x00\xff\xfe garbage\r\n\r\n", "CONNECT\r\n\r\n", "CONNECT a:b:c HTTP/1.1\r\n\r\n",
                "CONNECT host:99999 HTTP/1.1\r\n\r\n", "CONNECT " + "a" * 20000 + ":443 HTTP/1.1\r\n\r\n"):
        proxy_raw(nsb, sid, req)
    status = proxy_raw(nsb, sid, f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n\r\n")
    assert status.startswith("HTTP/1.1 200"), status


HOG = r"""
import os, socket, time
host, port = os.environ["HTTPS_PROXY"].split("//")[1].split(":")
socks = [socket.create_connection((host, int(port)), timeout=5) for _ in range(80)]
open('/tmp/hog-ready', 'w').close()
time.sleep(20)
"""


def test_one_sandbox_cannot_starve_siblings_of_the_proxy(nsb, echo_port):
    hog, victim = create(nsb), create(nsb)
    nsb.m.exec(hog, ["sh", "-c", f"cat > /tmp/hog.py; {PY} /tmp/hog.py >/dev/null 2>&1 &"], stdin=HOG.encode())
    deadline = time.monotonic() + 15
    while sh(nsb, hog, "test -e /tmp/hog-ready")["exit_code"] != 0:
        assert time.monotonic() < deadline, "hog never opened its connections"
        time.sleep(0.2)
    t = time.monotonic()
    status = proxy_raw(nsb, victim, f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n\r\n")
    assert status.startswith("HTTP/1.1 200") and time.monotonic() - t < 5, status


# ============================================================ the proxy as a pivot


AS_NOBODY = r"""
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect((sys.argv[1], int(sys.argv[2]))); print("CONNECTED")
except OSError as e:
    print("BLOCKED", type(e).__name__)
"""


@pytest.mark.xfail(strict=True, reason="known limitation (DESIGN.md §5.3): the proxy's outbound sockets live in "
                                        "the host netns, so a compromised proxy (uid 65534) can reach host-local "
                                        "services. Remove this mark when that is fixed.")
def test_compromised_proxy_cannot_reach_host_services(nmgr):
    """What an RCE in the proxy would get: code running as its uid in the host netns."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    try:
        out = subprocess.run([sys.executable, "-I", "-c", AS_NOBODY, "127.0.0.1", str(listener.getsockname()[1])],
                             user=65534, group=65534, capture_output=True, text=True, timeout=30).stdout
        assert out.startswith("BLOCKED"), out
    finally:
        listener.close()
