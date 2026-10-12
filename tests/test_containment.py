"""Phase 3: verify the containment controls exist and behave as configured.

Scope, deliberately narrow (agreed for Phase 3): each test checks that one
configured control is in place and does what its configuration says.
These are NOT adversarial escape attempts. That suite is Phase 4, and a
pass here says nothing about resistance to a determined attacker.

Hermetic: the only allowlisted upstream is an echo server on the host's
loopback, allowed by IP literal (the explicit opt-in for non-global
addresses). No internet access is needed.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import threading

import pytest

from conftest import Tracker, make_config

WORKLOAD_TAR = "/var/tmp/sandboxd-workload.tar"
PY = "/usr/local/bin/python3"
NETNS = "sbxeg-test"


@pytest.fixture(scope="session")
def echo_port():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=lambda c=c: (c.sendall(c.recv(1024)), c.close()), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1]
    srv.close()


@pytest.fixture(scope="session")
def nmgr(echo_port):
    from control_plane.manager import SandboxManager

    if not os.path.exists(WORKLOAD_TAR):
        pytest.skip(f"{WORKLOAD_TAR} missing: run bench/build_workload.sh first")
    cfg = make_config("net", network=True, seccomp=True, egress_netns=NETNS, egress_subnet="10.201.0.0/16",
                      egress_allowlist=[f"127.0.0.1:{echo_port}", f"localhost:{echo_port}"])
    m = SandboxManager(cfg)
    m.start()
    if "workload" not in m.list_images():
        m.import_image("workload", WORKLOAD_TAR)
    yield m
    for sid in m.list_sandboxes():
        m.destroy(sid)
    m.close()


@pytest.fixture
def nsb(nmgr):
    t = Tracker(nmgr)
    yield t
    t.finish()


def create(t: Tracker, **kw) -> str:
    return t._track(t.m.create_environment("workload", **kw)["id"])


def pyjson(t: Tracker, sid: str, code: str, timeout=30):
    r = t.m.exec(sid, [PY, "-c", code], timeout=timeout)
    assert r["exit_code"] == 0, (r["exit_code"], r["stdout"], r["stderr"])
    return json.loads(r["stdout"].decode().strip().splitlines()[-1])


PROXY_HELPER = r'''
import json, os, socket
def via_proxy(target, payload=None):
    host, port = os.environ["HTTPS_PROXY"].split("//")[1].split(":")
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        c = s.recv(1)
        if not c:
            break
        head += c
    status = head.split(b"\r\n")[0].decode()
    echo = None
    if payload and " 200 " in status:
        s.sendall(payload); echo = s.recv(64).decode()
    return status, echo
def direct(ip, port):
    try:
        socket.create_connection((ip, port), timeout=2).close()
        return "connected"
    except OSError as e:
        return type(e).__name__
'''


# ------------------------------------------------------------------- network


def test_only_route_is_the_point_to_point_link(nsb, nmgr):
    sid = create(nsb)
    routes = pyjson(nsb, sid, "import json; print(json.dumps(open('/proc/net/route').read().splitlines()[1:]))")
    fields = [r.split() for r in routes]
    assert [f[0] for f in fields] == ["eth0"], routes
    assert all(f[1] != "00000000" for f in fields), "sandbox should have no default route"
    assert nmgr._sandboxes[sid]["net"]["ip"].startswith("10.201.")


def test_allowlisted_destination_works_through_proxy(nsb, echo_port):
    sid = create(nsb)
    status, echo = pyjson(nsb, sid, PROXY_HELPER + f'print(json.dumps(via_proxy("127.0.0.1:{echo_port}", b"ping")))')
    assert status == "HTTP/1.1 200 Connection Established"
    assert echo == "ping"


def test_proxy_refuses_what_is_not_allowlisted(nsb, echo_port):
    sid = create(nsb)
    other = echo_port + 1 if echo_port < 65535 else echo_port - 1
    res = pyjson(nsb, sid, PROXY_HELPER + f'print(json.dumps({{t: via_proxy(t)[0] for t in ["127.0.0.1:{other}", "example.org:443"]}}))')
    assert all(v.startswith("HTTP/1.1 403") for v in res.values()), res


def test_proxy_only_speaks_connect(nsb, nmgr):
    sid = create(nsb)
    gw = nmgr._sandboxes[sid]["net"]["gateway"]
    status = pyjson(nsb, sid, f'''
import json, socket
s = socket.create_connection(("{gw}", 3128), timeout=5)
s.sendall(b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
print(json.dumps(s.recv(100).split(b"\\r\\n")[0].decode()))''')
    assert status.startswith("HTTP/1.1 405"), status


def test_allowlisted_name_that_resolves_to_loopback_is_refused(nsb, echo_port):
    # `localhost:<port>` is on the allowlist by name. The proxy's post-resolution
    # check must still refuse it, because it resolves to a non-global address.
    sid = create(nsb)
    status, _ = pyjson(nsb, sid, PROXY_HELPER + f'print(json.dumps(via_proxy("localhost:{echo_port}")))')
    assert status.startswith("HTTP/1.1 403"), status


def test_no_direct_connection_outside_the_proxy(nsb, nmgr):
    a, b = create(nsb), create(nsb)
    gw = nmgr._sandboxes[a]["net"]["gateway"]
    b_ip = nmgr._sandboxes[b]["net"]["ip"]
    res = pyjson(nsb, a, PROXY_HELPER + f'''
print(json.dumps({{
  "public": direct("1.1.1.1", 443),
  "gateway_other_port": direct("{gw}", 22),
  "sibling": direct("{b_ip}", 8000),
}}))''')
    assert all(v != "connected" for v in res.values()), res


def test_proxy_runs_unprivileged(nmgr):
    pid = nmgr.network.proxy.pid
    status = dict(l.split(":", 1) for l in open(f"/proc/{pid}/status").read().splitlines())
    assert status["Uid"].split()[:3] == ["65534"] * 3
    assert int(status["CapEff"].strip(), 16) == 0
    assert int(status["CapPrm"].strip(), 16) == 0


def test_egress_ruleset_unchanged_by_sandbox_activity(nsb):
    def ruleset():
        out = subprocess.run(["ip", "netns", "exec", NETNS, "nft", "-j", "list", "table", "inet", "sandboxd"],
                             capture_output=True, text=True, check=True).stdout
        # counters and set contents change legitimately; compare rule structure only
        data = json.loads(out)["nftables"]
        rules = [e["rule"]["expr"] for e in data if "rule" in e]
        for r in rules:
            for e in r:
                e.pop("counter", None)
        return hashlib.sha256(json.dumps(rules, sort_keys=True).encode()).hexdigest()

    before = ruleset()
    sid = create(nsb)
    nsb.m.exec(sid, ["sh", "-c", "true"])
    assert ruleset() == before


# ------------------------------------------------------------------- seccomp


def test_seccomp_blocks_the_configured_syscalls(nsb):
    sid = create(nsb)
    res = pyjson(nsb, sid, r'''
import ctypes, errno, fcntl, json, os
libc = ctypes.CDLL(None, use_errno=True)
def call(fn):
    try:
        fn(); return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
def raw(nr, *a):
    r = libc.syscall(nr, *a)
    if r < 0:
        raise OSError(ctypes.get_errno(), "")
out = {}
out["unshare_newuser"] = call(lambda: os.unshare(os.CLONE_NEWUSER))
out["mount"] = call(lambda: raw(165, b"none", b"/tmp", b"tmpfs", 0, None))
out["io_uring_setup"] = call(lambda: raw(425, 1, ctypes.create_string_buffer(120)))
out["keyctl"] = call(lambda: raw(250, 0, 0, 0, 0, 0))
fd = os.open("/tmp", os.O_RDONLY)
out["btrfs_ioctl"] = call(lambda: fcntl.ioctl(fd, 0x5000940E, bytearray(4096)))
out["clone3"] = call(lambda: raw(435, 0, 0))
print(json.dumps(out))''')
    assert res == {"unshare_newuser": "EPERM", "mount": "EPERM", "io_uring_setup": "EPERM", "keyctl": "EPERM",
                   "btrfs_ioctl": "EPERM", "clone3": "ENOSYS"}, res


def test_seccomp_leaves_normal_work_alone(nsb):
    sid = create(nsb)
    r = nsb.m.exec(sid, ["/workspace/venv/bin/python", "-m", "pytest", "-q", "-x", "tests/test_basic.py", "-p", "no:cacheprovider"],
                   cwd="/workspace/flask", timeout=300)
    assert r["exit_code"] == 0, r["stdout"][-500:]


# ------------------------------------------------------------- cgroup limits


def test_memory_limit_enforced(nsb, nmgr):
    sid = create(nsb, limits={"memory_max": str(128 << 20)})
    r = nsb.m.exec(sid, [PY, "-c", "x = bytearray(512 << 20); x[::4096] = b'1' * len(x[::4096]); print('survived')"], timeout=60)
    assert r["exit_code"] == -9 and b"survived" not in r["stdout"]
    events = dict(l.split() for l in nmgr.cg.stat(sid)["memory.events"].splitlines())
    assert int(events["oom_kill"]) >= 1


def test_pids_limit_enforced(nsb, nmgr):
    sid = create(nsb, limits={"pids_max": "32"})
    nsb.m.exec(sid, ["sh", "-c", "for i in $(seq 100); do sleep 30 & done 2>/dev/null; true"], timeout=30)
    assert len(nmgr.cg.procs(sid)) <= 32


def test_cpu_limit_enforced(nsb, nmgr):
    sid = create(nsb, limits={"cpu_max": "10000 100000"})  # 10% of one CPU
    nsb.m.exec(sid, [PY, "-c", "import time\nt=time.time()\nwhile time.time()-t<1.5: pass"], timeout=30)
    stat = dict(l.split() for l in open(os.path.join(nmgr.cg.path(sid), "cpu.stat")).read().splitlines())
    assert int(stat["nr_throttled"]) > 0, stat


# ----------------------------------------------------- no shared mutable state


def test_siblings_have_separate_namespaces_and_state(nsb, nmgr):
    p = create(nsb)
    c = nsb.fork(p)
    rp, rc = nmgr._sandboxes[p], nmgr._sandboxes[c]
    assert rp["userns_inode"] != rc["userns_inode"]
    assert rp["netns_inode"] != rc["netns_inode"]
    assert rp["net"]["ip"] != rc["net"]["ip"]
    assert rp["uid_base"] != rc["uid_base"]
    nsb.m.exec(p, ["sh", "-c", "echo p > /dev/shm/marker"])
    assert nsb.m.exec(c, ["test", "-e", "/dev/shm/marker"])["exit_code"] == 1
    # The fork inherited the parent's egress allowlist, as configured.
    assert rc["egress_allow"] == rp["egress_allow"]
