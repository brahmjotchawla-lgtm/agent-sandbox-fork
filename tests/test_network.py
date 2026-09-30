"""Phase 3: egress containment, adversary = root inside the sandbox.

Where the adversary needs ip/nft (not in the base image), tests run the
host binary with the sandbox root's exact privileges via as_sandbox_root().
"""
from __future__ import annotations

import socket
import subprocess

from conftest import as_sandbox_root, py

CONNECT = r"""
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
except OSError as e:
    print('BLOCKED', type(e).__name__, e.errno)
else:
    print('CONNECTED')  # a TCP handshake completed: containment failed
"""

VIA_PROXY = r"""
import socket, sys
proxy = sys.argv[1].split('//')[1]
h, p = proxy.split(':')
s = socket.create_connection((h, int(p)), timeout=5)
s.sendall(sys.argv[2].encode())
data = b''
while True:
    try:
        c = s.recv(4096)
    except socket.timeout:
        break
    if not c:
        break
    data += c
print(data.decode(errors='replace'))
"""


def connect(mgr, sid, host, port):
    return mgr.exec(sid, ["python3", "-c", CONNECT, host, str(port)])["stdout"]


def proxy_req(mgr, sid, request):
    proxy = mgr._load(sid)["net"]["proxy"]
    return mgr.exec(sid, ["python3", "-c", VIA_PROXY, proxy, request], timeout=30)["stdout"]


def host_ips():
    out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True).stdout
    return [l.split()[3].split("/")[0] for l in out.splitlines()]


def test_no_route_to_internet(mgr, sandbox):
    assert connect(mgr, sandbox, "1.1.1.1", 443).startswith("BLOCKED")


def test_host_services_unreachable(mgr, sandbox, upstream):
    # The upstream listens on host loopback; also try every host address.
    listener = socket.socket()
    listener.bind(("0.0.0.0", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        for ip in host_ips() + ["127.0.0.1"]:
            assert connect(mgr, sandbox, ip, port).startswith("BLOCKED"), ip
    finally:
        listener.close()


def test_allowlisted_destination_via_proxy(mgr, sandbox, upstream):
    out = proxy_req(mgr, sandbox, f"CONNECT 127.0.0.1:{upstream.port} HTTP/1.1\r\n\r\n")
    assert "200 Connection established" in out and "upstream-ok" in out


def test_non_allowlisted_denied(mgr, sandbox, upstream):
    assert "403" in proxy_req(mgr, sandbox, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
    assert "403" in proxy_req(mgr, sandbox, f"CONNECT 127.0.0.1:{upstream.port + 1} HTTP/1.1\r\n\r\n")


def test_plain_http_forwarding_refused(mgr, sandbox, upstream):
    out = proxy_req(mgr, sandbox, f"GET http://127.0.0.1:{upstream.port}/ HTTP/1.1\r\nHost: x\r\n\r\n")
    assert "405" in out


def test_hostname_resolving_to_private_address_refused(mgr, sandbox, upstream):
    """'localhost:PORT' is allowlisted by name, but resolves to loopback.
    Only an explicit IP entry may reach a non-global address."""
    out = proxy_req(mgr, sandbox, f"CONNECT localhost:{upstream.port} HTTP/1.1\r\n\r\n")
    assert "502" in out and "upstream-ok" not in out


def test_root_cannot_route_around_egress_netns(mgr, sandbox):
    net = mgr._load(sandbox)["net"]
    r = as_sandbox_root(mgr, sandbox, ["ip", "route", "add", "default", "via", net["gateway"]])
    assert r.returncode == 0, r.stderr  # it CAN change its own routes...
    as_sandbox_root(mgr, sandbox, ["nft", "flush", "ruleset"])
    # ...but the egress netns does not forward.
    assert connect(mgr, sandbox, "1.1.1.1", 443).startswith("BLOCKED")


def test_root_cannot_modify_egress_rules(mgr, sandbox):
    # Its nft sees only its own (empty) netns ruleset.
    r = as_sandbox_root(mgr, sandbox, ["nft", "list", "ruleset"])
    assert "sbx_egress" not in r.stdout
    # Joining the egress netns requires CAP_SYS_ADMIN over the host user ns.
    # as_sandbox_root does not enter the sandbox mount namespace, so even the
    # host paths are visible here; the kernel must still refuse.
    for target in (mgr.net.netns_path, "/proc/1/ns/net"):
        r = as_sandbox_root(mgr, sandbox, ["nsenter", f"--net={target}", "true"])
        assert r.returncode != 0, (target, r.stderr)
        assert "Operation not permitted" in r.stderr or "Permission denied" in r.stderr, r.stderr


def test_siblings_cannot_reach_each_other(mgr, sandbox):
    other = mgr.create_environment("base")["sandbox_id"]
    mgr.exec(other, ["sh", "-c", "python3 -m http.server 8080 >/dev/null 2>&1 &"])
    gw = mgr._load(sandbox)["net"]["gateway"]
    as_sandbox_root(mgr, sandbox, ["ip", "route", "add", "default", "via", gw])
    target = mgr._load(other)["net"]["address"]
    from control_plane.util import wait_until
    assert wait_until(lambda: "CONNECTED" in connect(mgr, other, "127.0.0.1", 8080), 10)
    assert connect(mgr, sandbox, target, 8080).startswith("BLOCKED")


def test_source_spoofing_dropped(mgr, sandbox, upstream):
    """Taking a sibling's address must not get traffic past rp_filter."""
    other = mgr.create_environment("base")["sandbox_id"]
    me, them = mgr._load(sandbox)["net"], mgr._load(other)["net"]
    as_sandbox_root(mgr, sandbox, ["ip", "addr", "flush", "dev", "eth0"])
    as_sandbox_root(mgr, sandbox, ["ip", "addr", "add", f"{them['address']}/16", "dev", "eth0"])
    out = connect(mgr, sandbox, me["gateway"], mgr.cfg.proxy_port)
    assert out.startswith("BLOCKED"), out
