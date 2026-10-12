"""Per-sandbox networking, with egress enforced from a namespace the sandbox cannot enter (DESIGN.md §5.4).

Topology:

    sandbox netns (owned by the sandbox's user ns)      egress netns (owned by host root)
    ┌───────────────────────────┐   veth pair    ┌────────────────────────────────────┐
    │ eth0  10.200.x.(4s+2)/30  │◄──────────────►│ sbx<slot> 10.200.x.(4s+1)/30       │
    │ route: only the /30       │                │ nftables: input policy DROP, except │
    └───────────────────────────┘                │   tcp/3128 from the sandbox's own   │
                                                 │   (iface . source ip) pair          │
                                                 │ forward policy DROP, ip_forward=0   │
                                                 │ output: established/related only    │
                                                 │ proxy listening socket :3128 ───────┼──► proxy process
                                                 └────────────────────────────────────┘    (outbound sockets
                                                                                            in host netns)

Sandboxed root holds CAP_NET_ADMIN inside its own netns, so it can rewrite
its own routes, add addresses, or flush anything there. None of that
matters, because nothing is enforced there. The only peer it has is the
egress netns. That netns forwards nothing, accepts nothing except
TCP to the proxy port from the sandbox's own interface and own address
(no spoofing a sibling), and has no route anywhere else. The egress netns
has no uplink. The proxy's listening socket lives in it, while the
proxy's outbound sockets are created in the host netns. So there is no
forwarding and no NAT on the host, and no host firewall rule can
accidentally open a path.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import sys
import time

TABLE = "sandboxd"


def _run(cmd: list[str], stdin: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, input=stdin, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {p.stderr.strip() or p.stdout.strip()}")
    return p


class EgressNetwork:
    def __init__(self, cfg):
        self.cfg = cfg
        self.ns = getattr(cfg, "egress_netns", None) or "sandboxd-egress"
        self.subnet = ipaddress.ip_network(getattr(cfg, "egress_subnet", None) or "10.200.0.0/16")
        self.port = getattr(cfg, "proxy_port", None) or 3128
        self.ns_path = f"/run/netns/{self.ns}"
        self.proxy: subprocess.Popen | None = None
        self._ctl = None
        self._sandboxes: dict[str, dict] = {}  # sid -> {"ip": ..., "allow": [...]}

    # ------------------------------------------------------------- addressing

    def addrs(self, slot: int) -> tuple[str, str]:
        base = int(self.subnet.network_address) + 4 * slot
        if base + 3 > int(self.subnet.broadcast_address):
            raise RuntimeError(f"slot {slot} does not fit in {self.subnet}")
        return str(ipaddress.ip_address(base + 1)), str(ipaddress.ip_address(base + 2))

    @staticmethod
    def ifname(slot: int) -> str:
        return f"sbx{slot}"

    # ----------------------------------------------------------------- start

    def start(self) -> None:
        if not os.path.exists(self.ns_path):
            _run(["ip", "netns", "add", self.ns])
        self._ns(["ip", "link", "set", "lo", "up"])
        # No forwarding, no IPv6, in the egress netns.
        self._ns(["sysctl", "-q", "-w", "net.ipv4.ip_forward=0", "net.ipv6.conf.all.disable_ipv6=1",
                  "net.ipv6.conf.default.disable_ipv6=1", "net.ipv4.conf.all.rp_filter=1",
                  "net.ipv4.conf.default.rp_filter=1"])
        self._install_rules()
        self._start_proxy()

    def _ns(self, cmd, stdin=None, check=True):
        return _run(["ip", "netns", "exec", self.ns] + cmd, stdin, check)

    def _install_rules(self) -> None:
        rules = f"""
table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
    set sandbox_src {{
        type ifname . ipv4_addr
    }}
    chain input {{
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        meta l4proto tcp tcp dport {self.port} iifname . ip saddr @sandbox_src ct state new accept
        counter comment "dropped: not a sandbox->proxy connection"
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
        counter comment "dropped: forwarding is never allowed"
    }}
    chain output {{
        type filter hook output priority 0; policy drop;
        oif "lo" accept
        ct state established,related accept
        counter comment "dropped: egress netns never originates traffic"
    }}
}}
"""
        self._ns(["nft", "-f", "-"], stdin=rules)

    def _start_proxy(self) -> None:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log = open(os.path.join(self.cfg.state_dir, "proxy.log"), "a")
        self.proxy = subprocess.Popen(
            [sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); from control_plane import proxy; proxy.main(sys.argv[2:])",
             repo, "--netns", self.ns_path, "--port", str(self.port), "--ctl-fd", str(child.fileno())],
            pass_fds=[child.fileno()], stdout=log, stderr=log, cwd="/",
        )
        child.close()
        self._ctl = parent.makefile("rwb")
        ready = json.loads(self._ctl.readline() or b"{}")
        if not ready.get("ready"):
            raise RuntimeError(f"egress proxy failed to start: {ready}")
        self._push()

    def _push(self) -> None:
        msg = {"sandboxes": {v["ip"]: {"id": k, "allow": v["allow"]} for k, v in self._sandboxes.items()}}
        self._ctl.write(json.dumps(msg).encode() + b"\n")
        self._ctl.flush()
        ack = json.loads(self._ctl.readline() or b"{}")
        if not ack.get("ok"):
            raise RuntimeError(f"proxy rejected config: {ack}")

    def close(self) -> None:
        if self.proxy:
            self.proxy.terminate()
            try:
                self.proxy.wait(5)
            except subprocess.TimeoutExpired:
                self.proxy.kill()
            self.proxy = None

    # ------------------------------------------------------- per sandbox

    def attach(self, sid: str, slot: int, init_pid: int, allow: list[str] | None = None) -> dict:
        gw, ip = self.addrs(slot)
        ifn = self.ifname(slot)
        t0 = time.monotonic_ns()
        # Remove any stale interface for this slot (e.g. after a crash), then create the pair.
        self._ns(["ip", "link", "del", ifn], check=False)
        _run(["ip", "-n", self.ns, "-b", "-"], stdin=(
            f"link add {ifn} type veth peer name eth0 netns {init_pid}\n"
            f"addr add {gw}/30 dev {ifn}\n"
            f"link set {ifn} up\n"))
        _run(["nsenter", f"--net=/proc/{init_pid}/ns/net", "ip", "-b", "-"], stdin=(
            "link set lo up\n"
            f"addr add {ip}/30 dev eth0\n"
            "link set eth0 up\n"))
        self._ns(["nft", "add", "element", "inet", TABLE, "sandbox_src", f"{{ {ifn} . {ip} }}"])
        self._sandboxes[sid] = {"ip": ip, "allow": list(allow if allow is not None else self.cfg.egress_allowlist)}
        self._push()
        proxy = f"http://{gw}:{self.port}"
        return {
            "ip": ip, "gateway": gw, "ifname": ifn, "slot": slot, "allow": self._sandboxes[sid]["allow"],
            "setup_ms": round((time.monotonic_ns() - t0) / 1e6, 3),
            "env": {"HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "https_proxy": proxy, "http_proxy": proxy,
                    "NO_PROXY": "localhost,127.0.0.1", "no_proxy": "localhost,127.0.0.1"},
        }

    def readopt(self, sid: str, rec: dict) -> None:
        net = rec["net"]
        self._sandboxes[sid] = {"ip": net["ip"], "allow": net.get("allow", [])}
        self._ns(["nft", "add", "element", "inet", TABLE, "sandbox_src", f"{{ {net['ifname']} . {net['ip']} }}"], check=False)
        self._push()

    def detach(self, sid: str, slot: int | None) -> None:
        info = self._sandboxes.pop(sid, None)
        if info:
            self._push()
        if slot is None:
            return
        gw, ip = self.addrs(slot)
        ifn = self.ifname(slot)
        self._ns(["nft", "delete", "element", "inet", TABLE, "sandbox_src", f"{{ {ifn} . {ip} }}"], check=False)
        # Usually already gone: a veth pair dies with the sandbox's netns.
        self._ns(["ip", "link", "del", ifn], check=False)

    def links(self) -> list[str]:
        out = self._ns(["ip", "-j", "link", "show"]).stdout
        return [l["ifname"] for l in json.loads(out or "[]") if l["ifname"].startswith("sbx")]

    def reconcile(self, known_ids) -> dict:
        """Remove interfaces/allowlist entries for sandboxes that no longer exist."""
        want = {f"sbx{self._slot_of(s)}" for s in self._sandboxes if s in known_ids}
        removed = []
        for ifn in self.links():
            if ifn not in want:
                self._ns(["ip", "link", "del", ifn], check=False)
                removed.append(ifn)
        self._install_rules()
        for sid, v in self._sandboxes.items():
            slot = self._slot_of(sid)
            if slot is not None:
                self._ns(["nft", "add", "element", "inet", TABLE, "sandbox_src", f"{{ sbx{slot} . {v['ip']} }}"], check=False)
        return {"removed_links": removed}

    def _slot_of(self, sid):
        ip = self._sandboxes.get(sid, {}).get("ip")
        if not ip:
            return None
        return (int(ipaddress.ip_address(ip)) - int(self.subnet.network_address)) // 4

    def audit(self, sid: str) -> list[str]:
        """Leaks attributable to a destroyed sandbox: its allowlist entry, or ANY
        sbx* interface in the egress netns that no live sandbox owns."""
        leaks = []
        if sid in self._sandboxes:
            leaks.append(f"proxy allowlist entry for {sid}")
        owned = {f"sbx{self._slot_of(s)}" for s in self._sandboxes}
        leaks += [f"orphan veth {l} in {self.ns}" for l in self.links() if l not in owned]
        return leaks
