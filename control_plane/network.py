"""Per-sandbox networking and the egress netns (DESIGN.md §5.4).

Topology::

    sandbox netns                 egress netns (control-plane owned)
    ┌──────────────┐  veth pair   ┌──────────────────────────────────┐
    │ eth0 10.203.x.2/30 ─────────── sbxh<slot> 10.203.x.1/30       │
    │ lo           │              │ nft: input only tcp/<proxy_port> │
    │ (no default  │              │      forward: drop               │
    │  route)      │              │      output: established only    │
    └──────────────┘              │ ip_forward=0, rp_filter=1        │
                                  │ proxy listening socket (0.0.0.0) │
                                  └──────────────────────────────────┘

The egress netns has no interface to the host or the internet at all. The
only thing a sandbox can talk to is the proxy's listening socket, which the
proxy process created inside this netns and then carried back to the host
netns (see control_plane/proxy.py), where it makes allowlisted upstream
connections. Sandboxed root holds CAP_NET_ADMIN only over its own netns:
it can flush its own nft rules or add routes, but every packet still has to
cross the veth into a netns whose rules it cannot touch.
"""
from __future__ import annotations

import ipaddress
import os
import shutil

from .util import CommandError, run

SUBNET = ipaddress.ip_network("10.203.0.0/16")
# IPv6 is disabled in both netns when the kernel has it at all.
IPV6_OFF = (["net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1"]
            if os.path.exists("/proc/sys/net/ipv6") else [])

EGRESS_RULESET = """
table inet sbx_egress {{
  chain input {{
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    iifname "sbxh*" tcp dport {port} ct state new accept
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
  }}
  chain output {{
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oifname "lo" accept
  }}
}}
"""


def slot_addrs(slot: int) -> tuple[str, str]:
    """(egress-side gateway, sandbox-side address) of a slot's /30."""
    base = int(SUBNET.network_address) + slot * 4
    if base + 3 > int(SUBNET.broadcast_address):
        raise ValueError(f"slot {slot} does not fit in {SUBNET}")
    return str(ipaddress.ip_address(base + 1)), str(ipaddress.ip_address(base + 2))


class Network:
    def __init__(self, netns: str, proxy_port: int):
        self.netns = netns
        self.proxy_port = proxy_port
        self.nsenter = shutil.which("nsenter")
        if not shutil.which("ip") or not shutil.which("nft"):
            raise RuntimeError("iproute2 (ip) and nft are required for sandbox networking")

    @property
    def netns_path(self) -> str:
        return f"/run/netns/{self.netns}"

    def setup(self) -> None:
        """Create the egress netns and load its ruleset (idempotent)."""
        if not os.path.exists(self.netns_path):
            run(["ip", "netns", "add", self.netns])
        ns = ["ip", "netns", "exec", self.netns]
        sysctls = ["net.ipv4.ip_forward=0", "net.ipv4.conf.all.rp_filter=1",
                   "net.ipv4.conf.default.rp_filter=1", *IPV6_OFF]
        run(ns + ["sysctl", "-qw", *sysctls])
        run(["ip", "-n", self.netns, "link", "set", "lo", "up"])
        # "add table; delete table; define table" replaces it atomically.
        ruleset = ("table inet sbx_egress\ndelete table inet sbx_egress\n"
                   + EGRESS_RULESET.format(port=self.proxy_port))
        run(ns + ["nft", "-f", "-"], input=ruleset)

    def attach(self, slot: int, pid: int) -> dict:
        gw, addr = slot_addrs(slot)
        host_if = f"sbxh{slot}"
        # Both ends are created directly in their target namespaces, so no
        # sandbox interface ever exists in the host netns.
        run(["ip", "link", "add", host_if, "netns", self.netns, "type", "veth",
             "peer", "name", "eth0", "netns", str(pid)])
        run(["ip", "-n", self.netns, "-batch", "-"],
            input=f"addr add {gw}/30 dev {host_if}\nlink set {host_if} up\n")
        sb = [self.nsenter, "-t", str(pid), "-n"]
        if IPV6_OFF:
            run(sb + ["sysctl", "-qw", *IPV6_OFF])
        run(sb + ["ip", "-batch", "-"],
            input=f"link set lo up\naddr add {addr}/30 dev eth0\nlink set eth0 up\n")
        return {"host_if": host_if, "gateway": gw, "address": addr,
                "proxy": f"http://{gw}:{self.proxy_port}"}

    def detach(self, slot: int) -> None:
        try:
            run(["ip", "-n", self.netns, "link", "del", f"sbxh{slot}"])
        except CommandError as e:
            if "Cannot find device" not in str(e) and "does not exist" not in str(e):
                raise

    def host_ifaces(self) -> list[str]:
        if not os.path.exists(self.netns_path):
            return []
        out = run(["ip", "-n", self.netns, "-o", "link", "show"]).stdout
        names = []
        for line in out.splitlines():
            name = line.split(":")[1].strip().split("@")[0]
            if name.startswith("sbxh"):
                names.append(name)
        return names
