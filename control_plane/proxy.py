"""Allowlist-only HTTP CONNECT proxy (DESIGN.md §5.4).

The listening socket is created *inside* the egress netns (the only netns a
sandbox can reach), then the process switches back to the host netns and
drops to an unprivileged user before serving. Upstream connections are
therefore made from the host network, but the only thing sandboxes can
connect to is this one socket. Those upstream connections are themselves
fenced by a host nft table keyed on the proxy's dedicated uid, so even a
compromised proxy can only reach what the allowlist names.

Deliberately minimal: CONNECT only, no plain HTTP forwarding, no admin
surface, no state shared between connections. Hostname allowlist entries
are resolved once and connected to by IP (no second resolution), and any
resolved address that is not globally routable (loopback, RFC 1918,
link-local incl. 169.254.169.254, CGNAT, multicast...) is refused unless
the allowlist names that exact IP.

    python3 -m control_plane.proxy --netns /run/netns/sbx-egress --port 3128 \
        --uid 999999 --allow api.example.com:443 --allow 10.0.0.5:8000
"""
from __future__ import annotations

import argparse
import asyncio
import ctypes
import ipaddress
import json
import os
import socket
import sys
import time

CLONE_NEWNET = 0x40000000
MAX_HEAD = 8192
HEAD_TIMEOUT = 10
CONNECT_TIMEOUT = 10
MAX_CONNS_PER_PEER = 64


def parse_allow(entries: list[str]) -> list[tuple[str, int]]:
    out = []
    for e in entries:
        host, _, port = e.rpartition(":")
        if not host or not port.isdigit():
            raise ValueError(f"allowlist entry must be host:port, got {e!r}")
        out.append((host.lower().strip("[]"), int(port)))
    return out


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


class Policy:
    def __init__(self, allow: list[tuple[str, int]]):
        self.allow = allow

    def match(self, host: str, port: int) -> str | None:
        """Return the matching entry's host pattern, or None."""
        host = host.lower().rstrip(".")
        for pat, p in self.allow:
            if p != port:
                continue
            if pat == host:
                return pat
            if pat.startswith("*.") and host.endswith(pat[1:]) and len(host) > len(pat) - 1:
                return pat
        return None

    async def resolve(self, host: str, port: int) -> list[str]:
        """Addresses we may connect to for an allowed (host, port)."""
        if _is_ip(host):
            return [str(ipaddress.ip_address(host))]  # exact IP was allowlisted
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM)
        addrs = []
        for *_, sockaddr in infos:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_global and str(ip) not in addrs:
                addrs.append(str(ip))
        return addrs


class Proxy:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.per_peer: dict[str, int] = {}

    def log(self, **kw):
        kw["ts"] = round(time.time(), 3)
        sys.stderr.write(json.dumps(kw) + "\n")
        sys.stderr.flush()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")[0]
        if self.per_peer.get(peer, 0) >= MAX_CONNS_PER_PEER:
            writer.close()
            return
        self.per_peer[peer] = self.per_peer.get(peer, 0) + 1
        try:
            await self._handle(peer, reader, writer)
        except Exception as e:  # never let one connection take the proxy down
            self.log(peer=peer, event="error", error=repr(e))
        finally:
            self.per_peer[peer] -= 1
            writer.close()

    async def _handle(self, peer, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            return
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()
        if len(parts) != 3 or parts[0] != "CONNECT" or not parts[2].startswith("HTTP/1."):
            self.log(peer=peer, event="deny", reason="not a CONNECT request", line=line[:200])
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            return
        host, _, port_s = parts[1].rpartition(":")
        host = host.strip("[]")
        if not host or not port_s.isdigit() or not 0 < int(port_s) < 65536:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return
        port = int(port_s)
        if self.policy.match(host, port) is None:
            self.log(peer=peer, event="deny", reason="not allowlisted", target=f"{host}:{port}")
            writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            return
        try:
            addrs = await self.policy.resolve(host, port)
        except OSError as e:
            addrs, err = [], repr(e)
        else:
            err = "no globally routable address"
        upstream = None
        for addr in addrs:
            try:
                upstream = await asyncio.wait_for(asyncio.open_connection(addr, port), CONNECT_TIMEOUT)
                break
            except (OSError, asyncio.TimeoutError) as e:
                err = repr(e)
        if upstream is None:
            self.log(peer=peer, event="deny", reason=err, target=f"{host}:{port}")
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            return
        self.log(peer=peer, event="allow", target=f"{host}:{port}", addr=addr)
        up_r, up_w = upstream
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        async def pipe(src, dst):
            try:
                while data := await src.read(65536):
                    dst.write(data)
                    await dst.drain()
            finally:
                dst.close()

        await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer), return_exceptions=True)


def listen_in_netns(netns_path: str, port: int) -> socket.socket:
    libc = ctypes.CDLL(None, use_errno=True)
    home = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = os.open(netns_path, os.O_RDONLY)
    if libc.setns(target, CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), "setns into egress netns")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(1024)
        sock.setblocking(False)
    finally:
        if libc.setns(home, CLONE_NEWNET) != 0:
            os._exit(111)  # never keep running in the wrong netns
        os.close(home)
        os.close(target)
    return sock


def drop_privileges(uid: int) -> None:
    # A dedicated uid (not "nobody"): the host nft filter keys on it.
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)


async def serve(sock: socket.socket, proxy: Proxy):
    server = await asyncio.start_server(proxy.handle, sock=sock, limit=MAX_HEAD)
    proxy.log(event="listening", port=sock.getsockname()[1])
    async with server:
        await server.serve_forever()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--netns", required=True)
    ap.add_argument("--port", type=int, default=3128)
    ap.add_argument("--allow", action="append", default=[])
    ap.add_argument("--uid", type=int, required=True)
    args = ap.parse_args(argv)
    policy = Policy(parse_allow(args.allow))
    sock = listen_in_netns(args.netns, args.port)
    drop_privileges(args.uid)
    asyncio.run(serve(sock, Proxy(policy)))


if __name__ == "__main__":
    main()
