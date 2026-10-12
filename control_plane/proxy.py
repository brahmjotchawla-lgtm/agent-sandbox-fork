"""Egress proxy: HTTP CONNECT only, with a per-sandbox destination allowlist (DESIGN.md §5.4).

This is a shared service that every sandbox can reach, which is exactly the
shape of the 2026 incident DESIGN.md §5.3 warns about. So it is kept as small
as possible:

  * One request type: `CONNECT host:port HTTP/1.1`. Everything else gets 405.
    There is no admin API on the network side at all. Configuration arrives
    only over an inherited Unix socketpair from the control plane.
  * It listens in the egress netns (where the sandboxes' veths end) but makes
    its outbound connections from the host netns. The listening socket is
    created after setns() into the egress netns, then the process returns
    to the host netns.
  * It drops to uid/gid 65534 (nobody) with no capabilities and
    NO_NEW_PRIVS right after binding.
  * The sandbox is identified by source IP, which the egress netns nftables
    set pins to that sandbox's own veth (no spoofing a sibling).
  * Allowlist match is on the requested host name and port. The proxy then
    resolves the name itself and refuses if ANY resolved address is not
    globally routable (loopback, RFC 1918, link-local incl. cloud metadata
    169.254.169.254, CGNAT, ULA, ...). It connects to the vetted address, not
    a re-resolution, so DNS rebinding cannot swap in an internal address
    between check and use. An IP literal is only allowed if that literal
    itself is allowlisted. That is the explicit way to permit a private
    inference server.
  * Per-sandbox concurrent connection cap, so one sandbox cannot exhaust
    the proxy for its siblings.

Residual risk (stated, not solved): a bug in this file or in Python's
asyncio/socket stack is reachable from every sandbox. An allowlisted
destination that is itself a shared, writable service is a coordination
channel between sandboxes. The allowlist is policy, and policy can be wrong.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import socket
import sys
import time

MAX_HEAD = 8192
HEAD_TIMEOUT = 10.0
CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 300.0
PER_SANDBOX_CONNS = 64
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*\.?$")

TABLE: dict[str, dict] = {}  # source ip -> {"id": sandbox id, "allow": [...]}
ACTIVE: dict[str, int] = {}


def log(**kw):
    kw["ts"] = round(time.time(), 3)
    sys.stderr.write(json.dumps(kw) + "\n")
    sys.stderr.flush()


def parse_target(target: str) -> tuple[str, int]:
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        if not rest.startswith(":"):
            raise ValueError("bad target")
        port = rest[1:]
        ipaddress.IPv6Address(host)
    else:
        host, sep, port = target.rpartition(":")
        if not sep:
            raise ValueError("missing port")
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("bad port")
    host = host.lower().rstrip(".")
    if not host:
        raise ValueError("empty host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOST_RE.match(host) or len(host) > 253:
            raise ValueError("bad host")
    return host, int(port)


def allowed(host: str, port: int, allow: list[str]) -> bool:
    for entry in allow:
        try:
            ehost, eport = parse_entry(entry)
        except ValueError:
            continue
        if eport != "*" and int(eport) != port:
            continue
        if ehost.startswith("*."):
            if host.endswith(ehost[1:]) and host != ehost[2:]:
                return True
        elif host == ehost:
            return True
    return False


def parse_entry(entry: str) -> tuple[str, str]:
    if entry.startswith("["):
        h, _, rest = entry[1:].partition("]")
        return h.lower(), rest.lstrip(":")
    h, _, p = entry.rpartition(":")
    if not h or not (p == "*" or p.isdigit()):
        raise ValueError(entry)
    return h.lower().rstrip("."), p


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def vet_address(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def resolve(host: str, port: int) -> list[tuple]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [(fam, sa) for fam, _, _, _, sa in infos]


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await asyncio.wait_for(src.read(65536), IDLE_TIMEOUT)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            dst.close()
        except OSError:
            pass


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")[0]
    sb = TABLE.get(peer)
    sid = sb["id"] if sb else None

    async def reply(code: int, reason: str, decision: str, **kw):
        log(sandbox=sid, src=peer, decision=decision, code=code, **kw)
        try:
            writer.write(f"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        writer.close()

    if sb is None:
        await reply(403, "Forbidden", "unknown-source")
        return
    if ACTIVE.get(peer, 0) >= PER_SANDBOX_CONNS:
        await reply(429, "Too Many Connections", "conn-limit")
        return
    ACTIVE[peer] = ACTIVE.get(peer, 0) + 1
    try:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
            await reply(400, "Bad Request", "bad-head")
            return
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            await reply(400, "Bad Request", "bad-request-line", line=line[:200])
            return
        method, target, _ = parts
        if method != "CONNECT":
            await reply(405, "Method Not Allowed", "not-connect", method=method[:20])
            return
        try:
            host, port = parse_target(target)
        except ValueError:
            await reply(400, "Bad Request", "bad-target", target=target[:200])
            return
        if not allowed(host, port, sb["allow"]):
            await reply(403, "Forbidden", "not-allowlisted", host=host, port=port)
            return
        if is_ip(host):
            candidates = [(socket.AF_INET6 if ":" in host else socket.AF_INET, (host, port))]
        else:
            try:
                candidates = await asyncio.wait_for(resolve(host, port), CONNECT_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as e:
                await reply(502, "Bad Gateway", "resolve-failed", host=host, err=str(e))
                return
            bad = [sa[0] for _, sa in candidates if not vet_address(sa[0])]
            if bad or not candidates:
                await reply(403, "Forbidden", "non-global-address", host=host, addrs=bad)
                return
        upstream = None
        for fam, sa in candidates:
            try:
                upstream = await asyncio.wait_for(asyncio.open_connection(sa[0], sa[1], family=fam), CONNECT_TIMEOUT)
                break
            except (OSError, asyncio.TimeoutError):
                continue
        if upstream is None:
            await reply(502, "Bad Gateway", "connect-failed", host=host, port=port)
            return
        ureader, uwriter = upstream
        log(sandbox=sid, src=peer, decision="allow", host=host, port=port, addr=sa[0])
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(_pipe(reader, uwriter), _pipe(ureader, writer))
    finally:
        ACTIVE[peer] -= 1
        if not writer.is_closing():
            writer.close()


async def control(fd: int) -> None:
    loop = asyncio.get_running_loop()
    r = asyncio.StreamReader(limit=1 << 22)
    sock = socket.socket(fileno=fd)
    transport, _ = await loop.connect_accepted_socket(lambda: asyncio.StreamReaderProtocol(r), sock=sock)

    def send(obj):
        transport.write(json.dumps(obj).encode() + b"\n")

    send({"ready": True, "pid": os.getpid(), "uid": os.getuid()})
    while True:
        line = await r.readline()
        if not line:
            log(event="control-channel-closed")
            os._exit(0)
        try:
            msg = json.loads(line)
            new = {}
            for ip, v in msg["sandboxes"].items():
                ipaddress.ip_address(ip)
                new[ip] = {"id": str(v["id"]), "allow": [str(a) for a in v["allow"]]}
            TABLE.clear()
            TABLE.update(new)
            send({"ok": True, "n": len(TABLE)})
        except (ValueError, KeyError, TypeError) as e:
            send({"ok": False, "error": str(e)})


def bind_in_netns(netns_path: str, port: int) -> socket.socket:
    host_ns = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    target = os.open(netns_path, os.O_RDONLY | os.O_CLOEXEC)
    os.setns(target, os.CLONE_NEWNET)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(1024)
        s.setblocking(False)
    finally:
        os.setns(host_ns, os.CLONE_NEWNET)
        os.close(host_ns)
        os.close(target)
    return s


def drop_privileges() -> None:
    import ctypes

    os.setgroups([])
    os.setresgid(65534, 65534, 65534)
    os.setresuid(65534, 65534, 65534)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    with open("/proc/self/status") as f:
        caps = {l.split(":")[0]: l.split(":")[1].strip() for l in f if l.startswith("Cap")}
    if int(caps["CapEff"], 16) or int(caps["CapPrm"], 16):
        raise RuntimeError(f"proxy still has capabilities after dropping privileges: {caps}")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--netns", required=True)
    ap.add_argument("--port", type=int, default=3128)
    ap.add_argument("--ctl-fd", type=int, required=True)
    args = ap.parse_args(argv)
    lsock = bind_in_netns(args.netns, args.port)
    drop_privileges()

    async def run():
        server = await asyncio.start_server(handle, sock=lsock, limit=MAX_HEAD)
        log(event="listening", port=args.port, uid=os.getuid())
        async with server:
            await asyncio.gather(server.serve_forever(), control(args.ctl_fd))

    asyncio.run(run())


if __name__ == "__main__":
    main()
