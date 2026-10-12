"""Local Unix-domain-socket JSON-RPC front end (DESIGN.md §6).

Deliberately not a network port. The socket lives in a root-owned 0700
directory. Each connection's peer credentials (SO_PEERCRED) are checked
against an allowlist of uids, because anyone who can talk to this socket
can create root-equivalent-on-the-sandbox resources.

Wire format: one JSON object per line.
    -> {"id": 1, "method": "fork", "params": {"sandbox_id": "sb-..."}}
    <- {"id": 1, "result": {...}}   or   {"id": 1, "error": {"type": ..., "message": ...}}
exec's stdout/stderr (and stdin) are base64-encoded.

    sudo python3 -m control_plane.server --config /etc/sandboxd.json
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import signal
import socket
import struct
import sys
import threading

from .config import Config
from .manager import SandboxError, SandboxManager

MAX_REQUEST = 1 << 20


class Server:
    def __init__(self, manager: SandboxManager, path: str, allowed_uids=(0,)):
        self.m = manager
        self.path = path
        self.allowed_uids = set(allowed_uids)
        self.sock: socket.socket | None = None
        self._stop = threading.Event()

    def methods(self):
        m = self.m
        return {
            "ping": lambda: "pong",
            "create_environment": lambda base_image, limits=None, fault=None, egress_allow=None: m.create_environment(base_image, limits, fault, egress_allow),
            "fork": lambda sandbox_id, limits=None, fault=None, egress_allow=None: m.fork(sandbox_id, limits, fault, egress_allow),
            "exec": self._exec,
            "snapshot_info": lambda sandbox_id: m.snapshot_info(sandbox_id),
            "destroy": lambda sandbox_id: m.destroy(sandbox_id),
            "list_sandboxes": lambda: m.list_sandboxes(),
            "import_image": lambda name, tar_path: m.import_image(name, tar_path),
            "list_images": lambda: m.list_images(),
            "host_info": lambda: {"volume": m.volume_info, "pid": os.getpid()},
        }

    def _exec(self, sandbox_id, cmd, env=None, cwd="/", timeout=60.0, stdin_b64=None, fault=None):
        stdin = base64.b64decode(stdin_b64) if stdin_b64 else None
        r = self.m.exec(sandbox_id, cmd, env=env, cwd=cwd, timeout=float(timeout), stdin=stdin, fault=fault)
        r["stdout_b64"] = base64.b64encode(r.pop("stdout")).decode()
        r["stderr_b64"] = base64.b64encode(r.pop("stderr")).decode()
        return r

    def serve(self) -> None:
        d = os.path.dirname(self.path)
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
        if os.path.exists(self.path):
            os.unlink(self.path)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        os.chmod(self.path, 0o600)
        self.sock.listen(64)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def stop(self):
        self._stop.set()
        if self.sock:
            self.sock.close()

    def _handle(self, conn: socket.socket) -> None:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", creds)
        f = conn.makefile("rwb")
        try:
            if uid not in self.allowed_uids:
                f.write(json.dumps({"id": None, "error": {"type": "PermissionError", "message": f"uid {uid} not allowed"}}).encode() + b"\n")
                f.flush()
                return
            table = self.methods()
            while True:
                line = f.readline(MAX_REQUEST + 1)
                if not line:
                    return
                if len(line) > MAX_REQUEST:
                    raise ValueError("request too large")
                req = json.loads(line)
                rid = req.get("id")
                try:
                    fn = table[req["method"]]
                    result = fn(**(req.get("params") or {}))
                    resp = {"id": rid, "result": result}
                except (SandboxError, KeyError, TypeError, ValueError, OSError, TimeoutError) as e:
                    resp = {"id": rid, "error": {"type": type(e).__name__, "message": str(e)}}
                f.write(json.dumps(resp).encode() + b"\n")
                f.flush()
        except (OSError, ValueError):
            pass
        finally:
            try:
                f.close()
                conn.close()
            except OSError:
                pass


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config")
    ap.add_argument("--socket", help="default: <run_dir>/sandboxd.sock")
    ap.add_argument("--allow-uid", type=int, action="append", default=[0])
    args = ap.parse_args(argv)
    cfg = Config.load(args.config)
    m = SandboxManager(cfg)
    report = m.start()
    print(json.dumps({"event": "started", "pid": os.getpid(), **report}), flush=True)
    srv = Server(m, args.socket or os.path.join(cfg.run_dir, "sandboxd.sock"), args.allow_uid)

    def _term(*_):
        srv.stop()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    try:
        srv.serve()
    finally:
        # Sandboxes are left running on purpose: a restart re-adopts them.
        m.close()


if __name__ == "__main__":
    sys.exit(main())
