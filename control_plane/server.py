"""JSON-RPC 2.0 over a Unix socket (DESIGN.md §6).

Newline-delimited: one JSON request per line, one response per line. The
socket is root-only (0600); there is no network listener. Requests are
size-capped and every parameter is validated before it reaches the Manager.
"""
from __future__ import annotations

import json
import os
import socketserver
import traceback

from .sandbox import Manager, SandboxError

MAX_REQUEST = 1024 * 1024

# method -> (Manager attribute, allowed params)
METHODS = {
    "create_environment": ("create_environment", {"image"}),
    "fork": ("fork", {"sandbox_id"}),
    "exec": ("exec", {"sandbox_id", "cmd", "timeout", "stdin", "env", "cwd"}),
    "snapshot_info": ("snapshot_info", {"sandbox_id"}),
    "destroy": ("destroy", {"sandbox_id"}),
    "list_sandboxes": ("list_sandboxes", set()),
    "import_image": ("import_image", {"name", "docker_ref"}),
    "list_images": ("list_images", set()),
}
PARAM_ALIASES = {"fork": {"sandbox_id": "parent_id"}}


def dispatch(mgr: Manager, req) -> dict:
    rid = req.get("id") if isinstance(req, dict) else None
    try:
        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or not isinstance(req.get("method"), str):
            return _err(rid, -32600, "invalid request")
        if req["method"] not in METHODS:
            return _err(rid, -32601, f"unknown method {req['method']!r}")
        attr, allowed = METHODS[req["method"]]
        params = req.get("params") or {}
        if not isinstance(params, dict) or set(params) - allowed:
            return _err(rid, -32602, f"params must be an object with keys from {sorted(allowed)}")
        timeout = params.get("timeout")
        if timeout is not None and (not isinstance(timeout, (int, float)) or not 0 < timeout <= 86400):
            return _err(rid, -32602, "timeout must be a number in (0, 86400]")
        for k in ("stdin", "cwd"):
            if params.get(k) is not None and not isinstance(params[k], str):
                return _err(rid, -32602, f"{k} must be a string")
        if params.get("env") is not None and not isinstance(params["env"], dict):
            return _err(rid, -32602, "env must be an object")
        aliases = PARAM_ALIASES.get(req["method"], {})
        kwargs = {aliases.get(k, k): v for k, v in params.items()}
        return {"jsonrpc": "2.0", "id": rid, "result": getattr(mgr, attr)(**kwargs)}
    except SandboxError as e:
        return _err(rid, 1, str(e))
    except TypeError as e:
        return _err(rid, -32602, str(e))
    except Exception as e:
        traceback.print_exc()
        return _err(rid, -32000, f"internal error: {e}")


def _err(rid, code, msg):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": msg}}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            line = self.rfile.readline(MAX_REQUEST + 1)
            if not line:
                return
            if len(line) > MAX_REQUEST:
                self._send(_err(None, -32600, "request too large"))
                return
            try:
                req = json.loads(line)
            except ValueError:
                self._send(_err(None, -32700, "parse error"))
                continue
            self._send(dispatch(self.server.mgr, req))

    def _send(self, resp):
        self.wfile.write(json.dumps(resp).encode() + b"\n")
        self.wfile.flush()


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, mgr: Manager):
        self.mgr = mgr
        path = mgr.cfg.socket_path
        if os.path.exists(path):
            os.unlink(path)
        old = os.umask(0o177)
        try:
            super().__init__(path, Handler)
        finally:
            os.umask(old)
