"""Thin client for the control-plane socket.

    from control_plane.client import Client
    c = Client()
    sid = c.create_environment("workload")["sandbox_id"]
    child = c.fork(sid)["sandbox_id"]
    print(c.exec(child, ["python3", "-c", "print(1)"]))
"""
from __future__ import annotations

import itertools
import json
import socket

DEFAULT_SOCKET = "/run/agent-sandbox/control.sock"


class RPCError(Exception):
    def __init__(self, code, message):
        super().__init__(f"[{code}] {message}")
        self.code = code


class Client:
    def __init__(self, path: str = DEFAULT_SOCKET):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.f = self.sock.makefile("rwb")
        self.ids = itertools.count(1)

    def call(self, method: str, **params):
        rid = next(self.ids)
        self.f.write(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method,
                                 "params": params}).encode() + b"\n")
        self.f.flush()
        line = self.f.readline()
        if not line:
            raise ConnectionError("control plane closed the connection")
        resp = json.loads(line)
        if "error" in resp:
            raise RPCError(resp["error"]["code"], resp["error"]["message"])
        return resp["result"]

    def create_environment(self, image):
        return self.call("create_environment", image=image)

    def fork(self, sandbox_id):
        return self.call("fork", sandbox_id=sandbox_id)

    def exec(self, sandbox_id, cmd, **kw):
        return self.call("exec", sandbox_id=sandbox_id, cmd=cmd, **kw)

    def snapshot_info(self, sandbox_id):
        return self.call("snapshot_info", sandbox_id=sandbox_id)

    def destroy(self, sandbox_id):
        return self.call("destroy", sandbox_id=sandbox_id)

    def list_sandboxes(self):
        return self.call("list_sandboxes")

    def close(self):
        self.f.close()
        self.sock.close()
