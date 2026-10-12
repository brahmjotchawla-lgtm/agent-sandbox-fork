"""Thin client for the control plane's Unix-socket JSON-RPC API."""
from __future__ import annotations

import base64
import itertools
import json
import socket


class RemoteError(Exception):
    def __init__(self, type_: str, message: str):
        super().__init__(f"{type_}: {message}")
        self.type = type_


class Client:
    def __init__(self, path: str = "/run/sandboxd/sandboxd.sock", timeout: float | None = None):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self.f = self.sock.makefile("rwb")
        self._ids = itertools.count(1)

    def call(self, method: str, **params):
        rid = next(self._ids)
        self.f.write(json.dumps({"id": rid, "method": method, "params": params}).encode() + b"\n")
        self.f.flush()
        line = self.f.readline()
        if not line:
            raise ConnectionError("control plane closed the connection")
        resp = json.loads(line)
        if "error" in resp:
            raise RemoteError(resp["error"]["type"], resp["error"]["message"])
        return resp["result"]

    def create_environment(self, base_image: str, limits: dict | None = None) -> dict:
        return self.call("create_environment", base_image=base_image, limits=limits)

    def fork(self, sandbox_id: str, limits: dict | None = None) -> dict:
        """Environment fork: filesystem + fresh namespaces/cgroup + fresh process tree (not a memory fork)."""
        return self.call("fork", sandbox_id=sandbox_id, limits=limits)

    def exec(self, sandbox_id: str, cmd: list[str], env=None, cwd="/", timeout=60.0, stdin: bytes | None = None) -> dict:
        r = self.call("exec", sandbox_id=sandbox_id, cmd=cmd, env=env, cwd=cwd, timeout=timeout,
                      stdin_b64=base64.b64encode(stdin).decode() if stdin else None)
        r["stdout"] = base64.b64decode(r.pop("stdout_b64"))
        r["stderr"] = base64.b64decode(r.pop("stderr_b64"))
        return r

    def snapshot_info(self, sandbox_id: str) -> dict:
        return self.call("snapshot_info", sandbox_id=sandbox_id)

    def destroy(self, sandbox_id: str) -> dict:
        return self.call("destroy", sandbox_id=sandbox_id)

    def list_sandboxes(self) -> list[str]:
        return self.call("list_sandboxes")

    def close(self):
        self.f.close()
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
