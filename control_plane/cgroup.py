"""cgroup v2 management: one leaf cgroup per sandbox.

A cgroup is a kernel object that groups processes so limits (memory, CPU,
pid count) and operations (freeze, kill) apply to the whole group. Every
process a sandbox ever runs is placed in its leaf before any sandbox code
executes (control_plane/nsinit.py joins it first), so the limits and the
freeze used by fork cover the whole sandbox, including processes that
daemonize or re-parent themselves.

Nothing cgroup-related is mounted inside the sandbox, and the sandbox gets
its own cgroup namespace, so sandboxed root cannot write its own limits.
"""
from __future__ import annotations

import os
import time

from .util import wait_until

CONTROLLERS = ("cpu", "memory", "pids", "io")


class CgroupV2:
    enforced = True

    def __init__(self, root: str):
        self.root = root
        mnt = os.path.dirname(root)
        if not os.path.exists(os.path.join(mnt, "cgroup.controllers")):
            raise RuntimeError(f"{mnt} is not a cgroup v2 hierarchy (DESIGN.md §5.2)")
        os.makedirs(root, exist_ok=True)
        available = set(_read(os.path.join(mnt, "cgroup.controllers")).split())
        missing = {"memory", "pids", "cpu"} - available
        if missing:
            raise RuntimeError(f"cgroup v2 controllers not available: {sorted(missing)}")
        wanted = [c for c in CONTROLLERS if c in available]
        for d in (mnt, root):
            enabled = set(_read(os.path.join(d, "cgroup.subtree_control")).split())
            todo = " ".join(f"+{c}" for c in wanted if c not in enabled)
            if todo:
                _write(os.path.join(d, "cgroup.subtree_control"), todo)

    def path(self, name: str) -> str:
        return os.path.join(self.root, name)

    def create(self, name: str, *, memory_max=None, memory_swap_max=None,
               pids_max=None, cpu_max=None) -> str:
        p = self.path(name)
        os.mkdir(p)
        for fname, val in (("memory.max", memory_max), ("memory.swap.max", memory_swap_max),
                           ("pids.max", pids_max), ("cpu.max", cpu_max)):
            if val is not None and os.path.exists(os.path.join(p, fname)):
                _write(os.path.join(p, fname), str(val))
        return p

    def freeze(self, name: str, timeout: float = 5.0) -> None:
        p = self.path(name)
        _write(os.path.join(p, "cgroup.freeze"), "1")
        if not wait_until(lambda: "frozen 1" in _read(os.path.join(p, "cgroup.events")), timeout):
            _write(os.path.join(p, "cgroup.freeze"), "0")
            raise TimeoutError(f"cgroup {name} did not freeze within {timeout}s")

    def thaw(self, name: str) -> None:
        _write(os.path.join(self.path(name), "cgroup.freeze"), "0")

    def kill_and_remove(self, name: str, timeout: float = 10.0) -> None:
        p = self.path(name)
        if not os.path.isdir(p):
            return
        # cgroup.kill (5.14+) SIGKILLs every process, including ones forked
        # concurrently; a frozen cgroup must be thawed for them to die.
        _write(os.path.join(p, "cgroup.freeze"), "0")
        _write(os.path.join(p, "cgroup.kill"), "1")
        if not wait_until(lambda: "populated 0" in _read(os.path.join(p, "cgroup.events")), timeout):
            raise TimeoutError(f"cgroup {name} still populated after kill")
        deadline = time.monotonic() + timeout
        while True:
            try:
                os.rmdir(p)
                return
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.01)

    def list(self) -> list[str]:
        return sorted(d for d in os.listdir(self.root) if os.path.isdir(self.path(d)))

    def stats(self, name: str) -> dict:
        p = self.path(name)
        out = {}
        for f in ("memory.current", "memory.max", "pids.current", "pids.max"):
            try:
                out[f] = _read(os.path.join(p, f))
            except OSError:
                pass
        return out


class NoCgroup:
    """dev_mode stand-in when the host has no usable cgroup v2.

    Nothing is enforced and fork cannot freeze the parent. Sandbox metadata
    records ``cgroup_enforced: false`` so this is never mistaken for the
    real configuration.
    """
    enforced = False

    def __init__(self, root: str):
        self.root = root

    def path(self, name):
        return None

    def create(self, name, **_):
        return None

    def freeze(self, name, timeout=5.0):
        pass

    def thaw(self, name):
        pass

    def kill_and_remove(self, name, timeout=10.0):
        pass

    def list(self):
        return []

    def stats(self, name):
        return {}


def open_cgroups(root: str, dev_mode: bool):
    try:
        return CgroupV2(root)
    except RuntimeError:
        if dev_mode:
            return NoCgroup(root)
        raise


def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def _write(path: str, value: str) -> None:
    with open(path, "w") as f:
        f.write(value)
