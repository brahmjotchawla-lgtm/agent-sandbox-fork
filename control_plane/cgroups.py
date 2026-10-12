"""cgroup v2, driven directly through the cgroup filesystem.

A sandbox's cgroup is the single source of truth for which host processes
belong to it. That is why destroy and crash-cleanup kill via
`cgroup.kill` (Linux >= 5.14) rather than by chasing PIDs: a PID can be
reused, and a sandbox can fork faster than anyone can enumerate it, but
neither can leave the cgroup.
"""
from __future__ import annotations

import errno
import os
import select
import time

CGROUP_FS = "/sys/fs/cgroup"
CONTROLLERS = ("cpu", "memory", "pids", "io")


def _write(path: str, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try:
        os.write(fd, value.encode())
    finally:
        os.close(fd)


def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def events(path: str) -> dict[str, str]:
    out = {}
    for line in _read(os.path.join(path, "cgroup.events")).splitlines():
        k, _, v = line.partition(" ")
        out[k] = v
    return out


def wait_event(path: str, key: str, value: str, timeout: float) -> None:
    """Block until cgroup.events has `key value`, without busy-polling.

    kernfs signals POLLPRI on cgroup.events whenever it changes.
    """
    deadline = time.monotonic() + timeout
    fd = os.open(os.path.join(path, "cgroup.events"), os.O_RDONLY | os.O_CLOEXEC)
    try:
        p = select.poll()
        p.register(fd, select.POLLPRI | select.POLLERR)
        while True:
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, 4096).decode()
            if f"{key} {value}" in data.splitlines():
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{path}: {key} did not become {value} within {timeout}s (now: {data.strip()!r})")
            p.poll(min(remaining, 0.5) * 1000)
    finally:
        os.close(fd)


class CgroupTree:
    def __init__(self, root: str):
        if not os.path.realpath(root).startswith(CGROUP_FS + "/"):
            raise ValueError(f"cgroup root must be under {CGROUP_FS}: {root}")
        self.root = root

    def ensure(self) -> None:
        """Create the sandboxd subtree and enable controllers down to it."""
        rel = os.path.relpath(self.root, CGROUP_FS)
        cur = CGROUP_FS
        for part in rel.split("/"):
            self._enable_controllers(cur)
            cur = os.path.join(cur, part)
            os.makedirs(cur, exist_ok=True)
        self._enable_controllers(self.root)

    @staticmethod
    def _enable_controllers(path: str) -> None:
        available = _read(os.path.join(path, "cgroup.controllers")).split()
        enabled = _read(os.path.join(path, "cgroup.subtree_control")).split()
        missing = [c for c in CONTROLLERS if c in available and c not in enabled]
        if missing:
            _write(os.path.join(path, "cgroup.subtree_control"), " ".join("+" + c for c in missing))
        not_available = [c for c in CONTROLLERS if c not in available]
        if not_available and path != CGROUP_FS:
            raise RuntimeError(f"cgroup controllers not available at {path}: {not_available}")

    def path(self, sid: str) -> str:
        return os.path.join(self.root, sid)

    def create(self, sid: str, limits: dict) -> str:
        p = self.path(sid)
        os.mkdir(p)
        self.set_limits(sid, limits)
        return p

    def set_limits(self, sid: str, limits: dict) -> None:
        p = self.path(sid)
        mapping = {
            "memory_max": "memory.max",
            "memory_swap_max": "memory.swap.max",
            "pids_max": "pids.max",
            "cpu_max": "cpu.max",
            "io_max": "io.max",
        }
        for key, fname in mapping.items():
            if limits.get(key) is not None:
                _write(os.path.join(p, fname), str(limits[key]))

    def exists(self, sid: str) -> bool:
        return os.path.isdir(self.path(sid))

    def list(self) -> list[str]:
        try:
            return sorted(e.name for e in os.scandir(self.root) if e.is_dir(follow_symlinks=False))
        except FileNotFoundError:
            return []

    def procs(self, sid: str) -> list[int]:
        out = []
        for dirpath, _, _ in os.walk(self.path(sid)):
            try:
                out += [int(x) for x in _read(os.path.join(dirpath, "cgroup.procs")).split()]
            except FileNotFoundError:
                pass
        return out

    def add_proc(self, sid: str, pid: int) -> None:
        _write(os.path.join(self.path(sid), "cgroup.procs"), str(pid))

    def freeze(self, sid: str, timeout: float = 10.0) -> None:
        _write(os.path.join(self.path(sid), "cgroup.freeze"), "1")
        wait_event(self.path(sid), "frozen", "1", timeout)

    def thaw(self, sid: str, timeout: float = 10.0) -> None:
        _write(os.path.join(self.path(sid), "cgroup.freeze"), "0")
        wait_event(self.path(sid), "frozen", "0", timeout)

    def is_frozen(self, sid: str) -> bool:
        return events(self.path(sid)).get("frozen") == "1"

    def kill(self, sid: str, timeout: float = 10.0) -> None:
        """SIGKILL every process in the cgroup subtree and wait until it is empty.

        cgroup.kill also works on a frozen cgroup: SIGKILL wakes frozen tasks.
        """
        p = self.path(sid)
        if not os.path.isdir(p):
            return
        _write(os.path.join(p, "cgroup.kill"), "1")
        wait_event(p, "populated", "0", timeout)

    def remove(self, sid: str, timeout: float = 10.0) -> None:
        p = self.path(sid)
        if not os.path.isdir(p):
            return
        self.kill(sid, timeout)
        # Children first. Sandboxes cannot create child cgroups (their cgroup
        # directory is owned by host root), but we don't rely on that here.
        for dirpath, dirnames, _ in sorted(os.walk(p), key=lambda t: t[0].count("/"), reverse=True):
            deadline = time.monotonic() + timeout
            while True:
                try:
                    os.rmdir(dirpath)
                    break
                except FileNotFoundError:
                    break
                except OSError as e:
                    if e.errno != errno.EBUSY or time.monotonic() > deadline:
                        raise
                    time.sleep(0.005)

    def stat(self, sid: str) -> dict:
        p = self.path(sid)
        out = {}
        for f in ("memory.current", "memory.peak", "pids.current", "memory.events", "pids.events"):
            try:
                out[f] = _read(os.path.join(p, f)).strip()
            except OSError:
                pass
        return out
