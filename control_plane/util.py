"""Small helpers shared by the control plane modules."""
from __future__ import annotations

import json
import os
import subprocess
import time


class CommandError(RuntimeError):
    pass


def run(cmd: list[str], *, check: bool = True, input: str | None = None,
        timeout: float = 60) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, capture_output=True, text=True, input=input, timeout=timeout)
    if check and p.returncode != 0:
        raise CommandError(f"{' '.join(cmd)} -> rc={p.returncode}: {p.stderr.strip() or p.stdout.strip()}")
    return p


def write_json_atomic(path: str, data: dict) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def read_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def proc_start_time(pid: int) -> int | None:
    """Kernel start time of a pid (clock ticks since boot), to detect pid reuse."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            stat = f.read()
    except OSError:
        return None
    # comm (field 2) may contain spaces/parens; fields after the last ')' are fixed.
    return int(stat.rsplit(")", 1)[1].split()[19])


def pid_alive(pid: int | None, start_time: int | None) -> bool:
    if not pid:
        return False
    st = proc_start_time(pid)
    if st is None or (start_time is not None and st != start_time):
        return False
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("State:"):
                    return "Z" not in line.split()[1]
    except OSError:
        return False
    return True


def wait_until(pred, timeout: float, interval: float = 0.005) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if pred():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def ms(t0: float, t1: float) -> float:
    return round((t1 - t0) * 1000, 3)


def is_mountpoint(path: str) -> bool:
    """True if path is a mount point in our mount namespace.

    os.path.ismount() misses bind mounts from the same filesystem (same
    st_dev), which is exactly what the idmapped rootfs mounts are.
    """
    path = os.path.realpath(path)
    with open("/proc/self/mountinfo") as f:
        for line in f:
            mp = line.split()[4]
            mp = mp.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
            if mp == path:
                return True
    return False
