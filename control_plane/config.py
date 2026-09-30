"""Control-plane configuration.

Defaults describe the target deployment (btrfs store, cgroup v2 enforced).
``dev_mode`` exists only so the lifecycle code can be exercised on hosts that
lack btrfs or cgroup v2 (for example the Claude cloud container this code was
first written in). It is recorded in every sandbox's metadata and the
benchmark harness refuses to produce claim-grade output with it on.
"""
from __future__ import annotations

import dataclasses
import json
import os


@dataclasses.dataclass
class Config:
    # Store root. With storage="btrfs" this must be a directory on a btrfs
    # filesystem, mounted nosuid,nodev on the host (files inside sandboxes are
    # stored with their in-sandbox owners, e.g. uid 0).
    store_root: str = "/var/lib/agent-sandbox"
    run_dir: str = "/run/agent-sandbox"
    storage: str = "btrfs"  # "btrfs" | "copy" (dev_mode only; full copies)

    cgroup_root: str = "/sys/fs/cgroup/agent-sandbox"
    # Per-sandbox cgroup v2 limits. None = leave the kernel default (max).
    memory_max: str | None = "2G"
    memory_swap_max: str | None = "0"
    pids_max: int | None = 1024
    cpu_max: str | None = None  # e.g. "200000 100000" = 2 CPUs

    # Sandbox N's root maps to host uids [uid_base + N*65536, +65536).
    uid_base: int = 1_000_000
    max_sandboxes: int = 1024

    network: bool = True
    # Egress allowlist for the CONNECT proxy: "host:port", "*.suffix:port",
    # or "IP:port". Hostname entries never resolve to private/loopback/
    # link-local addresses; an IP entry is an explicit opt-in to that address.
    egress_allowlist: list[str] = dataclasses.field(default_factory=list)
    proxy_port: int = 3128

    dev_mode: bool = False

    @property
    def socket_path(self) -> str:
        return os.path.join(self.run_dir, "control.sock")

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        path = path or os.environ.get("AGENT_SANDBOX_CONFIG")
        if not path:
            return cls()
        with open(path) as f:
            data = json.load(f)
        unknown = set(data) - {f.name for f in dataclasses.fields(cls)}
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        return cls(**data)

    def validate(self) -> None:
        if os.uname().machine != "x86_64":
            raise RuntimeError("only x86_64 is supported (seccomp filter uses x86_64 syscall numbers)")
        if self.storage not in ("btrfs", "copy"):
            raise ValueError(f"unknown storage backend {self.storage!r}")
        if self.storage == "copy" and not self.dev_mode:
            raise ValueError("storage='copy' is a full-copy dev backend; it requires dev_mode=true")
