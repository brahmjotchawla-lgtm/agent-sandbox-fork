from __future__ import annotations

import dataclasses
import json
import os


@dataclasses.dataclass
class Config:
    state_dir: str = "/var/lib/sandboxd"
    run_dir: str = "/run/sandboxd"
    # btrfs backing store: a dedicated block device if given, else a sparse loopback file.
    btrfs_device: str | None = None
    btrfs_image: str | None = None  # default: <state_dir>/btrfs.img
    btrfs_size_gb: int = 40
    cgroup_root: str = "/sys/fs/cgroup/sandboxd"
    # Each sandbox gets its own 65536-wide host uid/gid range starting here.
    # Chosen far above typical /etc/subuid allocations (100000+).
    uid_base_start: int = 0x40000000
    uid_size: int = 65536
    max_sandboxes: int = 4096
    default_limits: dict = dataclasses.field(
        default_factory=lambda: {
            "memory_max": str(2 << 30),
            "memory_swap_max": "0",
            "pids_max": "1024",
            "cpu_max": "max 100000",
        }
    )
    # Max bytes of stdout/stderr captured per exec. Output past this is dropped,
    # so a sandbox cannot make the control plane buffer unbounded data.
    exec_output_cap: int = 16 << 20
    # Test-only: allows requests to carry a fault-injection point.
    allow_faults: bool = False
    # Phase 3 settings (network + seccomp) live in the same file.
    network: bool = False
    seccomp: bool = False
    egress_allowlist: list = dataclasses.field(default_factory=list)

    @property
    def volume(self) -> str:
        return os.path.join(self.state_dir, "vol")

    @property
    def image_path(self) -> str:
        return self.btrfs_image or os.path.join(self.state_dir, "btrfs.img")

    @classmethod
    def load(cls, path: str | None) -> "Config":
        if not path:
            return cls()
        with open(path) as f:
            data = json.load(f)
        return cls(**data)
