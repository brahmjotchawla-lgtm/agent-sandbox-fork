"""Copy-on-write storage for sandbox root filesystems (DESIGN.md §3).

``BtrfsStore`` is the real backend: images and sandboxes are btrfs
subvolumes, create/fork are writable snapshots, destroy is subvolume delete.

``CopyStore`` is a dev-only fallback that does a full ``cp -a --reflink=auto``.
On a filesystem without reflinks it copies every byte, so it says nothing
about fork cost; it exists so the namespace/cgroup/network lifecycle can be
tested on hosts without btrfs. Config refuses it unless dev_mode is set.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from .util import CommandError, run

BTRFS_SUBVOL_ROOT_INO = 256


class BtrfsStore:
    name = "btrfs"

    def __init__(self, root: str):
        self.root = root
        fstype = run(["stat", "-f", "-c", "%T", root]).stdout.strip()
        if fstype != "btrfs":
            raise RuntimeError(f"{root} is on {fstype}, not btrfs (DESIGN.md §3)")

    def import_tar(self, dst: str, tar_stream) -> None:
        run(["btrfs", "subvolume", "create", dst])
        _untar(dst, tar_stream)
        run(["btrfs", "property", "set", "-ts", dst, "ro", "true"])

    def snapshot(self, src: str, dst: str) -> None:
        # Writable snapshot. btrfs flushes the source's dirty data as part of
        # snapshot creation; tests/test_lifecycle.py verifies this rather
        # than assuming it (DESIGN.md §3).
        run(["btrfs", "subvolume", "snapshot", src, dst])

    def delete(self, path: str) -> None:
        if not os.path.lexists(path):
            return
        # A sandbox's root can create nested subvolumes only if btrfs ioctls
        # get past seccomp; handle them anyway, deepest first, so destroy is
        # total. Subvolume roots are the directories with inode 256.
        nested = []
        for dirpath, dirnames, _ in os.walk(path, topdown=True, followlinks=False):
            for d in dirnames:
                p = os.path.join(dirpath, d)
                st = os.lstat(p)
                if st.st_ino == BTRFS_SUBVOL_ROOT_INO and os.path.isdir(p) and not os.path.islink(p):
                    nested.append(p)
        for p in sorted(nested, key=len, reverse=True):
            run(["btrfs", "property", "set", "-ts", p, "ro", "false"], check=False)
            run(["btrfs", "subvolume", "delete", p])
        run(["btrfs", "property", "set", "-ts", path, "ro", "false"], check=False)
        run(["btrfs", "subvolume", "delete", path])

    def info(self, path: str) -> dict:
        out = run(["btrfs", "subvolume", "show", path]).stdout
        info = {"backend": self.name}
        for line in out.splitlines():
            k, sep, v = line.strip().partition(":")
            if sep and k in ("UUID", "Parent UUID", "Subvolume ID", "Generation", "Creation time"):
                info[k.lower().replace(" ", "_")] = v.strip()
        return info


class CopyStore:
    name = "copy"

    def __init__(self, root: str):
        self.root = root

    def import_tar(self, dst: str, tar_stream) -> None:
        os.mkdir(dst)
        _untar(dst, tar_stream)

    def snapshot(self, src: str, dst: str) -> None:
        run(["cp", "-a", "--reflink=auto", src, dst], timeout=600)

    def delete(self, path: str) -> None:
        if os.path.lexists(path):
            shutil.rmtree(path)

    def info(self, path: str) -> dict:
        return {"backend": self.name, "note": "full copy; not copy-on-write"}


def _untar(dst: str, tar_stream) -> None:
    p = subprocess.run(["tar", "--numeric-owner", "-xpf", "-", "-C", dst],
                       stdin=tar_stream, capture_output=True, text=True)
    if p.returncode != 0:
        raise CommandError(f"tar extract into {dst} failed: {p.stderr.strip()}")


def open_store(kind: str, root: str):
    return BtrfsStore(root) if kind == "btrfs" else CopyStore(root)
