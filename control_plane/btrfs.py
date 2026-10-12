"""btrfs subvolume operations via ioctl(2), not by shelling out to btrfs-progs.

A snapshot is one ioctl on the destination directory, so there is no process
spawn in the fork path. The struct layouts and ioctl numbers come from
include/uapi/linux/btrfs.h:

    struct btrfs_ioctl_vol_args    { __s64 fd; char name[4088]; }      4096 bytes
    struct btrfs_ioctl_vol_args_v2 { __s64 fd; __u64 transid; __u64 flags;
                                     __u64 unused[4]; char name[4040]; } 4096 bytes

    _IOW(type, nr, size) = (1 << 30) | (size << 16) | (type << 8) | nr
"""
from __future__ import annotations

import errno
import fcntl
import os
import stat
import struct
import subprocess

BTRFS_IOCTL_MAGIC = 0x94
_ARGS_SIZE = 4096


def _iow(nr: int, size: int = _ARGS_SIZE) -> int:
    return (1 << 30) | (size << 16) | (BTRFS_IOCTL_MAGIC << 8) | nr


BTRFS_IOC_SUBVOL_CREATE = _iow(14)
BTRFS_IOC_SNAP_DESTROY = _iow(15)
BTRFS_IOC_SNAP_CREATE_V2 = _iow(23)
BTRFS_SUBVOL_RDONLY = 1 << 1
BTRFS_FIRST_FREE_OBJECTID = 256  # inode number of every subvolume's root directory
BTRFS_SUPER_MAGIC = 0x9123683E


def _vol_args(fd: int, name: str) -> bytearray:
    raw = name.encode()
    if not raw or b"/" in raw or len(raw) > 4087 or raw in (b".", b".."):
        raise ValueError(f"bad subvolume name {name!r}")
    buf = bytearray(_ARGS_SIZE)
    struct.pack_into("q", buf, 0, fd)
    buf[8 : 8 + len(raw)] = raw
    return buf


def _vol_args_v2(fd: int, name: str, flags: int) -> bytearray:
    raw = name.encode()
    if not raw or b"/" in raw or len(raw) > 4039 or raw in (b".", b".."):
        raise ValueError(f"bad subvolume name {name!r}")
    buf = bytearray(_ARGS_SIZE)
    struct.pack_into("qQQ", buf, 0, fd, 0, flags)
    buf[56 : 56 + len(raw)] = raw
    return buf


def _open_dir(path: str) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def create_subvolume(path: str) -> None:
    parent, name = os.path.split(path.rstrip("/"))
    pfd = _open_dir(parent)
    try:
        fcntl.ioctl(pfd, BTRFS_IOC_SUBVOL_CREATE, _vol_args(0, name))
    finally:
        os.close(pfd)


def snapshot(src: str, dst: str, readonly: bool = False) -> None:
    """Snapshot subvolume `src` to new subvolume `dst`. Shares all extents (no data copy).

    The kernel flushes the source subvolume's dirty page-cache data
    (delalloc) before taking the snapshot, so writes that completed before
    this call are in the snapshot even if they were never fsync'd. Phase 2's
    fork-during-I/O test checks this. It is not assumed.
    """
    parent, name = os.path.split(dst.rstrip("/"))
    sfd = _open_dir(src)
    try:
        pfd = _open_dir(parent)
        try:
            fcntl.ioctl(pfd, BTRFS_IOC_SNAP_CREATE_V2, _vol_args_v2(sfd, name, BTRFS_SUBVOL_RDONLY if readonly else 0))
        finally:
            os.close(pfd)
    finally:
        os.close(sfd)


def _destroy_one(path: str) -> None:
    parent, name = os.path.split(path.rstrip("/"))
    pfd = _open_dir(parent)
    try:
        fcntl.ioctl(pfd, BTRFS_IOC_SNAP_DESTROY, _vol_args(0, name))
    finally:
        os.close(pfd)


def is_subvolume(path: str) -> bool:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(st.st_mode) and st.st_ino == BTRFS_FIRST_FREE_OBJECTID


def nested_subvolumes(path: str) -> list[str]:
    """Subvolumes strictly below `path`, deepest first.

    The tree is sandbox-controlled content, so this never follows symlinks.
    os.walk uses lstat-based scandir and followlinks=False. It is only
    called after every process in the sandbox is dead, so the tree cannot
    change under us.
    """
    found = []
    root_dev = os.lstat(path).st_dev
    for dirpath, dirnames, _ in os.walk(path, topdown=True, followlinks=False):
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode) and st.st_ino == BTRFS_FIRST_FREE_OBJECTID and st.st_dev != root_dev:
                found.append(full)
            keep.append(d)
        dirnames[:] = keep
    found.sort(key=lambda p: p.count("/"), reverse=True)
    return found


def delete_subvolume(path: str) -> None:
    """Delete a subvolume, including any subvolumes nested inside it.

    A sandbox's root can create nested subvolumes (subvolume creation needs only
    write permission on the directory) unless seccomp blocks it, and a subvolume
    with children cannot be deleted. So we delete the children first.
    """
    if not os.path.lexists(path):
        return
    try:
        _destroy_one(path)
        return
    except OSError as e:
        if e.errno != errno.ENOTEMPTY:
            raise
    for child in nested_subvolumes(path):
        _destroy_one(child)
    _destroy_one(path)


def fs_magic(path: str) -> int:
    # statfs is not exposed in os; `stat -f` is cheap and only used at start-up.
    out = subprocess.run(["stat", "-f", "-c", "%t", path], capture_output=True, text=True, check=True).stdout.strip()
    return int(out, 16)


def is_btrfs(path: str) -> bool:
    try:
        return fs_magic(path) == BTRFS_SUPER_MAGIC
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
        return False


def ensure_volume(mountpoint: str, image: str | None, device: str | None, size_gb: int) -> dict:
    """Make sure a btrfs filesystem is mounted at `mountpoint`.

    Prefers a dedicated block device and falls back to a sparse loopback file.
    Returns a description of the backing store, which every benchmark result
    must record (BENCHMARKS.md §3.6).
    """
    os.makedirs(mountpoint, mode=0o700, exist_ok=True)
    if not is_btrfs(mountpoint):
        if device:
            src, opts = device, "nosuid,nodev,noatime"
        else:
            if not image:
                raise RuntimeError("need either a block device or a loopback image path for the btrfs volume")
            if not os.path.exists(image):
                with open(image, "wb") as f:
                    f.truncate(size_gb << 30)
                subprocess.run(["mkfs.btrfs", "-q", image], check=True)
            src, opts = image, "loop,nosuid,nodev,noatime"
        subprocess.run(["mount", "-t", "btrfs", "-o", opts, src, mountpoint], check=True)
    os.chmod(mountpoint, 0o700)
    for sub in ("images", "sandboxes"):
        p = os.path.join(mountpoint, sub)
        if not os.path.isdir(p):
            os.mkdir(p, 0o700)
    src = subprocess.run(["findmnt", "-n", "-o", "SOURCE,OPTIONS", "--target", mountpoint], capture_output=True, text=True).stdout.strip()
    return {"mountpoint": mountpoint, "backing": "block-device" if device else "loopback-file", "device": device, "image": image if not device else None, "findmnt": src}


def backing_devno(mountpoint: str) -> str | None:
    """major:minor of the block device behind the btrfs mount (the loop device, for a loopback file).

    cgroup io.max is keyed by this device.
    """
    src = subprocess.run(["findmnt", "-n", "-o", "SOURCE", "--target", mountpoint], capture_output=True, text=True).stdout.strip()
    src = src.split("[", 1)[0]
    if not src.startswith("/dev/"):
        return None
    st = os.stat(src)
    return f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
