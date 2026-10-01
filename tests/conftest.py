"""Shared fixtures. Tests need root, Linux x86_64, Docker (to import a base
image) and iproute2/nft. Storage and cgroups follow the host:

- AGENT_SANDBOX_TEST_BTRFS=/path/on/btrfs  -> real btrfs backend; otherwise the
  dev-only full-copy backend is used and the run is marked dev_mode.
- cgroup v2 present at /sys/fs/cgroup -> enforced; otherwise dev_mode and
  cgroup-dependent tests skip with an explicit reason.

The mode each run used is printed in the pytest header so results can't be
mistaken for a target-host run.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
import uuid

import pytest

from control_plane.config import Config
from control_plane.sandbox import Manager

TEST_IMAGE = os.environ.get("AGENT_SANDBOX_TEST_IMAGE", "python:3.12-slim")
HAVE_CGROUP2 = os.path.exists("/sys/fs/cgroup/cgroup.controllers")
BTRFS_ROOT = os.environ.get("AGENT_SANDBOX_TEST_BTRFS")


def pytest_report_header(config):
    return (f"agent-sandbox: storage={'btrfs' if BTRFS_ROOT else 'copy (dev_mode)'} "
            f"cgroup_v2={'yes' if HAVE_CGROUP2 else 'NO (dev_mode, limits not enforced)'}")


requires_cgroup = pytest.mark.skipif(not HAVE_CGROUP2, reason="host has no cgroup v2 unified hierarchy")


class Upstream:
    """A host-side TCP server standing in for an allowlisted destination.
    Replies 'upstream-ok' to every connection."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with c:
                c.sendall(b"upstream-ok\n")


@pytest.fixture(scope="session")
def upstream():
    return Upstream()


@pytest.fixture(scope="session")
def cfg(upstream, tmp_path_factory):
    if os.geteuid() != 0:
        pytest.skip("tests must run as root")
    if not shutil.which("docker") or subprocess.run(["docker", "info"], capture_output=True).returncode:
        pytest.skip("docker daemon required to import the test base image")
    tag = uuid.uuid4().hex[:6]
    store = os.path.join(BTRFS_ROOT, f"sbxtest-{tag}") if BTRFS_ROOT else f"/var/tmp/sbxtest-{tag}"
    c = Config(
        store_root=store,
        run_dir=f"/run/sbxtest-{tag}",
        storage="btrfs" if BTRFS_ROOT else "copy",
        cgroup_root=f"/sys/fs/cgroup/sbxtest-{tag}",
        memory_max="256M",
        pids_max=128,
        dev_mode=not (BTRFS_ROOT and HAVE_CGROUP2),
        egress_allowlist=[f"127.0.0.1:{upstream.port}", f"localhost:{upstream.port}"],
        proxy_port=3128,
        proxy_uid=990_000 + int(tag, 16) % 9000,
    )
    if subprocess.run(["docker", "image", "inspect", TEST_IMAGE], capture_output=True).returncode:
        subprocess.run(["docker", "pull", "-q", TEST_IMAGE], check=True)
    m = Manager(c)
    m.import_image("base", TEST_IMAGE)
    m.close()
    yield c
    m = Manager(c)
    for s in m.list_sandboxes():
        m.destroy(s["id"])
    m.store.delete(m._store("images", "base"))
    m.close()
    netns = m._netns_name()
    subprocess.run(["ip", "netns", "del", netns], capture_output=True)
    subprocess.run(["nft", "delete", "table", "inet", f"sbx_proxy_{c.proxy_uid}"], capture_output=True)
    shutil.rmtree(store, ignore_errors=True)
    shutil.rmtree(c.run_dir, ignore_errors=True)
    if HAVE_CGROUP2 and os.path.isdir(c.cgroup_root):
        os.rmdir(c.cgroup_root)


@pytest.fixture
def mgr(cfg):
    m = Manager(cfg)
    yield m
    for s in m.list_sandboxes():
        m.destroy(s["id"])
    m.close()


@pytest.fixture
def sandbox(mgr):
    return mgr.create_environment("base")["sandbox_id"]


def py(mgr, sid, code, **kw):
    """Run a Python snippet as root inside the sandbox."""
    return mgr.exec(sid, ["python3", "-c", code], **kw)


def as_sandbox_root(mgr, sid, argv, namespaces=("-U", "-n")):
    """Run a HOST binary (e.g. ip, nft) with exactly the sandbox root's
    privileges: its user namespace (so only capabilities over sandbox-owned
    namespaces) plus the listed namespaces, under the same seccomp filter.

    The base image has no iproute2/nft; this is how the tests give the
    adversary those tools without weakening what it is allowed to do.
    """
    from control_plane.sandbox import NSINIT, PYTHON
    st = mgr._load(sid)
    return subprocess.run([PYTHON, "-I", "-S", NSINIT, "enter", mgr.cg.path(sid) or "-", "--",
                           "nsenter", "-t", str(st["holder_pid"]), *namespaces, "--", *argv],
                          capture_output=True, text=True, timeout=30)
