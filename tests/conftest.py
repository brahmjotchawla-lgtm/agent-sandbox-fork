"""Shared fixtures. These tests drive real kernel primitives and need root on Linux.

    sudo python3 -m pytest tests/ -v

They use their own state dir, cgroup subtree and btrfs loopback volume, so they
never touch a production /var/lib/sandboxd.
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from control_plane.client import Client  # noqa: E402
from control_plane.config import Config  # noqa: E402
from control_plane.manager import SandboxManager  # noqa: E402

if platform.system() != "Linux" or os.geteuid() != 0:
    pytest.skip("sandbox tests need root on Linux", allow_module_level=True)

BUSYBOX_TAR = "/var/tmp/sandboxd-test-busybox.tar"


def make_config(name: str, **kw) -> Config:
    return Config(
        state_dir=f"/var/lib/sandboxd-{name}",
        run_dir=f"/run/sandboxd-{name}",
        cgroup_root=f"/sys/fs/cgroup/sandboxd-{name}",
        btrfs_size_gb=8,
        allow_faults=True,
        **kw,
    )


def ensure_busybox_image(m: SandboxManager) -> None:
    if "busybox" in m.list_images():
        return
    if not os.path.exists(BUSYBOX_TAR):
        subprocess.run(["sh", os.path.join(REPO, "scripts", "make_busybox_rootfs.sh"), BUSYBOX_TAR], check=True)
    m.import_image("busybox", BUSYBOX_TAR)


@pytest.fixture(scope="session")
def mgr():
    m = SandboxManager(make_config("test"))
    m.start()
    ensure_busybox_image(m)
    yield m
    for sid in m.list_sandboxes():
        m.destroy(sid)
    m.close()


class Tracker:
    """Creates sandboxes and, at teardown, destroys them and asserts nothing leaked."""

    def __init__(self, m: SandboxManager):
        self.m = m
        self.ids: list[tuple[str, int | None]] = []

    def _track(self, sid):
        rec = self.m._sandboxes.get(sid, {})
        self.ids.append((sid, rec.get("userns_inode")))
        return sid

    def create(self, image="busybox", **kw) -> str:
        return self._track(self.m.create_environment(image, **kw)["id"])

    def fork(self, parent, **kw) -> str:
        return self._track(self.m.fork(parent, **kw)["id"])

    def sh(self, sid, script, **kw):
        return self.m.exec(sid, ["sh", "-c", script], **kw)

    def finish(self):
        problems = []
        for sid, ino in self.ids:
            if sid in self.m._sandboxes:
                self.m.destroy(sid)
            leaks = self.m.audit(sid, ino)
            if leaks:
                problems.append((sid, leaks))
        assert not problems, f"leaked resources: {problems}"


@pytest.fixture
def sb(mgr):
    t = Tracker(mgr)
    yield t
    t.finish()


class Daemon:
    """The control plane as a separate process, so tests can SIGKILL it mid-operation."""

    def __init__(self, name: str, **cfg_kw):
        self.cfg = make_config(name, **cfg_kw)
        self.cfg_path = f"/run/sandboxd-{name}.json"
        with open(self.cfg_path, "w") as f:
            json.dump(self.cfg.__dict__, f)
        self.sock = os.path.join(self.cfg.run_dir, "sandboxd.sock")
        self.proc = None

    def start(self) -> dict:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "control_plane.server", "--config", self.cfg_path],
            cwd=REPO, stdout=subprocess.PIPE, text=True,
        )
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("daemon failed to start")
        info = json.loads(line)
        deadline = time.monotonic() + 10
        while not os.path.exists(self.sock):
            if time.monotonic() > deadline:
                raise RuntimeError("daemon socket never appeared")
            time.sleep(0.01)
        return info

    def client(self, timeout=None) -> Client:
        return Client(self.sock, timeout=timeout)

    def kill9(self):
        self.proc.kill()
        self.proc.wait()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(10)

    def manager(self) -> SandboxManager:
        """An in-process manager on the same state, for audit() after the daemon is gone."""
        return SandboxManager(self.cfg)
