"""Phase 1/2 failure paths (CLAUDE.md rule 4): crashes mid-operation must not leak anything.

Faults are injected at named points (control_plane/zygote.py `_fault`,
manager.py `_maybe_fault`). Then the failing component is killed or allowed
to fail, and SandboxManager.audit() must come back empty. That audit covers
cgroup, subvolume, state file, mounts in every process's mount namespace,
and processes in the sandbox's user namespace.
"""
import os
import signal
import threading
import time

import pytest

from conftest import Daemon, ensure_busybox_image
from control_plane.client import RemoteError
from control_plane.manager import SandboxError


def _new_ids(mgr, before):
    return set(os.listdir(mgr.state_files)) - before


@pytest.mark.parametrize("point", ["after_userns", "after_cgroup", "in_pid1"])
def test_launch_failure_at_each_stage_leaks_nothing(mgr, point):
    before = set(mgr._sandboxes)
    with pytest.raises(SandboxError):
        mgr.create_environment("busybox", fault={"point": point, "action": "exit"})
    leaked = set(mgr._sandboxes) - before
    assert not leaked
    for name in os.listdir(os.path.join(mgr.cfg.volume, "sandboxes")):
        assert name in mgr._sandboxes, f"orphan subvolume {name}"
    for name in mgr.cg.list():
        assert name in mgr._sandboxes, f"orphan cgroup {name}"


def test_launcher_hung_mid_setup_is_killed_and_cleaned(mgr):
    """The launcher hangs while holding a half-built sandbox (user ns created,
    idmapped mount not yet made). Launch times out, and teardown must kill it
    via the cgroup."""
    before = set(mgr._sandboxes)
    t = time.monotonic()
    with pytest.raises(SandboxError, match="timed out"):
        mgr.create_environment("busybox", fault={"point": "after_userns", "action": "hang", "timeout": 1.0})
    assert time.monotonic() - t < 15
    assert set(mgr._sandboxes) == before
    for name in mgr.cg.list():
        assert name in mgr._sandboxes


def test_init_killed_from_host(sb, mgr):
    sid = sb.create()
    pid = mgr._sandboxes[sid]["init_pid"]
    os.kill(pid, signal.SIGKILL)
    time.sleep(0.2)
    # PID 1 dying tears down the whole PID namespace. setns into a dead
    # process's namespaces must fail cleanly, not hang.
    with pytest.raises(SandboxError):
        mgr.exec(sid, ["true"], timeout=5)
    # destroy + leak audit in fixture teardown


def test_exec_helper_hung_before_setns(sb, mgr):
    sid = sb.create()
    r = mgr.exec(sid, ["true"], timeout=0.5, fault={"point": "exec_before_setns", "action": "hang"})
    assert r["timed_out"]
    assert sb.sh(sid, "echo ok")["exit_code"] == 0


def test_destroy_during_running_exec(sb, mgr):
    sid = sb.create()
    res = {}

    def run():
        res["r"] = mgr.exec(sid, ["sleep", "60"], timeout=30)

    th = threading.Thread(target=run)
    th.start()
    time.sleep(0.3)
    mgr.destroy(sid)
    th.join(10)
    assert not th.is_alive()
    assert res["r"]["exit_code"] is None and res["r"]["killed"]


def test_fork_failure_while_parent_frozen_thaws_parent(sb, mgr):
    parent = sb.create()
    with pytest.raises(SandboxError):
        mgr.fork(parent, fault={"point": "fork_while_frozen", "action": "raise"})
    assert not mgr.cg.is_frozen(parent)
    assert sb.sh(parent, "echo alive")["exit_code"] == 0


# ---------------------------------------------------------------- daemon crashes


@pytest.fixture
def daemon():
    d = Daemon("crash")
    info = d.start()
    m = d.manager()
    ensure_busybox_image(m)  # imports through the volume the daemon mounted
    yield d
    d.stop()
    # Final sweep: restart once more, destroy everything, and audit.
    d2 = Daemon("crash")
    d2.start()
    with d2.client() as c:
        for sid in c.list_sandboxes():
            c.destroy(sid)
    d2.stop()


def _audit_all(d: Daemon, ids):
    m = d.manager()
    leaks = {sid: m.audit(sid) for sid in ids}
    return {k: v for k, v in leaks.items() if v}


def test_control_plane_killed_mid_create_then_reconciled(daemon):
    c = daemon.client(timeout=60)
    import json, socket
    # Fire a create that hangs inside the launcher, then SIGKILL the control plane.
    raw = socket.socket(socket.AF_UNIX)
    raw.connect(daemon.sock)
    raw.sendall(json.dumps({"id": 1, "method": "create_environment",
                            "params": {"base_image": "busybox", "fault": {"point": "after_cgroup", "action": "hang", "timeout": 120}}}).encode() + b"\n")
    state_dir = os.path.join(daemon.cfg.state_dir, "state")
    deadline = time.monotonic() + 10
    while not os.listdir(state_dir):
        assert time.monotonic() < deadline
        time.sleep(0.01)
    time.sleep(0.5)  # let the launcher get into the hang with a user ns + cgroup
    sid = os.listdir(state_dir)[0].removesuffix(".json")
    daemon.kill9()
    raw.close()
    c.close()
    # The zygote dies with its parent (PDEATHSIG). The launcher it forked is
    # still alive, now orphaned, inside the sandbox cgroup.
    m = daemon.manager()
    assert m.cg.exists(sid) and m.cg.procs(sid), "expected a half-built sandbox to be left behind"
    info = daemon.start()
    assert sid in info["reconcile"]["removed"], info
    assert not _audit_all(daemon, [sid])


def test_control_plane_killed_mid_fork_parent_thawed(daemon):
    c = daemon.client(timeout=60)
    parent = c.create_environment("busybox")["id"]
    c.exec(parent, ["sh", "-c", "echo before > /work/f"])
    import json, socket
    raw = socket.socket(socket.AF_UNIX)
    raw.connect(daemon.sock)
    raw.sendall(json.dumps({"id": 1, "method": "fork", "params": {"sandbox_id": parent,
                            "fault": {"point": "fork_while_frozen", "action": "hang"}}}).encode() + b"\n")
    m = daemon.manager()
    deadline = time.monotonic() + 10
    while not m.cg.is_frozen(parent):
        assert time.monotonic() < deadline
        time.sleep(0.01)
    daemon.kill9()
    raw.close()
    c.close()
    assert m.cg.is_frozen(parent), "parent should be left frozen by the crash"
    info = daemon.start()
    assert parent in info["reconcile"]["adopted"]
    assert parent in info["reconcile"]["thawed"] or not m.cg.is_frozen(parent)
    assert len(info["reconcile"]["removed"]) == 1  # the half-made child
    child = info["reconcile"]["removed"][0]
    with daemon.client() as c:
        r = c.exec(parent, ["cat", "/work/f"])
        assert r["stdout"] == b"before\n"
    assert not _audit_all(daemon, [child])


def test_control_plane_restart_readopts_running_sandbox(daemon):
    with daemon.client() as c:
        sid = c.create_environment("busybox")["id"]
        c.exec(sid, ["sh", "-c", "echo persisted > /work/f; sleep 1000 &"])
    daemon.kill9()
    info = daemon.start()
    assert sid in info["reconcile"]["adopted"]
    with daemon.client() as c:
        assert c.exec(sid, ["cat", "/work/f"])["stdout"] == b"persisted\n"
        child = c.fork(sid)["id"]
        assert c.exec(child, ["cat", "/work/f"])["stdout"] == b"persisted\n"
        c.destroy(child)
        c.destroy(sid)
    assert not _audit_all(daemon, [sid, child])


def test_remote_errors_are_reported_not_fatal(daemon):
    with daemon.client() as c:
        with pytest.raises(RemoteError):
            c.exec("sb-nope", ["true"])
        assert c.call("ping") == "pong"
