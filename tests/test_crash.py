"""Crash mid-create / mid-fork, then restart: nothing may leak (CLAUDE.md rule 4).

Each case runs a control plane in a subprocess that SIGKILLs itself at an
injected point, then starts a fresh Manager (which reconciles) and checks
that no state file, subvolume, cgroup, mount, veth or holder process
remains for the half-built sandbox, and that a forked parent is intact and
not left frozen.
"""
from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys

import pytest

from control_plane.sandbox import Manager, _find_holders

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CREATE_POINTS = ["create:after_state", "create:after_snapshot", "start:after_cgroup",
                 "start:after_mount", "start:after_holder", "start:after_network"]
FORK_POINTS = ["fork:after_state", "fork:while_frozen", "fork:after_snapshot",
               "start:after_holder", "start:after_network"]


def crash_run(cfg, op, arg, point):
    code = ("import json,sys; from control_plane.config import Config; "
            "from control_plane.sandbox import Manager; "
            f"m = Manager(Config(**json.loads(sys.argv[1]))); getattr(m, {op!r})({arg!r})")
    env = dict(os.environ, AGENT_SANDBOX_CRASH_AT=point, PYTHONPATH=REPO)
    p = subprocess.run([sys.executable, "-c", code, json.dumps(dataclasses.asdict(cfg))],
                       env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == -9, f"did not crash at {point}: rc={p.returncode} {p.stderr[-500:]}"


def assert_clean(m, keep=()):
    states = [s["id"] for s in m._all_states()]
    assert sorted(states) == sorted(keep)
    assert sorted(os.listdir(m._store("sandboxes"))) == sorted(keep)
    assert os.listdir(m._dir("mnt")) == []
    assert sorted(m.cg.list()) == (sorted(keep) if m.cg.enforced else [])
    if m.net:
        slots = {m._load(k)["slot"] for k in keep}
        assert sorted(m.net.host_ifaces()) == sorted(f"sbxh{s}" for s in slots)
    leaked = [p for sid in os.listdir(m._store("sandboxes")) if sid not in keep
              for p in _find_holders(sid)]
    assert not leaked


@pytest.mark.parametrize("point", CREATE_POINTS)
def test_crash_during_create(cfg, point):
    crash_run(cfg, "create_environment", "base", point)
    m = Manager(cfg)
    try:
        assert m.last_reconcile["torn_down"] or m.last_reconcile["orphan_subvols"] \
            or m.last_reconcile["orphan_cgroups"] or m.last_reconcile["orphan_mounts"]
        assert_clean(m)
    finally:
        m.close()


@pytest.mark.parametrize("point", FORK_POINTS)
def test_crash_during_fork(cfg, point):
    m = Manager(cfg)
    parent = m.create_environment("base")["sandbox_id"]
    m.exec(parent, ["sh", "-c", "echo keep > /root/k"])
    m.close()

    crash_run(cfg, "fork", parent, point)

    m = Manager(cfg)
    try:
        assert parent in m.last_reconcile["adopted"]
        assert_clean(m, keep=[parent])
        # Parent intact and thawed (a crash while frozen must not wedge it).
        r = m.exec(parent, ["cat", "/root/k"], timeout=10)
        assert not r["timed_out"] and r["stdout"] == "keep\n"
        assert m.fork(parent)["sandbox_id"]
    finally:
        for s in m.list_sandboxes():
            m.destroy(s["id"])
        m.close()


def test_orphans_without_state_are_removed(cfg):
    """Resources whose state file vanished entirely are still found."""
    m = Manager(cfg)
    sid = m.create_environment("base")["sandbox_id"]
    st = m._load(sid)
    os.unlink(m._state_path(sid))
    m.close()
    m = Manager(cfg)
    try:
        assert sid in m.last_reconcile["orphan_subvols"]
        assert_clean(m)
        assert not _find_holders(sid)
        assert not os.path.exists(f"/proc/{st['holder_pid']}") or \
            open(f"/proc/{st['holder_pid']}/cmdline").read().find(sid) < 0
    finally:
        m.close()
