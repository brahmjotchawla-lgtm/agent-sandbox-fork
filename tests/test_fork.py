"""Phase 2: environment fork (filesystem + fresh process tree; NOT a process-memory fork)."""
import os
import threading
import time

import pytest


def out(r):
    return r["stdout"].decode()


def test_child_sees_parent_state_at_fork(sb):
    p = sb.create()
    sb.sh(p, "mkdir -p /work/d && echo v1 > /work/d/f && ln -s d/f /work/link")
    c = sb.fork(p)
    assert out(sb.sh(c, "cat /work/d/f /work/link")) == "v1\nv1\n"


def test_fork_isolation_both_directions(sb):
    p = sb.create()
    sb.sh(p, "echo base > /work/shared")
    c = sb.fork(p)
    sb.sh(p, "echo parent-after > /work/shared; echo p > /work/only-parent")
    sb.sh(c, "echo child-after > /work/shared; echo c > /work/only-child")
    assert out(sb.sh(p, "cat /work/shared; ls /work")) == "parent-after\nonly-parent\nshared\n"
    assert out(sb.sh(c, "cat /work/shared; ls /work")) == "child-after\nonly-child\nshared\n"


def test_child_has_fresh_process_tree_and_identity(sb, mgr):
    p = sb.create()
    sb.sh(p, "sleep 1000 &")
    c = sb.fork(p)
    # Environment fork: parent processes are NOT carried over.
    comms = out(sb.sh(c, "for p in /proc/[0-9]*; do cat $p/comm; done")).split()
    assert set(comms) <= {"memfd:sandbox-i", "sh", "cat"}, comms  # comm of a memfd exec is "memfd:<name>", truncated to 15 chars
    assert "sleep" in out(sb.sh(p, "for p in /proc/[0-9]*; do cat $p/comm; done"))
    assert out(sb.sh(c, "hostname")).strip() == c
    assert mgr._sandboxes[c]["uid_base"] != mgr._sandboxes[p]["uid_base"]
    assert mgr._sandboxes[c]["parent"] == p


def test_fork_during_active_io(sb, mgr):
    """Writes the parent completed before the freeze must all be in the child,
    with no torn record, even though nothing is fsync'd."""
    p = sb.create()
    sb.sh(p, "i=0; while :; do echo $i >> /work/log; i=$((i+1)); done >/dev/null 2>&1 &")
    time.sleep(0.5)
    host_log = os.path.join(mgr.subvol(p), "work", "log")
    for _ in range(5):
        before = sum(1 for _ in open(host_log))  # lower bound on completed writes at fork time
        c = sb.fork(p)
        data = out(sb.sh(c, "cat /work/log"))
        assert data.endswith("\n"), "torn final record"
        nums = [int(x) for x in data.splitlines()]
        assert nums == list(range(len(nums))), "records lost or reordered"
        assert len(nums) >= before, f"child has {len(nums)} records, parent had completed >= {before} before fork"
    # The parent kept writing after fork; the child's copy is frozen in time.
    time.sleep(0.2)
    assert sum(1 for _ in open(host_log)) > len(nums)


def test_fork_while_parent_writes_large_file(sb, mgr):
    p = sb.create(limits={"memory_max": str(512 << 20)})
    sb.sh(p, "while :; do dd if=/dev/urandom of=/work/big bs=1M count=64 2>/dev/null; done >/dev/null 2>&1 &")
    time.sleep(0.5)
    r = mgr.fork(p)
    c = r["id"]
    sb.ids.append((c, None))
    assert r["timings"]["parent_frozen_window_ms"] > 0
    assert sb.sh(c, "ls -l /work/big")["exit_code"] == 0


def test_fork_under_memory_pressure(sb, mgr):
    """Parent pinned near its memory.max (tmpfs pages charge to the cgroup) and
    with a process that keeps getting OOM-killed. Fork must still work."""
    p = sb.create(limits={"memory_max": str(48 << 20)})
    sb.sh(p, "dd if=/dev/zero of=/dev/shm/fill bs=1M count=40 2>/dev/null; true")
    sb.sh(p, "while :; do tail /dev/zero; done >/dev/null 2>&1 &")  # repeatedly OOMs inside the parent
    time.sleep(1.0)
    ev = mgr.cg.stat(p)["memory.events"]
    c = sb.fork(p)
    assert sb.sh(c, "echo ok")["exit_code"] == 0
    # exec into the still-saturated parent. The exec helper is not charged to
    # the sandbox, so it survives and always reports a status. The command
    # itself can legitimately be OOM-killed (-9) while the hog churns, so we
    # require at least one success, not all.
    codes = [sb.sh(p, "echo ok")["exit_code"] for _ in range(5)]
    assert None not in codes and 0 in codes, codes
    oom_kills = int(dict(l.split() for l in mgr.cg.stat(p)["memory.events"].splitlines())["oom_kill"])
    assert oom_kills > 0, f"memory pressure was not actually applied: {ev}"
    # The child got its own fresh cgroup; the parent's pressure is not inherited.
    assert int(mgr.cg.stat(c)["memory.current"]) < 16 << 20


def test_deep_fork_chain(sb):
    s = sb.create()
    sb.sh(s, "echo gen0 > /work/g0")
    chain = [s]
    for i in range(1, 21):
        s = sb.fork(s)
        sb.sh(s, f"echo gen{i} > /work/g{i}")
        chain.append(s)
    r = sb.sh(chain[-1], "cat /work/g0 /work/g10 /work/g20; ls /work | wc -l")
    assert out(r) == "gen0\ngen10\ngen20\n21\n"


def test_destroy_parent_with_live_children(sb, mgr):
    p = sb.create()
    sb.sh(p, "echo data > /work/f")
    kids = [sb.fork(p) for _ in range(3)]
    mgr.destroy(p)
    for k in kids:
        assert out(sb.sh(k, "cat /work/f")) == "data\n"


def test_concurrent_fanout_from_one_parent(sb, mgr):
    p = sb.create()
    sb.sh(p, "echo seed > /work/seed")
    results, errors = [], []

    def go():
        try:
            results.append(mgr.fork(p)["id"])
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=go) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    sb.ids += [(c, None) for c in results]
    assert not errors, errors
    assert len(set(results)) == 16
    bases = {mgr._sandboxes[c]["uid_base"] for c in results}
    assert len(bases) == 16
    for c in results:
        assert out(sb.sh(c, "cat /work/seed")) == "seed\n"
    assert not mgr.cg.is_frozen(p)


def test_fork_of_destroyed_or_unknown_sandbox_fails(sb, mgr):
    from control_plane.manager import SandboxError

    p = sb.create()
    mgr.destroy(p)
    with pytest.raises(SandboxError):
        mgr.fork(p)
