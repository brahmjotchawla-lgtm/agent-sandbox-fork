"""Phase 1/2: create, exec, fork, destroy, and their failure paths."""
from __future__ import annotations

import os
import subprocess
import time

import pytest

from control_plane.sandbox import SandboxError
from control_plane.util import pid_alive
from conftest import py, requires_cgroup


def host_uid(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("Uid:"):
                return int(line.split()[1])


def test_exec_basics(mgr, sandbox):
    r = mgr.exec(sandbox, ["sh", "-c", "id -u; hostname; echo err >&2; exit 3"])
    assert r["exit_code"] == 3
    assert r["stdout"].split() == ["0", sandbox]
    assert r["stderr"] == "err\n"
    assert mgr.exec(sandbox, ["cat"], stdin="hello")["stdout"] == "hello"
    assert mgr.exec(sandbox, ["sh", "-c", "echo $FOO"], env={"FOO": "bar"})["stdout"] == "bar\n"
    assert mgr.exec(sandbox, ["pwd"], cwd="/tmp")["stdout"] == "/tmp\n"


def test_sandbox_is_its_own_pid_namespace(mgr, sandbox):
    r = py(mgr, sandbox, "import os; print(sorted(int(p) for p in os.listdir('/proc') if p.isdigit()))")
    pids = eval(r["stdout"])
    assert pids[0] == 1 and len(pids) < 10, pids


def test_sandbox_root_is_unprivileged_on_host(mgr):
    a = mgr.create_environment("base")["sandbox_id"]
    b = mgr.create_environment("base")["sandbox_id"]
    sa, sb = mgr._load(a), mgr._load(b)
    ua, ub = host_uid(sa["holder_pid"]), host_uid(sb["holder_pid"])
    assert ua == sa["host_uid_base"] and ub == sb["host_uid_base"]
    assert ua != 0 and ub != 0 and abs(ua - ub) >= 65536, "siblings must not share host uids"


def test_files_are_stored_with_in_sandbox_owner(mgr, sandbox):
    mgr.exec(sandbox, ["sh", "-c", "echo x > /root/owned"])
    st = os.stat(os.path.join(mgr._load(sandbox)["subvol"], "root", "owned"))
    assert (st.st_uid, st.st_gid) == (0, 0)  # idmapped mount: disk sees in-sandbox uid


def test_destroy_releases_everything(mgr, sandbox):
    st = mgr._load(sandbox)
    mgr.destroy(sandbox)
    assert not os.path.exists(mgr._state_path(sandbox))
    assert not os.path.exists(st["subvol"])
    assert not os.path.exists(mgr._dir("mnt", sandbox))
    assert not pid_alive(st["holder_pid"], st["holder_start"])
    if mgr.net:
        assert f"sbxh{st['slot']}" not in mgr.net.host_ifaces()
    if mgr.cg.enforced:
        assert not os.path.exists(mgr.cg.path(sandbox))
    with pytest.raises(SandboxError):
        mgr.exec(sandbox, ["true"])


@pytest.mark.parametrize("bad", ["../../etc", "sbx-../../x", "", None, "sbx-ZZZZZZZZZZZZ"])
def test_invalid_ids_rejected(mgr, bad):
    with pytest.raises(SandboxError):
        mgr.destroy(bad)


def test_fork_isolation(mgr, sandbox):
    mgr.exec(sandbox, ["sh", "-c", "echo before > /root/f"])
    child = mgr.fork(sandbox)["sandbox_id"]
    mgr.exec(sandbox, ["sh", "-c", "echo parent-after > /root/f; echo p > /root/p"])
    mgr.exec(child, ["sh", "-c", "echo c > /root/c"])
    assert mgr.exec(child, ["cat", "/root/f"])["stdout"] == "before\n"
    assert mgr.exec(child, ["test", "-e", "/root/p"])["exit_code"] == 1
    assert mgr.exec(sandbox, ["test", "-e", "/root/c"])["exit_code"] == 1
    assert mgr.snapshot_info(child)["parent_id"] == sandbox


def test_fork_starts_fresh_process_tree(mgr, sandbox):
    """Environment fork, not process fork (DESIGN.md §4)."""
    mgr.exec(sandbox, ["sh", "-c", "sleep 1000 >/dev/null 2>&1 &"])
    child = mgr.fork(sandbox)["sandbox_id"]
    procs = lambda s: mgr.exec(s, ["sh", "-c", "cat /proc/[0-9]*/cmdline | tr '\\0' ' '"])["stdout"]
    assert "sleep 1000" in procs(sandbox)
    assert "sleep 1000" not in procs(child)


def test_fork_chain(mgr, sandbox):
    sid = sandbox
    for i in range(5):
        mgr.exec(sid, ["sh", "-c", f"echo {i} >> /root/chain"])
        sid = mgr.fork(sid)["sandbox_id"]
    assert mgr.exec(sid, ["cat", "/root/chain"])["stdout"].split() == ["0", "1", "2", "3", "4"]


def test_siblings_independent(mgr, sandbox):
    kids = [mgr.fork(sandbox)["sandbox_id"] for _ in range(3)]
    for i, k in enumerate(kids):
        mgr.exec(k, ["sh", "-c", f"echo {i} > /root/id"])
    assert [mgr.exec(k, ["cat", "/root/id"])["stdout"] for k in kids] == ["0\n", "1\n", "2\n"]


WRITER = r"""
import os
os.makedirs('/root/w', exist_ok=True)
log = open('/root/w/log', 'a')
i = 0
while True:
    with open(f'/root/w/{i}', 'wb') as f:
        f.write(bytes([i % 256]) * 65536)
    log.write(f'{i}\n'); log.flush()
    i += 1
"""

CHECK = r"""
import os
done = [int(x) for x in open('/root/w/log').read().split()]
bad = [i for i in done if os.path.getsize(f'/root/w/{i}') != 65536
       or open(f'/root/w/{i}', 'rb').read() != bytes([i % 256]) * 65536]
print(len(done), bad[:5])
"""


def test_fork_during_active_io(mgr, sandbox):
    """Every write the parent completed before the fork is in the child.

    No fsync: this checks that the snapshot includes page-cache data, which
    DESIGN.md §3 says must be verified, not assumed. The invariant only holds
    if fork freezes the parent; without cgroup v2 there is no freeze, so the
    test is expected to be able to fail in dev mode.
    """
    if not mgr.cg.enforced:
        pytest.xfail("no cgroup freeze in dev mode: snapshot races the writer")
    mgr.exec(sandbox, ["sh", "-c", f"python3 -c \"{WRITER}\" >/dev/null 2>&1 &"])
    time.sleep(0.5)
    for _ in range(5):
        child = mgr.fork(sandbox)["sandbox_id"]
        out = py(mgr, child, CHECK)["stdout"].split(maxsplit=1)
        assert int(out[0]) > 0 and out[1].strip() == "[]", out
        mgr.destroy(child)


def test_exec_timeout(mgr, sandbox):
    t = time.monotonic()
    r = mgr.exec(sandbox, ["sleep", "30"], timeout=0.5)
    assert r["timed_out"] and time.monotonic() - t < 5
    assert mgr.exec(sandbox, ["true"])["exit_code"] == 0


def test_exec_output_is_capped(mgr, sandbox):
    r = mgr.exec(sandbox, ["sh", "-c", "head -c 20000000 /dev/zero | tr '\\0' a"])
    assert len(r["stdout"]) == 8 * 1024 * 1024


def test_exec_on_dead_holder_errors_and_destroy_still_cleans(mgr, sandbox):
    st = mgr._load(sandbox)
    os.kill(st["holder_pid"], 9)
    time.sleep(0.2)
    r = mgr.exec(sandbox, ["true"])
    assert r["exit_code"] != 0
    mgr.destroy(sandbox)
    assert not os.path.exists(st["subvol"])


def test_second_manager_refused(mgr, cfg):
    from control_plane.sandbox import Manager
    with pytest.raises(SandboxError):
        Manager(cfg)


@requires_cgroup
def test_memory_limit_enforced(mgr, sandbox):
    r = py(mgr, sandbox, "b = bytearray(1024 * 1024 * 1024); print('survived')")
    assert r["exit_code"] == -9 or "MemoryError" in r["stderr"], r
    assert mgr.exec(sandbox, ["true"])["exit_code"] == 0


@requires_cgroup
def test_pids_limit_contains_fork_bomb(mgr, sandbox):
    r = mgr.exec(sandbox, ["sh", "-c", "f() { f | f & }; f; sleep 2; echo done"], timeout=20)
    assert int(mgr.cg.stats(sandbox)["pids.current"]) <= mgr.cfg.pids_max
    mgr.destroy(sandbox)  # cgroup.kill must clean up a live fork bomb


@requires_cgroup
def test_fork_under_memory_pressure(mgr, sandbox):
    """Parent sits near memory.max; fork must still succeed (no memory copy)."""
    mgr.exec(sandbox, ["sh", "-c",
                       "python3 -c \"import time; b=bytearray(200*1024*1024); time.sleep(600)\" "
                       ">/dev/null 2>&1 &"])
    time.sleep(1)
    assert int(mgr.cg.stats(sandbox)["memory.current"]) > 150 * 1024 * 1024
    child = mgr.fork(sandbox)["sandbox_id"]
    assert mgr.exec(child, ["true"])["exit_code"] == 0
    assert int(mgr.cg.stats(child)["memory.current"]) < 64 * 1024 * 1024
