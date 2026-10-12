"""Phase 1: single-sandbox lifecycle. create -> exec -> destroy with verified cleanup.

Every test uses the `sb` fixture, which runs SandboxManager.audit() on each
sandbox at teardown. That audit covers the cgroup, the subvolume, the state
file, mounts in ANY process's mount table, and processes still in the
sandbox's user namespace.
"""
import os
import time

from control_plane.manager import SandboxError
import pytest


def out(r):
    return r["stdout"].decode()


def test_create_exec_destroy(sb):
    sid = sb.create()
    r = sb.sh(sid, "id -u; hostname; echo $$")
    assert r["exit_code"] == 0, r
    uid, host, pid = out(r).split()
    assert uid == "0"
    assert host == sid
    # The command runs in the sandbox's own PID namespace, where PID 1 is sandbox-init.
    assert int(pid) < 50


def test_user_namespace_maps_root_to_private_host_range(sb, mgr):
    a, b = sb.create(), sb.create()
    maps = {}
    for s in (a, b):
        fields = out(sb.sh(s, "cat /proc/self/uid_map")).split()
        assert fields[0] == "0" and fields[2] == "65536"
        maps[s] = int(fields[1])
        assert maps[s] == mgr._sandboxes[s]["uid_base"]
        assert maps[s] >= mgr.cfg.uid_base_start
    assert maps[a] != maps[b], "siblings must not share a host uid range"


def test_idmapped_rootfs_stores_unshifted_ownership(sb, mgr):
    sid = sb.create()
    assert sb.sh(sid, "echo x > /root/owned && chown 1234:1234 /root/owned")["exit_code"] == 0
    st = os.stat(os.path.join(mgr.subvol(sid), "root", "owned"))
    # On disk: the sandbox-relative ids. That is what lets fork skip chown.
    assert (st.st_uid, st.st_gid) == (1234, 1234)
    r = sb.sh(sid, "stat -c '%u %g' /root/owned")
    assert out(r).strip() == "1234 1234"


def test_no_host_supplementary_groups(sb):
    sid = sb.create()
    status = out(sb.sh(sid, "cat /proc/self/status"))
    groups = [l for l in status.splitlines() if l.startswith("Groups:")][0]
    assert groups.split(":", 1)[1].strip() == "", groups


def test_siblings_from_same_image_do_not_share_writes(sb):
    a, b = sb.create(), sb.create()
    assert sb.sh(a, "echo from-a > /work/f")["exit_code"] == 0
    assert sb.sh(b, "test -e /work/f")["exit_code"] == 1


def test_mount_table_exposes_no_host_paths(sb, mgr):
    sid = sb.create()
    mi = out(sb.sh(sid, "cat /proc/self/mountinfo"))
    for line in mi.splitlines():
        mountpoint = line.split()[4]
        assert mountpoint in ("/", "/proc", "/dev", "/dev/pts", "/dev/shm") or mountpoint.startswith("/dev/"), line
    assert mgr.cfg.state_dir not in mi
    assert mgr.cfg.run_dir not in mi


def test_init_is_sealed_memfd(sb):
    sid = sb.create()
    r = sb.sh(sid, "readlink /proc/1/exe")
    assert out(r).startswith("/memfd:sandbox-init"), out(r)
    # Sandboxed root must not be able to modify the init binary (shared by every sandbox).
    r = sb.sh(sid, "echo pwned >> /proc/1/exe")
    assert r["exit_code"] != 0
    r = sb.sh(sid, "dd if=/dev/zero of=/proc/1/exe bs=1 count=1 conv=notrunc")
    assert r["exit_code"] != 0


def test_init_survives_signals_from_inside(sb):
    sid = sb.create()
    sb.sh(sid, "kill -TERM 1; kill -KILL 1; kill -INT 1; true")
    time.sleep(0.1)
    r = sb.sh(sid, "echo alive")
    assert out(r) == "alive\n"


def test_network_namespace_has_only_loopback(sb):
    sid = sb.create()
    links = out(sb.sh(sid, "ls /sys/class/net 2>/dev/null || cat /proc/net/dev"))
    assert "eth" not in links and "wlan" not in links and "veth" not in links, links


def test_exec_nonzero_and_missing_command(sb, mgr):
    sid = sb.create()
    assert sb.sh(sid, "exit 7")["exit_code"] == 7
    r = mgr.exec(sid, ["/no/such/binary"])
    assert r["exit_code"] == 127
    assert b"cannot exec" in r["stderr"]


def test_exec_killed_by_signal_reports_negative_code(sb):
    sid = sb.create()
    assert sb.sh(sid, "kill -9 $$")["exit_code"] == -9


def test_exec_stdin_env_cwd(sb, mgr):
    sid = sb.create()
    r = mgr.exec(sid, ["sh", "-c", "cat; echo $FOO; pwd"], env={"PATH": "/bin", "FOO": "bar"}, cwd="/tmp", stdin=b"in\n")
    assert out(r) == "in\nbar\n/tmp\n"


def test_exec_timeout(sb):
    sid = sb.create()
    t = time.monotonic()
    r = sb.sh(sid, "sleep 30", timeout=0.5)
    assert r["timed_out"]
    assert time.monotonic() - t < 5
    assert sb.sh(sid, "echo still-usable")["exit_code"] == 0


def test_exec_background_process_does_not_hang_exec(sb):
    sid = sb.create()
    t = time.monotonic()
    r = sb.sh(sid, "sleep 30 & echo started", timeout=10)
    assert r["exit_code"] == 0 and out(r) == "started\n"
    assert time.monotonic() - t < 5


def test_exec_output_is_capped(sb, mgr):
    sid = sb.create()
    cap = mgr.cfg.exec_output_cap
    r = sb.sh(sid, f"head -c {cap + 1000000} /dev/zero", timeout=60)
    assert len(r["stdout"]) == cap
    assert r["truncated"]


def test_destroy_kills_background_processes(sb, mgr):
    sid = sb.create()
    sb.sh(sid, "for i in 1 2 3 4 5; do (sleep 1000 &) ; done; nohup sleep 999 >/dev/null 2>&1 &")
    assert len(mgr.cg.procs(sid)) >= 6
    # destroy + audit happen in the fixture teardown.


def test_pids_limit_contains_fork_bomb(sb, mgr):
    sid = sb.create(limits={"pids_max": "64"})
    r = sb.sh(sid, "i=0; while [ $i -lt 200 ]; do sleep 100 & i=$((i+1)); done 2>/dev/null; true", timeout=20)
    assert len(mgr.cg.procs(sid)) <= 64
    events = mgr.cg.stat(sid)["pids.events"]
    assert "max 0" not in events, "pids.max was never hit"


def test_operations_on_unknown_sandbox_fail_cleanly(mgr):
    with pytest.raises(SandboxError):
        mgr.exec("sb-doesnotexist", ["true"])
    with pytest.raises(SandboxError):
        mgr.fork("sb-doesnotexist")
    with pytest.raises(SandboxError):
        mgr.destroy("sb-doesnotexist")
    with pytest.raises(SandboxError):
        mgr.create_environment("no-such-image")


def test_destroy_removes_nested_subvolumes(sb, mgr):
    """Sandboxed root can create btrfs subvolumes (it needs only write permission)
    unless seccomp blocks it. Destroy must still succeed. Phase 3's seccomp
    policy blocks the ioctl. This test runs without it, so it exercises the
    cleanup path."""
    sid = sb.create()
    from control_plane import btrfs

    # Simulate it from the host side: busybox has no btrfs tool.
    btrfs.create_subvolume(os.path.join(mgr.subvol(sid), "work", "nested"))
    btrfs.create_subvolume(os.path.join(mgr.subvol(sid), "work", "nested", "deeper"))
    assert len(btrfs.nested_subvolumes(mgr.subvol(sid))) == 2
