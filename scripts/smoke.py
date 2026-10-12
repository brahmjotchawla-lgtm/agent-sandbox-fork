#!/usr/bin/env python3
"""Manual smoke test: create -> exec -> fork -> exec -> destroy, printing timings.

    sudo python3 scripts/smoke.py --tar /var/tmp/busybox-rootfs.tar
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from control_plane.config import Config  # noqa: E402
from control_plane.manager import SandboxManager  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--tar", required=True)
ap.add_argument("--state-dir", default="/var/lib/sandboxd-smoke")
args = ap.parse_args()

cfg = Config(state_dir=args.state_dir, run_dir="/run/sandboxd-smoke", cgroup_root="/sys/fs/cgroup/sandboxd-smoke", btrfs_size_gb=4)
m = SandboxManager(cfg)
print(json.dumps(m.start(), indent=1))
if "busybox" not in m.list_images():
    print(m.import_image("busybox", args.tar))
a = m.create_environment("busybox")
print("create", json.dumps(a, indent=1))
r = m.exec(a["id"], ["sh", "-c", "id; hostname; echo $$; ls /; cat /proc/self/uid_map; echo hi > /work/x"])
print(r["exit_code"], r["stdout"].decode(), r["stderr"].decode())
b = m.fork(a["id"])
print("fork", json.dumps(b, indent=1))
r = m.exec(b["id"], ["cat", "/work/x"])
print(r)
for s in (a["id"], b["id"]):
    m.destroy(s)
    print(s, "leaks:", m.audit(s))
m.close()
