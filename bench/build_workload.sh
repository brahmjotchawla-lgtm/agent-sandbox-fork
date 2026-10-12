#!/bin/sh
# Build the benchmark workload once and make it available to BOTH sides:
#   1. docker image  sandboxd-workload:latest   (the container-restart baseline)
#   2. btrfs image   "workload"                 (the fork side), imported from `docker export`
#      of a container created from that same image.
# Records image id, size and file count next to the results.
#
#   sudo sh bench/build_workload.sh [STATE_DIR]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
state=${1:-/var/lib/sandboxd-bench}
tar=/var/tmp/sandboxd-workload.tar

docker build -q -t sandboxd-workload:latest "$here/workload"
cid=$(docker create sandboxd-workload:latest)
docker export -o "$tar" "$cid"
docker rm "$cid" >/dev/null
python3 - "$repo" "$state" "$tar" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
from control_plane.config import Config
from control_plane.manager import SandboxManager
cfg = Config(state_dir=sys.argv[2], run_dir="/run/sandboxd-bench", cgroup_root="/sys/fs/cgroup/sandboxd-bench")
m = SandboxManager(cfg); m.start()
if "workload" in m.list_images():
    m.delete_image("workload")
print(json.dumps(m.import_image("workload", sys.argv[3])))
# The workspace has to actually work inside a sandbox, not just exist.
sid = m.create_environment("workload")["id"]
r = m.exec(sid, ["/workspace/venv/bin/python", "-m", "pytest", "-q", "-x", "tests/test_basic.py"], cwd="/workspace/flask", timeout=300)
print(r["stdout"].decode()[-400:], r["stderr"].decode()[-400:])
m.destroy(sid); m.close()
sys.exit(0 if r["exit_code"] == 0 else 1)
PY
docker image inspect sandboxd-workload:latest --format '{"image_id": "{{.Id}}", "size_bytes": {{.Size}}}'
echo "files_in_rootfs: $(tar -tf "$tar" | wc -l)"
