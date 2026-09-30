#!/usr/bin/env python3
"""Claim 1 harness: environment fork vs. container start (BENCHMARKS.md).

    sudo python3 bench/fork_vs_restart.py --config cfg.json --trials 30

Starts its own control-plane server (so fork is timed through the real
socket API), and drives Docker through the Engine API socket directly (so
the baseline does not pay Docker CLI start-up: steel-manned, rule 3).

Scenarios, each timed from the client's first call until an ``exec`` of
``true`` has returned exit 0 inside the new environment ("ready to exec"):

  fork           fork(parent) + exec            parent idle
  fork_active    fork(parent) + exec            parent writing continuously
  docker         create + start + exec          image already local (warm)
  *_writes       the above + modify --writes files of the repo checkout
                 (post-fork copy-on-write cost, BENCHMARKS.md §3.4)
  fanout         N forks vs N containers, sequential, for each --fanout N

Trials of different scenarios are interleaved in a shuffled order so slow
drift on the host cannot favour one side. Output: one JSON line per trial
(trials.jsonl), the host spec (host.json), percentiles (summary.json) and the
exact command (command.txt), under --out.

Refuses to run unless storage is btrfs, cgroups are enforced, and the btrfs
store and Docker's data-root are on the same block device (§3.6). With
--allow-invalid-substrate it runs anyway (for testing the harness) and marks
every file valid_for_claims=false with the reasons.
"""
from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import os
import platform
import random
import shlex
import socket
import statistics
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from control_plane.client import Client  # noqa: E402
from control_plane.config import Config  # noqa: E402

WRITES_SCRIPT = ("find /workspace/repo -name '*.py' | sort | head -n {n} | "
                 "while read f; do echo '# agent edit' >> \"$f\"; done")
WRITER = ("nohup sh -c 'i=0; while :; do head -c 1048576 /dev/urandom > /tmp/io.$((i%64)); "
          "i=$((i+1)); done' >/dev/null 2>&1 &")


# ---- Docker Engine API over the unix socket --------------------------------
class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=300)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)


class Docker:
    def __init__(self, sock="/var/run/docker.sock"):
        self.sock = sock

    def req(self, method, path, body=None):
        c = _UnixHTTP(self.sock)
        c.request(method, path, body=json.dumps(body) if body is not None else None,
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read()
        c.close()
        if r.status >= 400:
            raise RuntimeError(f"docker {method} {path}: {r.status} {data[:300]!r}")
        return json.loads(data) if data and data[:1] in b"{[" else None

    def run(self, image, host_config):
        cid = self.req("POST", "/containers/create",
                       {"Image": image, "Cmd": ["sleep", "infinity"], "HostConfig": host_config})["Id"]
        self.req("POST", f"/containers/{cid}/start")
        return cid

    def exec(self, cid, cmd):
        # Attached streams make /start block until the process exits (the
        # same semantics as the control plane's synchronous exec).
        eid = self.req("POST", f"/containers/{cid}/exec",
                       {"Cmd": cmd, "AttachStdout": True, "AttachStderr": True})["Id"]
        self.req("POST", f"/exec/{eid}/start", {"Detach": False, "Tty": False})
        info = self.req("GET", f"/exec/{eid}/json")
        if info["Running"]:
            raise RuntimeError(f"exec {eid} still running after start returned")
        return info["ExitCode"]

    def rm(self, cid):
        self.req("DELETE", f"/containers/{cid}?force=1")


# ---- host description / substrate checks ------------------------------------
def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


def backing(path):
    src, fstype = sh(f"findmnt -n -o SOURCE,FSTYPE -T {shlex.quote(path)}").split()[:2]
    dev = src.split("[")[0]
    return {"path": path, "source": src, "device": dev, "fstype": fstype,
            "loop_backing": sh(f"losetup -n -O BACK-FILE {shlex.quote(dev)} 2>/dev/null") or None}


def host_spec(cfg, docker_root, server_info):
    cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?")
    mem_kb = next(int(l.split()[1]) for l in open("/proc/meminfo") if l.startswith("MemTotal"))
    return {"hostname": platform.node(), "kernel": platform.release(), "cpu": cpu,
            "cpus": os.cpu_count(), "mem_gib": round(mem_kb / 2**20, 1),
            "store": backing(cfg.store_root), "docker_root": backing(docker_root),
            "docker_version": sh("docker version -f '{{.Server.Version}}'"),
            "docker_storage_driver": sh("docker info -f '{{.Driver}}'"),
            "control_plane": server_info}


def validity(cfg, spec):
    reasons = []
    if cfg.storage != "btrfs":
        reasons.append(f"storage backend is {cfg.storage!r}, not btrfs")
    if cfg.dev_mode or not spec["control_plane"].get("cgroup_enforced"):
        reasons.append("dev_mode / cgroups not enforced (fork cannot freeze the parent)")
    if spec["store"]["device"] != spec["docker_root"]["device"]:
        reasons.append(f"btrfs store on {spec['store']['device']} but Docker data-root on "
                       f"{spec['docker_root']['device']} (BENCHMARKS.md §3.6)")
    if spec["store"]["loop_backing"]:
        reasons.append(f"btrfs store is a loopback file ({spec['store']['loop_backing']}); "
                       "record and never mix with block-device results")
    return reasons


def pct(xs):
    xs = sorted(xs)
    q = statistics.quantiles(xs, n=100, method="inclusive") if len(xs) > 1 else [xs[0]] * 99
    return {"n": len(xs), "min": xs[0], "median": statistics.median(xs), "p95": q[94],
            "p99": q[98], "max": xs[-1]}


# ---- main -------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True)
    ap.add_argument("--image", default="workload", help="control-plane image name")
    ap.add_argument("--docker-image", default="agent-sandbox-workload:django-5.1.4")
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--writes", type=int, default=200, help="files modified in *_writes scenarios")
    ap.add_argument("--fanout", default="1,10,50")
    ap.add_argument("--fanout-trials", type=int, default=5)
    ap.add_argument("--out")
    ap.add_argument("--allow-invalid-substrate", action="store_true")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    cfg = Config.load(args.config)
    docker = Docker()
    docker_root = docker.req("GET", "/info")["DockerRootDir"]
    image_meta = docker.req("GET", f"/images/{args.docker_image}/json")
    host_config = {"Memory": _bytes(cfg.memory_max), "PidsLimit": cfg.pids_max or 0}

    server = subprocess.Popen([sys.executable, "-m", "control_plane", "--config", args.config, "serve"],
                              cwd=REPO, stdout=subprocess.PIPE, text=True)
    c = None
    try:
        line = server.stdout.readline()
        if not line:
            raise SystemExit("control-plane server failed to start")
        server_info = json.loads(line)
        c = Client(cfg.socket_path)
        spec = host_spec(cfg, docker_root, server_info)
        reasons = validity(cfg, spec)
        if reasons and not args.allow_invalid_substrate:
            print("refusing to produce claim-grade numbers:\n  - " + "\n  - ".join(reasons), file=sys.stderr)
            return 2
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = args.out or os.path.join(REPO, "results", f"{stamp[:8]}-phase2-bench",
                                       f"{stamp}-{platform.node()}" + ("-INVALID" if reasons else ""))
        os.makedirs(out, exist_ok=True)
        common = {"valid_for_claims": not reasons, "invalid_reasons": reasons}
        with open(os.path.join(out, "host.json"), "w") as f:
            json.dump({**common, **spec, "docker_image": args.docker_image,
                       "docker_image_id": image_meta["Id"], "sandbox_image": args.image,
                       "docker_host_config": host_config}, f, indent=2)
        with open(os.path.join(out, "command.txt"), "w") as f:
            f.write(" ".join(shlex.quote(a) for a in sys.argv) + "\n")

        idle = c.create_environment(args.image)["sandbox_id"]
        active = c.create_environment(args.image)["sandbox_id"]
        c.exec(active, ["sh", "-c", WRITER])
        # Warm-up, discarded: first-touch page cache on both sides.
        c.destroy(c.fork(idle)["sandbox_id"])
        docker.rm(docker.run(args.docker_image, host_config))

        writes = WRITES_SCRIPT.format(n=args.writes)

        def t_fork(parent, do_writes):
            t0 = time.perf_counter()
            r = c.fork(parent)
            assert c.exec(r["sandbox_id"], ["true"])["exit_code"] == 0
            t1 = time.perf_counter()
            rec = {"ready_ms": (t1 - t0) * 1e3, "components_ms": r["timings_ms"]}
            if do_writes:
                assert c.exec(r["sandbox_id"], ["sh", "-c", writes])["exit_code"] == 0
                rec["ready_plus_writes_ms"] = (time.perf_counter() - t0) * 1e3
            c.destroy(r["sandbox_id"])
            return rec

        def t_docker(do_writes):
            t0 = time.perf_counter()
            cid = docker.run(args.docker_image, host_config)
            assert docker.exec(cid, ["true"]) == 0
            t1 = time.perf_counter()
            rec = {"ready_ms": (t1 - t0) * 1e3}
            if do_writes:
                assert docker.exec(cid, ["sh", "-c", writes]) == 0
                rec["ready_plus_writes_ms"] = (time.perf_counter() - t0) * 1e3
            docker.rm(cid)
            return rec

        scenarios = {
            "fork": lambda: t_fork(idle, False),
            "fork_active": lambda: t_fork(active, False),
            "docker": lambda: t_docker(False),
            "fork_writes": lambda: t_fork(idle, True),
            "docker_writes": lambda: t_docker(True),
        }
        order = [s for s in scenarios for _ in range(args.trials)]
        random.Random(args.seed).shuffle(order)
        results = {s: [] for s in scenarios}
        with open(os.path.join(out, "trials.jsonl"), "w") as f:
            for i, s in enumerate(order):
                rec = {"scenario": s, "trial": len(results[s]), "seq": i,
                       "wall_start": time.time(), **scenarios[s]()}
                results[s].append(rec)
                f.write(json.dumps(rec) + "\n")
                f.flush()

            fan = {}
            for n in [int(x) for x in args.fanout.split(",")]:
                for side in ("fork", "docker") * args.fanout_trials:
                    t0 = time.perf_counter()
                    made = []
                    for _ in range(n):
                        if side == "fork":
                            sid = c.fork(idle)["sandbox_id"]
                            assert c.exec(sid, ["true"])["exit_code"] == 0
                        else:
                            sid = docker.run(args.docker_image, host_config)
                            assert docker.exec(sid, ["true"]) == 0
                        made.append(sid)
                    total = (time.perf_counter() - t0) * 1e3
                    for sid in made:
                        c.destroy(sid) if side == "fork" else docker.rm(sid)
                    rec = {"scenario": f"fanout_{side}", "n": n, "total_ms": total,
                           "per_env_ms": total / n, "wall_start": time.time()}
                    fan.setdefault(f"fanout_{side}_n{n}", []).append(total)
                    f.write(json.dumps(rec) + "\n")
                    f.flush()

        summary = {**common, "ready_ms": {s: pct([r["ready_ms"] for r in rs]) for s, rs in results.items()},
                   "ready_plus_writes_ms": {s: pct([r["ready_plus_writes_ms"] for r in rs])
                                            for s, rs in results.items() if s.endswith("_writes")},
                   "fork_components_ms": {}, "fanout_total_ms": {k: pct(v) for k, v in fan.items()},
                   "writes": args.writes}
        comps = [r["components_ms"] for r in results["fork"]]
        for k in comps[0]:
            if isinstance(comps[0][k], (int, float)) and not isinstance(comps[0][k], bool):
                summary["fork_components_ms"][k] = pct([x[k] for x in comps])
        with open(os.path.join(out, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2)
        print(json.dumps(summary, indent=2))
        print(f"\nwrote {out}", file=sys.stderr)
        c.destroy(idle)
        c.destroy(active)
        return 0
    finally:
        if c:
            c.close()
        server.terminate()
        server.wait()


def _bytes(v):
    if v is None:
        return 0
    units = {"K": 2**10, "M": 2**20, "G": 2**30}
    return int(float(v[:-1]) * units[v[-1]]) if v[-1] in units else int(v)


if __name__ == "__main__":
    sys.exit(main())
