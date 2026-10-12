#!/usr/bin/env python3
"""Claim 1 benchmark: environment fork vs. Docker container start, on the same workspace.

    sudo python3 bench/fork_vs_restart.py --label <host-label> [--trials 30]

Prerequisite: `sudo sh bench/build_workload.sh` (builds the docker image and
imports the identical rootfs as btrfs image "workload").

What is timed (all wall-clock, time.monotonic_ns, from the API call until the
sandbox has run `true` and returned its exit status = "ready to exec"):

  fork_idle         fork(parent) + exec(true), parent idle
  fork_busy         fork(parent) + exec(true), parent continuously writing to its rootfs
  create_fresh      create_environment(workload image) + exec(true)
  docker_run        Engine API: containers/create + start + exec(true), warm image
  docker_commit_run Engine API: commit(parent container, pause=true) + create + start + exec(true).
                    This is the state-equivalent baseline: like fork, the new container
                    carries the parent's diverged state.
  cow_*             the same, then a realistic post-fork write workload (the agent edits
                    every tracked .py file under src/ and tests/ and commits). This makes
                    the deferred copy-on-write cost visible (BENCHMARKS.md §3.4).
  fanout_*_N        N children started concurrently; wall time until all N are ready.

"fork" here is an ENVIRONMENT fork (filesystem + fresh process tree), not a
process-memory fork. See DESIGN.md §4.

Both sides are driven through their native API over a Unix socket (no CLI
process spawns). Docker uses NetworkMode=none because Phase 2 forks have no
network yet. Scenarios are run round-robin in a shuffled order each round, so
drift (thermal, page cache, background activity) is spread across all of them.
Every trial is written as one JSON line, warm-ups included and flagged.
"""
from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import os
import random
import socket
import statistics
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "scripts"))

from control_plane.client import Client  # noqa: E402
from control_plane.config import Config  # noqa: E402
from record import provenance, sh  # noqa: E402

DOCKER_IMAGE = "sandboxd-workload:latest"
PARENT_SETUP = (
    "cd /workspace/flask && git checkout -q -b agent-work && "
    "echo '# agent was here' >> src/flask/app.py && git commit -qam wip && "
    "/workspace/venv/bin/python -m pytest -q -x tests/test_basic.py -p no:cacheprovider >/dev/null"
)
EDIT_WORKLOAD = (
    "cd /workspace/flask && for f in $(git ls-files 'src/*.py' 'tests/*.py'); do echo '# agent edit' >> \"$f\"; done "
    "&& git add -A && git commit -qm edit"
)
BUSY_WRITER = "while :; do dd if=/dev/urandom of=/tmp/churn bs=1M count=16 2>/dev/null; done >/dev/null 2>&1 &"


def now() -> int:
    return time.monotonic_ns()


def ms(a: int, b: int) -> float:
    return round((b - a) / 1e6, 3)


# --------------------------------------------------------------------- docker


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost", timeout=300)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(300)
        s.connect(self._path)
        self.sock = s


class Docker:
    """Minimal Docker Engine API client over /var/run/docker.sock."""

    def __init__(self, sock="/var/run/docker.sock"):
        self.sock = sock
        self.c = _UnixHTTP(sock)

    def req(self, method, url, body=None, ok=(200, 201, 204, 304)):
        headers = {"Content-Type": "application/json"} if body is not None else {}
        self.c.request(method, url, body=json.dumps(body) if body is not None else None, headers=headers)
        r = self.c.getresponse()
        data = r.read()
        if r.will_close:
            self.c.close()
        if r.status not in ok:
            raise RuntimeError(f"docker {method} {url}: {r.status} {data[:300]!r}")
        if data and (r.getheader("Content-Type") or "").startswith("application/json"):
            return json.loads(data)
        return data

    def run(self, image, cmd=("sleep", "infinity")) -> str:
        cid = self.req("POST", "/containers/create", {"Image": image, "Cmd": list(cmd), "HostConfig": {"NetworkMode": "none"}})["Id"]
        self.req("POST", f"/containers/{cid}/start")
        return cid

    def exec(self, cid, cmd) -> int:
        eid = self.req("POST", f"/containers/{cid}/exec", {"Cmd": list(cmd), "AttachStdout": True, "AttachStderr": True})["Id"]
        self.req("POST", f"/exec/{eid}/start", {"Detach": False, "Tty": False})
        return self.req("GET", f"/exec/{eid}/json")["ExitCode"]

    def commit(self, cid, tag) -> str:
        return self.req("POST", f"/commit?container={cid}&repo=sandboxd-bench-commit&tag={tag}&pause=true", {})["Id"]

    def rm(self, cid):
        self.req("DELETE", f"/containers/{cid}?force=1&v=1", ok=(204, 404))

    def rmi(self, iid):
        self.req("DELETE", f"/images/{iid}?force=1", ok=(200, 404, 409))

    def info(self):
        i = self.req("GET", "/info")
        v = self.req("GET", "/version")
        return {k: i.get(k) for k in ("Driver", "DriverStatus", "DockerRootDir", "DefaultRuntime", "CgroupVersion", "SecurityOptions", "ServerVersion")} | {
            "ApiVersion": v.get("ApiVersion"), "containerd": [c.get("Version") for c in v.get("Components", []) if c.get("Name") == "containerd"]}


# ---------------------------------------------------------------- our daemon


class OurDaemon:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.cfg_path = os.path.join(cfg.run_dir + ".json")
        with open(self.cfg_path, "w") as f:
            json.dump(cfg.__dict__, f)
        self.sock = os.path.join(cfg.run_dir, "sandboxd.sock")
        if os.path.exists(self.sock):
            os.unlink(self.sock)
        self.proc = subprocess.Popen([sys.executable, "-m", "control_plane.server", "--config", self.cfg_path],
                                     cwd=REPO, stdout=subprocess.PIPE, text=True)
        self.start_info = json.loads(self.proc.stdout.readline())
        while not os.path.exists(self.sock):
            time.sleep(0.01)

    def client(self) -> Client:
        return Client(self.sock)

    def stop(self):
        self.proc.terminate()
        self.proc.wait(30)


# ------------------------------------------------------------------ scenarios


class Bench:
    def __init__(self, args, daemon: OurDaemon, docker: Docker):
        self.args = args
        self.d = daemon
        self.c = daemon.client()
        self.dk = docker
        self.commit_seq = 0

    # setup / teardown of long-lived parents
    def setup(self):
        r = self.c.create_environment("workload")
        self.parent = r["id"]
        res = self.c.exec(self.parent, ["sh", "-c", PARENT_SETUP], timeout=600)
        assert res["exit_code"] == 0, res
        self.busy_parent = self.c.fork(self.parent)["id"]
        res = self.c.exec(self.busy_parent, ["sh", "-c", BUSY_WRITER])
        assert res["exit_code"] == 0, res
        self.dparent = self.dk.run(DOCKER_IMAGE)
        assert self.dk.exec(self.dparent, ["sh", "-c", PARENT_SETUP]) == 0

    def teardown(self):
        for s in (self.busy_parent, self.parent):
            try:
                self.c.destroy(s)
            except Exception as e:  # noqa: BLE001
                print("teardown:", e, file=sys.stderr)
        self.dk.rm(self.dparent)

    # --- ours
    def _ours(self, make, writes: bool):
        t0 = now()
        r = make()
        t1 = now()
        sid = r["id"]
        res = self.c.exec(sid, ["true"])
        t2 = now()
        assert res["exit_code"] == 0, res
        rec = {"api_ms": ms(t0, t1), "ready_ms": ms(t0, t2), "server_timings": r["timings"]}
        if writes:
            res = self.c.exec(sid, ["sh", "-c", EDIT_WORKLOAD], timeout=300)
            t3 = now()
            assert res["exit_code"] == 0, res
            rec |= {"writes_ms": ms(t2, t3), "ready_plus_writes_ms": ms(t0, t3)}
        t4 = now()
        rec["destroy_ms"] = self.c.destroy(sid)["total_ms"]
        rec["destroy_wall_ms"] = ms(t4, now())
        return rec

    def fork_idle(self):
        return self._ours(lambda: self.c.fork(self.parent), False)

    def fork_busy(self):
        return self._ours(lambda: self.c.fork(self.busy_parent), False)

    def create_fresh(self):
        return self._ours(lambda: self.c.create_environment("workload"), False)

    def cow_fork(self):
        return self._ours(lambda: self.c.fork(self.parent), True)

    # --- docker
    def _docker(self, commit: bool, writes: bool):
        t0 = now()
        rec = {}
        image = DOCKER_IMAGE
        iid = None
        if commit:
            self.commit_seq += 1
            iid = self.dk.commit(self.dparent, f"t{self.commit_seq}")
            image = iid
            rec["commit_ms"] = ms(t0, now())
        tc = now()
        cid = self.dk.run(image)
        t1 = now()
        assert self.dk.exec(cid, ["true"]) == 0
        t2 = now()
        rec |= {"api_ms": ms(t0, t1), "create_start_ms": ms(tc, t1), "ready_ms": ms(t0, t2)}
        if writes:
            assert self.dk.exec(cid, ["sh", "-c", EDIT_WORKLOAD]) == 0
            t3 = now()
            rec |= {"writes_ms": ms(t2, t3), "ready_plus_writes_ms": ms(t0, t3)}
        t4 = now()
        self.dk.rm(cid)
        if iid:
            self.dk.rmi(iid)
        rec["destroy_wall_ms"] = ms(t4, now())
        return rec

    def docker_run(self):
        return self._docker(False, False)

    def docker_commit_run(self):
        return self._docker(True, False)

    def cow_docker_run(self):
        return self._docker(False, True)

    def cow_docker_commit(self):
        return self._docker(True, True)

    # --- fan-out
    def fanout_fork(self, n):
        clients = [self.d.client() for _ in range(n)]
        ids, errs = [None] * n, []
        barrier = threading.Barrier(n + 1)
        done = [0] * n

        def go(i):
            barrier.wait()
            try:
                ids[i] = clients[i].fork(self.parent)["id"]
                assert clients[i].exec(ids[i], ["true"])["exit_code"] == 0
                done[i] = now()
            except Exception as e:  # noqa: BLE001
                errs.append(repr(e))

        ths = [threading.Thread(target=go, args=(i,)) for i in range(n)]
        for t in ths:
            t.start()
        t0 = now()
        barrier.wait()
        for t in ths:
            t.join()
        rec = self._fan_rec(n, t0, done, errs)
        for i, sid in enumerate(ids):
            if sid:
                clients[i].destroy(sid)
            clients[i].close()
        return rec

    def fanout_docker(self, n):
        dks = [Docker(self.dk.sock) for _ in range(n)]
        ids, errs = [None] * n, []
        barrier = threading.Barrier(n + 1)
        done = [0] * n

        def go(i):
            barrier.wait()
            try:
                ids[i] = dks[i].run(DOCKER_IMAGE)
                assert dks[i].exec(ids[i], ["true"]) == 0
                done[i] = now()
            except Exception as e:  # noqa: BLE001
                errs.append(repr(e))

        ths = [threading.Thread(target=go, args=(i,)) for i in range(n)]
        for t in ths:
            t.start()
        t0 = now()
        barrier.wait()
        for t in ths:
            t.join()
        rec = self._fan_rec(n, t0, done, errs)
        for i, cid in enumerate(ids):
            if cid:
                dks[i].rm(cid)
        return rec

    @staticmethod
    def _fan_rec(n, t0, done, errs):
        if errs:
            return {"n": n, "errors": errs}
        per = sorted(ms(t0, d) for d in done)
        return {"n": n, "all_ready_ms": per[-1], "first_ready_ms": per[0], "median_child_ready_ms": statistics.median(per)}


# --------------------------------------------------------------------- stats


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 3)


def summarize(trials):
    groups = {}
    for t in trials:
        if t.get("warmup") or "error" in t:
            continue
        g = groups.setdefault(t["scenario"], {})
        flat = dict(t["result"])
        st = flat.pop("server_timings", None)
        if st:
            for k, v in st.items():
                if isinstance(v, (int, float)):
                    flat["server." + k] = v
                elif isinstance(v, dict):
                    for k2, v2 in v.items():
                        flat[f"server.{k}.{k2}"] = v2
        for k, v in flat.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool) and k != "n":
                g.setdefault(k, []).append(v)
    out = {}
    for scen, metrics in groups.items():
        out[scen] = {k: {"n": len(v), "min": round(min(v), 3), "median": pct(v, 50), "p95": pct(v, 95), "p99": pct(v, 99),
                         "max": round(max(v), 3), "mean": round(statistics.fmean(v), 3)} for k, v in metrics.items()}
    return out


def host_info(daemon: OurDaemon, docker: Docker):
    df = lambda p: sh("findmnt", "-n", "-o", "SOURCE,FSTYPE,OPTIONS", "--target", p)  # noqa: E731
    dinfo = docker.info()
    return {
        "provenance": provenance(),
        "lsblk": sh("lsblk", "-o", "NAME,ROTA,TYPE,SIZE,MODEL,FSTYPE,MOUNTPOINTS"),
        "btrfs_volume": daemon.start_info.get("volume"),
        "btrfs_backing_file_fs": df(daemon.cfg.image_path) if not daemon.cfg.btrfs_device else None,
        "docker": dinfo,
        "docker_root_fs": df(dinfo.get("DockerRootDir") or "/var/lib/docker"),
        "docker_image": docker.req("GET", f"/images/{DOCKER_IMAGE}/json").get("Id"),
        "workload_parent_setup": PARENT_SETUP,
        "edit_workload": EDIT_WORKLOAD,
        "busy_writer": BUSY_WRITER,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", required=True, help="host label for the results dir, e.g. wsl-dev-NOT-TARGET")
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--scenarios", default="fork_idle,fork_busy,create_fresh,docker_run,docker_commit_run,cow_fork,cow_docker_run,cow_docker_commit")
    ap.add_argument("--fanout", default="1,10,50,100")
    ap.add_argument("--fanout-trials", type=int, default=30)
    ap.add_argument("--state-dir", default="/var/lib/sandboxd-bench")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    started = dt.datetime.now(dt.timezone.utc)
    out_dir = os.path.join(REPO, "results", "phase2-bench", args.label, started.strftime("%Y%m%dT%H%M%SZ"))
    os.makedirs(out_dir)
    cfg = Config(state_dir=args.state_dir, run_dir="/run/sandboxd-bench", cgroup_root="/sys/fs/cgroup/sandboxd-bench",
                 max_sandboxes=1024)
    daemon = OurDaemon(cfg)
    docker = Docker()
    bench = Bench(args, daemon, docker)
    rng = random.Random(args.seed)
    trials_path = os.path.join(out_dir, "trials.jsonl")
    meta = {"command": " ".join([sys.executable] + sys.argv), "started_utc": started.isoformat(), "args": vars(args),
            "host": host_info(daemon, docker)}
    with open(os.path.join(out_dir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1)

    trials = []

    def record(scenario, rnd, warm, fn, *a):
        rec = {"scenario": scenario, "round": rnd, "warmup": warm, "t_unix": time.time()}
        try:
            rec["result"] = fn(*a)
        except Exception as e:  # noqa: BLE001
            rec["error"] = repr(e)
            print(f"[{scenario} r{rnd}] ERROR {e!r}", file=sys.stderr, flush=True)
        trials.append(rec)
        with open(trials_path, "a") as f:
            f.write(json.dumps(rec) + "\n")

    bench.setup()
    try:
        scenarios = [s for s in args.scenarios.split(",") if s]
        for rnd in range(args.warmup + args.trials):
            order = scenarios[:]
            rng.shuffle(order)
            for s in order:
                record(s, rnd, rnd < args.warmup, getattr(bench, s))
            print(f"round {rnd + 1}/{args.warmup + args.trials} done", flush=True)
        for n in [int(x) for x in args.fanout.split(",") if x]:
            for rnd in range(1 + args.fanout_trials):  # one warm-up round per N
                order = [("fanout_fork", bench.fanout_fork), ("fanout_docker", bench.fanout_docker)]
                rng.shuffle(order)
                for name, fn in order:
                    record(f"{name}_{n}", rnd, rnd < 1, fn, n)
            print(f"fanout N={n} done", flush=True)
    finally:
        bench.teardown()
        daemon.stop()

    summary = summarize(trials)
    errors = [t for t in trials if "error" in t]
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump({"note": "Computed from trials.jsonl by bench/fork_vs_restart.py:summarize(); warm-up rounds and errored trials excluded. "
                           "p99 over 30 samples is close to the max and should be read as such.",
                   "errors": len(errors), "summary": summary}, f, indent=1)
    meta["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    with open(os.path.join(out_dir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1)
    print(json.dumps({k: v.get("ready_ms") or v.get("all_ready_ms") for k, v in summary.items()}, indent=1))
    print("results ->", out_dir)


if __name__ == "__main__":
    main()
