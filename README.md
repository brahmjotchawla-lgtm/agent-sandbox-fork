# Sandbox server for AI agents (working title)

A sandbox server for AI agents that forks a running agent environment into
N parallel copies, with containment enforced from outside the sandbox.

**Status: Phases 1–3 implemented; no performance claims yet.** The control
plane, the environment fork, the egress containment and the benchmark
harness exist and are tested. Two things are still missing:

- **No performance numbers.** They can only come from the harness running on
  a host with btrfs and cgroup v2. That host hasn't been provisioned yet
  ([PLAN.md](PLAN.md)). Per [CLAUDE.md](CLAUDE.md), this README states
  none.
- **The tests have only run on a host that is not the target.** The
  [raw output](results/phase1-3-tests/claude-cloud-container-NOT-TARGET/20260930T180732Z-vm.txt)
  comes from a cloud container whose kernel has no btrfs and no cgroup v2
  controllers. That run used the dev-only full-copy storage backend with
  cgroups unenforced. Everything that depends on btrfs or cgroups is
  unverified until the suite runs on the target host. See
  [What has been verified where](#what-has-been-verified-where).

## What it is

- `fork(sandbox_id)` is an **environment fork**. It freezes the parent's
  cgroup, takes a btrfs snapshot of its subvolume, thaws it, and starts a
  **fresh process tree** in new namespaces and a new cgroup. No process
  memory is copied. Live memory fork (CRIU) is a separate stretch goal and
  is not implemented. See [DESIGN.md §4](DESIGN.md#4-process-model).
- Every sandbox runs as root inside its own user, mount, PID, UTS, IPC, net
  and cgroup namespaces. Its root maps to a **distinct unprivileged host
  uid range** per sandbox, using idmapped mounts. It runs under a seccomp
  filter and `no_new_privs`, and its only network peer is an
  allowlist-only CONNECT proxy whose rules live in a netns the sandbox
  can't enter. See [DESIGN.md §5](DESIGN.md#5-containment-model-and-threat-model).
- Built directly from Linux primitives (`unshare(2)`, `pivot_root(2)`,
  cgroup v2 files, `nft`, `ip`) in Python. See
  [`control_plane/nsinit.py`](control_plane/nsinit.py).

## Quickstart (target host)

```sh
sudo scripts/setup_host.sh /dev/<spare-disk> --wipe     # btrfs store + docker on one disk
sudo python3 scripts/host_check.py --workdir /var/lib/agent-sandbox
sudo cp config.example.json /etc/agent-sandbox.json      # edit egress_allowlist
sudo python3 -m control_plane --config /etc/agent-sandbox.json serve &
sudo AGENT_SANDBOX_CONFIG=/etc/agent-sandbox.json bench/workload/build.sh

sudo python3 -m control_plane --config /etc/agent-sandbox.json create workload
sudo python3 -m control_plane --config /etc/agent-sandbox.json fork sbx-XXXXXXXXXXXX
sudo python3 -m control_plane --config /etc/agent-sandbox.json exec sbx-YYYYYYYYYYYY -- python3 -c "import django; print(django.get_version())"
```

Python API: [`control_plane/client.py`](control_plane/client.py).

## Tests and benchmark

```sh
# full suite (root; Docker is needed to import the base image)
sudo AGENT_SANDBOX_TEST_BTRFS=/var/lib/agent-sandbox python3 -m pytest tests -v -rsx

# Claim 1 harness; refuses to run unless the substrate is valid (BENCHMARKS.md §3)
sudo python3 bench/fork_vs_restart.py --config /etc/agent-sandbox.json --trials 30
```

## What has been verified where

| Area | Cloud container (not target) | Target VM |
|---|---|---|
| Namespaces, per-sandbox uid mapping, pivot_root, exec, destroy | tested, pass | not run |
| Fork semantics (isolation, fresh process tree, chains, siblings) | tested, pass (copy backend) | not run |
| Crash mid-create / mid-fork, then reconcile (11 injection points) | tested, pass | not run |
| Egress: no route out, host unreachable, proxy allowlist, SSRF-to-private refusal, root re-routing, rule tampering, sibling reach, IP spoofing | tested, pass | not run |
| seccomp (btrfs ioctls, `no_new_privs`) | tested, pass | not run |
| Phase 4 adversarial suite: 30 attack rows, see [DESIGN.md §5.6](DESIGN.md#56-adversarial-coverage-phase-4) | pass, except rows marked known limitation, skipped or not tested there | not run |
| btrfs snapshot / delete, fork during active I/O (freeze) | **not testable here** (xfail) | not run |
| cgroup limits (memory, pids, fork-under-memory-pressure) | **skipped: no cgroup v2** | not run |
| Benchmark harness | smoke-tested; output correctly marked invalid, not committed | not run |

## Docs

- [DESIGN.md](DESIGN.md): architecture, copy-on-write choice, threat model
  (including what it doesn't cover), and the API surface.
- [BENCHMARKS.md](BENCHMARKS.md): what's measured, the baselines, and how
  the harness avoids misleading numbers.
- [PLAN.md](PLAN.md): the phased build plan and its current status.
- [CLAUDE.md](CLAUDE.md): ground rules for anyone, human or agent, working
  in this repo.

## Layout

| Path | Purpose |
|---|---|
| `control_plane/` | Control plane: manager, namespace init, storage, cgroups, network, proxy, RPC |
| `bench/` | Benchmark harness and workload definition |
| `results/` | Committed raw benchmark and test output |
| `tests/` | Lifecycle, crash-recovery, network, seccomp and adversarial tests |
| `scripts/` | Host setup and verification scripts |

## License

Apache-2.0. See [LICENSE](LICENSE).
