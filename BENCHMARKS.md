# BENCHMARKS.md

Status: draft — this document defines what will be measured and how. It
contains **no performance numbers**, because none have been measured yet
(no code exists). Per [CLAUDE.md](CLAUDE.md) rule 1, no number appears
anywhere in this repo's docs until it's produced by a script under
`/bench` with raw output committed under `/results`. This document will
be updated with links to actual results as each phase in
[PLAN.md](PLAN.md) lands.

## 1. What's measured

**Claim 1: fork is dramatically cheaper than container restart.**

Primary metric: wall-clock latency from API call to "sandbox ready to
`exec`," for two operations on the same starting workload:

- `fork(sandbox_id)` — this repo's btrfs-snapshot-based environment fork
  (DESIGN.md §3-4).
- Container restart baseline — `docker run` against a **warm-cached**
  image containing the same workload (see §2).

Reported per component, not just as one number, because the interesting
engineering claim is *why* fork is cheap:

- parent cgroup freeze-to-thaw window
- btrfs snapshot time
- namespace creation time
- rootfs mount/pivot time
- cgroup setup time
- veth/netns setup time
- total, end-to-end

Secondary metric (see §3.4 — this is the one most benchmarks in this
space skip): **post-fork copy-on-write cost.** A snapshot shares extents at fork time; the cost of divergence is paid later, when a forked sandbox writes to a shared extent. A benchmark that reports only the fork call's latency and ignores
this is misleading by omission — see §3.4 for how this is measured
honestly.

Fan-out metric: latency of `fork` to N children (N = 1, 10, 50, 100,
hardware-permitting) vs. starting N containers, to test the actual shape of the claim: whether fork cost stays flat in N while restart cost grows with N. Either outcome is reported.

**Claim 2: containment holds against root-inside adversary.**

This is a pass/fail adversarial test suite, not a performance benchmark —
see DESIGN.md §5 and the Phase 4 test suite. It is reported as a results
table (test name → pass/fail/known-limitation), never as a number that
could be mistaken for a performance metric.

## 2. Baselines (steel-manned, per CLAUDE.md rule 3)

- **Container runtime:** Docker, the most widely used and easiest for a
  reviewer to sanity-check independently.
- **Warm image cache.** The baseline measures `docker run` against an
  image already present on the host (`docker pull` happens once, before
  any timed run, and is never part of a reported number). Measuring cold
  pulls would compare fork against a baseline nobody actually runs in
  production RL/eval loops, which run warm.
- **Realistic minimal image**, not `hello-world`/`busybox`. The image
  contains the same workload used for the fork side of the comparison: a
  real mid-size open-source repo checkout, an installed language runtime,
  and installed dependencies (matching the "coding-agent workspace"
  decision — see DESIGN.md §1 and PLAN.md Phase 2). A trivial image would
  make container restart look artificially competitive and understate
  the actual gap this project is trying to demonstrate honestly.

## 3. What would be misleading, and how the harness avoids it

1. **Comparing an empty fork against a loaded container restart (or vice
   versa).** Both sides of every comparison run against the identical
   workload content and size — enforced by both the fork base image and
   the Docker baseline image being built from the same source spec in
   `/bench/workload/`.
2. **Cold-pull baselines.** Explicitly excluded — see §2.
3. **Reporting only a single best-case or median number.** Every
   benchmark run reports the full distribution (min/median/p95/p99) over
   N ≥ 30 trials, with raw per-trial timestamps committed under
   `/results`, not just a summary.
4. **Ignoring deferred copy-on-write cost.** A fork-only number taken in
   isolation overstates the win, because it hides the cost that gets paid
   later. The harness also runs a "fork + realistic post-fork writes"
   scenario (e.g., the agent modifies N files after forking) and reports
   that total alongside the bare fork number, so the two numbers can't be
   conflated. If this total ever exceeds the container-restart baseline
   for realistic post-fork write volumes, that will be reported as-is,
   not omitted.
5. **Single fork (1:1) only, when the real value proposition is fan-out.**
   The harness measures 1:1 and fan-out (N children) separately — see §1.
   A design whose only advantage shows up at 1:1 and disappears or
   inverts at realistic fan-out would be a materially different (weaker)
   claim than what this project sets out to prove, so both are reported.
6. **Mismatched storage substrates.** Forking on btrfs (especially a loopback file on the VM's root disk) against a Docker baseline on a different filesystem would compare two storage stacks, not fork versus restart. Every result records the filesystem and backing device for both sides; the baseline's Docker data-root is placed on the same physical device as the btrfs volume, and loopback-versus-block-device results are never mixed in one comparison.
7. **Fork measured only on an idle parent.** Snapshot cost may depend on in-flight writes, so fork is also measured while the parent is actively writing, and that number is reported next to the idle one.
8. **Unstated or unreproducible hardware.** Every result in `/results`
   includes the exact host spec (CPU, RAM, disk type, kernel version) it
   was produced on, in the same file as the raw output. Numbers are not
   claimed to generalize beyond that documented hardware.
9. **Cherry-picked runs.** The harness script and its exact invocation
   are linked from every number that appears in README/DESIGN, per
   CLAUDE.md rule 2 — anyone can re-run it.

## 4. Harness

- Location: `/bench` (scripts), `/results/<date>-<phase>/` (committed raw
  output — JSON lines, one record per trial, including timestamps, host
  spec, and the exact command invoked).
- Implemented: [bench/fork_vs_restart.py](bench/fork_vs_restart.py), workload
  [bench/workload/Dockerfile](bench/workload/Dockerfile), built and imported by
  [bench/build_workload.sh](bench/build_workload.sh).

## 4a. Results so far: WSL2 dev host only, NOT the target VM

Command: `sudo sh bench/build_workload.sh && sudo python3 bench/fork_vs_restart.py --label wsl-dev-NOT-TARGET`
(30 trials plus 3 warm-up rounds per scenario, shuffled round-robin). Raw per-trial data, host spec and a
provenance note are in
[results/phase2-bench/wsl-dev-NOT-TARGET/20261012T154223Z/](results/phase2-bench/wsl-dev-NOT-TARGET/20261012T154223Z/).
Phase 2 conditions: no networking on either side (Docker `NetworkMode: none`), no seccomp on the fork side.
Docker uses its default seccomp profile. The btrfs volume is a loopback file. These numbers say nothing
about the target VM. They are here because rule 1 forbids estimates, not because they are the headline.

"ready" = API call until `exec(true)` has returned. All values are in ms.

| scenario | median | p95 | p99 |
|---|---|---|---|
| fork_idle (environment fork, parent idle) | 56.3 | 330.8 | 944.5 |
| fork_busy (parent writing continuously) | 69.8 | 963.8 | 1175.9 |
| create_fresh (snapshot of base image) | 65.1 | 792.0 | 1089.0 |
| docker_run (warm image, Engine API) | 318.3 | 1486.0 | 1685.5 |
| docker_commit_run (state-equivalent baseline) | 2298.1 | 4799.7 | 6218.3 |
| cow_fork, ready + edit-and-commit workload | 151.1 (total) | | |
| cow_docker_run, ready + same workload | 663.4 (total) | | |

Fan-out, wall time until all N children are ready (median ms):

| N | fork | docker_run |
|---|---|---|
| 1 | 187.0 | 445.7 |
| 10 | 649.9 | 1052.6 |
| 50 | 5824.0 | 4805.5 |
| 100 | 11330.3 | 8991.0 |

What these numbers show, including the parts that cut against Claim 1:

1. **Single fork, median:** faster than a warm `docker run` on this host, and much faster than the
   state-equivalent `docker commit` + run.
2. **Tail latency is bad.** The parent-frozen window (median ~29 ms) has a p99 near 0.9–1.6 s. The time
   is the btrfs snapshot ioctl, which commits a filesystem transaction. A forking parent can therefore be
   frozen for over a second at the tail. This is unexplained beyond "transaction commit", and it is
   not fixed.
3. **Fan-out at N=50 and N=100: fork is slower than `docker run` on this host.** Forks from one parent
   serialize on that parent (freeze + snapshot under a per-parent lock), and every snapshot commits a
   transaction. Per §3.5 this is a materially weaker result than the claim this project set out to
   prove. It is reported as-is. It is the first thing to investigate (batching N snapshots under one
   freeze is the obvious candidate) and to re-measure on the target VM.


## 5. Explicitly not a benchmark

The Phase 4 adversarial security test suite (DESIGN.md §5) is a
correctness/security artifact, not a performance one. It will never be
summarized as a single score or percentage that could be read as a
performance-style metric — findings are reported as a table of specific
attack attempts and their outcomes, including known limitations, per
CLAUDE.md rule 5.
