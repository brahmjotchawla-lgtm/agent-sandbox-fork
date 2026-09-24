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

- `fork(sandbox_id)` — this repo's overlayfs-based environment fork
  (DESIGN.md §3-4).
- Container restart baseline — `docker run` against a **warm-cached**
  image containing the same workload (see §2).

Reported per component, not just as one number, because the interesting
engineering claim is *why* fork is cheap:

- namespace creation time
- overlayfs mount time
- cgroup setup time
- veth/netns setup time
- total, end-to-end

Secondary metric (see §3.4 — this is the one most benchmarks in this
space skip): **post-fork copy-up cost.** overlayfs fork is metadata-only
at fork time; the cost of divergence is paid later, per byte, when a
forked sandbox actually writes to a file that exists only in a lower
layer. A benchmark that reports only the fork call's latency and ignores
this is misleading by omission — see §3.4 for how this is measured
honestly.

Fan-out metric: latency of `fork` to N children (N = 1, 10, 50, 100,
hardware-permitting) vs. starting N containers, to demonstrate the actual
shape of the claim (shared lower layer keeps fork flat; restart cost
scales ~linearly with N).

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
4. **Ignoring deferred copy-up cost.** A fork-only number taken in
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
6. **Unstated or unreproducible hardware.** Every result in `/results`
   includes the exact host spec (CPU, RAM, disk type, kernel version) it
   was produced on, in the same file as the raw output. Numbers are not
   claimed to generalize beyond that documented hardware.
7. **Cherry-picked runs.** The harness script and its exact invocation
   are linked from every number that appears in README/DESIGN, per
   CLAUDE.md rule 2 — anyone can re-run it.

## 4. Harness

- Location: `/bench` (scripts), `/results/<date>-<phase>/` (committed raw
  output — JSON lines, one record per trial, including timestamps, host
  spec, and the exact command invoked).
- Not yet implemented — lands with Phase 2 (basic fork-vs-restart) and is
  extended in Phase 3 (fan-out, containment-adjacent overhead) per
  PLAN.md. This document will gain a "Results" section with links once
  real numbers exist; until then, no numbers are stated anywhere in this
  repo.

## 5. Explicitly not a benchmark

The Phase 4 adversarial security test suite (DESIGN.md §5) is a
correctness/security artifact, not a performance one. It will never be
summarized as a single score or percentage that could be read as a
performance-style metric — findings are reported as a table of specific
attack attempts and their outcomes, including known limitations, per
CLAUDE.md rule 5.
