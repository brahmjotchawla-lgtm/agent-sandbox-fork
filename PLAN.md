# PLAN.md

## Status (2026-09-30)

| Phase | State |
|---|---|
| 0 | Host check written. It has run on two non-target hosts (WSL laptop, and the Claude cloud container, which has no btrfs and no cgroup v2). **It has not run on the target VM yet.** |
| 1 | Implemented and tested on the non-target host (dev_mode: copy backend, cgroups unenforced). |
| 2 | Fork and harness implemented. Fork semantics are tested. The btrfs path, the freeze, and all benchmark numbers are **pending the target VM**. |
| 3 | Egress netns, proxy, nft, per-sandbox uid ranges and seccomp are implemented and tested. The cgroup limit tests are written but skipped (no cgroup v2 on the test host). |
| 4 | Suite and coverage table (DESIGN.md §5.6) done for everything testable without btrfs/cgroup v2. Open: the ABI-kill seccomp rule, cgroup self-modification, and the btrfs-specific rows, which need the target VM. |
| 5 | Not started (CRIU stretch). |
| 6 | Not started. |

**Next step, which blocks every claim:** provision the target VM
(`scripts/setup_host.sh`), run `scripts/host_check.py`, run the full test
suite with `AGENT_SANDBOX_TEST_BTRFS` set, then run the benchmark and
commit all raw output.

### Phase 1–3 decisions most likely to be wrong, and the fallback for each

1. **Idmapped mounts on btrfs for per-sandbox uid ranges.** Verified on
   ext4 only. *Fallback:* one shared host uid range for all sandboxes
   (chown the base image once). This weakens sibling isolation after an
   escape, and the change must be flagged in DESIGN.md §5.2.
2. **Creating cgroups directly under `/sys/fs/cgroup` on a systemd host.**
   systemd may not tolerate unmanaged cgroups, or the needed controllers
   may not be delegated. *Fallback:* run the control plane in a systemd
   service with `Delegate=yes` and set `cgroup_root` inside its subtree.
3. **The btrfs snapshot including page-cache data from a frozen parent.**
   `test_fork_during_active_io` checks this and is expected to pass on
   btrfs with the freeze. *Fallback if it fails:* `syncfs` on the parent's
   subvolume while it is frozen, then snapshot. That costs latency, which
   gets reported as its own component.

High-level phased roadmap. Each phase ends in something demonstrable —
not just code that compiles. Detailed task-by-task plans for each phase
are written immediately before that phase starts (not all upfront), and
each phase's kickoff names the 2-3 decisions most likely to be wrong and
the fallback for each, per CLAUDE.md.

**Checkpoint rule (from the original brief):** minimum shippable = Phases
0-3 (filesystem-only fork, real benchmark, working egress control). If
week 3 ends without Phases 1-3 solid, Phase 5 (CRIU) is cut — no
ceremony, just skip straight to Phase 4 with the remaining time.

**Separate checkpoint, independent of phase completion:** at the end of
week 4, switch to adversarial self-review of the repo as a skeptical
staff engineer (see the original brief, step 4). This happens on
schedule regardless of which phase is in progress.

## Phase 0 — Host verification and scaffold (~2-3 days)

Demonstrable: a script (`scripts/host_check.py`) that proves the target VM actually has what
the design assumes — a btrfs subvolume can be snapshotted while its source keeps being written, `unshare` can create
mount/PID/UTS/IPC/net namespaces, cgroup v2 is mounted and delegatable,
`nft` is available — run once against the real provisioned host, output
committed under `/results/phase0-host-check/`.

Also: repo scaffold, this doc set (done), CI skeleton.

## Phase 1 — Single-sandbox lifecycle (~1 week)

Demonstrable: control plane can create one sandbox from a base image
(btrfs subvolume snapshot + namespaces + cgroup, no network yet), `exec` a command
inside it, and `destroy` it with verified cleanup — including a test that
crashes a sandbox mid-operation and confirms the control plane still
cleans up mounts/namespaces/cgroups afterward (per CLAUDE.md rule 4).

## Phase 2 — Fork + first benchmark (~1 week)

Demonstrable: `fork(sandbox_id)` produces an independent sibling via cgroup freeze + btrfs snapshot + fresh namespaces/cgroup (network isolation still
pending — Phase 3). First real benchmark run: fork latency vs. Docker
container restart on the same workspace, raw output committed under
`/results`, exact command in BENCHMARKS.md.

## Phase 3 — Containment (~1 week)

Demonstrable: network namespace + veth + egress proxy enforced from
outside the sandbox's netns (DESIGN.md §5.4); cgroup resource limits
active; verified no shared mutable state between siblings. Manual
verification that sandboxed root cannot reach the network except through
the allowlisted proxy and cannot flush/modify the egress rules (formal
adversarial suite is Phase 4).

## Phase 4 — Adversarial security test suite (~1 week)

Demonstrable: the actual escape-attempt tests as code — privilege
escalation attempts, netns escape attempts, cgroup bypass attempts,
btrfs ioctl and subvolume-path escape attempts, symlink/mount escape attempts, attempts to reach the control
plane or the proxy's non-existent admin surface. Results table
(pass/fail/known-limitation) committed, matching DESIGN.md §5.3's stated
non-coverage — no silent gaps.

## Phase 5 — CRIU stretch (only if Phases 1-3 solid by end of week 3, ~3-5 days)

Demonstrable, if attempted: live process-memory fork on top of the
filesystem fork, reported honestly as "attempted, here's how far it got"
— not folded into Claim 1's headline numbers regardless of outcome.

## Phase 6 — Polish and final benchmark pass (~3-5 days)

Demonstrable: README written, all DESIGN/BENCHMARKS claims reconciled
against actual implementation (dead links or stale claims fixed), full
benchmark suite re-run end-to-end on the final code, raw output
committed. Repo ready for the week-4 adversarial self-review and for
external review.
