# Phase 2 kickoff — fork + first benchmark

Goal (PLAN.md): `fork(sandbox_id)` produces an independent sibling via
cgroup freeze + btrfs snapshot + fresh namespaces/cgroup. Then the first
real benchmark: fork vs. Docker container start on the same workspace.

`fork` is an **environment** fork: filesystem state plus a fresh process
tree. It is not a process-memory fork (DESIGN.md §4). Every result file
and table says so.

## The decisions most likely to be wrong, and the fallback for each

1. **"The snapshot contains every write the parent completed before the
   freeze."** btrfs flushes the source subvolume's delalloc (dirty page
   cache) when it creates a snapshot. So un-fsync'd writes *should* be
   included. If `test_fork_during_active_io` shows otherwise, the
   fallback is `syncfs()` on the parent's subvolume while frozen and
   before the snapshot, with the cost added to the reported frozen
   window. The same mechanism carries a second risk: the frozen window
   grows with the parent's amount of dirty data. So fork is also
   benchmarked against a parent that is actively writing, and the frozen
   window is reported on its own.
2. **What counts as the Docker baseline.** "Restart a container from
   the image" is the brief's comparison. But a fresh container does not
   contain the parent's *diverged* state, so it is not
   state-equivalent to a fork. Both are measured:
   * `docker_run_warm`: create + start a container from the warm image,
     then `exec true`.
   * `docker_commit_run`: `docker commit` of a parent container that has
     the same diverged state, then create + start + `exec true`. This
     is the state-equivalent baseline.

   Steel-manning, per CLAUDE.md rule 3: Docker is driven through the
   Engine HTTP API on its Unix socket, not the CLI (no per-call process
   spawn). It uses `NetworkMode: none`, because Phase 2 forks have no
   network yet; Phase 3 re-runs both sides with networking. The image
   cache is warm, and the image is the real workspace. If someone shows
   a faster correct way to get a ready container from Docker, that
   becomes the baseline.
3. **Storage-substrate mismatch.** On the dev host the btrfs volume is a
   loopback file on the same ext4 virtual disk that holds Docker's
   data-root (overlayfs snapshotter). Same physical device, different
   filesystem stacks. Every result records both. Loopback and
   block-device results are never mixed. The dev host is a WSL2 VM and
   is labelled NOT-TARGET everywhere. Its numbers say nothing about the
   target VM.

## Exit criteria

- `tests/test_fork.py` passes: isolation in both directions, fork during
  active I/O (no lost or torn records), fork under memory pressure, deep
  fork chains, concurrent fan-out from one parent, destroying a parent
  under live children.
- `bench/fork_vs_restart.py` runs ≥ 30 trials per scenario. Raw per-trial
  JSONL plus host spec is committed under `results/phase2-bench/`, and
  the exact command is in BENCHMARKS.md.
