# CLAUDE.md

Guidance for any Claude Code session (or other agent) working in this repo.

## What this project is

A sandbox server for AI agents. Two things it must prove with real
measurements, not estimates:

1. Forking a running agent environment (filesystem; process state is a
   stretch goal via CRIU) is dramatically cheaper than restarting a
   container from an image.
2. An agent with root **inside** the sandbox cannot reach the network, the
   host, or sibling sandboxes.

See [DESIGN.md](DESIGN.md) for architecture and threat model,
[BENCHMARKS.md](BENCHMARKS.md) for what's measured and how, and
[PLAN.md](PLAN.md) for the phased build plan.

## Non-negotiable ground rules

1. **Never state a performance number that didn't come from running the
   harness in this repo.** No estimates, no "typically ~X ms". If a number
   isn't measured yet, say so explicitly instead of guessing.
2. **Every claim in README/DESIGN links to the script that produced it**,
   with raw output committed under `/results`. A claim without a linked,
   re-runnable script is not allowed to ship.
3. **Baselines are steel-manned.** The container-restart baseline uses a
   warm image cache and a realistic minimal image (the actual coding-agent
   workspace content — a real repo checkout, installed deps — not a
   `hello-world`/`busybox` image). Comparing fork against a deliberately
   weak baseline is a form of lying and is not acceptable here.
4. **Tests cover failure paths**, not just the happy path: fork under
   memory pressure, fork during active I/O, cleanup after crash mid-fork.
5. **Security tests are adversarial and assume root inside the sandbox.**
   Don't write a test that assumes the attacker is polite. Failures get
   documented as known limitations in DESIGN.md's threat model — never
   hidden, never silently worked around.
6. **When something doesn't work, stop and say so.** Don't stub a
   component and move on as if it were done. Don't quietly narrow a claim
   to make a test pass without flagging that the claim changed.
7. **Only ever red-team this repo's own infrastructure.** Exploits written
   for the Phase 4 adversarial test suite target this project's sandbox
   only — never a target outside this repo.
8. **This project explicitly does not claim to have prevented the 2026
   OpenAI/Hugging Face incident.** That incident involved a shared,
   internally-reachable service (a package manager) that became a
   coordination and pivot channel. Do not let README/DESIGN language imply
   this design is immune to that class of incident — it is only immune to
   the extent the egress allowlist is configured correctly, which is
   itself called out as a residual risk in DESIGN.md.

## Architecture at a glance (see DESIGN.md for the real version)

- Host: Linux VM with root, a btrfs volume, network/mount/PID namespaces, cgroup v2.
- Copy-on-write: btrfs subvolume snapshots. overlayfs was rejected after Phase 0 findings (see DESIGN.md §3).
- Control plane: Python, with small C/Rust used only where a syscall
  genuinely isn't reachable cleanly from Python.
- Fork MVP = clone the environment (btrfs snapshot of the parent subvolume + new namespaces + new cgroup) and start a fresh process tree inside it. This is distinct
  from CRIU-based live process memory fork, which is a stretch goal — keep
  this distinction explicit everywhere in docs and code comments.
- Containment primitives (namespaces, cgroups, btrfs snapshots, egress filtering) are built directly from Linux primitives (`unshare`, `mount`,
  cgroup v2 fs, `nft`) rather than wrapped from an existing sandbox
  toolkit (bubblewrap, runc) — that's where this project's technical
  depth comes from.
- Egress filtering is enforced from a namespace the sandboxed root cannot
  enter (host side of a veth pair) — never from inside the sandbox's own
  netns, where sandboxed root could just flush the rules.

## Working style for this repo

- The user (Brahmjot) is a 3rd-year Computer Engineering/CS student,
  strong in Python/PyTorch and ML deployment, shallow on Linux-internals
  depth. Explain kernel/namespace/cgroup concepts as they come up rather
  than assuming familiarity — that's part of the point of the project.
- This is a portfolio project targeting SWE/infra internships at AI labs.
  Code and docs should be technically credible to a skeptical staff
  engineer — precise about what is and isn't proven, explicit about
  limitations, no hand-waving.
- Implementation proceeds one phase at a time (see PLAN.md). Before each
  phase, name the 2-3 decisions most likely to be wrong and the fallback
  for each. After each phase, run the benchmarks/tests and show raw
  output plus the exact command used.
