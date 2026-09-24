# Sandbox server for AI agents (working title)

A sandbox server for AI agents that forks a running agent environment into
N parallel copies, with containment enforced from outside the sandbox.

**Status: design phase. No code and no measurements exist yet.** This README
makes no performance or security claims. Per [CLAUDE.md](CLAUDE.md), any
claim added here must link to the script that produced it, with raw output
committed under [`results/`](results/).

## Docs

- [DESIGN.md](DESIGN.md) — architecture, copy-on-write choice, threat model
  (including what it does not cover), API surface
- [BENCHMARKS.md](BENCHMARKS.md) — what is measured, baselines, and how the
  harness avoids misleading numbers
- [PLAN.md](PLAN.md) — phased build plan
- [CLAUDE.md](CLAUDE.md) — ground rules for anyone (human or agent) working in
  this repo

## Layout

| Path | Purpose |
|---|---|
| `control_plane/` | Sandbox control plane (Python) |
| `bench/` | Benchmark harness and workload definitions |
| `results/` | Committed raw benchmark and test output |
| `tests/` | Unit, failure-path, and adversarial security tests |
| `scripts/` | Host setup and verification scripts |

## License

Apache-2.0. See [LICENSE](LICENSE).
