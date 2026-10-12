# Sandbox server for AI agents (working title)

A sandbox server for AI agents that forks a running agent environment into
N parallel copies, with containment enforced from outside the sandbox.

**Status: Phases 1–3 of [PLAN.md](PLAN.md) are implemented** (lifecycle,
environment fork, containment controls). Everything has run only on a WSL2
dev host, **not** the target VM. Containment has been checked for
existence, not attacked: Phase 4 has not started. So this README makes no
security claim. The first fork-vs-Docker measurements, including the
results that go against the claim, are in [BENCHMARKS.md §4a](BENCHMARKS.md).

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
