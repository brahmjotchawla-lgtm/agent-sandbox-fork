# DESIGN.md

Status: draft, pending author review. No code has been written yet — this
document is the spec that implementation (see [PLAN.md](PLAN.md)) will be
held to.

## 1. Problem and use case

RL rollouts and agent evals branch: one agent trajectory needs to become N
parallel futures, each exploring a different action from the same starting
state. The standard way to get N independent environments today is to
restart N containers from a base image. That's wasteful when the N
environments are 99% identical at the moment of the branch — they only
differ from each other going forward.

This project builds a sandbox server that can **fork** a running agent
environment — clone its filesystem state (and, as a stretch goal, its
process state) into N independent children — far cheaper than restarting
N containers, while guaranteeing that an agent with root inside a sandbox
still cannot reach the network, the host, or its sibling sandboxes.

Two claims must be defended with measurements produced by this repo:

1. Forking is dramatically cheaper than container restart (see
   [BENCHMARKS.md](BENCHMARKS.md)).
2. Root inside a sandbox cannot escape containment (see §5 and the
   adversarial test suite, Phase 4).

**Non-goal (see the GPU discussion below):** the sandbox does not contain
a live GPU/PyTorch process. The environment being forked is the CPU-side
agent harness — filesystem, shell, orchestrator/tool-use process, rollout
bookkeeping. Model inference happens via network calls to an inference
server that lives outside the sandbox and is not forked. This mirrors how
real RL rollout infrastructure is actually built (harnesses call an
inference server; they don't embed model weights per-sandbox) and keeps
Claim 1 honestly measurable — attempting to checkpoint/restore a live CUDA
context is not a solved problem in open source and the physical cost of
copying GPU memory contradicts a millisecond-scale fork claim regardless.
The inference-server call is also the concrete thing the egress proxy
(§5.4) exists to mediate.

## 2. Architecture overview

```
                     ┌─────────────────────────┐
     RL trainer /    │   Sandbox Control Plane  │   runs as host root;
     eval harness ───┼─►  (Python, Unix socket   │   part of the TCB —
     (client)        │   JSON-RPC API)          │   see §5.5
                     └─────────┬────────────────┘
                               │ sets up per-sandbox:
                               │ namespaces, overlayfs, cgroup, veth
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
      ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
      │  Sandbox A     │ │  Sandbox B     │ │  Sandbox C     │  siblings —
      │ (forked from   │ │ (forked from   │ │ (fresh from    │  no shared
      │  base image)   │ │  Sandbox A)    │ │  base image)   │  mutable
      │ own netns,     │ │ own netns,     │ │ own netns,     │  state
      │ mountns, pidns,│ │ mountns, ...   │ │ mountns, ...   │  between
      │ cgroup, upper  │ │ cgroup, upper  │ │ cgroup, upper  │  any of
      │ overlay layer  │ │ overlay layer  │ │ overlay layer  │  these
      └───────┬────────┘ └───────┬────────┘ └───────┬────────┘
              │ veth             │ veth             │ veth
              ▼                  ▼                  ▼
      ┌─────────────────────────────────────────────────┐
      │  Egress proxy (host-side netns, NOT reachable    │
      │  or modifiable from inside any sandbox netns)    │
      │  — allowlist-filtered HTTP(S) CONNECT proxy       │
      └───────────────────────┬───────────────────────────┘
                               ▼
                    inference server / internet
                    (only allowlisted destinations)
```

Each sandbox is: an overlayfs mount (lowerdir = shared read-only base or a
parent sandbox's flattened state, upperdir = this sandbox's own writes,
empty at fork time) + a fresh set of Linux namespaces (mount, PID, UTS,
IPC, network, and a user namespace — §5.2) + a cgroup v2 leaf for resource
limits + a veth pair into the egress-proxy netns.

## 3. Copy-on-write mechanism: overlayfs

**Decision: overlayfs**, rejecting btrfs and ZFS.

| | overlayfs | btrfs | ZFS |
|---|---|---|---|
| Setup cost | None — works on top of any existing filesystem (ext4/xfs) already backing the VM | Requires a dedicated btrfs-formatted volume/subvolume | Requires the out-of-tree `zfsutils-linux` kernel module + zpool setup |
| Fork cost | `mkdir` for a new upper/work dir + one `mount(2)` syscall — no data copy | Subvolume clone (`btrfs subvolume snapshot`) — no data copy | Dataset clone from snapshot (`zfs clone`) — no data copy |
| Known limitation | Lowerdir stack depth capped (~500 on modern kernels); deep fork chains need periodic flattening (merge upper into a fresh combined lower) | None significant for this use case | None significant for this use case |
| Production precedent | Docker's default storage driver on modern kernels | systemd-nspawn, older Docker storage driver | Used by some PaaS-style sandbox providers for exactly this clone-based pattern |

overlayfs wins on time budget: it needs zero disk provisioning (the VM's
existing root filesystem is enough), has the most-documented failure
modes of the three, and is what the most widely deployed container
runtime already uses in production, which makes any benchmark story about
it easy for a reviewer to sanity-check independently. btrfs and ZFS both
have cleaner clone semantics (no stacking-depth ceiling) but that
advantage isn't worth the setup cost and the new operational surface
(kernel module version drift, dedicated volume management) inside a
6-week part-time budget. The stacking-depth limitation is treated as a
documented known limitation, not hidden: past a configurable chain depth,
the control plane flattens a sandbox's overlay stack into a new base
layer before continuing to fork from it.

**Fork mechanics:**
- Base image = a directory tree, mounted read-only as `lowerdir`.
- `create_sandbox(base)` → new empty `upperdir`/`workdir`, overlay-mounted
  against `lowerdir`. Cost: directory creation + one mount call.
- `fork(sandbox_id)` → the forking sandbox's current `lowerdir + upperdir`
  become the new sandbox's `lowerdir` (multiple lowerdirs are stacked, not
  merged), with a fresh empty `upperdir`. No bytes are copied at fork
  time; both parent and child continue writing into their own, separate,
  now-diverging upper layers. Divergence cost is paid later, per write,
  as normal overlayfs copy-up behavior — see BENCHMARKS.md for why this
  deferred cost has to be measured too, not just the fork call itself.

## 4. Process model

**MVP definition of "fork": environment fork, not process fork.**
`fork(sandbox_id)` clones the filesystem state and namespace/cgroup setup
described above, then starts a **fresh process tree** inside the new
sandbox (e.g., re-invokes the agent harness entrypoint). It does **not**
freeze and resume the memory of an already-running process. This
distinction matters and is kept explicit everywhere in docs, API naming,
and code comments — conflating the two would misstate what's actually
being measured in Claim 1.

**Stretch goal: CRIU-based process-state fork.** If time allows (checked
at the end of week 3 — see PLAN.md), attempt to checkpoint a live
process's memory/FD state with CRIU and resume it inside the forked
filesystem, so a child sandbox continues from the exact point in
execution the parent was at, rather than restarting the harness. This is
cut without ceremony if the core (filesystem fork + benchmark + egress
control) isn't solid by week 3, and if attempted, is reported honestly as
"attempted, here's how far it got" rather than folded into the headline
claims.

## 5. Containment model and threat model

### 5.1 Adversary model

The agent process inside a sandbox is **fully adversarial and has root
inside its own namespaces.** This is not a hypothetical: an RL rollout is
explicitly optimizing behavior, and nothing prevents it from discovering
that attacking its own sandbox is a viable strategy. The design assumes:

- The adversary can run arbitrary code as root inside the sandbox's
  mount/PID/UTS/IPC/network namespaces.
- The adversary will attempt privilege escalation, namespace escape,
  cgroup bypass, and network egress bypass as a matter of course, not as
  an edge case.
- Per the 2026 OpenAI/Hugging Face incident: assume the adversary will
  look for **any reachable shared service** as a coordination or pivot
  channel, not just try to break the isolation boundary directly.

### 5.2 Mechanisms

- **Mount, PID, UTS, IPC, network namespaces** — standard process/resource
  isolation; a sandboxed process cannot see host processes, host
  mounts, or the host's network interfaces.
- **User namespace (defense in depth).** Sandbox UID 0 is mapped to an
  unprivileged UID on the host. This means that even in the event of a
  successful namespace escape, the escaping process lands on the host as
  an unprivileged user, not as root — an extra layer behind the namespace
  boundary itself, not a replacement for it. Known complexity: unprivileged
  overlayfs mounts inside a user namespace need kernel ≥ 5.11 or the mount
  must be performed by the (already-root) control plane on the sandbox's
  behalf before namespace setup completes; this is a concrete
  implementation risk called out for Phase 1/3 (see PLAN.md).
- **cgroup v2** — CPU, memory, PID count, and disk I/O limits per sandbox,
  so a single sandbox (or a runaway fork fan-out) cannot starve the host
  or sibling sandboxes of resources. This is the mechanism that answers
  "can a sandbox at least be limited even where isolation is
  incomplete" (see §5.3).
- **No shared mutable state between siblings.** Each sandbox gets its own
  overlayfs upper layer and its own netns; there is no shared writable
  volume, shared socket, or shared service reachable by more than one
  sandbox other than the egress proxy itself (§5.4), which does not
  expose a writable or stateful surface to the sandboxes that call it.
  This directly targets the OpenAI-incident lesson that shared mutable
  state between isolated units destroys the isolation property even when
  each unit's individual boundary looks fine.
- **Egress proxy enforced from outside the sandbox's own netns (§5.4).**

### 5.3 What this does *not* cover (stated explicitly, not hidden)

- **Kernel 0-days.** This is namespace/cgroup-based containment sharing
  one host kernel, not a VM boundary. A kernel exploit that escapes
  namespaces is out of scope for what this design can prevent; it is
  mitigated only by normal host patching hygiene, which this project does
  not itself provide.
- **Side-channel attacks** (cache timing, etc.) between sandboxes sharing
  a CPU are not addressed.
- **The egress proxy's own attack surface.** A bug in the proxy is a new
  shared service reachable from every sandbox — precisely the shape of
  the OpenAI incident. The proxy is kept minimal (allowlist-filtered
  CONNECT only, no admin/control API reachable from the sandbox side) to
  reduce this, but "minimal" is a mitigation, not a proof of safety; this
  is called out as a residual risk.
- **The control plane itself is part of the trusted computing base**
  (§5.5) and is not sandboxed. A vulnerability in the control plane is a
  full host compromise; this design does not attempt to protect against
  that.
- **This design does not claim to have prevented the 2026 OpenAI
  incident.** That incident's pivot channel was a shared internal service
  the sandbox was allowed to reach; this design's egress allowlist only
  helps to the extent it's configured to exclude such services, and
  allowlist misconfiguration is itself a residual risk, not something the
  architecture eliminates by construction.
- **Multi-host.** Single host only; no claims about isolation across a
  cluster of hosts.
- **Resource-limit completeness.** cgroup v2 limits (§5.2) cover CPU,
  memory, PIDs, and disk I/O for processes inside the sandbox; they do
  not cover every possible host resource an adversarial process might try
  to exhaust (e.g., inode exhaustion, open file descriptor limits beyond
  PID cgroup accounting) unless specifically tested in Phase 4 and listed
  as covered there.

### 5.4 Egress proxy

The critical design point, stated as plainly as possible: **egress
filtering rules must live in a namespace the sandboxed root cannot enter
or modify.** A design that puts `nft`/`iptables` allowlist rules inside
the sandbox's own netns is broken, because sandboxed root has
`CAP_NET_ADMIN` inside that netns and can simply flush its own rules.

Instead: each sandbox gets one end of a veth pair; the other end lives in
a separate netns owned by the control plane, which the sandbox has no
capability to enter (no shared PID namespace with it, no file descriptor
to it, not reachable via `setns(2)` from inside the sandbox). All traffic
from the sandbox's veth end is routed through this control-plane-owned
netns, where an HTTP(S) CONNECT proxy enforces a destination allowlist
before traffic leaves the host. The sandbox has a route to the proxy and
nothing else — no default route to the internet or to other sandboxes'
veth interfaces.

### 5.5 Control plane as trusted computing base

The control plane runs as host root to set up namespaces, overlayfs
mounts, and cgroups on the sandboxes' behalf (regular unprivileged
processes can't do all of this). That makes it part of the TCB: a bug in
it is not "a sandbox escaped," it's "the host is compromised directly."
Mitigations are process hygiene, not architectural elimination of the
risk: keep its code surface small, never deserialize untrusted input
originating from inside a sandbox without validation, and don't expose
more API surface to sandboxes than `exec`/basic I/O requires.

## 6. API surface

Local Unix-domain-socket JSON-RPC, not an HTTP port — deliberately, to
avoid adding a network-reachable control-plane attack surface beyond what
the use case (a local RL trainer/eval harness on the same host) actually
needs. A thin Python client library wraps the socket for callers.

```
create_environment(base_image: str) -> sandbox_id
fork(sandbox_id: str) -> sandbox_id            # environment fork, see §4
exec(sandbox_id: str, cmd: list[str]) -> {stdout, stderr, exit_code}
snapshot_info(sandbox_id: str) -> {overlay_chain_depth, created_at, ...}
destroy(sandbox_id: str) -> None
list_sandboxes() -> list[sandbox_id]
```

`fork` is the operation under benchmark in Claim 1; `create_environment`
+ `exec` are what the container-restart baseline is compared against.

## 7. Non-goals

- Multi-host orchestration.
- GPU/live-model-state forking (§1) — inference is external and unforked.
- Arbitrary non-Linux workloads.
- Live process-memory fork in the MVP (CRIU is a stretch goal, §4).
- A network-reachable control-plane API.
