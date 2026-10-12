# DESIGN.md

Status: Phases 1–3 are implemented (lifecycle, fork, containment controls). Phase 4 (adversarial testing) has not started. Later sections
are still the spec that implementation (see [PLAN.md](PLAN.md)) is held to.
Where implementation has resolved an open question, the text says so and
links the code and test.

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
                               │ namespaces, btrfs snap, cgroup, veth
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
      ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
      │  Sandbox A     │ │  Sandbox B     │ │  Sandbox C     │  siblings —
      │ (forked from   │ │ (forked from   │ │ (fresh from    │  no shared
      │  base image)   │ │  Sandbox A)    │ │  base image)   │  mutable
      │ own netns,     │ │ own netns,     │ │ own netns,     │  state
      │ mountns, pidns,│ │ mountns, ...   │ │ mountns, ...   │  between
      │ cgroup, own    │ │ cgroup, own    │ │ cgroup, own    │  any of
      │ subvolume      │ │ subvolume      │ │ subvolume      │  these
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

Each sandbox is: its own btrfs subvolume (a snapshot of the base image or of a parent sandbox) + a fresh set of Linux namespaces (mount, PID, UTS,
IPC, network, and a user namespace — §5.2) + a cgroup v2 leaf for resource
limits + a veth pair into the egress-proxy netns.

## 3. Copy-on-write mechanism: btrfs subvolume snapshots

**Decision: btrfs.** This supersedes an earlier overlayfs choice (see
"Why not overlayfs" below); the reversal is deliberate and the evidence
is cited, not hidden.

**Mechanics:**
- Backing store: a btrfs filesystem at a control-plane-owned path. A
  dedicated block device is preferred; a loopback file on the VM is the
  fallback, and BENCHMARKS.md §3 explains why that distinction must be
  recorded with every result.
- Base image = a btrfs subvolume.
- `create_environment(base)` = writable snapshot of the base subvolume.
  No file data is copied; extents are shared until written.
- `fork(sandbox)` = freeze the parent's cgroup, snapshot the parent's
  subvolume, thaw. The parent keeps writing to its own subvolume; the
  child gets its own. Neither is a layer under the other, so there is no
  shared mutable layer — this is the property overlayfs could not give us.
  The freeze window is part of fork's cost and is reported separately.
  Whether the snapshot contains every write the parent completed before
  the freeze (including data still in the page cache) is required
  behavior that Phase 2's "fork during active I/O" test must verify; it
  is not assumed here.
- Each sandbox's rootfs is its own subvolume, mounted into its own mount
  namespace. A sandbox never gets a path to the btrfs top level or to
  another sandbox's subvolume.
- `destroy` = subvolume delete. Space reclamation is asynchronous in the
  kernel, so cleanup tests must poll rather than assume immediacy.

| | overlayfs | btrfs | ZFS |
|---|---|---|---|
| Fork a *live* parent safely | No — see below | Snapshot of the source subvolume; parent unaffected afterwards | Same, via `zfs snapshot`/`clone` |
| Stacking depth limit | Yes, and it depends on path length (measured below) | No layer stack; each snapshot is an independent subvolume (deep-chain behavior still to be tested in Phase 2) | None |
| Setup cost | None | Needs a btrfs volume (dedicated device or loopback) and `btrfs-progs` | Out-of-tree kernel module + zpool |

**Why not overlayfs.** Two findings, both from Phase 0:

1. *Forking a live parent is unsafe.* The natural overlayfs fork stacks
   the parent's `upperdir` under the child as a lower layer while the
   parent keeps writing to it. The kernel's overlayfs documentation says
   behavior is undefined if an underlying layer is modified while the
   overlay is mounted. Observed on the WSL2 dev host (**not** the target
   VM): the parent's post-fork writes were visible in the child
   ([raw output](results/phase0-host-check/wsl-dev-NOT-TARGET/20260924T063306Z-Brahmjotslaptop.json),
   check `overlay_parent_write_after_fork`, produced by
   [scripts/host_check.py](scripts/host_check.py)). That observation is
   not a guarantee either way, which is the point: the design cannot rest
   on it. Avoiding the problem means moving the parent onto a new upper
   layer, which cannot be done underneath running processes.
2. *The stacking limit is not a fixed 500.* On the same WSL2 host,
   legacy `mount(2)` accepted 500 stacked lowerdirs with short relative
   paths but only 121 with absolute paths, because all layer paths must
   fit in one mount-option string (same JSON, check `overlay_max_layers`).
   To be re-measured on the target VM.

**Why not ZFS:** unchanged from the earlier analysis — it needs an
out-of-tree kernel module and a zpool, which is setup and operational
surface this budget can't absorb for no semantic gain over btrfs here.

**Costs and risks of btrfs, stated plainly:**
- *Substrate must be recorded and, where possible, matched.* Forking on a
  btrfs loopback file while the Docker baseline runs on the VM's root
  filesystem would compare two different storage stacks. See
  BENCHMARKS.md §3.
- *Snapshot latency under write load is unmeasured.* Creating a snapshot
  is not free of coordination with in-flight writes; fork is therefore
  benchmarked while the parent is actively writing, not only when idle.
- *Larger kernel attack surface.* btrfs adds filesystem-specific ioctls
  that a root process in a sandbox could try to call. Mitigations planned
  for Phase 3: no path to the top-level volume, and a seccomp filter
  denying btrfs ioctls. These are mitigations, not proofs, and are
  covered by Phase 4 adversarial tests and listed in §5.3.
- *Snapshots are crash-consistent, not application-consistent.* Freezing
  the cgroup narrows the window but does not make a database-in-progress
  consistent.
- *UID mapping.* Implemented in Phase 1 with **idmapped mounts**. The
  base image is stored on disk with its original ownership (uid 0..65535).
  Each sandbox's rootfs is an `open_tree` + `mount_setattr(MOUNT_ATTR_IDMAP)`
  clone of its subvolume, keyed to that sandbox's user namespace. So every
  sandbox gets its **own** 65536-wide host uid range, and fork needs no
  `chown`
  ([control_plane/zygote.py](control_plane/zygote.py), tested by
  `test_user_namespace_maps_root_to_private_host_range` and
  `test_idmapped_rootfs_stores_unshifted_ownership` in
  [tests/test_lifecycle.py](tests/test_lifecycle.py)). Consequence: files the
  sandbox makes owned by its root are stored on disk as real uid 0. The btrfs
  volume is therefore mounted `nosuid,nodev` on the host and lives under a
  0700 root-only directory, so a setuid-root file written by a sandbox can
  never be executed from the host side.
- *Disk space is not bounded by cgroup io limits.* Per-sandbox disk
  quotas would need btrfs qgroups, whose overhead is unmeasured; until
  then disk exhaustion is a documented gap (§5.3).

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
  boundary itself, not a replacement for it. Phase 1 resolution: each sandbox gets a private host range (idmapped rootfs, §3). The process calls `setgroups([])` and `setresuid/setresgid(0)` inside the namespace after the map is written. Without that, Phase 0 showed the creator reads as overflow uid 65534. The `setgroups([])` matters: without it, host root's supplementary gid 0 would ride along on every sandbox process (`test_no_host_supplementary_groups`).
- **cgroup v2** — CPU, memory, PID count, and disk I/O limits per sandbox,
  so a single sandbox (or a runaway fork fan-out) cannot starve the host
  or sibling sandboxes of resources. This is the mechanism that answers
  "can a sandbox at least be limited even where isolation is
  incomplete" (see §5.3).
- **No shared mutable state between siblings.** Each sandbox gets its own btrfs subvolume and its own netns; there is no shared writable
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
- **btrfs-specific attack surface.** Filesystem ioctls (e.g. subvolume and inode-lookup operations) are reachable from a root process in the sandbox unless filtered. Planned mitigations (no path to the top-level volume, seccomp denial of btrfs ioctls) are unproven until Phase 4 tests them; anything they miss is a known limitation.
- **Disk exhaustion.** cgroup limits do not bound disk space; without btrfs qgroups a sandbox can fill the shared volume.
- **Phase 3 status: checked for existence, not attacked.** The controls in §5.2 and §5.4 are implemented ([docs/phases/phase3.md](docs/phases/phase3.md)). [tests/test_containment.py](tests/test_containment.py) only verifies that each one is present and behaves as configured. No adversarial (Phase 4) testing has been done, so nothing in this section is yet a claim of resistance to a root-inside attacker.
- **seccomp is a deny-list** ([control_plane/seccomp.py](control_plane/seccomp.py)), weaker than an allow-list: any dangerous syscall missing from the list is reachable.
- **The egress proxy's outbound sockets live in the host network namespace.** A compromised proxy runs as `nobody` with no capabilities, but it can still reach whatever the host netns can (loopback services, the host's LAN). The proxy's destination checks are its only barrier there.
- **exec into a sandbox at its memory limit can have the command OOM-killed.** Until `execve`, the command process is a copy of the Python exec helper (about 10 MB RSS), charged to the sandbox's cgroup. The helper itself stays outside and always reports the result ([tests/test_fork.py](tests/test_fork.py) `test_fork_under_memory_pressure`).
- **`io.max` is plumbed but untested,** so disk I/O limits are not claimed.
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

The control plane runs as host root to set up namespaces, btrfs subvolumes, and cgroups on the sandboxes' behalf (regular unprivileged
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
fork(sandbox_id: str) -> sandbox_id            # environment fork, see §3-4
exec(sandbox_id: str, cmd: list[str]) -> {stdout, stderr, exit_code}
snapshot_info(sandbox_id: str) -> {subvolume_id, parent_id, created_at, ...}
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
