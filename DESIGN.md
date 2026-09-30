# DESIGN.md

Status: Phases 1–3 implemented (see [PLAN.md](PLAN.md) for status and
[README.md](README.md#what-has-been-verified-where) for what has been
verified on which host). Implementation-specific details are in §8.
Nothing here is a performance claim.

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
- *UID mapping.* Resolved with idmapped mounts (§8.1): the base image
  stays owned by uid 0..65535 on disk, and each sandbox's rootfs is an
  idmapped bind mount of its subvolume onto that sandbox's own host uid
  range. No chown happens at create or fork time. Idmapped mounts have been
  verified on ext4 (dev host). On btrfs (kernel ≥ 5.15) they have not been
  verified yet; that happens on the target host.
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
  unprivileged host uid, and **each sandbox gets a disjoint 65536-uid host
  range**. A process that escapes the namespace boundary therefore lands on
  the host as an unprivileged uid that also differs from every sibling's
  uid, so it can't signal or ptrace sibling processes. This sits behind the
  namespace boundary as an extra layer; it doesn't replace it. The Phase 0
  finding (the creator of a fresh user namespace reads as uid 65534 until
  it switches) is handled in `nsinit.py`: a helper still in the host
  namespace writes uid_map/gid_map, then the process calls setresuid(0).
- **seccomp + no_new_privs** on every sandbox process, installed before
  any sandbox code runs (§8.2).
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
- **Multi-host.** Single host only; no claims about isolation across a
  cluster of hosts.
- **Resource-limit completeness.** cgroup v2 limits (§5.2) cover CPU,
  memory, PIDs, and disk I/O for processes inside the sandbox; they do
  not cover every possible host resource an adversarial process might try
  to exhaust (e.g., inode exhaustion, open file descriptor limits beyond
  PID cgroup accounting) unless specifically tested in Phase 4 and listed
  as covered there.
- **Known gaps found during implementation** (not yet addressed):
  - `exec(timeout=...)` kills the command's process group. A command that
    calls `setsid()` escapes the timeout and keeps running *inside* the
    sandbox (still in its cgroup and namespaces) until `destroy`.
  - The proxy runs in the host netns as `nobody`. If it were compromised,
    the attacker could reach whatever `nobody` on the host network can,
    including host-local services, so its SSRF filtering is a mitigation
    and doesn't prove anything. Moving upstream traffic into a dedicated
    uplink netns with its own nft allowlist would bound this; that isn't
    implemented.
  - The egress rules are IPv4-only. IPv6 is disabled in the egress and
    sandbox netns when the kernel has IPv6 at all. Sandboxed root can
    re-enable it in its own netns, but the egress netns has no IPv6
    addresses and its `inet` input policy is drop.
  - `/sys` is not mounted in sandboxes, which some tools expect.
  - Per-sandbox proxy connection cap (64) is a crude bound, not fair
    scheduling; one sandbox can still consume proxy CPU.
  - The seccomp filter targets btrfs ioctls and non-x86_64 ABIs only. It
    is not a general syscall-surface reduction (no keyctl/bpf/userfaultfd
    denial, for example); the user namespace and dropped host capabilities
    are what bound those today.

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

As implemented (§8.3), the proxy's *listening socket* lives in the egress
netns. The proxy *process* makes its upstream connections from the host
netns after dropping to `nobody`. The egress netns itself has no path to
the host or the internet. The residual risk this leaves is listed in §5.3.

### 5.5 Control plane as trusted computing base

The control plane runs as host root to set up namespaces, btrfs subvolumes, and cgroups on the sandboxes' behalf (regular unprivileged
processes can't do all of this). That makes it part of the TCB: a bug in
it is not "a sandbox escaped," it's "the host is compromised directly."
Mitigations are process hygiene, not architectural elimination of the
risk: keep its code surface small, never deserialize untrusted input
originating from inside a sandbox without validation, and don't expose
more API surface to sandboxes than `exec`/basic I/O requires.

### 5.6 Adversarial coverage (Phase 4)

The adversary in every test is root inside the sandbox. The "Result"
column comes from the
[cloud-container run](results/phase4-adversarial/claude-cloud-container-NOT-TARGET/)
(NOT the target host: no btrfs, no cgroup v2). *Pass* means the attack
failed. *Known limitation* means the test pins the current, weaker
behaviour, so a fix or a regression shows up. *Not tested* means the
defence exists, or the gap is documented, but nothing here verifies it.

| Attack | Test | Result (non-target) |
|---|---|---|
| See or signal host processes | `test_adversarial::test_cannot_see_host_processes`, `test_kill_all_only_hits_sandbox` | pass |
| Climb out of the root (double chroot, `/proc/1/root`) | `test_chroot_breakout_stays_inside`, `test_proc_1_root_is_sandbox_root` | pass |
| Create or mount host block devices | `test_cannot_mknod_or_mount_host_devices` | pass |
| Load kernel modules | `test_cannot_load_kernel_modules` | pass (kernel has no module support: ENOSYS) |
| `reboot(2)` | `test_reboot_only_kills_own_sandbox` | pass (kills only its own sandbox) |
| Write host sysctls, sysrq | `test_host_sysctls_and_sysrq_not_writable` | pass |
| Map host uid 0 via a nested userns | `test_nested_userns_cannot_map_host_root` | pass |
| Reach the control socket | `test_control_socket_not_visible` | pass |
| Siblings share a host uid | `test_lifecycle::test_sandbox_root_is_unprivileged_on_host` | pass |
| btrfs ioctls (subvolume create/snapshot/lookup) | `test_seccomp::test_btrfs_ioctls_blocked` | pass at the filter level (EPERM); **not tested against a real btrfs mount** |
| Syscalls through non-x86_64 ABIs (32-bit, x32) | none | **not tested**: the filter kills them (§8.2), but no test here exercises that rule |
| No new privileges via setuid binaries | `test_no_new_privs_and_seccomp_on_every_process` | pass |
| Egress to the internet directly, or after re-routing and flushing own nft | `test_network::test_no_route_to_internet`, `test_root_cannot_route_around_egress_netns` | pass |
| Reach host services on any host address | `test_host_services_unreachable` | pass |
| Join or modify the egress netns | `test_root_cannot_modify_egress_rules` | pass |
| Reach or spoof a sibling on the network | `test_siblings_cannot_reach_each_other`, `test_source_spoofing_dropped` | pass |
| SSRF through the proxy (non-allowlisted, name resolving to private, proxy loop) | `test_non_allowlisted_denied`, `test_hostname_resolving_to_private_address_refused`, `test_adversarial_phase4::test_proxy_refuses_to_connect_to_itself` | pass |
| Proxy admin or other surface (GET, DELETE, OPTIONS, HTTP/2 preface) | `test_plain_http_forwarding_refused`, `test_proxy_has_no_admin_surface` | pass |
| Crash the proxy with malformed or oversized requests | `test_proxy_survives_malformed_and_oversized_requests` | pass |
| Starve siblings of the proxy (slowloris) | `test_one_sandbox_cannot_starve_siblings_of_the_proxy` | pass (per-peer cap; mutation-checked) |
| Abstract unix socket to host services | `test_host_abstract_unix_socket_unreachable` | pass |
| SysV IPC with a sibling | `test_sibling_ipc_isolated` | pass |
| Symlinks aimed at host paths, followed by host-root copy/delete | `test_symlinks_to_host_survive_fork_and_destroy` | pass (copy backend; the btrfs delete walk is **not tested**) |
| Hostile filenames or permissions breaking destroy | `test_hostile_filenames_do_not_break_destroy` | pass |
| Mounts leaking to forks or the host | `test_sandbox_mounts_do_not_reach_forks_or_host` | pass |
| Host fds or env leaking into exec | `test_exec_leaks_no_host_fds_or_env` | pass (mutation-checked) |
| Outlive an exec timeout via `setsid()` | `test_KNOWN_LIMITATION_setsid_escapes_exec_timeout` | **known limitation** (stays inside the sandbox; removed on destroy) |
| Memory, pids and fork-bomb exhaustion | `test_lifecycle::test_memory_limit_enforced`, `test_pids_limit_contains_fork_bomb` | **skipped**: no cgroup v2 on this host |
| Writing own cgroup limits (mount cgroup2 inside) | none | **not tested**: needs cgroup v2 |
| Disk exhaustion | none | **known limitation** (§5.3), deliberately not run: it would fill the host disk |
| Proxy compromise, then host-network access as `nobody` | none | **known limitation** (§5.3) |
| Kernel 0-days, side channels | none | out of scope (§5.3) |

## 6. API surface

Local Unix-domain-socket JSON-RPC, not an HTTP port — deliberately, to
avoid adding a network-reachable control-plane attack surface beyond what
the use case (a local RL trainer/eval harness on the same host) actually
needs. A thin Python client library wraps the socket for callers.

```
create_environment(base_image: str) -> {sandbox_id, timings_ms}
fork(sandbox_id: str) -> {sandbox_id, parent_id, timings_ms}   # environment fork, see §3-4
exec(sandbox_id: str, cmd: list[str], timeout?, stdin?, env?, cwd?)
    -> {stdout, stderr, exit_code, timed_out, duration_ms}   # output capped at 8 MiB/stream
snapshot_info(sandbox_id: str) -> {id, parent_id, image, subvolume{uuid, parent_uuid, ...}, cgroup, net, ...}
destroy(sandbox_id: str) -> None
list_sandboxes() -> [{id, image, parent_id, phase}]
import_image(name: str, docker_ref: str) -> {...}   # admin: docker export -> read-only base subvolume
list_images() -> [...]
```

`create_environment` and `fork` both return per-component timings
(`snapshot_ms`, `freeze_window_ms`, `cgroup_ms`, `rootfs_mount_ms`,
`namespaces_and_pivot_ms`, `network_ms`, `total_ms`). The benchmark reports
them separately (BENCHMARKS.md §1).

`fork` is the operation under benchmark in Claim 1; `create_environment`
+ `exec` are what the container-restart baseline is compared against.

## 7. Non-goals

- Multi-host orchestration.
- GPU/live-model-state forking (§1) — inference is external and unforked.
- Arbitrary non-Linux workloads.
- Live process-memory fork in the MVP (CRIU is a stretch goal, §4).
- A network-reachable control-plane API.

## 8. Implementation notes

### 8.1 Sandbox start sequence

The code is `control_plane/sandbox.py` (`Manager._start`) plus
`control_plane/nsinit.py`.

1. A state file is written *before* any resource is acquired, and updated
   as each one is added (crash recovery, §8.4).
2. A btrfs snapshot is taken of the image (create) or of the frozen parent
   (fork).
3. A cgroup v2 leaf is created with memory, swap, pids and cpu limits.
4. The subvolume gets an idmapped, `nosuid,nodev` bind mount at
   `run_dir/mnt/<id>`, mapping on-disk 0..65535 to this sandbox's host
   range.
5. `nsinit.py holder` starts as host root. It joins the cgroup, sets
   `no_new_privs` and seccomp, calls `unshare(CLONE_NEWUSER)`, and a helper
   still in the host user namespace writes the id maps. It then calls
   setresuid(0) and unshares mount, UTS, IPC, net, PID and cgroup
   namespaces, and forks. The child is PID 1. It re-binds the rootfs
   (the mount copied from the host namespace is locked), mounts `proc`, a
   minimal tmpfs `/dev` (null, zero, full, random, urandom, tty, a new
   devpts instance, shm), sets the hostname, calls
   `pivot_root(".", ".")` and detaches the old root, so no host path
   remains in the sandbox's mount namespace. It then reaps children.
6. The host's copy of the rootfs mount is detached. The sandbox keeps its
   own copy.
7. A veth pair is created with each end directly in its target namespace
   (`sbxh<slot>` in the egress netns, `eth0` in the sandbox). The sandbox
   gets only a /30 connected route, with no default route.

`exec` runs `nsinit.py enter`, which joins the cgroup and sets the same
seccomp filter, then execs `nsenter` into all the sandbox's namespaces
with the sandbox's root and working directory. Environment variables are
set explicitly; nothing is inherited from the control plane.

### 8.2 seccomp filter

Classic BPF, installed with `no_new_privs`. Syscalls from any non-x86_64
ABI (32-bit `int 0x80`, and x32) are killed outright, because a filter
keyed on x86_64 syscall numbers wouldn't see `ioctl` there. Any `ioctl`
whose request type byte is 0x94 (`BTRFS_IOCTL_MAGIC`) returns EPERM.

### 8.3 Egress

The egress netns has no uplink at all. Its nft ruleset (input: only new
TCP to the proxy port from `sbxh*`; forward: drop; output: established
only), `ip_forward=0` and strict `rp_filter` are set by the control plane.
The sandbox has no capability over that netns.

The proxy process opens its listening socket *inside* the egress netns,
switches back to the host netns, drops to `nobody`, and serves CONNECT
only. It makes upstream connections from the host network, but only to
allowlisted `host:port` entries. It resolves each name once and connects
by IP, and it refuses non-global addresses unless that exact IP is
allowlisted.

### 8.4 Crash recovery

`reconcile()` runs on every control-plane start. It tears down any
sandbox whose state isn't `ready` or whose PID 1 is gone (checked by pid
*and* process start time). It also removes any subvolume, cgroup, host
mount or egress veth that has no state file, and thaws adopted sandboxes,
since a crash during fork can leave the parent frozen. Holder processes
from before their pid was recorded are found by command line. Only one
control plane may own a `run_dir` (an flock), so a second instance can't
reconcile away a sandbox that is still being created.

### 8.5 dev_mode

`storage: "copy"` (full `cp -a --reflink=auto`) and running without
cgroup v2 are allowed only with `dev_mode: true`. dev_mode exists so the
lifecycle, network and containment code can be tested on hosts without
btrfs or cgroup v2. It is recorded in every sandbox's metadata. Without
cgroups, fork cannot freeze the parent and nothing is resource-limited.
The benchmark harness refuses to produce claim-grade output in this mode.
