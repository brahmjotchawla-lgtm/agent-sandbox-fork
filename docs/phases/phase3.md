# Phase 3 — containment

**Process note:** CLAUDE.md asks for this risk list *before* a phase
starts. For Phase 3 it was written after the code. The decisions below
are the ones already made, recorded honestly as made.

## What was built

- **Network** ([control_plane/network.py](../../control_plane/network.py)).
  Each sandbox gets a veth pair: `eth0` in its own netns (a /30 route only,
  no default route) and `sbx<slot>` in a control-plane-owned egress netns.
  nftables in the egress netns does three things:
  - Input is dropped, except TCP to the proxy port from the sandbox's own
    `(interface, source IP)` pair.
  - Forward is dropped.
  - Nothing is originated except established/related traffic.

  The egress netns also has `ip_forward=0`, IPv6 disabled, and no uplink.
- **Proxy** ([control_plane/proxy.py](../../control_plane/proxy.py)).
  - It is CONNECT-only, and each sandbox has its own allowlist.
  - It listens in the egress netns and makes outbound connections from
    the host netns. So the host does no forwarding and no NAT.
  - It refuses any name that resolves to a non-global address, and it
    connects to the address it vetted rather than resolving again.
  - It runs as uid 65534 with no capabilities and NO_NEW_PRIVS. It is
    configured only over an inherited socketpair.
- **seccomp** ([control_plane/seccomp.py](../../control_plane/seccomp.py)):
  a classic-BPF deny-list, applied to sandbox PID 1 and to every exec'd
  command.
- **cgroup limits**: memory, swap, pids, cpu. `io.max` is plumbed through
  (`Config.io_limits`, keyed by the btrfs backing device). It is **not**
  yet tested.

## Decisions most likely to be wrong, and the fallback for each

1. **Proxy outbound sockets live in the host netns.** A compromised proxy
   is then a process in the host network namespace. It runs as `nobody`
   with no capabilities, but that is still host-netns reachability:
   loopback services, the host's LAN. Fallback: give the egress netns an
   uplink veth with a NAT rule restricted to the proxy's address. The
   proxy then never shares the host netns, at the cost of host forwarding
   and NAT rules that can interact with Docker's own firewall rules.
2. **seccomp is a deny-list.** Anything not listed is allowed, so a
   syscall that is dangerous from inside a user namespace but missing from
   the list is open. Fallback: an allow-list derived from the workload by
   tracing it, at the cost of breaking unusual agent tooling.
3. **Allowlist by host name.** The proxy vets resolved addresses, but an
   allowlisted host name that is itself a shared, writable service is a
   channel between sandboxes. This is the 2026 incident's shape, and
   DESIGN.md §5.3 already lists it as residual risk. No architectural
   fallback exists. It is policy.

## Verification done (narrow, by agreement)

[tests/test_containment.py](../../tests/test_containment.py) checks that
each control **exists and behaves as configured**:
- no default route
- the allowlisted destination works through the proxy
- non-allowlisted destinations get 403, and non-CONNECT requests get 405
- an allowlisted name that resolves to loopback is refused
- no direct connections to a public IP, the gateway or a sibling
- the proxy runs unprivileged
- the egress ruleset is unchanged by sandbox activity
- the listed syscalls return EPERM, and clone3 returns ENOSYS
- the Flask test suite still runs under seccomp
- memory, pids and cpu limits are enforced
- siblings have separate namespaces and /dev/shm

These are **not adversarial tests.** A pass here says the configuration is
in place, not that it resists a determined root-inside attacker. That is
Phase 4, and it has not been done.

Raw output: [results/phase3-tests/wsl-dev-NOT-TARGET/](../../results/phase3-tests/wsl-dev-NOT-TARGET/).
