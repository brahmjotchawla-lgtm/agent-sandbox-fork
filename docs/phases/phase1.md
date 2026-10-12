# Phase 1 kickoff — single-sandbox lifecycle

Goal (PLAN.md): create one sandbox from a base image (btrfs snapshot +
namespaces + cgroup, no network yet), `exec` inside it, `destroy` it with
verified cleanup, including crash-mid-operation tests.

## Concrete design choices for this phase

- **Process tree.** The control plane never `fork()`s itself (it is
  multi-threaded). It starts one single-threaded helper, the *zygote*,
  at boot. The zygote forks one short-lived child per `create`/`exec`.
  This keeps Python interpreter start-up out of the fork/create critical
  path. The zygote is a child subreaper, so sandbox init processes
  re-parent to it, not to host PID 1.
- **Launch sequence** (`control_plane/launch.py`), all from Linux
  primitives:
  1. launcher `unshare(CLONE_NEWNS)`: a private, throwaway mount namespace.
  2. fork C1 → `unshare(CLONE_NEWUSER)`. The launcher writes C1's
     `uid_map`/`gid_map` (sandbox 0..65535 → a per-sandbox host range) and
     moves C1 into the sandbox cgroup.
  3. The launcher builds an **idmapped mount** of the sandbox subvolume
     (`open_tree` + `mount_setattr(MOUNT_ATTR_IDMAP)` + `move_mount`)
     using C1's user namespace. It attaches it inside its private
     mount namespace only.
  4. C1 `setresuid(0)` inside the userns, then
     `unshare(NEWNS|NEWUTS|NEWIPC|NEWNET|NEWPID|NEWCGROUP)`, forks C2 =
     PID 1 of the sandbox.
  5. C2 does `pivot_root(".", ".")` and detaches the old root. Only
     **after** that does it mount `/proc`, `/dev` (tmpfs + bind-mounted
     host device nodes via pre-opened detached mounts) and `/dev/pts`.
     So every in-rootfs path resolves inside the sandbox root, and a
     symlink planted in the rootfs cannot redirect a mount to a host path.
  6. C2 `execve`s a tiny static C init (`control_plane/init.c`) from a
     **memfd**. `/proc/1/exe` inside the sandbox then points at an
     anonymous file, not a host binary (this is the CVE-2019-5736 class).
- **exec** = a zygote child joins the sandbox cgroup, sets itself
  non-dumpable (so sandboxed root cannot ptrace it while it still holds
  host-side state), and `setns()`s into all of init's namespaces via a
  pidfd held since creation (no PID-reuse race). It then forks the
  command so it lands inside the sandbox PID namespace.
- **Cleanup source of truth** is the cgroup (`cgroup.kill`) plus the
  state file. It is not PIDs. `reconcile()` at start-up removes anything
  half-built.

## The decisions most likely to be wrong, and the fallback for each

1. **Idmapped mounts on btrfs inside a fresh userns.** This gives every
   sandbox its own host UID range with zero per-fork `chown`. It needs
   kernel ≥ 5.15, `FS_ALLOW_IDMAP` on btrfs, and `open_tree`/
   `mount_setattr` working from a privileged launcher. If it fails on the
   target kernel, the fallback is to shift ownership of the base image
   once at import and give **all** sandboxes one shared host UID range.
   That is a weaker defense-in-depth property, because an escapee from
   one sandbox would own sibling rootfs files on the host. It would be
   documented in DESIGN.md §5.3 if used.
2. **mounting `/proc` from inside the userns.** The kernel refuses a new
   procfs mount if the host's `/proc` has over-mounts that would be
   "revealed" (`mount_too_revealing`). Fallback: bind-mount the host's
   `/proc` (the pidns-correct view requires a fresh mount, so that
   fallback would leak host PIDs). The real fallback is therefore to
   clean up the host's `/proc` over-mounts, and to record this as a host
   requirement.
3. **Python as launcher/exec-helper language.** The window between
   `setns()` and `execve()` runs Python inside the sandbox's namespaces.
   It mitigates this with `PR_SET_DUMPABLE=0` and by closing every
   non-stdio fd first. If Phase 4 shows that window is attackable (e.g.
   via `/proc/<pid>/` of the helper), the fallback is to move the
   setns-and-exec step into the small C helper, which shrinks the window
   to a few syscalls.

## Exit criteria

- `tests/test_lifecycle.py` passes as root: create → exec → destroy, with
  a check for leftover cgroups, subvolumes, mounts in **any** process's
  mountinfo, and processes.
- `tests/test_failure_paths.py`: launcher killed mid-create, sandbox init
  killed while running, control plane killed mid-create, then
  `reconcile()`. Each one is followed by the same leftover check.
