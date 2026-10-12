# Provenance note for this run (written by hand, after the run)

- **Code version:** the run started from commit `219fe2d` with a clean tree.
  `meta.json` shows `git_commit: ""` and `git_dirty: False` because
  `scripts/record.py`'s git calls failed. They ran as root on a
  Windows-mounted checkout ("dubious ownership"). So the `git_dirty`
  value in `meta.json` is **not** evidence of a clean tree. This note is
  the record, and `record.py` is fixed in the same commit as this file.
- While the run was in progress, uncommitted Phase 3 edits were made to
  `control_plane/`. The benchmark's control-plane daemon and zygote had
  already imported their modules at start-up, so they ran `219fe2d` code.
  That claim rests on Python's import behaviour, not on a hash taken at
  the end. Re-run on the target VM before relying on any of these numbers.
- Host: WSL2 dev laptop, **NOT the target VM**. btrfs is a loopback file
  on the same virtual disk as Docker's data-root (overlayfs snapshotter).
