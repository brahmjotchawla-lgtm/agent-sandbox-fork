# Provenance note (written by hand, after the fact)

These four records show an empty `git_commit` and `git_dirty: False`.
Both are artifacts of a bug: `scripts/record.py` ran git as root on a
Windows-mounted checkout, git refused ("dubious ownership"), and its
empty output was read as "clean". From the git log, the runs map to
code as follows:

- `20261012T152939Z` (1 fixture error): commit `3b6e4a5`
- the three later runs: commit `22467f8` (stale-socket fixture fix)

That mapping comes from commit order and timestamps, not from a recorded
hash. `record.py` is fixed in the commit that adds this note.
