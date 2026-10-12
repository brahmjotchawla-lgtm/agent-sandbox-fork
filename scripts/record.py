#!/usr/bin/env python3
"""Run a command and commit-ready record its raw output plus provenance.

    sudo python3 scripts/record.py results/phase1-tests/<host-label> -- python3 -m pytest -v tests/

Writes <dir>/<UTC timestamp>.txt: a provenance header (exact command, git
commit + dirty flag, kernel, distro, CPU, RAM, virtualisation, WSL flag),
then the command's combined stdout/stderr, then its exit code. Nothing is
summarised or filtered.
"""
import datetime as dt
import os
import platform
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sh(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, cwd=REPO).stdout.strip()
    except FileNotFoundError:
        return "n/a"


def provenance() -> list[str]:
    cpu = "n/a"
    try:
        with open("/proc/cpuinfo") as f:
            cpu = next(l.split(":", 1)[1].strip() for l in f if l.startswith("model name"))
    except (OSError, StopIteration):
        pass
    mem = "n/a"
    try:
        with open("/proc/meminfo") as f:
            mem = f.readline().split(":", 1)[1].strip()
    except OSError:
        pass
    distro = "n/a"
    try:
        with open("/etc/os-release") as f:
            distro = next(l.split("=", 1)[1].strip().strip('"') for l in f if l.startswith("PRETTY_NAME="))
    except (OSError, StopIteration):
        pass
    return [
        f"kernel: {platform.release()}",
        f"distro: {distro}",
        f"cpu: {cpu} x{os.cpu_count()}",
        f"mem_total: {mem}",
        f"virt: {sh('systemd-detect-virt') or 'n/a'}",
        f"wsl: {'microsoft' in platform.release().lower()}",
        f"python: {platform.python_version()}",
        f"git_commit: {sh('git', 'rev-parse', 'HEAD')}",
        f"git_dirty: {bool(sh('git', 'status', '--porcelain'))}",
    ]


def main():
    if "--" not in sys.argv:
        sys.exit(__doc__)
    i = sys.argv.index("--")
    out_dir, cmd = sys.argv[1], sys.argv[i + 1 :]
    os.makedirs(out_dir, exist_ok=True)
    started = dt.datetime.now(dt.timezone.utc)
    p = subprocess.run(cmd, cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    finished = dt.datetime.now(dt.timezone.utc)
    path = os.path.join(out_dir, started.strftime("%Y%m%dT%H%M%SZ") + ".txt")
    with open(path, "w") as f:
        f.write(f"command: {' '.join(cmd)}\ncwd: {REPO}\nstarted_utc: {started.isoformat()}\nfinished_utc: {finished.isoformat()}\n")
        f.write("\n".join(provenance()) + "\n")
        f.write("-" * 72 + "\n")
        f.write(p.stdout)
        f.write("-" * 72 + f"\nexit_code: {p.returncode}\n")
    sys.stdout.write(p.stdout)
    print(f"\nrecorded -> {path}")
    sys.exit(p.returncode)


if __name__ == "__main__":
    main()
