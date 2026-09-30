#!/bin/sh
# Prepare a target host (Ubuntu 24.04, x86_64) for the control plane and the
# benchmark. DESTRUCTIVE: wipes DEVICE.
#
#   sudo scripts/setup_host.sh /dev/nvme1n1 --wipe
#
# DEVICE is split into two partitions on the same physical disk
# (BENCHMARKS.md §3.6):
#   part 1: btrfs, mounted nosuid,nodev at /var/lib/agent-sandbox (sandbox store)
#   part 2: ext4, mounted at /var/lib/docker (Docker's default overlay2 driver,
#           i.e. the configuration people actually run: steel-manned baseline)
set -eu
DEV=${1:?usage: setup_host.sh DEVICE --wipe}
[ "${2:-}" = "--wipe" ] || { echo "refusing: pass --wipe to confirm $DEV will be erased" >&2; exit 2; }
[ "$(uname -m)" = x86_64 ] || { echo "x86_64 only" >&2; exit 2; }

apt-get update -q
apt-get install -y -q btrfs-progs iproute2 nftables util-linux parted docker.io python3 python3-pytest

systemctl stop docker docker.socket 2>/dev/null || true
parted -s "$DEV" mklabel gpt mkpart store btrfs 0% 50% mkpart docker ext4 50% 100%
udevadm settle
P1=$(lsblk -lnpo NAME "$DEV" | sed -n 2p)
P2=$(lsblk -lnpo NAME "$DEV" | sed -n 3p)
mkfs.btrfs -f -q "$P1"
mkfs.ext4 -F -q "$P2"
mkdir -p /var/lib/agent-sandbox /var/lib/docker
echo "UUID=$(blkid -s UUID -o value "$P1") /var/lib/agent-sandbox btrfs nosuid,nodev,noatime 0 0" >> /etc/fstab
echo "UUID=$(blkid -s UUID -o value "$P2") /var/lib/docker ext4 defaults,noatime 0 0" >> /etc/fstab
mount /var/lib/agent-sandbox
mount /var/lib/docker
systemctl start docker

# cgroup v2 is the default on Ubuntu 22.04+; fail loudly if not.
[ -f /sys/fs/cgroup/cgroup.controllers ] || { echo "cgroup v2 not mounted at /sys/fs/cgroup" >&2; exit 1; }
echo "done. next: sudo python3 scripts/host_check.py --workdir /var/lib/agent-sandbox"
