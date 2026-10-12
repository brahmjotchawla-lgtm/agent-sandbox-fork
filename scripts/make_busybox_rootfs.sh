#!/bin/sh
# Build a tiny busybox rootfs tarball for the lifecycle and failure-path tests.
# This image is for TESTS ONLY. It is never used for benchmarks: the Claim 1
# workload is bench/workload/ (BENCHMARKS.md §2).
#
#   sudo scripts/make_busybox_rootfs.sh /var/tmp/busybox-rootfs.tar
set -eu
out=${1:?usage: $0 OUT.tar}
bb=$(command -v busybox)
file -L "$bb" 2>/dev/null | grep -q 'statically linked' || { echo "need a statically linked busybox (apt install busybox-static)" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/proc" "$tmp/dev" "$tmp/sys" "$tmp/tmp" "$tmp/root" "$tmp/etc" "$tmp/work"
chmod 1777 "$tmp/tmp"
cp "$bb" "$tmp/bin/busybox"
for app in $("$bb" --list); do
  [ -e "$tmp/bin/$app" ] || ln -s busybox "$tmp/bin/$app"
done
echo 'root:x:0:0:root:/root:/bin/sh' > "$tmp/etc/passwd"
echo 'root:x:0:' > "$tmp/etc/group"
tar --numeric-owner -C "$tmp" -cf "$out" .
echo "$out"
