#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:-$(dirname "$root")/absd-kernel-std-run}
work=${ABSD_FS_WORK:-$root/.fs-work}

# SQLite randomness, filesystem identities, and AG lifecycle nonces use
# RDRAND; pin the same virtual CPU identity as the other durable workloads.
: "${ABSD_QEMU:=qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand}"

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
test "$(readelf -h "$root/ag-sqlite.elf" | awk '$1 == "Type:" { print $2 }')" = EXEC
test -z "$(nm -u "$root/ag-sqlite.elf")"
rm -rf "$work"
python3 "$root/scripts/fs-matrix.py" \
    --kernel "$kernel" --elf "$root/ag-sqlite.elf" \
    --work "$work" --qemu "$ABSD_QEMU" ${ABSD_FS_ARGS:-}
rm -rf "$work"
printf '%s\n' 'ABSD RUST FS AG SQLITE OK'
