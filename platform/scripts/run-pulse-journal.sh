#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:-$(dirname "$root")/absd-kernel-std-run}
work=${ABSD_DURABLE_WORK:-$root/.durable-work}

# The Pulse runtime derives key material through `getrandom`; use the same
# pinned virtual CPU identity as the AG authority workload.
: "${ABSD_QEMU:=qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand}"

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
test "$(readelf -h "$root/pulse-journal-std.elf" | awk '$1 == "Type:" { print $2 }')" = EXEC
test -z "$(nm -u "$root/pulse-journal-std.elf")"
rm -rf "$work"
python3 "$root/scripts/durable-matrix.py" \
    --kernel "$kernel" --elf "$root/pulse-journal-std.elf" \
    --work "$work" --qemu "$ABSD_QEMU" ${ABSD_DURABLE_ARGS:-}
rm -rf "$work"
printf '%s\n' 'ABSD RUST STD PULSE JOURNAL OK'
