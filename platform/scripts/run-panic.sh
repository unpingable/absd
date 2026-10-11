#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:-$(dirname "$root")/absd-kernel-std-run}
log=$kernel/build/external.serial.log

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
test -f "$root/panic-std.elf"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
status=0
make -C "$kernel" external-test \
    EXTERNAL_USER_ELF="$root/panic-std.elf" \
    EXTERNAL_INPUT="$root/input.txt" \
    EXTERNAL_EXPECTED="$root/expected.txt" || status=$?
test "$status" -ne 0
grep -Eq '^USER EXIT pid=[0-9]+ status=101$' "$log"
grep -qx 'EXTERNAL status=99 frames=0 processes=0 cells=0 pipes=0' "$log"
grep -qx 'EXTERNAL WORKLOAD FAILED' "$log"
printf '%s\n' 'ABSD RUST STD PANIC OK'
