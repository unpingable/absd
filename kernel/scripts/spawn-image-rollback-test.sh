#!/bin/sh
# Local VM qualification for partial spawn_image frame exhaustion.
set -eu
qemu=${1:-qemu-system-x86_64}
cd "$(dirname "$0")/.."
work=build/spawn-image-rollback-test
mkdir -p "$work"
: > "$work/empty"
printf '%s\n' 'SPAWN IMAGE ROLLBACK OK refusals=19 controls=20' > "$work/expected"
make --no-print-directory external-build EXTERNAL_KERNEL_FEATURES=spawn-image-rollback-test \
    EXTERNAL_USER_ELF= EXTERNAL_INPUT="$work/empty" EXTERNAL_EXPECTED="$work/empty" >/dev/null
probe=$(find build/external/target -name image_rollback.elf -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2)
test -f "$probe"
make --no-print-directory external-test QEMU="$qemu" \
    EXTERNAL_KERNEL_FEATURES=spawn-image-rollback-test EXTERNAL_USER_ELF="$probe" \
    EXTERNAL_INPUT="$work/empty" EXTERNAL_EXPECTED="$work/expected" >/dev/null
log=build/external.serial.log
children=$(grep -c '^SPAWN OK pid=[0-9]* parent=[0-9]* program=image$' "$log")
if [ "$children" -ne 20 ]; then
    echo "spawn-image-rollback-test: $children image children, expected 20" >&2
    exit 1
fi
grep -qx 'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0' "$log"
if grep -q 'PANIC\|KERNEL FAULT' "$log"; then
    echo "spawn-image-rollback-test: kernel panic or fault in $log" >&2
    exit 1
fi
rm -f "$work/empty" "$work/expected"
rmdir "$work"
echo 'SPAWN IMAGE ROLLBACK TEST OK refusals=19 controls=20 frames=0 processes=0 cells=0 pipes=0'
