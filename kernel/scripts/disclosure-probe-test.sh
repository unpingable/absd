#!/bin/sh
# Syscall information-disclosure probe (docs/SYSCALL-DISCLOSURE.md): output
# records are written whole and nothing past them, refusals write and consume
# nothing, stale handles never reach a successor object, a child starts with
# clean registers, and fault records carry only user-chosen values.
set -eu
qemu=${1:-qemu-system-x86_64}
cd "$(dirname "$0")/.."
work=build/disclosure-probe-test
rm -rf "$work"
mkdir -p "$work"
: > "$work/empty"
make --no-print-directory external-build EXTERNAL_USER_ELF= \
    EXTERNAL_INPUT="$work/empty" EXTERNAL_EXPECTED="$work/empty" >/dev/null
probe=$(find build/external/target -name disclosure_probe.elf -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2)
test -f "$probe"
cp scripts/disclosure-probe.expected "$work/expected"
make --no-print-directory external-test QEMU="$qemu" EXTERNAL_USER_ELF="$probe" \
    EXTERNAL_INPUT="$work/empty" EXTERNAL_EXPECTED="$work/expected" >/dev/null
log=build/external.serial.log
grep -qx 'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0' "$log"
if grep -q 'PANIC\|KERNEL FAULT' "$log"; then
    echo "disclosure-probe-test: kernel panic or fault in $log" >&2
    exit 1
fi
checks=$(grep -c '^DISCLOSE [a-z-]* ok ' "$work/expected")
rm -rf "$work"
echo "DISCLOSURE PROBE TEST OK checks=$checks frames=0 processes=0 cells=0 pipes=0"
