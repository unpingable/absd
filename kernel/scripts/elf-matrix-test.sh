#!/bin/sh
# Adversarial ELF matrix for spawn_image (syscall 31): the external workload
# builds every image from one template and mutates the named fields
# (user/src/bin/elf_matrix.rs). Each case must give its expected refusal or
# child outcome, leave the resource census unchanged, and be followed by a
# control image that starts with the next PID. The kernel's accounting line
# then proves nothing was left behind; docs/ADVERSARIAL-ELF.md lists the cases.
set -eu
qemu=${1:-qemu-system-x86_64}
cd "$(dirname "$0")/.."
work=build/elf-matrix-test
rm -rf "$work"
mkdir -p "$work"
: > "$work/empty"
make --no-print-directory external-build EXTERNAL_USER_ELF= \
    EXTERNAL_INPUT="$work/empty" EXTERNAL_EXPECTED="$work/empty" >/dev/null
probe=$(find build/external/target -name elf_matrix.elf -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2)
test -f "$probe"
cp scripts/elf-matrix.expected "$work/expected"
make --no-print-directory external-test QEMU="$qemu" EXTERNAL_USER_ELF="$probe" \
    EXTERNAL_INPUT="$work/empty" EXTERNAL_EXPECTED="$work/expected" >/dev/null
log=build/external.serial.log
# Every child the probe started was announced; no refusal was.
children=$(grep -c 'SPAWN OK pid=[0-9]* parent=[0-9]* program=image$' "$log")
# One per accepted case, one control per case, and the sentinel.
cases=$(grep -c '^ELF [a-z0-9-]* \(refused\|exit\|fault\)=' "$work/expected")
accepted=$(grep -c '^ELF [a-z0-9-]* \(exit\|fault\)=' "$work/expected")
expected_children=$((accepted + cases + 1))
if [ "$children" -ne "$expected_children" ]; then
    echo "elf-matrix-test: $children image children, expected $expected_children" >&2
    exit 1
fi
grep -qx 'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0' "$log"
if grep -q 'PANIC\|KERNEL FAULT' "$log"; then
    echo "elf-matrix-test: kernel panic or fault in $log" >&2
    exit 1
fi
rm -rf "$work"
echo "ELF MATRIX TEST OK cases=$cases children=$children frames=0 processes=0 cells=0 pipes=0"
