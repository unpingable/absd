#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    printf '%s\n' 'usage: run-external.sh ELF INPUT EXPECTED MARKER' >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:-$(dirname "$root")/absd-kernel-std-run}
elf=$1
input=$2
expected=$3
marker=$4
qemu=${ABSD_QEMU:-qemu-system-x86_64}

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
test -f "$elf"
test -f "$input"
test -f "$expected"
make -C "$kernel" external-test \
    QEMU="$qemu" \
    EXTERNAL_USER_ELF="$elf" \
    EXTERNAL_INPUT="$input" \
    EXTERNAL_EXPECTED="$expected"
printf '%s\n' "$marker"
