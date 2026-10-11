#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

# QEMU's default virtual CPU has no accepted entropy source. The `getrandom`
# RDRAND backend also rejects QEMU's old-family AMD identity by design, so pin
# an Intel vendor identity and expose the emulated RDRAND instruction.
: "${ABSD_QEMU:=qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand}"
export ABSD_QEMU

if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi

"$root/scripts/run-external.sh" \
    "$root/ag-authority.elf" \
    "$root/ag-authority-input.txt" \
    "$root/ag-authority-expected.txt" \
    "NEXT REAL CONSTELLATION WORKLOAD OK"
