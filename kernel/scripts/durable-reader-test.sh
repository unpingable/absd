#!/bin/sh
# Durable composition: the reader init starts after the worker holds only a
# read-only duplicate of the block handle (the kernel refuses its write and
# flush), and init refuses to start it while anything the worker started is
# still alive.
set -eu
qemu=${1:-qemu-system-x86_64}
cd "$(dirname "$0")/.."
work=build/durable-reader-test
rm -rf "$work"
mkdir -p "$work"
: > "$work/empty"
printf reader > "$work/reader-input"
make --no-print-directory external-build EXTERNAL_USER_ELF= >/dev/null
probe=$(find build/external/target -name durable_probe.elf -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2)
test -f "$probe"

boot() {
    step=$1
    make --no-print-directory durable-iso DURABLE_STEP=$step EXTERNAL_USER_ELF="$probe" \
        EXTERNAL_INPUT="$work/empty" EXTERNAL_READER_ELF="$probe" EXTERNAL_READER_INPUT="$work/reader-input" >/dev/null
    truncate -s 2M "$work/$step.img"
    scripts/durable-boot.sh "build/durable/absd-durable-$step.iso" "$work/$step.img" "$work/$step.log" 120 $qemu
}

status=$(boot 1)
test "$status" -eq 3
printf 'DURABLE PROBE WORKER step=1 machine=stop-only\nDURABLE PROBE READER write=refused flush=refused\n' > "$work/expected-1"
python3 scripts/check-external-output.py "$work/1.log" "$work/expected-1"
grep -q 'DURABLE READER START pid=[0-9]* rights=read' "$work/1.log"
grep -q 'DURABLE READER OUTCOME pid=[0-9]* status=0' "$work/1.log"

status=$(boot 2)
test "$status" -eq 7
grep -q 'durable worker left a live descendant' "$work/2.log"
if grep -q 'DURABLE READER START' "$work/2.log"; then echo 'durable-reader-test: reader started beside a live descendant' >&2; exit 1; fi

rm -rf "$work"
echo 'durable-reader-test: reader authority is read-only; a live descendant stops init'
