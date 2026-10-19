#!/bin/sh
# Representative guest file-server interruption/recovery cases. This is a
# core verdict; run-fs-matrix.sh remains the extended AG SQLite verdict.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
work=${ABSD_CORE_FSD_WORK:-$root/.core-fsd-recovery-work}
qemu=${ABSD_QEMU:-qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand}

# This fixture has only kernel/platform inputs even in a full development
# checkout. A standalone invocation must not stage integration workloads.
ABSD_PROFILE=core
export ABSD_PROFILE
. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
for file in sshd.elf absd-fsd.elf fsd-probe.elf sshtest.elf fixture-import.elf \
    commands/absd-sh; do
    test -f "$root/$file"
done
python3 "$root/scripts/core-fsd-recovery.py" --work "$work" --kernel "$kernel" \
    --platform "$root" --shell "$root/commands/absd-sh" --qemu "$qemu"
