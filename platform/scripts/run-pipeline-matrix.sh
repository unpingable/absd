#!/bin/sh
# The real Nightshift observation pipeline with brokered owner processes
# (scripts/pipeline-matrix.py): the writer, `nq`, and `pulse-support-resolver`
# natively, the read-only resolver after, all against the Linux reference in
# fixtures/nightshift-pipeline. Needs a broker kernel in ABSD_KERNEL_RUN.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=$root/.pipeline-work

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
rm -rf "${work:?}"
python3 "$root/scripts/pipeline-matrix.py" --kernel "$kernel" \
    --importer "$root/fixture-import.elf" --writer "$root/nightshift-pipeline-writer.elf" \
    --resolver "$root/nightshift-resolver.elf" --nq "$root/nq.elf" \
    --pulse "$root/pulse-support-resolver.elf" --fixture "$root/fixtures/nightshift-pipeline" \
    --work "$work" --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand"
rm -rf "${work:?}"
printf '%s\n' 'ABSD RUST NIGHTSHIFT PIPELINE OK'
