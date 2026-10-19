#!/bin/sh
# Vertical A link cases (scripts/link-matrix.py); arguments pass through
# (`--only CASE`). Host rules while U1 runs: nice 10, one QEMU of this lane,
# 1-minute load <= 10. ABSD_KERNEL_RUN is a disposable kernel copy.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
lane=$(dirname "$root")
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel copy}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=$root/.link-work
# Kernel and platform inputs only, as run-core-fsd-recovery.sh: never stage integration workloads.
ABSD_PROFILE=core
export ABSD_PROFILE
. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
load=$(cut -d' ' -f1 /proc/loadavg)
if awk -v l="$load" 'BEGIN { exit !(l > 10) }'; then
    echo "run-link-matrix: 1-minute load $load exceeds 10; not starting QEMU" >&2; exit 1
fi
if ps -eo args= | awk -v lane="$lane" '$1 ~ /qemu-system/ && index($0, lane) { f = 1 } END { exit !f }'; then
    echo "run-link-matrix: a QEMU of this lane is already running" >&2; exit 1
fi
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then "$root/scripts/prepare-and-build.sh"; fi
for file in sshd.elf absd-fsd.elf sshtest.elf fsd-probe.elf fixture-import.elf commands/absd-sh commands/cat; do
    test -f "$root/$file"
done
rm -rf "${work:?}"; mkdir -p "$work"
nice -n 10 python3 "$root/scripts/link-matrix.py" --work "$work" --kernel "$kernel" \
    --shell "$root/commands/absd-sh" --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand" "$@"
rm -rf "${work:?}"
printf '%s\n' 'ABSD RUST LINK OK'
