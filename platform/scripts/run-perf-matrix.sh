#!/bin/sh
# Program start and file-server transfer times (scripts/perf-matrix.py) on
# a `net fsd` boot, against perf/baseline.json. Needs a kernel with the fsd
# boot mode in ABSD_KERNEL_RUN. Builds the platform and the ports unless
# ABSD_SKIP_BUILD=1. ABSD_PERF_RECORD=<file> also writes this run's figures.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=$root/.perf-work

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
    "$root/scripts/build-ports.sh"
fi
for file in sshd.elf absd-fsd.elf sshtest.elf fsd-probe.elf fixture-import.elf commands/absd-sh; do
    test -f "$root/$file"
done
rm -rf "${work:?}"
mkdir -p "$work"
set -- --baseline "$root/perf/baseline.json" --min-factor "${ABSD_PERF_MIN_FACTOR:-5}"
if [ -n "${ABSD_PERF_RECORD:-}" ]; then
    set -- --record "$ABSD_PERF_RECORD"
fi
python3 "$root/scripts/perf-matrix.py" --work "$work" "$@" --kernel "$kernel" --shell "$root/commands/absd-sh" \
    --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand" | tee "$work.log"
if [ -z "${ABSD_PERF_RECORD:-}" ]; then
    grep -q '^FSD THROUGHPUT OK before=' "$work.log" || { echo "run-perf-matrix: no FSD THROUGHPUT OK" >&2; exit 1; }
    grep -q '^COMMAND START OK native=' "$work.log" || { echo "run-perf-matrix: no COMMAND START OK" >&2; exit 1; }
fi
rm -rf "${work:?}" "${work:?}.log"
printf '%s\n' 'ABSD RUST PERF OK'
