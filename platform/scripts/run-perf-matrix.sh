#!/bin/sh
# Program start and file-server transfer times (scripts/perf-matrix.py) on
# a `net fsd` boot, against perf/baseline.json. Needs a kernel with the fsd
# boot mode in ABSD_KERNEL_RUN. Builds the platform and the ports unless
# ABSD_SKIP_BUILD=1. ABSD_PERF_RECORD=<file> also writes this run's figures.
# ABSD_PERF_ACCEL=kvm runs the guest under KVM (-accel kvm -cpu host), as
# ABSD_CONTAIN_ACCEL does for the contain matrix; the default is TCG. The
# baseline (perf/baseline.json) and its --min-factor gate were recorded
# under TCG, so a KVM run compares against TCG figures: use it with
# ABSD_PERF_RECORD to measure, not as the gate. The baseline is TCG-only.
#
# The selection (scripts/perf-accel.sh, self-test scripts/test-perf-accel.sh)
# refuses before any work: an unknown value, an accelerator named in
# ABSD_QEMU, or kvm without a KVM that answers KVM_GET_API_VERSION.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
work=$root/.perf-work
. "$root/scripts/perf-accel.sh"

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
# POSIX sh has no pipefail: the matrix's own status travels through a file,
# so a failed run is a failure even when tee succeeds (and with
# ABSD_PERF_RECORD, where no OK line is grepped, it is the only signal).
{ status=0
  python3 "$root/scripts/perf-matrix.py" --work "$work" "$@" --kernel "$kernel" --shell "$root/commands/absd-sh" \
      --qemu "$qemu" || status=$?
  echo "$status" > "$work.status"; } | tee "$work.log"
status=$(cat "$work.status")
if [ "$status" != 0 ]; then
    echo "run-perf-matrix: perf-matrix.py exited $status (log $work.log)" >&2
    exit "$status"
fi
if [ -z "${ABSD_PERF_RECORD:-}" ]; then
    grep -q '^FSD THROUGHPUT OK before=' "$work.log" || { echo "run-perf-matrix: no FSD THROUGHPUT OK" >&2; exit 1; }
    grep -q '^COMMAND START OK native=' "$work.log" || { echo "run-perf-matrix: no COMMAND START OK" >&2; exit 1; }
fi
rm -rf "${work:?}" "${work:?}.log" "${work:?}.status"
printf '%s\n' "ABSD RUST PERF OK accel=$accel"
