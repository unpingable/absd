#!/bin/sh
# AG's real `ag-loopctl` natively on ABSD, standalone (scripts/ag-native-matrix.py):
# init and record-proposal as durable workers against the Linux reference's
# Nightshift store, the observation resolver brokered by init, the wall
# clock from the kernel's RTC, and a Linux twin at the native instants.
# Needs a kernel with the broker and the wall-clock syscall in
# ABSD_KERNEL_RUN, and the Linux reference programs: ABSD_REFERENCE_LINUX
# is the directory whose bin/ holds the Linux ag-loopctl and
# nightshift-observation-resolver that produced fixtures/ag-native (its
# manifest pins them; scripts/make-reference-fixture.sh).
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=$root/.ag-native-work

. "$root/scripts/inputs.sh"
linux=$ABSD_REFERENCE_LINUX
test -x "$linux/bin/ag-loopctl" || {
    echo "the Linux reference programs are absent: set ABSD_REFERENCE_LINUX (looked in $linux/bin)" >&2
    exit 1
}
absd_not_kernel_source "$kernel"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
rm -rf "${work:?}"
python3 "$root/scripts/ag-native-matrix.py" --kernel "$kernel" \
    --importer "$root/fixture-import.elf" --init "$root/ag-loopctl-init.elf" \
    --record "$root/ag-loopctl-record-proposal.elf" --resolver "$root/nightshift-ag-resolver.elf" \
    --resolver-short-ttl "$root/nightshift-ag-resolver-short-ttl.elf" \
    --fixture "$root/fixtures/ag-native" --linux-fixture "$linux" \
    --shim-source "$root/tools/ag-linux-twin/twin-shim.c" \
    --work "$work" --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand -rtc base=utc -m 512"
if [ "${ABSD_KEEP_WORK:-0}" != 1 ]; then
    rm -rf "${work:?}"
fi
printf '%s\n' 'ABSD RUST AG NATIVE OK'
