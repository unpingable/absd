#!/bin/sh
# Real Nightshift on ABSD against its Linux twin: the frozen Linux fixture,
# the resolver with read-only authority, hostile stores, the native writer,
# and crashes inside the writer. The Linux reference binaries are built
# from the pinned Nightshift commit, unpatched, outside this repository.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone}
. "$root/scripts/inputs.sh"
nightshift=$(absd_source NIGHTSHIFT)
commit=e2675dd854dbfe633bf14456595d722e88bf92bc
tree=bd7afe042251fc4f007413871589a01d26e0583f
linux=$(dirname "$root")/absd-std-nightshift-linux
work=${ABSD_NIGHTSHIFT_WORK:-$root/.nightshift-work}
: "${ABSD_QEMU:=qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand}"

absd_not_kernel_source "$kernel"
test -f "$root/fixture-import.elf" && test -f "$root/nightshift-resolver.elf" && test -f "$root/nightshift-writer.elf"
rm -rf "$linux" "$work"
mkdir -p "$linux"
absd_stage_input Nightshift "$nightshift" "$commit" "$tree" "$linux"
(cd "$linux" && env -u RUSTFLAGS cargo build --release --locked --offline -p nightshiftd \
    --bin nightshift --bin nightshift-observation-resolver)
python3 "$root/scripts/nightshift-matrix.py" --kernel "$kernel" \
    --importer "$root/fixture-import.elf" --resolver "$root/nightshift-resolver.elf" \
    --writer "$root/nightshift-writer.elf" \
    --linux-resolver "$linux/target/release/nightshift-observation-resolver" \
    --linux-writer "$linux/target/release/nightshift" \
    --fixture "$root/fixtures/nightshift" --posture-request "$root/fixtures/nightshift/posture-request.json" \
    --work "$work" --qemu "$ABSD_QEMU"
rm -rf "$work" "$linux"
printf '%s\n' 'ABSD RUST NIGHTSHIFT OK'
