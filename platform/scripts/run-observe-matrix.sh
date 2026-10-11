#!/bin/sh
# ABSD as an observed host: the ABSD-owned frame-pressure support family
# (observe/, patches/pulse-absd-frame-pressure.patch) end to end on ABSD,
# checked on the host by an independent verifier and the host reference.
# Needs two disposable kernel clones: ABSD_KERNEL_RUN with `frame_stats`
# (syscall 35) and ABSD_KERNEL_OLD_RUN without it (the unavailable case).
# ABSD_OBSERVE_SKIP_UNAVAILABLE=1 runs without the second and skips exactly
# that case, printing ABSD SOURCE UNAVAILABLE SKIPPED: for a kernel source
# with no history (a snapshot), from which no earlier kernel can be made.
# Requires scripts/build-pulse-observe.sh and fixture-import.elf.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone with frame_stats}
if [ "${ABSD_OBSERVE_SKIP_UNAVAILABLE:-0}" = 1 ]; then
    old_kernel=
else
    old_kernel=${ABSD_KERNEL_OLD_RUN:?set ABSD_KERNEL_OLD_RUN to a disposable kernel clone without frame_stats}
fi
stage=$(dirname "$root")/absd-std-staged-pulse-observe
work=${ABSD_OBSERVE_WORK:-$root/.observe-work}
: "${ABSD_QEMU:=qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand}"

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
if [ -n "$old_kernel" ]; then absd_not_kernel_source "$old_kernel"; fi
grep -q 'pub const SYS_FRAME_STATS: u64 = 35;' "$kernel/abi/src/syscall.rs" || \
    { echo "run-observe-matrix: $kernel has no frame_stats" >&2; exit 1; }
if [ -n "$old_kernel" ]; then
    ! grep -q 'SYS_FRAME_STATS' "$old_kernel/abi/src/syscall.rs" || \
        { echo "run-observe-matrix: $old_kernel has frame_stats" >&2; exit 1; }
fi
for elf in fixture-import.elf pulse-frame-pressure-cycle.elf pulse-frame-pressure-resolver.elf \
    pulse-frame-pressure-resolver-test.elf; do
    test -f "$root/$elf"
done
test -f "$stage/crates/pulse-absd-frame-pressure/src/platform.rs"
rm -rf "${work:?}"
mkdir -p "$work"
# The family library's own tests, and its Linux build (roles by argv[0]).
(cd "$stage" && env -u RUSTFLAGS cargo test --offline --locked --target x86_64-unknown-linux-gnu \
    --target-dir "$work/host" -p pulse-absd-frame-pressure 2>&1) | grep -E '^test result' | tee "$work/host-tests.txt"
grep -q 'test result: ok. [1-9]' "$work/host-tests.txt"
# (`! grep` would not stop `set -e`.)
if grep -q 'FAILED' "$work/host-tests.txt"; then exit 1; fi
(cd "$stage" && env -u RUSTFLAGS cargo build --offline --locked --release --target x86_64-unknown-linux-gnu \
    --target-dir "$work/host" -p pulse-absd-frame-pressure --bin pulse-absd-frame-pressure)
(cd "$root/tools/pulse-frame-pressure-reference" && env -u RUSTFLAGS cargo build --release --locked --offline \
    --target x86_64-unknown-linux-gnu --target-dir "$work/reference-target")
python3 "$root/scripts/observe-matrix.py" --root "$root" --kernel "$kernel" \
    ${old_kernel:+--old-kernel "$old_kernel"} \
    --importer "$root/fixture-import.elf" --cycle "$root/pulse-frame-pressure-cycle.elf" \
    --resolver "$root/pulse-frame-pressure-resolver-test.elf" \
    --deployment-resolver "$root/pulse-frame-pressure-resolver.elf" \
    --reference "$work/reference-target/x86_64-unknown-linux-gnu/release/pulse-frame-pressure-reference" \
    --linux "$work/host/x86_64-unknown-linux-gnu/release/pulse-absd-frame-pressure" \
    --work "$work" --qemu "$ABSD_QEMU" --results "${ABSD_OBSERVE_RESULTS:-$work/results.json}" \
    --present-memory "${ABSD_OBSERVE_PRESENT_MEMORY:-32M}" \
    --present-ballast "${ABSD_OBSERVE_PRESENT_BALLAST:-6000}"
rm -rf "${work:?}"
printf '%s\n' 'ABSD RUST OBSERVE OK'
