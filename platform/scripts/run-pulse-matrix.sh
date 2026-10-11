#!/bin/sh
# Real Pulse `pulse-support-resolver` on ABSD against its Linux twin (the
# pinned, unpatched binary) and the host reference (the same patched
# library with an injected clock). Also runs the patched crate's own tests
# on Linux: Unix behavior is unchanged. Requires scripts/build-pulse.sh
# (which stages ../absd-std-staged-pulse) and fixture-import.elf.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone}
. "$root/scripts/inputs.sh"
pulse=$(absd_source PULSE)
commit=81c2354674990679f43be4f207349ff1b2429bc7
tree=b3f746c4e16b5303d0fd7bf98b327bfa14382951
stage=$(dirname "$root")/absd-std-staged-pulse
linux=$(dirname "$root")/absd-std-pulse-linux
work=${ABSD_PULSE_WORK:-$root/.pulse-work}
: "${ABSD_QEMU:=qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand}"

absd_not_kernel_source "$kernel"
# The resolver's clock is the kernel's boot identity: refuse a kernel without it.
grep -q 'pub const SYS_BOOT_ID: u64 = 29;' "$kernel/abi/src/syscall.rs" || \
    { echo "run-pulse-matrix: $kernel has no SYS_BOOT_ID" >&2; exit 1; }
test -f "$root/fixture-import.elf" && test -f "$root/pulse-support-resolver.elf" && \
    test -f "$root/pulse-support-resolver-test.elf"
test -f "$stage/crates/pulse-nq-load-support/src/platform.rs"
rm -rf "${linux:?}" "${work:?}"
mkdir -p "$linux" "$work"
absd_stage_input Pulse "$pulse" "$commit" "$tree" "$linux"
(cd "$linux" && env -u RUSTFLAGS cargo build --release --locked --offline \
    -p pulse-nq-load-support --bin pulse-nq-load-support)
# The patched crate on Linux: its unit and process-boundary tests.
(cd "$stage" && env -u RUSTFLAGS cargo test --offline --target x86_64-unknown-linux-gnu \
    --target-dir "$work/host-test" -p pulse-nq-load-support > "$work/host-test.log" 2>&1) || \
    { tail -n 40 "$work/host-test.log" >&2; exit 1; }
grep -E '^test result' "$work/host-test.log" | tee "$work/host-tests.txt"
test "$(grep -c 'test result: ok' "$work/host-tests.txt")" -ge 2
if grep -q 'FAILED' "$work/host-tests.txt"; then echo 'run-pulse-matrix: host tests failed' >&2; exit 1; fi
(cd "$root/tools/pulse-support-reference" && env -u RUSTFLAGS cargo build --release --locked --offline \
    --target x86_64-unknown-linux-gnu --target-dir "$work/reference-target")
python3 "$root/scripts/pulse-matrix.py" --kernel "$kernel" \
    --importer "$root/fixture-import.elf" --resolver "$root/pulse-support-resolver-test.elf" \
    --deployment-resolver "$root/pulse-support-resolver.elf" \
    --linux "$linux/target/release/pulse-nq-load-support" \
    --reference "$work/reference-target/x86_64-unknown-linux-gnu/release/pulse-support-reference" \
    --fixture "$root/fixtures/pulse" --work "$work" --qemu "$ABSD_QEMU" \
    --results "${ABSD_PULSE_RESULTS:-$work/results.json}"
rm -rf "${work:?}" "${linux:?}"
printf '%s\n' 'ABSD RUST PULSE SUPPORT OK'
