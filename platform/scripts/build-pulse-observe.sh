#!/bin/sh
# Builds the ABSD-owned frame-pressure support family (crate
# pulse-absd-frame-pressure: Pulse 81c2354's pulse-nq-load-support, the
# ABSD platform patch, and the family patch) for ABSD, in its own staged
# workspace with its own pinned lock. The role is chosen by the image name
# (`ABSD_PROGRAM_NAME`), as argv[0] chooses it on Linux:
#
#   pulse-frame-pressure-cycle.elf          absd-frame-pressure-cycle: the
#       durable worker's producer then receiver (command on stdin).
#   pulse-frame-pressure-resolver.elf       pulse-support-resolver, the
#       deployment build: configuration path only from
#       PULSE_FRAME_PRESSURE_SUPPORT_CONFIG in a brokered environment.
#   pulse-frame-pressure-resolver-test.elf  TEST ONLY (--cfg
#       pulse_absd_test_config): the path /observe/support-config.json is
#       fixed into the image; the environment is never read.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
stage=$(dirname "$root")/absd-std-staged-pulse-observe
test -d "$sysroot/lib/rustlib/src/rust/library"
"$root/scripts/stage-pulse-observe.sh"

build() {
elf=$1 target_dir=$2 name=$3 cfg=$4
(cd "$stage" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
ABSD_REAL_RUSTC=$toolchain/bin/rustc \
ABSD_STAGED_SYSROOT=$sysroot \
RUSTC=$root/scripts/rustc-staged.sh \
RUSTC_BOOTSTRAP=1 \
RUST_TARGET_PATH=$root/targets \
CARGO_TARGET_DIR=$stage/$target_dir \
CARGO_TARGET_X86_64_UNKNOWN_ABSD_RUSTFLAGS="-C link-arg=-T$root/user-linker.ld -C link-arg=--gc-sections --check-cfg cfg(pulse_absd_test_config) $cfg" \
CARGO_PROFILE_RELEASE_PANIC=abort \
ABSD_PROGRAM_NAME=$name \
PULSE_ABSD_TEST_CONFIG=/observe/support-config.json \
cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort \
    --target x86_64-unknown-absd --release --offline ${ABSD_CARGO_LOCKED---locked} \
    -p pulse-absd-frame-pressure --bin pulse-absd-frame-pressure
cp "$stage/$target_dir/x86_64-unknown-absd/release/pulse-absd-frame-pressure" "$root/$elf"
printf '%s\n' "ABSD PULSE FRAME PRESSURE $elf BUILT $(sha256sum "$root/$elf" | cut -d' ' -f1)"
)
}

build pulse-frame-pressure-cycle.elf target-cycle absd-frame-pressure-cycle ""
build pulse-frame-pressure-resolver.elf target pulse-support-resolver ""
build pulse-frame-pressure-resolver-test.elf target-test pulse-support-resolver "--cfg pulse_absd_test_config"
