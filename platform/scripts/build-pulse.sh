#!/bin/sh
# Builds Pulse's real `pulse-support-resolver` role (crate
# pulse-nq-load-support, pinned 81c2354 plus the carried platform patch)
# for ABSD, in its own staged workspace with its own pinned lock. The role
# is selected by argv[0] as on Linux; ABSD has no exec, so the image carries
# its name (`ABSD_PROGRAM_NAME`). Requires the staged sysroot
# (scripts/prepare-and-build.sh or scripts/stage-library.sh).
#
# Two images:
#   pulse-support-resolver.elf       the deployment build: its
#       configuration path comes only from the environment
#       (PULSE_LOAD_SUPPORT_CONFIG), which ABSD gives a program only through
#       a brokered startup record; without one it refuses, as Linux does.
#   pulse-support-resolver-test.elf  TEST ONLY (--cfg pulse_absd_test_config):
#       the configuration path is fixed into the image at build time
#       (PULSE_ABSD_TEST_CONFIG) and the environment is never read. It
#       exists for standalone qualification and is not a deployment.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
stage=$(dirname "$root")/absd-std-staged-pulse
test_config=/pulse/support-config.json
test -d "$sysroot/lib/rustlib/src/rust/library"
"$root/scripts/stage-pulse.sh"

build() {
elf=$1 target_dir=$2 cfg=$3
(cd "$stage" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
ABSD_REAL_RUSTC=$toolchain/bin/rustc \
ABSD_STAGED_SYSROOT=$sysroot \
RUSTC=$root/scripts/rustc-staged.sh \
RUSTC_BOOTSTRAP=1 \
RUST_TARGET_PATH=$root/targets \
CARGO_TARGET_DIR=$stage/$target_dir \
CARGO_TARGET_X86_64_UNKNOWN_ABSD_RUSTFLAGS="-C link-arg=-T$root/user-linker.ld -C link-arg=--gc-sections --check-cfg cfg(pulse_absd_test_config) $cfg" \
CARGO_PROFILE_RELEASE_PANIC=abort \
ABSD_PROGRAM_NAME=pulse-support-resolver \
PULSE_ABSD_TEST_CONFIG=$test_config \
cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort \
    --target x86_64-unknown-absd --release --offline ${ABSD_CARGO_LOCKED---locked} \
    -p pulse-nq-load-support --bin pulse-nq-load-support
cp "$stage/$target_dir/x86_64-unknown-absd/release/pulse-nq-load-support" "$root/$elf"
printf '%s\n' "ABSD PULSE $elf BUILT $(sha256sum "$root/$elf" | cut -d' ' -f1)"
)
}

build pulse-support-resolver.elf target ""
build pulse-support-resolver-test.elf target-test "--cfg pulse_absd_test_config"
