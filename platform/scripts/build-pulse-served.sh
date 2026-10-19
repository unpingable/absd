#!/bin/sh
# Build one ordinary native Pulse command over an existing FSD session.
# Uses the exact existing frame-pressure family and its locked dependencies.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
stage=$(dirname "$root")/absd-std-staged-pulse-observe
test -d "$sysroot/lib/rustlib/src/rust/library"
# Development-only reuse: the same already staged family and sysroot. The
# default always re-verifies/stages the pinned inputs; never reuse after either
# input changes. Cargo still rebuilds the copied command source below.
if [ "${ABSD_PULSE_SERVED_INCREMENTAL:-0}" = 1 ]; then
    test -f "$stage/crates/pulse-absd-frame-pressure/src/lib.rs"
    test -f "$stage/Cargo.lock"
else
    "$root/scripts/stage-pulse-observe.sh"
fi
mkdir -p "$stage/crates/pulse-absd-frame-pressure/src/bin"
cp "$root/observe/served.rs" "$stage/crates/pulse-absd-frame-pressure/src/bin/pulse-frame-pressure.rs"
absd_full_rustflags pulse-observe ""
(cd "$stage" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
    -u CARGO_TARGET_X86_64_UNKNOWN_ABSD_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS \
CARGO_ENCODED_RUSTFLAGS="$ABSD_FULL_RUSTFLAGS" \
ABSD_REAL_RUSTC=$toolchain/bin/rustc ABSD_STAGED_SYSROOT=$sysroot \
RUSTC=$root/scripts/rustc-staged.sh RUSTC_BOOTSTRAP=1 RUST_TARGET_PATH=$root/targets \
CARGO_TARGET_DIR=$stage/target-served CARGO_PROFILE_RELEASE_PANIC=abort \
ABSD_PROGRAM_NAME=pulse-frame-pressure \
cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort \
    --target x86_64-unknown-absd --release --offline --locked \
    -p pulse-absd-frame-pressure --bin pulse-frame-pressure)
cp "$stage/target-served/x86_64-unknown-absd/release/pulse-frame-pressure" "$root/pulse-frame-pressure.elf"
printf '%s\n' "ABSD SERVED PULSE BUILT $(sha256sum "$root/pulse-frame-pressure.elf" | cut -d' ' -f1)"
