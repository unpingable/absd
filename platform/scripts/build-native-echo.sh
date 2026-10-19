#!/bin/sh
# Source-pinned foreground build on the separately admitted compiler VM.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
ABSD_PROFILE=${ABSD_PROFILE:-core}
export ABSD_PROFILE
. "$root/scripts/inputs.sh"
absd_rust_remap
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
"$root/scripts/stage-library.sh"
build() {
    env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
        CARGO_BUILD_JOBS=1 ABSD_REAL_RUSTC="$toolchain/bin/rustc" \
        ABSD_STAGED_SYSROOT="$root/.staged-sysroot" RUSTC="$root/scripts/rustc-staged.sh" \
        RUSTC_BOOTSTRAP=1 RUST_TARGET_PATH="$root/targets" \
        ABSD_PING_CLIENT_ELF="$root/ping-once.elf" \
        cargo +1.95.0 --config "$ABSD_RUST_REMAP" build --manifest-path "$root/Cargo.toml" \
        -Z build-std=core,alloc,std,panic_abort --release --locked --offline \
        --features native-echo-probe --bin "$1"
}
build ping-once
llvm-strip-18 -o "$root/ping-once.elf" "$root/target/x86_64-unknown-absd/release/ping-once"
build echo_service_probe
llvm-strip-18 -o "$root/echo-service-probe.elf" "$root/target/x86_64-unknown-absd/release/echo_service_probe"
sha256sum "$root/ping-once.elf" "$root/echo-service-probe.elf"
