#!/bin/sh
# Isolated development build of native TCP diagnostic and its pipe service.
# Uses the pinned Rust patch, target and lock; does not rebuild an SDK/kit.
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
        ABSD_TCP_CLIENT_ELF="$root/tcp-client.elf" \
        cargo +1.95.0 --config "$ABSD_RUST_REMAP" build \
        -Z build-std=core,alloc,std,panic_abort --release --locked --offline \
        --features native-tcp-probe --bin "$1"
}
build tcp_client
llvm-strip-18 -o "$root/tcp-client.elf" "$root/target/x86_64-unknown-absd/release/tcp_client"
build tcp_service_probe
llvm-strip-18 -o "$root/tcp-service-probe.elf" "$root/target/x86_64-unknown-absd/release/tcp_service_probe"
sha256sum "$root/tcp-client.elf" "$root/tcp-service-probe.elf"
