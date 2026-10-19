#!/bin/sh
# Opt-in development build. No guest, NIC or acceptance runner is launched.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
ABSD_PROFILE=${ABSD_PROFILE:-core}
export ABSD_PROFILE
. "$root/scripts/inputs.sh"
absd_rust_remap
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
"$root/scripts/stage-library.sh"
env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
    CARGO_BUILD_JOBS=1 ABSD_REAL_RUSTC="$toolchain/bin/rustc" \
    ABSD_STAGED_SYSROOT="$root/.staged-sysroot" RUSTC="$root/scripts/rustc-staged.sh" \
    RUSTC_BOOTSTRAP=1 RUST_TARGET_PATH="$root/targets" \
    cargo +1.95.0 --config "$ABSD_RUST_REMAP" build \
    -Z build-std=core,alloc,std,panic_abort --release --locked --offline \
    --features native-ipv6-echo-responder-probe --bin ipv6_echo_responder_probe
llvm-strip-18 -o "$root/ipv6-echo-responder-probe.elf" "$root/target/x86_64-unknown-absd/release/ipv6_echo_responder_probe"
sha256sum "$root/ipv6-echo-responder-probe.elf"
