#!/bin/sh
# Foreground isolated native build. No child or service is spawned by this probe.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
: "${ABSD_DHCP_REFUSAL_ELF:?exact external occurrence output path required}"
case "$ABSD_DHCP_REFUSAL_ELF" in
    /*) ;;
    *) echo 'DHCP refusal output must be absolute' >&2; exit 1 ;;
esac
case "$ABSD_DHCP_REFUSAL_ELF" in
    "$root"/*) echo 'DHCP refusal output must be outside source checkout' >&2; exit 1 ;;
esac
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
    cargo +1.95.0 --config "$ABSD_RUST_REMAP" build --manifest-path "$root/Cargo.toml" \
    -Z build-std=core,alloc,std,panic_abort --release --locked --offline \
    --features native-dhcpv4-probe --bin dhcp_refusal_probe
llvm-strip-18 -o "$ABSD_DHCP_REFUSAL_ELF" "$root/target/x86_64-unknown-absd/release/dhcp_refusal_probe"
sha256sum "$ABSD_DHCP_REFUSAL_ELF"
