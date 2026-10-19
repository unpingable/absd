#!/bin/sh
# Foreground build for an admitted isolated compiler host; never an SDK rebuild.
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
        ABSD_DHCP_DNS_CLIENT_ELF="$root/dhcp-dns-client.elf" \
        cargo +1.95.0 --config "$ABSD_RUST_REMAP" build --manifest-path "$root/Cargo.toml" \
        -Z build-std=core,alloc,std,panic_abort --release --locked --offline \
        --features native-dhcpv4-probe --bin "$1"
}
build dhcp_dns_client
llvm-strip-18 -o "$root/dhcp-dns-client.elf" "$root/target/x86_64-unknown-absd/release/dhcp_dns_client"
build dhcp_service_probe
llvm-strip-18 -o "$root/dhcp-service-probe.elf" "$root/target/x86_64-unknown-absd/release/dhcp_service_probe"
sha256sum "$root/dhcp-dns-client.elf" "$root/dhcp-service-probe.elf"
