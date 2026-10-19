#!/bin/sh
# Isolated development build of native static-routed paired IPv6 UDP/TCP DNS diagnostic and its pipe service.
# Uses the pinned Rust patch, target and lock; does not rebuild an SDK/kit.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
ABSD_PROFILE=${ABSD_PROFILE:-core}
export ABSD_PROFILE
# A private immutable owner configuration. Cargo records option_env! changes.
ABSD_ROUTE6_TCP_IP_MTU=${ABSD_ROUTE6_TCP_IP_MTU:-1500}
case "$ABSD_ROUTE6_TCP_IP_MTU" in
    1280|1500) ;;
    *) echo 'ABSD_ROUTE6_TCP_IP_MTU must be 1280 or 1500' >&2; exit 2 ;;
esac
export ABSD_ROUTE6_TCP_IP_MTU
# The strip paths below name this recipe's own target tree, never an inherited one.
unset CARGO_TARGET_DIR
. "$root/scripts/inputs.sh"
absd_rust_remap
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
"$root/scripts/stage-library.sh"
build() {
    env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
        CARGO_BUILD_JOBS=1 ABSD_REAL_RUSTC="$toolchain/bin/rustc" \
        ABSD_STAGED_SYSROOT="$root/.staged-sysroot" RUSTC="$root/scripts/rustc-staged.sh" \
        RUSTC_BOOTSTRAP=1 RUST_TARGET_PATH="$root/targets" \
        ABSD_ROUTE6_TCP_CLIENT_ELF="$root/ipv6-route-tcp-dns-client.elf" \
        cargo +1.95.0 --config "$ABSD_RUST_REMAP" build \
        -Z build-std=core,alloc,std,panic_abort --release --locked --offline \
        --features native-ipv6-routed-tcp-probe --bin "$1"
}
build ipv6_route_tcp_dns_client
llvm-strip-18 -o "$root/ipv6-route-tcp-dns-client.elf" "$root/target/x86_64-unknown-absd/release/ipv6_route_tcp_dns_client"
build ipv6_route_tcp_service_probe
llvm-strip-18 -o "$root/ipv6-route-tcp-service-probe.elf" "$root/target/x86_64-unknown-absd/release/ipv6_route_tcp_service_probe"
sha256sum "$root/ipv6-route-tcp-dns-client.elf" "$root/ipv6-route-tcp-service-probe.elf"
