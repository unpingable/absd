#!/bin/sh
# Isolated qualification build: default importer plus seven explicit stops.
# One freshly verified std staging; only the executable setting varies.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
out=${1:?give a fresh output directory}
if [ "$(pwd -P)" != "$root" ]; then
    echo "build-fixture-import-controls: run from the source root" >&2
    exit 2
fi
mkdir "$out"
ABSD_PROFILE=core
export ABSD_PROFILE
. "$root/scripts/inputs.sh"
absd_rust_remap
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
"$root/scripts/stage-library.sh"
for stop in normal directory-created created prefix-copied input-written synced verified renamed normal-repeat; do
    case $stop in
        normal|normal-repeat) unset ABSD_FIXTURE_IMPORT_STOP ;;
        *) ABSD_FIXTURE_IMPORT_STOP=$stop; export ABSD_FIXTURE_IMPORT_STOP ;;
    esac
    env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
        ABSD_REAL_RUSTC="$toolchain/bin/rustc" ABSD_STAGED_SYSROOT="$root/.staged-sysroot" \
        RUSTC="$root/scripts/rustc-staged.sh" RUSTC_BOOTSTRAP=1 RUST_TARGET_PATH="$root/targets" \
        cargo +1.95.0 --config "$ABSD_RUST_REMAP" build -Z build-std=core,alloc,std,panic_abort \
        --release --locked --offline --target x86_64-unknown-absd \
        --bin fixture_import --manifest-path "$root/Cargo.toml"
    llvm-strip-18 -o "$out/fixture-import-$stop.elf" "$root/target/x86_64-unknown-absd/release/fixture_import"
    sha256sum "$out/fixture-import-$stop.elf"
done
cmp "$out/fixture-import-normal.elf" "$out/fixture-import-normal-repeat.elf"
printf '%s\n' 'FIXTURE IMPORT CONTROL BUILD OK normal=reproducible stops=7'
