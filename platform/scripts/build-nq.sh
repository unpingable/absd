#!/bin/sh
# Builds NQ-NG's real `nq` for ABSD from the staged, patched NQ tree through
# the consumer workspace (scripts/stage-nq.sh), with this repository's
# staged standard library, compiler wrapper, and freestanding SQLite.
#
# A program started through the broker takes its arguments from the startup
# record; without one it runs the arguments fixed here at build time
# (`ABSD_PROGRAM_ARGS`). Two images are built for standalone qualification:
#   nq.elf          --config /nq/nq.toml --json diagnostics qualify <fixture artifact>
#   nq-unknown.elf  the same with a well-formed artifact id the store lacks
# Requires scripts/stage-library.sh to have staged the sysroot.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
stage=$(dirname "$root")/absd-std-staged-nq
artifact=sha256:bddd0a9e1e29fad5c066ab0fb3cfd6c32408e6f1ad8d3f38ec79235a5a83bbd3
unknown=sha256:0000000000000000000000000000000000000000000000000000000000000000
test -d "$sysroot/lib/rustlib/src/rust/library"
"$root/scripts/stage-nq.sh"
clang_include=$(clang -print-resource-dir)/include

build() {
elf=$1 args=$2
absd_full_rustflags nq
(cd "$stage/absd-nq" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
    -u CARGO_TARGET_X86_64_UNKNOWN_ABSD_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS \
CARGO_ENCODED_RUSTFLAGS="$ABSD_FULL_RUSTFLAGS" \
ABSD_REAL_RUSTC=$toolchain/bin/rustc \
ABSD_STAGED_SYSROOT=$sysroot \
RUSTC=$root/scripts/rustc-staged.sh \
RUSTC_BOOTSTRAP=1 \
RUST_TARGET_PATH=$root/targets \
CC_x86_64_unknown_absd=clang \
AR_x86_64_unknown_absd=llvm-ar-18 \
CRATE_CC_NO_DEFAULTS=1 \
CFLAGS_x86_64_unknown_absd="--target=x86_64-unknown-none-elf -ffreestanding -nostdinc -isystem $clang_include -I$root/sqlite/include -mcmodel=large -fno-pic -O2 -ffunction-sections -fdata-sections" \
LIBSQLITE3_FLAGS="-DSQLITE_OS_OTHER=1 -DSQLITE_OMIT_LOCALTIME -USQLITE_ENABLE_LOAD_EXTENSION -DSQLITE_OMIT_LOAD_EXTENSION" \
ABSD_PROGRAM_ARGS="$args" \
cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort \
    --target x86_64-unknown-absd --release --offline ${ABSD_CARGO_LOCKED---locked} --bin nq
cp "$stage/absd-nq/target/x86_64-unknown-absd/release/nq" "$root/$elf"
printf '%s\n' "ABSD NQ $elf BUILT $(sha256sum "$root/$elf" | cut -d' ' -f1)"
)
}

build nq.elf "--config /nq/nq.toml --json diagnostics qualify $artifact"
build nq-unknown.elf "--config /nq/nq.toml --json diagnostics qualify $unknown"
# The profile digest compiled into the ABSD image, from nq-profiles's own
# build script over the staged (unchanged) inputs.
digest=$(cat "$stage"/absd-nq/target/x86_64-unknown-absd/release/build/nq-profiles-*/output |
    sed -n 's/^cargo:rustc-env=NQ_PROFILES_SOURCE_DIGEST=//p' | sort -u)
test "$(printf '%s\n' "$digest" | wc -l)" -eq 1
printf '%s\n' "$digest" > "$root/nq-profile-digest.txt"
printf '%s\n' "ABSD NQ PROFILE DIGEST $digest"
