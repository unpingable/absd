#!/bin/sh
# Builds AG's real `ag-loopctl` for ABSD from the staged, patched AG tree
# through the consumer workspace (scripts/stage-ag-loopctl.sh), with this
# repository's staged standard library, compiler wrapper, and freestanding
# SQLite. Also builds the Nightshift observation resolver that AG's runtime
# profile pins for the native AG path (scripts/ag-native-matrix.py).
#
# A durable worker runs the arguments fixed at build time
# (`ABSD_PROGRAM_ARGS`), so the one source is built once per subcommand the
# Linux reference ran, with its argument vector at ABSD paths:
#   ag-loopctl-init.elf             init --database ... --genesis ... --runtime-profile ...
#   ag-loopctl-record-proposal.elf  record-proposal --database ... --input ...
#                                   --observation-resolver ... --expected-observation-resolver-id ...
# The resolver image fixes its deployment arguments, as the Linux
# reference's wrapper script does; AG starts it with no arguments.
# Requires scripts/stage-library.sh to have staged the sysroot.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
stage=$(dirname "$root")/absd-std-staged-ag-loopctl
test -d "$sysroot/lib/rustlib/src/rust/library"
"$root/scripts/stage-ag-loopctl.sh"
clang_include=$(clang -print-resource-dir)/include

build() {
elf=$1 args=$2
(cd "$stage/absd-ag" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
ABSD_REAL_RUSTC=$toolchain/bin/rustc \
ABSD_STAGED_SYSROOT=$sysroot \
RUSTC=$root/scripts/rustc-staged.sh \
RUSTC_BOOTSTRAP=1 \
RUST_TARGET_PATH=$root/targets \
CARGO_TARGET_X86_64_UNKNOWN_ABSD_RUSTFLAGS="-C link-arg=-T$root/user-linker.ld -C link-arg=--gc-sections --cfg getrandom_backend=\"rdrand\"" \
CC_x86_64_unknown_absd=clang \
AR_x86_64_unknown_absd=llvm-ar-18 \
CRATE_CC_NO_DEFAULTS=1 \
CFLAGS_x86_64_unknown_absd="--target=x86_64-unknown-none-elf -ffreestanding -nostdinc -isystem $clang_include -I$root/sqlite/include -mcmodel=large -fno-pic -O2 -ffunction-sections -fdata-sections" \
LIBSQLITE3_FLAGS="-DSQLITE_OS_OTHER=1 -DSQLITE_OMIT_LOCALTIME -USQLITE_ENABLE_LOAD_EXTENSION -DSQLITE_OMIT_LOAD_EXTENSION" \
ABSD_PROGRAM_ARGS="$args" \
cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort \
    --target x86_64-unknown-absd --release --offline ${ABSD_CARGO_LOCKED---locked} --bin ag-loopctl
cp "$stage/absd-ag/target/x86_64-unknown-absd/release/ag-loopctl" "$root/$elf"
printf '%s\n' "ABSD AG $elf BUILT $(sha256sum "$root/$elf" | cut -d' ' -f1)"
)
}

build ag-loopctl-init.elf \
    "init --database /ag/state/ag.sqlite --genesis /ag/genesis.json --runtime-profile /ag/config/runtime-profile.json"
build ag-loopctl-record-proposal.elf \
    "record-proposal --database /ag/state/ag.sqlite --input /ag/proposal.json --observation-resolver /ag/config/observation-resolver --expected-observation-resolver-id nightshift-observation-resolver/v1"
