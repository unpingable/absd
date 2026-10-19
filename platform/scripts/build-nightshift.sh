#!/bin/sh
# Builds Nightshift's real `nightshift-observation-resolver` for ABSD from
# the staged, patched Nightshift workspace, with this repository's staged
# standard library, compiler wrapper, and freestanding SQLite. Its
# deployment arguments are fixed into the image, as AG's deployment wrapper
# fixes them on Linux. Requires scripts/prepare-and-build.sh (or at least
# scripts/stage-library.sh) to have staged the sysroot.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
stage=$(dirname "$root")/absd-std-staged-nightshift
test -d "$sysroot/lib/rustlib/src/rust/library"
"$root/scripts/stage-nightshift.sh"
clang_include=$(clang -print-resource-dir)/include

build() {
bin=$1 elf=$2 args=$3 strip=${4:-}
absd_full_rustflags nightshift
(cd "$stage" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
    -u CARGO_TARGET_X86_64_UNKNOWN_ABSD_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS \
CARGO_ENCODED_RUSTFLAGS="$ABSD_FULL_RUSTFLAGS" \
ABSD_REAL_RUSTC=$toolchain/bin/rustc \
ABSD_STAGED_SYSROOT=$sysroot \
RUSTC=$root/scripts/rustc-staged.sh \
RUSTC_BOOTSTRAP=1 \
RUST_TARGET_PATH=$root/targets \
CARGO_PROFILE_RELEASE_PANIC=abort \
CC_x86_64_unknown_absd=clang \
AR_x86_64_unknown_absd=llvm-ar-18 \
CRATE_CC_NO_DEFAULTS=1 \
CFLAGS_x86_64_unknown_absd="--target=x86_64-unknown-none-elf -ffreestanding -nostdinc -isystem $clang_include -I$root/sqlite/include -mcmodel=large -fno-pic -O2 -ffunction-sections -fdata-sections" \
LIBSQLITE3_FLAGS="-DSQLITE_OS_OTHER=1 -DSQLITE_OMIT_LOCALTIME -USQLITE_ENABLE_LOAD_EXTENSION -DSQLITE_OMIT_LOAD_EXTENSION" \
ABSD_PROGRAM_ARGS="$args" \
${strip:+CARGO_PROFILE_RELEASE_STRIP=$strip} \
cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort \
    --target x86_64-unknown-absd --release --offline ${ABSD_CARGO_LOCKED---locked} \
    -p nightshiftd --bin "$bin"
cp "$stage/target/x86_64-unknown-absd/release/$bin" "$root/$elf"
printf '%s\n' "ABSD NIGHTSHIFT $bin BUILT $(sha256sum "$root/$elf" | cut -d' ' -f1)"
)
}

# The resolver, deployed as AG's wrapper deploys it on Linux.
build nightshift-observation-resolver nightshift-resolver.elf \
    "--store /nightshift/nightshift.sqlite --resolver-id nightshift-observation-resolver/v1 --default-ttl-ms 600000"
# The resolver AG's native runtime profile pins (scripts/ag-native-matrix.py):
# the Linux reference's AG wrapper arguments (fixture runs/i-fresh-ag), with
# the store at its ABSD path. AG starts it with no arguments, so these fixed
# arguments are part of the pinned image, as they are part of the pinned
# wrapper script on Linux. The image also travels inside the ABSD filesystem
# (AG measures it there), so its symbol table is stripped: the same code in
# a smaller import, which must finish within init's worker deadline.
build nightshift-observation-resolver nightshift-ag-resolver.elf \
    "--store /nightshift/nightshift.sqlite --resolver-id nightshift-observation-resolver/v1 --default-ttl-ms 86400000" symbols
# The same resolver deployed with a ten-minute default TTL (as
# nightshift-resolver.elf is): the native AG matrix's not-current variant.
build nightshift-observation-resolver nightshift-ag-resolver-short-ttl.elf \
    "--store /nightshift/nightshift.sqlite --resolver-id nightshift-observation-resolver/v1 --default-ttl-ms 600000" symbols
# The writer, one posture-only cycle; its owner commands name programs that
# ABSD cannot start, so every owner is unavailable.
build nightshift nightshift-writer.elf \
    "--store /nightshift/nightshift.sqlite cycle run --request /nightshift/posture-request.json --present-evidence-resolver /owners/pulse-support-resolver --nq-program /owners/nq --nq-config /owners/nq.toml --nq-source-id nq-node:fixture"
# The writer of the native observation pipeline (scripts/pipeline-matrix.py):
# the Linux reference's invocation, with ABSD paths. Init's broker starts its
# `nq` and `pulse-support-resolver`; the AG paths are named because the
# request carries a proposal, and are reached only on current support.
build nightshift nightshift-pipeline-writer.elf \
    "--store /nightshift/nightshift.sqlite cycle run --request /nightshift/cycle-request.json --present-evidence-resolver /owners/pulse-support-resolver --nq-program /owners/nq --nq-config /owners/nq.toml --nq-source-id nq-store-genesis:26373050-17aa-4ed9-8a41-cc27f3bcfb1f --ag-loopctl /owners/ag-loopctl --ag-database /ag/ag.sqlite --ag-observation-resolver /owners/observation-resolver --ag-observation-resolver-id nightshift-observation-resolver/v1 --ag-runtime-profile /ag/runtime-profile.json"
