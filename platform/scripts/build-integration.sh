#!/bin/sh
# Builds the extended integration programs: ABSD test programs that run
# other projects' code on ABSD, and those projects' own programs built for
# ABSD. Needs the Pulse, AG, Nightshift and NQ sources at the pinned
# revisions (scripts/inputs.sh) and the sysroot scripts/stage-library.sh
# stages; scripts/prepare-and-build.sh calls this in the full profile.
# Nothing installed on an image comes from here.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
stage=$root/.staged-sysroot

# As in prepare-and-build.sh: never reuse std archives across a fresh
# source verification; ABSD_INCREMENTAL=1 keeps the target directory and
# the staged trees.
if [ "${ABSD_INCREMENTAL:-0}" = 1 ] && [ -d "$root/integration/target" ] &&
    [ -d "$(dirname "$root")/absd-std-staged-ag" ] && [ -d "$(dirname "$root")/absd-std-staged-pulse-source" ]; then
    printf '%s\n' "build-integration: incremental (ABSD_INCREMENTAL=1): target and staged trees kept"
else
    rm -rf "$root/integration/target"
    "$root/scripts/stage-ag.sh"
    "$root/scripts/stage-pulse-source.sh"
fi

# The four programs of the integration workspace (integration/), whose
# manifest names the staged AG and Pulse crates. SQLite (bundled by
# rusqlite) is C: compiled freestanding against the declarations in
# sqlite/include, whose symbols absd-sqlite and absd-runtime define.
clang_include=$(clang -print-resource-dir)/include
(cd "$root/integration" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS \
    -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
ABSD_REAL_RUSTC=$toolchain/bin/rustc \
ABSD_STAGED_SYSROOT=$stage \
RUSTC=$root/scripts/rustc-staged.sh \
RUSTC_BOOTSTRAP=1 \
RUST_TARGET_PATH=$root/targets \
CC_x86_64_unknown_absd=clang \
AR_x86_64_unknown_absd=llvm-ar-18 \
CRATE_CC_NO_DEFAULTS=1 \
CFLAGS_x86_64_unknown_absd="--target=x86_64-unknown-none-elf -ffreestanding -nostdinc -isystem $clang_include -I$root/sqlite/include -mcmodel=large -fno-pic -O2 -ffunction-sections -fdata-sections" \
LIBSQLITE3_FLAGS="-DSQLITE_OS_OTHER=1 -DSQLITE_OMIT_LOCALTIME -USQLITE_ENABLE_LOAD_EXTENSION -DSQLITE_OMIT_LOAD_EXTENSION" \
cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort \
    --release --locked --offline)
cp "$root/integration/target/x86_64-unknown-absd/release/pulse_std" "$root/pulse-std.elf"
cp "$root/integration/target/x86_64-unknown-absd/release/ag_authority" "$root/ag-authority.elf"
cp "$root/integration/target/x86_64-unknown-absd/release/pulse_journal_std" "$root/pulse-journal-std.elf"
cp "$root/integration/target/x86_64-unknown-absd/release/ag_sqlite" "$root/ag-sqlite.elf"
# Nightshift's resolver and writer build in their own staged workspace:
# their rusqlite links a different libsqlite3-sys than AG's.
"$root/scripts/build-nightshift.sh"
# Pulse's support resolver builds in its own staged Pulse workspace.
"$root/scripts/build-pulse.sh"
# The ABSD-owned frame-pressure family builds in its own staged Pulse tree.
"$root/scripts/build-pulse-observe.sh"
# NQ-NG's `nq` builds from a consumer workspace beside the staged NQ tree,
# so that the tree's manifests and lock (profile-digest inputs) stay intact.
"$root/scripts/build-nq.sh"
# AG's `ag-loopctl` builds from a consumer workspace beside its own staged,
# patched AG tree (with ag-app's platform seam and ring's ABSD assembly).
"$root/scripts/build-ag-loopctl.sh"
