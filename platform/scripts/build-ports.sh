#!/bin/sh
# Builds the unmodified crates.io utilities installed under /bin beside the
# platform's own commands (README "Commands"): the uutils programs and
# ripgrep, the ones the source-portability probe
# (docs/COMPATIBILITY-LEDGER.md) found to build and to agree with Linux.
# Same staged trees and pinned locks as scripts/build-compat.sh; the
# profile is sized for a filesystem image
# (LTO, opt-level z, one codegen unit: about 30% smaller, and every byte of
# a program crosses the file server when it starts). Output: ports/<bin>,
# stripped. Requires scripts/stage-library.sh to have staged the sysroot.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
stage=$(dirname "$root")/absd-std-staged-compat
# crate-version:bin, each a "run" row of compat/programs.tsv.
ports="uu_basename-0.12.0:basename uu_seq-0.12.0:seq uu_cut-0.12.0:cut uu_fold-0.12.0:fold
uu_nl-0.12.0:nl uu_uniq-0.12.0:uniq uu_base64-0.12.0:base64 ripgrep-15.2.0:rg"
test -d "$sysroot/lib/rustlib/src/rust/library"
"$root/scripts/stage-compat.sh"
rm -rf "${stage:?}/target-ports" "${root:?}/ports"
mkdir -p "$root/ports" "$stage/logs"
tab=$(printf '\t')
for port in $ports; do
    tree=${port%:*} bin=${port#*:}
    crate=${tree%-*} version=${tree##*-}
    awk -F"$tab" -v c="$crate" -v v="$version" -v b="$bin" \
        '$1 == c && $2 == v && $4 == b && $5 == "run" {found=1} END {exit !found}' "$root/compat/programs.tsv" ||
        { echo "build-ports: $tree $bin is not a run row of compat/programs.tsv" >&2; exit 1; }
    # ripgrep's build script embeds `git rev-parse HEAD` of whatever
    # repository encloses the build directory (the staging area is inside
    # this host's git tree): stop git's discovery at the staging root so
    # the binary carries no host revision and rebuilds identically.
    (cd "$stage/absd/$tree" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
        GIT_CEILING_DIRECTORIES=$stage \
        ABSD_REAL_RUSTC=$toolchain/bin/rustc \
        ABSD_STAGED_SYSROOT=$sysroot \
        RUSTC=$root/scripts/rustc-staged.sh \
        RUSTC_BOOTSTRAP=1 \
        RUST_TARGET_PATH=$root/targets \
        ABSD_RESTRICTED_STD_ALL=1 \
        CARGO_TARGET_DIR=$stage/target-ports \
        CARGO_TARGET_X86_64_UNKNOWN_ABSD_RUSTFLAGS="-C link-arg=-T$root/user-linker.ld -C link-arg=--gc-sections --cfg getrandom_backend=\"rdrand\"" \
        CARGO_PROFILE_RELEASE_PANIC=abort \
        CARGO_PROFILE_RELEASE_LTO=true \
        CARGO_PROFILE_RELEASE_OPT_LEVEL=z \
        CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
        cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort \
            -Z build-std-features=optimize_for_size \
            --target x86_64-unknown-absd --release --offline --locked --bin "$bin") \
        >"$stage/logs/$tree.ports.log" 2>&1 ||
        { tail -40 "$stage/logs/$tree.ports.log" >&2; echo "build-ports: $tree does not build" >&2; exit 1; }
    llvm-strip-18 -o "$root/ports/$bin" "$stage/target-ports/x86_64-unknown-absd/release/$bin"
    printf '%s\n' "PORT BUILT $tree $bin $(stat -c %s "$root/ports/$bin")"
done
printf '%s\n' "ABSD PORTS BUILT"
