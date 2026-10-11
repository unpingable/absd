#!/bin/sh
# Builds the source-portability probe (docs/COMPATIBILITY-LEDGER.md) from the
# trees scripts/stage-compat.sh stages:
#   compat-commands/<bin>  each "run" program for ABSD, stripped (it travels
#                          into the guest filesystem through init's pipe);
#   compat-linux/<bin>     the same program for Linux from the unmodified
#                          archive and its own lock, the reference output.
# Every ABSD build uses this repository's staged standard library, compiler
# wrapper, target, and linker script, with ABSD_RESTRICTED_STD_ALL=1 so the
# wrapper gates unmodified crates and links absd-runtime (scripts/rustc-staged.sh).
# With ABSD_COMPAT_FAILURES=1 it also builds each "fail" program and requires
# the build to fail with the ledger's signature in its log.
# Requires scripts/stage-library.sh to have staged the sysroot.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
stage=$(dirname "$root")/absd-std-staged-compat
test -d "$sysroot/lib/rustlib/src/rust/library"
"$root/scripts/stage-compat.sh"
# As in prepare-and-build.sh: build-std fingerprints do not notice a
# replaced sysroot at the same path, so never reuse ABSD output.
rm -rf "${stage:?}/target-absd" "${stage:?}/target-linux" "${stage:?}/logs"
rm -rf "$root/compat-commands" "$root/compat-linux"
mkdir -p "$root/compat-commands" "$root/compat-linux" "$stage/logs"

absd_build() {
    (cd "$1" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
    ABSD_REAL_RUSTC=$toolchain/bin/rustc \
    ABSD_STAGED_SYSROOT=$sysroot \
    RUSTC=$root/scripts/rustc-staged.sh \
    RUSTC_BOOTSTRAP=1 \
    RUST_TARGET_PATH=$root/targets \
    ABSD_RESTRICTED_STD_ALL=1 \
    CARGO_TARGET_DIR=$stage/target-absd \
    CARGO_TARGET_X86_64_UNKNOWN_ABSD_RUSTFLAGS="-C link-arg=-T$root/user-linker.ld -C link-arg=--gc-sections --cfg getrandom_backend=\"rdrand\"" \
    CARGO_PROFILE_RELEASE_PANIC=abort \
    cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort \
        -Z build-std-features=optimize_for_size \
        --target x86_64-unknown-absd --release --offline --locked --keep-going "$2" "$3")
}

built=0
tab=$(printf '\t')
for program in $(grep -v '^#' "$root/compat/programs.tsv" | awk -F"$tab" '$5 == "run" {print $1 "-" $2 ":" $4}'); do
    tree=${program%:*} bin=${program#*:}
    absd_build "$stage/absd/$tree" --bin "$bin" >"$stage/logs/$tree.absd.log" 2>&1 ||
        { tail -40 "$stage/logs/$tree.absd.log" >&2; echo "build-compat: $tree does not build for ABSD" >&2; exit 1; }
    llvm-strip-18 -o "$root/compat-commands/$bin" "$stage/target-absd/x86_64-unknown-absd/release/$bin"
    (cd "$stage/linux/$tree" && env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR=$stage/target-linux \
        cargo +1.95.0 build --release --offline --locked --bin "$bin") >"$stage/logs/$tree.linux.log" 2>&1 ||
        { tail -40 "$stage/logs/$tree.linux.log" >&2; echo "build-compat: $tree does not build for Linux" >&2; exit 1; }
    cp "$stage/target-linux/release/$bin" "$root/compat-linux/$bin"
    built=$((built + 1))
    printf '%s\n' "COMPAT BUILT $tree $bin $(stat -c %s "$root/compat-commands/$bin")"
done

if [ "${ABSD_COMPAT_FAILURES:-0}" = 1 ]; then
    grep -v '^#' "$root/compat/programs.tsv" | awk -F"$tab" '$5 == "fail"' |
    while IFS="$tab" read -r crate version sum bin expect signature; do
        log=$stage/logs/$crate-$version.absd.log
        if absd_build "$stage/absd/$crate-$version" --bin "$bin" >"$log" 2>&1; then
            echo "build-compat: $crate $version builds for ABSD; update the ledger" >&2
            exit 1
        fi
        grep -qF -- "$signature" "$log" ||
            { echo "build-compat: $crate $version fails without the ledger's signature: $signature" >&2; exit 1; }
        printf '%s\n' "COMPAT BUILD FAILS AS RECORDED $crate $version"
    done
fi
printf '%s\n' "ABSD COMPAT BUILT built=$built"
