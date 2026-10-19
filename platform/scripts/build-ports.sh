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
# Then the base userland's sbase ports (C, through the C kit):
# scripts/install-userland-ports.sh puts each row of userland/PORTS.tsv into
# ports/<name> at its recorded digest, building them first with
# scripts/build-userland.sh if they are not built (that needs the C kit:
# scripts/build-picolibc.sh, scripts/build-c-kit.sh).
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
stage=$(dirname "$root")/absd-std-staged-compat
# The host's Cargo registry (index and downloaded archives) is read through
# a private Cargo home per port (see the loop); nothing else of it is used.
host_cargo=${CARGO_HOME:-$HOME/.cargo}
index=index.crates.io-1949cf8c6b5b557f  # as scripts/stage-compat.sh reads it
# The stage, the Cargo homes and the target directories are shared by every
# checkout beside this one: one invocation at a time (waits for the lock).
mkdir -p "$stage"
exec 9>"$stage/.build-ports.lock"
flock 9
# Cargo reads .cargo/config* from the build directory's ancestors as well as
# from CARGO_HOME; refuse rather than build with configuration the pins do
# not name.
dir=$stage/absd
while :; do
    for config in "$dir/.cargo/config" "$dir/.cargo/config.toml"; do
        [ ! -e "$config" ] || { echo "build-ports: $config would configure the port builds; remove it" >&2; exit 1; }
    done
    [ "$dir" = / ] && break
    dir=$(dirname "$dir")
done
# The ports are assembled here and published as ports/ only when every one
# has built and installed.
partial=$root/.ports.partial
# crate-version:bin, each a "run" row of compat/programs.tsv.
ports="uu_basename-0.12.0:basename uu_seq-0.12.0:seq uu_cut-0.12.0:cut uu_fold-0.12.0:fold
uu_nl-0.12.0:nl uu_uniq-0.12.0:uniq uu_base64-0.12.0:base64 ripgrep-15.2.0:rg"
test -d "$sysroot/lib/rustlib/src/rust/library"
"$root/scripts/stage-compat.sh"
rm -rf "${stage:?}/target-ports" "${stage:?}/cargo-home-ports" "${partial:?}"
mkdir -p "$partial" "$stage/logs"
tab=$(printf '\t')
for port in $ports; do
    tree=${port%:*} bin=${port#*:}
    crate=${tree%-*} version=${tree##*-}
    awk -F"$tab" -v c="$crate" -v v="$version" -v b="$bin" \
        '$1 == c && $2 == v && $4 == b && $5 == "run" {found=1} END {exit !found}' "$root/compat/programs.tsv" ||
        { echo "build-ports: $tree $bin is not a run row of compat/programs.tsv" >&2; exit 1; }
    # uucore's build script embeds the locales of every uu_* crate unpacked
    # next to it in the Cargo registry, so a port built against the host's
    # ~/.cargo depended on what other builds had unpacked there. Each port
    # gets a fresh Cargo home whose registry/src starts empty: it shares
    # only the host's index and archives (read through links), so cargo
    # unpacks exactly the crates this port's pinned lock and build-std need,
    # and the host's Cargo configuration is not read. Its own target
    # directory keeps one port's build-script output from another's. The
    # private paths are remapped. The build's environment is exactly the
    # one written below (env -i): nothing else of the caller's reaches it,
    # in particular no CARGO_* setting, no locale (uucore reads LANG to
    # embed a second one), no GIT_DIR/GIT_WORK_TREE, and no
    # UUCORE_TARGET_UTIL (which selects uucore's single-utility mode, which
    # finds no messages in a crates.io layout).
    home=$stage/cargo-home-ports/$tree
    mkdir -p "$home/registry"
    ln -s "$host_cargo/registry/index" "$home/registry/index"
    ln -s "$host_cargo/registry/cache" "$home/registry/cache"
    # The port itself builds from the stage, not the registry, so uucore
    # would not see it and would leave out the utility's own messages:
    # unpack the port's archive (the one stage-compat checked against its
    # crates.io checksum) beside the crates cargo will unpack.
    mkdir -p "$home/registry/src/$index"
    tar -xzf "$host_cargo/registry/cache/$index/$tree.crate" -C "$home/registry/src/$index"
    # ripgrep's build script embeds `git rev-parse HEAD` of whatever
    # repository encloses the build directory (the staging area is inside
    # this host's git tree): stop git's discovery at the staging root so
    # the binary carries no host revision and rebuilds identically.
    (cd "$stage/absd/$tree" && env -i PATH="$PATH" HOME="$HOME" \
        ${RUSTUP_HOME:+RUSTUP_HOME="$RUSTUP_HOME"} ${TMPDIR:+TMPDIR="$TMPDIR"} \
        CARGO_HOME=$home \
        GIT_CEILING_DIRECTORIES=$stage \
        ABSD_REAL_RUSTC=$toolchain/bin/rustc \
        ABSD_STAGED_SYSROOT=$sysroot \
        RUSTC=$root/scripts/rustc-staged.sh \
        RUSTC_BOOTSTRAP=1 \
        RUST_TARGET_PATH=$root/targets \
        ABSD_RESTRICTED_STD_ALL=1 \
        CARGO_TARGET_DIR=$stage/target-ports/$tree \
        CARGO_TARGET_X86_64_UNKNOWN_ABSD_RUSTFLAGS="-C link-arg=-T$root/user-linker.ld -C link-arg=--gc-sections --cfg getrandom_backend=\"rdrand\" --remap-path-prefix=$home=/absd/cargo-home" \
        CARGO_PROFILE_RELEASE_PANIC=abort \
        CARGO_PROFILE_RELEASE_LTO=true \
        CARGO_PROFILE_RELEASE_OPT_LEVEL=z \
        CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
        cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort \
            -Z build-std-features=optimize_for_size \
            --target x86_64-unknown-absd --release --offline --locked --bin "$bin") \
        >"$stage/logs/$tree.ports.log" 2>&1 ||
        { tail -40 "$stage/logs/$tree.ports.log" >&2; echo "build-ports: $tree does not build" >&2; exit 1; }
    llvm-strip-18 -o "$partial/$bin" "$stage/target-ports/$tree/x86_64-unknown-absd/release/$bin"
    printf '%s\n' "PORT BUILT $tree $bin $(stat -c %s "$partial/$bin")"
done
ABSD_PORTS_DIR=$partial sh "$root/scripts/install-userland-ports.sh"
rm -rf "${root:?}/ports"
mv "$partial" "$root/ports"
printf '%s\n' "ABSD PORTS BUILT"
