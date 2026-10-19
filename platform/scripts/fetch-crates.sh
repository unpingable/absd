#!/bin/sh
# Fills the Cargo cache ($CARGO_HOME, default ~/.cargo) with everything the
# core-profile builds read, so that their `--offline --locked` builds work
# from a fresh clone on a machine that has never built ABSD. Needs network;
# nothing else does. Run it once, before scripts/prepare-and-build.sh:
#
#   ABSD_PROFILE=core scripts/fetch-crates.sh
#
# It downloads from crates.io the registry archives the staging scripts
# unpack themselves (sunset 0.6.0 for scripts/stage-ssh.sh, every row of
# compat/programs.tsv for scripts/stage-compat.sh), each checked against
# the sha256 those scripts pin, into the cache directory they read; stages
# the patched standard library, sunset and the compat crates exactly as the
# builds do; and runs `cargo fetch --locked` (with -Z build-std, so the
# standard library's own dependencies are fetched too) in every workspace
# the core profile builds: this tree, ssh/, sh/, c/absd-c/, and each staged
# compat crate. It changes no pinned input: every fetch is --locked.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
cache=${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f
compat=$(dirname "$root")/absd-std-staged-compat

die() { echo "fetch-crates: $*" >&2; exit 1; }

# archive CRATE VERSION SHA256: the registry archive, downloaded once.
archive() {
    file=$cache/$1-$2.crate
    if ! [ -f "$file" ]; then
        mkdir -p "$cache"
        curl -fsSL -o "$file.part" "https://static.crates.io/crates/$1/$1-$2.crate"
        mv "$file.part" "$file"
    fi
    [ "$(sha256sum "$file" | cut -d' ' -f1)" = "$3" ] || die "$file does not have the pinned sha256 $3"
}

# fetch DIR [ARGS]: cargo fetch in DIR with the staged sysroot, as the builds see it.
fetch() {
    dir=$1; shift
    (cd "$dir" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
        ABSD_REAL_RUSTC=$toolchain/bin/rustc \
        ABSD_STAGED_SYSROOT=$sysroot \
        RUSTC=$root/scripts/rustc-staged.sh \
        RUSTC_BOOTSTRAP=1 \
        RUST_TARGET_PATH=$root/targets \
        cargo +1.95.0 fetch --locked "$@") >/dev/null || die "cargo fetch failed in $dir"
    printf '%s\n' "ABSD FETCHED ${dir#"$(dirname "$root")/"}"
}

sunset_sha=$(sed -n 's/^expected=\([0-9a-f]\{64\}\)$/\1/p' "$root/scripts/stage-ssh.sh")
[ -n "$sunset_sha" ] || die "scripts/stage-ssh.sh pins no sunset sha256"
archive sunset 0.6.0 "$sunset_sha"
grep -v '^#' "$root/compat/programs.tsv" | while IFS="$(printf '\t')" read -r crate version sum _rest; do
    archive "$crate" "$version" "$sum"
done

"$root/scripts/stage-library.sh"
"$root/scripts/stage-ssh.sh"
"$root/scripts/stage-compat.sh"

std="-Z build-std=core,alloc,std,panic_abort"
# shellcheck disable=SC2086  # one option per word
fetch "$root" $std
# shellcheck disable=SC2086
fetch "$root/ssh" $std
fetch "$root/sh"
mkdir -p "$root/c/absd-c/tree"
for crate in runtime broker fs fsd release; do
    ln -sfn "../../../$crate" "$root/c/absd-c/tree/$crate"
done
fetch "$root/c/absd-c" -Z build-std=core,alloc,panic_abort
for dir in "$compat"/absd/* "$compat"/linux/*; do
    case $dir in
    "$compat"/absd/*)
        # shellcheck disable=SC2086
        fetch "$dir" $std ;;
    *) [ -f "$dir/Cargo.lock" ] && fetch "$dir" ;;
    esac
done
printf '%s\n' 'ABSD CRATES FETCHED'
