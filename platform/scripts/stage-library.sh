#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
source_root=$toolchain/lib/rustlib/src/rust
stage=$root/.staged-sysroot

"$root/scripts/verify-inputs.sh"
rm -rf "$stage"
mkdir -p "$stage/lib/rustlib/src/rust"
cp -a "$source_root/library" "$stage/lib/rustlib/src/rust/library"
cp -a "$root/vendor/rustc-literal-escaper" \
    "$stage/lib/rustlib/src/rust/library/rustc-literal-escaper"
(cd "$stage/lib/rustlib/src/rust" &&
    GIT_CEILING_DIRECTORIES=$root \
        git apply --check --verbose "$root/patches/rust-1.95.0-absd-std.patch" &&
    GIT_CEILING_DIRECTORIES=$root \
        git apply --verbose "$root/patches/rust-1.95.0-absd-std.patch" &&
    GIT_CEILING_DIRECTORIES=$root \
        git apply --reverse --check "$root/patches/rust-1.95.0-absd-std.patch")
cp "$root/pins/library.Cargo.lock" \
    "$stage/lib/rustlib/src/rust/library/Cargo.lock"

staged_hash=$(
    cd "$stage/lib/rustlib/src/rust"
    find library -type f -print0 |
        LC_ALL=C sort -z |
        xargs -0 sha256sum |
        sha256sum |
        awk '{print $1}'
)
staged_files=$(find "$stage/lib/rustlib/src/rust/library" -type f | wc -l)
staged_bytes=$(find "$stage/lib/rustlib/src/rust/library" -type f -printf '%s\n' |
    awk '{total += $1} END {print total}')
staged_symlinks=$(find "$stage/lib/rustlib/src/rust/library" -type l | wc -l)
test "$staged_hash" = \
    c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c
test "$staged_files" -eq 2251
test "$staged_bytes" -eq 45920288
test "$staged_symlinks" -eq 0
test -z "$(find "$stage" \( -name '*.rej' -o -name '*.orig' \) -print -quit)"

printf '%s\n' 'ABSD RUST PATCH REAPPLY OK'
