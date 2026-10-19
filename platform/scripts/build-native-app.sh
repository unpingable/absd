#!/bin/sh
# Cross-build an external, runtime-linked Cargo application with the existing
# restricted std. Stage the sysroot first; add absd-runtime as an ABSD-only
# manifest dependency and pin the resulting lock without changing app source.
# A fresh output directory avoids build-std's stale sysroot fingerprints and
# keeps this build independent of the shared compatibility/ports staging area.
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: build-native-app.sh MANIFEST BIN FRESH_OUTPUT_DIRECTORY" >&2
    exit 2
fi
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
manifest=$(realpath "$1")
bin=$2
output=$(realpath -m "$3")
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
test -f "$manifest"
test -f "$(dirname "$manifest")/Cargo.lock"
test -d "$sysroot/lib/rustlib/src/rust/library"
case "$bin" in ''|*[!a-zA-Z0-9_-]*) echo "invalid binary name: $bin" >&2; exit 2 ;; esac
if [ -e "$output" ]; then
    echo "native-app: output already exists; select a fresh directory: $output" >&2
    exit 2
fi
mkdir -p "$output"
cd "$(dirname "$manifest")"
rustflags=$(printf '%s\037' '-C' "link-arg=-T$root/user-linker.ld" \
    '-C' 'link-arg=--gc-sections' \
    "--remap-path-prefix=$root=/absd/platform" \
    "--remap-path-prefix=$(dirname "$manifest")=/absd/application")
rustflags=${rustflags%?}
env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
    ABSD_REAL_RUSTC="$toolchain/bin/rustc" \
    ABSD_STAGED_SYSROOT="$sysroot" \
    RUSTC="$root/scripts/rustc-staged.sh" \
    RUSTC_BOOTSTRAP=1 \
    RUST_TARGET_PATH="$root/targets" \
    ABSD_RESTRICTED_STD_ALL=1 \
    CARGO_TARGET_DIR="$output/target" \
    CARGO_ENCODED_RUSTFLAGS="$rustflags" \
    CARGO_PROFILE_RELEASE_PANIC=abort \
    CARGO_PROFILE_RELEASE_LTO=true \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=z \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort \
        -Z build-std-features=optimize_for_size \
        --target x86_64-unknown-absd --release --offline --locked \
        --manifest-path "$manifest" --bin "$bin"
cp "$output/target/x86_64-unknown-absd/release/$bin" "$output/$bin.unstripped"
llvm-strip-18 -o "$output/$bin" "$output/$bin.unstripped"
"$toolchain/bin/rustc" --version --verbose > "$output/compiler.txt"
sha256sum "$manifest" "$(dirname "$manifest")/Cargo.lock" \
    "$root/targets/x86_64-unknown-absd.json" "$root/user-linker.ld" \
    "$root/patches/rust-1.95.0-absd-std.patch" "$root/pins/library.Cargo.lock" \
    "$root/scripts/rustc-staged.sh" "$root/scripts/build-native-app.sh" \
    "$output/$bin" "$output/$bin.unstripped" > "$output/SHA256SUMS"
printf '%s\n' "NATIVE APP BUILT $bin $output/$bin"
