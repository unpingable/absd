#!/bin/sh
# Builds the C application kit: libabsd_c.a (the runtime as a staticlib),
# then the C objects, libabs.a and the headers check, over the Picolibc
# install scripts/build-picolibc.sh puts beside the repository
# ($camp/picolibc/install, or $ABSD_PICOLIBC_PREFIX/install; its libc.a and
# libm.a must hash as c/picolibc/PIN says). Output goes to $camp/ckit-build,
# or ABSD_CKIT_BUILD, so the platform tree stays clean. kit/BUILT-FROM names
# the source tree (commit, whether it had changes, path), the toolchain and
# the hashes of the kit's archives; scripts/run-c-kit.sh checks it.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
out=${ABSD_CKIT_BUILD:-$camp/ckit-build}
mkdir -p "$out"
# The source tree's identity, taken before anything is built.
if commit=$(git -C "$root" rev-parse HEAD 2>/dev/null); then
    dirty=no; dirty_paths=$(git -C "$root" status --porcelain | head -n 8 | tr '\n' ' ')
    [ -z "$dirty_paths" ] || dirty=yes
else
    commit=none dirty=unknown dirty_paths=
fi
if ! [ -d "$sysroot/lib/rustlib/src/rust/library" ]; then
    "$root/scripts/stage-library.sh"
fi
# The archive must not depend on where the tree is checked out. The
# first-party crates are workspace members through c/absd-c/tree/ (see its
# Cargo.toml), so Cargo names their sources relative to c/absd-c: tree/ is
# remapped to /absd/. Every other path under the tree (its physical spelling
# too, which Cargo sees from the working directory; so the staged sysroot's
# library sources) is remapped to /absd, and the Cargo registry's sources to
# /cargo/registry/src.
mkdir -p "$root/c/absd-c/tree"
for crate in runtime broker fs fsd release; do
    ln -sfn "../../../$crate" "$root/c/absd-c/tree/$crate"
done
root_physical=$(CDPATH= cd -- "$root" && pwd -P)
us=$(printf '\037')
rustflags="--remap-path-prefix=tree=/absd$us--remap-path-prefix=$root=/absd"
[ "$root_physical" = "$root" ] || rustflags="$rustflags$us--remap-path-prefix=$root_physical=/absd"
rustflags="$rustflags$us--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}/registry/src=/cargo/registry/src"
(cd "$root/c/absd-c" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
CARGO_ENCODED_RUSTFLAGS="$rustflags" \
ABSD_REAL_RUSTC=$toolchain/bin/rustc \
ABSD_STAGED_SYSROOT=$sysroot \
RUSTC=$root/scripts/rustc-staged.sh \
RUSTC_BOOTSTRAP=1 \
RUST_TARGET_PATH=$root/targets \
CARGO_TARGET_DIR=$out/absd-c \
cargo +1.95.0 build -Z build-std=core,alloc,panic_abort \
    --target x86_64-unknown-absd --release --offline ${ABSD_CARGO_LOCKED---locked})
test -f "$out/absd-c/x86_64-unknown-absd/release/libabsd_c.a"
printf '%s\n' "ABSD C KIT libabsd_c.a $(sha256sum "$out/absd-c/x86_64-unknown-absd/release/libabsd_c.a" | cut -d' ' -f1)"
pico=${ABSD_PICOLIBC_PREFIX:-$camp/picolibc}/install
for archive in libc.a libm.a; do
    want=$(awk -F '\t' -v n="picolibc-$archive" '$1 == n { print $3 }' "$root/c/picolibc/PIN")
    [ -n "$want" ] || { echo "build-c-kit: c/picolibc/PIN has no picolibc-$archive line" >&2; exit 1; }
    if ! [ -f "$pico/lib/$archive" ]; then
        echo "build-c-kit: $pico/lib/$archive is missing: run scripts/build-picolibc.sh" >&2; exit 1
    fi
    got=$(sha256sum "$pico/lib/$archive" | cut -d' ' -f1)
    if [ "$got" != "$want" ]; then
        echo "build-c-kit: $pico/lib/$archive is $got, c/picolibc/PIN says $want: rebuild it with scripts/build-picolibc.sh" >&2; exit 1
    fi
done
printf '%s\n' "ABSD C KIT picolibc libc.a $(sha256sum "$pico/lib/libc.a" | cut -d' ' -f1) (pinned)"
kit=$out/kit
rm -rf "$kit"; mkdir -p "$kit/lib" "$kit/include/absd" "$kit/bin"
# The kit's C objects are compiled by the clang absd-cc drives (clang 18).
clang=${ABSD_CLANG:-clang-18}
clang_version=$("$clang" -dumpversion)
[ "${clang_version%%.*}" = 18 ] || { echo "build-c-kit: $clang is clang $clang_version: the kit needs clang 18" >&2; exit 1; }
clang_include=$("$clang" -print-resource-dir)/include
kitflags="--target=x86_64-unknown-none-elf -ffreestanding -nostdinc -nostdlib -mcmodel=large -fno-pic -fno-pie -fno-stack-protector -mno-avx -march=x86-64 -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -O2 -g0 -Wall -Wextra -Werror -isystem $root/c/include -isystem $pico/include -isystem $clang_include"
objs=
for src in crt0 malloc fd errno_map clock locale strerror_hook; do
    extra=; [ "$src" = clock ] && extra=-mrdrnd
    "$clang" $kitflags $extra -c "$root/c/libabs/$src.c" -o "$out/$src.o"
    objs="$objs $out/$src.o"
done
# -ffreestanding must keep the compiler from folding malloc+memset into a
# call to calloc (or any allocator call) inside the allocator itself.
if llvm-nm-18 -u "$out/malloc.o" | awk '{print $NF}' | grep -qx 'calloc\|malloc'; then
    echo "build-c-kit: malloc.o references calloc/malloc from within itself" >&2; exit 1
fi
rm -f "$kit/lib/libabs.a"
cp "$out/absd-c/x86_64-unknown-absd/release/libabsd_c.a" "$kit/lib/libabs.a"
llvm-ar-18 rcs "$kit/lib/libabs.a" $objs
# The Rust compiler_builtins member carries ~76 weak libm definitions that
# must lose to Picolibc's strong ones, while the kit's own definitions (clock.c
# getpid/sleep/..., the runtime's mem*) must win over Picolibc's libos
# fallbacks; one archive cannot sit both before and after libc.a, so the
# builtins member moves to libabs_builtins.a, linked after libc.a and libm.a.
cb=$(llvm-ar-18 t "$kit/lib/libabs.a" | grep '^compiler_builtins-')
test "$(printf '%s\n' "$cb" | wc -l)" = 1
mkdir -p "$out/cb"; rm -f "$out/cb/"*
(cd "$out/cb" && llvm-ar-18 x "$kit/lib/libabs.a" "$cb")
llvm-ar-18 d "$kit/lib/libabs.a" "$cb"
rm -f "$kit/lib/libabs_builtins.a"; llvm-ar-18 rcs "$kit/lib/libabs_builtins.a" "$out/cb/$cb"
cp "$out/crt0.o" "$kit/lib/crt0.o"      # also inside libabs.a; the explicit object keeps the entry pulled
# The pinned archives carry DWARF naming the host's clang include directory
# (/usr/lib/llvm-18/...), which every linked program would inherit. The kit
# holds debug-stripped copies; the install stays as pinned (its hashes are
# the ones checked above), and the copies' hashes are printed beside them.
for archive in libc.a libm.a; do
    llvm-strip-18 --strip-debug -o "$kit/lib/$archive" "$pico/lib/$archive"
    printf '%s\n' "ABSD C KIT kit $archive $(sha256sum "$kit/lib/$archive" | cut -d' ' -f1) (debug-stripped from pinned $(sha256sum "$pico/lib/$archive" | cut -d' ' -f1))"
done
cp -r "$pico/include/." "$kit/include/"
cp "$root/c/include/absd/"*.h "$kit/include/absd/"
cp "$root/c/absd-c.ld" "$kit/absd-c.ld"
cp "$root/c/bin/absd-cc" "$kit/bin/absd-cc"; chmod +x "$kit/bin/absd-cc"
python3 -I "$root/scripts/check-c-headers.py" "$root"
python3 -I "$root/scripts/check-fs-kinds.py" "$root"     # A13: exactly File and Dir
digest() { sha256sum "$1" | cut -d' ' -f1; }
{
    printf 'commit %s\n' "$commit"
    printf 'dirty %s\n' "$dirty"
    # N13: name what made the tree dirty, so a stamp taken mid-gate explains itself.
    [ -z "$dirty_paths" ] || printf 'dirty-paths %s\n' "$dirty_paths"
    printf 'source %s\n' "$root"     # the one path-dependent line; nothing in lib/ carries it
    printf 'rustc %s\n' "$("$toolchain/bin/rustc" --version)"
    printf 'cargo %s\n' "$(cargo +1.95.0 --version)"
    printf 'clang %s\n' "$("$clang" --version | head -n 1)"
    printf 'ld.lld %s\n' "$(ld.lld-17 --version)"
    printf 'llvm-ar %s\n' "$(llvm-ar-18 --version | sed -n 's/.*LLVM version //p' | head -n 1)"
    printf 'picolibc-libc.a %s\n' "$(digest "$pico/lib/libc.a")"
    printf 'picolibc-libm.a %s\n' "$(digest "$pico/lib/libm.a")"
    for file in libabs.a libabs_builtins.a crt0.o libc.a libm.a; do
        printf 'lib/%s %s\n' "$file" "$(digest "$kit/lib/$file")"
    done
} > "$kit/BUILT-FROM"
printf '%s\n' "ABSD C KIT BUILT-FROM commit=$commit dirty=$dirty${dirty_paths:+ paths=[$dirty_paths]}"
printf '%s\n' "ABSD C KIT libabs.a $(sha256sum "$kit/lib/libabs.a" | cut -d' ' -f1)"
printf '%s\n' "ABSD C KIT libabs_builtins.a $(sha256sum "$kit/lib/libabs_builtins.a" | cut -d' ' -f1)"
