#!/bin/sh
# Builds every stage-2 product for ABSD (absd-cc, the adapter archive) and
# for Linux (gcc), checks every ABSD ELF and its link map, records each
# product's demand (names its objects reference and do not define) and
# proves every name resolved by Picolibc, the kit or the adapter, proves the
# ABSD build reproducible (two clean rounds hash-equal: each round rebuilds
# the adapter archive and every product, and records the archive's hash
# beside the products') and writes the size table (name, bytes, demand count).
set -eu
# Symbol ordering is part of the retained .demand artifacts.
export LC_ALL=C
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
out=${ABSD_CPORTS_BUILD:-$camp/cports-build}
kit=${ABSD_CKIT_BUILD:-$camp/ckit-build}/kit
up=${ABSD_CPORTS_UPSTREAM:-$camp/upstream}
test -f "$out/stage.txt" || sh "$root/scripts/stage-cports.sh"
products=$(grep -h '^PRODUCTS +=' "$root"/cports/build/*.mk | awk '{print $3}')
mk() { make --no-print-directory -f "$root/cports/build/Makefile" ROOT="$root" CAMP="$camp" UP="$up" OUT="$out" CC_ABSD="$kit/bin/absd-cc" SIDE="$1" all; }
mkdir -p "$out/repro"
for round in 1 2; do
    # The archive is rebuilt every round, never reused (a stale archive
    # could lack an object a port names on its link line).
    sh "$root/scripts/build-posix.sh"
    rm -rf "$out/obj/absd" "$out/absd"; mkdir -p "$out/obj/absd" "$out/absd"
    mk absd
    (cd "$out" && sha256sum lib/libabsd-posix.a && for p in $products; do sha256sum "absd/$p"; done) > "$out/repro/round$round.sha256"
done
cmp -s "$out/repro/round1.sha256" "$out/repro/round2.sha256" || { diff "$out/repro/round1.sha256" "$out/repro/round2.sha256" || true; echo "build-cports: the two ABSD builds differ" >&2; exit 1; }
rm -rf "$out/obj/linux" "$out/linux"; mkdir -p "$out/obj/linux" "$out/linux"
mk linux
for p in $products; do test -x "$out/linux/$p" || { echo "build-cports: linux/$p missing" >&2; exit 1; }; done
# Every name Picolibc (libc.a, libm.a), the kit (libabs.a, libabs_builtins.a,
# the clang builtins) and the adapter archive define.
resolvers="$kit/lib/libc.a $kit/lib/libm.a $kit/lib/libabs.a $kit/lib/libabs_builtins.a $("${ABSD_CLANG:-clang-18}" -print-resource-dir)/lib/linux/libclang_rt.builtins-x86_64.a $out/lib/libabsd-posix.a"
llvm-nm-18 --defined-only --extern-only $resolvers 2>/dev/null | awk 'NF==3 {print $3}' | sort -u > "$out/obj/resolvers.txt"
: > "$out/sizes.txt"
for name in $products; do
    elf=$out/absd/$name
    python3 -I "$root/scripts/check-c-elf.py" "$elf" --map "$elf.map" || { echo "build-cports: $name refused by the ELF/map check" >&2; exit 1; }
    if [ -f "$out/obj/absd/$name.objs" ]; then objs=$(cat "$out/obj/absd/$name.objs"); else objs=$out/obj/absd/$name.o; fi
    llvm-nm-18 -u $objs | awk 'NF==2 && $1=="U" {print $2}' | sort -u > "$out/obj/absd/$name.u"
    llvm-nm-18 --defined-only $objs | awk 'NF==3 {print $3}' | sort -u > "$out/obj/absd/$name.d"
    comm -23 "$out/obj/absd/$name.u" "$out/obj/absd/$name.d" > "$elf.demand"
    unresolved=$(comm -23 "$elf.demand" "$out/obj/resolvers.txt")
    [ -z "$unresolved" ] || { echo "build-cports: $name demands names nothing defines:" >&2; printf '  %s\n' $unresolved >&2; exit 1; }
    echo "DEMAND $name names=$(wc -l < "$elf.demand") unresolved=0"
    printf '%s\t%s\t%s\n' "$name" "$(stat -c %s "$elf")" "$(wc -l < "$elf.demand")" >> "$out/sizes.txt"
done
cat "$out/sizes.txt"
echo "CPORTS BUILD OK products=$(wc -l < "$out/sizes.txt") reproducible=2"
