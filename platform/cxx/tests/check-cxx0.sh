#!/bin/sh
# Host checks of the C++0 probe (cxx/README.md): build cxx/tests/cxx0.cpp
# twice with absd-c++ (-Oz) in two different directories and require
# identical ELFs, gate both with scripts/check-c-elf.py --map, list the
# probe's undefined symbols (only Picolibc's weak stdin is admitted), then
# build the same source on Linux with g++ and clang++ (-O2 -fno-exceptions
# -fno-rtti, the host's libstdc++) and require both outputs to equal
# cxx/tests/cxx0.expected, the bytes the guest run must print. The ELF is
# left at $ABSD_CXX0_OUT (default $camp/cxx-build/tests/cxx0) for the
# steward's guest run. Nothing is booted.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
camp=$(dirname "$root")
driver=${ABSD_CXX_DRIVER:-${ABSD_CXX_BUILD:-$camp/cxx-build}/bin/absd-c++}
out=${ABSD_CXX0_OUT:-${ABSD_CXX_BUILD:-$camp/cxx-build}/tests/cxx0}
src=$root/cxx/tests/cxx0.cpp expected=$root/cxx/tests/cxx0.expected
die() { echo "check-cxx0: $*" >&2; exit 1; }
[ -x "$driver" ] || die "$driver absent: run scripts/build-cxx-runtime.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-cxx0.XXXXXX"); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/a" "$tmp/b/deeper" "$(dirname "$out")"
nice -n 19 "$driver" -Oz -o "$tmp/a/cxx0" "$src"
nice -n 19 "$driver" -Oz -o "$tmp/b/deeper/cxx0" "$src"
cmp -s "$tmp/a/cxx0" "$tmp/b/deeper/cxx0" || die "two builds of the probe differ"
for d in a b/deeper; do
    gate=$(python3 -I "$root/scripts/check-c-elf.py" "$tmp/$d/cxx0" --map "$tmp/$d/cxx0.map") || die "$gate"
done
undef=$(llvm-nm-18 -u "$tmp/a/cxx0" | awk '{ print $1 ":" $2 }' | tr '\n' ' ')
[ "$undef" = "w:stdin " ] || die "undefined symbols other than Picolibc's weak stdin: $undef"
cp "$tmp/a/cxx0" "$out"; cp "$tmp/a/cxx0.map" "$out.map"; cp "$tmp/a/cxx0.toolchain" "$out.toolchain"
gate=$(python3 -I "$root/scripts/check-c-elf.py" "$out" --map "$out.map") || die "$gate"
echo "$gate"
for cxx in g++ clang++-18; do
    nice -n 19 "$cxx" -std=gnu++17 -O2 -fno-exceptions -fno-rtti -o "$tmp/host-$cxx" "$src"
    (cd "$tmp" && env -i "$tmp/host-$cxx" > "$tmp/host-$cxx.out" 2>&1) || die "the $cxx reference exited non-zero"
    cmp -s "$tmp/host-$cxx.out" "$expected" || die "the $cxx reference output differs from cxx/tests/cxx0.expected"
done
loads=$(llvm-readelf-18 -lW "$out" | grep -c ' LOAD ')
set -- $(llvm-size-18 "$out" | awk 'NR == 2 { print $1, $2, $3 }')
echo "CXX0 HOST OK bytes=$(stat -c %s "$out") text=$1 data=$2 bss=$3 loads=$loads sha256=$(sha256sum "$out" | cut -d' ' -f1) expected_lines=$(wc -l < "$expected") out=$out"
