#!/bin/sh
# Builds the base userland ports (userland/README.md) for ABSD (absd-cc, the
# kit and the POSIX adapter) and, as the host REFERENCE, with gcc against
# glibc; then checks them with scripts/check-userland.py.
#
#   1. stage sbase (userland/PIN) if it is not staged;
#   2. copy the staged tree (read-only, never written) to $out/src and apply
#      every userland/patches/*.patch there, each checked to apply cleanly
#      and to reverse cleanly afterwards;
#   3. two clean ABSD rounds, each rebuilding the adapter archive and every
#      product, which must hash identically (sha256 of the adapter archive
#      and every ELF);
#   4. the Linux reference build of the same patched sources;
#   5. scripts/check-userland.py: the kit's ELF gate on every ABSD ELF,
#      the symbol-level demand check, and the host cases on the reference.
#
# Output goes to $ABSD_USERLAND_BUILD (default <campaign>/userland-build);
# the kit is $ABSD_CKIT_BUILD/kit, the adapter $ABSD_CPORTS_BUILD/lib.
# The last line is `USERLAND BUILD OK ports=<n> reproducible=2 ...`.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
kit=${ABSD_CKIT_BUILD:-$camp/ckit-build}/kit
cports=${ABSD_CPORTS_BUILD:-$camp/cports-build}
up=${ABSD_USERLAND_UPSTREAM:-$camp/upstream}
out=${ABSD_USERLAND_BUILD:-$camp/userland-build}
version=$(awk -F '\t' '$1 == "sbase" { print $2 }' "$root/userland/PIN")
staged=$up/sbase/src/sbase-$version
if ! [ -f "$staged/LICENSE" ] || ! [ -f "$up/toybox/src/diff/diff.c" ] || ! [ -f "$up/toybox/src/hexdump/hexdump.c" ]; then
    sh "$root/scripts/stage-userland.sh"
fi
test -x "$kit/bin/absd-cc" || { echo "build-userland: $kit/bin/absd-cc missing: run scripts/build-c-kit.sh" >&2; exit 1; }
src=$out/src
rm -rf "$src"; mkdir -p "$out"
cp -R "$staged" "$src"; chmod -R u+w "$src"
for p in "$root"/userland/patches/*.patch; do
    [ -f "$p" ] || continue
    patch -d "$src" -p1 --dry-run --quiet < "$p" >/dev/null || { echo "build-userland: $(basename "$p") does not apply" >&2; exit 1; }
    patch -d "$src" -p1 --quiet --no-backup-if-mismatch < "$p"
    patch -d "$src" -p1 -R --dry-run --quiet < "$p" >/dev/null || { echo "build-userland: $(basename "$p") does not reverse" >&2; exit 1; }
    echo "USERLAND PATCH $(basename "$p") $(sha256sum "$p" | cut -d' ' -f1)"
done
# Stage accepted Toybox patches afresh from the exact pinned archive into
# this build's own source directories, never compile a mutable upstream copy.
toybox_archive=$up/toybox/dl/toybox-0.8.15.tar.gz
rm -rf "$out/toybox-src"; mkdir -p "$out/toybox-src"
for utility in diff hexdump; do
    python3 -I "$root/scripts/stage-$utility.py" "$toybox_archive" "$out/toybox-src/$utility"
done
mk() {
    make --no-print-directory -f "$root/userland/Makefile" ROOT="$root" SRC="$src" TOYBOX_SRC="$out/toybox-src" UP="$up" OUT="$out" \
        CC_ABSD="$kit/bin/absd-cc" POSIX_A="$cports/lib/libabsd-posix.a" SIDE="$1" all
}
utils=$(sed -n 's/^UTILS := //p' "$root/userland/Makefile")
mkdir -p "$out/repro"
for round in 1 2; do
    sh "$root/scripts/build-posix.sh" >/dev/null
    rm -rf "$out/obj/absd" "$out/absd"
    mk absd >/dev/null
    (cd "$out" && sha256sum "$cports/lib/libabsd-posix.a" | sed "s#$cports/##" && for u in $utils; do sha256sum "absd/$u"; done) > "$out/repro/round$round.sha256"
done
cmp -s "$out/repro/round1.sha256" "$out/repro/round2.sha256" ||
    { diff "$out/repro/round1.sha256" "$out/repro/round2.sha256" || true; echo "build-userland: the two ABSD builds differ" >&2; exit 1; }
rm -rf "$out/obj/linux" "$out/linux"
mk linux >/dev/null
cat "$out/repro/round1.sha256"
python3 -I "$root/scripts/check-userland.py"
