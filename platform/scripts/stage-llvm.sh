#!/bin/sh
# Stage the pinned LLVM source (cxx/PIN) that the C++ runtime (and later the
# native Clang lane) builds from: download the release tarball into an empty
# directory if absent, verify its sha256 against the pin before anything reads
# it, extract it into a fresh directory beside the repository (never inside
# it), make the extracted tree read-only, and check that its licence file is
# the one carried as cxx/llvm-project.LICENSE and that it is the pinned
# release (LLVM_VERSION_* in llvm/CMakeLists.txt). Nothing in the tree is run.
# Layout: $ABSD_LLVM_UPSTREAM (default $camp/upstream)/llvm-project/dl/<tarball>
# and .../llvm-project/src/llvm-project-<version>.src.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
up=${ABSD_LLVM_UPSTREAM:-$camp/upstream}
pin=$root/cxx/PIN
die() { echo "stage-llvm: $*" >&2; exit 1; }
rows=$(grep -v '^#' "$pin" | grep -v '^[[:space:]]*$')
[ "$(printf '%s\n' "$rows" | wc -l)" = 1 ] || die "cxx/PIN must name exactly one source"
bad=$(printf '%s\n' "$rows" | awk -F'\t' '{ if (NF != 6) { print; next } for (i = 1; i <= NF; i++) if ($i == "") { print; next } }')
[ -z "$bad" ] || die "cxx/PIN row without six non-empty fields: $bad"
tab=$(printf '\t')
IFS="$tab" read -r name version commit url sha licence <<EOF
$rows
EOF
[ "$name" = llvm-project ] || die "cxx/PIN names $name, not llvm-project"
top=llvm-project-$version.src
dl=$up/$name/dl; mkdir -p "$dl"
file=$dl/$(basename "$url")
if ! [ -f "$file" ]; then
    [ -z "$(ls -A "$dl")" ] || die "$dl is not empty and holds no $(basename "$url")"
    tmp=$(mktemp -d "$dl/fetch.XXXXXX")
    curl -fsSL --retry 3 -o "$tmp/$(basename "$url")" "$url" ||
        { rm -rf "$tmp"; die "download of $url failed"; }
    # verify before the file takes its place, so a bad download is not kept
    got=$(sha256sum "$tmp/$(basename "$url")" | cut -d' ' -f1)
    [ "$got" = "$sha" ] || { rm -rf "$tmp"; die "sha256 mismatch: download of $url is $got, cxx/PIN says $sha (not kept)"; }
    mv "$tmp/$(basename "$url")" "$file"; rmdir "$tmp"
fi
got=$(sha256sum "$file" | cut -d' ' -f1)
[ "$got" = "$sha" ] || die "sha256 mismatch: $file is $got, cxx/PIN says $sha"
dest=$up/$name/src
[ -e "$dest" ] && chmod -R u+w "$dest"
rm -rf "$dest"; mkdir -p "$dest"
case $file in
    *.tar.xz) nice -n 19 tar -xJf "$file" -C "$dest" --no-same-owner --no-same-permissions ||
                  die "extracting $file failed" ;;
    *) die "$file: unknown archive type" ;;
esac
[ "$(ls -A "$dest")" = "$top" ] || die "$dest does not hold exactly $top"
for f in LICENSE.TXT llvm/CMakeLists.txt runtimes/CMakeLists.txt libcxx/CMakeLists.txt libcxxabi/CMakeLists.txt; do
    [ -f "$dest/$top/$f" ] || die "$dest/$top/$f is absent"
done
cmp -s "$dest/$top/LICENSE.TXT" "$root/cxx/llvm-project.LICENSE" ||
    die "$top/LICENSE.TXT differs from cxx/llvm-project.LICENSE"
v=$(awk '/set\(LLVM_VERSION_(MAJOR|MINOR|PATCH) / { gsub(/\)/, "", $2); printf "%s%s", sep, $2; sep = "." }' "$dest/$top/llvm/CMakeLists.txt")
[ "$v" = "$version" ] || die "$top/llvm/CMakeLists.txt says LLVM $v, cxx/PIN says $version"
chmod -R a-w "$dest"
echo "LLVM STAGE OK $name $version commit=$commit(recorded,unverified) sha256=$sha licence=$licence src=$dest/$top"
