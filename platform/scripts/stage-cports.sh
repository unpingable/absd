#!/bin/sh
# Stage the stage-2 upstream sources (CPORTS-HARNESS.md 2): download into an
# empty directory if absent, verify sha256 against cports/programs.tsv before
# anything reads the file, extract twice (linux/, absd/) beside the
# repository, never inside it, and never modify an extracted tree.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
up=${ABSD_CPORTS_UPSTREAM:-$camp/upstream}
cports_build=${ABSD_CPORTS_BUILD:-$camp/cports-build}
mkdir -p "$cports_build"
# stage.txt is written whole or not at all: built in a temporary file and
# moved into place only after every program staged.
stage=$cports_build/stage.txt
rm -f "$stage" "$stage.tmp"
: > "$stage.tmp"
tab=$(printf '\t')
# `read` with IFS=tab treats tab as whitespace and collapses empty fields,
# which would shift the columns: every row must have six non-empty fields.
bad=$(grep -v '^#' "$root/cports/programs.tsv" | awk -F'\t' 'NF { if (NF != 6) { print; next } for (i = 1; i <= NF; i++) if ($i == "") { print; next } }')
[ -z "$bad" ] || { echo "stage-cports: cports/programs.tsv rows without six non-empty fields: $bad" >&2; exit 1; }
grep -v '^#' "$root/cports/programs.tsv" | grep -v '^[[:space:]]*$' | while IFS="$tab" read -r name version url sha expect note; do
    [ "$expect" = run ] || [ "$expect" = input ] || continue
    case $name in
        lua) want=lua-5.4.9/src/lua.c ;;
        lua-tests) want=lua-5.4.9-tests/all.lua ;;
        zlib) want=zlib-1.3.2/test/minigzip.c ;;
        sqlite-amalgamation) want=sqlite-amalgamation-3540000/sqlite3.c ;;
        sqlite-src) want=sqlite-src-3540000/test/speedtest1.c ;;
        *) echo "stage-cports: $name: no expected file recorded" >&2; exit 1 ;;
    esac
    dl=$up/$name/dl; mkdir -p "$dl"
    file=$dl/$(basename "$url")
    if ! [ -f "$file" ]; then
        tmp=$(mktemp -d "$dl/fetch.XXXXXX")
        curl -fsSL --retry 3 -o "$tmp/$(basename "$url")" "$url" ||
            { rm -rf "$tmp"; echo "stage-cports: $name: download of $url failed" >&2; exit 1; }
        mv "$tmp/$(basename "$url")" "$file"; rmdir "$tmp"
    fi
    echo "$sha  $file" | sha256sum -c --quiet - || { echo "stage-cports: $name: sha256 mismatch" >&2; exit 1; }
    for side in linux absd; do
        dest=$up/$name/$side
        [ -e "$dest" ] && chmod -R u+w "$dest"   # a previous run left it read-only; rm -rf needs writable directories
        rm -rf "$dest"; mkdir -p "$dest"
        case $file in
            *.tar.gz) tar -xzf "$file" -C "$dest" || { echo "stage-cports: $name: extracting $file failed" >&2; exit 1; } ;;
            *.zip) python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$file" "$dest" ||
                       { echo "stage-cports: $name: extracting $file failed" >&2; exit 1; } ;;
            *) echo "stage-cports: $file: unknown archive type" >&2; exit 1 ;;
        esac
        [ "$(ls -A "$dest" | wc -l)" -eq 1 ] || { echo "stage-cports: $name: $dest does not hold exactly one top-level entry" >&2; exit 1; }
        [ -f "$dest/$want" ] || { echo "stage-cports: $name: $dest/$want is absent" >&2; exit 1; }
        chmod -R a-w "$dest"           # extracted trees are read-only: no build may write into them
    done
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$version" "$sha" "$(ls "$up/$name/linux")" "$want" >> "$stage.tmp"
done
mv "$stage.tmp" "$stage"
cat "$stage"
echo "CPORTS STAGE OK programs=$(wc -l < "$stage")"
