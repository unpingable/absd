#!/bin/sh
# Stage the base userland's upstream (userland/PIN): download the tarball
# into an empty directory if absent, verify its sha256 against the pin before
# anything reads it, extract it into a fresh directory beside the repository
# (never inside it), make the extracted tree read-only, and check that the
# licence file in it is the one carried as userland/<name>.LICENSE.
# Layout: $ABSD_USERLAND_UPSTREAM (default $camp/upstream)/<name>/dl/<tarball>
# and .../<name>/src/<top-level directory>.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
up=${ABSD_USERLAND_UPSTREAM:-$camp/upstream}
pin=$root/userland/PIN
bad=$(grep -v '^#' "$pin" | awk -F'\t' 'NF { if (NF != 5) { print; next } for (i = 1; i <= NF; i++) if ($i == "") { print; next } }')
[ -z "$bad" ] || { echo "stage-userland: userland/PIN rows without five non-empty fields: $bad" >&2; exit 1; }
tab=$(printf '\t')
n=0
grep -v '^#' "$pin" | grep -v '^[[:space:]]*$' > "${TMPDIR:-/tmp}/stage-userland.$$"
trap 'rm -f "${TMPDIR:-/tmp}/stage-userland.$$"' EXIT
while IFS="$tab" read -r name version url sha licence; do
    case $name in
        toybox) top=toybox-$version; want= ;;
        sbase) top=sbase-$version; want="$top/LICENSE $top/libutil/getlines.c $top/grep.c" ;;
        *) echo "stage-userland: $name: no expected files recorded" >&2; exit 1 ;;
    esac
    dl=$up/$name/dl; mkdir -p "$dl"
    file=$dl/$(basename "$url")
    if ! [ -f "$file" ]; then
        tmp=$(mktemp -d "$dl/fetch.XXXXXX")
        curl -fsSL --retry 3 -o "$tmp/$(basename "$url")" "$url" ||
            { rm -rf "$tmp"; echo "stage-userland: $name: download of $url failed" >&2; exit 1; }
        # verify before the file takes its place, so a bad download is not kept
        got=$(sha256sum "$tmp/$(basename "$url")" | cut -d' ' -f1)
        [ "$got" = "$sha" ] || { rm -rf "$tmp"; echo "stage-userland: $name: sha256 mismatch: download of $url is $got, userland/PIN says $sha (not kept)" >&2; exit 1; }
        mv "$tmp/$(basename "$url")" "$file"; rmdir "$tmp"
    fi
    got=$(sha256sum "$file" | cut -d' ' -f1)
    [ "$got" = "$sha" ] || { echo "stage-userland: $name: sha256 mismatch: $file is $got, userland/PIN says $sha" >&2; exit 1; }
    if [ "$name" = toybox ]; then
        # Source-specific stagers verify archive, selected members, license,
        # adaptation patch and resulting source before accepting output.
        dest=$up/toybox/src
        [ ! -e "$dest" ] || chmod -R u+w "$dest"
        rm -rf "$dest"; mkdir -p "$dest"
        for utility in diff hexdump; do
            python3 -I "$root/scripts/stage-$utility.py" "$file" "$dest/$utility"
        done
        chmod -R a-w "$dest"
        echo "USERLAND STAGE OK toybox $version sha256=$sha licence=$licence src=$dest"
        n=$((n + 1))
        continue
    fi
    dest=$up/$name/src
    [ -e "$dest" ] && chmod -R u+w "$dest"
    rm -rf "$dest"; mkdir -p "$dest"
    case $file in
        *.tar.gz) tar -xzf "$file" -C "$dest" --no-same-owner --no-same-permissions ||
                      { echo "stage-userland: $name: extracting $file failed" >&2; exit 1; } ;;
        *) echo "stage-userland: $file: unknown archive type" >&2; exit 1 ;;
    esac
    [ "$(ls -A "$dest")" = "$top" ] || { echo "stage-userland: $name: $dest does not hold exactly $top" >&2; exit 1; }
    for f in $want; do [ -f "$dest/$f" ] || { echo "stage-userland: $name: $dest/$f is absent" >&2; exit 1; }; done
    cmp -s "$dest/$top/LICENSE" "$root/userland/$name.LICENSE" ||
        { echo "stage-userland: $name: $top/LICENSE differs from userland/$name.LICENSE" >&2; exit 1; }
    chmod -R a-w "$dest"
    echo "USERLAND STAGE OK $name $version sha256=$sha licence=$licence src=$dest/$top"
    n=$((n + 1))
done < "${TMPDIR:-/tmp}/stage-userland.$$"
[ "$n" -gt 0 ] || { echo "stage-userland: userland/PIN names nothing" >&2; exit 1; }
