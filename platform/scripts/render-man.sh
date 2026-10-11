#!/bin/sh
# Renders the manual for the image. The pages' source is mdoc(7) in
# man/NAME.S; ABSD has no roff, so each page is rendered here, on the build
# host, to plain ASCII with the GNU groff that scripts/verify-inputs.sh
# pins, and installed as /share/man/catS/NAME.0 (scripts/ssh_absd.py).
# man(1) on ABSD only copies the file. Also writes the index `man -k`
# searches, /share/man/whatis: one `NAME(S) - DESCRIPTION` line per page.
#
# Every page must lint clean (`groff -ww -z`), name itself in `.Dt`, and
# render to printable ASCII lines only. Output: manpages/.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
out=$root/manpages
groff=/usr/bin/groff

fail() {
    printf '%s\n' "render-man: $*" >&2
    exit 1
}

# A clean environment: no GROFF_* variables, no locale, the pinned binary.
run_groff() {
    env -i PATH=/usr/bin:/bin LC_ALL=C "$groff" "$@"
}

version=$(run_groff --version | sed -n 1p)
test "$version" = "GNU groff version 1.23.0" || fail "unexpected groff: $version"

rm -rf "${out:?}"
mkdir -p "$out"
index=$out/whatis.unsorted
: >"$index"
count=0
names=
for source in "$root"/man/*.[1-9]; do
    test -f "$source" || fail "no pages under $root/man"
    file=$(basename "$source")
    name=${file%.*}
    section=${file##*.}
    upper=$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')
    title=$(sed -n 's/^\.Dt  *//p' "$source")
    test "$title" = "$upper $section" || fail "$file: .Dt is '$title', not '$upper $section'"
    description=$(sed -n 's/^\.Nd  *//p' "$source")
    test -n "$description" || fail "$file: no .Nd"
    warnings=$(run_groff -mdoc -ww -z "$source" 2>&1)
    test -z "$warnings" || fail "$file: groff warnings:
$warnings"
    mkdir -p "$out/cat$section"
    page=$out/cat$section/$name.0
    # -P-cbou: no SGR escapes and no overstriking, so the page is plain
    # text on any terminal; HY=0 and AD=l: no hyphenation, ragged right.
    run_groff -mdoc -Tascii -P-cbou -rHY=0 -dAD=l "$source" >"$page"
    if LC_ALL=C grep -q '[^ -~]' "$page"; then
        fail "$file: rendered page has bytes other than printable ASCII"
    fi
    head -n 1 "$page" | grep -q "^$upper($section) " || fail "$file: rendered page has no $upper($section) header"
    printf '%s(%s) - %s\n' "$name" "$section" "$description" >>"$index"
    count=$((count + 1))
    names="${names:+$names,}$name($section)"
done
LC_ALL=C sort "$index" >"$out/whatis"
rm -f "$index"
printf '%s\n' "ABSD MAN RENDERED pages=$count names=$names"
