#!/bin/sh
# Public snapshot: the omitted TinyCC stage is never a passing test.
printf '%s\n' 'TCC STAGE NOT_RUN: not included in the public source' >&2
exit 78
# Stages TinyCC at the commit pinned in tcc/PIN into tcc-build/upstream (a
# fresh clone in its own directory, never modified afterwards). Verifies: the
# commit object exists and is what `git rev-parse` resolves; the checked-out
# tree has no changes against it; the commit is reachable from the mob branch
# of at least one listed mirror (ls-remote + fetch, 30 s timeout each when
# timeout(1) exists), else from the clone's own origin/mob ref (weaker: it only
# proves reachability as of the clone); the sha256 and byte count of
# `git archive` equal the pin's archive_sha256 and archive_bytes. When either
# says RECORD_ON_FIRST_STAGING the values are printed and the script exits 2
# without writing stage.txt. Writes tcc-build/stage.txt, one tab-separated
# line: name, commit, archive sha256, archive bytes, reachable_from (a mirror
# URL, or origin/mob). The checked-out tree is made read-only; .git stays
# writable so later runs can fetch mirror refs. Second run: verifies and exits
# 0 without re-cloning.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
out=$camp/tcc-build
pin=$root/tcc/PIN
commit=$(awk '$1=="commit"{print $2}' "$pin")
want=$(awk '$1=="archive_sha256"{print $2}' "$pin")
want_bytes=$(awk '$1=="archive_bytes"{print $2}' "$pin")
origins=$(awk '$1=="origin"{for(i=2;i<=NF;i++)print $i}' "$pin")
[ -n "$commit" ] && [ -n "$want" ] && [ -n "$want_bytes" ] && [ -n "$origins" ] || { echo "stage-tcc: $pin lacks commit, archive_sha256, archive_bytes or origin" >&2; exit 1; }
up=$out/upstream
arc=$out/tcc-archive.tmp.$$
trap 'rm -rf "$out/upstream.tmp" "$arc"' EXIT
net() { if command -v timeout >/dev/null 2>&1; then timeout 30 "$@"; else "$@"; fi; }
mkdir -p "$out"
if [ ! -e "$up" ]; then
    cloned=no
    for origin in $origins; do
        rm -rf "$out/upstream.tmp"
        if git clone -q --no-checkout "$origin" "$out/upstream.tmp"; then cloned=$origin; break; fi
        echo "stage-tcc: clone of $origin failed" >&2
    done
    [ "$cloned" != no ] || { echo "stage-tcc: no origin could be cloned" >&2; exit 1; }
    git -C "$out/upstream.tmp" cat-file -e "$commit^{commit}" || { echo "stage-tcc: $commit not in the clone" >&2; exit 1; }
    git -C "$out/upstream.tmp" checkout -q "$commit" || { echo "stage-tcc: checkout of $commit failed" >&2; exit 1; }
    mv "$out/upstream.tmp" "$up"
elif [ ! -d "$up/.git" ]; then
    echo "stage-tcc: $up exists but is not a git clone; remove it to restage" >&2; exit 1
fi
head=$(git -C "$up" rev-parse HEAD)
[ "$head" = "$commit" ] || { echo "stage-tcc: upstream is at $head, pin is $commit" >&2; exit 1; }
# The checked-out tree read-only (not .git, not through symlinks), then checked.
find "$up" \( -path "$up/.git" -o -type l \) -prune -o -exec chmod a-w {} +
[ -z "$(find "$up" \( -path "$up/.git" -o -type l \) -prune -o -perm /222 -print)" ] || { echo "stage-tcc: $up still has writable entries" >&2; exit 1; }
dirty=$(git -C "$up" status --porcelain) || { echo "stage-tcc: git status failed in $up" >&2; exit 1; }
[ -z "$dirty" ] || { echo "stage-tcc: $up differs from $commit:" >&2; echo "$dirty" >&2; exit 1; }
# Reachability from a mirror's mob branch (any one suffices; network may be absent: then the clone's own origin/mob ref is used).
reach=no
for m in $(awk '$1=="mirrors"{for(i=2;i<=NF;i++)print $i}' "$pin"); do
    tip=$(net git ls-remote -q "$m" refs/heads/mob 2>/dev/null | awk '{print $1}') || tip=
    [ -n "$tip" ] || continue
    net git -C "$up" fetch -q "$m" "+refs/heads/mob:refs/mirrors/$(echo "$m" | tr -c 'A-Za-z0-9' _)" 2>/dev/null || continue
    git -C "$up" merge-base --is-ancestor "$commit" "$tip" 2>/dev/null && { reach=$m; break; }
done
if [ "$reach" = no ]; then
    git -C "$up" merge-base --is-ancestor "$commit" origin/mob || { echo "stage-tcc: $commit not reachable from any mob branch" >&2; exit 1; }
    reach=origin/mob
fi
# The archive goes to a file first: POSIX sh has no pipefail.
git -C "$up" archive --format=tar --prefix=tcc/ "$commit" > "$arc" || { echo "stage-tcc: git archive of $commit failed" >&2; exit 1; }
[ -s "$arc" ] || { echo "stage-tcc: git archive of $commit is empty" >&2; exit 1; }
got=$(sha256sum "$arc" | awk '{print $1}')
bytes=$(wc -c < "$arc" | tr -d ' ')
rm -f "$arc"
case $got in *[!0-9a-f]*|'') echo "stage-tcc: bad sha256 '$got'" >&2; exit 1;; esac
[ ${#got} -eq 64 ] || { echo "stage-tcc: bad sha256 '$got'" >&2; exit 1; }
if [ "$want" = RECORD_ON_FIRST_STAGING ] || [ "$want_bytes" = RECORD_ON_FIRST_STAGING ]; then
    echo "stage-tcc: RECORD archive_sha256 $got and archive_bytes $bytes in tcc/PIN, then run again" >&2
    exit 2
fi
[ "$got" = "$want" ] || { echo "stage-tcc: archive sha256 $got != pinned $want" >&2; exit 1; }
[ "$bytes" = "$want_bytes" ] || { echo "stage-tcc: archive bytes $bytes != pinned $want_bytes" >&2; exit 1; }
printf 'tcc\t%s\t%s\t%s\t%s\n' "$commit" "$got" "$bytes" "$reach" > "$out/stage.txt"
echo "TCC STAGE OK commit=$commit archive_sha256=$got bytes=$bytes reachable_from=$reach"
