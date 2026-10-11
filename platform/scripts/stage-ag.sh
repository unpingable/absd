#!/bin/sh
# Stages the pinned AG source tree with the carried ABSD platform patch. The
# tree is `git archive` of the exact commit, so local edits in the AG
# checkout can never leak in; the patch must apply exactly and reverse.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
ag=$(absd_source AG)
commit=21c8da079f2465a2466c54431cc315699fc57cbe
tree=3c44f564e2be9add17224954f6e5bb45ccdec84c
stage=$(dirname "$root")/absd-std-staged-ag
patch=$root/patches/ag-store-absd.patch

rm -rf "$stage"
mkdir -p "$stage"
absd_stage_input AG "$ag" "$commit" "$tree" "$stage"
(cd "$stage" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply --check "$patch" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply "$patch" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply --reverse --check "$patch")
test -z "$(find "$stage" \( -name '*.rej' -o -name '*.orig' \) -print -quit)"
test -f "$stage/crates/ag-store/src/platform.rs"
printf '%s\n' 'ABSD AG PATCH APPLY OK'
