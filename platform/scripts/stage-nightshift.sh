#!/bin/sh
# Stages the pinned Nightshift source with the carried ABSD platform patch,
# for the ABSD build of its read-only observation resolver. The tree is
# `git archive` of the exact commit; `absd-platform` inside it links back to
# this repository, which the patch's ABSD-only dependencies name.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
nightshift=$(absd_source NIGHTSHIFT)
commit=e2675dd854dbfe633bf14456595d722e88bf92bc
tree=bd7afe042251fc4f007413871589a01d26e0583f
stage=$(dirname "$root")/absd-std-staged-nightshift
patch=$root/patches/nightshiftd-absd.patch

rm -rf "$stage"
mkdir -p "$stage"
absd_stage_input Nightshift "$nightshift" "$commit" "$tree" "$stage"
(cd "$stage" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply --check "$patch" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply "$patch" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply --reverse --check "$patch")
test -z "$(find "$stage" \( -name '*.rej' -o -name '*.orig' \) -print -quit)"
test -f "$stage/crates/nightshiftd/src/platform.rs"
ln -s "$root" "$stage/absd-platform"
cp "$root/pins/nightshift-absd.Cargo.lock" "$stage/Cargo.lock" 2>/dev/null || true
printf '%s\n' 'ABSD NIGHTSHIFT PATCH APPLY OK'
