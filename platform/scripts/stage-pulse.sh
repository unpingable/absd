#!/bin/sh
# Stages the pinned Pulse source with the carried ABSD platform patch for
# the real `pulse-support-resolver` (crate pulse-nq-load-support). The tree
# is `git archive` of the exact commit; `absd-platform` inside it links back
# to this repository, which the patch's ABSD-only dependency names.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
pulse=$(absd_source PULSE)
commit=81c2354674990679f43be4f207349ff1b2429bc7
tree=b3f746c4e16b5303d0fd7bf98b327bfa14382951
stage=$(dirname "$root")/absd-std-staged-pulse
patch=$root/patches/pulse-nq-load-support-absd.patch

rm -rf "${stage:?}"
mkdir -p "$stage"
absd_stage_input Pulse "$pulse" "$commit" "$tree" "$stage"
(cd "$stage" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply --check "$patch" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply "$patch" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply --reverse --check "$patch")
test -z "$(find "$stage" \( -name '*.rej' -o -name '*.orig' \) -print -quit)"
test -f "$stage/crates/pulse-nq-load-support/src/platform.rs"
ln -s "$root" "$stage/absd-platform"
cp "$root/pins/pulse-absd.Cargo.lock" "$stage/Cargo.lock" 2>/dev/null || true
printf '%s\n' 'ABSD PULSE PATCH APPLY OK'
