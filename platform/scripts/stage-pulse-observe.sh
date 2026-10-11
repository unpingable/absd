#!/bin/sh
# Stages the ABSD-owned frame-pressure support family: the pinned Pulse
# source, the carried ABSD platform patch for pulse-nq-load-support, then
# patches/pulse-absd-frame-pressure.patch, which copies that crate to
# crates/pulse-absd-frame-pressure and changes only the family (the source,
# the state derivation, the validity, the identities). Its own staged tree
# and lock (pins/pulse-observe-absd.Cargo.lock); the Pulse resolver's stage
# (scripts/stage-pulse.sh) is untouched.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
pulse=$(absd_source PULSE)
commit=81c2354674990679f43be4f207349ff1b2429bc7
tree=b3f746c4e16b5303d0fd7bf98b327bfa14382951
stage=$(dirname "$root")/absd-std-staged-pulse-observe
platform=$root/patches/pulse-nq-load-support-absd.patch
family=$root/patches/pulse-absd-frame-pressure.patch

rm -rf "${stage:?}"
mkdir -p "$stage"
absd_stage_input Pulse "$pulse" "$commit" "$tree" "$stage"
(cd "$stage" &&
    export GIT_CEILING_DIRECTORIES="$(dirname "$stage")" &&
    git apply --check "$platform" && git apply "$platform" &&
    git apply --check "$family" && git apply "$family" &&
    git apply --reverse --check "$platform")
# The family patch copies the ported crate (a reverse check would try to
# re-create the copy's source), so check the other way: the platform patch
# still reverses, and the copied crate exists beside the untouched original.
test -f "$stage/crates/pulse-nq-load-support/src/platform.rs"
test -z "$(find "$stage" \( -name '*.rej' -o -name '*.orig' \) -print -quit)"
test -f "$stage/crates/pulse-absd-frame-pressure/src/platform.rs"
# The family's pinned identities are the digests of the documents here.
for document in question profile threshold-policy; do
    digest=$(sha256sum "$root/observe/$document.v1.json" | cut -d' ' -f1)
    grep -q "sha256:$digest" "$stage/crates/pulse-absd-frame-pressure/src/lib.rs" || \
        { echo "stage-pulse-observe: $document digest is not pinned by the family" >&2; exit 1; }
done
ln -s "$root" "$stage/absd-platform"
cp "$root/pins/pulse-observe-absd.Cargo.lock" "$stage/Cargo.lock"
printf '%s\n' 'ABSD PULSE FRAME PRESSURE PATCH APPLY OK'
