#!/bin/sh
# Stages the pinned Pulse source tree, unpatched, for the integration
# workspace (integration/), whose manifest names the Pulse crates there (as
# it names AG's in the tree scripts/stage-ag.sh makes). Its own directory: scripts/stage-pulse.sh and
# scripts/stage-pulse-observe.sh stage patched trees for other builds.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
pulse=$(absd_source PULSE)
commit=81c2354674990679f43be4f207349ff1b2429bc7
tree=b3f746c4e16b5303d0fd7bf98b327bfa14382951
stage=$(dirname "$root")/absd-std-staged-pulse-source

rm -rf "${stage:?}"
mkdir -p "$stage"
absd_stage_input Pulse "$pulse" "$commit" "$tree" "$stage"
printf '%s\n' 'ABSD PULSE SOURCE STAGE OK'
