#!/bin/sh
# Produces the frozen Pulse support fixture on Linux, with no ABSD code
# involved: the real pinned, unpatched `pulse-nq-load-support` binary runs
# its producer and receiver roles on this host (real /proc/loadavg, real
# Linux boot clock) under a test deployment configuration with a test key
# generated here, then its resolver answers once. Only public material is
# retained in OUT: the configuration (receipt paths rewritten to the ABSD
# mount), the signed receipts, the producer envelopes, the query, the
# Linux answer, and provenance. The private test key is discarded.
#
#   make-pulse-fixture.sh OUT
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
out=${1:?output directory}
. "$root/scripts/inputs.sh"
pulse=$(absd_source PULSE)
commit=81c2354674990679f43be4f207349ff1b2429bc7
tree=b3f746c4e16b5303d0fd7bf98b327bfa14382951
linux=$(dirname "$root")/absd-std-pulse-linux
work=$(dirname "$root")/absd-std-pulse-fixture-work

test ! -e "$out" || { echo "refusing to overwrite $out" >&2; exit 1; }
rm -rf "${linux:?}" "${work:?}"
mkdir -p "$linux" "$work"
absd_stage_input Pulse "$pulse" "$commit" "$tree" "$linux"
(cd "$linux" && env -u RUSTFLAGS cargo build --release --locked --offline \
    -p pulse-nq-load-support --bin pulse-nq-load-support)
python3 "$root/scripts/pulse_fixture.py" make --binary "$linux/target/release/pulse-nq-load-support" \
    --work "$work" --out "$out" --pulse-commit "$commit"
rm -rf "${work:?}" "${linux:?}"
printf '%s\n' "ABSD PULSE FIXTURE OK $out"
