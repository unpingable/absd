#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
pulse=$(absd_source PULSE)
report=$root/.pulse-host-report.json

"$root/scripts/verify-inputs.sh"
rm -f "$report"
(cd "$pulse" &&
    CARGO_TARGET_DIR="$root/.host-target" \
    cargo +1.95.0 run --release --locked --offline \
        -p pulse-replay --bin pulse-replay -- \
        replay-json traces/demo.jsonl "$report")
cmp "$report" "$pulse/artifacts/demo-report.json"
test "$(wc -c < "$report")" -eq 29302
rm "$report"
printf '%s\n' 'ABSD RUST STD PULSE ORACLE OK bytes=29302'
