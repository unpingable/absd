#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
pulse=$(absd_source PULSE)

"$root/scripts/verify-inputs.sh"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
"$root/scripts/run-external.sh" \
    "$root/pulse-std.elf" "$pulse/traces/demo.jsonl" \
    "$pulse/artifacts/demo-report.json" 'ABSD RUST STD PULSE OK'
