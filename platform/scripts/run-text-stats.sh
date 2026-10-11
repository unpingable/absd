#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
"$root/scripts/run-external.sh" \
    "$root/text-stats.elf" "$root/text-stats-input.txt" \
    "$root/text-stats-expected.txt" 'ABSD RUST TEXT STATS OK'
