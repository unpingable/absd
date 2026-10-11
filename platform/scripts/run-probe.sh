#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
"$root/scripts/run-external.sh" \
    "$root/probe.elf" "$root/input.txt" "$root/expected.txt" \
    'ABSD RUST STD PROBE OK'
