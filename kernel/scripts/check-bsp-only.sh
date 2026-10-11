#!/bin/sh
set -eu

log=$(mktemp)
trap 'rm -f "$log"' EXIT HUP INT TERM
if cargo check --bin absd-kernel --features ap-startup >"$log" 2>&1; then
    echo 'bsp-only: AP startup feature unexpectedly built' >&2
    exit 1
fi
if ! grep -q 'SMP_SERIALIZATION_LIFECYCLE refuses generic AP startup' "$log"; then
    cat "$log" >&2
    echo 'bsp-only: expected compile-time refusal was absent' >&2
    exit 1
fi
echo 'BSP ONLY BUILD GUARD OK'
