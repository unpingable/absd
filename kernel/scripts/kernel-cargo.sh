#!/bin/sh
# Apply the source mapping to dependencies as well as the final kernel.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
source_map=$(sh "$root/scripts/rust-source-map.sh")
if [ "${CARGO_ENCODED_RUSTFLAGS+x}" = x ]; then
    separator=$(printf '\037')
    export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS}${CARGO_ENCODED_RUSTFLAGS:+$separator}--remap-path-prefix=$source_map"
else
    export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$source_map"
fi
exec cargo "$@"
