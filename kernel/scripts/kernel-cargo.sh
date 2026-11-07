#!/bin/sh
# Apply the source mapping to dependencies as well as the final kernel.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
exec python3 "$root/scripts/rust-build-flags.py" kernel "$root" "$@"
