#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
output="$root/.host-target/runtime-allocator"
mkdir -p "$output"
env -u RUSTFLAGS rustc +1.95.0 --edition 2024 --target x86_64-unknown-linux-gnu \
    --test "$root/tests/runtime_allocator.rs" -o "$output/tests"
"$output/tests"
printf '%s\n' 'ABSD RUNTIME ALLOCATOR HOST TEST OK'
