#!/bin/sh
# Keep rustc's installed source lookup equal to its shipped virtual paths.
# Print one FROM=TO value for --remap-path-prefix, not shell source.
set -eu
compiler=${RUSTC:-rustc}
sysroot=$("$compiler" --print sysroot)
commit=$("$compiler" -vV | sed -n 's/^commit-hash: //p')
case "$commit" in
    ''|*[!0-9a-f]*) echo 'rust-source-map: compiler lacks a full commit hash' >&2; exit 1 ;;
esac
[ "${#commit}" -eq 40 ] && [ -d "$sysroot/lib/rustlib" ] ||
    { echo 'rust-source-map: invalid compiler identity or sysroot' >&2; exit 1; }
printf '%s/lib/rustlib/src/rust=/rustc/%s\n' "$sysroot" "$commit"
