#!/bin/sh
# Stages sunset 0.6.0 for the SSH server (ssh/): the registry archive,
# checked against its crates.io checksum, extracted beside this
# repository as `absd-std-staged-ssh/sunset`, with
# patches/sunset-server-channel.patch applied exactly and reversible. The
# patch adds the server's channel EOF, exit-status and close and stops the
# server echoing a peer's EOF (PATCH_AUDIT.md); it touches no manifest.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
stage=$(dirname "$root")/absd-std-staged-ssh
crate=${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f/sunset-0.6.0.crate
expected=3b52312b804ac95f10d3963f6ef5889117ad678bd6ce977be4aa4cf491bad78f

test "$(sha256sum "$crate" | cut -d' ' -f1)" = "$expected"
# A patched path dependency has no checksum in the lock: it must name
# sunset 0.6.0 exactly once and from no registry.
if [ -f "$root/ssh/Cargo.lock" ]; then
python3 - "$root/ssh/Cargo.lock" <<'PY'
import sys, tomllib
pins = [p for p in tomllib.load(open(sys.argv[1], "rb"))["package"] if p["name"] == "sunset"]
if len(pins) != 1 or pins[0]["version"] != "0.6.0" or "source" in pins[0]:
    sys.exit(f"ssh/Cargo.lock does not resolve sunset to the staged 0.6.0: {pins}")
PY
fi
if git apply --numstat "$root/patches/sunset-server-channel.patch" | awk '{print $3}' |
    grep -v '^src/'; then
    echo "sunset-server-channel.patch touches something outside sunset's sources" >&2
    exit 1
fi
rm -rf "${stage:?}"
mkdir -p "$stage"
tar -xzf "$crate" -C "$stage"
mv "$stage/sunset-0.6.0" "$stage/sunset"
(cd "$stage/sunset" &&
    GIT_CEILING_DIRECTORIES=$stage git apply --check "$root/patches/sunset-server-channel.patch" &&
    GIT_CEILING_DIRECTORIES=$stage git apply "$root/patches/sunset-server-channel.patch" &&
    GIT_CEILING_DIRECTORIES=$stage git apply --reverse --check "$root/patches/sunset-server-channel.patch")
# The archive itself carries Cargo.toml.orig (cargo's original manifest).
test -z "$(find "$stage" \( -name '*.rej' -o -name '*.orig' \) \
    ! -path "$stage/sunset/Cargo.toml.orig" -print -quit)"
grep -q 'pub fn send_exit_status' "$stage/sunset/src/runner.rs"
printf '%s\n' 'ABSD SSH SUNSET PATCH APPLY OK'
