#!/bin/sh
# Stages the source-portability probe's programs (compat/programs.tsv,
# docs/COMPATIBILITY-LEDGER.md) beside this repository, in
# `absd-std-staged-compat/`:
#   linux/<crate>  the registry archive exactly as published, for the Linux
#                  reference build with its own Cargo.lock;
#   absd/<crate>   the same archive with one stanza appended to Cargo.toml,
#                  absd-runtime as an ABSD-only dependency (it holds the CRT
#                  entry, the allocator, and std's hooks, which an unmodified
#                  program never names), and pins/compat/<crate>-<ver>.Cargo.lock.
# No source file is changed. Each archive is checked against its crates.io
# checksum, and each pinned lock against the archive's own lock: it may add
# packages (absd-runtime and its closure) and drop unused ones, never change
# the version or checksum of a package the upstream lock pins.
#
# A pinned lock is regenerated, after the stanza changes, by copying the
# archive's lock into absd/<crate>, running `cargo metadata --offline`
# (without --locked, which keeps every existing pin), and copying the result
# to pins/compat; the check below then shows the diff is only local.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
stage=$(dirname "$root")/absd-std-staged-compat
cache=${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f

rm -rf "${stage:?}/linux" "${stage:?}/absd"
mkdir -p "$stage/linux" "$stage/absd"
grep -v '^#' "$root/compat/programs.tsv" | while IFS="$(printf '\t')" read -r crate version sum bin expect signature; do
    archive=$cache/$crate-$version.crate
    test "$(sha256sum "$archive" | cut -d' ' -f1)" = "$sum" ||
        { echo "stage-compat: $archive does not match its crates.io checksum" >&2; exit 1; }
    tar -xzf "$archive" -C "$stage/linux"
    tar -xzf "$archive" -C "$stage/absd"
    dir=$stage/absd/$crate-$version
    printf '\n%s\n%s\n' \
        "[target.'cfg(target_os = \"absd\")'.dependencies.absd-runtime]" \
        "path = \"$root/runtime\"" >> "$dir/Cargo.toml"
    cp "$root/pins/compat/$crate-$version.Cargo.lock" "$dir/Cargo.lock"
    python3 - "$stage/linux/$crate-$version/Cargo.lock" "$dir/Cargo.lock" <<'PY'
import os, sys, tomllib
upstream, pinned = sys.argv[1], sys.argv[2]
if not os.path.exists(upstream):
    # The archive ships no lock (xsv 0.13.0): the pin is the local resolution.
    print(f"COMPAT LOCK {pinned.split('/')[-2]} no upstream lock")
    sys.exit(0)
def load(path):
    return {(p["name"], p["version"]): p.get("checksum")
            for p in tomllib.load(open(path, "rb"))["package"]}
up, pin = load(upstream), load(pinned)
def line(version):
    # Cargo keeps one version per semver-compatible line.
    parts = version.split("+")[0].split("-")[0].split(".")
    return tuple(parts[:2]) if parts[0] == "0" else (parts[0],)
for (name, version), checksum in pin.items():
    if (name, version) in up:
        if up[(name, version)] != checksum:
            sys.exit(f"{pinned}: {name} {version} checksum differs from upstream")
for name, version in set(up) - set(pin):
    for other, other_version in pin:
        if other == name and line(other_version) == line(version):
            sys.exit(f"{pinned}: {name} {other_version} replaces the upstream pin {version}")
added = sorted(name for name, version in pin if (name, version) not in up)
print(f"COMPAT LOCK {pinned.split('/')[-2]} added={len(added)} dropped={len(set(up) - set(pin))}")
PY
done
printf '%s\n' 'ABSD COMPAT STAGED OK'
