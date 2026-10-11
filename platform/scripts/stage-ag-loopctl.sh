#!/bin/sh
# Stages AG (pinned 21c8da0) for the ABSD build of `ag-loopctl`: `git
# archive` of the exact commit, then patches/ag-store-absd.patch (the store's
# platform seam, the same patch the root workspace's staged AG tree carries)
# and patches/ag-loopctl-absd.patch (ag-app's platform seam), each applying
# exactly and reversing. The patches touch no manifest or lockfile of AG's
# except ag-store's (Unix-only libc/nix/rustix). The build runs from a
# separate consumer workspace (`absd-ag/`, from ag/Cargo.toml and the pinned
# lock), whose registry versions must all be ones AG's own lock pins.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
ag=$(absd_source AG)
commit=21c8da079f2465a2466c54431cc315699fc57cbe
tree=3c44f564e2be9add17224954f6e5bb45ccdec84c
stage=$(dirname "$root")/absd-std-staged-ag-loopctl

rm -rf "${stage:?}"
mkdir -p "$stage"
absd_stage_input AG "$ag" "$commit" "$tree" "$stage"
if git apply --numstat "$root/patches/ag-loopctl-absd.patch" | awk '{print $3}' |
    grep -v '^crates/ag-app/src/'; then
    echo "ag-loopctl-absd.patch touches something outside ag-app's sources" >&2
    exit 1
fi
for patch in "$root/patches/ag-store-absd.patch" "$root/patches/ag-loopctl-absd.patch"; do
    (cd "$stage" &&
        GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply --check "$patch" &&
        GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply "$patch")
done
(cd "$stage" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply --reverse --check "$root/patches/ag-loopctl-absd.patch")
test -z "$(find "$stage" \( -name '*.rej' -o -name '*.orig' \) -print -quit)"
test -f "$stage/crates/ag-store/src/platform.rs"
test -f "$stage/crates/ag-app/src/platform.rs"
# ring 0.17.14 exactly as AG's lock pins it (the registry archive, checked
# against the lock's checksum), with patches/ring-absd.patch: its build
# script selects the pregenerated ELF x86_64 assembly for ABSD as for Linux.
ring_crate=${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f/ring-0.17.14.crate
test "$(sha256sum "$ring_crate" | cut -d' ' -f1)" = \
    a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7
tar -xzf "$ring_crate" -C "$stage"
mv "$stage/ring-0.17.14" "$stage/absd-ring"
(cd "$stage/absd-ring" &&
    GIT_CEILING_DIRECTORIES=$stage git apply --check "$root/patches/ring-absd.patch" &&
    GIT_CEILING_DIRECTORIES=$stage git apply "$root/patches/ring-absd.patch" &&
    GIT_CEILING_DIRECTORIES=$stage git apply --reverse --check "$root/patches/ring-absd.patch")
ln -s "$root" "$stage/absd-platform"
mkdir "$stage/absd-ag"
cp "$root/ag/Cargo.toml" "$stage/absd-ag/Cargo.toml"
cp "${ABSD_AG_SEED_LOCK:-$root/pins/ag-absd.Cargo.lock}" "$stage/absd-ag/Cargo.lock"
if [ -f "$stage/absd-ag/Cargo.lock" ]; then
python3 - "$stage/Cargo.lock" "$stage/absd-ag/Cargo.lock" <<'PY'
import sys, tomllib
ag = {}
for package in tomllib.load(open(sys.argv[1], "rb"))["package"]:
    ag.setdefault(package["name"], set()).add(package["version"])
for package in tomllib.load(open(sys.argv[2], "rb"))["package"]:
    if package.get("source", "").startswith("registry") and \
            package["version"] not in ag.get(package["name"], ()):
        sys.exit(f"ABSD lock resolves {package['name']} {package['version']}, which AG does not pin")
PY
fi
printf '%s\n' 'ABSD AG LOOPCTL PATCH APPLY OK'
