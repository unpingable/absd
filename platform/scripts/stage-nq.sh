#!/bin/sh
# Stages NQ-NG (pinned 8057441) for the ABSD build of `nq`: `git archive` of
# the exact commit plus patches/nq-absd.patch, which changes only Rust
# sources. The NQ workspace's manifests, lockfile, toolchain file, and the
# nq-profiles/nq-protocol sources stay byte-identical, because nq-profiles's
# build script hashes them into the profile digest that `diagnostics
# qualify` checks against the store. The ABSD build runs from a separate
# consumer workspace (`absd-nq/`, from nq/Cargo.toml and the pinned lock),
# which the digest does not read.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
nq=$(absd_source NQ)
commit=80574417f0188afd37992db7ac764a6f0f72ff62
tree=13c0b6b36ec26b941adc586088275df248360492
stage=$(dirname "$root")/absd-std-staged-nq
patch=$root/patches/nq-absd.patch

rm -rf "$stage"
mkdir -p "$stage"
absd_stage_input NQ-NG "$nq" "$commit" "$tree" "$stage"
# The patch must not touch any input of the profile digest.
if git apply --numstat "$patch" | awk '{print $3}' |
    grep -E '(^|/)Cargo\.(toml|lock)$|^rust-toolchain\.toml$|^crates/nq-(profiles|protocol)/'; then
    echo "nq-absd.patch touches a profile-digest input" >&2
    exit 1
fi
(cd "$stage" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply --check "$patch" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply "$patch" &&
    GIT_CEILING_DIRECTORIES=$(dirname "$stage") git apply --reverse --check "$patch")
test -z "$(find "$stage" \( -name '*.rej' -o -name '*.orig' \) -print -quit)"
test -f "$stage/crates/nq-core/src/platform.rs"
ln -s "$root" "$stage/absd-platform"
mkdir "$stage/absd-nq"
cp "$root/nq/Cargo.toml" "$stage/absd-nq/Cargo.toml"
cp "$root/pins/nq-absd.Cargo.lock" "$stage/absd-nq/Cargo.lock"
# Every registry package the ABSD build resolves is a version NQ's own lock
# pins: the consumer lock changes the graph's shape, never a version.
python3 - "$stage/Cargo.lock" "$stage/absd-nq/Cargo.lock" <<'PY'
import sys, tomllib
nq = {}
for package in tomllib.load(open(sys.argv[1], "rb"))["package"]:
    nq.setdefault(package["name"], set()).add(package["version"])
for package in tomllib.load(open(sys.argv[2], "rb"))["package"]:
    if package.get("source", "").startswith("registry") and \
            package["version"] not in nq.get(package["name"], ()):
        sys.exit(f"ABSD lock resolves {package['name']} {package['version']}, which NQ does not pin")
PY
printf '%s\n' 'ABSD NQ PATCH APPLY OK'
