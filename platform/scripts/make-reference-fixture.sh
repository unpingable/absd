#!/bin/sh
# Produces the Linux reference for the native Nightshift pipeline and the
# native AG path, in place (fixtures/nightshift-pipeline, fixtures/ag-native),
# with no ABSD code involved: scripts/reference_fixture.py runs the real
# pinned, unpatched Linux programs over the NQ fixture (fixtures/nq) under
# fixed synthetic deployment names and test keys derived from published
# seeds. See that script for what is fixed and what varies.
#
#   make-reference-fixture.sh LINUX_BIN
#
# LINUX_BIN holds the Linux builds of the pinned sources: ag-loopctl,
# nightshift, nightshift-observation-resolver, nq (a debug build: the NQ
# fixture store's admission lock allows the same identity only there) and
# pulse-nq-load-support. reference_fixture.py lists each one's commit and
# build command; fixtures/ag-native/manifest.json records the digests of the
# ones used. The request builder is built here against the pinned Nightshift.
#
# The reference lives at /tmp/absd-reference while it is produced (AG's
# sealed runtime profile pins absolute paths, and the AG matrix's Linux
# twin mounts the reference there again); it must not exist beforehand and
# is removed afterwards. Afterwards, update the pin of
# fixtures/ag-native/manifest.json in scripts/verify-inputs.sh.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
linux_bin=${1:?directory of the Linux programs}
. "$root/scripts/inputs.sh"
nightshift_source=$(absd_source NIGHTSHIFT)
nightshift_commit=e2675dd854dbfe633bf14456595d722e88bf92bc
nightshift_tree=bd7afe042251fc4f007413871589a01d26e0583f
work=$(dirname "$root")/absd-std-reference-fixture-work
reference=/tmp/absd-reference

test ! -e "$reference" || { echo "refusing to overwrite $reference" >&2; exit 1; }
rm -rf "${work:?}"
# The builder names Nightshift at ../../src/nightshift.
mkdir -p "$work/src/nightshift" "$work/tools"
absd_stage_input Nightshift "$nightshift_source" "$nightshift_commit" "$nightshift_tree" "$work/src/nightshift"
cp -R "$root/fixtures/nightshift-pipeline/tools/request-builder" "$work/tools/request-builder"
(cd "$work/tools/request-builder" && env -u RUSTFLAGS cargo build --release --locked --offline \
    --target-dir "$work/target")
gcc -shared -fPIC -O2 -Wall -Werror -o "$work/twin-shim.so" "$root/tools/ag-linux-twin/twin-shim.c" -ldl
python3 "$root/scripts/reference_fixture.py" make --linux-bin "$linux_bin" \
    --request-builder "$work/target/release/laned-request-builder" --shim "$work/twin-shim.so" \
    --fixtures "$root/fixtures"
chmod -R u+w "$reference"
rm -rf "${work:?}" "${reference:?}"
printf '%s\n' 'ABSD REFERENCE FIXTURE OK'
