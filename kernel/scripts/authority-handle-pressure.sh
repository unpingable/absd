#!/bin/sh
# Uses the already-qualified actual kernel host library; allocation trace only.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
out=${1:?fresh output directory}
mkdir "$out"
lib=${2:-}
if [ -z "$lib" ]; then
    set -- "${CARGO_TARGET_DIR:-target}"/debug/deps/libabsd_kernel-*.rlib
    if [ "$#" -ne 1 ]; then
        echo 'pressure trace: select the exact qualified library as argument 2' >&2
        exit 1
    fi
    lib=$1
fi
test -f "$lib"
sha256sum "$lib" scripts/authority-handle-pressure.rs > "$out/inputs.sha256"
git rev-parse HEAD > "$out/kernel.source"
rustc --version > "$out/rustc.version"
rustc --edition=2024 scripts/authority-handle-pressure.rs \
    -L "dependency=$(dirname "$lib")" --extern "absd_kernel=$lib" \
    -o "$out/trace"
sha256sum "$out/trace" > "$out/executable.sha256"
"$out/trace" > "$out/result.log"
grep -qx 'HANDLE PRESSURE TRACE initial=61 startup-peak=64 pre-spawn=63 published=64 wait-copy=Full source-authority=unchanged' "$out/result.log"
grep -qx 'HANDLE PRESSURE TRACE close-startup-reader=true wait-copy=granted right=WAIT limit=64' "$out/result.log"
grep -qx 'HANDLE PRESSURE TRACE reissued-slot=true stale-wait=Invalid stale-close=Invalid successor=unchanged' "$out/result.log"
cat "$out/result.log"
