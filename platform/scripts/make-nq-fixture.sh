#!/bin/sh
# Produces the frozen NQ fixture on Linux, with no ABSD code involved: the
# real pinned, unpatched `nq` (the debug build scripts/run-nq-matrix.sh
# builds) and the real `nq-host-helper` initialize a store, admit the
# helper and execute it once, in unprivileged namespaces (bubblewrap) that
# present a synthetic host; scripts/nq_fixture.py says what is synthetic
# and what stays measured. OUT gets the store, the artifact, the qualify
# configuration at the guest paths, the Linux qualify output, and a
# manifest.
#
#   make-nq-fixture.sh OUT
#
# Every production has a new artifact id and store genesis id (the script
# prints them). After replacing fixtures/nq with OUT, update what pins
# them: the artifact id in scripts/build-nq.sh, scripts/nq-matrix.py and
# scripts/pulse_fixture.py; the genesis id in scripts/build-nightshift.sh,
# scripts/pipeline-matrix.py and scripts/pulse_fixture.py (its vantage id);
# the manifest in scripts/verify-inputs.sh. Then produce the fixtures made
# from this one again: scripts/make-pulse-fixture.sh and
# scripts/make-reference-fixture.sh.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
out=${1:?output directory}
. "$root/scripts/inputs.sh"
nq=$(absd_source NQ)
commit=80574417f0188afd37992db7ac764a6f0f72ff62
tree=13c0b6b36ec26b941adc586088275df248360492
linux=$(dirname "$root")/absd-std-nq-fixture-linux
work=$(dirname "$root")/absd-std-nq-fixture-work

test ! -e "$out" || { echo "refusing to overwrite $out" >&2; exit 1; }
rm -rf "${linux:?}" "${work:?}"
mkdir -p "$linux"
absd_stage_input NQ-NG "$nq" "$commit" "$tree" "$linux"
(cd "$linux" && env -u RUSTFLAGS cargo build --locked --offline -p nq-app --bin nq)
(cd "$linux" && env -u RUSTFLAGS cargo build --locked --offline -p nq-host-helper)
digest=$(cat "$linux"/target/debug/build/nq-profiles-*/output |
    sed -n 's/^cargo:rustc-env=NQ_PROFILES_SOURCE_DIGEST=//p' | sort -u)
test "$(printf '%s\n' "$digest" | wc -l)" -eq 1
python3 "$root/scripts/nq_fixture.py" make --nq "$linux/target/debug/nq" \
    --helper "$linux/target/debug/nq-host-helper" --work "$work" --out "$out" \
    --nq-commit "$commit" --nq-tree "$tree" --profile-digest "$digest"
rm -rf "${work:?}" "${linux:?}"
printf '%s\n' "ABSD NQ FIXTURE OK $out"
