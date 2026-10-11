#!/bin/sh
# Real NQ-NG `nq diagnostics qualify` on ABSD against its Linux twin: the
# frozen Linux fixture, read-only authority, a WAL-mode store, and hostile
# inputs. Two Linux references are built (debug, as the fixture's writer
# was): the pinned NQ commit unpatched, and the staged tree with
# patches/nq-absd.patch, which must behave identically on Unix.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone}
. "$root/scripts/inputs.sh"
nq=$(absd_source NQ)
commit=80574417f0188afd37992db7ac764a6f0f72ff62
tree=13c0b6b36ec26b941adc586088275df248360492
stage=$(dirname "$root")/absd-std-staged-nq
linux=$(dirname "$root")/absd-std-nq-linux
work=${ABSD_NQ_WORK:-$root/.nq-work}
: "${ABSD_QEMU:=qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand}"

absd_not_kernel_source "$kernel"
test -f "$root/fixture-import.elf" && test -f "$root/nq.elf" && test -f "$root/nq-unknown.elf"
test -f "$stage/crates/nq-core/src/platform.rs"
rm -rf "$linux" "$work"
mkdir -p "$linux"
absd_stage_input NQ-NG "$nq" "$commit" "$tree" "$linux"
(cd "$linux" && env -u RUSTFLAGS cargo build --locked --offline -p nq-app --bin nq)
(cd "$stage" && env -u RUSTFLAGS cargo build --locked --offline -p nq-app --bin nq)
# The profile digest: the unpatched Linux build, the patched Unix build,
# and the ABSD image must all compile the same one.
for build in "$linux/target/debug" "$stage/target/debug"; do
    digest=$(cat "$build"/build/nq-profiles-*/output |
        sed -n 's/^cargo:rustc-env=NQ_PROFILES_SOURCE_DIGEST=//p' | sort -u)
    test "$digest" = "$(cat "$root/nq-profile-digest.txt")"
done
printf '%s\n' "NQ PROFILE DIGEST OK $(cat "$root/nq-profile-digest.txt") builds=linux,unix-patched,absd"
python3 "$root/scripts/nq-matrix.py" --kernel "$kernel" \
    --importer "$root/fixture-import.elf" --nq "$root/nq.elf" --nq-unknown "$root/nq-unknown.elf" \
    --linux-nq "$linux/target/debug/nq" --linux-patched-nq "$stage/target/debug/nq" \
    --fixture "$root/fixtures/nq" --work "$work" --qemu "$ABSD_QEMU" ${ABSD_NQ_ONLY:+--only "$ABSD_NQ_ONLY"}
test -n "${ABSD_NQ_ONLY:-}" && exit 0
rm -rf "$work" "$linux"
printf '%s\n' 'ABSD RUST NQ OK'
