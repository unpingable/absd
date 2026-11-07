#!/bin/sh
# Operator-authorized writable recovery: the guest matrix from one command
# (scripts/storage-fence-resume-matrix.py; ACCEPTANCE-v5 of coordination record #63):
#
#   ABSD_KERNEL_RUN=<kernel clone> scripts/run-storage-fence-resume.sh \
#       --key KEY [storage-fence-resume-matrix.py arguments...]
#
# Builds the platform (unless ABSD_SKIP_BUILD=1), builds the paired release
# directory with release.py build (ABSD_RELEASE_ID, default `dev`) and a
# second release (`other`) whose ISO P0n boots on the first's disk, then runs
# the matrix against the kernel clone. ABSD_FENCE_ACCEL=kvm runs the guests
# under KVM; the default is TCG. Work directory: ABSD_FENCE_WORK or
# .fence-work/resume. One QEMU at a time; the matrix kills only the exact
# child it started.
#
#   scripts/run-storage-fence-resume.sh --host-only
#
# runs the matrix's host-only self-test (no build, no QEMU).
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ "${1:-}" = "--host-only" ]; then
    exec python3 -I "$root/scripts/storage-fence-resume-matrix.py" --host-only
fi
. "$root/scripts/inputs.sh"
work=${ABSD_FENCE_WORK:-$root/.fence-work/resume}
kernel=${ABSD_KERNEL_RUN:?ABSD_KERNEL_RUN names the kernel clone}
absd_not_kernel_source "$kernel"
# A kernel clone inside this checkout inherits the platform's
# .cargo/config.toml (target x86_64-unknown-absd) and cannot build itself.
kernel_real=$(CDPATH= cd -- "$kernel" && pwd -P)
root_real=$(CDPATH= cd -- "$root" && pwd -P)
case "$kernel_real/" in
"$root_real"/*)
    echo "run-storage-fence-resume.sh: ABSD_KERNEL_RUN ($kernel_real) is inside the platform checkout; clone the kernel outside it" >&2
    exit 2 ;;
esac
# The C kit chain's outputs default beside the checkout; keep them under
# the ignored .fence-work/ unless the caller chose otherwise.
: "${ABSD_CKIT_BUILD:=$root/.fence-work/ckit-build}"
: "${ABSD_USERLAND_BUILD:=$root/.fence-work/userland-build}"
: "${ABSD_CPORTS_BUILD:=$root/.fence-work/cports-build}"
export ABSD_CKIT_BUILD ABSD_USERLAND_BUILD ABSD_CPORTS_BUILD
grep -q 'storage-fence=' "$kernel/src/main.rs" || {
    echo "storage fence: $kernel has no storage-fence= option" >&2
    exit 2
}
key= prev=
for arg in "$@"; do
    case $prev in --key) key=$arg ;; esac
    prev=$arg
done
test -n "${key:-}" || { echo "run-storage-fence-resume.sh: --key KEY is required" >&2; exit 2; }
test -f "$key" && test -f "$key.pub" || { echo "run-storage-fence-resume.sh: $key and $key.pub must exist" >&2; exit 2; }

release_id=${ABSD_RELEASE_ID:-dev}
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
case "${ABSD_FENCE_ACCEL:-tcg}" in
    kvm) qemu="${ABSD_QEMU:-qemu-system-x86_64} -accel kvm -cpu host" ;;
    tcg) qemu="${ABSD_QEMU:-qemu-system-x86_64} -cpu max,vendor=GenuineIntel,+rdrand" ;;
    *) echo "ABSD_FENCE_ACCEL must be kvm or tcg" >&2; exit 2 ;;
esac
absd_work_dir "$work" "$root/.fence-work/resume"
rm -rf "${work:?}"
mkdir -p "$(dirname "$work")"
# The matrix creates $work itself (it must not exist yet); mark it on the way out.
trap 'absd_mark_work "$work"' EXIT
releases=$root/.fence-work/resume-releases
rm -rf "$releases"
mkdir -p "$releases"
python3 -I "$root/scripts/release.py" build --kernel "$kernel" --platform "$root" --id "$release_id" \
    --authorized-keys "$key.pub" "$releases/$release_id"
# The second release (P0n's wrong-release ISO, S1/S2 staging): the same
# platform under another id, kept under the ignored .fence-work/ so the
# checkout stays clean for c_kit_source.source() (release.py build refuses
# a dirty checkout).
other=
if [ "${ABSD_SKIP_OTHER_RELEASE:-0}" != 1 ]; then
    other_log=$root/.fence-work/resume-other-release.log
    ABSD_RELEASE_ID=other ABSD_INCREMENTAL=1 "$root/scripts/prepare-and-build.sh" > "$other_log" 2>&1
    python3 -I "$root/scripts/release.py" build --kernel "$kernel" --platform "$root" --id other \
        --authorized-keys "$key.pub" --replace "$releases/other"
    # Back to the lane id for the matrix's own release.
    ABSD_INCREMENTAL=1 "$root/scripts/prepare-and-build.sh" >> "$other_log" 2>&1
    other="--other-release $releases/other"
fi
nice -n 10 python3 -I "$root/scripts/storage-fence-resume-matrix.py" --work "$work" --kernel "$kernel" \
    --platform "$root" --release "$releases/$release_id" $other --qemu "$qemu" --accel "${ABSD_FENCE_ACCEL:-tcg}" "$@"
printf '%s\n' "ABSD STORAGE FENCE RESUME OK accel=${ABSD_FENCE_ACCEL:-tcg}"
