#!/bin/sh
# The file server's release rule under load (scripts/fsd-release-load.py),
# rerunnable from one command and not part of check-all.sh:
#
#   scripts/run-fsd-release-load.sh [fsd-release-load.py arguments...]
#
# Builds the platform (unless ABSD_SKIP_BUILD=1), clones the pinned kernel
# (or uses ABSD_KERNEL_RUN), pins QEMU and ABSD_LOAD_HOGS busy loops
# (default 12) to ABSD_LOAD_CPUS (default 0-3), and runs ABSD_LOAD_ROUNDS
# (default 40) sessions that write garbage or a request and exit.
# ABSD_LOAD_ACCEL=kvm runs the guest under KVM; the default is TCG. The
# last line is FSD RELEASE LOAD OK with the counts on the line before it.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
campaign_root=$(dirname "$root")
. "$root/scripts/inputs.sh"
kernel_commit=4212fff26bb0b160eac718c26fcc7ed5d67034a7
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=$root/.fsd-load-work
run=

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$run" ] && [ -e "$run" ]; then
        case "$run" in
            "$campaign_root"/absd-kernel-std-run.*) rm -rf "${run:?}" ;;
            *) printf '%s\n' "refusing unexpected cleanup path: $run" >&2; status=1 ;;
        esac
    fi
    if ps -eo args= | awk -v w="$work" '$1 ~ /qemu-system/ && index($0, w) {found=1} END {exit !found}'; then
        printf '%s\n' 'FSD RELEASE LOAD CLEANUP qemu=present' >&2
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
for file in sshd.elf absd-fsd.elf absd-fsd-regenerate.elf sshtest.elf fsd-probe.elf fixture-import.elf \
    commands/absd-sh commands/cat; do
    test -f "$root/$file"
done
kernel=${ABSD_KERNEL_RUN:-}
if [ -z "$kernel" ]; then
    run=$(mktemp -d "$campaign_root/absd-kernel-std-run.XXXXXX")
    canonical_kernel=$(absd_source KERNEL)
    absd_kernel_run "$canonical_kernel" "$kernel_commit" "$run"
    kernel=$run
fi
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
case "${ABSD_LOAD_ACCEL:-tcg}" in
    kvm) qemu="$qemu -accel kvm -cpu host" ;;
    tcg) qemu="$qemu -cpu max,vendor=GenuineIntel,+rdrand" ;;
    *) echo "ABSD_LOAD_ACCEL must be kvm or tcg" >&2; exit 2 ;;
esac
rm -rf "${work:?}"
mkdir -p "$work"
python3 "$root/scripts/fsd-release-load.py" --work "$work" --kernel "$kernel" --shell "$root/commands/absd-sh" \
    --qemu "$qemu" --rounds "${ABSD_LOAD_ROUNDS:-40}" --hogs "${ABSD_LOAD_HOGS:-12}" --cpus "${ABSD_LOAD_CPUS:-0-3}" "$@"
rm -rf "${work:?}"
printf '%s\n' "ABSD RUST FSD RELEASE LOAD OK accel=${ABSD_LOAD_ACCEL:-tcg}"
