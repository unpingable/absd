#!/bin/sh
# Session containment matrix (experiment E2, scripts/contain-matrix.py) from
# one command, for any agent or human to rerun:
#
#   scripts/run-contain-matrix.sh [contain-matrix.py arguments...]
#
# Builds the platform (unless ABSD_SKIP_BUILD=1), then two
# qualification-only variants that are never installed:
#   .contain-build/absd-sh-keep-spawn  absd-sh that leaves the spawn right
#                                      with its commands (negative control)
#   .contain-build/sshd-controls.elf   sshd with --qualification-controls
#                                      (shell-killed and sshd-died controls)
# and runs the matrix against a disposable shared clone of the pinned kernel
# (or ABSD_KERNEL_RUN). ABSD_CONTAIN_ACCEL=kvm runs the guests under KVM
# (-accel kvm -cpu host); the default is TCG as in every other matrix.
# Extra arguments go to contain-matrix.py (for instance --only races
# --race-rounds 20). Results: the E2 lines and <work>/results.json, where
# <work> is ABSD_CONTAIN_WORK or .contain-work/run.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
campaign_root=$(dirname "$root")
. "$root/scripts/inputs.sh"
kernel_commit=4212fff26bb0b160eac718c26fcc7ed5d67034a7
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
out=$root/.contain-build
work=${ABSD_CONTAIN_WORK:-$root/.contain-work/run}
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
        printf '%s\n' 'CONTAIN CLEANUP qemu=present' >&2
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
test -d "$sysroot/lib/rustlib/src/rust/library"
rm -rf "${out:?}"
mkdir -p "$out"

# The shell without its deny (root workspace, own target directory).
(cd "$root" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
    ABSD_REAL_RUSTC=$toolchain/bin/rustc ABSD_STAGED_SYSROOT=$sysroot RUSTC=$root/scripts/rustc-staged.sh \
    RUSTC_BOOTSTRAP=1 RUST_TARGET_PATH=$root/targets ABSD_SH_QUALIFICATION_KEEP_SPAWN_RIGHT=1 \
    cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort --release --locked --offline \
    --target-dir "$out/target" --bin absd_sh)
llvm-strip-18 -o "$out/absd-sh-keep-spawn" "$out/target/x86_64-unknown-absd/release/absd_sh"
if cmp -s "$out/absd-sh-keep-spawn" "$root/commands/absd-sh"; then
    echo "contain: the keep-spawn shell is the installed shell" >&2
    exit 1
fi

# sshd with the qualification controls (ssh workspace, own target directory).
(cd "$root/ssh" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
    ABSD_REAL_RUSTC=$toolchain/bin/rustc ABSD_STAGED_SYSROOT=$sysroot RUSTC=$root/scripts/rustc-staged.sh \
    RUSTC_BOOTSTRAP=1 RUST_TARGET_PATH=$root/targets ABSD_PROGRAM_ARGS="--qualification-controls" \
    cargo +1.95.0 build -Z build-std=core,alloc,std,panic_abort --target x86_64-unknown-absd --release \
    --offline --locked --target-dir "$out/target-ssh" --bin sshd)
cp "$out/target-ssh/x86_64-unknown-absd/release/sshd" "$out/sshd-controls.elf"

kernel=${ABSD_KERNEL_RUN:-}
if [ -z "$kernel" ]; then
    run=$(mktemp -d "$campaign_root/absd-kernel-std-run.XXXXXX")
    canonical_kernel=$(absd_source KERNEL)
    absd_kernel_run "$canonical_kernel" "$kernel_commit" "$run"
    kernel=$run
fi
absd_not_kernel_source "$kernel"
case "${ABSD_CONTAIN_ACCEL:-tcg}" in
    kvm) qemu="${ABSD_QEMU:-qemu-system-x86_64} -accel kvm -cpu host" ;;
    tcg) qemu="${ABSD_QEMU:-qemu-system-x86_64} -cpu max,vendor=GenuineIntel,+rdrand" ;;
    *) echo "ABSD_CONTAIN_ACCEL must be kvm or tcg" >&2; exit 2 ;;
esac
rm -rf "${work:?}"
mkdir -p "$work"
python3 "$root/scripts/contain-matrix.py" --work "$work" --kernel "$kernel" --platform "$root" \
    --qemu "$qemu" --shell "$root/commands/absd-sh" --keep-spawn-shell "$out/absd-sh-keep-spawn" \
    --sshd "$root/sshd.elf" --controls-sshd "$out/sshd-controls.elf" --results "$work/results.json" "$@"
printf '%s\n' "ABSD RUST CONTAIN OK accel=${ABSD_CONTAIN_ACCEL:-tcg}"
