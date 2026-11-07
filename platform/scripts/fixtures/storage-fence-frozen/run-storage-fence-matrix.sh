#!/bin/sh
# The stale-write fence matrix (scripts/storage-fence-matrix.py; kernel
# docs/STORAGE-STALE-WRITE-FENCE.md) from one command:
#
#   ABSD_KERNEL_RUN=<kernel clone> scripts/run-storage-fence-matrix.sh \
#       --key KEY [storage-fence-matrix.py arguments...]
#
# Builds the platform (unless ABSD_SKIP_BUILD=1) and the qualification-only
# sshd with --qualification-controls (the exit fault of
# scripts/survival-recovery.py), then runs the matrix against the kernel
# clone, which must carry the storage fence (kernel src/storage_fence.rs).
# ABSD_FENCE_ACCEL=kvm runs the guests under KVM; the default is TCG.
# Work directory: ABSD_FENCE_WORK or .fence-work/run.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
out=$root/.fence-build
work=${ABSD_FENCE_WORK:-$root/.fence-work/run}
kernel=${ABSD_KERNEL_RUN:?ABSD_KERNEL_RUN names the kernel clone with the storage fence}
absd_not_kernel_source "$kernel"
grep -q 'storage-fence=' "$kernel/src/main.rs" || {
    echo "storage fence: $kernel has no storage-fence= option" >&2
    exit 2
}

if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
test -d "$sysroot/lib/rustlib/src/rust/library"
rm -rf "${out:?}"
mkdir -p "$out"
absd_rust_remap
(cd "$root/ssh" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
    ABSD_REAL_RUSTC=$toolchain/bin/rustc ABSD_STAGED_SYSROOT=$sysroot RUSTC=$root/scripts/rustc-staged.sh \
    RUSTC_BOOTSTRAP=1 RUST_TARGET_PATH=$root/targets ABSD_PROGRAM_ARGS="--qualification-controls" \
    cargo +1.95.0 --config "$ABSD_RUST_REMAP" build -Z build-std=core,alloc,std,panic_abort --target x86_64-unknown-absd --release \
    --offline --locked --target-dir "$out/target-ssh" --bin sshd)
cp "$out/target-ssh/x86_64-unknown-absd/release/sshd" "$out/sshd-controls.elf"

case "${ABSD_FENCE_ACCEL:-tcg}" in
    kvm) qemu="${ABSD_QEMU:-qemu-system-x86_64} -accel kvm -cpu host" ;;
    tcg) qemu="${ABSD_QEMU:-qemu-system-x86_64} -cpu max,vendor=GenuineIntel,+rdrand" ;;
    *) echo "ABSD_FENCE_ACCEL must be kvm or tcg" >&2; exit 2 ;;
esac
rm -rf "${work:?}"
mkdir -p "$(dirname "$work")"
python3 "$root/scripts/storage-fence-matrix.py" --work "$work" --kernel "$kernel" --platform "$root" \
    --qemu "$qemu" --sshd-controls "$out/sshd-controls.elf" "$@"
printf '%s\n' "ABSD STORAGE FENCE OK accel=${ABSD_FENCE_ACCEL:-tcg}"
