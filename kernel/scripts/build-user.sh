#!/bin/sh
# Builds the freestanding userspace programs and copies each ELF into the
# output directory as <name>.elf. Used by build.rs and `make user`.
set -eu

output=${1:?output directory required}
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$output"
target_dir="$output/cargo"

# This may run inside the kernel's build script: drop the outer build's
# rustc flags, wrappers, and jobserver so the nested build is independent.
unset CARGO_ENCODED_RUSTFLAGS RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET \
    RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CLIPPY_ARGS CARGO_MAKEFLAGS \
    MAKEFLAGS MFLAGS TARGET

programs="init durable_probe broker_probe broker_child image_probe image_rollback elf_matrix disclosure_probe hello_a hello_b exit7 fault fpu trap privileged heap unmapped overflow cell shared readonly watcher piper sleeper shell fuzz multi_handle stack_grow stack_jump orphaner supervised_worker recovery_worker service_client client_service_worker alloc_probe isolation input_stream external_workload block_probe nic_probe machine_probe hostile_probe rt_probe fpu_mxcsr smp_user"
user_flags=$(python3 "$root/scripts/rust-build-flags.py" user "$root")
# The kernel's native-pcm-experiment build selects init's private PCM modes
# (build.rs); every other build leaves them out of init entirely.
case ${ABSD_USER_NATIVE_PCM:-0} in
    0) set -- ;;
    1) set -- --features native-pcm-experiment ;;
    *) echo "ABSD_USER_NATIVE_PCM must be 0 or 1" >&2; exit 2 ;;
esac
case ${ABSD_USER_MWM:-0} in
    0) ;;
    1) programs="$programs mwm"; set -- "$@" --features mwm-experiment ;;
    *) echo "ABSD_USER_MWM must be 0 or 1" >&2; exit 2 ;;
esac
case ${ABSD_USER_SUCCESSOR:-0} in
    0) ;;
    1) programs="$programs mwm_successor_producer"; set -- "$@" --features mwm-successor ;;
    *) echo "ABSD_USER_SUCCESSOR must be 0 or 1" >&2; exit 2 ;;
esac
# Embedded programs must share the kernel's address-space layout and resource
# profile: inside the kernel's build script Cargo exports the kernel's features.
if [ -n "${CARGO_FEATURE_BUILDER_PROFILE:-}" ]; then
    set -- "$@" --features absd-abi/builder-profile
fi
if [ -n "${CARGO_FEATURE_BUILDER_LARGE_ENVELOPE:-}" ]; then
    set -- "$@" --features absd-abi/builder-large-envelope
fi

# Cargo does not track the linker script, so force the final links to rerun.
for name in $programs; do
    rm -f "$target_dir/x86_64-unknown-linux-gnu/release/$name" \
        "$target_dir/x86_64-unknown-linux-gnu/release/deps/$name-"*
done

# Static, non-PIE, no libc or start files; the kernel loader accepts only
# ET_EXEC images placed by user/linker.ld inside the fixed user window.
CARGO_ENCODED_RUSTFLAGS="$user_flags" \
    "${CARGO:-cargo}" build --quiet --release \
    --manifest-path "$root/user/Cargo.toml" \
    --target-dir "$target_dir" \
    --target x86_64-unknown-linux-gnu "$@"

for name in $programs; do
    cp "$target_dir/x86_64-unknown-linux-gnu/release/$name" "$output/$name.elf"
done
