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
source_map=$(sh "$root/scripts/rust-source-map.sh")

# Cargo does not track the linker script, so force the final links to rerun.
for name in $programs; do
    rm -f "$target_dir/x86_64-unknown-linux-gnu/release/$name" \
        "$target_dir/x86_64-unknown-linux-gnu/release/deps/$name-"*
done

# Static, non-PIE, no libc or start files; the kernel loader accepts only
# ET_EXEC images placed by user/linker.ld inside the fixed user window.
RUSTFLAGS="--remap-path-prefix=$source_map -C relocation-model=static -C code-model=large -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-no-pie -C link-arg=-Wl,-T,$root/user/linker.ld" \
    "${CARGO:-cargo}" build --quiet --release \
    --manifest-path "$root/user/Cargo.toml" \
    --target-dir "$target_dir" \
    --target x86_64-unknown-linux-gnu

for name in $programs; do
    cp "$target_dir/x86_64-unknown-linux-gnu/release/$name" "$output/$name.elf"
done
