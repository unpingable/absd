#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
output=${ABSD_ARM_BUILD:-"$root/build/arm64"}
mkdir -p "$output"
user_target=aarch64-unknown-none
RUSTFLAGS="-C relocation-model=static -C code-model=large -C link-arg=-T$root/user/arch-aarch64.ld" cargo build --manifest-path "$root/user/Cargo.toml" --target "$user_target" --target-dir "$output/user" --release --bin portability --bin exit7 --bin fault
ABSD_ARM_INIT_ELF="$output/user/$user_target/release/portability" ABSD_ARM_EXIT7_ELF="$output/user/$user_target/release/exit7" ABSD_ARM_FAULT_ELF="$output/user/$user_target/release/fault" RUSTFLAGS="${ABSD_ARM_KERNEL_CFG:-} -C relocation-model=static -C link-arg=-T$root/src/arch/aarch64/linker.ld" cargo build --manifest-path "$root/Cargo.toml" --target aarch64-unknown-none-softfloat --target-dir "$output/kernel" --features "${ABSD_ARM_FEATURES:-arm64}" --bin absd-arm64
${LLVM_OBJCOPY:-llvm-objcopy-18} -O binary "$output/kernel/aarch64-unknown-none-softfloat/debug/absd-arm64" "$output/kernel.img"
sha256sum "$output/kernel.img"
