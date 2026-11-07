#!/bin/sh
# One stock-build slice; never launches QEMU.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
output="$root/build/successor"
export ABSD_USER_SUCCESSOR=1 ABSD_USER_MWM=1 CARGO_BUILD_JOBS=2
sh "$root/scripts/build-user.sh" "$output/user"
export ABSD_EXTERNAL_USER_ELF="$output/user/mwm_successor_producer.elf"
export CARGO_TARGET_DIR="$output/target"
sh "$root/scripts/kernel-cargo.sh" rustc --manifest-path "$root/Cargo.toml" \
    --bin absd-kernel --features mwm-experiment -- -C relocation-model=static \
    -C code-model=kernel -C no-redzone=yes -C link-arg=-T"$root/linker.ld" \
    -C link-arg=-nostdlib -C link-arg=-no-pie -C link-arg=-Wl,--build-id=sha1
set -- "$output"/target/debug/build/absd-kernel-*/out/mwm_successor_producer.elf
test "$#" -eq 1
cmp "$ABSD_EXTERNAL_USER_ELF" "$1"
mkdir -p "$output/iso/boot/grub"
cp "$output/target/debug/absd-kernel" "$output/iso/boot/absd-kernel"
printf '%s\n' 'set timeout=0' 'menuentry "ABSD successor slice 3" {' \
    '  multiboot2 /boot/absd-kernel mwm-demo halt-on-exit' '  boot' '}' \
    > "$output/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$output/slice3.iso" "$output/iso"
sha256sum "$ABSD_EXTERNAL_USER_ELF" "$output/target/debug/absd-kernel" \
    "$output/slice3.iso" > "$output/artifacts.sha256"
