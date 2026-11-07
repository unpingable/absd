#!/bin/sh
# Build the isolated native PCM tone/probe image. Does not launch a guest.
set -eu
mode=${1:-pcm-tone}
case "$mode" in pcm-tone|pcm-probe|pcm-underrun|pcm-stop|pcm-death) ;; *) echo 'expected pcm-tone or pcm-probe' >&2; exit 2;; esac
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
sh scripts/kernel-cargo.sh rustc --features native-pcm-qemu82 --bin absd-kernel -- \
  -C relocation-model=static -C code-model=kernel -C no-redzone=yes \
  -C link-arg=-Tlinker.ld -C link-arg=-nostdlib -C link-arg=-no-pie
output="build/native-pcm/$mode"
mkdir -p "$output/iso/boot/grub"
cp target/debug/absd-kernel "$output/iso/boot/absd-kernel"
cat > "$output/iso/boot/grub/grub.cfg" <<CFG
set timeout=0
set default=0
menuentry "ABSD native PCM experiment" {
    multiboot2 /boot/absd-kernel $mode
    boot
}
CFG
grub-mkrescue -o "$output/guest.iso" "$output/iso"
sha256sum "$output/iso/boot/absd-kernel" "$output/guest.iso"
