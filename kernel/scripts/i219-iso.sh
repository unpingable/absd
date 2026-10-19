#!/bin/sh
# Builds operator A1 media; never writes a block device or modifies firmware.
# Default initialization-only entry installs no frame DMA rings.
set -eu
cd "$(dirname "$0")/.."
make physical-build
work=build/i219-native
mkdir -p "$work/iso/boot/grub"
cp build/physical/target/debug/absd-kernel "$work/iso/boot/absd-kernel"
printf '%s\n' 'insmod all_video' 'set timeout=10' 'set default=0' \
 'menuentry "ABSD I219 initialization only - no frame DMA" {' \
 ' multiboot2 /boot/absd-kernel i219-init halt-on-exit' ' boot' '}' \
 'menuentry "ABSD I219 frame qualification - separately admitted DMA" {' \
 ' multiboot2 /boot/absd-kernel net-probe net-i219 halt-on-exit' ' boot' '}' \
 > "$work/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$work/absd-i219.iso" "$work/iso"
sha256sum "$work/absd-i219.iso" "$work/iso/boot/absd-kernel"
echo 'i219-iso: staged only; physical use requires operator qualification admission (docs/hardware/I219-NATIVE.md)'
