#!/bin/sh
# Builds the YY3568 first-light image (docs/arm64-first-light/README.md): the
# ARM64 kernel with the diagnostic path and the RK3568 UART2 early console,
# as a Linux-style `Image` that U-Boot's booti keeps in place (header flags
# bit 3), plus the boot commands for the operator. Nothing here touches a
# board. Output: build/arm64-first-light/{absd-arm64-firstlight.img,boot.cmd,SHA256SUMS}.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
out=${ABSD_ARM_FIRST_LIGHT_OUT:-"$root/build/arm64-first-light"}
mkdir -p "$out"
ABSD_ARM_BUILD="$out" ABSD_ARM_FEATURES=arm64,arm64-first-light,arm64-console-dwapb-rk3568 sh "$root/scripts/build-arm64.sh"
cp "$out/kernel.img" "$out/absd-arm64-firstlight.img"
cat > "$out/boot.cmd" <<'CMD'
# YY3568 first light, at the U-Boot prompt, with the SD card (mmc 1) holding
# absd-arm64-firstlight.img and rk3568-yy3568.dtb in its first partition.
# The image must sit at exactly 0x40080000 (its link address); the tree may
# be anywhere in RAM (the kernel reads it before the MMU is on).
load mmc 1:1 0x40080000 absd-arm64-firstlight.img
load mmc 1:1 ${fdt_addr_r} rk3568-yy3568.dtb
booti 0x40080000 - ${fdt_addr_r}
# Expected: ABSD ARM64 KERNEL BOOT, ARM BOOT entry_el=2 psci=smc, one ARM RAM
# REGION line per bank (two on a unit with RAM above 4 GiB), ARM RAM OK, ARM
# MMU OK, ARM EXCEPTION OK, ARM FIRST LIGHT ..., ARM FIRMWARE psci_version=...
# cpus=4 cpu_shift=8 console=0x00000000fe660000 dw-apb, ARM GIC distributor
# pidr2_archrev=3 ... redistributors=4, ARM GIC redistributors count=4
# ended=last affinities=0x00000000,0x00000100,0x00000200,0x00000300, ARM TIMER
# MARK ..., ARM TIMER cntfrq=24000000 ticks_per_1500_bytes=~240000, ARM FIRST
# LIGHT OK, then the board stops (PSCI SYSTEM_OFF, which upstream TF-A never
# returns from): power-cycle to recover. If U-Boot prints "Moving Image from
# ..." the header flag was not honoured (falsifier F3). A line starting
# "ABSD ARM PANIC:" names a refusal (device tree, placement, console).
# Fallback if the kernel refuses the tree's placement: setenv fdt_high
# 0xffffffffffffffff and load the tree at 0x48000000 instead of ${fdt_addr_r}.
CMD
(cd "$out" && sha256sum absd-arm64-firstlight.img boot.cmd > SHA256SUMS && cat SHA256SUMS)
