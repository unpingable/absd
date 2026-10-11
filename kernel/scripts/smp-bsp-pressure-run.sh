#!/bin/sh
# Closed ordinary suite with fixed independent pressure on every AP.
set -eu
kernel=${1:?qualification ELF}; out=${2:?new output directory}; cpus=${3:?2/4/6}
case "$cpus" in 2|4|6) ;; *) exit 1 ;; esac
cd "$(dirname "$0")/.."
mkdir "$out"
result=1
trap 'printf "%s\n" "$result" > "$out/status"' EXIT
mkdir -p "$out/iso/boot/grub"
cp "$kernel" "$out/iso/boot/absd-kernel"
sha256sum "$kernel" > "$out/kernel.sha256"
options='smp-user-pressure smp-user-preempt smp-scheduler-test smp-multicore-pressure smp-bsp-app'
if [ "$cpus" != 2 ]; then options="$options smp-cpus=$cpus"; fi
printf '%s\n' 'set timeout=0' 'menuentry "ABSD BSP suite with all-AP pressure" {' " multiboot2 /boot/absd-kernel $options" ' boot' '}' > "$out/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$out/boot.iso" "$out/iso" > "$out/iso.log" 2>&1
qstatus=0
SMP_BENCH_VCPUS=$cpus SMP_TOPOLOGY=separate python3 scripts/smp-user-qemu.py "$out" > "$out/runner.log" 2>&1 || qstatus=$?
test "$qstatus" -eq 3
python3 scripts/check-smp-bsp-pressure.py --serial "$out/serial.log" --placement "$out/vcpu-placement.json" --cpus "$cpus" --mode suite --expected-peak 16 > "$out/oracle.log" 2>&1
result=0
