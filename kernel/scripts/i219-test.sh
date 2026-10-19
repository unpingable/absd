#!/bin/sh
# Deterministic identity refusal: QEMU 82540 must never impersonate I219.
# Runtime dispatch/refusal only, not I219 hardware behavior.
# QEMU e1000e (8086:10d3) is a negative control only: a sibling e1000e-family
# function is not admitted by the native probe (8086:15b7 only), and without
# `net-i219` the 82540 path (8086:100e only) does not take it either.
# The txhold rows: `net-i219 nic-tx-hold` must be refused in the kernel's
# option block (ABSD PANIC, status 7) before any NIC line, with no NIC and
# with QEMU's 82540 attached; the fixture is QEMU e1000 only.
# `--list` prints the cases without building or booting.
set -eu
cd "$(dirname "$0")/.."
cases='frames:none frames:e1000 frames:e1000e init:none init:e1000 init:e1000e legacy:e1000e txhold:none txhold:e1000'
mode_of() {
 case $1 in
  frames) options='net-probe net-i219 nic-ring-fault'; expected=7; marker='NIC UNAVAILABLE Absent' ;;
  init) options='i219-init'; expected=7; marker='I219 INIT REFUSED Absent' ;;
  legacy) options='net-probe nic-ring-fault'; expected=7; marker='NIC UNAVAILABLE Absent' ;;
  # A panic ends in exit_qemu(1) (src/main.rs panic handler), which writes
  # (1 << 1) | 1 = 3 to isa-debug-exit; QEMU exits (3 << 1) | 1 = 7.
  txhold) options='net-probe net-i219 nic-tx-hold'; expected=7; marker='transmit-hold fixture is QEMU e1000 only' ;;
 esac
}
device_of() {
 case $1 in
  none) nic='-nic none' ;;
  e1000) nic='-nic user,model=e1000' ;;
  e1000e) nic='-netdev user,id=n0 -device e1000e,netdev=n0' ;;
 esac
}
if [ "${1:-}" = --list ]; then
 n=0
 for row in $cases; do
  mode_of "${row%%:*}"; device_of "${row#*:}"; n=$((n + 1))
  printf '%s-%s: options="%s" qemu="%s" exit=%s marker="%s"\n' \
   "${row%%:*}" "${row#*:}" "$options" "$nic" "$expected" "$marker"
 done
 echo "i219-test: $n cases"
 exit 0
fi
qemu=${1:-qemu-system-x86_64}
make build
mkdir -p build/i219-refusal/iso/boot/grub
cp target/debug/absd-kernel build/i219-refusal/iso/boot/absd-kernel
for mode in frames init legacy txhold; do
 mode_of "$mode"
 printf '%s\n' 'insmod all_video' 'set timeout=0' \
  'menuentry "I219 identity refusal" {' " multiboot2 /boot/absd-kernel $options" ' boot' '}' \
  > build/i219-refusal/iso/boot/grub/grub.cfg
 grub-mkrescue -o build/i219-refusal/$mode.iso build/i219-refusal/iso >build/i219-refusal/$mode-iso.log 2>&1
done
n=0
for row in $cases; do
 mode=${row%%:*}; device=${row#*:}
 mode_of "$mode"; device_of "$device"
 log=build/i219-refusal/$mode-$device.log
 result=0
 # shellcheck disable=SC2086 # $nic is a fixed word list from device_of
 timeout 60s "$qemu" -cpu max -m 128 -cdrom build/i219-refusal/$mode.iso \
  -display none -serial file:"$log" -no-reboot -no-shutdown \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 $nic >/dev/null 2>&1 || result=$?
 if [ "$result" -ne "$expected" ]; then
  echo "i219-test: $mode-$device: QEMU exit status $result, expected $expected" >&2; exit 1
 fi
 if ! grep -qx "$marker" "$log"; then
  echo "i219-test: $mode-$device: marker line missing: $marker" >&2; exit 1
 fi
 unavailable=$(grep -c '^NIC UNAVAILABLE' "$log" || true)
 if [ "$mode" = txhold ]; then
  # Refused in the option block: exactly one panic and no NIC line at all.
  if [ "$unavailable" -ne 0 ] || [ "$(grep -c '^ABSD PANIC: ' "$log" || true)" -ne 1 ]; then
   echo "i219-test: $mode-$device: expected one ABSD PANIC before any NIC line" >&2; exit 1
  fi
 elif [ "$mode" != init ] && [ "$unavailable" -ne 1 ]; then
  echo "i219-test: $mode-$device: expected exactly one NIC UNAVAILABLE line" >&2; exit 1
 fi
 if grep -Eq 'NIC CONTROLLER|NETWORK LINK OK|NIC LINK DOWN AT PROBE|NIC RING FAULT INJECTED|NIC DISABLED|NIC RX REFUSED|NIC TX HOLD|NIC PROBE TX|ABSD BOOT OK' "$log"; then
  echo "i219-test: $mode-$device: selector fell through to the 82540 path or falsely passed" >&2; exit 1
 fi
 if [ "$mode" = init ] && grep -Eq 'BLOCK DEVICE|BLOCK BACKEND|NVME |SPAWN' "$log"; then
  echo 'i219-test: initialization-only entry reached storage/userspace' >&2; exit 1
 fi
 n=$((n + 1))
 echo "i219-test: $mode-$device refused ($marker)"
done
echo "i219-test: $n refusals: 7 identity (3 on QEMU e1000e 8086:10d3), 2 transmit-hold fixture before probe; no legacy fallback, native ring-fault injection, native transmit hold or init-only storage/userspace"
