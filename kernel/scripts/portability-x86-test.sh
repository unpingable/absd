#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
output=build/arm64/x86-portability
mkdir -p "$output"
RUSTFLAGS="-C relocation-model=static -C code-model=large -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-no-pie -C link-arg=-Wl,-T,$root/user/linker.ld" cargo build --release --manifest-path user/Cargo.toml --target x86_64-unknown-linux-gnu --target-dir "$output/user" --bin portability
ABSD_PORTABILITY_ELF="$root/$output/user/x86_64-unknown-linux-gnu/release/portability" make external-iso EXTERNAL_TARGET="$output/kernel"
status=0
case "${ABSD_PORTABILITY_X86_ACCEL:-tcg}" in
 kvm) set -- qemu-system-x86_64 -accel kvm -cpu host ;;
 tcg) set -- qemu-system-x86_64 -accel tcg ;;
 *) echo 'ABSD_PORTABILITY_X86_ACCEL must be kvm or tcg' >&2; exit 1 ;;
esac
timeout 60 "$@" -cdrom build/absd-external.iso -display none -serial "file:$output/serial.log" -no-reboot -no-shutdown -nic none -device isa-debug-exit,iobase=0xf4,iosize=0x04 || status=$?
test "$status" -eq 3
for marker in 'PORTABLE MEMORY VALIDATION OK' 'PORTABLE HANDLE ISOLATION RIGHTS TRANSITIONS OK' 'PORTABLE FAULT ISOLATION OK' 'PORTABLE FP SIMD PREEMPTION OK' 'PORTABLE CAPACITY REUSE 200 REAPS OK' 'PORTABLE MACHINE AUTHORITY REFUSAL OK' 'PORTABLE SEMANTICS OK' 'PORTABLE B3 FAULT RECLAMATION FP HEALTH OK'; do
 test "$(grep -xc "$marker" "$output/serial.log")" -eq 1
done
if grep -q 'ABSD PANIC' "$output/serial.log"; then exit 1; fi
printf '%s\n' 'PORTABILITY X86 PASS'
