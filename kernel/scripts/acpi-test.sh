#!/bin/sh
# ACPI consumption qualification on QEMU q35 under TCG
# (docs/x86-acpi-20261015/RESULT.md). Boots the `acpi-test` mode, which
# reads and reports the tables right after HEAP OK and ends the boot.
#   - MADT at -smp 1, 2 and 4 must report exactly that many CPUs, an IOAPIC
#     and interrupt source overrides; FADT reset register and \_S5 found.
#   - Table location at -m 128M, 512M, 2G and 3G (above the first GiB from
#     2G on, read through the one remapped read-only scratch view, which
#     takes no mmio region slot).
#   - The SMP cross-check against the kernel-only AP bring-up's assumption
#     (match at -smp 2, disclosed MISMATCH at -smp 4).
#   - `acpi-poweroff`: QEMU must exit with status 0 through ACPI S5 (no
#     -no-shutdown) right after the `ACPI S5 POWEROFF` line.
#   - Negative: a second MADT or FADT (QEMU -acpitable) is ambiguous and
#     refuses; with power-off requested, it is never armed.
#   - UEFI (OVMF) when present: the RSDP v2 / XSDT path.
set -eu
iso=$1
out=build/acpi
rm -rf "$out"; mkdir -p "$out"
QEMU=${QEMU:-qemu-system-x86_64}

die() { echo "acpi-test: $*" >&2; exit 1; }

normalize_serial() {
	python3 - "$1" <<'EOF'
from pathlib import Path
import sys
path = Path(sys.argv[1])
raw = path.read_bytes()
normalized = raw.replace(b'\r\n', b'\n')
if normalized != raw:
    path.with_suffix(path.suffix + '.raw').write_bytes(raw)
    path.write_bytes(normalized)
EOF
}

# The bootstrap stack is distinct from the per-task kernel stacks. ACPI
# previously overflowed it and could even corrupt the selected finish mode.
stack_margin() {
	awk '
	/^BOOT STACK/ { total++ }
	/^BOOT STACK used=[0-9]+ capacity=[0-9]+ margin=[0-9]+ canary=[0-9]+$/ {
		split($3, used, "="); split($4, capacity, "="); split($5, margin, "=");
		split($6, canary, "=");
		count++; valid = capacity[2] == 32768 && margin[2] >= 2048 && used[2] + margin[2] == capacity[2] && canary[2] == 4096;
	}
	END { exit !(total == 1 && count == 1 && valid) }
	' "$1"
}

# boot NAME CMDLINE EXPECTED-STATUS QEMU-ARGS...
boot() {
	name=$1; cmdline=$2; expect=$3; shift 3
	dir=$out/$name-iso
	mkdir -p "$dir/boot/grub"
	cp build/iso/boot/absd-kernel "$dir/boot/absd-kernel"
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD acpi" {' "  multiboot2 /boot/absd-kernel $cmdline" '  boot' '}' > "$dir/boot/grub/grub.cfg"
	grub-mkrescue -o "$out/$name.iso" "$dir" >/dev/null 2>&1
	log=$out/$name.serial.log
	status=0
	timeout 120s $QEMU -M q35 -accel tcg -cdrom "$out/$name.iso" -display none \
		-serial file:"$log" -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		"$@" >/dev/null 2>"$out/$name.qemu.err" || status=$?
	[ "$status" -eq "$expect" ] || die "$name: QEMU exit $status, expected $expect (see $log)"
	normalize_serial "$log"
	if grep -q 'PANIC\|KERNEL FAULT' "$log"; then die "$name: kernel fault in $log"; fi
	grep -qx 'HEAP OK' "$log" || die "$name: boot did not reach HEAP OK"
	stack_margin "$log" || die "$name: missing or insufficient bootstrap stack margin"
	echo "acpi-test: $name status=$status $(grep '^ACPI LOCATION' "$log" || echo 'no location')"
}

topology() {
	name=$1; cpus=$2; log=$out/$name.serial.log
	grep -qx 'ACPI OK' "$log" || die "$name: no ACPI OK"
	grep -q "^ACPI MADT cpus=$cpus online-capable=0 disabled=0 ioapics=1 isos=[1-9][0-9]* " "$log" \
		|| die "$name: MADT summary does not show $cpus CPUs, 1 IOAPIC and overrides"
	n=$(grep -c '^ACPI MADT CPU kind=xapic uid=[0-9]* apic=[0-9]* enabled=1 ' "$log")
	[ "$n" -eq "$cpus" ] || die "$name: $n enabled CPU lines, expected $cpus"
	grep -q '^ACPI MADT IOAPIC id=[0-9]* address=0xfec00000 gsi-base=0$' "$log" || die "$name: IOAPIC"
	grep -q '^ACPI MADT ISO bus=0 irq=0 gsi=2 ' "$log" || die "$name: timer override (IRQ0 -> GSI2)"
	grep -q '^ACPI FADT RESET supported=1 space=io address=0xcf9 width=8 value=0x0f machine-reset-port=same machine-reset-value=different$' "$log" \
		|| die "$name: FADT reset register"
	grep -q '^ACPI S5 slp-typa=0 slp-typb=0 pm1a=0x604 pm1b=0x0$' "$log" || die "$name: S5 sleep type"
	if grep -q 'REFUSED' "$log"; then die "$name: unexpected refusal"; fi
}

# MADT count follows -smp; table location across memory sizes.
boot smp1-128m acpi-test 3 -smp 1 -m 128M
topology smp1-128m 1
grep -q '^ACPI LOCATION .* above-first-gib=no mmio-slots=0 scratch-pages=2 scratch-remaps=0 access-refusals=0$' $out/smp1-128m.serial.log || die "128M: tables expected below 1 GiB"
boot smp2-512m acpi-test 3 -smp 2 -m 512M
topology smp2-512m 2
grep -q '^ACPI LOCATION .* above-first-gib=no mmio-slots=0 scratch-pages=2 scratch-remaps=0 access-refusals=0$' $out/smp2-512m.serial.log || die "512M: tables expected below 1 GiB"
boot smp4-2g acpi-test 3 -smp 4 -m 2G
topology smp4-2g 4
grep -q '^ACPI LOCATION .* above-first-gib=yes mmio-slots=0 scratch-pages=2 scratch-remaps=[1-9][0-9]* access-refusals=0$' $out/smp4-2g.serial.log || die "2G: tables expected in the window"
boot smp2-3g acpi-test 3 -smp 2 -m 3G
topology smp2-3g 2
grep -q '^ACPI LOCATION .* above-first-gib=yes mmio-slots=0 scratch-pages=2 scratch-remaps=[1-9][0-9]* access-refusals=0$' $out/smp2-3g.serial.log || die "3G: tables expected in the window"
boot smp4-6g acpi-test 3 -smp 4 -m 6G
topology smp4-6g 4

# Cross-check against the kernel-only AP bring-up's assumption (2 CPUs,
# APIC IDs 0 and 1). The boot ends before any AP is started.
boot check-smp2 'acpi-test smp-kernel-only' 3 -smp 2 -m 512M
grep -q '^ACPI MADT SMP-CHECK bsp-apic=0 bsp-listed=yes bringup=kernel-only-ap assumed-cpus=2 assumed-ids-listed=yes madt-cpus=2 result=match$' \
	$out/check-smp2.serial.log || die "check-smp2: expected match"
boot check-smp4 'acpi-test smp-kernel-only' 3 -smp 4 -m 512M
grep -q '^ACPI MADT SMP-CHECK .* bringup=kernel-only-ap assumed-cpus=2 .* madt-cpus=4 result=MISMATCH$' \
	$out/check-smp4.serial.log || die "check-smp4: expected disclosed mismatch"

# A whole default boot with `acpi` and the kernel-only AP: the scratch view
# must leave the LAPIC and device mappings their slots, the AP must come up
# after the report, and the boot must finish.
boot full-smp2 'default acpi smp-kernel-only' 3 -smp 2 -m 2G
grep -q '^ACPI MADT SMP-CHECK .* result=match$' $out/full-smp2.serial.log || die "full-smp2: cross-check"
grep -qx 'ACPI OK' $out/full-smp2.serial.log || die "full-smp2: no ACPI OK"
grep -qx 'SMP AP KERNEL ONLY ONLINE' $out/full-smp2.serial.log || die "full-smp2: AP not online after ACPI"
grep -qx 'ABSD BOOT OK' $out/full-smp2.serial.log || die "full-smp2: boot did not finish"
grep -q '^FRAMES baseline=0 .* final=0 ' $out/full-smp2.serial.log || die "full-smp2: default suite accounting absent"
grep -q '^COUNTERS .* init=0$' $out/full-smp2.serial.log || die "full-smp2: default suite counters absent"
if grep -Eq '^((RT|RTC|EXTERNAL|DURABLE|NET|SMP-LIFECYCLE|SMP-CREATED-STOP) WORKLOAD OK|FUZZ OK|HOSTILE OK|FPU OK|SHELL SESSION OK)$' $out/full-smp2.serial.log; then
	die "full-smp2: alternate-mode receipt in default suite"
fi

# S5 power-off: QEMU must exit 0 (ACPI shutdown), never through debug-exit.
boot poweroff 'acpi-test acpi-poweroff' 0 -smp 2 -m 2G
topology poweroff 2
grep -qx 'ACPI POWEROFF ARMED' $out/poweroff.serial.log || die "poweroff: not armed"
last=$(tail -n 1 $out/poweroff.serial.log)
case $last in
	'ACPI S5 POWEROFF pm1a=0x604 slp-typa=0 pm1b=0x0 slp-typb=0') ;;
	*) die "poweroff: last serial line is '$last'" ;;
esac
# Without the option the same boot ends through debug-exit (status 3).
boot no-poweroff acpi-test 3 -smp 2 -m 2G
if grep -q 'POWEROFF' $out/no-poweroff.serial.log; then die "no-poweroff: power-off without opt-in"; fi

# Negative cases through QEMU's -acpitable. QEMU recomputes the checksum
# of a user table (seen on QEMU 8.2: a deliberately wrong checksum byte is
# repaired), so checksum, length and truncation refusals are covered by the
# host tests (src/acpi.rs); here the extra table makes the firmware
# ambiguous, which must refuse rather than pick one.
python3 - "$out" <<'EOF'
import struct, sys
out = sys.argv[1]
def table(sig, body):
    length = 36 + len(body)
    raw = bytearray(sig + struct.pack('<IBB', length, 1, 0) + b'ABSD  ' + b'ABSDTEST'
                    + struct.pack('<I', 1) + b'ABSD' + struct.pack('<I', 1) + body)
    raw[9] = (-sum(raw)) & 0xff
    return bytes(raw)
# A second MADT (one CPU, plus a zero-length entry) and a second, short FADT.
madt = struct.pack('<II', 0xfee00000, 1) + bytes([0, 8, 0, 0, 1, 0, 0, 0, 7, 0])
open(f'{out}/dup-madt.aml', 'wb').write(table(b'APIC', madt))
open(f'{out}/dup-facp.aml', 'wb').write(table(b'FACP', bytes(40)))
EOF
boot dup-madt acpi-test 7 -smp 2 -m 512M -acpitable file=$out/dup-madt.aml
grep -q '^ACPI TABLE sig=APIC .*' $out/dup-madt.serial.log || die "dup-madt: tables not listed"
[ "$(grep -c '^ACPI TABLE sig=APIC ' $out/dup-madt.serial.log)" -eq 2 ] || die "dup-madt: QEMU did not add the second MADT"
grep -qx 'ACPI REFUSED stage=madt reason=Duplicate' $out/dup-madt.serial.log || die "dup-madt: ambiguous MADT not refused"
if grep -q '^ACPI MADT ' $out/dup-madt.serial.log; then die "dup-madt: topology reported from an ambiguous MADT"; fi
if grep -qx 'ACPI OK' $out/dup-madt.serial.log; then die "dup-madt: ACPI OK after refusal"; fi
# With power-off requested, an ambiguous FADT must refuse it: the boot ends
# through debug-exit (status 7, failure), never through S5.
boot dup-facp 'acpi-test acpi-poweroff' 7 -smp 2 -m 2G -acpitable file=$out/dup-facp.aml
grep -qx 'ACPI REFUSED stage=fadt reason=Duplicate' $out/dup-facp.serial.log || die "dup-facp: ambiguous FADT not refused"
if grep -q 'POWEROFF ARMED\|S5 POWEROFF' $out/dup-facp.serial.log; then die "dup-facp: power-off armed from an ambiguous FADT"; fi

# UEFI: OVMF hands GRUB an RSDP v2 and an XSDT.
ovmf=/usr/share/OVMF/OVMF_CODE_4M.fd
if [ -r "$ovmf" ] && [ -d /usr/lib/grub/x86_64-efi ]; then
	cp /usr/share/OVMF/OVMF_VARS_4M.fd $out/vars.fd
	boot uefi-smp4 acpi-test 3 -smp 4 -m 2G \
		-drive if=pflash,format=raw,readonly=on,file=$ovmf -drive if=pflash,format=raw,file=$out/vars.fd
	grep -q '^ACPI RSDP tag=new revision=2 ' $out/uefi-smp4.serial.log || die "uefi: RSDP v2 expected"
	grep -q '^ACPI ROOT kind=XSDT ' $out/uefi-smp4.serial.log || die "uefi: XSDT expected"
	grep -q '^ACPI MADT cpus=4 ' $out/uefi-smp4.serial.log || die "uefi: MADT cpus=4"
	grep -qx 'ACPI OK' $out/uefi-smp4.serial.log || die "uefi: no ACPI OK"
else
	echo 'acpi-test: UEFI case skipped (no OVMF or x86_64-efi GRUB)'
fi
echo 'acpi-test: MADT, FADT, S5 power-off and refusals qualified (build/acpi)'
