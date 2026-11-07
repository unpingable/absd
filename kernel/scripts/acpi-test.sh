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
#   - AMD-Vi discovery (#111): no IVRS without an IOMMU; QEMU's amd-iommu
#     table reported, cross-checked and summarised with its one deviation
#     (10h feature field nonzero while reserved) and DMA admission not
#     established; live IOMMU state printed as not observed; IVMD, unpaired
#     entries, capability offsets F8h/FCh, a synthetic target-shaped table
#     (its tolerated alias reported as a deviation) with no IOMMU function,
#     and a second IVRS refuse, each with its class.
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

# AMD-Vi discovery (#111 increment 2): reported, never enabled. Without an
# IOMMU there is no IVRS. QEMU 8.2.2's own table sets its 10h feature field
# (reserved while IVinfo[EFRSup] = 0): it is described, that deviation is
# listed, it is matched against the PCI function and the memory map, and
# the result carries structure, deviations, scope and DMA admission (not
# established) as separate properties.
# Nothing reads the unit's registers, so its live state is printed as not
# observed, never as a value. Bad or unbacked tables through -acpitable
# must refuse with their own class and reason, and never panic.
amdvi_unobserved() {
	grep -qx 'AMDVI HANDOFF iommu-en=not-observed translation=not-observed absd-enabled=no' "$1" || die "$2: live IOMMU state not printed as unobserved"
	if grep '^AMDVI' "$1" | grep -q -e ' enabled=' -e 'iommu-en=[01]' -e 'translation=none'; then die "$2: unobserved IOMMU state printed as a value"; fi
}
grep -qx 'AMDVI NONE reason=no-ivrs' $out/smp1-128m.serial.log || die "no-iommu: expected no IVRS"
if grep -q '^AMDVI \(UNIT\|REFUSED\|HANDOFF\)' $out/smp1-128m.serial.log; then die "no-iommu: unit or refusal without IVRS"; fi
boot amdvi acpi-test 3 -smp 2 -m 2G -device amd-iommu
log=$out/amdvi.serial.log
grep -qx 'ACPI OK' $log || die "amdvi: no ACPI OK"
grep -q '^ACPI TABLE sig=IVRS ' $log || die "amdvi: QEMU listed no IVRS"
grep -q '^AMDVI IVRS address=0x[0-9a-f]* length=[0-9]* revision=1 ivinfo=0x00002800 efrsup=0 preboot-dma-protection=0$' $log || die "amdvi: IVRS header"
grep -q '^AMDVI UNIT devid=00:[0-9a-f][0-9a-f]\.[0-7] cap=0x40 base=0xfed80000 window=0x4000 segment=0 info=0x0000 flags=0xd1 used=10h present=10h efr=none host-levels=unknown ivmd=0$' $log || die "amdvi: unit line"
grep -qx 'AMDVI SPECIAL ioapic handle=0 source=00:14.0 setting=0x00' $log || die "amdvi: IOAPIC special"
grep -qx 'AMDVI DEVIATION block=10h offset=0x44 field=feature-reserved-without-efrsup rule=reserved raw=0x44 unexpected=0x44' $log || die "amdvi: reserved feature field not reported"
[ "$(grep -c '^AMDVI DEVIATION' $log)" -eq 1 ] || die "amdvi: expected exactly one deviation"
grep -q '^AMDVI PCI devid=00:[0-9a-f][0-9a-f]\.[0-7] ids=0x[0-9a-f]*1022 class=0x080600 cap=0x40 listed=yes cap-header=0x[0-9a-f]*0f base-low=0x[0-9a-f]* base-high=0x[0-9a-f]* base=0x[0-9a-f]* base-enable=0$' $log || die "amdvi: PCI cross-check"
grep -q '^AMDVI MEMORY base=0xfed80000 window=0x4000 map=\(reserved\|unlisted\)$' $log || die "amdvi: memory placement"
amdvi_unobserved $log amdvi
grep -q '^AMDVI RESULT devid=00:[0-9a-f][0-9a-f]\.[0-7] base=0xfed80000 pci-base=unverified-enable-0 structure=valid deviations=1 validated-fields=[1-9][0-9]* unvalidated-fields=[1-9][0-9]* dma-admission=not-established preboot-dma=uncontained$' $log || die "amdvi: result line"
if grep -q '^AMDVI REFUSED' $log; then die "amdvi: unexpected refusal"; fi
python3 - "$out" <<'PY'
import struct, sys
out = sys.argv[1]
def ivrs(revision, ivinfo, blocks):
    length = 48 + sum(len(b) for b in blocks)
    raw = bytearray(b'IVRS' + struct.pack('<IBB', length, revision, 0) + b'ABSD  ' + b'ABSDTEST'
                    + struct.pack('<I', 1) + b'ABSD' + struct.pack('<II', 1, ivinfo) + bytes(8))
    for b in blocks:
        raw += b
    raw[9] = (-sum(raw)) & 0xff
    return bytes(raw)
def ivhd(kind, devid, base, word, entries, efr=0, flags=0x20, cap=0x40):
    header = 24 if kind == 0x10 else 40
    body = struct.pack('<BBHHHQHHI', kind, flags, header + len(entries), devid, cap, base, 0, 0, word)
    if header == 40:
        body += struct.pack('<QQ', efr, 0)
    return body + entries
def e4(kind, devid, setting=0):
    return struct.pack('<BHB', kind, devid, setting)
def e8(kind, devid, setting, b4, devid_b, b7):
    return struct.pack('<BHBBHB', kind, devid, setting, b4, devid_b, b7)
def f0(devid, setting, hid, uid):
    return struct.pack('<BHB', 0xf0, devid, setting) + hid + bytes(8) + struct.pack('<BB', 2, len(uid)) + uid
qemu_like = e4(2, 0x0000) + e4(2, 0x0008) + e8(0x48, 0, 0, 0, 0x00a0, 1)
# An IVMD (unity range) after a plain unit: refused, not half-honoured.
ivmd = struct.pack('<BBHHHHQQQ', 0x20, 0x07, 32, 0, 0, 0, 0, 0x100000, 0x1000)
open(f'{out}/ivrs-ivmd.aml', 'wb').write(ivrs(1, 0x2800, [ivhd(0x10, 0x0008, 0xfed80000, 0, qemu_like), ivmd]))
# A range start without its end.
open(f'{out}/ivrs-unpaired.aml', 'wb').write(ivrs(1, 0x2800, [ivhd(0x10, 0x0008, 0xfed80000, 0, e4(3, 0x0008) + e4(2, 0x0010))]))
# The review's reproducer (coordination record#111 review R1): a capability offset
# whose block runs past FFh, naming 00:00.0, which exists in q35.
for cap in (0xf8, 0xfc):
    open(f'{out}/ivrs-cap{cap:x}.aml', 'wb').write(ivrs(1, 0x2800, [ivhd(0x10, 0x0000, 0xfed80000, 0, e4(2, 0x0000) + e4(2, 0x0008), cap=cap)]))
# The synthetic target shape (src/ivrs/tests.rs `syn`, invented values):
# 10h/11h/40h, a flat range with a one-bus alias over its tail (reported as
# a deviation in each block), a reserved zero entry, three specials, four
# ACPI-HID entries. It is structurally valid; no IOMMU function exists at
# 00:02.1 here, so PCI refuses it.
efr = (2 << 10) | (1 << 9) | (1 << 6) | (1 << 1)
fixed = (e4(3, 0x0018) + e4(4, 0x7ffe) + e8(0x43, 0x7f00, 0, 0, 0x0040, 0) + e4(4, 0x7fff) + bytes(4)
         + e8(0x48, 0, 0, 1, 0x0038, 2) + e8(0x48, 0, 0x01, 5, 0x0038, 1) + e8(0x48, 0, 0, 6, 0x0039, 1))
hids = b''.join(f0(0x0040, 0x80, b'ABSD0001', b'\\_SB.SYN%d' % n) for n in range(4))
feature = (2 << 30) | (1 << 17) | (2 << 13) | (1 << 5)
attributes = (1 << 17) | (2 << 13)
open(f'{out}/ivrs-syn-shape.aml', 'wb').write(ivrs(2, (52 << 8) | 1, [
    ivhd(0x10, 0x0011, 0xf7f80000, feature, fixed, cap=0x50),
    ivhd(0x11, 0x0011, 0xf7f80000, attributes, fixed, efr, cap=0x50),
    ivhd(0x40, 0x0011, 0xf7f80000, attributes, fixed + hids, efr, cap=0x50)]))
PY
boot amdvi-ivmd acpi-test 3 -smp 2 -m 512M -acpitable file=$out/ivrs-ivmd.aml
grep -q '^AMDVI REFUSED class=unsupported reason=ivmd-present offset=0x[0-9a-f]* block=0x20$' $out/amdvi-ivmd.serial.log || die "amdvi-ivmd: IVMD not refused"
boot amdvi-unpaired acpi-test 3 -smp 2 -m 512M -acpitable file=$out/ivrs-unpaired.aml
grep -q '^AMDVI REFUSED class=malformed reason=entry offset=0x[0-9a-f]* problem=Unpaired$' $out/amdvi-unpaired.serial.log || die "amdvi-unpaired: not refused"
for cap in f8 fc; do
	boot amdvi-cap$cap acpi-test 3 -smp 2 -m 512M -acpitable file=$out/ivrs-cap$cap.aml
	grep -qx "AMDVI REFUSED class=malformed reason=capability-offset offset=0x30 capability=0x$cap" $out/amdvi-cap$cap.serial.log || die "amdvi-cap$cap: capability offset not refused"
	grep -qx 'ACPI OK' $out/amdvi-cap$cap.serial.log || die "amdvi-cap$cap: no ACPI OK"
done
boot amdvi-syn-shape acpi-test 3 -smp 2 -m 512M -acpitable file=$out/ivrs-syn-shape.aml
log=$out/amdvi-syn-shape.serial.log
grep -q '^AMDVI UNIT devid=00:02.1 cap=0x50 base=0xf7f80000 window=0x80000 segment=0 info=0x0000 flags=0x20 used=11h present=10h,11h,40h efr=0x0000000000000a42 efr2=0x0 host-levels=6 ivmd=0$' $log || die "amdvi-syn-shape: unit not parsed"
grep -qx 'AMDVI ENTRY alias first=7f:00.0 last=7f:1f.7 setting=0x00 source=00:08.0' $log || die "amdvi-syn-shape: alias range"
grep -qx 'AMDVI HID devid=00:08.0 hid=ABSD0001 uid=\\_SB.SYN3 setting=0x80 use=recorded-only' $log || die "amdvi-syn-shape: HID entry"
grep -qx 'AMDVI SUMMARY spans=2 aliased-ids=256 specials=3 hids=4 padding=1 own-source=undescribed' $log || die "amdvi-syn-shape: summary"
grep -q '^AMDVI DEVIATION block=11h offset=0x[0-9a-f]* field=alias-over-range-tail rule=tolerated-overlap first=0x7f00 last=0x7fff target=0x0040 end-offset=0x[0-9a-f]*$' $log || die "amdvi-syn-shape: tolerated alias not reported as a deviation"
[ "$(grep -c '^AMDVI DEVIATION' $log)" -eq 3 ] || die "amdvi-syn-shape: expected the alias deviation once per block, nothing else"
grep -qx 'AMDVI REFUSED class=mismatch reason=pci-absent' $log || die "amdvi-syn-shape: missing IOMMU function not refused"
# Two IVRS tables (QEMU's and one more) are ambiguous.
boot amdvi-dup acpi-test 3 -smp 2 -m 512M -device amd-iommu -acpitable file=$out/ivrs-unpaired.aml
grep -qx 'AMDVI REFUSED class=malformed reason=table-Duplicate' $out/amdvi-dup.serial.log || die "amdvi-dup: duplicate IVRS not refused"
for name in amdvi amdvi-ivmd amdvi-unpaired amdvi-capf8 amdvi-capfc amdvi-syn-shape amdvi-dup; do
	if grep -q '^AMDVI REFUSED' $out/$name.serial.log && ! grep -q '^AMDVI REFUSED class=\(malformed\|unsupported\|mismatch\) ' $out/$name.serial.log; then die "$name: refusal without a class"; fi
	if grep '^AMDVI' $out/$name.serial.log | grep -qi 'canonical\|conform\|dma-admission=[^n]'; then die "$name: scope stated as a single word or admission claimed"; fi
done
for name in amdvi-ivmd amdvi-unpaired amdvi-capf8 amdvi-capfc amdvi-syn-shape amdvi-dup; do
	if grep -q '^AMDVI RESULT' $out/$name.serial.log; then die "$name: refused table has a result line"; fi
done

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
echo 'acpi-test: MADT, FADT, S5 power-off, AMD-Vi discovery and refusals qualified (build/acpi)'
