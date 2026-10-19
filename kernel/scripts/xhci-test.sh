#!/bin/sh
# Bounded xHCI bring-up qualification (docs/xhci-20261010/RECORD.md).
# Every case is a fresh, disposable QEMU boot of an `xhci-probe` ISO built
# by `make xhci-iso` (or the default ISO, for the not-probed control). Each
# must exit through the kernel's success path (QEMU status 3) with the
# ordinary boot suite complete (`ABSD BOOT OK`) and no panic or kernel
# fault, whatever happened to the controller: an absent or failed xHCI
# must not cost the rest of the kernel anything. Each result line is
# printed only after its checks pass; any failed check stops the script.
#
#   xhci-test.sh [QEMU]
set -eu
qemu=${1:-qemu-system-x86_64}
cd "$(dirname "$0")/.."
work=build/xhci
rm -rf "${work:?}"
mkdir -p "$work"

die() { printf 'XHCI TEST FAILED: %s\n' "$*" >&2; exit 1; }
has() { grep -qx -- "$1" "$2" || die "$2 lacks '$1'"; }
has_re() { grep -q -- "$1" "$2" || die "$2 lacks /$1/"; }
lacks_re() { if grep -q -- "$1" "$2"; then die "$2 has /$1/"; fi; }
count() { n=$(grep -c -- "$1" "$2" || true); test "$n" -eq "$3" || die "$2 has $n lines /$1/, not $3"; }

common="-display none -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04"
# A case boots one ISO with extra QEMU arguments into $work/NAME.log.
boot() {
	name=$1; iso=$2; shift 2
	log=$work/$name.log
	status=0
	# shellcheck disable=SC2086
	timeout 120s $qemu -cdrom "build/absd-xhci-$iso.iso" $common -serial "file:$log" "$@" >/dev/null 2>&1 || status=$?
	test "$status" -eq 3 || die "$name: QEMU exited $status, not 3"
	settled "$log"
}
# The boot finished normally; if the controller was probed it was halted.
# Once claimed, the driver let go of it exactly one way: taken off the bus
# (ABSD owned it) or preserved (ABSD never established ownership). The
# firmware model, where present, saw no change while ABSD was not owner.
settled() {
	lacks_re 'PANIC\|KERNEL FAULT' "$1"
	has 'ABSD BOOT OK' "$1"
	if grep -q '^XHCI HALTED' "$1"; then
		lacks_re '^XHCI HALTED .* halted=no' "$1"
	fi
	lacks_re '^XHCI DMA ON' "$1"
	lacks_re '^XHCI FIRMWARE MODEL VIOLATION' "$1"
	if grep -q '^XHCI FIRMWARE MODEL' "$1"; then
		has_re '^XHCI FIRMWARE MODEL behaviour=.* violations=0 ' "$1"
	fi
	if grep -q '^XHCI CLAIMED' "$1"; then
		count '^XHCI DMA OFF bus_master=0 command=[0-9a-f]\{4\}$\|^XHCI PRESERVED \|^XHCI ABANDONED ' "$1" 1
		if grep -q '^XHCI PRESERVED ' "$1"; then
			as_found "$1"
		fi
	fi
}
# Preserved as found: the PCI command register as it was at the claim,
# USBCMD (where it could be read) as it was found, nothing started.
as_found() {
	claim=$(sed -n 's/^XHCI CLAIMED pci_command=\([0-9a-f]*\)$/\1/p' "$1")
	has_re "^XHCI PRESERVED owner=[a-z-]* usbcmd=\(unread\|[0-9a-f]\{8\}\) pci_command=$claim bus_master=" "$1"
	if grep -q '^XHCI FOUND' "$1"; then
		found=$(sed -n 's/^XHCI FOUND usbcmd=\([0-9a-f]*\) .*/\1/p' "$1")
		has_re "^XHCI PRESERVED owner=[a-z-]* usbcmd=$found pci_command=" "$1"
	fi
	lacks_re '^XHCI RUNNING\|^XHCI PAGESIZE\|^XHCI SCRATCHPAD INSTALLED\|^XHCI CONTROLLER' "$1"
	legacy_left "$1"
}
# The legacy semaphores as left, where a handoff was attempted: ABSD's OS
# request withdrawn (bit 24 clear); with owner=firmware both registers equal
# what was found, in the guest's PRESERVED line and in the model's own state;
# with owner=indeterminate the SMI control is as found (firmware itself may
# have changed its semaphore); indeterminate-smi-cleared names the SMI
# enables ABSD cleared.
legacy_left() {
	grep -q '^XHCI LEGACY ' "$1" || return 0
	sup=$(sed -n 's/^XHCI LEGACY offset=[0-9a-f]* legsup=\([0-9a-f]*\) control=\([0-9a-f]*\)$/\1/p' "$1")
	ctl=$(sed -n 's/^XHCI LEGACY offset=[0-9a-f]* legsup=\([0-9a-f]*\) control=\([0-9a-f]*\)$/\2/p' "$1")
	has_re '^XHCI PRESERVED .* legsup=00[0-9a-f]\{6\} legctlsts=[0-9a-f]\{8\}$' "$1"
	if grep -q '^XHCI PRESERVED owner=firmware ' "$1"; then
		has_re "^XHCI PRESERVED owner=firmware .* legsup=$sup legctlsts=$ctl\$" "$1"
		has_re "^XHCI FIRMWARE MODEL behaviour=.* violations=0 legsup=$sup control=$ctl " "$1"
	elif grep -q '^XHCI PRESERVED owner=indeterminate ' "$1"; then
		has_re "^XHCI PRESERVED owner=indeterminate .* legctlsts=$ctl\$" "$1"
		has_re "^XHCI FIRMWARE MODEL behaviour=.* violations=0 legsup=00[0-9a-f]\{6\} control=$ctl " "$1"
	elif grep -q '^XHCI PRESERVED owner=indeterminate-smi-cleared ' "$1"; then
		has_re '^XHCI UNAVAILABLE Refused(Handoff(LostAfterSmi { legsup: [0-9]*, smi_before: [0-9]* }))$' "$1"
	fi
}
# A round that completed: endpoint zero exercised, the round and the
# bring-up reported done.
completed() {
	has 'XHCI EP0 OK round=1 reads=8 transfer_ring_wraps=3' "$1"
	has 'XHCI ROUND OK round=1' "$1"
	has 'XHCI DONE rounds=1' "$1"
	lacks_re '^XHCI FAILED' "$1"
}
# Probed and claimed: identity, the handoff state, the ownership control.
claimed() {
	has_re '^XHCI CONTROLLER pci=[0-9a-f:.]* vendor=1b36 device=000d version=0100 bar_bytes=16384 slots=64 ports=8 context_bytes=32 ppc=0$' "$1"
	has 'XHCI PROTOCOL usb2 ports=5-8' "$1"
	has 'XHCI PROTOCOL usb3 ports=1-4' "$1"
	has_re '^XHCI HANDOFF usbcmd=[0-9a-f]\{8\} usbsts=[0-9a-f]\{8\} pci_command=[0-9a-f]\{4\}$' "$1"
	has 'XHCI SECOND CLAIM REFUSED owner=xhci' "$1"
}
ring_ok() { has "XHCI COMMAND RING OK round=$2 noops=40 command_ring_wraps=2 event_ring_wraps=2" "$1"; }
# A failure that must stop the controller: named, halted, no enumeration.
failed_closed() {
	has "XHCI FAILED round=1 error=$2" "$1"
	has_re '^XHCI HALTED round=1 halted=yes ' "$1"
	has 'XHCI STOPPED' "$1"
	lacks_re '^XHCI DEVICE\|^XHCI DONE\|^XHCI ROUND OK' "$1"
}
kbd_hs='usb=0200 class=00 vendor=0627 product=0001 max_packet0=64 configurations=1'
image=$work/nvme.img
truncate -s 2M "$image"
stick=$work/stick.img
truncate -s 1M "$stick"
# XHCI_CASES (space-separated case names) runs a subset; default: all.
cases=${XHCI_CASES:-}
want() { test -z "$cases" || case " $cases " in *" $1 "*) true ;; *) false ;; esac; }
passed=0

# 1. One high-speed usb-kbd, with an NVMe namespace alongside.
if want present; then
	boot present probe -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1 \
		-drive "if=none,id=nvm,file=$image,format=raw" -device nvme,serial=absd-xhci,drive=nvm
	log=$work/present.log
	claimed "$log"
	has 'XHCI RUNNING round=1' "$log"
	ring_ok "$log" 1
	has 'XHCI PORT round=1 port=5 connected speed=high protocol=usb2 power=1' "$log"
	has 'XHCI PORTS round=1 connected=1' "$log"
	has "XHCI DEVICE round=1 port=5 slot=1 address=1 $kbd_hs" "$log"
	has 'XHCI EP0 OK round=1 reads=8 transfer_ring_wraps=3' "$log"
	has 'XHCI ROUND OK round=1' "$log"
	has_re '^XHCI HALTED round=1 halted=yes commands=43 transfers=8 events=[0-9]* port_events=[0-9]*$' "$log"
	has 'XHCI DONE rounds=1' "$log"
	has 'BLOCK DEVICE OK sectors=4096' "$log"
	has 'BLOCK BACKEND nvme access=read-only' "$log"
	echo 'xhci-test: present: high-speed usb-kbd enumerated, device descriptor read, NVMe alongside'
	passed=$((passed + 1))
fi

# 2. No controller at all.
if want absent; then
	boot absent probe
	log=$work/absent.log
	has 'XHCI UNAVAILABLE Absent' "$log"
	lacks_re '^XHCI CONTROLLER\|^XHCI RUNNING' "$log"
	echo 'xhci-test: absent: refused by name, boot unaffected'
	passed=$((passed + 1))
fi

# 3. A controller with nothing attached.
if want empty; then
	boot empty probe -device qemu-xhci,id=xhci
	log=$work/empty.log
	claimed "$log"
	ring_ok "$log" 1
	has 'XHCI PORTS round=1 connected=0' "$log"
	has 'XHCI NO DEVICE round=1' "$log"
	lacks_re '^XHCI DEVICE\|^XHCI PORT round' "$log"
	has 'XHCI ROUND OK round=1' "$log"
	echo 'xhci-test: empty: controller initialized, no device reported, no enumeration'
	passed=$((passed + 1))
fi

# 4. Not probed unless asked: the default ISO never touches the controller.
if want default; then
	status=0
	timeout 120s $qemu -cdrom build/absd-kernel.iso $common -serial "file:$work/default.log" \
		-device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 >/dev/null 2>&1 || status=$?
	test "$status" -eq 3 || die "default: QEMU exited $status, not 3"
	settled "$work/default.log"
	lacks_re '^XHCI' "$work/default.log"
	echo 'xhci-test: default boot: controller present, never probed'
	passed=$((passed + 1))
fi

# 5. Three full reset/initialize/enumerate/halt rounds in one boot.
if want rounds; then
	boot rounds rounds -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1
	log=$work/rounds.log
	claimed "$log"
	for round in 1 2 3; do
		has "XHCI RUNNING round=$round" "$log"
		ring_ok "$log" "$round"
		has "XHCI DEVICE round=$round port=5 slot=1 address=1 $kbd_hs" "$log"
		has "XHCI ROUND OK round=$round" "$log"
		has_re "^XHCI HALTED round=$round halted=yes " "$log"
	done
	has 'XHCI DONE rounds=3' "$log"
	echo 'xhci-test: rounds: three resets, initializations and enumerations, each ending halted'
	passed=$((passed + 1))
fi

# 6. Speeds: SuperSpeed usb-storage (read-only scratch image; only its
# device descriptor is read), full-speed usb-kbd (8-byte endpoint zero),
# and full-speed usb-audio (64-byte endpoint zero, Evaluate Context).
if want speeds; then
	boot super probe -device qemu-xhci,id=xhci \
		-drive "if=none,id=stick,file=$stick,format=raw,readonly=on" -device usb-storage,bus=xhci.0,drive=stick
	log=$work/super.log
	claimed "$log"
	completed "$log"
	has 'XHCI PORT round=1 port=1 connected speed=super protocol=usb3 power=1' "$log"
	has 'XHCI DEVICE round=1 port=1 slot=1 address=1 usb=0300 class=00 vendor=46f4 product=0001 max_packet0=512 configurations=1' "$log"
	boot full probe -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,usb_version=1
	log=$work/full.log
	claimed "$log"
	completed "$log"
	has 'XHCI PORT round=1 port=5 connected speed=full protocol=usb2 power=1' "$log"
	has 'XHCI DEVICE round=1 port=5 slot=1 address=1 usb=0200 class=00 vendor=0627 product=0001 max_packet0=8 configurations=1' "$log"
	lacks_re '^XHCI EP0 PACKET UPDATED' "$log"
	boot full64 probe -audiodev none,id=snd -device qemu-xhci,id=xhci -device usb-audio,bus=xhci.0,audiodev=snd
	log=$work/full64.log
	claimed "$log"
	completed "$log"
	has 'XHCI PORT round=1 port=5 connected speed=full protocol=usb2 power=1' "$log"
	has 'XHCI EP0 PACKET UPDATED from=8 to=64' "$log"
	has 'XHCI DEVICE round=1 port=5 slot=1 address=1 usb=0100 class=00 vendor=46f4 product=0002 max_packet0=64 configurations=1' "$log"
	echo 'xhci-test: speeds: super (512), high (64), full (8), full with packet-size update (8 -> 64)'
	passed=$((passed + 1))
fi

# 7. Register bounds: BAR0 treated as 64 bytes; refused before any
# operational register is touched. Ownership cannot be established without
# a trusted layout, so (successor lane) the controller is preserved as found,
# bus mastering included, instead of being taken off the bus.
if want bar-bounds; then
	boot bar-bounds bar-bounds -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0
	log=$work/bar-bounds.log
	has 'XHCI UNAVAILABLE Refused(Layout(OutsideBar { region: "operational", end: 1216 }))' "$log"
	lacks_re '^XHCI CONTROLLER\|^XHCI RUNNING\|^XHCI FOUND\|^XHCI DMA OFF' "$log"
	has_re '^XHCI PRESERVED owner=indeterminate usbcmd=unread pci_command=[0-9a-f]\{4\} bus_master=[01]$' "$log"
	echo 'xhci-test: bar-bounds: layout outside the BAR refused, controller preserved as found'
	passed=$((passed + 1))
fi

# 8. Initialization timeout: Run/Stop never set.
if want run-timeout; then
	boot run-timeout run-timeout -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0
	failed_closed "$work/run-timeout.log" 'Timeout("run")'
	lacks_re '^XHCI RUNNING' "$work/run-timeout.log"
	echo 'xhci-test: run-timeout: bounded, named, halted, boot unaffected'
	passed=$((passed + 1))
fi

# 9. Command timeout: a command whose doorbell is never rung.
if want command-timeout; then
	boot command-timeout command-timeout -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 \
		-drive "if=none,id=nvm,file=$image,format=raw" -device nvme,serial=absd-xhci,drive=nvm
	log=$work/command-timeout.log
	has 'XHCI FAULT INJECTED command-timeout' "$log"
	failed_closed "$log" 'Timeout("command")'
	has 'BLOCK BACKEND nvme access=read-only' "$log"
	echo 'xhci-test: command-timeout: bounded, named, halted, boot and NVMe unaffected'
	passed=$((passed + 1))
fi

# 10. A completion for a command never submitted, and a non-event TRB on the
# event ring, each substituted for the controller's next event.
if want events; then
	boot foreign-event foreign-event -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0
	log=$work/foreign-event.log
	has 'XHCI FAULT INJECTED foreign-event' "$log"
	has_re '^XHCI FAILED round=1 error=Unexpected(CommandCompletion { command: [0-9]*, code: 1, slot: 0 })$' "$log"
	has_re '^XHCI HALTED round=1 halted=yes ' "$log"
	has 'XHCI STOPPED' "$log"
	lacks_re '^XHCI DEVICE\|^XHCI DONE\|^XHCI COMMAND RING OK' "$log"
	boot malformed-event malformed-event -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0
	log=$work/malformed-event.log
	has 'XHCI FAULT INJECTED malformed-event' "$log"
	failed_closed "$log" 'Malformed(Malformed { kind: 1 })'
	echo 'xhci-test: foreign-event, malformed-event: refused, controller stopped, boot unaffected'
	passed=$((passed + 1))
fi

# 11. The controller's own error completion (Address Device on a slot never
# enabled) is named and not fatal: enumeration follows normally.
if want bad-slot; then
	boot bad-slot bad-slot -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1
	log=$work/bad-slot.log
	has 'XHCI BAD SLOT REFUSED code=SlotNotEnabled(11)' "$log"
	has "XHCI DEVICE round=1 port=5 slot=1 address=1 $kbd_hs" "$log"
	has 'XHCI DONE rounds=1' "$log"
	echo 'xhci-test: bad-slot: SlotNotEnabled reported by name, enumeration unaffected'
	passed=$((passed + 1))
fi

# 12. Detach and re-attach (QEMU monitor device_del/device_add): the slot is
# disabled and the new full-speed device enumerated afresh.
if want hotplug; then
	timeout 180s python3 scripts/xhci-hotplug.py "$work/hotplug" "$work/hotplug.log" \
		$qemu -cdrom build/absd-xhci-hotplug.iso $common
	log=$work/hotplug.log
	settled "$log"
	has "XHCI DEVICE round=1 port=5 slot=1 address=1 $kbd_hs" "$log"
	has 'XHCI AWAIT DETACH port=5' "$log"
	has 'XHCI DETACHED port=5' "$log"
	has 'XHCI ATTACHED port=5' "$log"
	has 'XHCI DEVICE round=1 port=5 slot=1 address=1 usb=0200 class=00 vendor=0627 product=0001 max_packet0=8 configurations=1' "$log"
	count '^XHCI DEVICE ' "$log" 2
	has 'XHCI DONE rounds=1' "$log"
	echo 'xhci-test: hotplug: detach seen, slot disabled, re-attached device enumerated'
	passed=$((passed + 1))
fi

# 13. Nobody detaches: the hotplug wait is bounded too.
if want hotplug-timeout; then
	boot hotplug-timeout hotplug -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1
	failed_closed_after_device() {
		has "XHCI FAILED round=1 error=$2" "$1"
		has_re '^XHCI HALTED round=1 halted=yes ' "$1"
		has 'XHCI STOPPED' "$1"
	}
	failed_closed_after_device "$work/hotplug-timeout.log" 'Timeout("detach")'
	has "XHCI DEVICE round=1 port=5 slot=1 address=1 $kbd_hs" "$work/hotplug-timeout.log"
	has 'XHCI AWAIT DETACH port=5' "$work/hotplug-timeout.log"
	echo 'xhci-test: hotplug-timeout: the detach wait ends by name, halted'
	passed=$((passed + 1))
fi

# 14. A stale completion: the previous command's completion substituted
# for the controller's next event.
if want stale-event; then
	boot stale-event stale-event -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0
	log=$work/stale-event.log
	has 'XHCI FAULT INJECTED stale-event' "$log"
	ring_ok "$log" 1
	has_re '^XHCI FAILED round=1 error=Unexpected(CommandCompletion { command: [0-9]*, code: 1, slot: 0 })$' "$log"
	has_re '^XHCI HALTED round=1 halted=yes ' "$log"
	has 'XHCI STOPPED' "$log"
	lacks_re '^XHCI DEVICE\|^XHCI DONE' "$log"
	echo 'xhci-test: stale-event: a repeated completion refused, controller stopped'
	passed=$((passed + 1))
fi

# 15. A real short data stage: 64 bytes asked, 18 returned (Short Packet on
# the data TRB with ISP), refused by name; enumeration then continues.
if want short-read; then
	boot short-read short-read -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1
	log=$work/short-read.log
	has 'XHCI FAULT INJECTED short-read' "$log"
	has 'XHCI SHORT REFUSED expected=64 got=18' "$log"
	has "XHCI DEVICE round=1 port=5 slot=1 address=1 $kbd_hs" "$log"
	completed "$log"
	echo 'xhci-test: short-read: short data stage measured and refused, enumeration unaffected'
	passed=$((passed + 1))
fi

# 16. Firmware first: q35 + OVMF boots the ISO from a usb-storage stick on
# the same xHCI, then the kernel takes the controller over and enumerates
# the stick (its device descriptor only).
if want firmware; then
	cp /usr/share/OVMF/OVMF_VARS_4M.fd "$work/OVMF_VARS.fd"
	status=0
	timeout 180s $qemu -machine q35 -m 512M \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
		-drive "if=pflash,format=raw,unit=1,file=$work/OVMF_VARS.fd" \
		-drive if=none,id=stick,file=build/absd-xhci-probe.iso,format=raw,readonly=on \
		-device qemu-xhci,id=xhci -device usb-storage,bus=xhci.0,drive=stick,bootindex=1 \
		$common -serial "file:$work/firmware.log" >/dev/null 2>&1 || status=$?
	test "$status" -eq 3 || die "firmware: QEMU exited $status, not 3"
	log=$work/firmware.log
	settled "$log"
	claimed "$log"
	has 'XHCI DEVICE round=1 port=1 slot=1 address=1 usb=0300 class=00 vendor=46f4 product=0001 max_packet0=512 configurations=1' "$log"
	has 'XHCI DONE rounds=1' "$log"
	echo 'xhci-test: firmware: OVMF-used controller reset, re-initialized, boot stick enumerated'
	passed=$((passed + 1))
fi

# ---------------------------------------------------------------------------
# Successor lane (docs/xhci-hw-readiness-20261010/RECORD.md): scratchpads and
# the USB Legacy Support ownership handoff. QEMU's qemu-xhci advertises no
# scratchpads (HCSPARAMS2 0000000f) and no legacy capability (its list is two
# Supported Protocol capabilities), which `present` asserts. The counts below
# are substituted into HCSPARAMS2 as the driver reads it; the firmware owner
# is a model spliced into the capability list at read time. Where the case
# says `observed`, scripts/xhci-observe.py pauses the guest while the
# controller runs and reads DCBAAP from the device and the array from guest
# memory: what a controller would consume, independently of the guest's log.

# A boot through the observer (QMP pause, monitor reads, resume).
observe_boot() {
	name=$1; iso=$2; shift 2
	log=$work/$name.log
	status=0
	# shellcheck disable=SC2086
	timeout 200s python3 scripts/xhci-observe.py "$work/$name-qmp" "$log" "$work/$name.obs" \
		$qemu -cdrom "build/absd-xhci-$iso.iso" $common "$@" >/dev/null 2>&1 || status=$?
	test "$status" -eq 3 || die "$name: observed boot exited $status, not 3"
	settled "$log"
}
# Round $2 was observed running with exactly $3 scratchpad entries: each
# 4 KiB-aligned, distinct, followed by a zero entry, at the array address
# the guest reported installing.
observed() {
	obs=$work/$1.obs
	has_re "^OBSERVED round=$2 usbcmd=[0-9a-f]*[13579bdf] dcbaap=0x[0-9a-f]* dcbaa0=0x[0-9a-f]* entries=$3 aligned=1 distinct=1 terminator=0x0 " "$obs"
	array=$(sed -n "s/^XHCI SCRATCHPAD INSTALLED round=$2 count=[0-9]* page_bytes=4096 array=\(0x[0-9a-f]*\) .*/\1/p" "$work/$1.log")
	test -n "$array" || die "$1: no installed array for round $2"
	array=$(printf '%#x' "$((array))")
	has_re "^OBSERVED round=$2 .* dcbaa0=$array " "$obs"
}
# The device's own capability values, unsubstituted.
device_caps() {
	has 'XHCI SCRATCHPADS required=0 spr=0 hcsparams2=0000000f device_hcsparams2=0000000f source=device' "$1"
	has 'XHCI EXTCAP offset=0020 id=2 header=02000402 source=device' "$1"
	has 'XHCI EXTCAP offset=0030 id=2 header=03000002 source=device' "$1"
	count '^XHCI EXTCAP ' "$1" 2
	has 'XHCI OWNERSHIP os-default legacy_capability=none' "$1"
}
substituted() { has_re "^XHCI SCRATCHPADS required=$2 spr=0 hcsparams2=[0-9a-f]\{8\} device_hcsparams2=0000000f source=substituted$" "$1"; }
# Modeled firmware capability spliced after the device's last one.
spliced() {
	has 'XHCI EXTCAP offset=0030 id=2 header=03004402 source=device next=substituted' "$1"
	has 'XHCI EXTCAP offset=0140 id=1 header=00010001 source=model' "$1"
}
# The driver owned the controller and refused or failed it: off the bus.
released() { has_re '^XHCI DMA OFF bus_master=0 command=[0-9a-f]\{4\}$' "$1"; lacks_re '^XHCI PRESERVED' "$1"; }
kbd() { boot "$@" -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1; }
nvme_drive="-drive if=none,id=nvm,file=$image,format=raw -device nvme,serial=absd-xhci,drive=nvm"

# 17. QEMU itself: no scratchpads, no legacy capability (device values).
if want device-caps; then
	if test ! -f "$work/present.log"; then
		kbd present probe
	fi
	device_caps "$work/present.log"
	echo 'xhci-test: device-caps: qemu-xhci advertises 0 scratchpads and no USB Legacy Support'
	passed=$((passed + 1))
fi

# 18. nec-usb-xhci (same QEMU core, NEC identity): the same, and enumerates.
if want nec; then
	boot nec probe -device nec-usb-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1
	log=$work/nec.log
	has_re '^XHCI CONTROLLER pci=[0-9a-f:.]* vendor=1033 device=0194 ' "$log"
	has_re '^XHCI SCRATCHPADS required=0 spr=0 hcsparams2=[0-9a-f]\{8\} device_hcsparams2=[0-9a-f]\{8\} source=device$' "$log"
	has 'XHCI OWNERSHIP os-default legacy_capability=none' "$log"
	lacks_re '^XHCI EXTCAP .* id=1 ' "$log"
	has_re '^XHCI DEVICE round=1 ' "$log"
	completed "$log"
	echo 'xhci-test: nec: nec-usb-xhci advertises 0 scratchpads and no USB Legacy Support, enumerates'
	passed=$((passed + 1))
fi

# 19. One scratchpad, observed installed while the controller runs.
if want scratch-one; then
	observe_boot scratch-one scratch-one -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1
	log=$work/scratch-one.log
	substituted "$log" 1
	has_re '^XHCI SCRATCHPAD INSTALLED round=1 count=1 page_bytes=4096 ' "$log"
	observed scratch-one 1 1
	completed "$log"
	has 'XHCI SCRATCHPAD RELEASED state=free installs=1' "$log"
	echo 'xhci-test: scratch-one: one scratchpad installed, observed in DCBAA[0], released after the halt'
	passed=$((passed + 1))
fi

# 20. 32 scratchpads (Max Scratchpad Buf Hi=1, Lo=0: the field boundary) over
# two full rounds; reinstalled after the reset, observed in both.
if want scratch-many; then
	observe_boot scratch-many scratch-many -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1
	log=$work/scratch-many.log
	substituted "$log" 32
	observed scratch-many 1 32
	observed scratch-many 2 32
	has "XHCI DEVICE round=2 port=5 slot=1 address=1 $kbd_hs" "$log"
	has 'XHCI ROUND OK round=2' "$log"
	has 'XHCI DONE rounds=2' "$log"
	count '^XHCI SCRATCHPAD RELEASED ' "$log" 2
	has 'XHCI SCRATCHPAD RELEASED state=free installs=2' "$log"
	echo 'xhci-test: scratch-many: 32 scratchpads, two rounds, observed both times, released after each reset'
	passed=$((passed + 1))
fi

# 21. The pool's limit (64) accepted; one more refused once ABSD owns it.
if want scratch-limit; then
	observe_boot scratch-limit scratch-limit -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1
	observed scratch-limit 1 64
	completed "$work/scratch-limit.log"
	kbd scratch-over scratch-over
	log=$work/scratch-over.log
	substituted "$log" 65
	has 'XHCI UNAVAILABLE Refused(Scratchpads(Exhausted { required: 65, limit: 64 }))' "$log"
	released "$log"
	lacks_re '^XHCI SCRATCHPAD INSTALLED\|^XHCI RUNNING' "$log"
	echo 'xhci-test: scratch-limit: 64 installed and observed; 65 refused by name, off the bus'
	passed=$((passed + 1))
fi

# 22. Page sizes: 8 KiB only, and 4 KiB+8 KiB, refused when scratchpads are
# required; 4 KiB+8 KiB accepted without scratchpads. Refused while the
# controller is halted and reset; bus mastering may still be on as firmware
# left it.
if want page-size; then
	kbd page-8k page-8k
	log=$work/page-8k.log
	has 'XHCI PAGESIZE round=1 value=00000002 source=substituted' "$log"
	has 'XHCI FAILED round=1 error=Refused(PageSize(2))' "$log"
	has 'XHCI STOPPED' "$log"
	lacks_re '^XHCI SCRATCHPAD INSTALLED\|^XHCI RUNNING' "$log"
	released "$log"
	kbd page-multi page-multi
	log=$work/page-multi.log
	has 'XHCI FAILED round=1 error=Refused(PageSizes(3))' "$log"
	lacks_re '^XHCI SCRATCHPAD INSTALLED\|^XHCI RUNNING' "$log"
	released "$log"
	kbd page-multi-none page-multi-none
	log=$work/page-multi-none.log
	has 'XHCI PAGESIZE round=1 value=00000003 source=substituted' "$log"
	completed "$log"
	echo 'xhci-test: page-size: 8 KiB and ambiguous page sizes refused with scratchpads, before the round arms the controller'
	passed=$((passed + 1))
fi

# 23. A scratchpad page fails its DMA check halfway through the array: the
# preparation is abandoned while the controller is halted and reset (DCBAAP
# cleared) and before the round arms it, the round is contained,
# and the next round installs all eight.
if want scratch-alloc; then
	kbd scratch-alloc scratch-alloc
	log=$work/scratch-alloc.log
	has 'XHCI FAULT INJECTED scratchpad-alloc' "$log"
	has_re '^XHCI SCRATCHPAD ABANDONED required=8 error=Refused(Address(Unowned { index: 4, address: [0-9]* }))$' "$log"
	has_re '^XHCI FAILED round=1 error=Refused(Address(Unowned { index: 4, ' "$log"
	has 'XHCI ROUND CONTAINED round=1' "$log"
	lacks_re '^XHCI SCRATCHPAD INSTALLED round=1\|^XHCI RUNNING round=1' "$log"
	has_re '^XHCI SCRATCHPAD INSTALLED round=2 count=8 ' "$log"
	has 'XHCI ROUND OK round=2' "$log"
	has 'XHCI DONE rounds=2' "$log"
	has 'XHCI SCRATCHPAD RELEASED state=free installs=1' "$log"
	echo 'xhci-test: scratch-alloc: partial preparation rolled back unseen, next round installs and runs'
	passed=$((passed + 1))
fi

# 24. Reclaim asked for while the controller runs with the pages: refused.
if want scratch-reclaim; then
	kbd scratch-reclaim scratch-reclaim
	log=$work/scratch-reclaim.log
	has 'XHCI FAULT INJECTED early-reclaim' "$log"
	has 'XHCI SCRATCHPAD RECLAIM REFUSED state=installed halted=0 bus_master=1' "$log"
	lacks_re '^XHCI SCRATCHPAD RECLAIMED WHILE RUNNING' "$log"
	completed "$log"
	has 'XHCI SCRATCHPAD RELEASED state=free installs=1' "$log"
	echo 'xhci-test: scratch-reclaim: reclaim while running refused; released only after halt and bus-master off'
	passed=$((passed + 1))
fi

# 25. Firmware owns the controller and releases on request.
if want legacy-release; then
	kbd legacy-release legacy-release
	log=$work/legacy-release.log
	spliced "$log"
	has 'XHCI LEGACY offset=0140 legsup=00010001 control=00002001' "$log"
	has 'XHCI OWNERSHIP CONFIRMED requested=1 waited_ticks=0 initial=00010001 smi_before=00002001 smi_after=00000000' "$log"
	completed "$log"
	has 'XHCI FIRMWARE MODEL behaviour=Release violations=0 legsup=01000001 control=00000000 requests=1 withdrawals=0' "$log"
	echo 'xhci-test: legacy-release: ownership confirmed before any change, SMIs disabled, enumeration'
	passed=$((passed + 1))
fi

# 26. Firmware releases 300 ticks after the request.
if want legacy-delayed; then
	kbd legacy-delayed legacy-delayed
	log=$work/legacy-delayed.log
	has_re '^XHCI OWNERSHIP CONFIRMED requested=1 waited_ticks=30[0-9] initial=00010001 ' "$log"
	completed "$log"
	echo 'xhci-test: legacy-delayed: bounded wait outlasted the delay, ownership then confirmed'
	passed=$((passed + 1))
fi

# 27. Firmware never releases: refused after the bound, preserved as found,
# bus mastering and the running controller untouched, SMIs untouched.
if want legacy-never; then
	kbd legacy-never legacy-never
	log=$work/legacy-never.log
	has_re '^XHCI UNAVAILABLE Refused(Handoff(FirmwareRetained { legsup: 16842753, waited: 100[0-9] }))$' "$log"
	has_re '^XHCI PRESERVED owner=firmware usbcmd=[0-9a-f]\{8\} pci_command=[0-9a-f]\{4\} bus_master=1 legsup=00010001 legctlsts=00002001$' "$log"
	has 'XHCI FIRMWARE MODEL behaviour=Never violations=0 legsup=00010001 control=00002001 requests=1 withdrawals=1' "$log"
	lacks_re '^XHCI DMA OFF' "$log"
	# Firmware that would release after the bound: the withdrawn request
	# cancels it, and the semaphores are left exactly as found.
	kbd legacy-late legacy-late
	log=$work/legacy-late.log
	has_re '^XHCI UNAVAILABLE Refused(Handoff(FirmwareRetained { legsup: 16842753, waited: 100[0-9] }))$' "$log"
	has_re '^XHCI PRESERVED owner=firmware .* legsup=00010001 legctlsts=00002001$' "$log"
	has 'XHCI FIRMWARE MODEL behaviour=Delayed(1500) violations=0 legsup=00010001 control=00002001 requests=1 withdrawals=1' "$log"
	echo 'xhci-test: legacy-never: ownership timeout bounded, request withdrawn, firmware state and bus mastering preserved; late release cancelled'
	passed=$((passed + 1))
fi

# 28. Two USB Legacy Support capabilities: the list is not trusted, nothing
# is requested, the controller is preserved.
if want legacy-duplicate; then
	kbd legacy-duplicate legacy-duplicate
	log=$work/legacy-duplicate.log
	has 'XHCI UNAVAILABLE Refused(Capabilities(DuplicateLegacy { first: 320, second: 336 }))' "$log"
	has_re '^XHCI PRESERVED owner=indeterminate ' "$log"
	has 'XHCI FIRMWARE MODEL behaviour=Duplicate violations=0 legsup=00010001 control=00002001 requests=0 withdrawals=0' "$log"
	lacks_re '^XHCI LEGACY\|^XHCI OWNERSHIP' "$log"
	echo 'xhci-test: legacy-duplicate: invalid legacy capability refused without a request, preserved'
	passed=$((passed + 1))
fi

# 29. Firmware turns on more SMIs and raises an SMI event while ABSD waits;
# after ownership every enable is cleared and the event acknowledged.
if want legacy-smi; then
	kbd legacy-smi legacy-smi
	log=$work/legacy-smi.log
	has_re '^XHCI OWNERSHIP CONFIRMED requested=1 waited_ticks=5[0-9] initial=00010001 smi_before=2000a011 smi_after=00000000$' "$log"
	completed "$log"
	echo 'xhci-test: legacy-smi: SMI state changed during negotiation, all disabled after ownership'
	passed=$((passed + 1))
fi

# 30. SMI enables that do not clear: ABSD owns the controller but refuses
# it, so it is halted and taken off the bus.
if want legacy-smi-stuck; then
	kbd legacy-smi-stuck legacy-smi-stuck
	log=$work/legacy-smi-stuck.log
	has 'XHCI UNAVAILABLE Refused(Handoff(SmiStuck { before: 8193, after: 8193 }))' "$log"
	released "$log"
	lacks_re '^XHCI RUNNING' "$log"
	echo 'xhci-test: legacy-smi-stuck: owned but SMIs stuck: refused, halted, off the bus'
	passed=$((passed + 1))
fi

# 31. Firmware clears both semaphores when asked: nobody demonstrably owns.
if want legacy-clears-os; then
	kbd legacy-clears-os legacy-clears-os
	log=$work/legacy-clears-os.log
	has 'XHCI UNAVAILABLE Refused(Handoff(OsSemaphoreLost { legsup: 1 }))' "$log"
	has_re '^XHCI PRESERVED owner=indeterminate .* legsup=00000001 legctlsts=00002001$' "$log"
	echo 'xhci-test: legacy-clears-os: contradictory semaphores are not ownership, preserved'
	passed=$((passed + 1))
fi

# 32. Capability present, neither semaphore set, SMIs on: claimed, SMIs off.
if want legacy-unowned; then
	kbd legacy-unowned legacy-unowned
	log=$work/legacy-unowned.log
	has 'XHCI LEGACY offset=0140 legsup=00000001 control=00002001' "$log"
	has 'XHCI OWNERSHIP CONFIRMED requested=1 waited_ticks=0 initial=00000001 smi_before=00002001 smi_after=00000000' "$log"
	completed "$log"
	echo 'xhci-test: legacy-unowned: unowned controller claimed, SMIs disabled'
	passed=$((passed + 1))
fi

# 33. Firmware takes the controller back after the handoff: caught before
# the first change (reacquire) and before Run/Stop with scratchpads already
# installed (reacquire-late, which are then quarantined). Nothing more is
# changed either way.
if want legacy-reacquire; then
	kbd legacy-reacquire legacy-reacquire
	log=$work/legacy-reacquire.log
	has_re '^XHCI OWNERSHIP CONFIRMED ' "$log"
	has 'XHCI FAILED round=1 error=OwnershipLost(Lost { legsup: 65537 })' "$log"
	has 'XHCI SCRATCHPAD STATE Free' "$log"
	has_re '^XHCI ABANDONED owner=firmware-reacquired usbcmd=[0-9a-f]\{8\} pci_command=[0-9a-f]\{4\} bus_master=[01] statics=reserved$' "$log"
	lacks_re '^XHCI PAGESIZE\|^XHCI RUNNING\|^XHCI DMA OFF\|^XHCI HALTED\|^XHCI PRESERVED' "$log"
	kbd legacy-reacquire-late legacy-reacquire-late
	log=$work/legacy-reacquire-late.log
	has_re '^XHCI SCRATCHPAD INSTALLED round=1 count=2 ' "$log"
	has 'XHCI FAILED round=1 error=OwnershipLost(Lost { legsup: 65537 })' "$log"
	has 'XHCI SCRATCHPAD STATE Quarantined { pages: 2 }' "$log"
	has_re '^XHCI ABANDONED owner=firmware-reacquired usbcmd=00000000 pci_command=[0-9a-f]\{4\} bus_master=1 statics=reserved$' "$log"
	lacks_re '^XHCI RUNNING\|^XHCI DMA OFF\|^XHCI HALTED\|^XHCI PRESERVED' "$log"
	# Taken back right after ABSD cleared the SMI enables: named apart.
	kbd legacy-reacquire-smi legacy-reacquire-smi
	log=$work/legacy-reacquire-smi.log
	has 'XHCI UNAVAILABLE Refused(Handoff(LostAfterSmi { legsup: 65537, smi_before: 8193 }))' "$log"
	has_re '^XHCI PRESERVED owner=indeterminate-smi-cleared .* legsup=00010001 legctlsts=00000000$' "$log"
	echo 'xhci-test: legacy-reacquire: ownership lost after handoff detected before any further change; lost after the SMI write named apart'
	passed=$((passed + 1))
fi

# 34. Both: delayed handoff and 32 scratchpads, observed, NVMe alongside.
if want both; then
	# shellcheck disable=SC2086
	observe_boot both both -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1 $nvme_drive
	log=$work/both.log
	spliced "$log"
	substituted "$log" 32
	has_re '^XHCI OWNERSHIP CONFIRMED requested=1 waited_ticks=30[0-9] ' "$log"
	observed both 1 32
	completed "$log"
	has 'BLOCK BACKEND nvme access=read-only' "$log"
	echo 'xhci-test: both: delayed handoff then 32 scratchpads observed, enumeration, NVMe alongside'
	passed=$((passed + 1))
fi

# 35. Both, scratchpad preparation failure after ownership: contained, then
# a successful round.
if want both-alloc; then
	kbd both-alloc both-alloc
	log=$work/both-alloc.log
	has_re '^XHCI OWNERSHIP CONFIRMED ' "$log"
	has 'XHCI ROUND CONTAINED round=1' "$log"
	lacks_re '^XHCI SCRATCHPAD INSTALLED round=1\|^XHCI RUNNING round=1' "$log"
	has 'XHCI ROUND OK round=2' "$log"
	has 'XHCI DONE rounds=2' "$log"
	echo 'xhci-test: both-alloc: allocation failure after ownership contained, next round succeeds'
	passed=$((passed + 1))
fi

# 36. Both, initialization failure after ownership (Run/Stop never set):
# ABSD's failure, so halted and off the bus, scratchpads released after.
if want both-run-timeout; then
	kbd both-run-timeout both-run-timeout
	log=$work/both-run-timeout.log
	has_re '^XHCI OWNERSHIP CONFIRMED ' "$log"
	has_re '^XHCI SCRATCHPAD INSTALLED round=1 count=8 ' "$log"
	failed_closed "$log" 'Timeout("run")'
	released "$log"
	has 'XHCI SCRATCHPAD RELEASED state=free installs=1' "$log"
	echo 'xhci-test: both-run-timeout: owned controller failed, halted, off the bus, pool released after'
	passed=$((passed + 1))
fi

# 37. Both, firmware never releases, NVMe alongside: nothing allocated or
# installed, preserved, NVMe and the boot unaffected.
if want both-never; then
	# shellcheck disable=SC2086
	kbd both-never both-never $nvme_drive
	log=$work/both-never.log
	has_re '^XHCI PRESERVED owner=firmware ' "$log"
	lacks_re '^XHCI SCRATCHPAD INSTALLED\|^XHCI SCRATCHPAD ABANDONED' "$log"
	has 'BLOCK BACKEND nvme access=read-only' "$log"
	echo 'xhci-test: both-never: refused controller preserved, nothing installed, NVMe unaffected'
	passed=$((passed + 1))
fi

# 38. Both, after OVMF used the controller to boot the ISO from a stick. The
# handoff is the model's (OVMF exposes no legacy capability on this device)
# and the scratchpad count is substituted.
if want both-ovmf; then
	cp /usr/share/OVMF/OVMF_VARS_4M.fd "$work/OVMF_VARS.fd"
	status=0
	timeout 180s $qemu -machine q35 -m 512M \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
		-drive "if=pflash,format=raw,unit=1,file=$work/OVMF_VARS.fd" \
		-drive if=none,id=stick,file=build/absd-xhci-both-ovmf.iso,format=raw,readonly=on \
		-device qemu-xhci,id=xhci -device usb-storage,bus=xhci.0,drive=stick,bootindex=1 \
		$common -serial "file:$work/both-ovmf.log" >/dev/null 2>&1 || status=$?
	test "$status" -eq 3 || die "both-ovmf: QEMU exited $status, not 3"
	log=$work/both-ovmf.log
	settled "$log"
	spliced "$log"
	has_re '^XHCI OWNERSHIP CONFIRMED requested=1 waited_ticks=30[0-9] ' "$log"
	has_re '^XHCI SCRATCHPAD INSTALLED round=1 count=32 ' "$log"
	has 'XHCI DEVICE round=1 port=1 slot=1 address=1 usb=0300 class=00 vendor=46f4 product=0001 max_packet0=512 configurations=1' "$log"
	has 'XHCI DONE rounds=1' "$log"
	echo 'xhci-test: both-ovmf: controller OVMF had used; modeled handoff and substituted scratchpads; boot stick enumerated'
	passed=$((passed + 1))
fi

# 39. External check of "no change before ownership": QEMU's own device
# traces. For each refused-ownership case, after the guest's claim line the
# only xHCI device writes are BAR0 sizing (command @0x4 decode off, BAR @0x10
# and @0x14 all ones and restored, command restored to the claim value): no
# operational, port, runtime or doorbell write. scratch-over, where ABSD
# owns and releases the controller, is the positive control: the gate must
# see its writes.
traced() {
	name=$1; iso=$2; shift 2
	trace=$work/$name.trace
	status=0
	# shellcheck disable=SC2086
	timeout 120s $qemu -cdrom "build/absd-xhci-$iso.iso" $common -serial stdio \
		-trace usb_xhci_oper_write -trace usb_xhci_port_write -trace usb_xhci_runtime_write \
		-trace usb_xhci_doorbell_write -trace pci_cfg_write "$@" >"$trace" 2>&1 || status=$?
	test "$status" -eq 3 || die "$name (traced): QEMU exited $status, not 3"
	has 'ABSD BOOT OK' "$trace"
	awk '/^XHCI CLAIMED/{f=1; next} f' "$trace" | grep -E '^usb_xhci_(oper|port|runtime|doorbell)_write|^pci_cfg_write (qemu-xhci|nec-usb-xhci) ' >"$trace.after" || true
}
untouched() {
	traced "$@"
	after=$work/$1.trace.after
	claim=$(sed -n 's/^XHCI CLAIMED pci_command=\([0-9a-f]*\)$/\1/p' "$work/$1.trace" | sed 's/^0*//')
	lacks_re '^usb_xhci_' "$after"
	count '^pci_cfg_write ' "$after" 6
	count '^pci_cfg_write [a-z-]* [0-9a-f:.]* @0x\(4\|10\|14\) ' "$after" 6
	tail -n 1 "$after" | grep -q "@0x4 <- 0x$claim\$" || die "$1: command register not restored to 0x$claim"
}
if want trace-gate; then
	untouched bar-bounds bar-bounds -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0
	for case in legacy-never legacy-late legacy-duplicate legacy-clears-os legacy-reacquire-smi; do
		untouched "$case-traced" "$case" -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1
	done
	# shellcheck disable=SC2086
	untouched both-never-traced both-never -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1 $nvme_drive
	traced scratch-over-traced scratch-over -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,port=1
	has_re '^usb_xhci_oper_write ' "$work/scratch-over-traced.trace.after"
	echo 'xhci-test: trace-gate: device traces show no xHCI write but BAR sizing after the claim on every refused-ownership case; the owned control is seen'
	passed=$((passed + 1))
fi

rm -f "$image" "$stick" "$work/OVMF_VARS.fd"
test "$passed" -gt 0 || die "no case selected"
if test -z "$cases"; then
	echo "xhci-test: HARDWARE READINESS QUALIFIED (QEMU, bounded): $passed cases passed"
else
	echo "xhci-test: selected cases passed: $passed"
fi
