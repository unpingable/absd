KERNEL := target/debug/absd-kernel
ISO := build/absd-kernel.iso
QEMU := qemu-system-x86_64
# Map source paths in every kernel compilation unit, including dependencies.
KERNEL_CARGO = sh scripts/kernel-cargo.sh
EXTERNAL_TARGET := build/external/target
EXTERNAL_KERNEL := $(EXTERNAL_TARGET)/debug/absd-kernel
EXTERNAL_INPUT ?= tests/external-input.txt
EXTERNAL_EXPECTED ?= $(EXTERNAL_INPUT)
EXTERNAL_USER_ELF ?=
EXTERNAL_KERNEL_FEATURES ?=
# Optional second durable program: runs after the worker with a read-only
# duplicate of the block handle, fed EXTERNAL_READER_INPUT.
EXTERNAL_READER_ELF ?=
EXTERNAL_READER_INPUT ?=
# Optional file server for `fsd` durable boots (DURABLE_OPTIONS=fsd): the
# only holder of the read-write block handle; the worker gets channels.
FILE_SERVER_ELF ?=
# A qualification boot's NIC-worker deadline in ticks (init's default is an
# hour); a served boot (DURABLE_OPTIONS="net fsd served") has none.
NET_WAIT_TICKS ?=
# 1 builds a dedicated enrollment image (docs/USERSPACE.md); empty otherwise.
ENROLL_STREAM ?=
# Broker mode (docs/BROKER.md): the workflow policy init embeds, and the
# programs it may start for the worker. Empty means no broker.
BROKER_POLICY ?=
OWNER_1_ELF ?=
OWNER_2_ELF ?=
OWNER_3_ELF ?=
OWNER_4_ELF ?=
EXTERNAL_LIVE_INPUT ?= $(EXTERNAL_INPUT)
EXTERNAL_LIVE_BYTE_ORACLE ?= $(EXTERNAL_LIVE_INPUT)
DURABLE_STEP ?= 0
# Extra boot options for a durable ISO, e.g. `net` to probe the NIC and
# hand it to the worker (docs/NETWORK.md).
DURABLE_OPTIONS ?=
DURABLE_ISO = build/durable/absd-durable-$(DURABLE_STEP).iso
# QEMU's scratch NVMe controller serial. A kernel writes an NVMe namespace
# only when the boot option `nvme-write=` names its controller's serial, so
# test ISOs name this one and nothing else.
NVME_SERIAL := absd
# Drive attachment for block-probe-test: `ata` (primary IDE master) or
# `nvme` (one QEMU NVMe namespace). The block syscalls are the same.
BLOCK_DEVICE ?= ata
ifeq ($(BLOCK_DEVICE),nvme)
BLOCK_ATTACH = -drive if=none,id=nvm,file="$$image",format=raw -device nvme,serial=$(NVME_SERIAL),drive=nvm
BLOCK_IRQS = [0-9]*
else ifeq ($(BLOCK_DEVICE),ata)
BLOCK_ATTACH = -drive file="$$image",format=raw,if=ide,index=0
BLOCK_IRQS = [1-9][0-9]*
else
$(error BLOCK_DEVICE must be ata or nvme)
endif

.PHONY: nic-cold-rx-measure provenance-check provenance-full whole-ram-iso whole-ram-test machine-recover-iso machine-recover-test xhci-iso xhci-test net-iso net-test durable-iso durable-reader-test broker-test spawn-image-test elf-matrix-test disclosure-probe-test block-probe-iso block-probe-test nvme-iso nvme-test framebuffer-iso framebuffer-test physical-build physical-iso physical-iso-test physical-iso-gate survey-iso survey-gate laptop-test laptop-matrix check user build iso fault-iso kernel-fault-iso shell-iso fuzz-iso external-build external-iso external-test external-live-iso external-live-test external-live-reject external-live-negative run shell fault-test kernel-fault-test shell-test fuzz-test smoke mutants debug clean

# The complete canonical verification, in the order HANDOFF.md lists it.
# Third-party material, licences and release obligations against the recorded
# baseline (docs/PROVENANCE.md). The first is fast and part of `check`; the
# second is for a distribution candidate.
provenance-check:
	python3 scripts/provenance.py check
	python3 scripts/test_provenance.py

provenance-full:
	python3 scripts/provenance.py full --out build/provenance

check:
	python3 scripts/provenance.py check
	python3 scripts/test_provenance.py
	python3 scripts/models/rt-fixture.py
	python3 scripts/models/smp-lifetime.py --self-test
	python3 scripts/models/xhci-irq.py --self-test
	python3 scripts/models/usb-keyboard.py --self-test
	python3 scripts/models/usb-recovery.py
	python3 scripts/xhci-observe.py --self-test
	python3 scripts/xhci-controller-test.py --self-test
	python3 scripts/usb-keyboard-test.py --self-test
	python3 scripts/usb-keyboard-recovery-test.py --self-test
	python3 scripts/test-i219-info.py
	python3 scripts/check-nvme-probe-order.py --self-test
	cargo test --workspace --exclude absd-user
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	$(MAKE) arm64-build
	$(MAKE) smoke
	$(MAKE) whole-ram-test
	$(MAKE) fault-test
	$(MAKE) kernel-fault-test
	$(MAKE) framebuffer-test
	$(MAKE) shell-test
	$(MAKE) fuzz-test
	$(MAKE) hostile-test
	$(MAKE) machine-recover-test
	$(MAKE) acpi-test
	$(MAKE) tsc-calibration-test
	$(MAKE) xhci-controller-test
	USB_KEYBOARD_CASES='keyboard absent console-test' $(MAKE) usb-keyboard-test
	USB_RECOVERY_CASES='cycles empty' $(MAKE) usb-keyboard-recovery-test
	$(MAKE) debug
	@echo 'check: all canonical targets passed'

# File-level licensing metadata alone (docs/SOURCE-LICENSING.md). The
# provenance check runs it too; this target is for working on provenance.toml.
.PHONY: spdx-check
spdx-check:
	python3 scripts/spdx-check.py

user:
	sh scripts/build-user.sh build/user
	@for image in build/user/*.elf; do readelf -h -l "$$image" >/dev/null; done
	@echo 'user: static ELF64 programs built under build/user (cargo output in build/user/cargo)'

# The kernel is interrupted in ring 0 (boot timer test, controlled fault),
# so it must not keep data below RSP.
build:
	$(KERNEL_CARGO) rustc --bin absd-kernel -- -C relocation-model=static -C code-model=kernel -C no-redzone=yes -C link-arg=-Tlinker.ld -C link-arg=-nostdlib -C link-arg=-no-pie

iso: build
	mkdir -p build/iso/boot/grub
	cp $(KERNEL) build/iso/boot/absd-kernel
	cp grub.cfg build/iso/boot/grub/grub.cfg
	grub-mkrescue -o $(ISO) build/iso

run: iso
	@set -eu; status=0; \
	$(QEMU) -cdrom $(ISO) -display none -serial stdio -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 || status=$$?; \
	if [ "$$status" -ne 3 ]; then echo "unexpected QEMU exit: $$status" >&2; exit 1; fi

# Clock 6a (docs/clock-contract-20261015 §6a): the TIMER CALIBRATION line
# under TCG, its invtsc flip, and the interrupts-off stall control that must
# widen the spread (scripts/tsc-calibration-check.py).
tsc-stall-iso: build
	mkdir -p build/tsc-stall-iso/boot/grub
	cp $(KERNEL) build/tsc-stall-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD tsc calibration stall" {' '  multiboot2 /boot/absd-kernel tsc-calibration-stall' '  boot' '}' > build/tsc-stall-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-tsc-stall.iso build/tsc-stall-iso

.PHONY: tsc-calibration-test
tsc-calibration-test: iso tsc-stall-iso
	python3 scripts/tsc-calibration-check.py --iso $(ISO) --stall-iso build/absd-tsc-stall.iso --work build/tsc-calibration --qemu "$(QEMU)"
# The KVM-only controls (needs /dev/kvm): the invtsc flip on model host and
# the KVM-vs-TCG comparison under host load (scripts/tsc-calibration-compare.py).
.PHONY: tsc-calibration-kvm-test
tsc-calibration-kvm-test: iso tsc-stall-iso
	@test -r /dev/kvm -a -w /dev/kvm || { echo 'tsc-calibration-kvm-test: needs KVM (/dev/kvm)' >&2; exit 1; }
	python3 scripts/tsc-calibration-check.py --kvm --iso $(ISO) --stall-iso build/absd-tsc-stall.iso --work build/tsc-calibration-kvm --qemu "$(QEMU)"
	python3 scripts/tsc-calibration-compare.py --iso $(ISO) --work build/tsc-calibration-compare --qemu "$(QEMU)"

fault-iso: build
	mkdir -p build/fault-iso/boot/grub
	cp $(KERNEL) build/fault-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD fault test" {' '  multiboot2 /boot/absd-kernel fault-test' '  boot' '}' > build/fault-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-fault.iso build/fault-iso

fault-test: fault-iso
	@set -eu; output="build/fault.serial.log"; rm -f "$$output"; status=0; \
	$(QEMU) -cdrom build/absd-fault.iso -display none -serial file:$$output -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 || status=$$?; \
	grep -qx 'PAGE FAULT OK' $$output; grep -qx 'PROCESS FAULT ISOLATION OK' $$output; \
	grep -qx 'ABSD BOOT OK' $$output; \
	if [ "$$status" -ne 3 ]; then echo "unexpected QEMU exit: $$status" >&2; exit 1; fi

kernel-fault-iso: build
	mkdir -p build/kernel-fault-iso/boot/grub
	cp $(KERNEL) build/kernel-fault-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD kernel fault test" {' '  multiboot2 /boot/absd-kernel kernel-fault-test' '  boot' '}' > build/kernel-fault-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-kernel-fault.iso build/kernel-fault-iso

# An unarmed ring-0 page fault must be reported and stop QEMU through
# exit_qemu(2), which the debug-exit device surfaces as status 11; it must
# never be recovered from or ignored.
kernel-fault-test: kernel-fault-iso
	@set -eu; output="build/kernel-fault.serial.log"; rm -f "$$output"; status=0; \
	$(QEMU) -cdrom build/absd-kernel-fault.iso -display none -serial file:$$output -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 || status=$$?; \
	grep -qx 'KERNEL FAULT TEST' $$output; \
	grep -q '^KERNEL FAULT vector=14 error=0x[0-9a-f]* rip=0x[0-9a-f]* cr2=0x0000400000000000$$' $$output; \
	if grep -q 'KERNEL FAULT NOT REPORTED' $$output; then echo "kernel-fault-test: unexpected output matching 'KERNEL FAULT NOT REPORTED' in $$output" >&2; exit 1; fi; \
	if [ "$$status" -ne 11 ]; then echo "unexpected QEMU exit: $$status" >&2; exit 1; fi; \
	echo 'kernel-fault-test: unarmed kernel page fault reported'

framebuffer-iso: build
	mkdir -p build/framebuffer-iso/boot/grub
	cp $(KERNEL) build/framebuffer-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD framebuffer postmortem" {' '  multiboot2 /boot/absd-kernel kernel-fault-test halt-on-exit' '  boot' '}' > build/framebuffer-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-framebuffer.iso build/framebuffer-iso

# The kernel-fault boot again, halting instead of exiting as a machine
# without the debug-exit device would. The host screendumps QEMU's display
# and requires every pixel of the screen to match its own rendering of the
# serial stream, including the fault report and halt notice in the failure
# colours (scripts/framebuffer-check.py).
framebuffer-test: framebuffer-iso
	@set -eu; output="build/framebuffer.serial.log"; \
	python3 scripts/framebuffer-check.py --iso build/absd-framebuffer.iso --serial "$$output" --screen build/framebuffer.ppm --until 'KERNEL FAULT vector=14' --halt-code 2; \
	grep -q '^FRAMEBUFFER CONSOLE OK width=[0-9]* height=[0-9]* ' "$$output"; \
	grep -q '^KERNEL FAULT vector=14 ' "$$output"; \
	echo 'framebuffer-test: screen matches the serial stream (build/framebuffer.ppm)'

# GRUB removes these ranges from the memory map it passes (cutmem, given in
# KiB: GRUB parses its numbers as 32-bit before the suffix), so every
# whole-RAM boot also has holes above 4 GiB with edges that are not 2 MiB
# aligned. They lie inside the high RAM of every case below.
WHOLE_RAM_CUTS := 0x140003000-0x140505000 0x161234000-0x161235000

whole-ram-iso: build
	mkdir -p build/whole-ram-iso/boot/grub
	cp $(KERNEL) build/whole-ram-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' $(foreach cut,$(WHOLE_RAM_CUTS),"cutmem $$(($(word 1,$(subst -, ,$(cut)))/1024))K $$(($(word 2,$(subst -, ,$(cut)))/1024))K") 'menuentry "ABSD whole RAM" {' '  multiboot2 /boot/absd-kernel whole-ram-test' '  boot' '}' > build/whole-ram-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-whole-ram.iso build/whole-ram-iso

# Whole-RAM frame tracking (docs/x86-whole-ram-20261015), under TCG: q35 with
# 4 and 8 GiB (RAM on both sides of the PCI hole), and i440fx with 6 GiB and
# low RAM ending at 0xbfe01000, so the low row's end above 1 GiB and the high
# row's end above 4 GiB are both unaligned. The kernel discloses the map, its
# reservations and what it tracks; the host oracle derives the reservations
# from the kernel ELF and its own plan and recomputes every count. The kernel
# then allocates every free frame, writes one per 2 MiB page through the
# direct map, frees them all, and runs the userspace suite with every frame
# below 4 GiB held.
whole-ram-test: whole-ram-iso
	@set -eu; for case in q35:4G q35:8G pc,max-ram-below-4g=0xbfe01000:6G; do \
	  machine=$${case%:*}; ram=$${case##*:}; name=$$(echo "$$machine-$$ram" | tr ',=' '--'); \
	  output="build/whole-ram-$$name.serial.log"; rm -f "$$output"; status=0; \
	  timeout 600s $(QEMU) -machine "$$machine" -m $$ram -cdrom build/absd-whole-ram.iso -display none -serial file:$$output -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 || status=$$?; \
	  if [ "$$status" -ne 3 ]; then echo "whole-ram-test: unexpected QEMU exit $$status for $$case ($$output)" >&2; exit 1; fi; \
	  python3 scripts/whole-ram-check.py --ram "$$ram" --kernel build/whole-ram-iso/boot/absd-kernel --fragmented $(foreach cut,$(WHOLE_RAM_CUTS),--cut $(cut)) "$$output"; \
	done; \
	echo 'whole-ram-test: three maps tracked, allocated above 4 GiB, freed exactly (build/whole-ram-*.serial.log)'

# Interactive shell on this terminal; type `quit` to end the session.
shell: shell-iso
	$(QEMU) -cdrom build/absd-shell.iso -display none -serial stdio -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 || true

fuzz-iso: build
	mkdir -p build/fuzz-iso/boot/grub
	cp $(KERNEL) build/fuzz-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD fuzz" {' '  multiboot2 /boot/absd-kernel fuzz' '  boot' '}' > build/fuzz-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-fuzz.iso build/fuzz-iso

# Thousands of random syscalls from ring 3: the kernel must refuse or serve
# each, keep running, and have reclaimed everything when the fuzzer exits.
fuzz-test: fuzz-iso
	@set -eu; output="build/fuzz.serial.log"; rm -f "$$output"; status=0; \
	$(QEMU) -cdrom build/absd-fuzz.iso -display none -serial file:$$output -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 || status=$$?; \
	grep -qx 'USER INIT STARTED' $$output; grep -qx 'INIT SPAWN OK' $$output; \
	grep -qx 'SPAWN HANDLE FUZZ OK' $$output; grep -qx 'RIGHTS CHAIN FUZZ OK' $$output; \
	grep -q '^fuzz: [0-9]* rounds, [0-9]* served, [0-9]* refused$$' $$output; \
	grep -qx 'INIT REAP OK' $$output; grep -qx 'USERSPACE BOOTSTRAP OK' $$output; \
	grep -q '^FUZZ status=0 frames=0 ' $$output; \
	grep -qx 'FUZZ OK' $$output; grep -qx 'ABSD BOOT OK' $$output; \
	if grep -q 'PANIC\|KERNEL FAULT' $$output; then echo "fuzz-test: unexpected output matching 'PANIC\|KERNEL FAULT' in $$output" >&2; exit 1; fi; \
	if [ "$$status" -ne 3 ]; then echo "unexpected QEMU exit: $$status" >&2; exit 1; fi; \
	echo 'fuzz-test: random syscall boot survived (build/fuzz.serial.log)'

hostile-iso: build
	mkdir -p build/hostile-iso/boot/grub
	cp $(KERNEL) build/hostile-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD hostile" {' '  multiboot2 /boot/absd-kernel hostile' '  boot' '}' > build/hostile-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-hostile.iso build/hostile-iso

# The hostile-userspace qualification boot (docs/HOSTILE-USERSPACE.md): every
# case must be contained, both witnesses must finish, the kernel must reclaim
# everything, and the boot must end on its own before the timeout — a kernel
# hang or a `KERNEL FAULT` fails the target instead of hanging make.
hostile-test: hostile-iso
	@set -eu; output="build/hostile.serial.log"; rm -f "$$output"; status=0; \
	timeout 60s $(QEMU) -cdrom build/absd-hostile.iso -display none -serial file:$$output -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 || status=$$?; \
	grep -qx 'USER INIT STARTED' $$output; \
	grep -qx 'hostile: sys abuse done refused=100000' $$output; \
	grep -qx 'HOSTILE SYS ABUSE OK' $$output; \
	for case in 'read-supervisor target=0x0000000000100000' 'write-supervisor target=0x0000000000100000' 'exec-supervisor target=0x0000000000100000' 'exec-nx-heap' 'write-text' 'read-null target=0x0000000000000000' 'read-gap target=0x0000008100000000' 'divide-zero' 'io-instruction' 'lidt' 'int3' 'noncanonical'; do \
	  grep -q "^hostile: case $$case" $$output; \
	done; \
	for ok in 'READ SUPERVISOR' 'WRITE SUPERVISOR' 'EXEC SUPERVISOR' 'EXEC NX HEAP' 'WRITE TEXT' 'READ NULL SUPERVISOR' 'READ GAP' 'DIVIDE ZERO' 'IO INSTRUCTION' 'LIDT' 'INT3' 'NONCANONICAL'; do \
	  grep -qx "HOSTILE $$ok OK" $$output; \
	done; \
	grep -q '^USER FAULT pid=[0-9]* vector=14 address=0x0000000000100000 error=0x0000000000000005$$' $$output; \
	grep -q '^USER FAULT pid=[0-9]* vector=14 address=0x0000000000100000 error=0x0000000000000007$$' $$output; \
	grep -q '^USER FAULT pid=[0-9]* vector=14 address=0x0000000000100000 error=0x0000000000000015$$' $$output; \
	grep -q '^USER FAULT pid=[0-9]* vector=14 address=0x0000000000000000 error=0x0000000000000005$$' $$output; \
	grep -q '^USER FAULT pid=[0-9]* vector=14 address=0x0000008100000000 error=0x0000000000000004$$' $$output; \
	grep -q '^USER FAULT pid=[0-9]* vector=14 address=0x8000000000000000 error=0x0000000000000005$$' $$output; \
	test "$$(grep -c '^USER FAULT pid=[0-9]* vector=0 ' $$output)" -eq 35; \
	test "$$(grep -c '^USER FAULT pid=[0-9]* vector=13 ' $$output)" -eq 3; \
	grep -q '^USER FAULT pid=[0-9]* vector=13 address=0x[0-9a-f]* error=0x000000000000001a$$' $$output; \
	nx_target=$$(sed -n 's/^hostile: case exec-nx-heap target=0x\([0-9a-f]*\)$$/\1/p' $$output); \
	test -n "$$nx_target"; \
	grep -q "^USER FAULT pid=[0-9]* vector=14 address=0x$$nx_target error=0x0000000000000015$$" $$output; \
	text_target=$$(sed -n 's/^hostile: case write-text target=0x\([0-9a-f]*\)$$/\1/p' $$output); \
	test -n "$$text_target"; \
	grep -q "^USER FAULT pid=[0-9]* vector=14 address=0x$$text_target error=0x0000000000000007$$" $$output; \
	grep -qx 'HOSTILE CRASH CYCLES OK' $$output; \
	grep -qx 'HOSTILE FLOOD WITNESS OK' $$output; \
	grep -qx 'hostile: state handles done' $$output; \
	grep -qx 'hostile: fork bomb spawned=13' $$output; \
	grep -qx 'hostile: heap window filled pages=8192' $$output; \
	grep -qx 'hostile: vm churn cycles=512' $$output; \
	grep -qx 'hostile: case kill-mapped pages=96' $$output; \
	grep -qx 'hostile: cells filled=32' $$output; \
	grep -qx 'hostile: pipes filled=48' $$output; \
	grep -qx 'hostile: churn cycles=200' $$output; \
	grep -q '^hostile: case exit-mapped' $$output; \
	grep -q '^hostile: case exit-with-child-and-pipe' $$output; \
	for ok in 'STATE HANDLES' 'STATE LIFECYCLE' 'STATE VM' 'STATE OBJECTS' 'STATE CHURN'; do \
	  grep -qx "HOSTILE $$ok OK" $$output; \
	done; \
	test "$$(grep -c '^USER KILLED ' $$output)" -eq 21; \
	grep -qx 'HOSTILE WITNESS OK' $$output; \
	test "$$(grep -cx 'user-B: hello from ELF userspace' $$output)" -eq 2; \
	grep -q '^HOSTILE status=0 frames=0 faults=46 kills=21 preempts=[1-9][0-9]* refused unknown=1[0-9][0-9][0-9][0-9][0-9][0-9]* pointer=17 handle=33 wait=2 spawn=1 map=12 cell=1 pipe=1 timeouts=2$$' $$output; \
	grep -qx 'HOSTILE OK' $$output; grep -qx 'ABSD BOOT OK' $$output; grep -qx 'USERSPACE BOOTSTRAP OK' $$output; \
	if grep -q 'PANIC\|KERNEL FAULT' $$output; then echo "hostile-test: unexpected output matching 'PANIC\|KERNEL FAULT' in $$output" >&2; exit 1; fi; \
	if [ "$$status" -ne 3 ]; then echo "unexpected QEMU exit: $$status" >&2; exit 1; fi; \
	echo 'hostile-test: hostile userspace contained (build/hostile.serial.log)'

external-build:
	@set -eu; test -f "$(EXTERNAL_INPUT)"; test -f "$(EXTERNAL_EXPECTED)"; \
	override="$(EXTERNAL_USER_ELF)"; \
	if [ -n "$$override" ]; then test -f "$$override"; fi; \
	reader="$(EXTERNAL_READER_ELF)"; reader_input="$(EXTERNAL_READER_INPUT)"; \
	if [ -n "$$reader" ]; then test -f "$$reader"; test -f "$$reader_input"; reader_input=$$(realpath "$$reader_input"); fi; \
	ABSD_EXTERNAL_INPUT="$(if $(ENROLL_STREAM),,$(abspath $(EXTERNAL_INPUT)))" \
	ABSD_EXTERNAL_READER_ELF="$$reader" ABSD_EXTERNAL_READER_INPUT="$$reader_input" \
	ABSD_BROKER_POLICY="$(if $(BROKER_POLICY),$(abspath $(BROKER_POLICY)))" \
	ABSD_FILE_SERVER_ELF="$(if $(FILE_SERVER_ELF),$(abspath $(FILE_SERVER_ELF)))" \
	ABSD_NET_WAIT_TICKS="$(NET_WAIT_TICKS)" ABSD_ENROLL_STREAM="$(ENROLL_STREAM)" \
	ABSD_OWNER_1_ELF="$(if $(OWNER_1_ELF),$(abspath $(OWNER_1_ELF)))" ABSD_OWNER_2_ELF="$(if $(OWNER_2_ELF),$(abspath $(OWNER_2_ELF)))" \
	ABSD_OWNER_3_ELF="$(if $(OWNER_3_ELF),$(abspath $(OWNER_3_ELF)))" ABSD_OWNER_4_ELF="$(if $(OWNER_4_ELF),$(abspath $(OWNER_4_ELF)))" \
	ABSD_EXTERNAL_USER_ELF="$$override" CARGO_TARGET_DIR="$(EXTERNAL_TARGET)" \
	$(KERNEL_CARGO) rustc --bin absd-kernel $(if $(EXTERNAL_KERNEL_FEATURES),--features $(EXTERNAL_KERNEL_FEATURES)) -- -C relocation-model=static -C code-model=kernel -C no-redzone=yes -C link-arg=-Tlinker.ld -C link-arg=-nostdlib -C link-arg=-no-pie

external-iso: external-build
	mkdir -p build/external/iso/boot/grub
	cp $(EXTERNAL_KERNEL) build/external/iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD external workload" {' '  multiboot2 /boot/absd-kernel external' '  boot' '}' > build/external/iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-external.iso build/external/iso

# Opt-in generic integration boot. It is intentionally not a dependency of
# `check`; callers may replace only the multi-start workload ELF and input.
external-test: external-iso
	@set -eu; output="build/external.serial.log"; rm -f "$$output"; status=0; \
	timeout 180s $(QEMU) -cdrom build/absd-external.iso -display none -serial file:$$output -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 || status=$$?; \
	python3 scripts/check-external-output.py "$$output" "$(EXTERNAL_EXPECTED)"; \
	grep -qx 'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0' $$output; \
	grep -qx 'EXTERNAL WORKLOAD OK' $$output; grep -qx 'ABSD BOOT OK' $$output; \
	if grep -q 'PANIC\|KERNEL FAULT\|EXTERNAL WORKLOAD FAILED' $$output; then echo "external-test: unexpected output matching 'PANIC\|KERNEL FAULT\|EXTERNAL WORKLOAD FAILED' in $$output" >&2; exit 1; fi; \
	if [ "$$status" -ne 3 ]; then echo "unexpected QEMU exit: $$status" >&2; exit 1; fi; \
	echo 'external-test: embedded input and captured output matched exactly'

external-live-iso: external-build
	mkdir -p build/external-live/iso/boot/grub
	cp $(EXTERNAL_KERNEL) build/external-live/iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD live external workload" {' '  multiboot2 /boot/absd-kernel external-live' '  boot' '}' > build/external-live/iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-external-live.iso build/external-live/iso

# The host waits for userspace readiness and then sends a generic bounded
# chunk stream over COM1. Output remains a captured pipe framed separately by
# init, so serial diagnostics can never be mistaken for application bytes.
external-live-test: external-live-iso
	@set -eu; output="build/external-live.serial.log"; socket="build/external-live.sock"; rm -f "$$output" "$$socket"; status=0; \
	$(QEMU) -cdrom build/absd-external-live.iso -display none -chardev socket,id=con,path="$$socket",server=on,wait=on -serial chardev:con -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 & qemu=$$!; \
	python3 scripts/external-live-session.py "$$socket" "$$output" "$(EXTERNAL_LIVE_INPUT)" "$${EXTERNAL_LIVE_MODE:-fragmented}" || { kill $$qemu 2>/dev/null || true; wait $$qemu 2>/dev/null || true; exit 1; }; \
	wait $$qemu || status=$$?; \
	python3 scripts/check-external-output.py "$$output" "$(EXTERNAL_EXPECTED)"; \
	grep -qx 'EXTERNAL INPUT ACCEPTED protocol=absd-stream-v1' "$$output"; \
	grep -qx "EXTERNAL INPUT EOF bytes=$$(stat -c %s "$(EXTERNAL_LIVE_BYTE_ORACLE)")" "$$output"; \
	grep -qx 'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0' "$$output"; \
	grep -qx 'EXTERNAL WORKLOAD OK' "$$output"; grep -qx 'ABSD BOOT OK' "$$output"; \
	if grep -q 'PANIC\|KERNEL FAULT\|EXTERNAL WORKLOAD FAILED\|EXTERNAL INPUT REFUSED' "$$output"; then echo "external-live-test: unexpected output matching 'PANIC\|KERNEL FAULT\|EXTERNAL WORKLOAD FAILED\|EXTERNAL INPUT REFUSED' in $$output" >&2; exit 1; fi; \
	if [ "$$status" -ne 3 ]; then echo "unexpected QEMU exit: $$status" >&2; exit 1; fi; \
	echo "external-live-test: post-boot stream matched exactly mode=$${EXTERNAL_LIVE_MODE:-fragmented}"

# Negative application-side stream probe. The host protocol must complete
# cleanly, while the selected child rejects its bytes and init reclaims every
# resource before reporting the expected failed external boot.
external-live-reject: external-live-iso
	@set -eu; output="build/external-live-reject.serial.log"; socket="build/external-live-reject.sock"; rm -f "$$output" "$$socket"; status=0; \
	$(QEMU) -cdrom build/absd-external-live.iso -display none -chardev socket,id=con,path="$$socket",server=on,wait=on -serial chardev:con -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 & qemu=$$!; \
	python3 scripts/external-live-session.py "$$socket" "$$output" "$(EXTERNAL_LIVE_INPUT)" "$${EXTERNAL_LIVE_MODE:-fragmented}" || { kill $$qemu 2>/dev/null || true; wait $$qemu 2>/dev/null || true; exit 1; }; \
	wait $$qemu || status=$$?; \
	grep -qx 'EXTERNAL INPUT ACCEPTED protocol=absd-stream-v1' "$$output"; \
	grep -qx "EXTERNAL INPUT EOF bytes=$$(stat -c %s "$(EXTERNAL_LIVE_BYTE_ORACLE)")" "$$output"; \
	grep -qx 'EXTERNAL status=99 frames=0 processes=0 cells=0 pipes=0' "$$output"; \
	grep -qx 'EXTERNAL WORKLOAD FAILED' "$$output"; \
	if grep -q 'ABSD BOOT OK\|PANIC\|KERNEL FAULT\|EXTERNAL INPUT REFUSED' "$$output"; then echo "external-live-reject: unexpected output matching 'ABSD BOOT OK\|PANIC\|KERNEL FAULT\|EXTERNAL INPUT REFUSED' in $$output" >&2; exit 1; fi; \
	if [ "$$status" -ne 7 ]; then echo "unexpected rejected-workload QEMU exit: $$status" >&2; exit 1; fi; \
	echo 'external-live-reject: child rejection reclaimed cleanly'

external-live-negative: external-live-iso
	@set -eu; \
	for mode in malformed truncated; do \
	  output="build/external-live-$$mode.serial.log"; socket="build/external-live-$$mode.sock"; rm -f "$$output" "$$socket"; status=0; \
	  $(QEMU) -cdrom build/absd-external-live.iso -display none -chardev socket,id=con,path="$$socket",server=on,wait=on -serial chardev:con -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 & qemu=$$!; \
	  python3 scripts/external-live-session.py "$$socket" "$$output" "$(EXTERNAL_LIVE_INPUT)" "$$mode" || { kill $$qemu 2>/dev/null || true; wait $$qemu 2>/dev/null || true; exit 1; }; \
	  wait $$qemu || status=$$?; \
	  grep -q '^EXTERNAL INPUT REFUSED reason=' "$$output"; \
	  grep -qx 'EXTERNAL status=99 frames=0 processes=0 cells=0 pipes=0' "$$output"; \
	  grep -qx 'EXTERNAL WORKLOAD FAILED' "$$output"; \
	  if grep -q 'ABSD BOOT OK\|PANIC\|KERNEL FAULT' "$$output"; then echo "external-live-negative: unexpected output matching 'ABSD BOOT OK\|PANIC\|KERNEL FAULT' in $$output" >&2; exit 1; fi; \
	  if [ "$$status" -ne 7 ]; then echo "unexpected negative QEMU exit: $$status" >&2; exit 1; fi; \
	done; \
	echo 'EXTERNAL LIVE NEGATIVE OK malformed truncated'

# The block substrate probe runs init's durable path against a zero-filled
# scratch image on the primary IDE channel; the image is disposable.
block-probe-iso: build
	mkdir -p build/block-probe-iso/boot/grub
	cp $(KERNEL) build/block-probe-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD block probe" {' '  multiboot2 /boot/absd-kernel block-probe nvme-write=$(NVME_SERIAL)' '  boot' '}' > build/block-probe-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-block-probe.iso build/block-probe-iso

block-probe-test: block-probe-iso
	@set -eu; output="build/block-probe.serial.log"; image="build/block-probe.img"; rm -f "$$output" "$$image"; status=0; \
	truncate -s 2M "$$image"; \
	timeout 180s $(QEMU) -cdrom build/absd-block-probe.iso $(BLOCK_ATTACH) -display none -serial file:$$output -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 || status=$$?; \
	grep -qx 'BLOCK DEVICE OK sectors=4096' $$output; \
	grep -qx 'BLOCK BACKEND $(BLOCK_DEVICE) access=read-write' $$output; \
	python3 scripts/check-external-output.py "$$output" tests/block-probe-expected.txt; \
	python3 scripts/block-probe-image-check.py "$$image"; \
	grep -q '^DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 block_reads=[1-9][0-9]* block_writes=[1-9][0-9]* block_flushes=3 block_errors=[0-9]* block_waits=[0-9]* block_irqs=$(BLOCK_IRQS) ticks=[0-9]*$$' $$output; \
	grep -qx 'DURABLE WORKLOAD OK' $$output; grep -qx 'ABSD BOOT OK' $$output; \
	if grep -q 'PANIC\|KERNEL FAULT\|DURABLE WORKLOAD FAILED' $$output; then echo "block-probe-test: unexpected output matching 'PANIC\|KERNEL FAULT\|DURABLE WORKLOAD FAILED' in $$output" >&2; exit 1; fi; \
	if [ "$$status" -ne 3 ]; then echo "unexpected QEMU exit: $$status" >&2; exit 1; fi; \
	rm -f "$$image"; \
	echo 'block-probe-test: sector transfers, flush, refusals, and extent recovery passed (backend $(BLOCK_DEVICE))'

# Kernel-level NVMe qualification ISOs: write a pattern with the namespace
# selected writable, verify it read-only on a fresh boot, and a boot whose
# `nvme-write=` names a different serial (must stay read-only). Under EFI,
# GRUB sets no framebuffer for a multiboot2 kernel ("no suitable video mode
# found") unless the video drivers are loaded, hence `insmod all_video`.
nvme-iso: build
	@set -eu; for phase in write:'nvme-qualify-write nvme-write=$(NVME_SERIAL)' verify:'nvme-qualify-verify' other:'nvme-qualify-write nvme-write=not-$(NVME_SERIAL)'; do \
	  name=$${phase%%:*}; line=$${phase#*:}; \
	  mkdir -p build/nvme-$$name-iso/boot/grub; cp $(KERNEL) build/nvme-$$name-iso/boot/absd-kernel; \
	  printf '%s\n' 'insmod all_video' 'set timeout=0' 'menuentry "ABSD NVMe qualification" {' "  multiboot2 /boot/absd-kernel $$line" '  boot' '}' > build/nvme-$$name-iso/boot/grub/grub.cfg; \
	  grub-mkrescue -o build/absd-nvme-$$name.iso build/nvme-$$name-iso >/dev/null 2>&1; \
	done

# Identify, known-block writes and read-back, FLUSH, namespace-boundary
# refusals, fresh-boot reinitialization over the same image, and the
# read-only default, against one QEMU NVMe namespace. The host checks the
# image file itself between boots (scripts/nvme-image-check.py). A 4 KiB-LBA
# namespace must be refused by name.
.PHONY: nvme-first-read-test
nvme-first-read-test: nvme-iso
	python3 scripts/nvme-first-read-test.py --self-test
	python3 scripts/nvme-first-read-test.py --qemu '$(QEMU)'

nvme-test: nvme-iso
	@set -eu; image="build/nvme.img"; rm -f "$$image" build/nvme-*.serial.log; truncate -s 2M "$$image"; \
	boot() { status=0; timeout 60s $(QEMU) -cdrom "build/absd-nvme-$$1.iso" -drive if=none,id=nvm,file="$$image",format=raw -device nvme,serial=$(NVME_SERIAL),drive=nvm$$3 -display none -serial file:"build/nvme-$$2.serial.log" -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 || status=$$?; \
	  if grep -q 'PANIC\|KERNEL FAULT' "build/nvme-$$2.serial.log"; then echo "nvme-test: unexpected output matching 'PANIC\|KERNEL FAULT' in build/nvme-$$2.serial.log" >&2; exit 1; fi; echo "$$status"; }; \
	log=build/nvme-write.serial.log; test "$$(boot write write '')" -eq 3; \
	grep -q '^NVME CONTROLLER pci=[0-9a-f:.]* vendor=1b36 device=0010 .* serial=$(NVME_SERIAL) ' $$log; \
	grep -qx 'NVME NAMESPACE nsid=1 lba_bytes=512 sectors=4096 access=read-write (selected by nvme-write)' $$log; \
	grep -qx 'BLOCK BACKEND nvme access=read-write' $$log; \
	grep -qx 'NVME BLOCK OK lbas=5 sectors=4096' $$log; grep -qx 'NVME FLUSH OK flush_commands=1' $$log; \
	grep -qx 'NVME BOUNDS OK kernel=OutOfRange device_status=0x0080' $$log; \
	python3 scripts/nvme-image-check.py "$$image"; before="$$(sha256sum < "$$image")"; \
	log=build/nvme-verify.serial.log; test "$$(boot verify verify '')" -eq 3; \
	grep -qx 'NVME NAMESPACE nsid=1 lba_bytes=512 sectors=4096 access=read-only' $$log; \
	grep -qx 'NVME REINIT OK lbas=5' $$log; grep -qx 'NVME READ ONLY OK' $$log; \
	test "$$before" = "$$(sha256sum < "$$image")"; \
	log=build/nvme-other.serial.log; test "$$(boot other other '')" -eq 7; \
	grep -qx 'NVME NAMESPACE nsid=1 lba_bytes=512 sectors=4096 access=read-only' $$log; \
	grep -qx 'NVME QUALIFY FAILED namespace not selected writable lba=0' $$log; \
	test "$$before" = "$$(sha256sum < "$$image")"; \
	log=build/nvme-4k.serial.log; test "$$(boot write 4k ',logical_block_size=4096,physical_block_size=4096')" -eq 7; \
	grep -qx 'NVME UNAVAILABLE Refused(LbaFormat { lba_bytes: 4096, metadata_bytes: 0 })' $$log; \
	grep -qx 'block: no device' $$log; \
	test "$$before" = "$$(sha256sum < "$$image")"; \
	rm -f "$$image"; \
	echo 'nvme-test: NVME BLOCK OK, NVME FLUSH OK, bounds, reinit, read-only default, 4 KiB refusal'

# The hybrid BIOS+EFI ISO for a first physical boot (docs/PHYSICAL-BOOT.md).
# No entry selects a writable disk: the NVMe namespace, if any, is
# identified and read only. `halt-on-exit` keeps the last screen instead of
# touching the QEMU debug-exit port.
OVMF ?= /usr/share/ovmf/OVMF.fd
# The physical ISO carries a kernel built with `block-read-only`: it can
# submit no block write or flush to any device, whatever the command line
# says. It is built in its own target directory so ordinary builds never
# overwrite it.
PHYSICAL_TARGET := build/physical/target
PHYSICAL_KERNEL := $(PHYSICAL_TARGET)/debug/absd-kernel
physical-build:
	CARGO_TARGET_DIR=$(PHYSICAL_TARGET) $(KERNEL_CARGO) rustc --bin absd-kernel --features block-read-only -- -C relocation-model=static -C code-model=kernel -C no-redzone=yes -C link-arg=-Tlinker.ld -C link-arg=-nostdlib -C link-arg=-no-pie

physical-iso: physical-build
	rm -rf build/physical-iso
	mkdir -p build/physical-iso/boot/grub
	cp $(PHYSICAL_KERNEL) build/physical-iso/boot/absd-kernel
	printf '%s\n' 'insmod all_video' 'set timeout=10' 'set default=0' \
	  'menuentry "ABSD physical probe: boot suite, disks read-only" {' '  multiboot2 /boot/absd-kernel suite halt-on-exit' '  boot' '}' \
	  'menuentry "ABSD kernel fault postmortem" {' '  multiboot2 /boot/absd-kernel kernel-fault-test halt-on-exit' '  boot' '}' \
	  > build/physical-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-physical.iso build/physical-iso
	@sha256sum build/absd-physical.iso $(PHYSICAL_KERNEL)

# The physical survey ISO (docs/hardware/HP-Z2-MINI-G3-FIRST-BOOT.md): the
# same read-only kernel, default entry `survey` (identity by reads only, no
# storage or network controller started), then the suite and postmortem
# entries of the physical ISO. A separate artifact with its own pin.
SURVEY_ISO := build/absd-physical-survey.iso
survey-iso: physical-build
	rm -rf build/survey-iso
	mkdir -p build/survey-iso/boot/grub
	cp $(PHYSICAL_KERNEL) build/survey-iso/boot/absd-kernel
	printf '%s\n' 'insmod all_video' 'set timeout=10' 'set default=0' \
	  'menuentry "ABSD physical survey: identity only, disks and network untouched" {' '  multiboot2 /boot/absd-kernel survey halt-on-exit' '  boot' '}' \
	  'menuentry "ABSD physical probe: boot suite, disks read-only" {' '  multiboot2 /boot/absd-kernel suite halt-on-exit' '  boot' '}' \
	  'menuentry "ABSD kernel fault postmortem" {' '  multiboot2 /boot/absd-kernel kernel-fault-test halt-on-exit' '  boot' '}' \
	  > build/survey-iso/boot/grub/grub.cfg
	grub-mkrescue -o $(SURVEY_ISO) build/survey-iso
	@sha256sum $(SURVEY_ISO) $(PHYSICAL_KERNEL)

# The AHCI census ISO (docs/hardware/SATA-AHCI-CENSUS.md):
# the read-only kernel with the census as its default entry (exits QEMU) and
# a halting entry for a physical machine. Gate: scripts/ahci-census-check.py
# under q35/ich9-ahci with two disks and a CD, QEMU traces showing IDENTIFY
# DEVICE as the only ATA command, images unchanged; a machine without AHCI;
# the pretend-RAID fixture's refusal; an empty controller.
AHCI_CENSUS_ISO := build/absd-ahci-census.iso
ahci-census-iso: physical-build
	rm -rf build/ahci-census-iso
	mkdir -p build/ahci-census-iso/boot/grub
	cp $(PHYSICAL_KERNEL) build/ahci-census-iso/boot/absd-kernel
	printf '%s\n' 'insmod all_video' 'set timeout=10' 'set default=0' \
	  'menuentry "ABSD AHCI census: IDENTIFY only, nothing written (halts on screen)" {' '  multiboot2 /boot/absd-kernel ahci-census halt-on-exit' '  boot' '}' \
	  'menuentry "ABSD AHCI census: IDENTIFY only, nothing written (exits QEMU)" {' '  multiboot2 /boot/absd-kernel ahci-census' '  boot' '}' \
	  'menuentry "ABSD AHCI census: pretend-RAID refusal fixture (halts)" {' '  multiboot2 /boot/absd-kernel ahci-census ahci-census-pretend-raid halt-on-exit' '  boot' '}' \
	  > build/ahci-census-iso/boot/grub/grub.cfg
	grub-mkrescue -o $(AHCI_CENSUS_ISO) build/ahci-census-iso
	@sha256sum $(AHCI_CENSUS_ISO) $(PHYSICAL_KERNEL)
# The gate's ISOs: the same kernel with the QEMU-exiting census, and with
# the pretend-RAID fixture, as default entries (GRUB entries cannot be
# chosen from QEMU's command line). The physical ISO's default halts.
ahci-census-qemu-iso: physical-build
	rm -rf build/ahci-census-qemu-iso
	mkdir -p build/ahci-census-qemu-iso/boot/grub
	cp $(PHYSICAL_KERNEL) build/ahci-census-qemu-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD AHCI census (exits QEMU)" {' '  multiboot2 /boot/absd-kernel ahci-census' '  boot' '}' > build/ahci-census-qemu-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-ahci-census-qemu.iso build/ahci-census-qemu-iso
ahci-census-raid-iso: physical-build
	rm -rf build/ahci-census-raid-iso
	mkdir -p build/ahci-census-raid-iso/boot/grub
	cp $(PHYSICAL_KERNEL) build/ahci-census-raid-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD AHCI census: pretend-RAID refusal fixture" {' '  multiboot2 /boot/absd-kernel ahci-census ahci-census-pretend-raid' '  boot' '}' > build/ahci-census-raid-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-ahci-census-raid.iso build/ahci-census-raid-iso
# The stuck-stop fixture: the first IDENTIFY's post-command engine stop is
# treated as failed (QEMU's engine always stops), so the gate sees the
# controller-level fail-closed path.
ahci-census-stuck-iso: physical-build
	rm -rf build/ahci-census-stuck-iso
	mkdir -p build/ahci-census-stuck-iso/boot/grub
	cp $(PHYSICAL_KERNEL) build/ahci-census-stuck-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD AHCI census: stuck engine stop fixture" {' '  multiboot2 /boot/absd-kernel ahci-census ahci-census-pretend-stuck-stop' '  boot' '}' > build/ahci-census-stuck-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-ahci-census-stuck.iso build/ahci-census-stuck-iso

.PHONY: ahci-census-test
ahci-census-test: ahci-census-iso ahci-census-qemu-iso ahci-census-raid-iso ahci-census-stuck-iso
	python3 scripts/ahci-census-check.py --iso build/absd-ahci-census-qemu.iso --raid-iso build/absd-ahci-census-raid.iso --stuck-iso build/absd-ahci-census-stuck.iso --physical-iso $(AHCI_CENSUS_ISO) --work build/ahci-census --qemu "$(QEMU)"

# The survey ISO's gate (scripts/survey-gate.sh): its entries, then its
# default entry under SeaBIOS and OVMF with NVMe, e1000, and ATA attached,
# screen matched against serial, QEMU device traces showing no PCI
# configuration write and no storage or NIC register write after the
# kernel's first line; a positive control; then physical-iso-gate.sh on it.
survey-gate: survey-iso
	@sh scripts/survey-gate.sh $(SURVEY_ISO) $(PHYSICAL_KERNEL) "$(QEMU)" "$(OVMF)"
	@sh scripts/physical-iso-gate.sh $(SURVEY_ISO) $(PHYSICAL_KERNEL) "$(QEMU)"

# Boots that exact ISO under QEMU with SeaBIOS and, when present, OVMF,
# with a patterned NVMe namespace attached: the whole screen must match the
# serial stream, the namespace must be identified read-only, and the image
# must be byte-for-byte unchanged afterwards.
physical-iso-test: physical-iso
	@set -eu; image="build/physical-nvme.img"; rm -f "$$image"; truncate -s 2M "$$image"; \
	printf 'ABSD PHYSICAL READ-ONLY WITNESS' | dd of="$$image" conv=notrunc status=none; \
	before="$$(sha256sum < "$$image")"; \
	attach="$(QEMU) -drive if=none,id=nvm,file=$$image,format=raw -device nvme,serial=physical-witness,drive=nvm"; \
	for firmware in bios efi; do \
	  if [ $$firmware = efi ] && [ ! -f "$(OVMF)" ]; then echo "physical-iso-test: no OVMF at $(OVMF); EFI boot not run"; continue; fi; \
	  log="build/physical-$$firmware.serial.log"; extra=""; [ $$firmware = efi ] && extra="--firmware $(OVMF)"; \
	  python3 scripts/framebuffer-check.py --iso build/absd-physical.iso --serial "$$log" --screen "build/physical-$$firmware.ppm" --until 'ABSD BOOT OK' --halt-code 0 --timeout 300 --qemu "$$attach" $$extra; \
	  grep -qx 'BLOCK WRITES DISABLED: read-only build' "$$log"; \
	  grep -qx 'NVME NAMESPACE nsid=1 lba_bytes=512 sectors=4096 access=read-only' "$$log"; \
	  grep -qx 'BLOCK BACKEND nvme access=read-only' "$$log"; \
	  grep -q '^NVME READ OK lba=0 ' "$$log"; grep -q '^TIMER OK ticks=' "$$log"; \
	  grep -qx 'USER PREEMPTION OK' "$$log"; grep -qx 'ABSD BOOT OK' "$$log"; \
	  test "$$before" = "$$(sha256sum < "$$image")"; \
	  echo "physical-iso-test: $$firmware boot matched on screen; NVMe untouched"; \
	done; rm -f "$$image"

# The physical ISO's safety gate: the ISO's own kernel and GRUB entries,
# then that kernel booted with write-requesting command lines against
# scratch NVMe and ATA images, with QEMU device traces (scripts/physical-iso-gate.sh).
physical-iso-gate: physical-iso-test
	@sh scripts/physical-iso-gate.sh build/absd-physical.iso $(PHYSICAL_KERNEL) "$(QEMU)"

# The laptop-shaped QEMU machine (scripts/laptop-test.sh): q35, OVMF, USB
# boot, NVMe only, no serial port; all evidence read back from the screen.
laptop-test: physical-iso nvme-iso
	@sh scripts/laptop-test.sh build/absd-physical.iso build/absd-nvme-write.iso build/absd-nvme-verify.iso "$(QEMU)"

# Informational: one legacy assumption varied at a time on the laptop
# machine; outcomes land in build/laptop-matrix/summary.txt.
laptop-matrix: physical-iso
	@sh scripts/laptop-matrix.sh build/absd-physical.iso "$(QEMU)"

# Bounded xHCI bring-up ISOs (docs/xhci-20261010/RECORD.md): the probe
# boot, three rounds in one boot, the hotplug boot, and one per injected
# fault. `xhci-probe` is the only mode word that touches an xHCI.
xhci-iso: build
	@set -eu; for phase in probe:'xhci-probe' rounds:'xhci-probe xhci-rounds=3' hotplug:'xhci-probe xhci-hotplug' \
	    bar-bounds:'xhci-probe xhci-fault=bar-bounds' run-timeout:'xhci-probe xhci-fault=run-timeout' \
	    command-timeout:'xhci-probe xhci-fault=command-timeout' foreign-event:'xhci-probe xhci-fault=foreign-event' \
	    malformed-event:'xhci-probe xhci-fault=malformed-event' bad-slot:'xhci-probe xhci-fault=bad-slot' \
	    stale-event:'xhci-probe xhci-fault=stale-event' short-read:'xhci-probe xhci-fault=short-read' \
	    scratch-one:'xhci-probe xhci-scratchpads=1 xhci-observe' \
	    scratch-many:'xhci-probe xhci-scratchpads=32 xhci-rounds=2 xhci-observe' \
	    scratch-limit:'xhci-probe xhci-scratchpads=64 xhci-observe' \
	    scratch-over:'xhci-probe xhci-scratchpads=65' \
	    page-8k:'xhci-probe xhci-scratchpads=4 xhci-pagesize=2' \
	    page-multi:'xhci-probe xhci-scratchpads=4 xhci-pagesize=3' \
	    page-multi-none:'xhci-probe xhci-pagesize=3' \
	    scratch-alloc:'xhci-probe xhci-scratchpads=8 xhci-fault=scratchpad-alloc xhci-rounds=2' \
	    scratch-reclaim:'xhci-probe xhci-scratchpads=2 xhci-fault=early-reclaim' \
	    legacy-release:'xhci-probe xhci-firmware=release' \
	    legacy-delayed:'xhci-probe xhci-firmware=delayed' \
	    legacy-never:'xhci-probe xhci-firmware=never' \
	    legacy-late:'xhci-probe xhci-firmware=late' \
	    legacy-reacquire-smi:'xhci-probe xhci-firmware=reacquire-smi' \
	    legacy-duplicate:'xhci-probe xhci-firmware=duplicate' \
	    legacy-smi:'xhci-probe xhci-firmware=smi-flip' \
	    legacy-smi-stuck:'xhci-probe xhci-firmware=smi-stuck' \
	    legacy-clears-os:'xhci-probe xhci-firmware=clears-os' \
	    legacy-unowned:'xhci-probe xhci-firmware=unowned' \
	    legacy-reacquire:'xhci-probe xhci-firmware=reacquire xhci-scratchpads=2' \
	    legacy-reacquire-late:'xhci-probe xhci-firmware=reacquire-late xhci-scratchpads=2' \
	    both:'xhci-probe xhci-firmware=delayed xhci-scratchpads=32 xhci-observe' \
	    both-alloc:'xhci-probe xhci-firmware=release xhci-scratchpads=8 xhci-fault=scratchpad-alloc xhci-rounds=2' \
	    both-run-timeout:'xhci-probe xhci-firmware=release xhci-scratchpads=8 xhci-fault=run-timeout' \
	    both-never:'xhci-probe xhci-firmware=never xhci-scratchpads=8' \
	    both-ovmf:'xhci-probe xhci-firmware=delayed xhci-scratchpads=32'; do \
	  name=$${phase%%:*}; line=$${phase#*:}; \
	  mkdir -p build/xhci-$$name-iso/boot/grub; cp $(KERNEL) build/xhci-$$name-iso/boot/absd-kernel; \
	  printf '%s\n' 'insmod all_video' 'set timeout=0' 'menuentry "ABSD xHCI qualification" {' "  multiboot2 /boot/absd-kernel $$line" '  boot' '}' > build/xhci-$$name-iso/boot/grub/grub.cfg; \
	  grub-mkrescue -o build/absd-xhci-$$name.iso build/xhci-$$name-iso >/dev/null 2>&1; \
	done

# Controller present/absent/empty, never probed by the default boot, three
# rounds, super/high/full speeds, register bounds, run and command
# timeouts, substituted foreign, malformed and stale events, a real short
# data stage, the controller's own error completion, detach/re-attach over QMP, the bounded hotplug wait,
# and an OVMF-used controller (scripts/xhci-test.sh). QEMU qemu-xhci only.
xhci-test: xhci-iso iso
	@sh scripts/xhci-test.sh "$(QEMU)"

# Admitted stage 1 MSI-X controller cases. Ordinary boots do not probe USB.
.PHONY: xhci-controller-iso xhci-controller-test
xhci-controller-iso: build
	@set -eu; for phase in base:'xhci-controller' observe:'xhci-controller xhci-observe' rounds:'xhci-controller xhci-rounds=3' \
	    masked:'xhci-controller xhci-fault=masked-vector' storm:'xhci-controller xhci-fault=interrupt-storm' \
	    late:'xhci-controller xhci-fault=late-msi' run-timeout:'xhci-controller xhci-fault=run-timeout' \
	    legacy-smi:'xhci-controller xhci-firmware=smi-flip' legacy-reacquire:'xhci-controller xhci-firmware=reacquire-smi' \
	    legacy-probe-loss:'xhci-controller xhci-firmware=reacquire'; do \
	  name=$${phase%%:*}; line=$${phase#*:}; \
	  mkdir -p build/xhci-controller-$$name-iso/boot/grub; cp $(KERNEL) build/xhci-controller-$$name-iso/boot/absd-kernel; \
	  printf '%s\n' 'set timeout=0' 'menuentry "ABSD USB controller" {' "  multiboot2 /boot/absd-kernel $$line" '  boot' '}' > build/xhci-controller-$$name-iso/boot/grub/grub.cfg; \
	  grub-mkrescue -o build/absd-xhci-controller-$$name.iso build/xhci-controller-$$name-iso >/dev/null 2>&1; \
	done

xhci-controller-test: xhci-controller-iso
	python3 scripts/xhci-controller-test.py "$(QEMU)"

.PHONY: usb-keyboard-iso
usb-keyboard-iso: build
	@set -eu; for phase in base:'shell usb-keyboard usb-keyboard-observe' \
	    masked:'shell usb-keyboard usb-keyboard-observe usb-keyboard-fault=masked-vector' \
	    console-test:'shell usb-keyboard usb-keyboard-observe usb-keyboard-test' \
	    recover:'shell usb-keyboard usb-keyboard-observe usb-keyboard-recover' \
	    recover-late-entry:'shell usb-keyboard usb-keyboard-observe usb-keyboard-recover usb-keyboard-recovery-test=late-entry' \
	    recover-reset-timeout:'shell usb-keyboard usb-keyboard-observe usb-keyboard-recover usb-keyboard-recovery-test=reset-timeout' \
	    recover-enumeration-hold:'shell usb-keyboard usb-keyboard-observe usb-keyboard-recover usb-keyboard-recovery-test=enumeration-hold' \
	    combo-probe:'xhci-probe usb-keyboard' combo-ap:'usb-keyboard smp-kernel-only' \
	    combo-controller:'xhci-controller usb-keyboard' \
	    combo-test:'usb-keyboard usb-keyboard-test' combo-recovery:'shell usb-keyboard-recover'; do \
	  name=$${phase%%:*}; line=$${phase#*:}; \
	  mkdir -p build/usb-keyboard-$$name-iso/boot/grub; cp $(KERNEL) build/usb-keyboard-$$name-iso/boot/absd-kernel; \
	  printf '%s\n' 'set timeout=0' 'menuentry "ABSD USB keyboard" {' "  multiboot2 /boot/absd-kernel $$line" '  boot' '}' > build/usb-keyboard-$$name-iso/boot/grub/grub.cfg; \
	  grub-mkrescue -o build/absd-usb-keyboard-$$name.iso build/usb-keyboard-$$name-iso >/dev/null 2>&1; \
	done
	CARGO_TARGET_DIR=build/usb-keyboard-smp-target cargo rustc --bin absd-kernel --features smp-user-test -- -C relocation-model=static -C code-model=kernel -C no-redzone=yes -C link-arg=-Tlinker.ld -C link-arg=-nostdlib -C link-arg=-no-pie
	mkdir -p build/usb-keyboard-combo-user-iso/boot/grub
	cp build/usb-keyboard-smp-target/debug/absd-kernel build/usb-keyboard-combo-user-iso/boot/absd-kernel
	sha256sum build/usb-keyboard-smp-target/debug/absd-kernel > build/usb-keyboard-combo-user-kernel.txt
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD USB refuses SMP user mode" {' '  multiboot2 /boot/absd-kernel smp-user-test usb-keyboard' '  boot' '}' > build/usb-keyboard-combo-user-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-usb-keyboard-combo-user.iso build/usb-keyboard-combo-user-iso >/dev/null 2>&1

.PHONY: usb-keyboard-test
usb-keyboard-test: usb-keyboard-iso
	python3 scripts/usb-keyboard-test.py "$(QEMU)"

# NIC qualification ISOs (docs/NETWORK.md): the reflector boot, the same
# boot with an out-of-ring receive head injected into the device, and with
# the transmit-hold fixture released when carrier returns, or never.
net-iso: build
	@set -eu; for phase in probe:'net-probe' fault:'net-probe nic-ring-fault' hold:'net-probe nic-tx-hold' stuck:'net-probe nic-tx-hold-stuck'; do \
	  name=$${phase%%:*}; line=$${phase#*:}; \
	  mkdir -p build/net-$$name-iso/boot/grub; cp $(KERNEL) build/net-$$name-iso/boot/absd-kernel; \
	  printf '%s\n' 'set timeout=0' 'menuentry "ABSD NIC qualification" {' "  multiboot2 /boot/absd-kernel $$line" '  boot' '}' > build/net-$$name-iso/boot/grub/grub.cfg; \
	  grub-mkrescue -o build/absd-net-$$name.iso build/net-$$name-iso >/dev/null 2>&1; \
	done

# The e1000 under QEMU: link up, the frame calls' refusals, a host harness
# on `-netdev dgram` checking byte-exact reflection and that 1515..1518-byte
# frames are refused (scripts/nic-reflect.py); the same boot with the link
# down before the probe (granted, nothing on the wire, recovered when the
# harness raises the link); then a device head register outside its ring
# disabling the NIC; then the link down with the transmit-hold fixture: a
# bound without carrier is a link outcome and is released when carrier
# returns, and a hold that never releases disables the NIC as a device
# outcome; then a `net-probe` boot with no NIC.
# Measurement only, not a gate (docs/NETWORK.md, "Limits"): times the first
# frame the guest receives after the probe's RCTL write, at send delays of
# 0, 500, 900 and 1100 ms after the guest's hello. Prints one JSON line each.
nic-cold-rx-measure: net-iso
	@set -eu; for delay in 0 500 900 1100; do \
	  timeout 120s python3 -I scripts/nic-cold-rx.py build/nic-cold-rx-$$delay $$delay $(QEMU) -m 256 -display none -no-reboot -no-shutdown \
	    -device isa-debug-exit,iobase=0xf4,iosize=0x04 -cdrom build/absd-net-probe.iso; \
	done

net-test: net-iso
	@set -eu; common="$(QEMU) -display none -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04"; \
	log=build/net-probe.serial.log; \
	timeout 180s python3 scripts/nic-reflect.py build/net-probe-sockets "$$log" $$common -cdrom build/absd-net-probe.iso; \
	grep -q '^NIC CONTROLLER pci=[0-9a-f:.]* vendor=8086 device=100e mac=52:54:00:12:34:56$$' $$log; \
	grep -qx 'NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048' $$log; \
	grep -qx 'NIC REFUSALS OK' $$log; \
	grep -qx 'NIC RX REFUSED length=1515' $$log; grep -qx 'NIC RX REFUSED length=1518' $$log; \
	grep -qx 'NIC PROBE REFLECTED frames=38 largest=1514 ignored=0 rx_frames=39 rx_refused=3 tx_frames=39' $$log; \
	grep -qx 'NIC PROBE OK' $$log; \
	grep -qx 'NET status=0 frames=0 processes=0 cells=0 pipes=0' $$log; \
	grep -qx 'NIC STATS rx_frames=39 rx_refused=3 rx_missed=0 tx_frames=39 tx_refused=5 tx_errors=0 flags=1' $$log; \
	grep -qx 'NET WORKLOAD OK' $$log; grep -qx 'ABSD BOOT OK' $$log; \
	if grep -q 'PANIC\|KERNEL FAULT\|NIC DISABLED\|NIC PROBE LINK\|NIC TX HOLD\|NIC PROBE TX' $$log; then echo "net-test: unexpected output matching 'PANIC\|KERNEL FAULT\|NIC DISABLED\|NIC PROBE LINK\|NIC TX HOLD\|NIC PROBE TX' in $$log" >&2; exit 1; fi; \
	log=build/net-linkdown.serial.log; \
	timeout 180s python3 scripts/nic-reflect.py --link-down build/net-linkdown-sockets "$$log" $$common -cdrom build/absd-net-probe.iso; \
	grep -q '^NIC CONTROLLER pci=[0-9a-f:.]* vendor=8086 device=100e mac=52:54:00:12:34:56$$' $$log; \
	grep -qx 'NIC LINK DOWN AT PROBE rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048' $$log; \
	grep -qx 'NIC PROBE LINK DOWN mac=52:54:00:12:34:56' $$log; grep -qx 'NIC PROBE LINK UP' $$log; \
	grep -qx 'NIC RX REFUSED length=1515' $$log; grep -qx 'NET status=0 frames=0 processes=0 cells=0 pipes=0' $$log; \
	grep -qx 'NIC REFUSALS OK' $$log; \
	grep -qx 'NIC PROBE REFLECTED frames=38 largest=1514 ignored=0 rx_frames=39 rx_refused=3 tx_frames=40' $$log; \
	grep -qx 'NIC PROBE OK' $$log; \
	grep -qx 'NIC STATS rx_frames=39 rx_refused=3 rx_missed=0 tx_frames=40 tx_refused=5 tx_errors=0 flags=1' $$log; \
	grep -qx 'NET WORKLOAD OK' $$log; grep -qx 'ABSD BOOT OK' $$log; \
	if grep -q 'PANIC\|KERNEL FAULT\|NIC DISABLED\|NIC UNAVAILABLE\|NETWORK LINK OK\|NIC TX HOLD\|NIC PROBE TX' $$log; then echo "net-test: unexpected output matching 'PANIC\|KERNEL FAULT\|NIC DISABLED\|NIC UNAVAILABLE\|NETWORK LINK OK\|NIC TX HOLD\|NIC PROBE TX' in $$log" >&2; exit 1; fi; \
	log=build/net-fault.serial.log; rm -f "$$log"; status=0; \
	timeout 60s $$common -cdrom build/absd-net-fault.iso -serial file:$$log -nic user,model=e1000 >/dev/null 2>&1 || status=$$?; \
	test "$$status" -eq 3; \
	grep -qx 'NIC RING FAULT INJECTED rdh=35' $$log; \
	grep -qx 'NIC DISABLED reason=rx-head-outside-ring head=35' $$log; \
	grep -qx 'NIC FAIL CLOSED OK' $$log; \
	grep -qx 'NIC STATS rx_frames=0 rx_refused=0 rx_missed=0 tx_frames=0 tx_refused=0 tx_errors=0 flags=2' $$log; \
	grep -qx 'NET WORKLOAD OK' $$log; \
	if grep -q 'NIC TX HOLD\|NIC PROBE TX' $$log; then echo "net-test: unexpected transmit-hold output in $$log" >&2; exit 1; fi; \
	log=build/net-txhold.serial.log; \
	timeout 180s python3 scripts/nic-reflect.py --tx-hold build/net-txhold-sockets "$$log" $$common -cdrom build/absd-net-hold.iso; \
	grep -q '^NIC TX HOLD FIXTURE ARMED mode=release kind=\(tctl\|software\)$$' $$log; \
	grep -qx 'NIC LINK DOWN AT PROBE rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048' $$log; \
	grep -q '^NIC PROBE TX HELD held_ticks=[0-9]* refused_ticks=\([0-9]\|[1-4][0-9]\)$$' $$log; \
	grep -qx 'NIC PROBE TX RELEASED tx_frames=2 tx_errors=1' $$log; \
	grep -qx 'NIC STATS rx_frames=0 rx_refused=0 rx_missed=0 tx_frames=2 tx_refused=0 tx_errors=1 flags=1' $$log; \
	grep -qx 'NET WORKLOAD OK' $$log; grep -qx 'ABSD BOOT OK' $$log; \
	if grep -q 'PANIC\|KERNEL FAULT\|NIC DISABLED' $$log; then echo "net-test: unexpected output matching 'PANIC\|KERNEL FAULT\|NIC DISABLED' in $$log" >&2; exit 1; fi; \
	log=build/net-txstuck.serial.log; \
	timeout 180s python3 scripts/nic-reflect.py --tx-hold-stuck build/net-txstuck-sockets "$$log" $$common -cdrom build/absd-net-stuck.iso; \
	grep -q '^NIC TX HOLD FIXTURE ARMED mode=stuck kind=\(tctl\|software\)$$' $$log; \
	grep -qx 'NIC LINK DOWN AT PROBE rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048' $$log; \
	grep -q '^NIC PROBE TX HELD held_ticks=[0-9]* refused_ticks=\([0-9]\|[1-4][0-9]\)$$' $$log; \
	grep -qx 'NIC DISABLED reason=tx-timeout' $$log; \
	grep -qx 'NIC PROBE TX STUCK DISABLED tx_errors=2' $$log; \
	grep -qx 'NIC STATS rx_frames=0 rx_refused=0 rx_missed=0 tx_frames=0 tx_refused=0 tx_errors=2 flags=2' $$log; \
	grep -qx 'NET WORKLOAD OK' $$log; \
	if grep -q 'PANIC\|KERNEL FAULT' $$log; then echo "net-test: unexpected output matching 'PANIC\|KERNEL FAULT' in $$log" >&2; exit 1; fi; \
	log=build/net-absent.serial.log; rm -f "$$log"; status=0; \
	timeout 60s $$common -cdrom build/absd-net-probe.iso -serial file:$$log -nic none >/dev/null 2>&1 || status=$$?; \
	test "$$status" -eq 7; \
	grep -qx 'NIC UNAVAILABLE Absent' $$log; grep -qx 'init: FAILED at no NIC' $$log; \
	grep -qx 'NET WORKLOAD FAILED' $$log; if grep -q 'NETWORK LINK OK\|ABSD BOOT OK\|NIC TX HOLD\|NIC PROBE TX' $$log; then echo "net-test: unexpected output matching 'NETWORK LINK OK\|ABSD BOOT OK\|NIC TX HOLD\|NIC PROBE TX' in $$log" >&2; exit 1; fi; \
	echo 'net-test: NETWORK LINK OK, refusals, byte-exact reflection, oversize refused, link down at the probe granted and recovered, ring fault disables the NIC, transmit bound without carrier held and released, stuck hold disabled, absent NIC refused'

durable-reader-test:
	@scripts/durable-reader-test.sh "$(QEMU)"

# Init-brokered spawning (docs/BROKER.md): refusals, narrowed authority,
# nested requesters, and reclamation when a requester ends.
broker-test:
	@scripts/broker-test.sh "$(QEMU)"

# spawn_image (syscall 31): a child from an image in the caller's memory,
# and every refusal with its exact error and no leak (docs/PROCESS-STARTUP.md).
spawn-image-test:
	@scripts/spawn-image-test.sh "$(QEMU)"

elf-matrix-test:
	@scripts/elf-matrix-test.sh "$(QEMU)"

spawn-image-rollback-test:
	@scripts/spawn-image-rollback-test.sh "$(QEMU)"

disclosure-probe-test:
	@scripts/disclosure-probe-test.sh "$(QEMU)"

# One durable boot ISO per step word: the external workload ELF runs with
# the block device and a step cell, and `durable=N` selects what it does.
# Booting is left to scripts/durable-boot.sh so a harness can preserve the
# backing image across abrupt stops and fresh boots.
durable-iso: external-build
	mkdir -p build/durable/iso-$(DURABLE_STEP)/boot/grub
	cp $(EXTERNAL_KERNEL) build/durable/iso-$(DURABLE_STEP)/boot/absd-kernel
	printf '%s\n' 'insmod all_video' 'set timeout=0' 'menuentry "ABSD durable step" {' '  multiboot2 /boot/absd-kernel durable=$(DURABLE_STEP) $(DURABLE_OPTIONS) nvme-write=$(NVME_SERIAL)' '  boot' '}' > build/durable/iso-$(DURABLE_STEP)/boot/grub/grub.cfg
	grub-mkrescue -o $(DURABLE_ISO) build/durable/iso-$(DURABLE_STEP)
	@echo "durable-iso: $(DURABLE_ISO)"

shell-iso: build
	mkdir -p build/shell-iso/boot/grub
	cp $(KERNEL) build/shell-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD shell" {' '  multiboot2 /boot/absd-kernel shell' '  boot' '}' > build/shell-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-shell.iso build/shell-iso

# An interactive session over a serial socket: scripts/shell-session.py
# sends each command only after the shell prompts for it, so the console
# read path really blocks, and the kernel checks reclamation at the end.
shell-test: shell-iso
	@set -eu; output="build/shell.serial.log"; rm -f "$$output" build/shell.sock; status=0; \
	$(QEMU) -cdrom build/absd-shell.iso -display none -chardev socket,id=con,path=build/shell.sock,server=on,wait=on -serial chardev:con -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 & qemu=$$!; \
	python3 scripts/shell-session.py build/shell.sock $$output 'hello-b' 'exit7' 'sleeper 30' 'bogus' 'trap' '' 'jobs' 'sleeper 5 &' 'sleeper 30' 'jobs' 'wait' 'exit7 |' 'sleeper 100000 &' 'kill 2' 'kill 9' 'wait' 'quit' || { kill $$qemu 2>/dev/null; exit 1; }; \
	wait $$qemu || status=$$?; \
	grep -qx 'user-B: hello from ELF userspace' $$output; \
	grep -qx 'shell: hello-b exited 0' $$output; \
	grep -qx 'user-exit7: exiting nonzero' $$output; grep -qx 'shell: exit7 exited 7' $$output; \
	grep -qx 'user-sleeper: slept for the requested ticks' $$output; grep -qx 'shell: sleeper exited 0' $$output; \
	grep -q 'shell: unknown program bogus$$' $$output; \
	grep -qx 'shell: trap faulted vector 6' $$output; \
	grep -q 'shell: no jobs$$' $$output; \
	grep -q 'shell: started sleeper as job 1 (pid [0-9]*)$$' $$output; \
	grep -q 'job 1: sleeper pid [0-9]* finished$$' $$output; \
	grep -q 'shell: job 1 (sleeper) exited 0$$' $$output; \
	test "$$(grep -cx 'user-exit7: exiting nonzero' $$output)" -eq 2; \
	grep -q 'shell: captured 28 bytes from exit7$$' $$output; \
	grep -q 'shell: killed job 2$$' $$output; grep -q 'shell: no job 9$$' $$output; \
	grep -q 'shell: job 2 (sleeper) killed$$' $$output; \
	grep -q 'USER KILLED pid=[0-9]* by=2$$' $$output; \
	grep -q 'shell: bye$$' $$output; \
	grep -qx 'USER INIT STARTED' $$output; grep -qx 'INIT SPAWN OK' $$output; \
	grep -qx 'INIT REAP OK' $$output; grep -qx 'USERSPACE BOOTSTRAP OK' $$output; \
	test "$$(grep -o '> ' $$output | wc -l)" -ge 18; \
	grep -q '^SHELL SESSION status=0 frames=0 console_reads=[0-9]*/[1-9][0-9]* dropped=0$$' $$output; \
	grep -qx 'SHELL SESSION OK' $$output; grep -qx 'ABSD BOOT OK' $$output; \
	if [ "$$status" -ne 3 ]; then echo "unexpected QEMU exit: $$status" >&2; exit 1; fi; \
	echo 'shell-test: scripted shell session passed (build/shell.serial.log)'

debug: iso
	rm -f build/qemu-debug.log
	@set -eu; status=0; \
	$(QEMU) -cdrom $(ISO) -display none -serial stdio -no-reboot -no-shutdown -d int,cpu_reset -D build/qemu-debug.log -device isa-debug-exit,iobase=0xf4,iosize=0x04 || status=$$?; \
	if [ "$$status" -ne 3 ]; then echo "unexpected QEMU exit: $$status" >&2; exit 1; fi; \
	test -s build/qemu-debug.log; echo 'debug: QEMU interrupt trace at build/qemu-debug.log'

# ACPI table reading, MADT topology, FADT reset/S5 and opt-in S5 power-off
# on q35 TCG (scripts/acpi-test.sh, docs/x86-acpi-20261015/RESULT.md).
.PHONY: acpi-test
acpi-test: iso
	cargo test --lib -- acpi::
	sh scripts/acpi-test.sh $(ISO)

smoke: iso
	@set -eu; output="build/smoke.serial.log"; rm -f "$$output"; \
	host_before=$$(date +%s); \
	$(QEMU) -cdrom $(ISO) -display none -serial file:$$output -no-reboot -no-shutdown -rtc base=utc -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 || status=$$?; \
	host_after=$$(date +%s); \
	wall=$$(sed -n 's/^WALL CLOCK OK seconds=\([0-9][0-9]*\) advanced=[1-9][0-9]*$$/\1/p' $$output); \
	test -n "$$wall"; test "$$wall" -ge "$$((host_before - 2))"; test "$$wall" -le "$$((host_after + 2))"; \
	grep -qx 'ABI VERSION OK n=1' $$output; \
	grep -q '^FRAME STATS OK tracked=[1-9][0-9]* free=[1-9][0-9]* allocated=[1-9][0-9]* limit=none mapped=6[4-9]$$' $$output; \
	grep -qx 'ABSD KERNEL BOOT' $$output; grep -qx 'ABSD BOOT OK' $$output; \
	grep -q '^FRAMEBUFFER CONSOLE OK width=[0-9]* height=[0-9]* ' $$output; \
	grep -q '^allocated frame 0: 0x[0-9a-f]*$$' $$output; \
	grep -q '^paging entry frame: 0x[0-9a-f]*$$' $$output; \
	grep -qx 'PAGE MAP OK' $$output; \
	grep -qx 'IDT BREAKPOINT OK' $$output; \
	grep -q '^TIMER OK ticks=[1-9][0-9]*$$' $$output; \
	grep -qx 'HEAP OK' $$output; \
	grep -q '^SPAWN EXHAUSTION frames_per_process=[1-9][0-9]*$$' $$output; grep -qx 'SPAWN EXHAUSTION OK' $$output; \
	grep -qx 'PROCESS MODEL OK' $$output; \
	grep -qx 'SPAWN OK pid=1 parent=0 program=init' $$output; \
	grep -qx 'USER INIT STARTED' $$output; grep -qx 'USERSPACE BOOTSTRAP OK' $$output; \
	grep -qx 'SPAWN OK pid=2 parent=1 program=hello-a' $$output; \
	grep -qx 'SPAWN OK pid=5 parent=1 program=fault' $$output; \
	grep -qx 'user-A: hello from ELF userspace' $$output; test "$$(grep -cx 'user-B: hello from ELF userspace' $$output)" -eq 1; \
	grep -qx 'init: captured child output through a pipe' $$output; \
	grep -qx 'init: cancellation verified' $$output; \
	grep -qx 'init: bounded transfers verified' $$output; \
	grep -qx 'MULTI HANDLE SPAWN OK' $$output; \
	grep -qx 'PIPE INFO OK' $$output; \
	grep -qx 'CHILD CONSOLE RIGHTS OK' $$output; \
	grep -qx 'HANDLE TRANSFER OK' $$output; grep -qx 'PIPE CELL COMPOSE OK' $$output; \
	grep -qx 'HANDLE LIFETIME STRESS OK' $$output; \
	grep -qx 'PROCESS HANDLE REAP OK' $$output; grep -qx 'PROCESS RIGHTS OK' $$output; \
	grep -qx 'WAIT ANY PARENTAGE OK' $$output; \
	grep -qx 'WAIT ANY PID OK' $$output; grep -qx 'ORPHAN ADOPTION OK' $$output; \
	grep -qx 'ADOPTION HANDLE PRESSURE OK' $$output; \
	grep -qx 'INIT REAPER OK' $$output; \
	grep -qx 'SUPERVISOR OBSERVED FAULT' $$output; \
	grep -qx 'SUPERVISOR REPLACEMENT SPAWNED' $$output; \
	grep -qx 'SUPERVISOR RECONCILE OK' $$output; \
	grep -qx 'SUPERVISOR CLOSURE OK' $$output; \
	grep -qx 'SUPERVISOR RESTART OK' $$output; \
	grep -qx 'SUPERVISOR GRACEFUL STOP OK' $$output; \
	grep -qx 'GRACEFUL STOP OK' $$output; \
	grep -qx 'SUPERVISOR STOP FALLBACK OK' $$output; \
	grep -qx 'SUPERVISOR TIMED WAIT OK' $$output; \
	grep -qx 'FORCED STOP OK' $$output; \
	grep -qx 'SUPERVISOR RECLAIM OK' $$output; \
	grep -qx 'SUPERVISOR ESCALATION OK' $$output; \
	grep -qx 'SUPERVISOR RESOURCE REFUSAL OK' $$output; \
	grep -qx 'SERVICE GENERATION OK' $$output; \
	grep -qx 'REQUEST IDENTITY OK' $$output; \
	grep -qx 'CONDITIONAL SERVICE UPDATE OK' $$output; \
	grep -qx 'RECOVERY NOT PERFORMED OK' $$output; \
	grep -qx 'RESTART BEFORE RECOVERY OK' $$output; \
	grep -qx 'RECOVERY RECONCILE OK' $$output; \
	grep -qx 'NO DOUBLE APPLY OK' $$output; \
	grep -qx 'RECOVERY NORMAL COMPLETION OK' $$output; \
	grep -qx 'SERVICE STATE SURVIVES RESTART OK' $$output; \
	grep -qx 'RECOVERY REPLACEMENT REFUSED' $$output; \
	grep -qx 'RECOVERY RESOURCE REFUSAL OK' $$output; \
	grep -qx 'SERVICE RECOVERY OK' $$output; \
	grep -qx 'CLIENT GENERATION CONTRACT OK' $$output; \
	grep -qx 'CLIENT SERVICE OBJECTS STABLE OK' $$output; \
	grep -qx 'CLIENT GENERATION CHANGE OK' $$output; \
	grep -qx 'STALE GENERATION REFUSED OK' $$output; \
	grep -qx 'CLIENT RETRY NOT PERFORMED OK' $$output; \
	grep -qx 'CLIENT RECONCILE COMPLETED OK' $$output; \
	grep -qx 'CLIENT NO DOUBLE APPLY OK' $$output; \
	grep -qx 'CLIENT NORMAL COMPLETION OK' $$output; \
	grep -qx 'CLIENT SURVIVES SERVICE RESTART OK' $$output; \
	grep -qx 'MULTI GENERATION SERVICE OK' $$output; \
	grep -qx 'CLIENT SERVICE UNAVAILABLE OK' $$output; \
	grep -qx 'CLIENT SERVICE RESUME OK' $$output; \
	grep -qx 'RECOVERY HEADROOM PRESERVED OK' $$output; \
	grep -qx 'RECOVERY HEADROOM EXHAUSTED OK' $$output; \
	grep -q '^SERVICE CLIENT COMPLETE pid=[1-9][0-9]* generations=9$$' $$output; \
	test "$$(grep -c '^CLIENT SERVICE START generation=[1-9] pid=[1-9][0-9]* request=[1-9][0-9]*$$' $$output)" -eq 9; \
	grep -q '^SERVICE INSTANCE service=test generation=[1-7] pid=[1-9][0-9]* request=[1-9][0-9]*$$' $$output; \
	grep -q '^SERVICE START service=test generation=[1-7] pid=[1-9][0-9]* request=[1-9][0-9]*$$' $$output; \
	test "$$(grep -c '^SERVICE INSTANCE service=test generation=[1-7] pid=[1-9][0-9]* request=[1-9][0-9]*$$' $$output)" -eq 8; \
	test "$$(grep -c '^SERVICE START service=test generation=[1-7] pid=[1-9][0-9]* request=[1-9][0-9]*$$' $$output)" -eq 8; \
	restart_line="$$(grep -n '^RESTART BEFORE RECOVERY OK$$' $$output | cut -d: -f1)"; \
	reconcile_line="$$(grep -n '^RECOVERY RECONCILE OK$$' $$output | cut -d: -f1)"; \
	refused_line="$$(grep -n '^RECOVERY REPLACEMENT REFUSED$$' $$output | cut -d: -f1)"; \
	resource_line="$$(grep -n '^RECOVERY RESOURCE REFUSAL OK$$' $$output | cut -d: -f1)"; \
	service_line="$$(grep -n '^SERVICE RECOVERY OK$$' $$output | cut -d: -f1)"; \
	test "$$restart_line" -lt "$$reconcile_line"; \
	test "$$reconcile_line" -lt "$$refused_line"; \
	test "$$refused_line" -lt "$$resource_line"; \
	test "$$resource_line" -lt "$$service_line"; \
	grep -q '^SUPERVISOR INSTANCE generation=[1-4] pid=[1-9][0-9]*$$' $$output; \
	grep -q '^WORKER START generation=[1-4] pid=[1-9][0-9]*$$' $$output; \
	grep -q '^WORKER STOP generation=3 pid=[1-9][0-9]*$$' $$output; \
	sed -n 's/^SUPERVISOR INSTANCE generation=\([0-9][0-9]*\) pid=\([0-9][0-9]*\)$$/\1 \2/p' $$output | \
	while read generation pid; do grep -qx "WORKER START generation=$$generation pid=$$pid" $$output; done; \
	sed -n 's/^WORKER START generation=\([0-9][0-9]*\) pid=\([0-9][0-9]*\)$$/\1 \2/p' $$output | \
	while read generation pid; do grep -qx "SUPERVISOR INSTANCE generation=$$generation pid=$$pid" $$output; done; \
	sed -n 's/^SERVICE INSTANCE service=test generation=\([0-9][0-9]*\) pid=\([0-9][0-9]*\) request=\([0-9][0-9]*\)$$/\1 \2 \3/p' $$output | \
	while read generation pid request; do grep -qx "SERVICE START service=test generation=$$generation pid=$$pid request=$$request" $$output; done; \
	grep -qx 'PROCESS CAPACITY OK' $$output; grep -qx 'HANDLE CAPACITY OK' $$output; grep -qx 'MACHINE RIGHT OK' $$output; \
	test "$$(grep -cx 'MACHINE REQUEST REFUSED pid=1 error=-1' $$output)" -eq 6; \
	test "$$(grep -cx 'MACHINE REQUEST REFUSED pid=1 error=-9' $$output)" -eq 3; \
	probes="$$(sed -n 's/^SPAWN OK pid=\([0-9][0-9]*\) parent=1 program=machine-probe$$/\1/p' $$output)"; \
	test "$$(printf '%s\n' $$probes | wc -l)" -eq 2; \
	unarmed="$$(printf '%s\n' $$probes | sed -n 1p)"; restart_only="$$(printf '%s\n' $$probes | sed -n 2p)"; \
	test "$$(grep -cx "MACHINE REQUEST REFUSED pid=$$unarmed error=-9" $$output)" -eq 5; \
	test "$$(grep -cx "MACHINE REQUEST REFUSED pid=$$restart_only error=-9" $$output)" -eq 3; \
	test "$$(grep -cx "MACHINE REQUEST REFUSED pid=$$restart_only error=-1" $$output)" -eq 2; \
	if grep -q '^MACHINE RECOVER RESET' $$output; then echo "smoke: unexpected MACHINE RECOVER RESET in $$output" >&2; exit 1; fi; \
	grep -qx 'OBJECT CAPACITY OK' $$output; \
	grep -qx 'USER STACK GROW OK' $$output; \
	grep -qx 'STACK GROW pages=1031' $$output; \
	grep -qx 'STACK GROW ISOLATION OK' $$output; \
	grep -qx 'USER HEAP ALLOC OK' $$output; \
	grep -qx 'ADDRESS SPACE ISOLATION OK' $$output; \
	grep -qx 'INPUT STREAM OK' $$output; \
	grep -qx 'hello from userspace buffer' $$output; \
	grep -qx 'READONLY USER BUFFER OK' $$output; \
	grep -qx 'SYSCALL NEGATIVE CONTROLS OK' $$output; grep -qx 'SYSCALL ABI OK' $$output; \
	grep -qx 'USER MEMORY VALIDATION OK' $$output; \
	grep -qx 'OBJECT TABLES EMPTY OK' $$output; \
	grep -qx 'PROCESS HANDLE ISOLATION OK' $$output; \
	grep -qx 'USER EXIT pid=2 status=0' $$output; grep -qx 'USER EXIT pid=3 status=0' $$output; \
	grep -qx 'USER EXIT pid=4 status=7' $$output; \
	grep -q '^USER FAULT pid=5 vector=14 address=0x[0-9a-f]* error=0x0000000000000007$$' $$output; \
	grep -q '^USER FAULT pid=6 vector=6 address=0x[0-9a-f]* error=0x0000000000000000$$' $$output; \
	grep -q '^USER FAULT pid=7 vector=13 address=0x[0-9a-f]* error=0x0000000000000000$$' $$output; \
	test "$$(grep -cx 'user-fpu: xmm state preserved' $$output)" -eq 2; \
	grep -qx 'init: demonstration outcomes verified' $$output; \
	grep -qx 'init: spawn capacity bounded and reaped' $$output; \
	grep -qx 'init: lifecycle stress complete' $$output; \
	grep -qx 'USER EXIT pid=1 status=0' $$output; \
	if grep -q 'must not appear' $$output; then echo "smoke: unexpected output matching 'must not appear' in $$output" >&2; exit 1; fi; \
	grep -qx 'user-heap: map/unmap verified' $$output; \
	grep -qx 'user-cell: conditional transitions verified' $$output; \
	test "$$(grep -c '^user-shared: racer [123] done' $$output)" -eq 3; \
	grep -qx 'user-readonly: write right correctly withheld' $$output; \
	grep -qx 'user-watcher: observed the cell reach its stop mark' $$output; \
	grep -qx 'init: pipe stream verified' $$output; \
	grep -qx 'user-sleeper: slept for the requested ticks' $$output; \
	grep -qx 'init: timed waits verified' $$output; \
	grep -q '^USER FAULT pid=[0-9]* vector=14 address=0x0000008010000000 error=0x0000000000000004$$' $$output; \
	grep -q '^FRAMES baseline=[0-9]* peak=[0-9]* final=[0-9]* spawns=[0-9]* reaps=[0-9]* maps=[0-9]* unmaps=[0-9]* cells=0 transitions=[0-9]*/[0-9]* cell_waits=[0-9]*/[0-9]* pipes=0 pipe_io=[0-9]*/[0-9]* pipe_waits=[0-9]*/[0-9]* sleeps=[0-9]* timeouts=13 idle=[1-9][0-9]* ticks=[0-9]* kstack_peak=[0-9]*/[0-9]*$$' $$output; \
	grep -qx 'PROCESS EXIT OK' $$output; grep -qx 'PROCESS FAULT ISOLATION OK' $$output; \
	grep -qx 'USER PREEMPTION OK' $$output; \
	grep -qx 'SPAWN OK' $$output; grep -qx 'SPAWN BOUNDED OK' $$output; grep -qx 'REAP OK' $$output; \
	grep -qx 'PROCESS RECLAIM OK' $$output; grep -qx 'PROCESS STRESS OK' $$output; \
	grep -qx 'USER PROCESSES OK' $$output; \
	grep -qx 'USER SCHEDULER OK' $$output; \
	if [ "$${status:-0}" -ne 3 ]; then echo "unexpected QEMU exit: $${status:-0}" >&2; exit 1; fi; \
	echo 'smoke: process lifecycle suite passed (build/smoke.serial.log)'

# Deliberately disable one enforcement boundary at a time. The ordinary boot
# oracle must reject every mutant; a successful status plus ABSD BOOT OK is a
# harness failure. Build trees and ISOs are disposable, while the small serial
# logs remain as diagnostics until `make clean`.
mutants:
	@set -eu; mkdir -p build/mutants; \
	for mutant in absd_mutant_no_rights_check absd_mutant_free_any_owner absd_mutant_ignore_writable; do \
		( scratch="$$(mktemp -d $${TMPDIR:-/tmp}/absd-mutant.XXXXXX)"; \
		  trap 'rm -rf "$$scratch"' EXIT INT TERM; \
		  CARGO_TARGET_DIR="$$scratch/target" RUSTFLAGS="--cfg $$mutant" \
		    $(KERNEL_CARGO) rustc --bin absd-kernel -- -C relocation-model=static -C code-model=kernel -C no-redzone=yes -C link-arg=-Tlinker.ld -C link-arg=-nostdlib -C link-arg=-no-pie; \
		  mkdir -p "$$scratch/iso/boot/grub"; \
		  cp "$$scratch/target/debug/absd-kernel" "$$scratch/iso/boot/absd-kernel"; \
		  cp grub.cfg "$$scratch/iso/boot/grub/grub.cfg"; \
		  grub-mkrescue -o "$$scratch/mutant.iso" "$$scratch/iso" >/dev/null 2>&1; \
		  log="build/mutants/$$mutant.serial.log"; rm -f "$$log"; status=0; \
		  timeout 30s $(QEMU) -cdrom "$$scratch/mutant.iso" -display none -serial "file:$$log" -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 || status=$$?; \
		  if [ "$$status" -eq 3 ] && grep -qx 'ABSD BOOT OK' "$$log"; then \
		    echo "mutants: $$mutant escaped the smoke oracle" >&2; exit 1; \
		  fi; \
		  echo "mutants: $$mutant rejected (qemu status $$status)" ); \
	done

clean:
	rm -rf build

# Small scheduler experiment, no disks/network or RT admission syscall.
.PHONY: rt-test rt-iso
rt-iso: build
	mkdir -p build/rt-iso/boot/grub
	cp $(KERNEL) build/rt-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD RT experiment" {' '  multiboot2 /boot/absd-kernel rt-test' '  boot' '}' > build/rt-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-rt.iso build/rt-iso >/dev/null 2>&1

rt-test: rt-iso
	@set -eu; status=0; \
	timeout 30s $(QEMU) -cdrom build/absd-rt.iso -display none -serial file:build/rt.serial.log -no-reboot -no-shutdown -nic none -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 || status=$$?; \
	test "$$status" -eq 3; \
	python3 scripts/check-rt.py build/rt.serial.log

.PHONY: rt-class-iso rt-class-run rt-class-test
rt-class-iso: build
	mkdir -p build/rtc-iso/boot/grub
	cp $(KERNEL) build/rtc-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD bounded RT class" {' '  multiboot2 /boot/absd-kernel rt-class' '  boot' '}' > build/rtc-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-rtc.iso build/rtc-iso >/dev/null 2>&1

rt-class-run: rt-class-iso
	@set -eu; status=0; \
	timeout 60s $(QEMU) -cdrom build/absd-rtc.iso -display none -serial file:build/rtc.serial.log -no-reboot -no-shutdown -nic none -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 || status=$$?; \
	test "$$status" -eq 3

rt-class-test: rt-class-run
	python3 scripts/check-rt-class.py build/rtc.serial.log

# Neither PID 1 nor the served boot authorizes machine_recover: in an
# ordinary boot init hands a recover-only handle to a child, and the child's
# request resets the machine. With -no-reboot and without -no-shutdown QEMU
# turns that reset into an exit with status 0 (a debug-exit halt is 3; a
# pause would end at the host timeout with 124).
machine-recover-iso: build
	mkdir -p build/machine-recover-iso/boot/grub
	cp $(KERNEL) build/machine-recover-iso/boot/absd-kernel
	printf '%s\n' 'set timeout=0' 'menuentry "ABSD machine recover right" {' '  multiboot2 /boot/absd-kernel machine-recover-test' '  boot' '}' > build/machine-recover-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-machine-recover.iso build/machine-recover-iso >/dev/null 2>&1

machine-recover-test: machine-recover-iso
	@set -eu; output="build/machine-recover.serial.log"; rm -f "$$output"; status=0; \
	timeout 60s $(QEMU) -cdrom build/absd-machine-recover.iso -display none -serial file:$$output -no-reboot -nic none -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 || status=$$?; \
	grep -qx 'MACHINE RECOVER TEST handing recover-only handle' $$output; \
	probe="$$(sed -n 's/^SPAWN OK pid=\([0-9][0-9]*\) parent=1 program=machine-probe$$/\1/p' $$output)"; \
	test -n "$$probe"; test "$$probe" -ne 1; \
	grep -qx "MACHINE RECOVER RESET pid=$$probe" $$output; \
	test "$$(grep -c '^MACHINE RECOVER RESET' $$output)" -eq 1; \
	if grep -q '^SERVED SHUTDOWN\|^SERVED RECOVERY BEGIN\|^SERVED RECOVERY RESET' $$output; then echo "machine-recover-test: unexpected served-boot init marker in $$output" >&2; exit 1; fi; \
	grep -q '^SERVED RECOVERY CENSUS processes=2 ' $$output; \
	if grep -q 'ABSD BOOT OK\|USER EXIT pid=1 \|init: FAILED' $$output; then echo "machine-recover-test: boot ended other than by the reset in $$output" >&2; exit 1; fi; \
	if [ "$$status" -ne 0 ]; then echo "machine-recover-test: unexpected QEMU exit: $$status" >&2; exit 1; fi; \
	echo "machine-recover-test: recover-only handle reset the machine from pid $$probe"

# UP handoff and BSP-only negative controls. The two-CPU QEMU boot leaves the
# application processor parked; it establishes no SMP execution claim.
.PHONY: smp-up-prep-test
smp-up-prep-test: build
	sh scripts/check-bsp-only.sh
	sh scripts/check-smp-up-prep.sh $(KERNEL) build/smp-up-prep

# FPU/MXCSR process isolation (docs/HOSTILE-USERSPACE.md). KVM only: QEMU TCG
# never raises #XM for an unmasked SSE exception, so the fault case cannot be
# exercised there and the boot would fail rather than pass without it.
.PHONY: fpu-iso fpu-test fpu-mutants
FPU_QEMU = $(QEMU) -enable-kvm -cpu host -display none -no-reboot -no-shutdown -nic none -device isa-debug-exit,iobase=0xf4,iosize=0x04
FPU_GRUB = printf '%s\n' 'set timeout=0' 'menuentry "ABSD fpu-test" {' '  multiboot2 /boot/absd-kernel fpu-test' '  boot' '}'

fpu-iso: build
	mkdir -p build/fpu-iso/boot/grub
	cp $(KERNEL) build/fpu-iso/boot/absd-kernel
	$(FPU_GRUB) > build/fpu-iso/boot/grub/grub.cfg
	grub-mkrescue -o build/absd-fpu.iso build/fpu-iso >/dev/null 2>&1

fpu-test: fpu-iso
	@set -eu; test -r /dev/kvm -a -w /dev/kvm || { echo 'fpu-test: needs KVM (/dev/kvm); TCG cannot deliver #XM' >&2; exit 1; }; \
	output="build/fpu.serial.log"; rm -f "$$output"; status=0; \
	timeout 60s $(FPU_QEMU) -cdrom build/absd-fpu.iso -serial file:$$output >/dev/null 2>&1 || status=$$?; \
	test "$$status" -eq 3; \
	python3 scripts/check-fpu.py $$output

# Each mutant must be rejected for its own reason: the restore skip by an
# isolation task observing its peer's state, the dirty fresh image by a witness.
fpu-mutants:
	@set -eu; test -r /dev/kvm -a -w /dev/kvm || { echo 'fpu-mutants: needs KVM (/dev/kvm)' >&2; exit 1; }; \
	mkdir -p build/mutants; \
	for pair in absd_mutant_skip_fpu_restore:CORRUPTED absd_mutant_fresh_fpu_dirty:CONTAMINATED; do \
		mutant=$${pair%%:*}; evidence=$${pair#*:}; \
		( scratch="$$(mktemp -d $${TMPDIR:-/tmp}/absd-mutant.XXXXXX)"; \
		  trap 'rm -rf "$$scratch"' EXIT INT TERM; \
		  CARGO_TARGET_DIR="$$scratch/target" RUSTFLAGS="--cfg $$mutant" \
		    $(KERNEL_CARGO) rustc --bin absd-kernel -- -C relocation-model=static -C code-model=kernel -C no-redzone=yes -C link-arg=-Tlinker.ld -C link-arg=-nostdlib -C link-arg=-no-pie; \
		  mkdir -p "$$scratch/iso/boot/grub"; \
		  cp "$$scratch/target/debug/absd-kernel" "$$scratch/iso/boot/absd-kernel"; \
		  $(FPU_GRUB) > "$$scratch/iso/boot/grub/grub.cfg"; \
		  grub-mkrescue -o "$$scratch/mutant.iso" "$$scratch/iso" >/dev/null 2>&1; \
		  log="build/mutants/$$mutant.serial.log"; rm -f "$$log"; status=0; \
		  timeout 60s $(FPU_QEMU) -cdrom "$$scratch/mutant.iso" -serial "file:$$log" >/dev/null 2>&1 || status=$$?; \
		  if python3 scripts/check-fpu.py "$$log" 2>/dev/null; then \
		    echo "fpu-mutants: $$mutant escaped the FPU oracle" >&2; exit 1; \
		  fi; \
		  grep -q "fpu-mxcsr: .*$$evidence" "$$log" || { echo "fpu-mutants: $$mutant rejected without $$evidence evidence" >&2; exit 1; }; \
		  echo "fpu-mutants: $$mutant rejected by $$evidence (qemu status $$status)" ); \
	done

# Focused authority/lifecycle regressions; explicit acceptance, outside make check.
.PHONY: capability-authority-test capability-mutants authority-effect-test authority-effect-mutants borrower-lifecycle-model-test authority-handle-pressure-test
capability-authority-test:
	@sh scripts/capability-authority-test.sh "$(QEMU)"
capability-mutants:
	@sh scripts/capability-mutants.sh "$(QEMU)"
authority-effect-test:
	@sh scripts/authority-effect-test.sh "$(QEMU)"
authority-effect-mutants:
	@sh scripts/authority-effect-mutants.sh "$(QEMU)"
borrower-lifecycle-model-test:
	@python3 tests/borrower_lifecycle_model.py
authority-handle-pressure-test:
	@sh scripts/authority-handle-pressure.sh "$(PRESSURE_OUTPUT)" "$(PRESSURE_LIBRARY)"

# Compare preserved producer traces. Both VMs must have passed their own oracle.
.PHONY: semantic-differential
semantic-differential:
	@test -n "$(X86_TRACE)" && test -n "$(ARM_TRACE)" && test -n "$(DIFF_RESULT)"
	python3 scripts/semantic-differential.py --x86 "$(X86_TRACE)" --arm "$(ARM_TRACE)" --output "$(DIFF_RESULT)"

# Bounded ARM virtual-platform build; qualification stays explicit.
.PHONY: arm64-build arm64-smp-build arm64-weak-memory-test portability-x86-test
arm64-build:
	sh scripts/build-arm64.sh
arm64-smp-build:
	ABSD_ARM_FEATURES=arm64-smp-qualification sh scripts/build-arm64.sh
arm64-weak-memory-test:
	python3 scripts/models/arm64-weak-memory.py --output "$(or $(WEAK_MEMORY_RESULT),build/arm64/weak-memory.json)"
# GICv3 and the GICv2 regression on QEMU virt (docs/ARM64.md): both images
# first, then one vCPU under each version, the refusal controls, and two
# and four vCPUs; TCG by default, ARM64_GIC_ARGS adds e.g. --accel hvf --full-smp.
.PHONY: arm64-gic-test
arm64-gic-test:
	sh scripts/build-arm64.sh
	ABSD_ARM_BUILD=$(CURDIR)/build/arm64-smp ABSD_ARM_FEATURES=arm64-smp-qualification sh scripts/build-arm64.sh
	python3 scripts/arm64-gic-qualify.py --image build/arm64/kernel.img --smp-image build/arm64-smp/kernel.img \
	    --work "$(or $(ARM64_GIC_WORK),build/arm64-gic)" $(ARM64_GIC_ARGS)
portability-x86-test:
	sh scripts/portability-x86-test.sh

# Host-only frame v0 gate. No emulator or external effects.
# with nice 19, CARGO_BUILD_JOBS<=4 and a load monitor (stop above 8).
.PHONY: check-frame-admission-host
check-frame-admission-host:
	python3 scripts/provenance.py check
	python3 scripts/test_provenance.py
	python3 scripts/models/rt-fixture.py
	python3 scripts/models/smp-lifetime.py --self-test
	python3 scripts/xhci-observe.py --self-test
	python3 scripts/test-i219-info.py
	python3 scripts/check-frame-admission.py
	python3 scripts/check-frame-admission.py --self-test
	python3 scripts/check-frame-admission-log.py --self-test
	cargo test --workspace --exclude absd-user --features frame-admission-v0
	cargo run --example frame_vm_qualification --features frame-admission-v0
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --features frame-admission-v0 -- -D warnings
	@mkdir -p build/frame-v0
	@if cargo check --lib --features frame-admission-v0,frame-reservation-experiment >build/frame-v0/mixed.log 2>&1; then echo 'test: mixed supported/private configuration accepted' >&2; exit 1; fi
	@grep -q 'supported frame admission cannot include private dispatch' build/frame-v0/mixed.log
	@if RUSTFLAGS='--cfg absd_mutant_frame_authority' cargo test --lib --features frame-admission-v0 frame_admission::tests::ready_is_bound_incremental_and_irreversible >build/frame-v0/authority-mutant.log 2>&1; then echo 'test: ungated authority mutant survived' >&2; exit 1; fi
	@grep -q 'test frame_admission::tests::ready_is_bound_incremental_and_irreversible ... FAILED' build/frame-v0/authority-mutant.log
	@echo 'FRAME ADMISSION HOST OK (guest gates remain separate)'
.PHONY: usb-keyboard-recovery-test
usb-keyboard-recovery-test: usb-keyboard-iso
	python3 scripts/usb-keyboard-recovery-test.py "$(QEMU)"
