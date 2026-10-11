# First physical boot checklist

Preparation for booting ABSD on a ThinkPad. Nothing here has been run on
physical hardware; the ISO below has only been booted under QEMU (SeaBIOS
and OVMF) by `make physical-iso-test`, `make physical-iso-gate`, and the
laptop-shaped machine of `make laptop-test`. The pins, the exact expected
screen, the failure table, and the USB and rollback steps are in
docs/PHYSICAL-BOOT-PACKAGE.md. A new machine's first boot uses the
separate survey ISO instead (identity by reads only, no controller
started): docs/hardware/HP-Z2-MINI-G3-FIRST-BOOT.md; the second named
candidate, with its storage-safety rules, is a development record that is
not part of a source release.

## Artifact

`make physical-iso` writes `build/absd-physical.iso`, a hybrid BIOS+EFI
image made by `grub-mkrescue` (GRUB 2.12, `i386-pc` and `x86_64-efi`). It
prints the ISO and kernel SHA-256. `grub-mkrescue` output is not
byte-reproducible, so the recorded hash names the one tested file; write
that file, not a rebuild.

| Item | Value |
|---|---|
| Kernel commit | see docs/PHYSICAL-BOOT-PACKAGE.md, "Pins" |
| ISO SHA-256 | see docs/PHYSICAL-BOOT-PACKAGE.md, "Pins" |

GRUB menu (10 s timeout):

1. `ABSD physical probe: boot suite, disks read-only` (default):
   `multiboot2 /boot/absd-kernel suite halt-on-exit`
2. `ABSD kernel fault postmortem`:
   `multiboot2 /boot/absd-kernel kernel-fault-test halt-on-exit`

`halt-on-exit` makes the kernel halt with the last screen intact instead of
writing the QEMU debug-exit port (0xf4), which has no business on a real
machine.

## Rules

- **THE PHYSICAL ISO CANNOT WRITE A DISK.** Its kernel is the
  `block-read-only` build: the block layer, the ATA driver, and the NVMe
  submission path all refuse every write and flush, and the NVMe driver
  submits nothing but Identify, Create I/O Completion/Submission Queue,
  and Read, regardless of the command line. Even an edited GRUB entry
  with `nvme-write=<exact controller serial>` only prints `NVME WRITE
  OPTION IGNORED: read-only build` (`make physical-iso-gate`). The
  controller sees: reset and enable (CC.EN), Identify (controller, active
  namespace list, namespace), the two queue creations, and one Read of
  LBA 0. The default entry runs the process suite, which never receives a
  block handle. A disk write is a separate, later experiment with its own
  build (docs/NATIVE-WRITE-EXPERIMENT.md).
- **Secure Boot must be disabled by the operator** in firmware setup. The
  GRUB EFI image from `grub-mkrescue` is unsigned.
- Writing the ISO to a USB stick overwrites that stick; confirm the device
  name before `dd`. The ThinkPad's internal disk is never a target.
- Do not start physical testing from this document alone; it is the plan.

## Boot

1. Firmware setup: Secure Boot off. Record the machine type, firmware
   version, and any "8254 clock gating" or legacy/CSM setting shown.
2. One-time boot menu (F12 on ThinkPads): choose the USB stick. Either the
   UEFI or the legacy entry works; UEFI is the expected path.
3. Let the default entry boot. There is no serial port: the screen is the
   console. Film or photograph the whole boot, then the final screen.

## Expected screen

The console is a ring of text rows: when it fills it wraps to the top, and
the blank row marks where the newest line is. Screens 1600 pixels wide or
more draw every font pixel as 2x2. Failure text (`ABSD PANIC:`,
`KERNEL FAULT`, and a nonzero `ABSD HALT`) is white on red; everything else
is light grey on dark blue.

In order, for the default entry:

```text
ABSD KERNEL BOOT
FRAMEBUFFER PROBE !"#$%&'()*+,-./0123456789:;<=>?@ABC...xyz{|}~
FRAMEBUFFER CONSOLE OK width=W height=H pitch=P bpp=32 rgb=... columns=C rows=R scale=S probe_row=4 cells=112 address=0x...
IDT BREAKPOINT OK
PAGE MAP OK
TIMER OK ticks=N
HEAP OK
BLOCK WRITES DISABLED: read-only build
NVME CONTROLLER pci=BB:DD.F vendor=VVVV device=DDDD version=... vwc=0|1 serial=... model=...
NVME NAMESPACE nsid=1 lba_bytes=512 sectors=N access=read-only
NVME READ OK lba=0 fnv1a=0x...
BLOCK DEVICE OK sectors=N
BLOCK BACKEND nvme access=read-only
SPAWN EXHAUSTION OK
PROCESS MODEL OK
... the process suite (see HANDOFF.md, "Serial success markers") ...
USER PREEMPT pid=X -> pid=Y
USER PREEMPTION OK
USER SCHEDULER OK
ABSD BOOT OK
ABSD HALT code=0
```

`FRAMEBUFFER CONSOLE OK` means the kernel read back every pixel of the
probe line and found each glyph exact; the line itself proves the font and
pixel format are right on this machine. The postmortem entry instead ends
with `KERNEL FAULT TEST`, a red `KERNEL FAULT vector=14 ...
cr2=0x0000400000000000`, and a red `ABSD HALT code=2`.

Expected variances, to record rather than fix on the spot:

- The framebuffer size is whatever GRUB could set (the kernel asks for
  1024x768x32 and accepts any 24/32-bit direct-colour mode). Nothing after
  GRUB means no usable framebuffer; record GRUB's `videoinfo` from its
  command line.
- `NVME UNAVAILABLE Refused(LbaFormat { lba_bytes: 4096, ... })`: the disk
  is formatted with 4 KiB LBAs; the kernel continues without a block device.
  Other `NVME UNAVAILABLE` reasons name the refusal or timeout; the boot
  continues.
- With more than one NVMe controller, the first in PCI bus/device/function
  order is used.

## Physical timer and interrupt probe

The first boot must visibly establish three things. Today's kernel drives
the legacy 8254 PIT through the legacy 8259 PIC; it does not use the LAPIC
or IOAPIC.

1. **Timer ticks advance.** `TIMER OK ticks=N` with N at least 5. The boot
   waits for five PIT interrupts by spinning against a TSC bound of 2^34
   cycles (about five seconds at 3.4 GHz); if none arrive the screen shows
   `TIMER FAILED ticks=0 (no PIT interrupts through the 8259 within the TSC
   bound)` and a red `ABSD HALT code=1`.
2. **User scheduling and preemption occur.** At least one
   `USER PREEMPT pid=X -> pid=Y` line, then `USER PREEMPTION OK` and
   `USER SCHEDULER OK`. The `FRAMES ...` line's `ticks=` and `idle=` counts
   are nonzero, and `init: timed waits verified` shows timeouts fire.
3. **Required external interrupts arrive.** The default boot needs exactly
   one: IRQ0 (PIT) through the 8259. COM1's IRQ4 matters only for serial
   input (the ThinkPad has no COM1), IRQ14 only for ATA (absent), and NVMe
   is polled with INTx masked. Items 1 and 2 therefore establish it.

**Hardware tripwire.** If `TIMER FAILED` appears, if the boot stalls after
`TIMER OK` with timed waits never completing, or if `USER PREEMPTION OK`
never appears, record: "legacy PIT/8259 absent or unreliable on <machine
type, firmware version, boot path UEFI/legacy>", with the photo of the last
screen. That is the trigger to evaluate the LAPIC timer (calibrated against
the TSC or ACPI PM timer) and LAPIC/IOAPIC interrupt routing next. Do not
replace the PIT/PIC before that evidence exists.

## Record

Photos of the whole boot and final screen; machine type and firmware
version; UEFI or legacy boot; the `FRAMEBUFFER CONSOLE OK` line; the
`NVME ...` lines; `TIMER OK ticks=`; whether `ABSD BOOT OK` and
`ABSD HALT code=0` appeared; and anything that differs from this list.
