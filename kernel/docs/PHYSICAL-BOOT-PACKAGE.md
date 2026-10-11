# Physical boot package

Everything an operator needs to take ABSD to a ThinkPad for the first time,
and everything the evidence must look like. It extends
docs/PHYSICAL-BOOT.md (the checklist) with exact pins, the exact screen, a
failure table, and the media instructions. **Nothing here has been run on
physical hardware.** All of it has been rehearsed under QEMU only, on a
laptop-shaped machine; that is not physical equivalence.

**The first physical boot is read-only, by construction.** The ISO's
kernel is built with the `block-read-only` cargo feature: no block write,
flush, or any NVMe command other than Identify, Create I/O queue, and Read
can be submitted to any device, and no boot option, including
`nvme-write=<the disk's exact serial>`, changes that. `make
physical-iso-gate` proves it on the ISO file itself (below).

## Pins

| Item | Value |
|---|---|
| Kernel source commit | `ac4322b` (served boots, machine authority, session control); the commit that records these pins changes documentation only |
| Kernel build | `cargo rustc --bin absd-kernel --features block-read-only` (dev profile: opt-level 2 with debug assertions and overflow checks), flags as in the Makefile's `physical-build` |
| Kernel ELF SHA-256 | `450665ba538ed9da780560753754df11558030a0ec995b06779d4ce62f2bb0ae` |
| ISO file | `physical/absd-physical-073467abffe2.iso` (read-only copy of the `make physical-iso-gate` output, kept outside every worktree), 15366144 bytes |
| ISO SHA-256 | `073467abffe2f01a06b817be460c1e729441c70fe52c110fa1f3326daac9b30f` |
| Toolchain | `rustc 1.98.0 (88d9e12ae 2026-08-18)`; `cargo 1.98.0 (797e8a9bc 2026-08-05)` |
| ISO tool | `grub-mkrescue (GRUB) 2.12-1ubuntu7.3` (targets `i386-pc` and `x86_64-efi`), xorriso 1.5.6 |
| QEMU used for rehearsal | `QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)`; OVMF from `/usr/share/OVMF/OVMF_CODE_4M.fd` (Ubuntu `ovmf` package) |

`grub-mkrescue` output is not byte-reproducible (timestamps, UUIDs), so a
rebuild from the same commit gives a different ISO digest; the kernel ELF
inside is reproducible for a given toolchain and tree. **Write the file
whose digest is above, not a rebuild.** Before writing, check both:

```sh
iso=physical/absd-physical-073467abffe2.iso
sha256sum "$iso"                           # must equal the ISO SHA-256 above
xorriso -osirrox on -indev "$iso" -extract /boot/absd-kernel /tmp/absd-kernel.check
sha256sum /tmp/absd-kernel.check           # must equal the kernel SHA-256 above
sh scripts/physical-iso-gate.sh "$iso" build/physical/target/debug/absd-kernel  # no rebuild
```

`make physical-iso-gate` rebuilds the ISO (so does `make laptop-test`),
which is why the tested file is kept as a copy: the pinned file is the one
the gate printed as `PHYSICAL ISO GATE OK iso_sha256=073467ab...`, and
`scripts/laptop-test.sh` was then run on that same copy.

### Survey artifact (physical-survey-v1)

A second, separately pinned artifact for the first boot of a new machine:
the same `block-read-only` kernel source line, default GRUB entry `survey
halt-on-exit` (identity by reads only; no storage or network controller is
started). Its pins, screen, and operator steps are in
docs/hardware/HP-Z2-MINI-G3-FIRST-BOOT.md. The rows above are the
milestone's and are unchanged by it.

| Item | Value |
|---|---|
| Kernel source commit | `913d338` |
| Kernel ELF SHA-256 | `875b7969e4fc740e69938ce3f8d7d945217e9e0c4e359c134a33ffaf2ad7a15f` |
| ISO file | `physical/absd-physical-survey-v1-9773e8b64ffe.iso`, 15769600 bytes |
| ISO SHA-256 | `9773e8b64ffeb97c22c3df9cbb58d83c86645894efc264854ca77d5844575e5d` |
| Gates | `make survey-gate`: `SURVEY GATE OK` and `PHYSICAL ISO GATE OK` for that digest |

## The safety gate

`make physical-iso-gate` (scripts/physical-iso-gate.sh) runs
`physical-iso-test` (SeaBIOS and OVMF boots of the exact ISO, whole screen
matched against serial, patterned NVMe image unchanged), then:

1. Extracts `/boot/absd-kernel` and `grub.cfg` from the ISO file and
   requires the kernel to be byte-identical to the `block-read-only` build
   and to contain the `BLOCK WRITES DISABLED: read-only build` banner; no
   GRUB entry may mention `nvme-write`, and every entry must carry
   `halt-on-exit`.
2. Boots that same kernel with write-requesting command lines,
   `nvme-qualify-write nvme-write=absd` and `block-probe nvme-write=absd`,
   against scratch images on an NVMe controller whose serial *is* `absd`,
   and `block-probe` against an ATA disk, with QEMU's own device traces on.
   Each must print `NVME WRITE OPTION IGNORED: read-only build`, identify
   the device read-only, leave the image byte-identical, and the traces
   must show only NVMe Read I/O commands, only Identify/Create CQ/Create SQ
   admin commands, and only IDENTIFY/READ (plus the CD-ROM's PACKET) ATA
   commands.
3. Prints `PHYSICAL ISO GATE OK iso_sha256=... kernel_sha256=...`.

As a negative control, the same boots with the ordinary (writable) kernel
fail the gate at the first boot (`image changed`; the trace shows 5 NVMe
writes and a flush).

## Boot menu

GRUB 2.12, `insmod all_video`, 10 second countdown, entries:

1. `ABSD physical probe: boot suite, disks read-only` (default):
   `multiboot2 /boot/absd-kernel suite halt-on-exit`
2. `ABSD kernel fault postmortem`:
   `multiboot2 /boot/absd-kernel kernel-fault-test halt-on-exit`

On UEFI the menu is drawn by GRUB on the firmware's text console; firmware
may first print lines such as `BdsDxe: loading Boot000N "USB ..."`. On
legacy BIOS it is the VGA text menu. Do not edit the entries on the first
boot. Pressing `e` and adding `nvme-write=...` would do nothing to the
disk (the gate above), but it is still not part of the plan.

## Secure Boot

Must be **disabled** in firmware setup (ThinkPad: F1 at power-on,
Security > Secure Boot > Disabled). The `BOOTX64.EFI` that `grub-mkrescue`
builds is unsigned; with Secure Boot on, the firmware refuses it (a
"Secure Boot violation" / "image failed to load" message, or the USB entry
missing from F12). Note the setting's original value and restore it
afterwards. Do not enroll keys or change the TPM.

## Expected screen, default entry

Light grey on dark blue, 8x13 font; failure lines white on red. The kernel
asks GRUB for 1024x768x32; whatever mode GRUB sets, the console has
`columns = width / 8` and `rows = min(height / 13, 256)` (both halved at
widths of 1600 or more, where each font pixel is drawn 2x2). The console is
a ring: after `rows - 1` lines it wraps to the top, and the blank row marks
the newest line. The default boot prints about 1140 lines, so only the
beginning (photograph it as it appears) and the last screen persist.

Lines in order. `<...>` varies per machine; everything else is exact.

```text
ABSD KERNEL BOOT
boot protocol: multiboot2
multiboot info: 0x<16 hex digits>
multiboot bytes: 0x<16 hex digits>
FRAMEBUFFER PROBE !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
FRAMEBUFFER CONSOLE OK width=<W> height=<H> pitch=<P> bpp=<24|32> rgb=<shift:bits,...> columns=<C> rows=<R> scale=<1|2> probe_row=4 cells=112 address=0x<16 hex>
IDT BREAKPOINT OK
usable memory regions: 0x<16 hex>
free frames: <N>
allocated frame 0: 0x<16 hex>
allocated frame 1: 0x<16 hex>
FRAME OWNER CHECK OK
paging probe pml4 index: 0x0000000000000100
paging entry frame: 0x<16 hex>
PAGE MAP OK
TIMER OK ticks=<N, at least 5; 5 in every QEMU run>
HEAP OK
BLOCK WRITES DISABLED: read-only build
NVME CONTROLLER pci=<BB:DD.F> vendor=<VVVV> device=<DDDD> version=<8 hex> vwc=<0|1> serial=<SN> model=<MN>
NVME NAMESPACE nsid=<N> lba_bytes=512 sectors=<N> access=read-only
NVME READ OK lba=0 fnv1a=0x<16 hex>
BLOCK DEVICE OK sectors=<N>
BLOCK BACKEND nvme access=read-only
SPAWN OK pid=1 parent=0 program=init
SPAWN EXHAUSTION frames_per_process=37
SPAWN EXHAUSTION OK
SPAWN OK pid=1 parent=0 program=init
PROCESS MODEL OK
USER INIT STARTED
init: spawning demonstration programs
SPAWN OK pid=2 parent=1 program=hello-a
USER PREEMPT pid=1 -> pid=2
USER PREEMPT pid=2 -> pid=1
... (the process suite; HANDOFF.md, "Serial success markers") ...
```

and the last screen ends:

```text
USER EXIT pid=1 status=0
FRAMES baseline=0 peak=<N> final=0 spawns=<N> reaps=<N> ... sleeps=<N> timeouts=13 idle=<N, nonzero> ticks=<N, nonzero> kstack_peak=<N>/32768
STACK GROW pages=1031
COUNTERS exits=<N> faults=<N> kills=<N> preempts=<N> writes=<N> refused unknown=<N> pointer=<N> handle=<N> wait=<N> spawn=<N> map=<N> init=0
OBJECT TABLES EMPTY OK
SYSCALL ABI OK
USER MEMORY VALIDATION OK
PROCESS HANDLE ISOLATION OK
PROCESS EXIT OK
PROCESS FAULT ISOLATION OK
USER PREEMPTION OK
SPAWN OK
SPAWN BOUNDED OK
REAP OK
PROCESS RECLAIM OK
PROCESS STRESS OK
USER PROCESSES OK
USER SCHEDULER OK
ABSD BOOT OK
ABSD HALT code=0
```

The `FRAMES` and `COUNTERS` lines are longer than 128 columns and wrap
onto a second row. `USER FAULT ...` lines in the middle are the suite's
deliberate, isolated user faults, not failures.

The postmortem entry instead ends with `KERNEL FAULT TEST`, a red
`KERNEL FAULT vector=14 error=0x... rip=0x... cr2=0x0000400000000000`, and
a red `ABSD HALT code=2`.

## Timer markers

The kernel drives only the legacy 8254 PIT (channel 0, ~1000 Hz) through
the 8259 PIC (IRQ0 unmasked, vector 32); no LAPIC or IOAPIC.

| Marker | Meaning |
|---|---|
| `TIMER OK ticks=N` (N >= 5) | PIT interrupts arrive through the 8259 while the boot spins against a TSC bound of 2^34 cycles |
| `USER PREEMPT pid=X -> pid=Y` (several) | the timer preempted ring-3 code |
| `init: timed waits verified` | timeouts fire on schedule |
| `FRAMES ... timeouts=13 idle=<nonzero> ticks=<nonzero>` | all 13 timed waits expired, the idle loop halted waiting for interrupts |
| `USER PREEMPTION OK`, `USER SCHEDULER OK` | the kernel's own checks of the above |

## NVMe identify output

`NVME CONTROLLER` is printed from Identify Controller and the PCI function;
`NVME NAMESPACE` from Identify Namespace for the first active namespace.

| Field | Source | Varies per device? |
|---|---|---|
| `pci=BB:DD.F` | first NVMe function in bus/device/function order | yes |
| `vendor=` `device=` | PCI configuration space IDs, 4 hex digits | yes |
| `version=` | controller VS register, 8 hex digits (`00010400` = 1.4.0) | yes |
| `vwc=` | Identify Controller VWC bit 0: volatile write cache present | yes |
| `serial=` | SN (20 bytes), trailing spaces trimmed, non-printables as `?` | yes, unique per device |
| `model=` | MN (40 bytes), trimmed likewise | yes |
| `nsid=` | first active namespace ID (normally 1) | rarely |
| `lba_bytes=512` | always 512: any other format is refused (below) | fixed |
| `sectors=` | NSZE of the namespace, in 512-byte sectors | yes |
| `access=read-only` | always, in this build | fixed |
| `NVME READ OK lba=0 fnv1a=` | FNV-1a 64 of LBA 0 (the disk's MBR/protective MBR) | yes |

With more than one NVMe controller only the first is used. Photograph
these lines: they are the identification record the future write
experiment needs (docs/NATIVE-WRITE-EXPERIMENT.md).

## Read-only and refusal lines

- `BLOCK WRITES DISABLED: read-only build` always appears after `HEAP OK`.
- `NVME WRITE OPTION IGNORED: read-only build` appears only if someone
  added `nvme-write=` to the command line; the namespace stays
  `access=read-only`.
- `NVME NAMESPACE ... access=read-only` and `BLOCK BACKEND nvme
  access=read-only` are the only possible forms in this build. An ATA disk
  (a machine in legacy IDE mode) would show `BLOCK BACKEND ata
  access=read-only`.
- The default entry runs the process suite, which never receives a block
  handle; the only data command sent to the disk is the one read of LBA 0.

## Failure and postmortem table

"Halt" means the screen stays with `ABSD HALT code=N` last; code 1 is a
failed check, code 2 a kernel CPU exception.

| What the screen shows last | Stop point and meaning | Record |
|---|---|---|
| Firmware says the image failed to load / Secure Boot violation; USB missing from F12 | Secure Boot still on, USB boot disabled, or the stick is bad | firmware settings, message photo |
| GRUB menu never appears, legacy boot only | stick not written as a raw image; try UEFI entry | |
| GRUB `error: no suitable video mode found` | GRUB found no 24/32-bit direct-colour mode (seen in QEMU only for ISOs without `insmod all_video`; the physical ISO has it) | GRUB `videoinfo` from its command line (`c`) |
| GRUB text stays, kernel prints nothing | the kernel runs blind: no usable framebuffer (`framebuffer: unavailable NoTag/NotDirectColor/Geometry/Map(...)` goes to the absent serial port only). QEMU reproduces this with `ramfb`, whose framebuffer sits in RAM below 1 GiB: `Map(InFirstGigabyte)` | GRUB `videoinfo`; wait 2 minutes, it may still be running |
| `FRAMEBUFFER CONSOLE FAILED column=C row=R` | pixel read-back disagrees with what was drawn: pixel format or write-combining problem | photo, `rgb=` fields |
| `IDT TEST FAILED`, `memory-map: ...`, `FRAME ... FAILED`, `PAGE MAP FAILED`, `HEAP FAILED` (halt 1) | early kernel self-checks: memory map or paging assumptions wrong on this firmware | photo |
| `TIMER FAILED ticks=0 (no PIT interrupts through the 8259 within the TSC bound)` (halt 1) | **hardware tripwire**: legacy PIT or 8259 absent, gated, or routed elsewhere. QEMU reproduces exactly this screen with `-machine pit=off` or `pic=off` | machine type, firmware version, UEFI/legacy, any "8254 clock gating" setting |
| `TIMER OK` then a stall before `USER PREEMPTION OK`, or `init: FAILED at ...` | timer unreliable after the probe (tripwire), or a timing-sensitive suite check | last screen photo, time waited |
| `NVME UNAVAILABLE Refused(LbaFormat { lba_bytes: 4096, ... })` | disk formatted with 4 KiB LBAs; boot continues with `block: no device` (reproduced in QEMU) | expected variance, record |
| `NVME UNAVAILABLE Refused(...)` / `Timeout("...")` | controller refused (no NVM command set, page size, no namespace, BAR/map) or timed out; boot continues without a disk | the exact text |
| `NVME READ FAILED lba=0 ...` then `BLOCK DEVICE FAILED: ...` (halt 1) | the one read failed | exact text |
| `block: no device` without any `NVME` line | no NVMe controller visible at PCI class 01/08/02 (VMD/RAID mode hides it: set storage to AHCI/NVMe in firmware if the option exists, or just record) | firmware storage mode |
| red `KERNEL FAULT vector=V error=... rip=... cr2=...` (halt 2) | kernel bug on this hardware | photo of the whole red line |
| red `ABSD PANIC: ...` (halt 1) | kernel assertion | photo |
| `USER PROCESS SUITE FAILED` (halt 1) | a suite check failed; the preceding lines say which | photo of the last screen |
| machine resets back to firmware/GRUB | triple fault (no `-no-reboot` on hardware) | how far it got |
| `ABSD BOOT OK` then `ABSD HALT code=0` | success | photos, then the record list in PHYSICAL-BOOT.md |

## Writing the USB stick (operator, later)

Not run by anyone yet. The stick is overwritten entirely; the machine's own
disk is never a target.

```sh
lsblk -o NAME,SIZE,MODEL,SERIAL,TRAN,RM     # before inserting the stick
# insert the stick
lsblk -o NAME,SIZE,MODEL,SERIAL,TRAN,RM     # the new row, TRAN=usb, RM=1, is the stick: /dev/sdX
sha256sum absd-physical.iso                  # equals the pinned ISO SHA-256
sudo umount /dev/sdX?* 2>/dev/null           # if the desktop auto-mounted it
sudo dd if=absd-physical.iso of=/dev/sdX bs=4M conv=fsync status=progress
sync
sudo cmp -n "$(stat -c %s absd-physical.iso)" absd-physical.iso /dev/sdX && echo stick verified
```

`/dev/sdX` is the whole device, not a partition, and must be the row that
appeared when the stick was inserted. If `lsblk` shows anything but a
removable USB device of the stick's size, stop.

## Rollback and removing the media

Nothing on the ThinkPad changes: the boot writes no disk, and the firmware
changes are Secure Boot (off) and the one-time F12 choice.

1. At `ABSD HALT`, hold the power button until the machine is off (the
   kernel halts with interrupts disabled; nothing needs flushing).
2. Remove the USB stick.
3. Firmware setup (F1): restore Secure Boot to its recorded value.
4. Power on normally and confirm the usual operating system boots.
5. The stick can be reused after wiping it (`sudo wipefs -a /dev/sdX` on
   the machine that wrote it, same `lsblk` identification as above).

## QEMU laptop profile (rehearsal, not equivalence)

`make laptop-test` (scripts/laptop-test.sh) boots on a synthetic
ThinkPad-shaped machine built by scripts/laptop-boot.py: `-nodefaults`,
q35, OVMF (pflash code and a private vars copy), the ISO as a USB stick on
xHCI, NVMe as the only disk, `-device VGA`, no serial port, no parallel
port, no debug-exit device. The host reads the console back from the
screen alone: it polls screendumps (once the kernel's first line shows,
the guest is paused for each one and run in slices short enough that
under a screen of rows scrolls between two; left running, bursts of
output outpaced the polling), decodes every cell against the X11 font,
merges screens by overlap into a transcript, counts gaps, and checks the
final screen pixel for pixel against that transcript. It prints, only when its checks pass:

- `FRAMEBUFFER ONLY BOOT OK`: the physical ISO's default entry, all ~1140
  lines recovered from the screen with no gaps, final screen exact.
- `NO SERIAL DEPENDENCY OK`: QEMU's device tree has no serial, parallel,
  or debug-exit device and no character device but the host monitor; the
  only disks are NVMe and the boot stick.
- `TIMER PREEMPTION OK`: the timer markers above, from the screen.
- `EFI NVME BOOT OK`: a (test-only, write-enabled) qualification kernel
  writes, flushes, and reads back five LBAs on NVMe under OVMF, then a fresh
  QEMU boot and a warm reset (HMP `system_reset`) each re-initialize the
  controller and verify the pattern read-only; the host checks the image.

`make laptop-matrix` varies one legacy assumption at a time; results are
recorded in HANDOFF.md, "Native hardware preparation".
