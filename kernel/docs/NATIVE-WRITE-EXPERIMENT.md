# Native write experiment (plan only)

The first time an ABSD kernel writes a physical disk. This document fixes
the safety conditions in advance; it builds nothing. No write-enabled
physical ISO exists, and none may be built until every precondition below
holds and the operator has named the sacrificial device. The QEMU-only
write ISOs (`make nvme-test`, `make laptop-test`) are test artifacts: they
name QEMU's controller serial `absd` and must never be written to a USB
stick.

## Preconditions

1. The read-only first boot (docs/PHYSICAL-BOOT-PACKAGE.md) has been run on
   the target machine with its record complete: `ABSD BOOT OK`, the timer
   and preemption markers, and the `NVME CONTROLLER` and `NVME NAMESPACE`
   lines photographed. A machine that failed the timer probe does not get
   a write experiment until the timer question is settled.
2. A **sacrificial NVMe device** holds nothing of value, is physically
   distinct from the machine's own disk, and has been seen by that
   read-only boot. The operator chooses it; this document does not.
   Preferred: a spare M.2 NVMe drive fitted as the *only* NVMe device, so
   the machine's own disk is not even present during the experiment. If
   the machine has one M.2 slot, the internal disk is removed for the
   duration and set aside; there is no configuration in which the
   experiment runs with the machine's own disk installed and the operator
   "is careful".
3. The device's namespace uses 512-byte LBAs (`lba_bytes=512` on the
   read-only boot). A device that reports `NVME UNAVAILABLE
   Refused(LbaFormat { lba_bytes: 4096, ... })` is not usable: the kernel
   supports only 512-byte formats and the experiment does not reformat.
4. The device has at least 16384 sectors (8 MiB); any real device does.

## Identification: what the operator records before any write

From the read-only boot's photo, copy exactly:

| Field | Source line | Example (QEMU) |
|---|---|---|
| Controller serial | `NVME CONTROLLER ... serial=S` | `laptop-witness` |
| Model | `NVME CONTROLLER ... model=M` | `QEMU NVMe Ctrl` |
| PCI location | `NVME CONTROLLER pci=BB:DD.F` | `00:03.0` |
| Vendor / device IDs | `vendor=VVVV device=DDDD` | `1b36` / `0010` |
| Namespace sectors | `NVME NAMESPACE nsid=1 lba_bytes=512 sectors=N` | `4096` |
| LBA 0 fingerprint | `NVME READ OK lba=0 fnv1a=0x...` | `0x2ad8...` |

The serial is the NVMe Identify Controller SN field with trailing spaces
removed (at most 20 ASCII characters); non-printable bytes show as `?`, and
a serial containing `?` or spaces is not usable as a gate and disqualifies
the device. Cross-check the serial and capacity against the drive's label
or, on another machine, `nvme id-ctrl` / `nvme id-ns` output: all must
agree before the write ISO is built.

## The write gate the experiment ISO must enforce

The experiment needs a separate build and new kernel code; neither exists
yet. Required properties, each to be demonstrated under QEMU first:

1. **Separate build, separate artifact.** A cargo feature
   (`native-write-experiment`) that the physical ISO never enables; its ISO
   has a different name (`absd-native-write-<serial>.iso`) and a GRUB menu
   whose only entry is the experiment. The read-only physical ISO and its
   gate (`make physical-iso-gate`) are unchanged.
2. **Three-part exact gate, all on the command line, all compared
   byte-exact against Identify data:** `nvme-write=<serial>`,
   `nvme-write-sectors=<N>` (namespace size), and
   `nvme-write-model=<model with spaces as '_'>`. Any mismatch, missing
   part, empty value, or a second NVMe controller present: the namespace
   stays read-only and the boot prints `NATIVE WRITE REFUSED reason=...`
   and halts with code 1. The current kernel's `nvme-write=SERIAL` gate
   alone is not sufficient for physical media.
3. **Capacity and model shown before any write, with time to abort.** The
   boot prints the `NVME CONTROLLER`, `NVME NAMESPACE`, and a line
   `NATIVE WRITE TARGET serial=S model=M sectors=N lbas=A..B` and then
   counts down 30 seconds on screen (`NATIVE WRITE IN 30`, one line per 5
   seconds, driven by the PIT) before the first write command. Pulling the
   power or the USB stick during the countdown aborts with nothing
   written. The countdown uses the timer the read-only boot proved.
4. **No partition-table interpretation.** The kernel never reads or
   parses MBR, GPT, or any filesystem. It addresses raw namespace LBAs
   only, and the range below is fixed in the source, not derived from
   anything on the disk.
5. **Exact destructive range: LBAs 8192 through 8255 inclusive** (64
   sectors, 32 KiB, byte offsets 4,194,304 to 4,227,071). Nothing outside
   that range is written, and the source asserts the range at compile
   time. It lies after the primary GPT (LBAs 0-33) and before any
   plausible backup GPT, so a sacrificial disk's partition table is left
   intact and the damage is small and exactly known; this is a courtesy,
   not a safety argument, since the device is sacrificial by precondition.
6. **Pre-image read.** Before writing, the boot reads all 64 sectors and
   prints `NATIVE WRITE PREIMAGE fnv1a=0x... zero=Z/64` (FNV-1a over the
   32 KiB, and how many sectors were all zero).
7. **Data pattern.** Sector at LBA L (8192 <= L <= 8255) is 512 bytes:
   bytes 0-15 ASCII `ABSD NATIVE WRX `, bytes 16-23 L as u64 little-endian,
   bytes 24-31 the run id (a 64-bit value given as
   `nvme-write-run=<16 hex digits>`, chosen fresh by the operator for each
   attempt), bytes 32-511 the xorshift64 stream seeded with
   `run_id ^ (L * 0x9E3779B97F4A7C15)` (seed 0 replaced by 1), each 64-bit
   state emitted little-endian. The host can recompute every byte from L
   and the run id.
8. **Writes, one command per sector,** through the existing polled path,
   in ascending LBA order; each completion status checked; the first error
   stops the experiment (`NATIVE WRITE FAILED lba=L status=0x...`), no
   retries.
9. **Flush.** One NVMe FLUSH after the last write, always issued (the
   `vwc=` bit is printed, not trusted to skip it). `NATIVE WRITE FLUSH OK`
   or `NATIVE WRITE FLUSH FAILED status=...`.
10. **Read-back verification in the same boot.** All 64 sectors read back
    after the flush and compared byte-for-byte against the pattern:
    `NATIVE WRITE READBACK OK lbas=64 fnv1a=0x...` or `... MISMATCH lba=L
    offset=O`. Nothing else is written, then or later in that boot; the
    kernel halts (`ABSD HALT code=0`) without starting init.
11. **Re-read after a cold reboot.** The operator powers the machine off
    (not a warm reset), waits 10 seconds, and boots a *read-only* verify
    entry (block-read-only build, same run id on its command line) that
    reads the 64 sectors, recomputes the pattern, and prints
    `NATIVE WRITE PERSISTED OK lbas=64 fnv1a=0x...` (same hash as the
    readback line) or the first mismatch. A second verify after a longer
    power-off (overnight) is optional evidence.

## QEMU rehearsal before the physical run

The experiment ISO is qualified the same way as everything else:
`make laptop-test`-style boots on the `thinkpad` profile with a scratch
image whose NVMe serial, model, and size are set to the operator's device
values (`-device nvme,serial=...`; QEMU's model string is fixed, so the
rehearsal uses a model override build or a documented exception). Required
before the physical run: each gate mismatch refused with the image hash
unchanged; the countdown visible; the host confirming that bytes outside
LBAs 8192-8255 are unchanged and inside them equal the pattern; the verify
entry passing after a fresh QEMU process; and a QEMU device trace
(`-trace pci_nvme_io_cmd`) showing exactly 64 writes, one flush, and no
other write-class command.

## Physical run

1. Machine powered off; only the sacrificial NVMe device installed.
2. Boot the experiment USB stick; photograph the countdown screen and
   check serial, model, and sector count against the record *before the
   countdown ends*. Any difference: pull the power.
3. Let it run; photograph the final screen (`READBACK OK`, `HALT code=0`).
4. Power off for at least 10 seconds; boot the verify entry; photograph
   `NATIVE WRITE PERSISTED OK`.
5. Optionally, on another machine, read the 64 sectors
   (`dd if=/dev/nvmeXn1 bs=512 skip=8192 count=64`, read-only) and compare
   with the host's recomputation.

## Stop conditions

Stop and record, never retry on the spot: any `REFUSED`, `FAILED`, or
`MISMATCH` line; a countdown that shows a device other than the one
recorded; a hang with no new line for more than a minute; any `KERNEL
FAULT` or `ABSD PANIC`. A write that reports success but fails the cold
re-read is the most important possible result and is recorded as such.

## Rollback

The device is sacrificial; nothing on it is restored. Remove the USB
stick, reinstall the machine's own disk if it was removed, and confirm the
machine boots its usual system. To return the sacrificial device to use,
wipe it on another machine.
