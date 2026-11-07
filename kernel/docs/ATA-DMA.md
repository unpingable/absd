# QEMU PIIX3 ATA DMA (#74)

This correction replaces repeated PIO data-port transfers with one bus-master
transfer for an explicitly supported emulator configuration. It does not change
block deadlines, workload limits, disk layout, backend selection, or flush policy.
Physical IDE hardware remains unqualified.

Admission requires a virtual CPU, the exact ATA model `QEMU HARDDISK` with all
remaining model words space padded, DMA capability, valid UDMA mode information
with one supported mode selected, PCI 8086:7010, class/prog-if 01:01:80, primary
channel enabled, and an assigned 16-byte-aligned BAR4 I/O address below 64 KiB.
Nonmatching devices retain the original PIO path. Active inherited bus-master
commands or conflicting PCI ownership fail probe rather than borrowing ownership.
Both channels must be idle before claiming the function; only primary master is
used. Firmware BAR assignments are retained.

The exact Intel register contract is in [82371FB/82371SB datasheet 290550-002,
sections 2.7 and 3.5.2.2](https://www.mouser.com/catalog/specsheets/intel%20corporation_29055002.pdf).
The implementation is written from that specification and existing kernel PCI
and NVMe ownership patterns; no external source was copied or adapted.

QEMU is the scope of the timing decision. Its [PIIX3 implementation](https://github.com/qemu/qemu/blob/v8.2.2/hw/ide/piix.c)
registers compatibility ports and BAR4; it does not drive physical IDE timing.
Its [ATA model](https://github.com/qemu/qemu/blob/v8.2.2/hw/ide/core.c) advertises
UDMA5 selected even for PIIX3 and accepts DMA commands through the emulated block
backend. We validate a selected supported advertised mode rather than programming
physical PIIX timing registers or claiming that the DMA support bit alone proves
physical transfer setup. The model/virtualization gates intentionally exclude
ordinary physical disks. A future physical driver needs its own mode negotiation
and controller timing qualification.

The BSP device lock serializes requests. Two static identity-mapped, 4 KiB aligned
kernel pages hold the bounce buffer and one EOT PRD. Both have addresses below
4 GiB; the data transfer is 1–8 sectors, even aligned and cannot cross a 64 KiB
boundary. The PRDT page cannot cross that boundary either. No user address reaches
the device. Sequentially consistent fences order CPU writes before command/start
and completion before CPU reads. The pages remain allocated for the entire boot.

Each request clears old BM error/interrupt bits while retaining capability bits,
programs the PRDT and direction, issues READ DMA C8 or WRITE DMA CA, then starts
BM. Success requires interrupt set, active/error clear, and ATA BSY/DRQ/ERR/DF
clear. Existing POLL_LIMIT bounds the wait. Every exit clears Start and checks
inactive. Any DMA error or timeout disables PCI bus mastering and permanently
poisons the backend: no fallback retry, later buffer reuse, or caller copy of a
partial read. Even if hardware fails to stop, these static pages remain quarantined.
Writes retain the existing whole-command success/error API: an error may leave
leading sectors written, with no exact partial count promised.

QEMU's `ide_dma_cb` reports completion after asynchronous block I/O callbacks;
`ide_flush_cache` uses `blk_aio_flush` and `ide_flush_cb` reports its outcome.
WRITE DMA acknowledgement is a completed backend write, not stable storage by
itself. The original FLUSH CACHE E7 path remains the durability boundary; no
new FUA or host-power-loss claim is made. QEMU error policies that stop/retry the
backend cannot turn an uncompleted guest command into success.

## Validation and limits

The admission log prints observed PCI function/ID, BAR4 and IDENTIFY word88;
once-per-direction first-complete markers distinguish selection from successful
DMA completion. Existing block request counters remain unchanged.

Host controls exercise exact admission, selected-mode refusal, address/count and
64 KiB/4 GiB boundaries, and every BM/ATA completion error bit. `python3 scripts/test-ata-dma.py` additionally runs the actual driver against
inert port/PCI stubs: successful read publication, BM error, ATA error, timeout,
active after stop, permanent poison, no later DMA, and no partial-read copy.
Only the privileged OUTL body is substituted in a temporary copy; the kernel
source is unchanged. The host fixture links below 4 GiB to respect the actual
address guard (an initial PIE fixture correctly failed that guard).
A full `make build` also passes. The bounded QEMU runtime evidence for kernel
`4bc8009701bfd0ddfde1b27851593aaad9aa906f` was independently accepted for
integration on 2026-10-25; that correction is included in development `latest`.
The KVM constructor recorded exact PIIX3 admission at BAR4 `0xc040`, both DMA
completion directions, zero block errors, 447 flushes, successful workload and
boot markers, and QEMU status 3. Host readback checked all 85 expected entries
and rejected unlisted import paths.

With the unchanged 120000-tick guest deadline, that constructor completed in
22953 ticks. The retained PIO diagnostic failed at 120545 ticks; its failure is
unchanged. These are individual observations, not a general speed factor. The
comparison input was newly constructed, not recovered historical bytes.

A separate TCG block probe passed exact output and disk-content checks with both
DMA direction markers. Setting `ide-hd.model=ABSD-PIO-CONTROL` exercised the
nonmatching-model PIO fallback: the same probe passed without DMA markers.
Reader-authority controls demonstrated write/flush refusal and refusal with a
live descendant. Five canonical KVM ATA writable-entry cases were separately
accepted before adoption. Error/timeout and failed-stop behavior is covered by
the host driver controls above, not by injected runtime device failures.

Physical-target read-only compilation passed; physical I/O was not executed.
This evidence establishes neither reset-time command retirement nor an
end-to-end or power-loss fence. It does not qualify physical IDE hardware,
arbitrary PIO devices, or an entire release.

Formalization consideration: the durable claim is that CPU buffer reuse follows
successful inactive completion, or is permanently prohibited after failure. The
single BSP request, static pages, exact completion predicate, and permanent poison
make this bounded enough for host boundary tests and source review here. Those
tests do not establish device quiescence on physical hardware or prove the QEMU
implementation. Other configurations need separate runtime qualification; no
wider storage ownership model is introduced.
