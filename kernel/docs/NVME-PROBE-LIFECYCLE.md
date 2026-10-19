# NVMe probe refusal and DMA

The probe clears PCI bus mastering before its first controller register access.
If inherited CC.EN is set, it waits for RDY=1 within the selected readiness
mode's limit, checks RDY again, then clears EN. A timeout or fatal status
refuses without clearing EN. If EN was already clear, it waits for RDY=0
without another CC write. Only after RDY=0 does it initialize the static
queue pages and queue registers. It enables bus mastering immediately before
CC.EN=1. Refusal before enable leaves bus mastering off and retains the claim.

Every explicit initialization error after that enable is captured by one
`Result` boundary. Before returning the original error to the block layer,
which may try ATA, cleanup requests CC.EN=0 and waits bounded for RDY=0 when
RDY was observed set. It clears bus mastering even if that wait fails. No
controller is published on error. The cleanup diagnostic reports whether stop
was confirmed, the initial raw CSTS and requested/skipped branch, and reads back
the PCI bus-master bit.

If RDY is already zero on cleanup, EN=1 may mean enable is still in progress.
NVMe 2.0c's CC.EN definition makes clearing EN in that state undefined. Cleanup
therefore clears bus mastering and reports stop unconfirmed without that write.
The initial firmware-reset path also avoids clearing EN during an observed
enable transition; actual firmware transition behavior remains physical
qualification work.

Readiness waits use CAP.TO in 500 ms units, with a 500 ms minimum. On NVMe 2.0
or later with CAP.CRMS with-media support, the driver also reads CRTO. The
with-media limit is at least CRWMT and CAP.TO; the inherited independent-mode
limit is at least CRIMT and CAP.TO when that mode is supported. Unsupported
or legacy CRTO fields are not read. A contradictory report with CRIMT larger
than CRWMT also raises the with-media bound. The new configuration selects
with-media readiness (CC.CRIME=0); cleanup uses that conservative bound.
The legacy maximum is 127,500 timer ticks. A full 16-bit CRTO field can extend
the limit to 32,767,500 ticks (about 9.1 hours). Timeout is observed on a later
poll. Every bound requires advancing PIT ticks and is not a wall-time guarantee.
Waits exceeding the legacy maximum print their target, advancing elapsed ticks,
reported bound and raw CSTS every 30,000 ticks. An inherited-enable timeout
has its own label. These diagnostics do not shorten a compliant device's bound
or guarantee operator receipt when serial output is unavailable.
No physical maximum-time claim follows from the QEMU run.

A successful probe publishes only its private NVMe controller; the block
backend is published after its proving sector read. If that read fails, the
driver takes the controller out of the global slot, requests bounded stop when
RDY is set, and clears bus mastering regardless of stop confirmation. The
original read error then reaches the existing fatal boot path. It does not
fall through to ATA. Subsequent NVMe calls observe no controller. No live
replacement or reuse is attempted.

Success adds no cleanup I/O or allocation. Refusal adds a status read, a possible reset/wait, a PCI command
read/modify/write, a diagnostic readback and a serial diagnostic. The existing
static queue/identify buffers remain dedicated for the boot and the PCI claim
is retained. They are never returned to a general allocator on refusal.

Clearing bus mastering prevents new bus-master requests under the controller
contract. It does not cancel requests or guest-memory mappings already held by
a device/backend, prove physical transaction retirement, or fence a backend
that writes after reporting failure. A confirmed controller stop is narrower
than safe live kernel generation transfer. Such transfer still needs a proven
device drain, buffer lifetime, outside successor validation and explicit
refusal before old-generation memory is reused; rollback is not inferred.

The host source guard checks the actual enable order, inherited-ready wait,
gated CRTO read, captured error boundary, withdrawal and cleanup sequence,
with independent substitutions of those source sites (30 negative controls).
Both the new-enable limit and the limit retained for withdrawal are pinned
to the with-media calculation.
Its publication check recognizes the tested direct and clone spellings;
arbitrary helper rewrites still require source review.
It is text-bound and fails closed on many harmless rewrites. It does not prove
hardware behavior or all possible helper substitutions. Native and physical
qualification must be attributed to the exact source revision exercised.

`nvme_ready` host vectors cover the four EN/RDY combinations, version/mode
gating, larger modern timeouts, contradictory fields and maximum encodings.
`make nvme-first-read-test` uses QEMU blkdebug to fail a real backing-image
read after successful Identify, both alone and with an available ATA disk.
It requires a failed NVMe read completion, confirmed stop, PCI BME readback
off, withdrawal, then the original block error and refusal exit. Neither
scratch disk may change. Eight independent output/exit substitutions must be
rejected. This does not produce inherited EN=1/RDY=0 or delayed CRTO readiness.

Formalization consideration: the durable propositions are that this source
clears inherited EN only after successful ready observation, and that the
explicit proving-read error path unpublishes and reaches DMA disable before
returning its original error. The pure four-state rule, timeout vectors,
source substitutions and actual error completion are sufficient for this
bounded change; no separate hardware model is claimed. MMIO observations
must correspond to the device, configuration has no concurrent writer,
PCI BME semantics and advancing timer interrupts are assumptions. Invariant
panics remain outside the explicit Result cleanup boundary. Exact source
and run identities accompany the lane receipt; independent Opus review and
the integration steward own acceptance. A future hardware model must cover
pending transactions and quiescence before generation retirement, not infer
them from these tests. The private Controller field is not a state-transfer
schema or an authority reconstruction rule.

Specification: [NVMe Base 2.0c](https://www.nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0c-2022.10.04-Ratified.pdf),
CAP.CRMS/TO, CC.EN/CRIME and CRTO definitions, §3.5 controller initialization
and §3.7.2 controller reset.
The fault fixture follows [QEMU's blkdebug interface](https://www.qemu.org/docs/master/devel/testing/blkdebug.html);
no third-party implementation code is incorporated.
