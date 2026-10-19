# Bounded native USB: stage 1 controller design

Tracked internally.
Owner request, 2026-10-15: begin this work. This first increment prepares the
stage 1 controller implementation. The runtime has passed host tests and
both architecture builds; guest qualification is in progress.
Stages 2 (one USB class), 3 (operational lifecycle), physical Z2 actions and
RK3568 integration require their own admissions.

## Source and existing behavior

Start from accepted kernel candidate `f8184ca`, rather than the older local
`main`. The candidate already includes enumeration `65796ce`, readiness
`5dc478a` / `55b7158` and hygiene `689ebd9`. The issue's statement that this
code is unmerged predates its composition into the accepted candidate. No
research needs to be redone or cherry-picked.

The current named consumer is the `xhci-probe` controller qualification boot:
`main.rs` calls `xhci::qualify`, which claims the PCI function, acquires
firmware ownership, resets the controller, runs command and EP0 rings,
enumerates one device and shuts down. It is polled, with controller
interrupt enables clear. `make xhci-test` exists separately; `make check`
already runs the observer self-test and host ring/ownership tests, but does
not run the xHCI guest matrix. Historical statements about those omissions
in the research records remain evidence of their original source revisions.

Carry forward the following:

| Area | Existing implementation | Stage 1 action |
| --- | --- | --- |
| PCI claim, BAR sizing and MMIO bounds | `pci.rs`, `mmio.rs`, `xhci_ring::layout` | Reuse; validate interrupt-table BARs separately. |
| Firmware handoff and scratchpads | `xhci_legacy.rs`, `xhci_scratch.rs`, `xhci.rs` | Reuse refusal and quarantine behavior; no forced handoff. |
| Command, event and EP0 rings | `xhci_ring.rs`, `xhci.rs` | Retain one outstanding operation and existing completion validation. |
| Root-port reset and descriptor reads | `xhci.rs` | Reuse USB2/USB3 protocol-range handling and bounded waits. |
| Existing research controls | `scripts/xhci-test.sh`, hotplug and observer tools | Preserve their criteria and results; run them after integration. |
| Interrupt transport | None for xHCI | Add the bounded MSI-X path below. |

## Interrupt path proposed for admission

### Admission delta, 2026-10-15

The owner has requested continuation until completion. The steward admitted
stage 1 with changes at 20:57:36Z after independent review. These amendments
are the delta for confirmation before runtime implementation:

- Reserve USB vector `0xd0`. `0xe0` already belongs to the AP timer.
  Centralize PIC, syscall, USB, AP timer/IPI, BSP acknowledgment/stop and
  spurious vector reservations in one compile-time checked constant table.
- Keep the USB IDT gate and a harmless ISR installed for the entire boot.
  After masking and disabling MSI-X and bus mastering, read configuration
  and BAR registers to flush writes, inspect this vector's LAPIC IRR/ISR,
  and service pending delivery in bounded `sti; hlt; cli` windows (at most
  200 PIT ticks). Refuse ring reuse on unresolved drain. Tag armed IRQ
  counts with a monotonically increasing round generation and keep retired
  and late counts separate. A physical MSI has no software generation tag;
  the drain fence, not count tagging alone, excludes old delivery on reuse.
- Limit delivery between event-ring acknowledgements to 64 interrupts. The ISR masks entry 0 at overflow,
  allowing the foreground to report `InterruptStorm` and shut down. Report
  a matching completed event without IRQ advancement as
  `CompletedWithoutInterrupt`, separately from a transfer timeout.
- Set IMOD to zero while halted. With IF clear, retain IRQ credit from the last ERDP/EHB acknowledgement
  across port-reset and observation waits, clear USBSTS.EINT (RW1C), clear IMAN.IP (RW1C, preserving IE;
  normally auto-cleared by MSI-X delivery), validate/consume TRBs, and write
  ERDP with EHB clear-by-write. Snapshot the generation count and reset its
  interrupt budget immediately before that ERDP write, and check the ring
  again before sleeping. One wait may consume coalesced events against its
  initial acknowledgement baseline; a new wait uses the latest baseline.
- Require both complete MSI-X regions inside already mapped BAR0, disjoint
  from capability, operational/port, runtime and doorbell register spans
  and all extended-capability DWORDs read by the driver. Require a nonzero
  vector count equal to HCSPARAMS1.MaxIntrs. Other BAR placements refuse.
  One additional LAPIC mapping consumes an existing MMIO region record
  (eight available, 2 MiB granularity). Reuse the existing BAR0 mapping.
- Recheck `ownership_holds()` immediately before enabling MSI-X, IMAN.IE
  or USBCMD.INTE. Run the SMI flip/reacquire fixtures in the new mode.
- Name negative cases: MSI-X absent using `nec-usb-xhci,msix=off` (the
  installed QEMU 8.2 generic model has no msix property), masked vector,
  interrupt storm, late interrupt after retirement, the NEC second model,
  and post-shutdown MSI-X/configuration trace silence. Add a realistic
  MSI+MSI-X coexistence parser fixture. The focused make target has at most
  thirteen boots with a 120-second outer deadline each; expected ordinary
  elapsed time below three minutes is to be measured in the guest slot.
- DMA remains in static kernel-image pages excluded by frame-admission
  issue #27. No frame allocation or per-workload DMA credit is introduced.
  Stage 2 requires its own authority/ABI admission for a named class consumer.
  Update the `pci.rs`, `xhci.rs` and gate-list contracts when runtime lands.

The settled mode word is `xhci-controller`; the make target is
`xhci-controller-test`. Reserved low bits in PCI capability pointers are
deliberately refused rather than masked. Unknown capability bodies remain
outside the parser's layout claim.

QEMU does not establish physical event-DMA/MSI posted-write ordering, IMOD
timing, real PBA or firmware SMI behavior, or Z2 MaxIntrs/table placement.
x2APIC firmware mode refuses, and firmware VT-d interrupt remapping can
block compatibility-format MSI-X. Neither is qualified in this local stage;
the existing Z2 survey ladder remains the physical path.

Use one MSI-X vector on the BSP, targeting interrupter 0. This fits the
existing QEMU `qemu-xhci` target and avoids a new legacy interrupt-routing
contract. MSI-X absence is a named refusal in the new mode; there is no
silent polling or MSI fallback. MSI discovery is needed to observe and
disable an alternative enabled transport after ownership is acquired.

The first code increment is `pci_interrupt::discover`. It reads the entire
conventional type-0 PCI capability list before returning MSI/MSI-X state.
It rejects invalid pointers, cycles, duplicate interrupt capabilities,
truncation and overlap with known capability registers. It validates the
complete MSI-X table and pending-bit array against caller-supplied, sized
memory BARs. It performs no configuration or MMIO writes. Unknown capability
bodies are not decoded; their headers alone are reserved. BAR type, base,
assignment and upper-half classification remain the hardware caller's job.

The runtime increment will:

1. Require a separate `xhci-controller` boot mode, refused in AP/startup
   pressure modes as `xhci-probe` is today. Ordinary and survey boots keep
   their present behavior. No userspace capability or USB ABI is added.
2. Discover interrupt capabilities read-only, then complete the existing
   firmware ownership handoff before changing any interrupt state. Validate
   and map the table/PBA BARs before enabling a transport; preserve unknown
   ownership as found. BAR sizing is a reversible configuration write and
   must retain the current claim/restore discipline.
3. Install a dedicated IDT gate (vector `0xd0`, checked against
   existing reservations) and initialize a BSP xAPIC route without starting
   an AP. Reuse the existing APIC register rules, but separate mapping and
   EOI from `ap::configure`: that function also requires a validated AP
   trampoline and is not a USB initialization API. Refuse unsupported CPU
   or APIC mode before arming the controller. Preserve PIC PIT/COM1 routing.
4. With Run/Stop clear, mask the MSI-X function and all its table entries,
   disable MSI if present, configure table entry 0 for the BSP, initialize
   the event ring and IRQ state, then enable MSI-X, IMAN.IE and USBCMD.INTE.
   Program all message words before unmasking entry 0. INTx stays masked.
   Re-read relevant controls; do not report an armed route on failed readback.
5. Keep the ISR small: record a bounded delivery count, acknowledge
   the local APIC, and return. It neither consumes TRBs nor takes the global
   kernel lock. Foreground code is the only event-ring consumer and clears
   controller pending/busy state in the order required by the specification.
6. Check events with interrupts disabled, then use `sti; hlt; cli` when
   waiting. PIT ticks retain the existing timeout bound. Completion validity
   comes from the matching event, not the interrupt count. Qualification
   additionally requires interrupt-count advancement and a masked-vector
   negative control, so PIT wakeups cannot stand in for working USB IRQs.

Technical basis: Intel's [xHCI revision 1.22 specification](https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/extensible-host-controler-interface-usb-xhci.pdf),
sections 4.17, 5.2.8 and 5.5.2. These define the transport and interrupter
register relationships. The generic PCI decoder permits the PCI MSI-X size
range; the xHCI caller must separately reconcile it with HCSPARAMS1.MaxIntrs.
The source is independently written from register definitions; no driver
implementation is copied.

## Fixed bounds and shutdown

Keep one controller, one enabled slot, one EP0 transfer ring and one event
segment. Existing bounds are 16 command TRBs (15 usable), 8 EP0 TRBs (7
usable), 16 event TRBs, at most one outstanding command or transfer, 64
consumed events per wait, 64 scratchpad pages plus the existing fixed DMA
pages, and a 32-entry xHCI extended-capability walk. PCI interrupt discovery
has at most 48 aligned conventional-capability headers. One vector is used;
masking the advertised table is bounded by its validated entry count.
PIT timeout limits remain those named in `xhci.rs`; stage 1 adds no dynamic
queues, hub traversal, isochronous traffic or USB class endpoint.

Successful shutdown stops admission, clears IMAN.IE and USBCMD.INTE, masks
and disables the MSI-X transport with readback, clears Run/Stop and observes
HCHalted, rechecks ownership, disables bus mastering with readback, and drains
pending BSP interrupt handling before reporting stopped. Ordering must be tested both
after success and after every initialization/transfer failure. If halt or
interrupt quiescence cannot be established, report the uncertainty and keep
all referenced static storage quarantined for the boot. A timeout, an IRQ
count, or a bus-master write alone is not proof that old DMA/IRQ references
are gone. Controller reset and ring reuse require the existing confirmed
halt/reset conditions, with the interrupt route fenced as well.

## Replacement and state review

The PCI function and root port are hardware identities; the interrupt route,
slot address, ring pointers and outstanding operations belong to the current
driver generation. Stage 1 offers no stable logical USB service, export
schema or authority rebind rule. Resetting a controller is not service
continuity and must not revive any old completion or handle.

Live replacement would require stopping submissions, fencing IRQ delivery
and DMA, accounting for outstanding transfers, reconstructing authority under
an explicit versioned state schema, validating the successor externally,
committing its routing, and retiring the predecessor's mappings and pages.
Those mechanisms are outside this increment. Existing MMIO mappings and
boot-lifetime PCI claims cannot currently be retired. A retained predecessor
kernel does not establish rollback after a USB effect; refusal and reset
must remain explicit. No native Rust layout becomes a transfer schema.

## Verification and next boundary

### Runtime source increment

The runtime source now adds `xhci-controller`, one BSP MSI-X route, the
permanent gate, foreground event handling, 64-IRQ storm masking and a
20-tick bounded opportunity for IRQ delivery when an event is already
present. That opportunity permits a PIT wakeup to occur before the USB
interrupt without treating the PIT itself as USB progress. A masked vector
still ends in `CompletedWithoutInterrupt`. Table programming and enable/
disable ordering use the same `MsixAccess` functions as their host fixtures.

The focused QEMU runner has thirteen cases and an external QMP observation
of the running generic controller's MSI-X table, unused-vector masks, IMAN,
IMOD and PBA. Its table/PBA offsets are pinned to the QEMU 8.2 model, from
[QEMU's device register definitions](https://github.com/qemu/qemu/blob/v8.2.2/hw/usb/hcd-xhci-pci.c).
The storm fixture enters the actual gate/ISR with software interrupts; it
does not claim a physical controller emitted those interrupts. The late
fixture queues a real No-op command and requires a pending LAPIC bit before
retirement; its eventual delivery must increment the retired count.

The thirteenth case was added during source inspection: the existing
`reacquire` firmware fixture takes ownership back at the probe's final
check. Cleanup must abandon the current state without halt or DMA-disable
writes, rather than call an owned-device release. Recheck ownership again
after a halt wait before disabling DMA. The unstarted host occurrences for
sources `f077729` and `5399647` were ended and reconciled before changing
their frozen inputs;
their terminal results remain `FAILED_OR_NOT_RUN` with zero commands. Each
corrected source gets a new run. Review also found that an IRQ delivered
during port reset must survive the start of the next event wait. IRQ credit
now starts at the last ERDP/EHB acknowledgement; the budget resets there,
not at a wait boundary. Host fixtures cover this delivery ordering and
refuse credit for a subsequent event without a new interrupt. Shutdown
rechecks ownership after halt, skips redundant controller-mode DMA writes
at the qualify tails, and rechecks before the late-MSI doorbell. On loss it
retires software accounting and reserves static DMA storage without further
device writes. LAPIC mapping logs its actual region-count delta and usage.

Runtime source `9591f498` passed all 267 workspace host tests, strict
Clippy, formatting, provenance, the model and oracle controls, and x86 plus
ARM64 kernel builds on the owned disposable Vultr VM (QEMU 8.2.2, TCG).
Occurrence `7c93468f-6e83-43dc-973b-e749c2e55e74` then FAILED the focused
runner on the empty-controller case: the guest recorded 40 IRQs, command/
event wraps, confirmed halt, DMA off and quiet, but the requested
`usb_xhci_irq_msix` record was absent. That failed verdict is preserved;
the prior xHCI matrix and canonical check were not reached.

Inspection of [QEMU 8.2.2's PCI interrupt callback](https://github.com/qemu/qemu/blob/v8.2.2/hw/usb/hcd-xhci-pci.c)
shows that the declared xHCI MSI-X trace hook is not called on notification.
It is not evidence of delivery. A separate bounded diagnostic boot of the
same kernel observed 40 messages for vector 208 at the BSP APIC and 40 guest
IRQs. [QEMU's APIC delivery implementation](https://github.com/qemu/qemu/blob/v8.2.2/hw/intc/apic.c)
emits `apic_deliver_irq` for that path. The runner correction uses this
emitted record with exact destination 0, physical destination mode, fixed
edge delivery and vector 208, together with the independent MSI-X table
observation and guest ISR count. Other vectors, another destination and
MSI-X use/unuse configuration records cannot supply IRQ credit. Masked
vector delivery and any vector-208 message after the quiet marker fail.
The six-positive/twenty-negative oracle fixtures cover these distinctions.
The kernel/ISR source is unchanged by this correction. A fresh occurrence
must still run all thirteen cases, the old matrix and canonical check;
neither the diagnostic nor a corrected oracle retroactively passes the
failed run. Steward review of this runner correction precedes that rerun.

Formalization for this increment: `scripts/models/xhci-irq.py` exhausts
101 states with two generations, up to two posted messages per generation,
one coalescing pending bit and a synchronous BSP ISR. Under the explicit
assumption that disabling/flushing the route excludes further old posts,
drain-before-rearm prevents cross-generation IRQ credit. Removing the drain
produces `arm -> post -> fence-retire -> arm -> handle`, a counterexample.
The model corresponds to route disable/readback, IRR/ISR drain, then
`State::arm`; its oracle generation tag is absent from physical MSI data.
It proves neither the hardware fence assumption nor event/DMA correctness,
and does not replace QEMU checks or physical qualification. Source/result
identities and the producer identity belong to this lane's runtime receipt.
Decision owner: Codex for this bounded model; the steward retains independent
candidate acceptance. No claim was weakened into physical continuity.

Host tests first cover configuration-list termination, every pointer value,
all four MSI capability layouts at every aligned offset, duplicate/overlap
refusals, MSI-X region sizing and arithmetic, and malformed tails after a
valid interrupt capability. The read-only trait exposes no write operation.
Then add host tests for IRQ arm/disarm ordering and pending-wakeup behavior
alongside the actual runtime implementation.

After design admission and a steward-issued guest slot, add a small
`xhci-controller-test` to `make check`: no controller; empty controller with
IRQ-driven command wraps; one root-port keyboard used only for EP0
descriptor reads; unavailable/masked interrupt route with bounded refusal
and clean shutdown. Require post-shutdown inactivity, normal boot completion
and no panic. Run the full existing xHCI research matrix, format/lint, host
tests and the canonical check as regression coverage on the final candidate.
Do not reinterpret old runs as results for this source revision.

Stage 1 was independently accepted as `ACCEPT_BOUNDED` on 2026-10-16 at
source `f3ce805a4b44b4aa2f07534b73ea9a2b8cf7733e`, tree
`b1fb8b2b649c91d0c59a36ace0840f18a6af5756`: QEMU 8.2.2 TCG, one BSP,
MSI-X runtime. The owning inspection is
`INSPECT-opus-usb-stage1-results-20261016.md` in the integration steward
registry. No push, main promotion or physical action follows from this result.

Occurrence `b65d1fe7-fc3f-47d2-8b6c-cdf09e2a1ba9` passed 267 host tests,
strict Clippy, architecture builds, all thirteen focused cases and all
thirty-nine unchanged prior xHCI cases. Its aggregate remains FAIL at the
missing external font input. Fresh source-identical canonical occurrence
`546867e5-64a8-4dca-a657-482a298b7b2c` passed the full `make check`, including
a fresh thirteen-case matrix. Attribute boot logs through the step naming
their run directory: retrieved shared-build logs also contain earlier runs.
The resource-owner occurrence `0f69d35b` itself failed at tool setup before
compilation; it does not own these passing test results.

The x86 executable and Clippy artifacts were reused from `9591f498`, whose
kernel build inputs are identical to `f3ce805a`; the latter changes only the
runner and this document. This is source equivalence, not a fresh x86 compile.
ARM64 rebuilt and reproduced the same bytes. The staged local font matches
the declared host input and tracked glyph bytes; no remote installed-font hash
was retained. The canonical framebuffer pixel check passed.

The keyboard and NEC cases each show 53 APIC messages and 51 ISR entries,
with no late entries. Coalescing is a possible explanation, not established
by the retained evidence. IRQ counts are progress/accounting, not one message
or completion identity per entry. Equality at 40 messages/40 entries was
observed in the empty-controller diagnostic, not asserted for all cases.
The accepted runner requires exact-route delivery and the independent ISR,
table and shutdown observations; it does not reconcile message/ISR counts.
These limits and the preserved failures do not imply physical DMA/interrupt
fencing or HID class support. The owned VM and scoped keys are retired, with
account-listing absence recorded; required kernels, logs and replay inputs
remain in local custody.

First-increment validation, 2026-10-15: 15 focused parser tests and all 256
workspace host tests passed; `cargo fmt --all -- --check` and
`cargo clippy --lib --tests --offline -j 1 -- -D warnings` passed. No guest
was started. These results cover the parser and its host integration only.

Formalization consideration: source `f8184ca` plus the first increment
identified by its commit and lane result. Proposition: for a stable type-0
configuration fixture, interrupt discovery terminates, reads only aligned
in-range DWORDs and returns no result for the listed malformed structures;
MSI-X extents fit the supplied memory-BAR lengths without overlap. The
finite pointer/shape sweeps and boundary tests are sufficient for this
read-only parser. They do not prove stability during concurrent device or
configuration changes, correctness of caller-supplied BAR facts, MMIO
ordering, IRQ delivery, DMA exclusion or physical behavior. Decision owner:
Codex for this parser; steward for stage 1 design admission. The runtime
arm/drain state machine merits a small bounded model when that code is added.


Review correction formalization consideration: the durable claims are that
IRQ delivery remains eligible across non-event waits until an event-ring
acknowledgement, and that no DMA-disable write follows observed ownership
loss. Practical tests of the actual State API plus the firmware model and
external device traces suffice for this delta; the existing bounded model
still covers only cross-generation drain. IF-clear foreground/ISR exclusion
and stable device behavior between a check and its immediately following
write remain explicit assumptions. No software check makes asynchronously
changing firmware ownership atomic. The acknowledgement count is local
accounting, never an event identity or proof of a transfer's completion.
Decision owner: Codex; exact source and test identities are recorded in the
successor lane receipt. Hardware ordering and physical transfer remain open.


Trace-oracle formalization consideration: in this one-BSP boot, only the
owned xHCI MSI-X route is programmed for vector 208. The QMP table sample,
emitted APIC message record and guest ISR count jointly establish the
bounded virtual route, while masked and post-quiet controls refuse missing
or residual delivery. This assumes that another device does not independently
send that vector; it is not a universal device-origin proof or physical
MSI/DMA fence proof. Actual-record fixtures and the independent guest checks
are sufficient for this runner correction. Exact source and failed/result
identities are in the lane receipts. Decision owner: Codex for the correction;
steward for the independent scope review and final result acceptance.
