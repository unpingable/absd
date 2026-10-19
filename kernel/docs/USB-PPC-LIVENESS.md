# Per-port keyboard power refusal

Admitted by the integration steward in the internal tracker on 2026-10-17,
after accepting D1 and stage 3 at `a5154a7` for composition. Native Console
is the live consumer. A port that cannot retain PP, or reports over-current
(OCA), is unavailable for that port; it does not quarantine keyboard recovery
for the whole controller. This supersedes stage 3's documented port-power
liveness trade-off. Other quarantine and authority rules are unchanged.

Initial keyboard setup uses a port-local power policy. The generic xHCI
probe/controller path retains its strict all-ports-powered requirement.
Neither path requests PP while OCA is asserted. The keyboard selector skips
an unpowered PPC port or an OCA port before allocating its slot, and scans
the other root ports. An all-ones PORTSC read is unavailable, not ready.

Deferred recovery still powers at most one port per pump. A failed power
readback is not a controller error: Scan checks readiness again and skips
the port if unavailable. If OCA cleared after the first power pass, Scan
can try PP once more for that port, then waits at least PORT_POWER_TICKS
before reading it again. That wait returns to the scheduler every tick and
has the existing tick/TSC deadline. No repeated attempt occurs in that scan.
At most two enable attempts per port per generation are possible, with no
enable attempt under OCA and no busy-wait in the runtime pump.

Each scan records connection, OCA and, for PPC controllers, PP state and
acknowledges all observed change bits, including OCC. On an unavailable,
unbound port, Watch acknowledges further changes while the port remains
unavailable. It retries PP at most once per port per 1,000 PIT ticks, never
under OCA, without resetting the controller. A retry enters a deferred
PORT_POWER_TICKS wait before reading the port again; like Watch, this wait
requires advancing PIT ticks and has no separate phase timeout. The normal
fenced stop path applies. Only one port is retried per pump, with fixed
256-entry private u32 timestamp storage (1 KiB) and no allocation. Retry
intervals use wrapping low tick bits; a full 32-bit tick period without an
observation may delay a retry by one interval, but cannot enable extra retries.
The per-port timing avoids one failing port starving another's retry.

When power becomes usable, the changed observation fences and permits a fresh
reconstruction, even without a CCS change. An unavailable port's changes also
do not interrupt enumeration on a later usable port. Other changes on a
previously usable port retain the ordinary fence. Loss of power on the bound port
fences input before accepting another report or posting another TD.
Continuous power/connection changes can exhaust the existing 32-successor
budget. Restoration while a different keyboard is already running does not
replace that working keyboard; a later rescan considers the restored port.

The earlier `b064ce8` policy preserved OCC for PP0/OCA0 and reconstructed on
that witness. Independent review found that a device tripping on every PP
attempt regenerates that same state in each successor, exhausting all 32
generations. The corrected policy acknowledges the pulse and retries in
Watch. Under the scripted recurring PP0/OCA0/OCC1 sequence it stays in one
generation; after removal of the fault, a PP write that remains set permits
one reconstruction. This is a sequence-model claim, not an electrical claim.
An unstable device that appears usable after the settling wait and fails
again later can still consume the normal successor budget. Other continuous
connection/power changes can also exhaust it.

That paragraph describes the accepted `26854f60` base. The separately admitted
B-M1 correction in `USB-PPC-LATE-TRIP.md` adds retained per-port backoff and a
finite, port-local refusal for repeated unsuccessful restoration. It does not
change the kernel8b/candidate11 input or qualify physical electrical behavior.

Logical Console identity and rights continue. Port observations are private
to one implementation generation and reconstructed from registers; their
u16 encoding is not an exported state schema. The existing halt/DMA/IRQ
fences, reset, successor validation, quarantine and generation retirement
remain mandatory. Stopping during the additional power wait uses the normal
fenced stop path. Power effects are not rolled back; this adds no live kernel
replacement or hardware-transfer proof.

Qualification scope: host negative inputs cover OCA, PP refusal, independent
later-port readiness, stable blocked observations, OCA clearance without
CCS change, PP restoration and latched OCC. A scripted host Scan → Watch →
successor model applies the production pure retry/change rules to repeated
PP writes that yield PP0/OCA0/OCC1. The reviewed policy exhausts 32 successors;
the corrected policy remains in the first generation through nine timed
Watch retries. Fault removal at tick 5,000 permits one successor and selection.
Separate vectors cover per-port fairness, tick wrap and no retry under OCA.
The actual QEMU 8.2.2 controller
used by the lane advertises PPC=0. Inspected upstream hcd-xhci.c returns
HCCPARAMS without PPC, accepts PP writes directly, and contains no producer
of OCA/OCC. There is no device-produced over-current case here. Ordinary
QEMU keyboard/recovery/controller regressions and both architecture builds
check the unaffected runtime paths; they do not qualify physical PPC.

Formalization consideration: the new proposition is per-port classification
and bounded retry, under the existing ownership and register-observation
assumptions. The added finite scripted sequence and pure host rules, tied to
the runtime by source review, are sufficient for this bounded correction;
the model assumes each PP attempt settles within its scripted wait and does
not model USB electrical behavior or every possible register interleaving.
The existing bounded generation/fence models remain relevant
and unchanged. They do not prove electrical behavior, scan fairness under
continuous changes or physical authority transfer. Exact source/result/model
identities are recorded in the lane receipt. Independent acceptance belongs
to the steward after the Claude review.
