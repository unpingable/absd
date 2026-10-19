# Ports that trip after power settles

B-M1 is admitted under the internal USB tracking record, from `26854f60`, for a kernel
after 8b. It does not change the candidate 11 input. The initial late-trip
host sequence is red on that production source plus test-only `f5833882`:
all 32 successors were consumed. Test-only `5c3affa` on rejected `81343e5`
adds three further compiled logical counterexamples: enumeration-time loss,
configure-then-trip, and ten-minute decay. Both cycling cases report 32
successors and 33 power writes; all three tests fail. Their exact executables,
source, logs and raw FAIL results remain in the lane registry. The correction
retains these three assertions and the scripted device's power-write condition.

Watching owns no bound keyboard slot or report TD. A power loss on an unbound
port is acknowledged without fencing the controller. Empty power restoration
also needs no reconstruction. Ordinary powered connection changes retain the
existing behavior. A usable connected port restored from unavailability, or
carrying OCC from a completed over-current pulse, may request reconstruction
under its own allowance.

`PortPowerRetry` belongs to the private service runtime and survives successor
construction and controller resets. It holds policy, not device state or
grants. Its fixed storage is about 3.3 KiB, with no allocation. The supervisor
supplies the current monotonic PIT tick before transitions. PP retry intervals
are 1, 2 and 4 thousand ticks after zero, one and two counted failures.
Only the PP retry timestamp uses wrapping low tick bits; failure-window age
uses the full 64-bit wrapping tick difference.

A restoration is reserved before its fence and becomes the active attempt in
the successor. Admission counts completed failures plus the active attempt,
so overlapping events cannot reserve a fourth attempt. An unsuccessful target
is charged once when the generation returns unbound, binds another port, or
is superseded. Every observed power-loss fence on the current enumeration or
bound port also charges that port immediately and closes its active attempt;
subsequent retirement cannot charge that attempt again. This covers PortWait,
the current-port enumeration change, initial report-TD posting, running-port
checks, bound port-status changes and report completion. Power checks precede
disconnect classification when both power and CCS/PED are lost. Observing an
already unavailable unbound port merely records its condition; it does not
charge another failure on every Watch pass.
Generic command/transfer errors and timeouts also resample power under current
ownership, charging the selected enumeration candidate before bound-port
assignment or the bound Running port; unbound Watch has no candidate to charge.

Healthy ports retain normal initialization power writes. An admitted target
also gets one initialization write if our HCRST cleared PP. After HID
configuration and a power-checked initial TD post, binding closes that target's
active attempt without charging it. It does not clear failure history. Binding
another port charges the old target once. Neither callback revives a refused
port or old input authority.

Three counted failures refuse only that port. It then gets no PP writes, slot
allocation or reconstruction requests; changes are still acknowledged, and
other ports remain watched. Scan reports `reason=refused`, distinguished from
`reason=port-power`. The refusal diagnostic names the count and decay window.
There is no operator rearm API.

Failures use the review's bounded window policy: the first counted failure
starts a 600,000-tick (about ten-minute) per-port window. Its count expires at
the end of that window before another admission or charge. Thus no failure
older than ten minutes remains counted. Later failures in the same window are
also forgiven at that boundary, possibly earlier than ten minutes after their
own occurrence. Binding does not move the boundary. A new failure after expiry
starts a new window. Decay reopens local admission, including when a fault
clears or a device is replaced; it never refunds the global successor budget.
This is a fixed per-port accounting window, not an exact rolling history of
three independent failure timestamps.

During enumeration the current candidate retains its strict change fence.
Earlier unbound ports suppress power loss and refused ports stay skipped;
ordinary powered changes still fence, including a swap after Disable Slot.
An earlier-port restoration uses the same allowance. The unchanged held-swap
fixture caught an overbroad ignore rule in `394d7476`; that run remains failed.
Bound input retains connection and completion-identity checks before translation.

The global 32-successor limit is unchanged. Within one accounting window, one
unbound cycling port spends at most three restoration reconstructions, plus
the existing initial transition into recovery. Across ports, 11 × 3 = 33
restorations already exceed 32. A current or bound power-loss failure can spend
a fence successor and a later restoration successor, at most two per charged
failure; the conservative aggregate is ports × 3 × 2, and six ports give 36.
Unrelated changes and an already-spent budget reduce the remaining capacity.
Repeated windows on one port, many failing ports and ordinary continuous
connection changes can still exhaust 32. Local refusal and decay promise no
unlimited availability and never revive fenced slots, reports or handles.

The original shared-rule host sequence retains its 20-tick settling observation,
50-tick late trip, 100,000-tick horizon and healthy later port at tick 80,000.
It checks reset-preserved and reset-cleared PP, local refusal, finite writes,
selection of another port, fault removal and a history-loss counterexample.
The new three-test sequence requires an admitted PP write before readiness
and supplies unavailable() at each loss fence. The red implementation only
marked FAULTED even with that notice; it also omitted runtime notifications.
Green policy charging and actual runtime call sites are separate obligations.
The transfer-error host regression guards the actual error-branch source and
executes shared policy separately; it does not execute MMIO or runtime glue.
Additional vectors check active-attempt charging exactly once, retained history
on bind, independent ports, backoff, reset repowering and decay across the low
tick wrap. The established guest runners and reference outputs are unchanged.

Formalization consideration: finite shared-rule sequences, explicit red
counterexamples, boundary vectors and independent source review are sufficient
for this bounded policy change. The proposition is per-port accounting and
admission within the stated window, with one supervisor clock and serialized
policy transitions. It is not a bound on arbitrary global transitions or a
proof of hardware behavior. Scan, supported-device and binding steps remain
fixture assumptions. Actual QEMU PPC0 runs check runtime regressions and stack
use; they do not produce electrical over-current. Exact source and result
identities belong in lane receipts. The integration steward owns acceptance
after independent review, outside the replaced runtime.

Console remains the stable logical service. Private policy reconstruction is
explicitly described here; native Rust layout is not an exported replacement
schema. Existing halt, DMA/IRQ fencing, successor validation and generation
retirement remain mandatory. No physical transaction drain, safe hardware
transfer, post-effect rollback or L3/L4 kernel replacement mechanism is proved
or introduced. The additional private table must fit the existing kernel stack
budget; guest high-water observations cover only their executed paths.

The absent-controller case found a separate qualification handshake race:
the host could send `quit` after the prompt but before the first console read
blocked. The shell exited normally with zero dropped bytes, but its unchanged
`console_waits > 0` acceptance condition correctly failed. Three unchanged
replays each at `438b8a3` and accepted stage 3 `a5154a7d` passed; these finite
samples do not reproduce an old-source failure or establish its frequency.
The runner, shell oracle and console-read implementation are byte-identical
between those revisions. Test-only `ed4437a` adds a deterministic fixture
against the real injection method; it fails because prompt-only observation
admits bytes before a blocked read.

Shell qualification mode now emits `SHELL CONSOLE BLOCKED` only after its
first console read records Waiting, its transfer and the wait counter. That
path then unconditionally returns Blocked. Handlers hold the kernel lock with
interrupts disabled, so later incoming bytes cannot bypass that registration.
The host waits for this receipt before serial injection, without a sleep.
The same fixture rejects prompt-only input and accepts the blocked-read receipt;
the shell's existing acceptance condition is unchanged. Other boot modes do
not emit the marker. This is an observation of an existing transition, not a
new syscall, authority grant or replacement state. The finite ordering fixture,
native cases and independent source review cover this small correspondence;
they do not establish general scheduler or hardware ordering claims. Original
failed qualification records remain failed.


A later modifiers run at `b4139b7` emitted the correct CapsLock `A`, but a
native `USB KEYBOARD PROGRESS` record interrupted the shell's separate writes
before their newline. The original reader timed out; that run remains failed.
Shell-response waits now remove only complete, explicitly matched PROGRESS,
ENQUEUED and IDLE records after the existing QEMU-trace reconstruction. Fixed
fixture programs do not print those names. The ordinary diagnostic view and
all native checks keep those records. Deterministic controls exercise the
actual wait method: the captured interleaving matches, its native progress
remains visible, and a lowercase user byte or malformed diagnostic is refused.
This lossy reconstruction is scoped to these known fixtures and three record
grammars, not a general log parser or a change to accepted keyboard bytes.
Raw captures are retained. The qualification-runner change requires independent
review, including its correspondence to the separate UART writers.
