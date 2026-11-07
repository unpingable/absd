# Native datagram link-failure feedback

Q24 needs the native datagram client to receive an observed link failure even
when the NIC holder calls `Stack::poll` before dispatching its next framed
request. Previously that poll removed the socket, and the next request saw
only `Stale` (8). The canonical link outcomes remain `LinkDown` (9),
`DeviceFailed` (10), and `LinkUnknown` (11). A disabled reading takes precedence
over a down-carrier reading, as it did on the request-first path.

Each datagram entry now has one optional, private terminal diagnostic. The
entry still names an exact Stack instance, slot and monotonically issued
epoch. Observing a link fault removes the socket and discards its queues and
ICMP/PMTU feedback immediately. Only the just-retired generation receives the
diagnostic. A later fault cannot replace it. The next SEND or RECEIVE for that
exact generation consumes it once; subsequent operations return `Stale`.
Request-first observation returns the error directly and consumes its own
diagnostic in the same call, preserving the existing error-then-Stale behavior.

The diagnostic is not socket authority, an active grant, a port reservation or
permission to emit. Binding may reuse the vacated slot and local port before
the diagnostic is read; a successful bind replaces it with a fresh epoch.
Foreign instances and old epochs cannot consume or clear another generation's
diagnostic. An explicit CLOSE/revoke or administrative `datagram_fence` clears
it. A CLOSE on the already-retired endpoint still returns `Stale`. Malformed
framed messages fail validation without reaching an endpoint operation.
For a retired exact endpoint, its one diagnostic has the same priority over
SEND argument checks that `Stale` previously had; no packet is enqueued.

Known link faults discovered by IPv6 maintenance or either outbound TCP family
use the same cause-preserving native datagram fence. Their own exposed return
values and retirement semantics are unchanged. A generic refusal such as the
existing IPv6 clock-rewind fence retains no native link diagnostic. This does
not repair other families' own poll-before-request terminal diagnostics.

## Bounded transition argument

For one exact generation, use states `A` (socket authority), `D(e)` (socket
absent, one pending observed reason), and `R` (socket absent, no reason).
These states describe private runtime state, not an exported schema.

| Event | A | D(e) | R |
| --- | --- | --- | --- |
| observed link fault f | D(f), remove socket | D(e) | R |
| valid SEND/RECEIVE | normal operation, or return observed f and enter R | return e, enter R | Stale |
| explicit close/revoke or generic fence | R, remove socket | R | R |
| successful fresh bind in the slot | old generation spent; new epoch A | old generation spent; new epoch A | old generation spent; new epoch A |
| foreign instance/old epoch operation | Stale for that reference; current generation unchanged | same | same |

The implementation correspondence is `Entry.socket`, `Entry.terminal`,
`Endpoints::take_terminal`, and `datagram_fence_reason`. All state mutation
requires the exclusive `&mut Stack` borrow; this argument assumes sequential
calls rather than concurrent mutation outside Rust's ownership rules. Epoch
and instance exhaustion retain their existing checked refusal behavior.
There are at most eight entry diagnostics and no retained packet bodies.

Formalization decision: this finite transition description plus actual
Stack/Session/Channel source controls is proportionate for the private state
change. It is not a machine-checked model. The controls cover all three error
codes, both operation/poll orders, consume-once, cross-family observation,
explicit clearing, instance/epoch substitutions, slot reuse, channel framing,
and a link change during actual ARP emission detected after interface polling.
Existing test methods are preserved. The off-host results below exercise all
13 new net controls in both default and DHCP configurations.
The deciding owners are the Q24 lane owner and independent integration
reviewer, with source/result identities recorded in the lane receipts.

## Replacement and observation limits

This is a current implementation generation's diagnostic, not a stable object
identifier, export format or rebind rule. A replacement service reconstructs
authority from explicit owner-issued grants; it does not import this native
Rust layout or revive an old endpoint. No live-generation state transfer,
conversion/downgrade or rollback mechanism is introduced.

A successful local SEND was only queued, and already emitted frames cannot be
recalled. Fencing removes the socket before later polls; it does not prove
hardware quiescence, retract DMA, or prevent unrelated interface traffic.
Link readings establish only what that call observed. A short transition
between readings may be missed. QMP identity/transition receipts, captured
Initial, driver propagation, native framed reply, process retirement and full
wire accounting belong to the separate Q24 consumer proof. Host tests alone
establish none of those external correspondences. No kernel, ABI, wire status,
dependency, canonical case, deadline or grant is changed here.

## Qualified consumer, 2026-10-18

Platform source `5cdfefde60f04a4c9e26ca78afc7a376e29f9a62` with kernel
`2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b` passed 527 artifact methods,
56 QUIC Rust tests, 319 default net tests and 332 DHCP net tests, including
all 13 link-feedback controls in each configuration. Four independent Linux
Q01 calibrations passed through the requested Q24/Q29/Q30 IPv4 and Q17 IPv6
profiles; their receipts identify the actual Q01 case. These results belong
to occurrence `630464e6-f025-4004-99de-ab52ceb64b26`, whose overall verdict
remains FAIL: its QEMU control-socket pathname was too long, before guest
startup. Three earlier failed occurrences remain in the same lane registry.

Native-only continuation `a0dd3dc8-9fe4-4958-a1df-0059e297d444` used the same
source, qualified client, root and Linux prerequisite, with a shorter owned
evidence path. Its three phases passed. One captured 1200-byte QUIC Initial
matched the parent SEND and Linux peer receipt. The QMP socket peer matched
the exact QEMU process; capabilities and `set_link quicnic up=false` were
acknowledged. The guest observed link-up at 572 ms and link-down at 986 ms,
reported `Native(LinkDown)` (9), fenced, exited normally and reached true
result EOF with sockets and child authority retired. There were no sends
after fencing. Host and guest clocks are not compared. Codes 10 and 11 are
host controls only; this guest run does not establish which polling order
first detected the fault.

Process, handle, pipe and cell counts returned to baseline. Allocator frames
rose from 559 to 566; full memory reclamation is unestablished. These two
occurrences provide source-coherent component evidence, not one all-pass
campaign. Exact archives, hashes, failed results and integration handoff live
under `archived-occurrence`, root run
`3d0619cd-b993-4b52-b22d-dc29ad378ad6`. Independent integration acceptance
remains separate. This result documentation does not change executable source.
