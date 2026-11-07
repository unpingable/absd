# Native TCP MTU advice and grant isolation fixture

This private, opt-in consumer exercises the existing experimental IPv4 stream
v4 interface through actual `Client` and `Session` codecs over bounded local
framed pipes. Its startup capability supplies the NIC. This establishes no
delegated child process or kernel pipe boundary. It changes no transport policy,
kernel ABI, default stream version, DNS, TLS or SSH behavior.

The path has MTU1500. Two explicit grants are already connected before advice
is introduced: target192.0.2.100:7100 to198.51.100.2:42100, and unaffected
192.0.2.100:7101 to198.51.100.2:42101. The target writes1024 bytes, position
`i % 251`; the ordinary Linux peer receives those bytes and holds the connection
open. A separately recorded Linux raw-frame actor derives each ICMP input from
an actual successful target submission. It sends one input and waits for the
native consumed-RX/status acknowledgement before sending another.

The three invalid inputs are a bad ICMP checksum, a checksum-valid wrong quoted
TCP sequence, and a reported MTU equal to the actual submitted IP length. After
each actual returned RX frame, the target's real v4 STATUS must still report
connected, with both sockets present. A fourth, matching raw quotation must
produce the typed terminal `FragmentationNeeded { mtu: 576 }` only for the
target. The old target client must then return `Stale` on read and write without
another service transaction or NIC submission. Prior1024-byte effects are known
to have reached the peer in this fixture; terminal advice does not undo them.

The owner explicitly revokes that target session. The same previously connected
unaffected grant then sends bytes0 through63, half-closes, receives the exact
echo and EOF, and is explicitly revoked. There is no new unaffected grant,
reconnection or replay hidden in this calibration.

Finally, the owner creates a new reservation on the old target tuple. This
reservation never executes CONNECT. The actor sends the exact old matching
quotation again. Actual v4 STATUS before and after that RX must report success
and connected=false, with zero engine sockets; no native TX may occur in the
reserved phase. A grant reserves authority but allocates its engine socket only
on CONNECT. Zero sockets therefore does not establish absence of the live
reservation. The new
reservation has empty submission history. This does not authenticate quotations:
equal wire bytes following a later actual submission can still match history.
The owner revokes the reservation and waits for zero sockets.

All inputs in this fixture are explicitly injected quotations. They are not
evidence of Linux router ICMP generation. The separate genuine lower-MTU router
proof in NATIVE-TCP-MTU-PROOF.md keeps its own attribution and verdict.

`TCP MTU BOUNDARY <KIND> v=1` records export complete successful local TX and
actual returned RX bytes, separate direction ordinals and boot timestamps,
actual request/reply messages excluding the two-byte framing prefix, and owner
events. The framing prefix is actually constructed and consumed. FRAME and RPC
records carry a phase; RPC and grant events carry an immutable pipe slot and
fixture logical label: target1, unaffected2, reserved3. These labels identify
the fixture's distinct Session instances, not durable kernel identities or
exported replacement state. Reusing a tuple does not revive an old Session or
authorize its fenced client.

BEGIN fixes one30-second observation budget. All grants use its remaining
budget and all operations keep the original outer deadline. Private grant
construction timestamps are not exported or inferred. Clock rewind, expiration,
more than256 frames in either direction, more than256 transactions, unexpected
batched controls, or receipt loss fails the fixture. A receipt failure after
submission does not reverse an external effect. The independent oracle binds
each raw input, actual native RX ordinal, v4 STATUS/refusal, complete capture
census, peer receipts, same-grant survival and terminal ownership.

Build with `ABSD_PROFILE=core sh scripts/build-native-tcp-mtu-boundary.sh`, feature
`native-tcp-mtu-boundary-probe`, producing one
`tcp-mtu-boundary-service-probe.elf`. Source construction and formatting are not
runtime evidence. Exact source, executable, controls and result identities live
in the owning lane receipts. Current source preparation is UNRUN.

The formalization consideration is finite correspondence and flow isolation:
disclosed literal negative controls, versioned messages, full byte censuses and
raw independent readback are sufficient for this bounded claim. It establishes
no authenticated origin/history, general PMTU recovery, universal TCP conformance,
physical timing or complete memory accounting. No live replacement is added.
Replacing the owning network service would still require quiescence, fencing
old Session authority and explicit reconstruction; these Rust objects are not
a transfer schema. Remote effects preclude an automatic rollback inference.
Root owns the source/result claim; the steward independently accepts integration.
