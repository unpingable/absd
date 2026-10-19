# Native one-shot IPv6 Echo diagnostic

This opt-in source tranche belongs to coordination issue #41. It adds an
actual `ping6_once` pipe-only child and `ipv6_echo_service_probe` sole NIC
owner. All new tests, host builds and native execution are UNRUN. The old
DAD runtime `150270fe` four native PASS and `7de27bc0` default 177 PASS are
exact historical evidence; they do not qualify this successor. Release/U1,
default IPv4/SSH and independent integration acceptance remain unchanged.

The public namespace is `ipv6::echo`, implemented as a child module of
`ipv6::dad` to reuse private ownership without exporting a Stack. Its Owner
retains the entire original DAD Owner, including its guarded Link and active
defense. That owner still holds the only NIC. Nothing moves a Stack out of a
dropping parent. Only the private Echo wrapper can install the one optional
Port admission record or access its one smoltcp ICMP handle. No kernel ABI,
raw client socket, network daemon, general ICMP API or configuration service
is introduced. smoltcp 0.14.0, dependency features and all lockfiles stay pinned.

The fixed profile remains candidate `fd00:ab5d::15/64`, peer `fd00:ab5d::2`,
logical scope 1. DAD acquisition must finish before Echo issuance. The scope
is trusted service-local link identity, not a received field or Linux scope
identifier. Issuance rejects every other peer/scope, has one slot and one
checked epoch, and requires fresh issuer identifier, sequence and nonce.
Zero values/entropy failure refuse. Instance allocation refuses overflow;
there is no reissue within an owner even after closing. A fresh owner uses a
new instance and random correlation; its checked epoch starts at 1 and is
never reused within that instance. References are process-local;
the dedicated pipe supplies actual child authority.

The child gets only pipe read/write handles and existing `SPAWN_NO_SPAWN`.
It receives original start/active stop in trusted startup environment and
checks the same values against the fixed bootstrap before START. Startup
environment is policy metadata, not a grant. It tries a wrong scope first,
requires Denied, then START once, OBSERVE until one result, and CLOSE. It has
no NIC role or ability to choose type/body/identifier/sequence/lifetime.

## Packet admission and engine behavior

The unchanged engine encodes IPv6/ICMP, resolves ND and parses/checks incoming
ICMPv6. Its Ident socket alone matches both Echo Request and Reply and is not
an exact-peer authority check. Port therefore adds a separate private optional
record: peer NA is authorized for ND without a dummy UDP grant, and only one
exact 40-byte Reply from issued peer to configured local IP can reach the
socket. It checks Ethernet destination, IPv6 direct next-header/length,
type 129/code 0, checksum, identifier, sequence and the entire fixed body.
Fragments/extensions, wrong endpoints and incoming Echo Requests remain
refused. With no optional record, the old Port admission result is identical.
The DHCP constructor initializes the new record to None; its behavior is
otherwise unchanged. Existing UDP/TCP peer slots are not consumed by Echo.

The 40-byte Request is type 128/code 0, random nonzero u16 identifier and
sequence, followed by 32 data bytes: ASCII `ABSDPNG6`, u64 instance, u64 epoch,
u64 random nonce, all integers big endian. Request checksum includes IPv6
pseudoheader. A small outer Link checks exact request bytes/endpoints before
the underlying call and marks submission first, including uncertain errors.
It refuses a second application request. The DAD Link still performs actual
pre/post clock/link/RX-loss checks and active defense for every device call.
The one receive packet is consumed only once after actual prior submission;
then the socket and admission record are removed, retaining the spent local
entry solely for bounded framing/CLOSE.

The engine re-encodes received ICMP into socket storage. Its original parser
and independent raw capture establish original checksum validity; checking
only that re-encoded buffer is insufficient. The host integration fixture
uses a separate unfiltered instance of the same pinned smoltcp Interface to exercise
actual automatic Echo response, original receive parsing, ND and socket path.
Production ingress is never widened to make that fixture pass.

RFC 4443 sections 2.3, 4.1 and 4.2 specify checksum, Echo fields and required
responder behavior: <https://www.rfc-editor.org/rfc/rfc4443.html#section-4.2>.
This intentionally outbound-only profile refuses Requests, so it is incomplete
general ICMPv6 conformance. A future owner-policy/rate-bounded inbound responder
belongs to #41. Merely enabling the engine's automatic replies globally would
change authority and traffic behavior; it is outside this tranche. IPv4 and
other existing engine control traffic retain their prior behavior; one Echo
Request does not mean one total Ethernet transmission.

## Fixed pipe schema 1, family 6

Requests are exactly 24 bytes: version, operation, zero, family, peer[16],
scope u32. START=1, OBSERVE=2, CLOSE=3. The same numeric version as IPv4 Echo
does not establish compatibility: its reserved byte must be zero, while this
family byte must be 6 and lengths differ. There is no UDP port field.

```text
START: 01 01 00 06 fd 00 ab 5d 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 01
CLOSE: 01 03 00 06 fd 00 ab 5d 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 01
```

Replies are exactly 64 bytes: version/op/status/family at 0..4; peer at
4..20; scope at 20..24; identifier/sequence at 24..28; instance at 28..36;
epoch at 36..44; nonce at 44..52; boot elapsed at 52..60; four zero bytes.
Only successful OBSERVE carries data. Every error and successful START/CLOSE
has zero bytes 4..64. Error codes 1..13 are fixed by `Error::code`; no native
Rust enum layout is a transfer protocol. Bootstrap is 40 bytes: version/family/
two zero bytes, peer, scope, original start, active stop. Literal request,
bootstrap and observation vectors are authored in the product tests.

Only one Channel may be constructed for an entry. It owns one partial request
and one pending reply, with one transfer per poll. First returned request
bytes use the pre-I/O frame deadline; partial/no-progress continuation and
every pending write are checked after I/O too. Idle None before any first
bytes can remain unarmed, but original owner budget always applies. Child
transactions additionally cap no-progress transfers at 4096 and never retry
START after uncertain I/O. Invalid headers/operations and wrong peer/scope
cannot construct grants or change policy.

Channel checks the exact endpoint and actual owner clock against an existing
frame deadline before entering Interface::poll, preventing dispatch when
expiry is already observed at entry. Interface::poll is not atomic: a receive
or scheduling step may cross the frame limit before later TX within that same
poll. The original DAD stop is separately enforced by Guarded; post-poll
detection retires local state. This does not provide atomic 250 ms network
effect cancellation or recall. The queued-NA/blocked-ACK source regression
targets already-observed expiry; neither it nor its pre-fix trace is executed.

## Lifetime, effects and replacement limits

Unused -> queued once -> possibly submitted -> observed once -> spent/closed.
CLOSE removes network authority before its empty ACK; the original DAD owner
survives only to guard that bounded ACK, then retires. Clock rewind, original
stop, unknown/down/disabled link, changed missed-RX count, device/pipe error,
EOF, frame timeout, explicit close or defense exhaustion drops local owner
queues and prevents later submission. Pending pipe data validates the exact
entry against actual DAD clock/link after every I/O, including final writes.
An old Channel passed a fresh Owner refuses without retiring that fresh owner.

The original invocation starts before DAD/entropy: acquisition <=3 s, one
probe and >=1 s boot observation; active Echo <=8 s within original <=12 s.
Frames are bounded by 250 boot milliseconds and existing active defense/frame/
call quotas remain unchanged. No retry renews these budgets. Boot elapsed is
START-to-observation, including ND, queues and scheduling; it is not a physical
wire RTT or accuracy claim. Result is unauthenticated diagnostic correlation,
not identity, enduring reachability or availability. A full one-packet queue
can prevent a legitimate observation.

An underlying send/write can cross the sampled boundary or return Err after
an effect. The first effect remains possible/irreversible; local retirement
cannot recall submitted/DMA/wire bytes or observations returned to Rust callers.
The synchronous spawn syscall has no established timeout. Startup writes have
per-call min(remaining,1000) boot bounds; NIC receive/defense is not serviced
during these calls. No 1 s defense-response latency or physical 12 s stopping
guarantee is promised. Existing DAD busy-link caps and modulo jitter bias
remain. Missing solicited-node MLD Reports violate the general RFC 4862
section 5.4.2 obligation on snooping links: only the bounded direct unsnooped
profile is supported, not general DAD conformance.

Logical service identity is ping6; instance/epoch identifies one implementation
generation. No exported replacement state schema, authority reconstruction,
live kernel transfer or post-effect rollback is implemented. Successors must
reconstruct neighbor/timer state and authority under explicit issuer rules;
fenced references never revive. Hardware/DMA exclusion and external successor
validation remain separate live-kernel evolution barriers.

Formalization consideration: the finite one-slot state and pipe transitions
are covered by meaningful authored engine/authority/fault/boundary cases,
with explicit clock and non-atomic I/O assumptions. Practical tests and prose
are proportional; no model or execution proof is claimed. Linux-kernel
qualification must later retain complete bounded capture, exact source/ELF/
ISO nesting, DAD/ND, one Request/Reply/consumption, scope denial/no NIC, strict
resource restoration and existing MLD reason accounting. Root owns source
review/storage; steward owns candidate composition/independent acceptance.

Build inputs: opt-in `native-ipv6-echo-probe`; recipe
`scripts/build-native-ipv6-echo.sh` builds child first, embeds exact child in
parent, and leaves external kernel embedding to the admitted build owner.
No default image change or proof runner is included. New host/build/native
execution remains UNRUN until separately admitted.
