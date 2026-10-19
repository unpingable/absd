# One explicitly activated inbound IPv6 Echo reply

`ipv6::echo_responder::Owner` is an opt-in sole-NIC-owner capability for the
existing direct static profile: candidate `fd00:ab5d::15/64`, exact unicast
peer `fd00:ab5d::2`, scope 1. The native probe's real consumer is a peer's
ordinary `ping -6 -c 1`; no pipe child or raw socket authority is needed.
Ordinary `Stack` and outbound Echo owners still refuse Echo Requests.

The responder keeps its entire private DAD Owner alive. It does not move out
the Stack, issue dummy UDP grants, export sockets or alter kernel ABI. Pinned
smoltcp 0.14 already parses an Echo Request and emits an automatic Echo Reply
in `iface/interface/ipv6.rs::process_icmpv6`. Its existing enabled
`auto-icmp-echo-reply` feature is unchanged. This wrapper bounds admission and
the actual reply submission instead of writing another protocol engine.

Only explicit `activate(fixture_peer())`, after successful DAD, installs the
private Port record. One owner can issue one endpoint, with a checked process
instance and generation. A denied peer/scope does not consume activation.
No request or declaration creates authority. Wrong endpoint identities refuse;
retired owners never reactivate. No general configuration mechanism is added.

| State | Permitted transition |
| --- | --- |
| DAD tentative | Original candidate probe/observation; no application admission. |
| DAD active, inactive responder | Explicit exact-peer activation only. |
| Armed | First valid exact-peer Echo Request becomes the sole immutable correlation record. |
| Request retained | With the peer MAC already cached, smoltcp can generate one matching Reply. With an uncached peer, it sends an NS and drops the Reply; later NA or requests cannot regenerate it or rearm the grant. |
| Reply attempted | Spent before underlying Link send, including uncertain error. No subsequent Reply submission. |
| Reply send returned Ok | A subsequent valid DAD/clock/link check permits one trusted-owner observation. |
| Observed or retired | Record cleared; no rearm, replay or stale observation. |

Incoming request admission requires exact local Ethernet and IPv6 destination,
nonzero distinct unicast Ethernet source, exact issued IPv6 peer/scope, direct
IPv6 next-header 58, nonzero hop limit, type 128/code 0, exact frame/payload
length and valid IPv6 pseudoheader checksum. ICMP length is 8 through 1240
bytes inclusive, so header-only messages and zero identifier/sequence are
legal; the usual Linux 64-byte message fits. Multicast/unspecified/routed
peers, wrong local destinations, extensions, fragments, extra/truncated bytes,
invalid checksums and oversized messages refuse. This does not authenticate
the sender or establish uniqueness from its tuple.

The outgoing Link allows original ND/DAD traffic and the one Reply only.
That Reply must swap the exact endpoints/MACs and mirror the retained
identifier, sequence and entire body, with type 129/code 0 and valid checksum.
Other protocol output refuses and fences this private owner. smoltcp supplies
the packet encoding/checksum. There are no application sockets; one retained
request uses at most 1240 bytes. Existing DAD bounds (128 frames, bounded
calls/receive loops and four rate-limited defenses) still apply. A busy LAN
can force refusal rather than guarantee service. No retry or fair scheduling
promise follows.

The controlled peer must establish ordinary ND with an NS carrying its SLLA
before its Echo Request. The engine learns that peer MAC from ND, not from the
Echo Request's Ethernet header. If the peer skips ND because it already has
the guest MAC cached, smoltcp attempts its own NS and drops the immediate
Reply. The immutable admitted request still consumes the one-shot admission;
`observe` remains `Again` with zero possible reply effects until expiry.
This is a known availability limit, with no hidden retransmission. A future
native proof must explicitly establish this ND precondition and retain the
actual NS/NA before the request; the passing original proof did so naturally.

The corrected default/inactive and active-conflict host cases first warm the
engine through a valid NS with SLLA and witness its NA. They then require no
Echo Reply and no NS targeting the peer, so unresolved-neighbor loss cannot
stand in for admission refusal. Malformed controls include a valid-checksum
seven-byte ICMP message, a self source MAC and type 129 with code 0.

Every check, wait, receive and send still traverses the original DAD Guarded
Link with actual pre/post boot-clock, carrier, disabled and RX-loss samples.
The original invocation budget starts before acquisition, including entropy;
activation does not restart it. Active lifetime is at most 8 seconds within
the original 12 seconds. Rewind, expiry, conflict, missed RX, Link error or
explicit retirement destroys the private Stack/admission and pending local
state. Already returned trusted-owner observation bytes cannot be recalled.

`possible_reply_effects()` counts a marked first submission attempt, even if
the underlying send returns Err. `Observation.submitted_at_ms` instead means
the send returned Ok followed by a valid owner check; neither is proof of
peer receipt. A synchronous Link call or an Interface poll may cross a clock
boundary. Post-call retirement cannot cancel DMA, packets already submitted,
or a physical effect in that interval. No absolute wire-stop or physical RTT
claim is made. There is no physical clock mapping or snapshot rollback witness.

The opt-in native recipe is `scripts/build-native-ipv6-echo-responder.sh`,
feature `native-ipv6-echo-responder-probe`. It builds one NIC-owner foreground
probe, whose READY line is only a readiness observation. A later separately
queued native proof must capture genuine Linux-kernel ND/Echo, exact request/
reply correlation, complete checksums and frame census, exact source/ELF/ISO
binding, normal exit and cleanup; merely printing PASS is insufficient.
There is no new runtime selector or qualification runner here. Native build
and guest execution are UNRUN until explicitly recorded as executed.

RFC 4443 sections 2.3/4.1/4.2 specify the pseudoheader checksum and unchanged
Echo identifier/sequence/data. The bounded exact-peer one-shot policy remains
incomplete general ICMPv6 conformance: it does not provide every node's general
inbound responder obligation. Existing missing solicited-node MLD Reports
limit DAD to the controlled unsnooped link. DAD startup still has synchronous
call/scheduling gaps and biased modulo jitter; no defense latency guarantee
or new async runtime is claimed. Reference:
<https://www.rfc-editor.org/rfc/rfc4443.html#section-4.2>.

Logical service identity differs from its current instance/generation.
Replacement state schema 1 for this tranche is **empty and retired only**:
discard captured request, possible-effect history and old handles; acquire a
fresh DAD owner and explicit owner authorization to construct a successor.
Native Rust layout/Rc state is not a transfer protocol. There is no authority
inheritance, warm-state downgrade or rollback of a reflected packet. Future
transfer needs quiescence, explicit authority reconstruction, successor
validation, external commit/refusal and generation retirement. No live kernel
replacement mechanism is added.

Formalization consideration: the durable proposition is one explicit grant,
one immutable admitted request, at most one possible matching Reply effect,
and no local authority revival after fencing. The transition table and
meaningful parser/engine/fault/clock/queue/generation tests are proportional
for this bounded wrapper; a small finite state model could later verify those
abstract transitions, but would not prove synchronous I/O or hardware effects.
Exact source and actual test results belong to attempt
`da244b28-9dbc-4099-9c73-64f0106f0f0c` and its immutable receipts. Root owns
engineering review/storage; the steward owns candidate composition and
independent integration acceptance. Native Linux qualification remains later.
