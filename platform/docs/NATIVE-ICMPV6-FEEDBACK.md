# Complete-packet IPv6 UDP diagnostic observations

Source attempt `b74bdc11-c767-4dae-8fa7-e1b56561fb5a` starts from composed
IPv6/DHCP `aa83b82a924ca0702bc4d854b490c7360e6531ec`, tree
`06d9ab4a77aa7fc431ef706b447951052107dda1`. The registry seals the final source
and tree. Canonical coordination is recorded internally. This source task
executes no compiler, test, protocol, guest, provider or key operation. Source
readiness is not interoperability or independent acceptance.

The current named paths are `ipv6_dns_client` -> `ipv6::dns::Datagram` and
`ipv6_tcp_client` -> explicitly paired `ipv6::dns_tcp::DatagramTcp`. They use
issued exact on-link UDP/TCP grants and smoltcp 0.14.0, without a child NIC.
`Port::fill` previously refused every ICMPv6 error before the engine, admitting
only strict NS/NA. The observation path observes selected errors before that
refusal; it does not admit them to the engine or alter ND, TCP, UDP packet construction,
routes, addresses, MSS, fragmentation or retry policy. Default IPv4/SSH and
accepted default DNS constructors retain their existing behavior.

Producer correction attempt `adaf7b0f-f503-4a2e-8fc1-35adca830fad` follows
actual default-suite failure `3ec5e8c9-b539-4baf-aaca-cffc930a9dbe` (151 pass,
one fail) and focused diagnostic `6bc84cc6-ea12-4f07-8fb4-fb0c49aa7105`
(zero pass, one fail, 151 filtered). The latter used source
`03b287882e30554c13df2be795181d2a57e2e9a5` and retained four complete frames.
The peer's Neighbor Advertisement wrote flags `40000000` into ICMP bytes
4..8; its following type 1/code 4 error retained that same unused word, with a
valid checksum and complete 68-byte quote exactly matching submitted IPv6/UDP.
The strict observer correctly refused its nonzero detail. Both FAIL results
remain unchanged. The initial ingress-filter hypothesis was disproved: this
on-link UDP path reaches the engine, and its NS learned the peer's link address.

The pinned smoltcp error emitter does not initialize that unused word, while
the adapter reuses one transmit buffer across packets. `TxToken::consume` now
zeroes only `min(requested length, FRAME_MAX)` bytes before calling the existing
emitter. This affects the shared IPv4/IPv6 adapter, including default TCP/SSH
and opt-in DHCP users; full net, DHCP and SSH regressions must be rerun by the
resource owner. It changes previously unwritten wire bytes to zero without a
vendor patch, ingress widening, observer relaxation or new packet authority.
The existing oversize refusal, send outcome and successful-submission accounting
remain in their original order. The actual engine-pair regression now witnesses
the earlier nonzero NA flags, later zero unused word, valid checksum, complete
quote equality, and one consumed observation under its original test name.
The temporary failure-context clone is removed; its exact diagnostic source
and retained result remain available. This source task executes no tests.

Formalization consideration for this correction: every bounded frame slice
starts initialized before the pinned emitter supplies its fields. The actual
finite NA-to-error counterexample and regression are proportionate evidence;
there is no claim that clearing a buffer proves general protocol correctness.
The extra bounded initialization does not transfer state, revive authority,
change queue or grant generations, add a clock sample or reorder local send
fencing. It cannot recall submitted I/O, prove physical-time bounds or provide
kernel replacement. Root and the independent reviewer own the decision, with
exact source/result identities sealed in the correction receipt.

`ipv6::feedback::Observation` contains `kind`, `code` and untrusted `detail`.
The profile accepts Destination Unreachable type 1/code 0..6, Time Exceeded
3/code 0..1, and Packet Too Big 2/code 0 with nonzero 32-bit MTU. Other error
forms are ignored. Type 1/3 unused detail must be zero in this deliberately
strict profile. PTB is an observation only: even a nonsensical claimed MTU is
not an admission ceiling, route update, retransmission instruction or validated
path property. No report creates endpoint, route, peer, address or raw-ICMP
transmit authority.

For each of eight issued UDP slots, the owner retains at most four complete
successfully submitted invoking IPv6 packets, each at most 1232 bytes including
its 40-byte IP header and 8-byte UDP header. Thus feedback-capable UDP bodies
are at most 1184 bytes. The ordinary UDP API still accepts 1232-byte bodies;
larger invoking packets continue normally but have no diagnostic record.
Records are allocated on demand, at most 39,424 invoking-packet bytes plus
bounded metadata. A fifth submission evicts the oldest slot cyclically. Failed
Link sends establish no record and clear prior correlation. An Err can already
have submitted a first effect; neither absence of a record nor teardown proves
wire absence, DMA cancellation or rollback.

Only Link::send Ok records evidence. That is a successful local submission,
not delivery. A received error must fit an ordinary IPv6 error packet of at
most 1280 bytes, have exact lengths, no extension/fragment headers, nonzero hop
limit, valid original ICMPv6 checksum, local Ethernet/IP destination, and the
exact issued peer IP and previously submitted destination MAC as source.
Its complete invoking packet, including the UDP checksum and entire body,
must match a record byte-for-byte within 1000 boot milliseconds of submission.
Inner hop-limit changes and router-origin reports are refused. Insufficient,
truncated, trailing, malformed, unknown, unauthorized, stale or unmatched
quotes are ignored. No tuple-only or normalized-checksum match is used.

One pending observation is retained per slot. A later fully matched type 1
replaces unread type 2/3 advice; otherwise the first observation wins and a
later distinct matched report is lost. Every matching identical history
entry is consumed, so one report cannot consume already submitted duplicate
copies repeatedly. A pending record expires 1000 boot milliseconds after
accepted observation, separately from the submitted-history window. Endpoint
close/reissue/fence, observed clock rewind and link or I/O loss clear retained
state. Checked slot/instance/epoch validation prevents cached state transfer
between logical endpoint generations. However, a delayed old quote can match
a byte-identical packet newly submitted after reissue or history consumption.
There is no wire generation or authentication guarantee. On a reused endpoint,
this is a diagnostic about submitted bytes, not DNS query identity.

The new v2 operation is FEEDBACK=4, disjoint from SEND/RECEIVE/CLOSE and TCP's
CONNECT..ABORT range. The issuer-selected session chooses the endpoint; its
28-byte request has version 2, opcode 4, status 0, family 6 and 24 zero bytes.
No child request selects an endpoint or peer. Success has the ordinary header,
22 zero address/scope/port bytes, length 8, and body:

```text
type code 00 00 detail_BE32
```

No observation returns existing Again=6 with zero body. Existing status codes
carry stale/link/refusal/exhaustion outcomes. Unknown or malformed body/status
forms retire the opt-in adapter. A literal full 36-byte Port Unreachable reply
and an eight-byte PTB vector above 65535 are authored golden controls.

Every provided v2 pipe construction path guards a serialized successful
FEEDBACK response, including explicitly paired DNS handlers. The framer captures
the exact endpoint and checked observer fault-generation stamp, validates it
before and after each pending pipe write, and discards undelivered local bytes
on close/reissue/fence/clock/link/I/O loss. The stamp is saved across a completing
write. Fault-generation exhaustion refuses diagnostics permanently in this
Stack; a fresh authorized Stack is required. Custom handlers without an issued
UDP endpoint cannot serialize successful FEEDBACK. SEND/RECEIVE/CLOSE retain
their existing behavior and zero-body CLOSE acknowledgements. The existing
250 ms pre/post frame bounds remain. A straddling write can already have
submitted partial or complete bytes; post-check retirement only prevents later
output. An Observation already returned to a trusted Rust caller is likewise
an external effect, outside the framer's retained-byte custody.

`ipv6::dns::Datagram::with_feedback` explicitly polls this same granted session
before receive. Destination Unreachable type 1 is returned as the terminal
endpoint diagnostic `dns::Error::Ipv6Feedback`, without translation to an
authenticated failure or automatic resend/fallback. Packet Too Big type 2 and
Time Exceeded type 3 are consumed as advice, then the adapter performs its one
ordinary RECEIVE under the same original deadline. They do not end the lookup,
change the packet ceiling, average MTUs, renew a timer, or cause an extra SEND.
The raw Stack/session API continues to expose all three observation types.
Its existing `new` constructor issues no new operation. Default paired DNS behavior is
unchanged; its handler participates in the guard if an authorized caller
explicitly requests FEEDBACK. The raw read-only Stack API consumes one pending
Observation for the exact endpoint. The existing IPv4 feedback framing, 16-bit
MTU detail and admission policy are unchanged and are not reused for IPv6.

Acceptance carry attempt `fb9e264f-d11e-4b25-972e-cd659d7f592d` starts from
accepted tip `013e5d64f6b47781cec178b136ff1f53fcd9cb51`, tree
`909da499b0ee8f654ce4184a30e3cb4ffe6c0813`. It changes only the opt-in DNS
policy above, focused tests and this document. The accepted native result
`658621d9` applies to its recorded bytes; it is not execution of this successor.
All newly authored and modified test methods remain UNEXECUTED by this source
task, and prior verdicts are unchanged.

The eight-byte observation has no quoted DNS ID, history token or original
datagram bytes. Query A can be submitted at boot millisecond 100 and receive a
valid answer at 110; B with a different DNS ID can be submitted at 120; a full
quote of A received at 121 still matches A's retained history. The next opt-in
FEEDBACK can therefore end B with type 1 before B's queued answer is read.
The same limit applies to a CNAME step. This is an endpoint diagnostic, not a
claim that the currently issuing DNS question failed. Draining pending advice
before B cannot exclude an A report arriving after that drain. Distinct DNS IDs
protect ordinary DNS answer matching but are absent from this diagnostic reply.

The current bounded native consumer uses a freshly issued endpoint for its
single DNS question, including its identical bounded retransmission, then
closes it. A caller needing that discipline must acquire a fresh owner-issued
channel; rebuilding a Resolver around the same endpoint does not clear history.
For reused DNS endpoints, callers must accept the documented type 1 behavior or
use the default constructor. This carry does not reject sequential lookups or
CNAME processing to manufacture query isolation, nor silently repurpose reserved
wire bytes. Reusable query-bound terminal feedback needs a separately reviewed
selector/reply design. Even such a design cannot establish authentication or
distinguish a delayed report about byte-identical newly submitted traffic.

The single pending slot is deliberately lossy. A fully matched type 1 report
supersedes unread PTB or Time Exceeded advice so the next feedback read can
fail fast. It cannot replace advice already copied into a pipe response or
returned to its consumer. An unread type 1 retains priority over later advice
or a different type 1; unread advice retains priority over later advice.
Every matched report consumes its exact submitted history, including a report
that loses this selection. Repeating it cannot recover the observation without
a new matching submission. The adapter never promotes advice itself to a
terminal failure. Submitted-history and accepted-pending ages each include exactly 1000
boot milliseconds and refuse 1001; they start at different observations. The
accepted native run needed one DNS retransmission while ND completed, making
that history window operationally relevant. This is a bounded diagnostic
opportunity, not a promise that every qualifying report will be delivered.

Formalization consideration for the carry: the durable local proposition is
that valid type 2/3 advice falls through to RECEIVE without new transmit or
deadline authority, while type 1 remains explicitly endpoint-terminal. Literal
wire observations composed with the actual Resolver, a delayed prior-query
counterexample, terminal-over-advice selection and first-pending loss, and exact age boundaries are proportional
deterministic controls. No endpoint, history, fault generation, framer or
authority construction changes. There is no new exported state schema or state
transfer; fresh authorized construction remains required after retirement.

The follow-up's bounded resolver control supplies repeated PTB and both Time
Exceeded codes through the actual framed Datagram adapter to Resolver. All
three reach the original 3000 ms lookup timeout with exactly two identical
query SENDs and no new write on reuse of the retired channel. Selection tests
require full submitted-packet correlation before a type 1 can replace advice,
consume both matching histories, and retain the first terminal observation.
At source `3ebf8abc71b3864fed3767e8bab5774032e5e1cb`, ordinary host run
`40377f75-e766-418b-b5b6-c4d9ca233236` passed 161 default and 173 DHCP
tests, plus the 17-test SSH suite. The terminal-over-advice control failed as
expected against the earlier implementation. Its 31-member evidence archive
has SHA-256 `26b1c9be4a1dcad8d1cf5b8d2e36c86a1a256c06b6d65f8a850c383598964ff8`.
The new advice-over-advice control covers PTB and both Time Exceeded codes in
both arrival positions, spent-history replay and a fresh matching submission.
Its execution and the matching negative control remain UNRUN until a separately
identified result. The earlier native closed-port run remains attributed to
f593/ed6 only and does not exercise pending advisory replacement.
Already submitted pipe or network effects remain irreversible, and a post-I/O
failure cannot recall them. Boot observations do not establish physical time.
Root owns source review and later execution; a source pass is not acceptance.
Root retains the unique source and minimal receipts through integration and
rollback, with disposition review on 2026-10-18. Any new test substrate is
temporary and retires after its result is in custody and live consumers have
released it; earlier test substrate has already retired.

The actual optional consumer `ipv6_feedback_client` invokes the real Resolver
against exact peer `fd00:ab5d::2%1:42019`, through one pipe grant, with no NIC
or spawn authority. It verifies wrong SEND peer and nonzero FEEDBACK selector
refusal, expects Linux Port Unreachable type 1/code 4/detail 0 before the DNS
lookup deadline, closes, and prints an explicit auth=none observation. Its
sole-NIC owner uses local `fd00:ab5d::15/64`, UDP 7002, an original eight-second
boot budget shared through bootstrap, finite output and exact stop/reap on
failure, then closes the endpoint and requires zero sockets. Build only via
`scripts/build-native-ipv6-feedback.sh`; it uses the existing pinned
lock, runtime, broker and compiler recipe through a new optional feature,
without dependency changes.

Later independent native proof must use a fresh isolated IPv6 namespace/TAP,
normal Linux kernel ND and UDP, no process bound to exact closed 42019, no raw
userspace ICMP responder and no public/routed contact. Record Linux namespace,
address/MTU/IPv6 settings and socket absence, then supply exact prebuilt child,
parent and dedicated kernel ELFs with source/build receipts and unique embedding.
Retain raw whole-boot PCAP and serial: exact NS/NA, guest DNS query tuple/body,
Linux original ICMP checksum, complete quoted packet, matched native error,
wrong-peer/no-NIC markers, normal child/debug exit, and exact process/namespace
cleanup. Reuse the approved first-four destination-reason accounting profile
for unavoidable Linux MLD setup traffic from accepted helper sources
`4a6e7c52124131b828e3ce093d504886d065657e` and
`4f9331e45b61373369914947a8932112fc3b3984`, including the run633db4 sidecar
buffer/evaluated-content equality correction. Retain the unchanged whole
capture and exact source/result identities; adapt census only for this new
ICMP error protocol. Introduce no new tolerance or strict-zero IPv6 rule. Do not infer native malformed/exhausted/
interrupted/fault cases from that positive exchange. Existing accepted IPv6
runners and verdicts remain unchanged; a separate proof runner/dispatch is
required. Source-authored unit cases are not an independent Linux peer.

Primary specifications: [RFC 4443 sections 2.3, 2.4 and 3](https://www.rfc-editor.org/rfc/rfc4443.html)
define error checksum, quoting and upper-layer notification; this profile is
narrower than general ICMPv6. [RFC 8201](https://www.rfc-editor.org/rfc/rfc8201.html)
places PTB in PMTU discovery; this change does not implement that algorithm.
[RFC 8200 section 5](https://www.rfc-editor.org/rfc/rfc8200.html#section-5)
sets the IPv6 minimum-MTU context. No general IPv6/ICMPv6 conformance is claimed.

Future PMTU recovery is a separate proposed design, not a stack-rewrite
requirement. In the locked engine `iface/interface/mod.rs:208` reads device
capabilities at Interface construction and stores InterfaceInner.caps;
`ip_mtu` at 858 uses that cached value. `socket_egress:717` rereads `_caps`
for optional segmentation offload, not the normal TCP segmentation context.
`socket/tcp.rs:2319,2631,2779` derives segmentation and MSS from cached
`cx.ip_mtu()`. Changing current Port::capabilities alone therefore does not
change an existing Interface. A fresh private owner/interface with a smaller
authorized device-MTU policy could reuse the pinned engine's segmentation.
Actual grant reconstruction, shared-owner effects, consumer usefulness and
independent smaller-path proof would need their own bounded source tranche.
Current UDP is already capped at an ordinary 1280-byte IPv6 packet and current
TCP buffers are 1024 bytes; no packet or advertised MSS is rewritten here.

Formalization consideration: the durable claim is limited to issued-slot
selection, bounded full-packet correlation, consumption/eviction and local
pending-output fencing under the actual Link/clock/framer calls. Meaningful
implementation cases cover malformed/wrong/unknown/insufficient quotes,
32-bit detail, eviction and first-pending loss, duplicate copies, stale epochs,
reissue, rewind, link/I/O faults, checked exhaustion, buffered-output fencing,
straddling writes and uncertain first send effects; golden vectors bind the
wire form. Practical deterministic controls and explicit source invariants
are proportional. They remain unexecuted by this task; they do not prove wire
freshness, physical boot-time accuracy, complete capture, compiler provenance
or hardware cancellation. Root and the independent steward own the decision.

Evolution and state: a configured logical address/link and grant identity are
distinct from implementation instance/slot/epoch and fault-generation state.
No retained quote, pending observation, response buffer or fenced handle is
transferred or revived. There is no exported replacement state schema; native
Rust layout is not an ABI. A successor reconstructs fresh authorized grants,
neighbor state and timers, validates externally and may refuse; historical
externally visible effects remain irreversible. Downgrade, hardware ownership
handoff and post-effect rollback are unqualified. This introduces no live
kernel replacement, ABI, broker, service manager or general clock framework.

Root owns aggregate storage and this source worktree's 32 MiB cap. No compiler
target, VM, package cache, capture or key is created here. Retain unique commits
and minimal receipts for integration, independent review and replay; root
retires the exact worktree after those consumers end. Review: 2026-10-17.
Release/main/U1/supported ABI holds remain intact.
