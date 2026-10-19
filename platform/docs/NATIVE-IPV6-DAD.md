# Bounded static IPv6 DAD owner

Source attempt `818f2c13-55db-4a96-a402-bb927c935789` starts from core
`5df550ca4ee81f634a00b45a6ce7530e00fe8b8e`, tree
`e8c79af110367829bcf3515ce7ca9692cb21ad7c`. The immutable source receipt seals
its final revision/tree. This is opt-in source development for existing #41;
all compiler, test, protocol, guest and independent Linux results remain UNRUN
by this producer. Default Stack construction, IPv4/SSH, legacy IPv6 ingress,
accepted framing and engine/dependency versions and locks are unchanged.

The named consumer is `ipv6_dad_dns_client`: the existing Resolver and scoped
IPv6 UDP transport perform A/AAAA lookups through one pipe grant, with no NIC
or spawn authority. Its dedicated parent owns the only NIC, the fixed policy
fd00:ab5d::15/64, scope 1, local UDP 7002 and resolver fd00:ab5d::2 port 42010.
`Policy::fixture` has private fields; neither DNS nor ND supplies policy.
The owner keeps both Stack and Channel private and never returns either.
There is one channel issuance, no rebind and no continuation after retirement.

Before any Interface contains the candidate, `Owner::acquire` consumes its
Link, reads fallible health/missed counters and obtains fresh issuer entropy.
The original invocation sample precedes NIC opening and entropy. Acquisition
ends within 3000 boot milliseconds; the invocation ends within 12000. One
random 0..1000 ms initial delay and one fixed NS are followed by 1000 ms of
observation measured after successful local send return. Input is also drained
before the probe and at the observation boundary, under finite work bounds.
The NS uses source ::, candidate's solicited-node destination, hop 255, code 0
and no source LLA option. The candidate has no application socket, child or
normal ND response during this stage. Any valid other-node DAD NS or NA for
the candidate, to all-nodes or the exact unicast candidate/MAC, refuses
activation. This includes valid solicited and unsolicited unicast NA; it is
a conservative refusal policy, not new authority from the advertised address.
An own-MAC reflection is ambiguous
and refuses; MAC equality does not prove a local loopback.

Only successful bounded observation immediately constructs/configures a fresh
private Stack and permits one exact DNS channel. Its active bound is at most
8000 ms from activation and never exceeds the original invocation bound. A
clear observation is unauthenticated and does not prove uniqueness or packet
delivery. There is no atomic wire-empty/activation boundary, stored verdict,
portable permit, address selection, RA, SLAAC, DHCPv6 or route installation.

Pinned smoltcp 0.14 has no tentative-address/DAD state. Its ordinary IPv6
source check rejects :: before ND, and the existing ingress rejects it too.
The optional, disabled SLAAC module tracks router/prefix/route state rather
than supplying DAD. Therefore a private guarded Link intercepts only valid
unspecified-source NS for its exact active candidate. It emits one fixed NA
from the candidate to ff02::1 / 33:33:00:00:00:01, target candidate,
Router=0, Solicited=0, Override=1, own target LLA and hop 255. Existing wire
encoders/checksum implementations construct initialized fixed buffers. There
is no engine fork or child-chosen ICMP body/type/address.

There are at most four defense attempts, at least 1000 boot ms apart. A fifth
request or closer repeat retires the invocation instead of silently claiming
continued defense. A conflicting valid NA for the active candidate also
retires. Own-MAC reflections remain ambiguous. All received frames count
against a 128-frame invocation bound. A receive call consumes at most 16
non-forwarded frames; saturation refuses. Underlying receive-call bounds are
4096 during acquisition and 32768 active, including empty polls, so a stalled
clock with promptly returning calls cannot spin indefinitely. A physically
blocked Link call or unavailable scheduler still needs external supervision;
no boot-domain limit is a physical-time precision claim.

These are also availability limits on a busy LAN: unrelated and malformed
received frames count, so the 128-frame invocation cap or 16 non-forwarded
frames in one receive can refuse a usable address without a duplicate. The
initial delay maps one little-endian 16-bit entropy sample modulo 1001. Even
with uniform input it is slightly biased: delays 0..470 have 66 preimages and
471..1000 have 65. No unbiased-jitter or successful-acquisition guarantee is
claimed; neither limit is relaxed by this carry.

The guard classifies ICMPv6 type before ND-only checks and validates direct
NS/NA lengths, checksum, hop 255, code,
exact target and relevant MAC/destination. Options must be bounded/nonzero;
DAD NS must omit SLLA, and multicast NA must have Solicited clear. Known TLLA
must have Ethernet length and match source MAC. Reserved fields and bounded
unknown options are ignored. Normal unicast-source NS is left to the existing
engine; unrelated ND and other ICMPv6, including short Echo and ordinary-hop
quoted errors, are forwarded in the active phase for the existing Stack to
validate. During tentative acquisition they cannot create application
authority. RA and application
packets never grant addresses or peers. Fragments/extensions and general proxy,
router, multicast membership and Neighbor Unreachability behavior are outside
this direct profile. Existing kernel ed6 admits all-nodes and every
solicited-node MAC already; its broad MTA can increase receive pressure. No
kernel filter syscall or promiscuous mode follows. Direct namespace/TAP is the
initial proof scope; MLD-snooping networks and Enhanced DAD are unqualified.
In particular, no solicited-node MLD Report is emitted. RFC 4862 section 5.4.2
requires membership in the all-nodes and solicited-node groups before probing
and explains the necessary MLD report for snooping-switch forwarding. The
driver's receive MAC filter does not inform such a switch of membership, so
its acceptance of multicast cannot establish that the required probes arrive.
This direct-link profile does not claim general DAD conformance or support for
snooping links. No MLD, RA or multicast-manager runtime is added here.

Clock overflow/rewind/expiry, unknown/down/disabled link, any missed-counter
change, receive failure, uncertain send, quota/work exhaustion or conflicting
address evidence latch retirement. Recovery of the link never revives it.
Every underlying Link and private Pipe operation has pre/post health/time
checks. The pipe adapter samples the actual shared Link after I/O; it does
not trust cached `Pipe::now_ms` or Channel step time. A failed post-check drops
both Stack and Channel, including queued datagrams, partial frames and owned
pending replies. No classic closing socket or old framer survives in an owner.
An output already copied to a caller/pipe is an external effect and cannot be
recalled. Send/receive/write can straddle a check, and an Err can have a first
submitted effect; retirement makes no wire/DMA recall promise. Fixed defense
attempts reserve quota before submission and never retry uncertain sends.

Native bootstrap schema 1 is exactly 40 bytes: version 1/reserved 0 at 0..2,
fixed peer IP at 2..18, scope BE32 at 18..22, port BE16 at 22..24, original
start BE64 at 24..32 and active stop BE64 at 32..40. Its literal source cases
bind these bytes and refuse wrong policy, overflow, rewind and late stops.
Metadata describes construction policy and budget; pipe/startup grants supply
authority separately. This is not exported replacement state or a kernel ABI.
The child bounds partial bootstrap reads before parsing, validates the original
start/stop, and uses a private pre/post boot-budget pipe around every refusal,
DNS and CLOSE transaction. Parent startup/result/wait/drain paths sample the
same original budget and current owner health. On close, application authority
is retired before bounded terminal reap/drain under the original total budget.
Every post-spawn failure still stops/reaps the exact child; no NIC/spawn copy
is delegated. Finite child output is capped at 4096 bytes. No daemon is added.

Startup has a concrete defense-service gap. After activation, the parent calls
synchronous `spawn_image_raw` and then two `write_within` operations for the
startup record and 40-byte bootstrap. The spawn wrapper and current ed6
`syscall_spawn_image_inner`/`sched::spawn_image` path have no timeout argument
or established duration bound. Each write requests `min(remaining, 1000)`
boot ticks and transfers at most 256 bytes; health/time checks follow return.
Those checks do not receive packets. The sole NIC owner does not process DAD
while blocked there or in other synchronous work. There is no upper bound of
one second on defense latency, and no finite startup-response latency follows
without bounded syscall/scheduler return assumptions. The 1000 ms defense
rule is minimum spacing between allowed attempts, not a response deadline.
The 3/8/12-second guards refuse continuation when time is next observed;
they cannot preempt a blocking call or recall an already submitted effect.
The four original native cases inject active DAD after the first DNS query,
so they do not qualify startup defense. This source carry documents that
limit rather than adding asynchronous/kernel scheduling machinery.

Source cases include literal NS/NA and bootstrap vectors with an independent
checksum fold, inactive acquisition, duplicate at the final observation,
simultaneous DAD/own reflection, malformed and valid unknown/reserved fields,
entropy/start failures, uncertainty and receive straddling, stalled-clock/work
refusal, active quota/rate/conflict/counter loss, no revival after recovery,
blocked/partial/final writes crossing the bound, actual link resampling despite
a stale pipe clock, wrong-peer refusal and fresh-owner stale-output isolation.
A composition case drives real Stack/Channel/Resolver A/AAAA traffic after DAD
using an explicitly synthetic ordinary peer fixture; it is not independent
Linux or native proof. All cases remain UNEXECUTED here.

Later Linux qualification must retain exact source/build/ELF/ISO, whole raw
capture and serial. Cases: unused candidate reaches the delegated DNS consumer;
a Linux-assigned duplicate emits real multicast NA and prevents activation;
a simultaneous Linux tentative address emits real :: NS and is refused; an
active-owner Linux DAD attempt receives the fixed NA and Linux reports
`dadfailed`, while DNS still completes within policy. The DNS fixture can gate
its response on that kernel witness; no extra parent hold API is necessary.
Include malformed/fault/uncertain effects separately without inferring them
from the positive Linux result. Existing first-four Linux MLD accounting and
cleanup predicates require a separately reviewed runner; none is added now.

Primary sources: [RFC 4862 section 5.4](https://www.rfc-editor.org/rfc/rfc4862.html#section-5.4)
sets tentative-address sequencing and duplicate observations;
[RFC 4861 section 7.1](https://www.rfc-editor.org/rfc/rfc4861.html#section-7.1)
sets valid NS/NA checks, and section 7.2.4 supplies the fixed active response.
[RFC 7527 section 4](https://www.rfc-editor.org/rfc/rfc7527.html#section-4)
explains enhanced loopback discrimination; this tranche instead refuses the
ambiguous case. Implemented from specifications and existing first-party
patterns; no third-party source, dependency or licence identifier is imported.

Formalization consideration: the finite candidate -> observed-clear -> active
-> retired transition requires application submission to have an authorized
active candidate and a currently healthy observed budget; fixed defense also
requires exact DAD input and remaining quota. A latched fault prevents later
submissions. Practical transition/byte/fault tests and explicit pre/post source
invariants are proportional here; a small bounded transition model remains a
useful future check, not a proof already obtained. Assumptions include truthful
Link/boot/counter reads and bounded I/O returning; counterexamples include
straddling effects, packet loss, duplicate MACs, missed multicast and delayed
wire observations. Root and independent steward own the decision.

Evolution: stable logical address/link policy differs from the current private
owner/Stack/endpoint generation. No internal Rust layout is transferred or
serialized. A successor must fence/drop old channels and queues, reconcile sole
NIC custody, reconstruct authorized policy and repeat preflight. A saved clear
result never rebinds fenced handles. Current static DMA/disabled-for-boot driver
state does not prove quiescence, safe live kernel hardware transfer, rollback
of wire effects or generation retirement. Release/main/U1 holds remain.

Build only with `scripts/build-native-ipv6-dad.sh` on the resource owner's
admitted compiler host. It builds the new optional child and parent with pinned
recipes and unchanged locks; no default image switch follows. Source allowance
is 32 MiB under root's aggregate S2 storage admission. No target/image/capture,
VM/provider/key or native runner is created by this source task. Preserve unique
commits and minimal handoff receipts; root retires this exact worktree once
integration/review/replay consumers end, with custody review on 2026-10-17.

## Steward composition carry

Attempt `9826e069-b438-4168-9561-5a46a2f90bc6` follows the steward's
`20261016T233446Z` ACCEPT_WITH_FIXES for runtime `150270fe` / proof `1fc67f54`.
A separate branch preserves those exact identities and all four old native
PASS results. The successor changes only the private ND classifier, its
source tests and this owning document; proof criteria, kernel, engine,
dependencies, default stack and SSH are unchanged.

Four new host methods cover short non-ND forwarding versus truncated ND,
unicast candidate NA before the probe and at the final observation, valid and
malformed unicast NA in both phases, and actual active Owner/Stack/v2 pipe
consumption of quoted Port Unreachable, PTB and Time Exceeded. The last case
uses a real successfully submitted datagram and existing full-quote observer,
not only a classifier label or a supplied FEEDBACK reply. It does not depend
on whether a later DNS adapter treats PTB as advisory. The peer is a synthetic
host fixture, not Linux qualification. Expected DAD methods are 25; full net
counts from source are 177 default / 189 DHCP, with 17 SSH. All host tests,
builds and native execution of this successor remain UNRUN.

Formalization consideration: type separation preserves non-ND traffic for the
existing stack's validator, while fully validated target NA conservatively
retires tentative or active state. Strict NS/NA checks and every existing
budget/fault latch remain. Practical composition, malformed/phase controls and
direct source comparison are proportional; no formal model or execution proof
is claimed. Startup blocking, absent MLD reports, busy-link refusal and biased
jitter are explicit counterexamples to broader timing/availability/conformance
claims. No exported state schema, authority reconstruction, live transfer,
fenced-handle revival or post-effect rollback is introduced. Root owns source
review and storage; the integration steward owns candidate composition and
independent integration acceptance. The old clear observation and old native
PASS never authorize or qualify the successor automatically.
