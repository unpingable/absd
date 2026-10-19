# Positive native responder evidence

This prospective successor is source attempt
`f8a7a80e-1135-4bc3-a4e4-9024bd6c9d96`. It requires runtime
`e5651789733d349ec73770737495c0a4e107267a`, tree
`55c31626ed097cf282cd820a0337d4f451d3d178`; lane kernel remains
`ed6a15ea7c7c999422e1e294e139b6119619b06c`, tree
`5c3834dcdb8cf393c86bc0e436ae62c7cda67af5`. The e565 changes are tests and
documentation only; its 18 corrected host methods remain UNRUN after two
automatic source-transfer refusals. All 25 successor artifact controls and
all successor native execution are UNRUN. Source authorship is not a pass.

Frozen proof ed126 / runtime 3cd already passed one real Linux ping in f6d7,
with complete naturally established NS/NA before Echo; that source/result is
unchanged. Its earlier host coverage was 17 focused, 213 default, 225 DHCP
and 17 SSH tests, and its 21 artifact controls passed at 6bcd. Neither that
coverage nor the original cache failure and a453 15/2 fixture failure is
relabeled as an e565 result. Steward F1 identified vacuous older default/
inactive refusal assertions; the corrected warmed oracle remains to execute.

The sole case is a genuine installed Linux `ping` process and its kernel
ICMPv6/ND implementation consuming the explicit native responder. No synthetic
packet sender or userspace Echo responder is launched. The installed ping ELF
is read once, copied byte-identically into the fresh case and executed there
as namespace root; no ambient setcap or privileged service is needed. Its
input/copied identities, version, argv, output and normal exit are retained.
The exact invocation uses IPv6, numeric output, one packet, two-second reply
wait, three-second overall ping bound, 56 data bytes and source
`fd00:ab5d::2`. No public network is contacted.

One fresh UUID namespace/TAP has only `fd00:ab5d::2/64`, MAC
`52:55:00:00:02:02`, MTU 1500, no generated address, RA/autoconfiguration,
forwarding or routed policy. Separate actual iproute2 link/address JSON and
exact before/after sysctl/routes/TCP-UDP inventories are retained. Those socket
inventories do not prove absence of raw sockets: the installed ping is the
intentional ICMP consumer, and process construction is the authority evidence.
QEMU uses one TCG CPU, explicit RDRAND, 256 MiB and guest MAC
`52:54:00:ab:5d:15`. Every process group and namespace is owned by this run.

Ping starts only after the collector decodes the actual complete native READY
line from contiguous kernel hex-framed stdout. The exact raw prefix hash and
native stop sample are retained and checked against terminal serial; a partial
line, missing READY or already completed service cannot establish readiness.
This is scheduled observation, not synchronized native/host physical time.
The original owner still checks its own boot clock and lifetime on every
applicable Link effect. No child selector is added.

The successor then explicitly asks the Linux kernel to establish the neighbor
before sending any application Echo. The fresh namespace must have no entry
for the guest. `ip -6 neigh add <guest> dev <owned-tap> use` requests dynamic
resolution; it supplies no cached MAC and emits no synthetic userspace packet.
Within a three-second observed bound, the runner requires both Linux's exact
guest/MAC/interface `REACHABLE` state and complete captured guest DAD, Linux
NS with SLLA, and guest NA, in that order, with no Echo or unexplained frame.
A successful control command, configured MAC or incomplete packet is not
proof. The exact kernel JSON, command and observed capture-prefix hash enter
an evaluated semantic fact and the ping launch record. That prefix must match
the final full capture and its witnesses must still parse identically.

This matters because pinned smoltcp drops an immediate automatic Reply when
the peer MAC is uncached. A later NA cannot regenerate it or rearm this grant.
The new fixture deliberately establishes the precondition; it does not alter
that production behavior or hide a lost first reply. The iproute2 `use`
semantics are documented in the upstream
[ip-neighbour manual](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html).
Actual installed-kernel/iproute2 behavior must still be executed; unexpected
JSON/state or missing capture fails the fixture. Control calls can straddle
the observed bound; post-call rejection cannot recall their ND effects.

Every original PCAP frame is retained. The predicate requires exactly one
guest tentative DAD NS, before any ordinary candidate-sourced traffic; genuine
Linux NS and guest NA before the Echo Request; one 64-byte incoming Request;
and one later outgoing Reply with the exact id/sequence and all 56 body bytes.
All Ethernet/IP endpoints, direct headers, exact lengths, IPv6 pseudoheader
checksums, hop limits and ordering are checked. Linux ping uses sequence 1;
its identifier may be zero. No native generation/nonce/authentication claim
is invented. Raw ping must exit zero and independently report one received
Reply with the correct peer/sequence, not just a native PASS label.

The native terminal line must match captured id/sequence/64-byte size, report
one possible reply effect, owner sockets zero and `auth=none`; the submitted
boot sample is before its original stop. QEMU exits normally with status 3,
the responder process exits zero, no child is spawned and kernel terminal
frames/processes/cells/pipes and block counters are zero. There is no global
before/after handle census. No default-off, malformed/off-peer, duplicate,
interrupted, exhausted, clock/link or uncertain-effect native case is claimed.

The unchanged hash-pinned `native-ipv6-accounting.py` supplies full PCAP decode,
ND/MLD and literal ed6 destination policy. A first-party reason evaluator is
adapted from the accepted reason profile: at most four exact logged refusal
reasons, enough compatible captured destinations, zero missed/TX refusal/error
counters, no refused protocol peer and no unexplained frame. All MLD prefix
frames remain. Serialized sidecar equality and evaluated-buffer hashes remain
required. There is no deduction, tolerance or strict-zero reclassification of
historical IPv6 captures, and no unique frame-to-DMA assignment is asserted.

Build receipt schema `absd-native-ipv6-echo-responder-build/1` pins clean exact
runtime/kernel revisions/trees and full canonical source tar hashes. Runtime
tar is 22,599,680 bytes,
`a44057ddc682ef0fe8d66a8d5396f3dc5a57d582194f92213e68213f6daec06c`.
Kernel tar is 11,417,600 bytes,
`568ac7c029d9d8e6e101519b1341c2e860300cb7dded1e65ea526efaa731212e`.
The outputs object has exact `parent`/`kernel` byte/hash pairs. Actual build
commands include the unchanged native responder script and kernel
`external-build` with exact parent and empty external input/expected paths.
Logs and a toolchain receipt are bounded/hash-bound and retained. The parent
must occur once in the kernel. Actual ISO9660/Rock Ridge critical extents for
kernel and GRUB configuration must match the exact retained buffers; finding
an arbitrary substring is insufficient. This is source/build correspondence,
not a proof of compiler correctness.

Case timeout is 10 through 180 seconds (default 120), with 45 seconds of
remaining lease margin; the enclosing durable execution uses the stricter
original resource fallback and finite unit. PCAP is bounded to 2 MiB/256 full
frames, serial/logs to 8 MiB each, ISO to 128 MiB and scratch disk to 2 MiB.
Fresh result directories and once-written semantic facts are required.
The evaluated mapping survives `finally`, including canonical cleanup bytes;
final sealing compares all evaluated inputs and facts, raw buffers and proof
inputs. Complete original source/ELF/ISO/capture/serial/ping evidence is retained.

All original PGIDs are checked even after leader exit. Any termination needed
by cleanup fails this positive case, including TERM; residual/unknown groups
or namespace state also fail. Namespace creation is recorded before the
mutation, and exact absence is reconciled after timeouts. No unrelated
processes, routes, host interfaces or other consumers' scratch are changed.
Durable supervision/checkpoints, resource dependency release and VM/key/PKI
teardown are separate owning orchestration, not properties of this runner.

Artifact controls are deterministic substitutions of packet/serial/build/ISO/
fact inputs, not packets delivered to ABSD. They must actually run before
native execution; source authorship alone is UNRUN. Host artifact execution
and actual native result identities belong in the owning immutable receipts.
Cross-vendor candidate review and steward acceptance remain separate.

Formalization consideration: the finite positive proposition binds exact
constructed inputs to checksum/correlation/order/normal-exit observations.
Practical full-buffer controls and prose are proportional. No formal model,
sender authentication, physical clock conversion, atomic cancellation,
general IPv6 conformance, live state transfer or post-effect rollback is proved.
Replacement needs fresh DAD/owner authority and external successor validation;
fenced generations never revive. Root owns engineering/storage; steward owns
candidate composition and independent acceptance.

Creator/root retains minimal source/result/hash pointers and exact native
replay inputs through first native handoff/composition disposition, review on
2026-10-17. Reproducible source/build/ISO scratch retires after custody and
consumer/mount/hardlink/backing checks. No new provider/key/lease is created.
