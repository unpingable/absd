# Immutable conservative IP MTU

This prospective source tranche starts from selected platform11
`9e90d912368c2e572842ee11da8b2ddfb45c69fd`, tree
`c6dd17c1bd51f6121b81c51c55d01214c949d0aa`. The live consumer is the
explicit routed DNS UDP-TC-to-TCP client and its paired owner, already delivered
at routed source 9ad/a923. Existing issue #41 owns the smaller-path follow-up;
issues #29/#13 retain the authority and native networking context. This is not
RA, SLAAC, DHCPv6, PMTU discovery or an authority-construction mechanism.
The separate f4af advice-order test is absent from this base and is not counted.

`Stack::open_with_ip_mtu(link, config, 1280)` selects the conservative profile.
Only 1280 and 1500 are admitted; an invalid value returns Config before observing
the Link. Existing `Stack::open`, Config defaults, physical FRAME_MAX 1514 and
the DHCP acquisition device 1514 remain unchanged. The private Port advertises
MTU 1294 or 1514 before public smoltcp Interface construction. `Stack::ip_mtu()`
reports that immutable setting. It applies to both IP families in this Stack,
not independently to one peer. There is no live MTU setter.

Whole RX frames exceeding the selected Ethernet limit are counted and refused
before parsing, diversion or copying a slice to the engine. Whole smoltcp TX
emissions exceeding that limit never reach Link::send. The existing physical
scratch bound is retained; an emitter within FRAME_MAX sees its entire requested
buffer, even when the selected MTU is smaller. No shortened frame is transmitted.
The existing link_errors observation/fencing remains and tx_oversize also counts
the local refusal; no kernel error code is invented. rx_oversize records RX
refusal. The direct owner raw_send operation retains its existing Link authority
and bypasses the IP device MTU. This is explicitly not an all-owner-TX bound.

Pinned public smoltcp 0.14 derives IPv6 SYN MSS and effective data sizing from
Interface IP MTU minus IPv6/TCP headers: 1220 for 1280, 1440 for 1500, with options
and the remote MSS able to reduce data further. No vendor patch or per-socket
private field is used. Host controls author actual two-engine, large-window,
bidirectional 3000-byte transfers at each setting, checksum-valid SYN MSS and
all emitted frame bounds. The test requires a full-size data segment in both
directions, so a 1024-byte public stream window cannot hide incorrect sizing.
A separate actual paired-grant same-resolver A/AAAA fallback control at 1280
retains 2 UDP/2 TCP queries, one initial connection and original lookup deadlines.
Additional controls cover invalid settings, exact boundary RX/TX, oversized
whole-frame refusal and the explicitly separate raw-send scope.

The private native build selector `ABSD_ROUTE6_TCP_IP_MTU` accepts 1280 or 1500
(default 1500) before NIC/Stack creation. It does not change the child's private
48-byte v2 bootstrap, endpoint tuples, route, exact Flow ingress, original 12s
owner budget, per-lookup deadline or close/fence retirement. The parent reports
its actual configured MTU. A prospective opted-in 1280 Linux forwarding proof
must bind this build setting, record 1280 on TAP/router egress/peer link, require
guest SYN MSS 1220 and refuse captured packets exceeding the selected IP size.
The old 1500 profile and its historical results remain distinct. Small DNS native
answers establish this consumer and MSS selection, not bulk segment sizing;
that separate claim belongs to the actual large-window host test. All new
host/control/native execution is UNRUN until exact runtime receipts exist.

ICMPv6 advice stays advisory and cannot alter MTU, route or authority. All
transport/ND authority remains derived from the existing exact grants and live
Flows. The native profile still assumes a controlled continuous VM and a path
supporting the configured size; it is not an arbitrary Internet path claim.

## Formalization and generation constraint

Proposition: under the Link physical-buffer contract, a constructed device
never delivers or sends a partial frame to satisfy its selected MTU, and TCP's
public Interface capability determines its advertised/effective MSS. Source
review plus finite invalid/boundary and actual-engine substitution controls
are proportionate for this immutable two-value setting. They do not prove
compiler correctness, hardware DMA, path discovery or all possible protocols.
The exact source/results and remaining counterexamples belong in the lane
receipt; root owns the bounded source/evidence review and the integration steward owns
independent acceptance and promotion.

The MTU belongs to that Stack implementation/configuration generation.
Default construction is unchanged; existing fencing retires its sockets/queues.
No live MTU mutation or state-transfer mechanism is introduced. A future
replacement must explicitly validate/reconstruct this setting in versioned
state with refusal/conversion preconditions. Native Rust layout is not a
transfer schema and an old grant cannot be revived by replacement.
