# One static IPv6 peer route

The NIC holder may call `configure_ipv6_route(routing::Route { router, peer })`
once after `configure_ipv6` and before any active IPv6 grant. `router` is one
usable unicast address inside the configured local prefix, distinct from the
local address. `peer` selects one off-link IP, transport port and exact nonzero scope.
The engine receives an exact `/128` route, not a default route. Invalid policy,
an active grant, duplicate configuration or a full engine route table is refused
without installing platform route state.

This is an opt-in extension of the live `Stack::ipv6_bind` → v2 `Session` /
`Channel` → `ipv6::dns::Datagram` → `dns::Resolver` path. Existing manifests still
pin smoltcp 0.14.0. Its public `Routes::update` already installs static routes;
`InterfaceInner::route`, `lookup_hardware_addr` and `process_ndisc` implement
next-hop lookup, NS/NA and link-address caching. No engine source is modified.
Existing on-link configuration and framing remain the default. The qualified
fixed DAD/Echo owner constructs its own private, fixed policy and receives no
route configurator; this change does not widen that profile or claim its DAD
results for a new routed invocation.

The configured route grants no endpoint by itself. Only an owner-issued UDP
grant for that exact `Address` enables a local port, and ND admission substitutes
the configured router for the logical off-link peer while that grant exists.
A valid NA may carry the Router flag only for this explicit current next hop.
Checksums, hop limit 255, direct source/target equality, destination and link-layer
options retain the existing ND checks. RA, redirect, proxy NA, automatic address
or route selection and unsupported extension/fragment paths remain refused.
ND supplies unauthenticated link delivery information; neither its source IP
nor its MAC proves router identity. Incoming off-link UDP must match the exact
peer IP and source port and a currently granted local port before engine entry.
The engine then validates the UDP checksum. On-link UDP retains its existing
broader ingress policy and four-entry receive queue until exact-peer reads.

UDP data remains at most 1232 bytes, so an ordinary packet fits IPv6's 1280-byte
minimum MTU. Success still means local queue acceptance. Missing router ND
causes bounded consumer timeout; it cannot authorize another router or direct
ND for the off-link peer. The original UDP-only consumer still refuses TCP fallback. An explicit paired
TCP grant for the exact configured peer is described in NATIVE-IPV6-ROUTED-TCP.md;
it requires a verified 1500-byte path with MSS 1440, without routed PMTU support.
DNS TC therefore returns `dns::Error::Truncated` through a UDP-only transport;
it neither constructs a TCP grant nor restarts the lookup deadline. Existing
ICMPv6 feedback correlation remains unchanged and does not imply general router
error or PMTU processing.

The route is immutable configuration for this Stack generation. It has no
independent lease and does not renew endpoint or caller deadlines. A trusted
owner still bounds the invocation and revokes its channel at its deadline;
the existing 250 ms partial-frame deadline is not an invocation lifetime.
Close, channel revocation, clock rewind and link fencing discard queued UDP
state, remove current router/port admission and leave all old endpoint epochs
stale. Recovery requires fresh owner-issued grants; configuration may remain,
as the configured local address already does. There is no delegated route
administration, replacement API or traffic-derived authority.

Nine authored host methods exercise the actual engine's next-hop NS, Router NA,
maximum-size routed UDP, exact ingress failures, absent router, close/fault/clock
fencing and a real framed Resolver A/AAAA consumer. A matching truncated DNS
fixture explicitly verifies no TCP submission. Fixtures are controlled packet
and pipe implementations, not independent Linux, native guest or physical
routing evidence. All new host/build/native execution is UNRUN at the initial
source freeze; later receipts identify actual results separately. Original
Echo, DHCP, TCP, SSH and failed qualification records retain their identities.

The bounded authority proposition is that immutable owner configuration admits
only the exact off-link UDP tuple while a current endpoint exists, and fences
remove that admission without reviving references. Focused engine/consumer tests
and exact source review are proportionate here; they do not prove all ordering
of external effects. A future formal model could cover bind/close/fence and the
immutable route state independently of ND cache behavior. No Rust layout is an
exported replacement schema. A successor must reconstruct authorized routes and
fresh grants, re-resolve neighbors, validate outside the old generation and
retire it; already submitted datagrams cannot be recalled, and downgrade after
such effects is not an inverse operation. Kernel ABI, hardware transfer and
live replacement mechanisms are outside this tranche.
