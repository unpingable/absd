# Bounded native IPv6 TCP server

This additive profile is one owner-granted on-link inbound flow. The named
consumer is a feature-declared pipe-only native echo child. Existing IPv6
outbound v2 DNS and HTTPS channels and the IPv4/SSH defaults are unchanged.
All runtime results are UNRUN at this source-design stage.

## State and authority

| State | Construction/effect | Allowed next transition |
| --- | --- | --- |
| Reserved | Original owner grant, instance/slot/checked epoch; no socket or active TCP flow | LISTEN, ABORT, expiry/fence |
| Listening | Exact local IPv6 address/port, peer IP/port/scope filter installed before engine polling; peer NA/transport-flow admission becomes active | ACCEPT after matching handshake, timeout, CLOSE/ABORT/fence |
| Accepted | Actual engine remote tuple checked; one connection, no replacement listener | Bounded read/write, shutdown, CLOSE/ABORT/fence |
| Closing | Application reference spent; only terminal reply and bounded FIN drain within original lifetime | Queue/socket removal, fault/fence |
| Retired | Socket/queues/filter/active TCP flow removed; old epoch never revives | New owner grant with fresh epoch only |

Accept timeout is measured from LISTEN and bounded by the original grant
lifetime from owner construction. ACCEPT does not renew either clock. Link
unknown/down/disabled, clock rewind, expired lifetime and strict framing failure
retire current server authority. No grant or reserved-only grant enables inbound TCP. The pre-existing NIC-owner
configured-address NS-to-NA maintenance policy is separate: it may answer a
valid on-link solicitation before LISTEN and after fence. It is not a child
capability, handshake, accepted flow or cryptographic identity. Active peer NA
admission still derives from current endpoint/Flow activity; other independently
issued consumers keep their own authority.
The strict server channel checks original authority before and after every pipe
read/write, including a pending response. A successful terminal acknowledgement
allows bounded drain only; pipe EOF without that terminal operation discards the
socket and queues immediately. Software fencing cannot recall emitted frames. Fresh same-tuple grants may admit
old delayed packets that satisfy the current filter; endpoint epochs distinguish
local authority references, not physical or authenticated wire generations.

## Explicit framing and literals

Server messages have an outer two-byte big-endian length, then a 28-byte v3
family-6 header: version, opcode, status/reserved, family; 16-byte peer IP;
4-byte owner scope; 2-byte peer port; 2-byte length/count. WRITE alone carries
that many body bytes. Maximum I/O is 1024 bytes; one frame is in flight and
partial frame/pending reply time is 250 ms. LISTEN=32 and ACCEPT=33 are separate
from outbound CONNECT=16. Operations 17 through 22 retain their stream meanings.
Existing v2 framing is not reinterpreted as an inbound capability.

For peer fd00:ab5d::2, scope 1, port 42030, LISTEN is:

```
001c03200006fd00ab5d00000000000000000000000200000001a42e0000
```

Its successful listening reply has outer length 29 and one zero status byte:

```
001d03200006fd00ab5d00000000000000000000000200000001a42e000100
```

A wrong peer port receives a v3/family-6 Denied=2 header containing the original
granted peer, with no body or socket effect. Literal vectors are consumed by
host controls, the native child and the independent proof source.

## Deliberate limits and evolution

Only static same-prefix exact-peer unicast is admitted. No wildcard, backlog,
routed listener, discovery-derived grant, RA/SLAAC, dynamic PMTU, TLS/server
protocol, default SSH/startup change or kernel ABI is introduced. Initial native
proof selects the existing 1500-byte IP MTU/MSS1440 profile explicitly. Scope is
owner configuration, not a wire field; ND does not authenticate the peer.

Logical service identity differs from this Stack instance and endpoint epoch.
Config/MTU, neighbor/timer/socket/queue state and Rust layout are not exported
replacement state. A successor must quiesce/fence, reconstruct validated static
configuration and fresh authority, validate outside the replaced generation,
then commit or refuse and retire the old generation. No live replacement,
downgrade or rollback of emitted traffic is claimed.

Formalization consideration: the finite table states the one-generation
proposition that tuple admission precedes engine effects and original authority
bounds pending I/O and drain. Literal vectors, meaningful state/fault controls
and a full native capture are the chosen correspondence checks. They do not
prove hardware fencing or arbitrary concurrent driver behavior. Root owns source
review and scope; the integration steward owns independent acceptance/promotion.

## Source checks and intended offhost checks

Source authoring includes 28 new host methods using an actual smoltcp pair,
strict pipe state transitions, literal v3 vectors and cached TCP/ND rechecks.
The existing outbound `ingress` predicate and v2 client/channel bytes are
preserved. The new Port fields are initialized in normal and DHCP construction;
one existing ICMP TxToken construction acquires an empty server-rule array.
No old test method is removed. These are authored controls, all UNRUN here.

On the separately admitted Linux VM, run locked/offline ordinary `absd-net`
`--lib --target x86_64-unknown-linux-gnu` tests both with default features and
`--features dhcpv4`, one test thread, retaining JSON harness paths and raw output.
The focused module is `ipv6::stream::server::tests`. Run unchanged IPv4 server,
outbound IPv6/DNS/routed/TLS controls as regressions, plus ordinary SSH tests.
Build the native child then parent using `scripts/build-native-ipv6-tcp-server.sh`
in a fresh source/target tree; retain actual Cargo metadata for both bins,
canonical staged std and exact source/kernel/helper/ELF/ISO/served-wrapper pins.
No host or native result is implied by rustfmt or source readiness.

## Prospective source review corrections

Initial product 64d03679 was source-only and was not accepted by the independent
same-vendor reader (7afc9061): its native parent lacked immediate post-result-read,
post-wait and terminal completion clock checks, and one NS test/doc proposition
contradicted baseline NIC-owner NS maintenance. These are source findings, not
executed failures. Successor source preserves NS maintenance, removes the new ND
egress veto, gates server status observations when no server is active, and adds
actual Client/transact malformed-reply and clock controls. A private completion
clock helper rejects the alternate EOF/normal-wait/empty-drain deadline history.
No runtime result is inferred. Existing outbound cache behavior is tightened only
by pure current TCP/NA authority rechecks: a previously cached frame whose Flow
has since been fenced is discarded. NS maintenance remains admissible. Focused
outbound TCP/NA and ordinary IPv4/no-server status-call controls cover that seam.

The no-server status-observation control also consumes a real TxToken and
verifies the frame was sent without either newly introduced Link status read.
