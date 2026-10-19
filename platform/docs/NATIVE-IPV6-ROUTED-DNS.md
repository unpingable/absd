# Native DNS through one explicit IPv6 router

This opt-in development consumer constructs the static routed UDP capability
from `ddb3ac0f` without changing its network core. `ipv6_route_service_probe`
owns the NIC, one static local address `fd00:ab5d:1::15/64`, one router
`fd00:ab5d:1::2`, and one exact off-link peer `fd00:ab5d:2::9:42010` in
service-local scope 1. The local UDP port is 7002. The route is `/128`, not a
default route. Neither packet traffic nor the child can issue or alter it.
The separate fixed DAD owner is untouched. This controlled static construction
does not run DAD, SLAAC, RA, DHCPv6, routed TCP or path-MTU discovery.

The child `ipv6_route_dns_client` receives only startup/request/reply/result pipe
handles. `SPAWN_NO_SPAWN` narrows construction and no NIC handle is copied. It
checks absence of a startup NIC role and refusal of NIC information on its pipe.
Three actual v2 transactions ask for a wrong peer IP, scope and port; each must
return the exact empty Denied response. It then runs the existing Resolver A
and AAAA lookups with entropy-issued IDs. DNS supplies controlled fixture answers
192.0.2.9 and 2001:db8::9, without claiming DNS authenticity. A TC reply still
returns Truncated through this UDP-only transport; no TCP grant is constructed.

The parent's private startup schema is version 1, 48 bytes: `[1,6,0,0]`, exact
16-byte peer, scope BE32, port BE16, six zero bytes, original start BE64 and stop
BE64. Stop is exactly start plus 12,000 ms and fits signed engine time. A shared
literal golden and every-byte substitutions qualify this two-binary schema.
Startup environment carries the same start/stop before the bootstrap read;
bytes alone are not grants. Scope is the owner-issued interface identity, not a
packet or host interface index. Existing delegated requests remain v2 unchanged.

One private Budget is shared among the parent's link and pipe wrappers and its
cleanup path. Parent and child enforce the same original absolute budget. Each
wrapper checks actual boot time before and after I/O, retaining rewind/expiry as
terminal. The parent also reads current NIC flags/missed counter around I/O and
latches any unexpected Link or pipe error. A possible first send/write effect
cannot be recalled; after a latched failure no later application submission is
allowed. Every Link::send/receive is individually guarded, including inside an
engine poll. No private engine rewrite or serialized packet mutation is used.
Stopping/reaping an owned child is still allowed after application expiry;
retirement uses bounded existing kill/immediate-wait calls, never a new grant.
These fixture wrappers are not a new supported network-service or kernel ABI.

Before the resource baseline, a positive-length read of inherited ordinary stdin
must return empty EOF within 1,000 ms and the original invocation budget. This
matches the known empty, non-live init sequence: close removes the writer's
handle entry before waking the EOF reader. It establishes retirement of those
known launch temporaries, not general global quiescence or identification of a
historical handle. The reader stays open. The parent takes real before/after
kernel process, handle, pipe and Cell snapshots, reaps its child, revokes all
UDP endpoints and requires equality of those four resource counts. Physical
frame counts are printed but are not an allocator high-water restoration claim.

Native controls are separate from the Linux wire proof. Before polling any
queued fixture datagram, the service proves one off-link bind is Denied without
its route; then it installs the route and exercises nine malformed v2 Session
requests, three exact-peer refusals, 1233-byte refusal, a four-packet queue and
eight-endpoint ceiling, close/rebind stale references, and queue-free cleanup.
Those Session calls execute in ABSD but are direct service calls. Two additional
controls use real kernel pipes: a partial prefix followed by EOF, and a retained
writer beyond the existing 250 ms frame deadline. Both retire the channel and
permit fresh owner-issued port binding. Every fixture pipe creation, duplicate,
read, write and Channel operation uses the same pre/post invocation guard. The
deliberate frame-expiry wait must fit the remaining original budget or the
fixture refuses; a later fixture never starts after expiry. The deliberate wait
uses 252 raw PIT ticks, since 251 ticks can floor to 250 boot milliseconds; the
Channel criterion remains its original 250 ms. This corrects an unexecuted
fixture measurement in source e128, not a timer or protocol change. Handle cleanup is
still permitted after a boundary. These are not killed-child or malformed
IPv6/ND packet tests. The delegated child's three denied requests are actual
framed pipe operations. Unexecuted wire/clock/device/child-interruption cases
must stay explicitly UNRUN in later qualification results.

Before its first Stack poll or child activation, the private fixture waits at
least 1,100 observed boot milliseconds under the same original guard, with a
128-call limit. It emits the observed interval. This accounts for the local
QEMU e1000 initial receive setup before the first NS can elicit Linux automatic
NA; no Linux response is delayed. It assumes continuous VM execution, supplies
no host/boot clock mapping or hardware readiness guarantee, and cannot renew
any budget. Actual full captures and receive success remain authoritative.
The existing fixed DAD owner and network core are unchanged.

Build with `scripts/build-native-ipv6-route.sh`; it emits the exact child and
parent ELFs. Root Cargo features/bins and its sole verify-inputs manifest pin
are updated together; dependency versions and locks are unchanged. The canonical
network core, fixed DAD/Echo consumers and prior proof verdicts remain intact.
The private fixture module has three authored host methods; native compilation
and all new execution are UNRUN at the initial source freeze. Later receipts
name actual source/build/proof identities and results separately.

Qualification must use an owned Linux router namespace, a separate Linux DNS
peer namespace, and a veth connecting them. Linux IPv6 forwarding and routing,
not an application forwarder, carry the guest UDP to the exact peer. Capture
both the guest TAP and peer veth, compare complete UDP bytes and addresses with
a one-hop limit decrement, require real ND and independent AF_INET6 socket
observations, retain the entire capture census and exact child→parent→kernel→ISO
buffers, and restore namespaces/process groups. Normal Linux MLD stays enabled;
the ed6 first-four reason profile remains a bounded compatibility statement,
not synchronized NIC/capture timing or MLD-snooping support. A routed native
claim awaits that actual qualification; source and host results do not imply it.

The authority proposition is bounded to one immutable owner route and current
checked endpoint epochs, one child channel, original time bounds and explicit
retirement. Shared codec vectors, focused host/native cases and exact source
review are proportionate here; none proves all external transition histories.
The logical router/peer identities are distinct from this process implementation
generation. Rust layouts, Rc state, neighbor cache and counters are not transfer
schemas. A replacement would require explicit versioned exported state,
authorized configuration/fresh grants, external successor validation and refusal
on missing state or authority; fencing never revives old references. Submitted
packets cannot be rolled back, and downgrade is unqualified. No hardware/DMA or
live kernel generation handoff is implemented by this fixture.
