# Native static IPv6 datagrams

The NIC holder can configure one static on-link IPv6 address and issue a
dedicated pipe session for one exact peer and local port. smoltcp 0.14 remains
the IPv6, UDP, checksum and Neighbor Discovery implementation. The kernel
continues to move Ethernet frames. No syscall or startup role is added.

`Stack::configure_ipv6` takes a 128-bit address, prefix and nonzero owner-issued
link scope. `ipv6_bind` creates an endpoint for a nonprivileged local port,
unicast on-link peer address/port, and exactly that scope. Unspecified,
loopback, mapped, multicast, self and off-link destinations are refused.
Global unicast, unique-local and link-local addresses are supported by the
bounded address policy. A second configuration is refused; changing addresses
requires a fresh stack. There is no route learned from received packets.

Each of eight IPv6 endpoint slots has four transmit and four receive packet
slots, with at most 1232 data bytes per datagram. This enforces a 1280-byte IP
ceiling without extension headers; it is not routed PMTU support. Successful
SEND means queued locally. Neither NIC submission nor UDP implies receipt.
Small RECEIVE leaves the packet available. Exact peer filtering happens before
delivery; wrong peer/scope bytes cannot select another session's grant.
The ingress wrapper admits UDP from any on-link source to the configured local
address before the endpoint applies its exact peer check. Such traffic can fill
the four-entry receive queue until the owner reads and discards it, delaying
the granted peer within that bounded queue. Exact peer delivery is an authority
boundary, not protection against on-link receive-queue pressure.

## Version 2 messages

IPv4 version 1 retains its existing bytes and consumers. IPv6 sessions use a
distinct version 2 header, prefixed by a two-byte big-endian frame length:

| Offset | Field |
| --- | --- |
| 0 | version = 2 |
| 1 | SEND = 1, RECEIVE = 2, CLOSE = 3 |
| 2 | request reserved zero; response status |
| 3 | family = 6 |
| 4 | sixteen address bytes |
| 20 | four-byte big-endian owner scope |
| 24 | two-byte big-endian port |
| 26 | two-byte big-endian length |
| 28 | SEND data or successful RECEIVE data |

RECEIVE request address/scope/port are zero and length is receive capacity.
CLOSE has every field after family zero. Successful SEND/CLOSE and all failures
have exactly 28 bytes; only TooSmall carries a needed-length detail on failure.
Status 1–11 retains the existing datagram error meanings. IPv4 ICMP status
details are not an IPv6 error representation. Malformed frames execute no
operation. The source tests contain a literal golden header and refusal cases.

One request is in flight. Transfers are bounded to 256 bytes per channel poll;
partial input and blocked output expire at 250 ms. Clock rewind, EOF and pipe
error revoke the session. Deadline and clock checks run after I/O, before any
new request effect. A client with an interrupted transaction fences its owned
transport and never retries an uncertain SEND. The owner closes/reaps a client
whose channel ends; the diagnostic allows a bounded terminal-exit wait.

## Direct Neighbor Discovery policy

The initial ingress policy accepts UDP to the configured local address and
direct NS/NA only. It validates header size, hop limit, ICMP checksum, target,
solicited-node destination and bounded nonzero options. Ethernet address
options must have the Ethernet length and agree with the source MAC. An NA
must concern a currently granted peer, have source equal to target, and carry
no Router flag. These are intentionally stricter direct-neighbor rules, not
general proxy or router Neighbor Discovery conformance.

Router advertisements, automatic address/route installation, DAD, IPv6 TCP,
other ICMPv6, extension headers and fragments are explicitly refused in this
first tranche. Configured addresses must already be assigned uniquely by the
owner. The kernel companion change admits all-nodes and solicited-node MACs;
hardware hash reception can be broader than software delivery, as documented
in the kernel's NETWORK.md. Driver receive-pressure limits remain material.

## Consumer and qualification

`scripts/build-native-ipv6.sh` builds a delegated DNS child and its NIC-owning
parent. The child has no NIC or spawn grant, first checks peer/scope refusals,
then asks for A and AAAA answers over the same IPv6 UDP capability. Answer
family and transport family are independent. The DNS adapter has no implicit
TCP grant; truncation remains explicit until IPv6 stream fallback is provided.
The fixture addresses are fd00:ab5d::15/64 and fd00:ab5d::2, link scope 1.

Engine-pair tests cover bounds, framing, malformed ND, peer/scope refusal,
queue and slot exhaustion, stale generations, clock and link failures.
Independent Linux-kernel UDP/ND and actual native execution are separate
claims and require their own source/executable/kernel/capture identities.
Source formatting or a host test is not native interoperability evidence.
Wrong-peer-IP refusal for received wire traffic is host-tested only; native
wrong-peer-source-IP injection remains unrun. Native malformed request and
wrong peer/scope request-field checks do not establish that wire case.

The IPv6 additions intentionally fence existing IPv4 datagram and stream grants
when IPv6 maintenance observes clock rewind or link failure. The shared DNS
parser also tightens TCP fallback query-header validation and refuses CNAME
plus AAAA data at the same owner as Malformed. These are intended behavior
changes, separately exercised by source-specific host tests.

## Replacement and formalization consideration

Logical link/service identity is separate from the stack implementation
generation. Endpoint references carry instance, slot and checked epoch; close,
link fault and clock rewind fence old references, and later grants never
revive them. Fencing cannot recall emitted traffic. Reconstruction requires
trusted configuration and fresh grants; neighbor state is rediscovered.
No native Rust state is a replacement schema. Any future state transfer needs
an explicit versioned format, conversion/refusal rules, authority reconstruction,
external successor validation, device quiescence and generation retirement.
No post-effect rollback or safe hardware transfer is claimed here.

The S2 decision owner considered a bounded authority/epoch model. For this
additive tranche, explicit checked-generation construction, literal framing
vectors and deterministic state-transition tests are sufficient practical
evidence at their stated scope. They do not prove the engine, hardware DMA,
distributed delivery or every scheduling history. A future replacement model
should include device fencing and external effects before claiming continuity.
Exact source and executed result identities belong in the lane handoff and
independent acceptance record.

Protocol references: [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200),
[RFC 4861](https://www.rfc-editor.org/rfc/rfc4861),
[RFC 3596](https://www.rfc-editor.org/rfc/rfc3596).
