# Scoped outbound IPv6 TCP source tranche

Issue #41 continues static on-link IPv6 UDP with outbound TCP. This source
is based on platform d6e2f50ff590f7c7a7faf2997f30890d5aacf042. It has no
native interoperability verdict until its exact executable runs against an
independent Linux kernel peer. The preceding UDP qualification is separate.

The NIC owner constructs `ipv6::stream::Grant`: local nonprivileged port,
exact 128-bit peer address/port, the configured nonzero interface scope,
connect timeout 100..10000 ms, and lifetime up to 60000 ms. Both endpoints
must be usable unicast on the owner-configured prefix by default. The separate
explicit routed profile in NATIVE-IPV6-ROUTED-TCP.md permits only the installed
exact route peer under its verified 1500-byte path condition. No route or grant is
derived from traffic. Grant reservation emits no TCP contact; CONNECT creates
the engine socket and its exact ingress tuple. The eight-entry table retains
closing sockets until bounded retirement, and checked instance/epoch values
make vacated references stale. Link refusal and clock/deadline failures stop
application I/O. Fencing drops local queues and cannot recall emitted bytes.
Graceful CLOSE may drain previously queued bytes only before the original
grant expires and while its clock remains monotonic. Closing sockets retain
ACK/FIN ingress until retirement. At expiry or rewind, maintenance immediately
removes a closing socket, discarding its queued application
bytes with no terminal-reset opportunity. Repeated maintenance cannot rearm
or retain a removed socket. Live-entry maintenance errors keep the existing
bounded reset opportunity unless separately fenced. A spent reference stays
stale throughout closing.

This tranche uses the existing Ethernet link with IP MTU 1500. smoltcp emits
its own unchanged IPv6 SYN and MSS 1440 with its own checksum; no serialized
TCP packet is modified. TCP ingress permits ordinary matching IPv6 packets
up to 1500 bytes. Each native stream has 1024-byte TX and RX buffers and
1024-byte I/O operations. The smaller buffers impose backpressure, not a
claim of a smaller path MTU. UDP retains its separate 1232-byte data/1280-byte
IP ceiling. Qualification must record that the Linux peer interface MTU is
1500. Smaller paths, ICMPv6 Packet Too Big, path-MTU/MSS adaptation,
fragments and extension headers remain later tranches. This is not mature
Internet path support.

The client receives an owned pipe, not a NIC or smoltcp socket. Version 2
uses the existing 28-byte scoped header: version, opcode, status/reserved,
family 6, address bytes 4..20, scope BE32 at 20..24, port BE16 at 24..26,
length BE16 at 26..28. Stream opcodes 16..22 keep their existing operations:
CONNECT, STATUS, WRITE, READ, SHUTDOWN_WRITE, CLOSE and ABORT. Every stream
request and response identifies the fixed granted peer; bytes never select
another endpoint. Status has one byte of connected/write-closed/peer-finished
bits. WRITE reports locally accepted bytes in length without a body. READ
returns length bytes; FIN and empty receive are distinct. Error numbers reuse
the existing stream enum. IPv4 version 1 framing remains unchanged.

The V2 channel shares one typed framing implementation with IPv6 UDP: one
request in flight, at most 256 pipe bytes per poll, 250 ms partial-frame or
blocked-reply deadline, and clock checks before and after I/O. A failed or
expired WRITE transaction has an unknown remote effect and is never retried;
the client fences itself. Half-close retains read authority. A paired DNS
transport requires explicit UDP and TCP grants for the same peer and scope;
TCP fallback may start only after the resolver's matching truncated UDP reply.
An interrupted UDP transaction retires the entire paired pipe in both the
IPv4 and IPv6 adapters; direct later TCP or UDP attempts perform no I/O.
This is an intended shared IPv4 DNS fallback change as well: `dns::tcp` carries
the UDP adapter's retired state into the paired transport with
`self.live &= self.udp.live`. Direct later `Transport::tcp` calls are fenced,
even when they do not pass through the resolver's usual fallback sequence.
Both adapters use one pure validated-query/response matcher in `dns::tcp`;
it preserves A/AAAA Ignore behavior and returns matching malformed replies
to the resolver. Invalid queries are refused before TCP I/O.

Stable identity is the owner-described logical endpoint/service, distinct
from this implementation generation. There is no serialized TCP replacement
state schema in this tranche. A successor must quiesce requests, fence old
pipe/NIC authority, reconstruct authorized grants and discovery state, and
validate externally before commit. Old handles never rebind automatically.
Native Rust layouts are not transfer protocols. Connection continuity, peer
effects, downgrade after effects, hardware ownership transfer and rollback
remain unqualified. No live-replacement mechanism is introduced here.

Formalization consideration: S2 owns the bounded proposition that request,
ND and cache transitions cannot construct a grant or revive a revoked endpoint,
under correct engine/pipe behavior and the stated link/clock observations.
Practical source review and deterministic identity, scope, exhaustion,
deadline, half-close, framing and interrupted-WRITE tests are sufficient for
this first implementation review; their execution results remain separate.
These tests do not prove arbitrary concurrency or physical device transfer.
A later small state model could examine grant/live/closing/error transitions
and conversion rules if replacement state is introduced. No model or general
protocol conformance is claimed. Exact source revision, test/runner identities
and results belong in the lane receipt, with independent acceptance separate.

The `ipv6_tcp_client` diagnostic owns one paired pipe and no NIC. It first
resolves A over UDP, then A and AAAA through deliberate UDP TC and TCP fallback,
and explicitly closes TCP. The parent uses UDP local port 7202 and TCP port
7203 to the same on-link peer UDP/TCP port 42020. It services FIN for a bounded
second before local socket fencing; the runner independently requires both
wire FIN directions and Linux peer EOF. A retained TIME-WAIT socket is local
implementation state, not a claim of continuing application authority.

`scripts/native-ipv6-tcp-matrix.py` creates a fresh disposable namespace/TAP,
verifies its MTU is 1500, and boots an exact prebuilt kernel embedding the
probe ELF. Linux's AF_INET6 sockets implement the actual UDP/TCP/ND peer; a
Python DNS application provides controlled records, large TCP responses,
other-family frames and short writes. The independent dig controls use the
same fixture but no ABSD. The native capture must show bidirectional NS/NA,
exact UDP/TCP tuples, checksum-valid segments, MSS 1440, FIN in both directions,
and one TCP connection carrying the two expected fallback questions. The peer
matches each TCP question to the complete earlier UDP query bytes, including
ID and QTYPE. Capture independently requires the first native TCP SYN to
follow receipt of the truncated UDP answer for its exact first question;
later questions may reuse that connection. Native
malformed-frame, reset, exhausted/interrupted-stream, smaller-path and live SSH
cases remain explicitly unrun by this first positive consumer runner. Old UDP
qualification scripts and verdict predicates are unchanged.

The bounded accepted TCP run `9cbaefed` included a duplicate `a.example` UDP
query: the resolver's 750 ms retry occurred during about 807 ms of Neighbor
Discovery resolution. This is an observation of that run's existing retry
behavior. Composition introduces no new retry timer or additional grant.
