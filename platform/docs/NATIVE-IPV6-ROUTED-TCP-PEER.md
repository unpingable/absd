# Independent Linux peer for routed IPv6 DNS over TCP

`scripts/native-ipv6-routed-tcp-peer.py WORK --timeout N` binds the controlled
resolver in the existing disposable peer namespace. `WORK` must exist and
contain no previous `PEER-READY.json`, `PEER-RESULT.json` or `PEER-STOP`.
The timeout is an absolute Linux monotonic deadline, from 1 to 180 seconds.
It does not renew on socket progress.

Linux implements IPv6, Neighbor Discovery, routing, UDP and TCP. The Python
application supplies controlled DNS messages; it is not an independent DNS
server product. The existing `native-ipv6-peer.py` question/answer codec is
loaded only after verifying its exact SHA-256, recorded by the new script.
The original UDP peer, runners and qualification criteria are unchanged.

The fixed peer is `[fd00:ab5d:2::9]:42010`. UDP must originate from
`[fd00:ab5d:1::15]:7002`, and TCP from the same address on port 7003.
Listeners on port 42011 record and refuse any contact. No ambient resolver,
public destination, route setup or forwarding configuration is used by the
peer. The matrix owns those exact disposable namespace resources.

The application exchange has exactly this order:

1. UDP A question for `a.example`; return TC=1 and zero answers.
2. The same complete question, including ID, over TCP; return `192.0.2.9`.
3. UDP AAAA question for `aaaa.example`; return TC=1 and zero answers.
4. The same complete question over the existing TCP stream; return
   `2001:db8::9`.
5. Observe socket read EOF after both framed answers have been sent, then
   successfully perform local `shutdown(SHUT_WR)` and close the connection.

TCP messages have the two-byte network-order DNS length prefix. Reads and
writes may split frames. The peer accepts exactly one TCP connection. DNS
messages are bounded at 1232 bytes, each complete TCP direction at 4096 bytes,
and the socket event census at 128 entries. The single I/O producer checks
event capacity before each socket call. It updates actual stream byte custody
before the corresponding event, so an exhausted census refuses the next
call before consuming or emitting its bytes. Cleanup closes remain explicit
connection metadata even when no event capacity remains.
Duplicate or reordered questions,
unexpected sources/destinations, malformed or oversized messages, early EOF,
deadline expiry and interruption before completion fail. This fixture does
not claim retransmission, larger-answer, general DNS-server or Internet
path coverage.

The process remains available until `WORK/PEER-STOP` appears or it receives
SIGINT/SIGTERM. A stop after the complete exchange succeeds. An incomplete
exchange fails. `PEER-RESULT.json` preserves observations on either outcome.

## Schema version 1

`PEER-READY.json` contains exactly these keys: `schema_version` (1), `pid`,
`bind`, `port` (42010), `forbidden_port` (42011), `udp_source` (two-element
address/port list), `tcp_source` (same), `transport` (literal
`Linux AF_INET6 SOCK_DGRAM + SOCK_STREAM`) and `codec_sha256`.

`PEER-RESULT.json` includes the same identity and codec fields, `records`,
`io`, `tcp`, `errors`, `stop_reason`, `disposition`, `limits`, `clock_scope`
and `eof_scope`. A passing result has an empty errors list, four ordered
records, one connection, complete streams and no pending or unsent bytes.
The matrix must independently validate content and counts; the peer's PASS
label alone does not qualify the native capability.

Each `records` entry includes `transport` (literal `UDP` or `TCP`), `source`
(Linux four-element IPv6 socket tuple), `port`, `name`, `kind`, `query_hex`,
`answer_hex`, `monotonic_ns` and `realtime_ns`. A TCP record is the decoded
DNS frame, without the two-byte prefix. A recorded answer is the intended
answer; actual emitted bytes are separately recorded by send events.

`io` contains timestamped `udp-recv`, `udp-send`, `tcp-accept`, `tcp-recv`,
`tcp-send`, `tcp-write-shutdown` and `tcp-close` events. Data events retain
raw `hex`; sends also retain requested and actual byte counts. UDP receive
retains flags and source/destination information. A zero-length `tcp-recv`
event records socket EOF.

`tcp` contains `source`, `connections`, `read_eof`, `write_shutdown`,
`closed`, timestamps for successful transitions, `received_hex`, `sent_hex`,
`received_sha256`, `sent_sha256`, `received_frames`, `sent_frames`,
`pending_hex` and `unsent_hex`. Complete stream fields include all two-byte
length prefixes. Frame arrays contain only DNS message bytes. Actual
received/sent stream hashes cover their corresponding raw bytes, including
any partial frame preserved on failure.

Linux host monotonic and realtime observations are separate clock domains
from the guest's operation clock. They do not establish native boot ordering.
Read EOF plus successful local SHUT_WR establishes those socket observations;
both wire FINs, checksums, routing, ND and native grant/fence bounds must be
checked separately from the two complete link captures and native report.

## Development controls and evolution scope

Run `python3 -B scripts/native-ipv6-routed-tcp-peer-test.py -v` only in the
isolated disposable Linux VM, with no concurrent peer. Fifteen controls use
real Linux loopback UDP/TCP sockets and the actual peer state machine. They
cover forced partial framing boundaries, two questions on one connection,
raw stream reconstruction, source/destination refusal, malformed/oversized
input, duplicate order, substituted transaction, premature EOF and interrupted
completion. Three deterministic exhausted-census controls use real Linux
sockets to establish that queued UDP/TCP bytes remain unread and pending TCP
output remains unsent. These controls change only the imported test module's address
and destination ports to loopback; the product entry point retains its fixed
routed tuple. They do not prove native routing or replace the matrix run.

This is an ephemeral qualification application, with no stable service
identity, exported replacement state or authority transfer. Sockets and
partial streams are discarded on close. A successor requires fresh namespace
setup and fresh native grants; old fenced handles are never rebound.
There is no claim of hardware quiescence, post-effect rollback or live kernel
generation replacement.
