# Native TCP MTU-refusal consumer

`tcp_mtu_service_probe` is an opt-in, finite native consumer of the experimental
IPv4 stream v4 service. It uses the actual `stream::Client` and `Session` over
a synchronous, bounded local `Pipe` fixture. The NIC comes from the existing
startup capability. This fixture does not establish kernel-pipe IPC or a
delegated child-process boundary.

The guest is `192.0.2.100/24`, with gateway `192.0.2.1`. The independent Linux
TCP peer is `198.51.100.2`. A router between them has an egress MTU of 576;
the peer interface remains at 1500 so its advertised MSS does not prevent the
guest from submitting the intended larger packet.

The first explicit grant uses local port 7100 and peer port 42100. After a
normal handshake, the client queues exactly 1024 bytes, byte `i % 251` at
position `i`. The capture must establish the actual submitted IP length and
DF bit; queued length alone does not establish a particular packet. A genuine
Linux router ICMP fragmentation-needed response must quote the corresponding
packet. The client must receive `FragmentationNeeded { mtu: 576 }`, and the
owner's socket count must already be zero. This is terminal advice; prior
submitted or remote effects remain unknown.

Two subsequent calls on that same client must return `Stale` without another
local service transaction or NIC submission. The owner then explicitly revokes
the old session. A separate grant uses local port 7101 and peer port 42101;
it sends the literal bytes 0 through 63, half-closes its write side, receives
the exact echo and EOF, then releases its socket. This is a fresh calibration
chosen by the fixture owner, not automatic reconnection or replay by the
transport. A distinct tuple avoids assuming remote TCP state disappeared when
the old local socket was removed.

The whole consumer budget is 30 seconds, the first stage has a fixed 12-second
outer deadline, and fresh calibration has at most 10 seconds within the
original whole budget. These are consumer observation deadlines; the fixture
does not export or infer the private grant construction timestamp. A clock
rewind or budget expiry fails the run. Neither malformed inputs nor partial
progress renew a budget.

`TCP MTU ... v=1` records contain the complete successful local TX and actual
returned RX frames, with separate direction ordinals and boot timestamps.
They also contain the actual v4 request and reply messages from each completed
local service transaction, excluding the two-byte stream length prefix. The
fixture constructs and consumes that prefix through the existing client
framing implementation. Frame receipt capacity is 128 in each direction;
transaction capacity is 128. Crossing a bound fails, including after an actual
submission; failure does not undo an earlier effect.

The independent matrix checks full packet and transcript correspondence. The
permitted representation differences are a native 42-byte transmitted ARP
request followed by exactly 18 zero bytes in capture, and a native 54-byte
transmitted TCP control frame followed by exactly six zero bytes in capture.
The latter requires a valid 20-byte IPv4 header with total length 40 and a
valid, optionless, empty TCP segment whose flags are ACK, FIN+ACK, RST+ACK or
RST. Both relations retain the exact native prefix, length and direction.
They do not permit general suffix stripping. RX frames, larger frames and
all other submissions remain byte-exact. Host monotonic timestamps, guest
boot timestamps and capture timestamps are separate clock domains.

Build with `ABSD_PROFILE=core sh scripts/build-native-tcp-mtu.sh`; this produces
one `tcp-mtu-service-probe.elf`. The source requires the matching experimental
transport commit. Source construction and formatting checks are not execution
evidence. The owning lane receipt records the exact source and result when
the separate Linux/native execution has run.

The formalization consideration is bounded: literal transcript, message,
checksum, tuple, sequence, clock and terminal-state checks can establish this
occurrence's correspondence. Practical controls and raw readback suffice for
that claim. They do not establish authenticated ICMP origin or history,
universal TCP/PMTU conformance, physical delivery, memory restoration, safe
live kernel replacement, or rollback after external effects. Generation and
authority reconstruction are unchanged; no state export schema or replacement
mechanism is introduced by this private fixture. Root owns the source/result
claim; independent integration acceptance belongs to the steward.
