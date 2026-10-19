# Bounded native inbound TCP capability

Standalone runtime `2b2f882c`, proof/peer `c1377f6c` and native run
`20b8bf78-03cc-41be-acac-3551cd8198d3` received independent bounded acceptance
on 2026-10-16. The kernel is lane `ed6a15ea`, not composed kernel 7. Candidate
10 composition and kernel 7 + platform 10 replay remain steward-owned.

Experimental source for existing coordination issue 29. It adds one exact-peer
IPv4 server capability and a delegated echo consumer, based on candidate8
eb70b62f. No compiler, host protocol test, guest or independent Linux run was
executed by the source producer. Release/main/U1 and supported-ABI holds remain.
smoltcp 0.14 remains the TCP/checksum/SYN/MSS implementation; no kernel call,
dependency version, lockfile, broker or protocol implementation is added.

`Stack::stream_server_grant` accepts one nonprivileged local port, an exact
on-link unicast peer IP and port, an accept timeout of 100..10000 ms and an
original grant lifetime of 100..60000 ms at least as long as the accept bound.
It shares the existing eight stream endpoint slots and checked instance/epoch
construction. A grant reserves the local port and ingress rule without a
socket or wire effect. Existing outbound grants, classic listeners and classic
connections cannot claim that port. Each LISTEN uses one fixed-local-address
socket; its accepted connection consumes that same slot. There is no automatic
rearm, backlog expansion or second accept. Accepting never creates authority
from received traffic or renews the original lifetime.
Here, one accept means one connection accepted by the native API. Before that
ACCEPT, the exact authorized peer can complete further transport handshakes
after a prior connection resets, within the same original accept/lifetime
bounds. The failed `ec9cbda7` trace demonstrates that distinction. The grant
does not promise only one handshake before the successful ACCEPT.

The exact IP/port rule is installed before LISTEN and before an Interface poll
can feed it. It checks both newly read and already held frames. Unsupported
IPv4 options/fragments for that flow are refused; the existing engine has no
fragment reassembly. Other ports and classic SSH keep their existing policy.
smoltcp validates the admitted TCP packet, sequence and checksum. The same
tuple can still be produced by another on-link sender; source correlation is
not authentication. Bounded link/ring/CPU pressure remains possible. This is
not a general public listener, connection broker or SYN-load defense.

The existing stream read/write/half-close implementation is reused, with
8192-byte RX and TX buffers and at most 1024 bytes per operation. READ, WRITE
and SHUTDOWN_WRITE require explicit ACCEPT even if a handshake has completed.
READ distinguishes Again from EOF; a peer FIN retains write authority. A
successful WRITE is local queue admission, not peer or application receipt.
SHUTDOWN_WRITE queues FIN after data and retains reads. CLOSE spends the handle
and permits bounded graceful drain under the original grant, even after its
channel closes. EOF/error without CLOSE and ABORT discard the socket/queues
immediately, retaining no reset. The trusted owner can fence remaining drains.

Listen/accept, accepted operation and retained close all honor boot-clock
lifetime/rewind and observed link refusal/unknown/down/disabled. The RX/TX
adapter also checks active inbound rules around Link calls. If expiry/rewind
is observed during Interface poll, later application submission is refused;
returned receive/send errors latch the same fence before further Interface
dispatch even if a later link-status read appears healthy. A failed send can
retain one uncertain first effect; no later server submission is permitted.
removal is idempotent on the pre/post maintenance passes. Closing does not
create a new linger authority past the original bound. Link and clock checks
are non-atomic: one send may already have affected the link before its post
check observes expiry. The regression retains that possible first effect and
requires no later submission. Already emitted data cannot be recalled.

## Typed native framing

Outbound v1 defaults and bytes remain unchanged. Server sessions explicitly
use version 3, family 4, a two-byte big-endian body length, and the existing
twelve-byte header. Byte 0 is version, byte 1 opcode, byte 2 request-zero or
reply status, byte 3 family, bytes 4..8 exact peer IPv4, 8..10 peer port, and
10..12 length. There is no endpoint selector. Valid WRITE bodies are at most
1024 bytes, or 1036 bytes including the header; the reused transport has its
existing bounded frame buffer.

LISTEN=32 and ACCEPT=33 require zero length and no data. They return one status
byte: connected, write-closed and peer-finished in bits 0..2. LISTEN returns
connected false; ACCEPT returns Again until handshake completion, succeeds
once, and then refuses repeat ACCEPT. STATUS=17 retains the underlying
connection-state meaning, which alone does not authorize pre-ACCEPT I/O.
WRITE=18, READ=19, SHUTDOWN_WRITE=20, CLOSE=21 and ABORT=22 preserve their
existing stream meanings and status codes. CONNECT=16 is refused on v3.
Wrong version/family/reserved/length/opcode has no operation; wrong peer is
Denied. The tests contain this literal LISTEN body and its first reply:

```text
03 20 00 04 0a 00 02 02 a4 2e 00 00
03 20 00 04 0a 00 02 02 a4 2e 00 01 00
```

Server channels opt into monotonic pre/post-I/O checks and the 250 ms frame
bound. They also check original endpoint instance/epoch, lifetime, link and
sticky fault before every pipe read/write and after each I/O return. Pending
READ data is discarded at an observed boundary instead of being released by
the old frame deadline alone. A pipe write crossing the boundary may already
have exposed one first effect; the channel then discards remaining output and
that exact endpoint generation. A stale channel cannot discard a replacement
grant. Successful CLOSE/ABORT may acknowledge within the original bound;
neither revives the spent handle. Normal EOF after CLOSE permits the existing
bounded drain, while clock/frame/endpoint failures fence it immediately.
Legacy handler authorization defaults remain true and strict checks remain
disabled; their close and framing behavior stays unchanged. The shared framing body now
takes internal expected version/family parameters; the public v1 wrapper
supplies its original constants. The shared client chooses those defaults or
the typed server headers/accept loop. Uncertain framed WRITE is never retried.
These are the only shared semantic branches; outbound close timing is unchanged.
One old ICMP test constructor supplies the new empty rule array without a
predicate change. No serialized network packet is rewritten.

## Actual consumer and independent peer recipe

`scripts/build-native-tcp-server.sh` builds `tcp_server_echo` and embeds its
exact stripped ELF in `tcp_server_service_probe`. The dedicated parent opens
192.0.2.100/24 with no gateway, port 7005, and only peer 192.0.2.1:42030. The
accept bound is five seconds and lifetime ten seconds on boot_millis. The
child gets five explicitly copied pipe/startup/result/console handles and
SPAWN_NO_SPAWN, no NIC. It confirms wrong-port denial and absent NIC, accepts,
echoes exactly 3072 bounded bytes, observes peer EOF, half-closes and closes.
The parent checks successful child exit/result, drains at most one second
within its original bound, fences and requires zero sockets. No SSH owner is
commandeered; this is a separate dedicated test boot.

Inside the separately admitted isolated Linux namespace, configure only
192.0.2.1/24 on its lane-owned TAP, attach the dedicated QEMU e1000 guest, and
retain an independent raw capture. After `TCP SERVER GRANT READY ...`, run:

```sh
python3 scripts/native-tcp-server-peer.py NEW_RESULT_JSON
```

The ordinary Linux AF_INET client binds source port 42030, connects to 7005,
sends a fixed 3072-byte pattern, half-closes, verifies every echoed byte and
requires EOF. The marker announces the owner grant; the client retries bounded
connection refusal while the child issues LISTEN. The parent separately emits
`TCP SERVER LISTEN READY sockets=1` only after its channel has processed LISTEN
and the dedicated Stack owns its sole socket. A native wrong-port refusal case
must wait for that observation and prove no earlier eligible SYN in capture.
Its finite 60-second host deadline is distinct from delivered
guest boot ticks. Its PASS covers that client only. Root must bind exact
source/build/child/parent/kernel ELF identities, captured ARP/SYN/tuple/MSS/
checksums/data/FIN, native markers and successful cleanup to a new execution
identity before reporting native interoperability. No native or fixture result
is implied by source formatting. No protocol execution or provider resource
is created by this source task.

Authored tests cover malformed/unauthorized frames, literal headers, preissued
identity, slot/port and TX exhaustion, stale/cross-stack/epoch identities,
wrong-peer SYN refusal before slot occupation, cached ingress, accept/original
lifetime, early-I/O refusal, half-close and post-FIN echo, cancellation, EOF,
partial expiry, rewind, link failures, queued-data discard during poll and
the retained first send effect. Actual accepted TCP READ data is also tested
while pending in pipe output across expiry, independent clock rewind, latched
I/O fault and explicit fencing, with retained first pipe effect and bounded
terminal acknowledgement/drain fixtures. Actual Linux/native malformed wire, native
consumer cancellation, backlog/load exhaustion, retransmission under loss and
live SSH coexistence remain unexecuted. Existing outbound and SSH suites also
need execution against this exact source; their unchanged design is not a pass.

## Evolution and formalization consideration

The logical service/peer differs from its checked implementation instance and
endpoint epoch. ACCEPT uses existing authority; fencing never revives a handle.
Rebinding requires a fresh owner-issued grant. No Rust layout is a replacement
schema. A future state transfer needs an explicit versioned format, conversion
preconditions/loss/refusal, reconstructed authority, external successor
validation, device quiescence and generation retirement. This source supplies
no hardware ownership transfer, post-effect rollback or live replacement.

S2 root considered the bounded state machine Reserved/Listening/Accepted/
HalfClosed/Draining/Fenced, with eight slots and one I/O crossing a bound. The
durable propositions are no traffic-derived grants, no stale-handle revival,
and no submission after an observed fence while retaining the possible first
effect. Literal vectors and practical state-transition fixtures suffice for
this small source tranche; tests are authored, not executed. A later model
must separate wire effects, tuple correlation and hardware exclusion instead
of treating local queue removal as rollback. Source/result identities belong
in the lane receipt and independent acceptance, not this document.

Root owns aggregate S2 storage; the source allowance is 32 MiB. No targets,
VMs, captures, package caches or keys are created here. Retain exact commits
and minimal receipts for review/integration/replay; retire the reproducible
worktree after those consumers end. Named next review: 2026-10-17.
