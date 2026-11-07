# Bounded native inbound TCP capability

Standalone runtime `2b2f882c`, proof/peer `c1377f6c` and native run
`20b8bf78-03cc-41be-acac-3551cd8198d3` received independent bounded acceptance
on 2026-10-16. The kernel is lane `ed6a15ea`, not composed kernel 7. Candidate
10 composition and kernel 7 + platform 10 replay remain steward-owned.

The original source tranche for existing coordination issue 29 added one
exact-peer IPv4 server capability and a delegated echo consumer, based on
candidate 8 eb70b62f. Its source-stage description was UNRUN: no compiler,
host protocol test, guest or independent Linux run was executed by that
source producer. The later sustained-refusal result is recorded in
NATIVE-TCP-SERVER-PROOF.md. The new observation source was UNRUN at its
`90ab` / `8b7d` freeze; occurrence `14761ecf` subsequently passed at those
exact sources, as recorded there.
Release/main/U1 and supported-ABI holds remain.
smoltcp 0.14 remains the TCP/checksum/SYN/MSS implementation; no kernel call,
dependency version, lockfile, broker or protocol implementation is added.
The later [native boundary fixture](NATIVE-TCP-SERVER-BOUNDARY.md)
adds selected actual grant/API/slot and pipe-only child interruption checks
before a fresh positive flow. Occurrence `9cde345e` passed at exact product
`137f6ac6` / oracle `f2d79c4b`; the `1476` result remains at its earlier
source. Net semantics are unchanged. See the proof document for exact
evidence and the remaining native cases.

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
192.0.2.1/24 on its lane-owned TAP and attach the dedicated QEMU e1000 guest.
The original source-stage recipe below is historical; the current proof
successor waits for LISTEN and verified neighbor readiness, then uses one
wrong-port connect and one positive connect, without retries. Its exact
source-pinned instructions are in NATIVE-TCP-SERVER-PROOF.md. The original
positive-only invocation was:

```sh
python3 scripts/native-tcp-server-peer.py NEW_RESULT_JSON
```

That historical ordinary Linux AF_INET client binds source port 42030, connects to 7005,
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

## Bounded owner observation

The NIC holder can read `Stack::stats().tcp_server_peer_dropped` and
`last_tcp_server_peer_refusal`. The count saturates at `u64::MAX`; the one
last record still updates at saturation. It names the observed source and
local destination, the rule's expected peer, TCP flags and sequence number,
and complete Ethernet frame length. This is a tuple/header observation, not
cryptographic authentication, stable peer identity or a unique frame hash.
There is no event queue, per-peer registry, reset operation or client message.

Only a frame actually discarded at one of the existing server ingress checks
can count. The observation classifier requires an installed, fault-free rule,
the exact local IP and port, a different peer IP or port, complete IPv4/TCP
lengths, IPv4 and TCP checksums, and parseable TCP options. IPv4 options,
fragments or reserved flags, nonzero TCP reserved bits, truncated headers,
bad checksums/options, unrelated local addresses/ports, and clock/link/expiry
faults are excluded. Exact-length frames and zero padding to the Ethernet
minimum are accepted for observation. This is deliberately a narrower subset
of ingress drops. It does not strengthen or alter admission: the original
`ingress` predicate and its ordering are unchanged, including its existing
delegation of malformed permitted-tuple packets to smoltcp.

After an ingress discard, observation-only classification may verify the
IPv4 header checksum and TCP pseudoheader checksum and parse TCP options
before recording or excluding the frame. This adds work proportional to the
bounded candidate frame under repeated rejected traffic; no throughput or
per-frame timing bound was measured. Admission remains unchanged.

`Port::fill` records only when it consumes a refused frame without caching
it. `Device::receive` records only when it takes a cached frame and its
second ingress check refuses it. The same discarded frame cannot reach both
sites. A cached frame that later encounters an expired/faulted rule is not
classified as a peer mismatch. No count is added for an API Denied reply,
queue discard, MTU refusal, rule removal, or a packet never received.

The new native parent reports a zero baseline and one final version 1 record
through its existing console after the child is reaped, bounded close drain
and fence. The child gets no observation API or additional authority; its
existing `denied=1` remains an independent framed API check. The proof must
bind the guest count and last record to the full captured wrong-tuple SYN
census and retain the complete positive stream, FIN/ACK/EOF and cleanup
checks. At the `90ab` / `8b7d` source freeze this qualification was UNRUN.

The opt-in native probe prints one final refusal observation containing the
observed and expected IP/port tuples, TCP sequence, flags and frame length.
Console output, raw serial and retained proof evidence therefore contain
that metadata. These fields describe an observation, not cryptographic peer
authentication.
The later `14761ecf-2155-443b-af58-90415887c6b6` occurrence passed: default
333 / DHCP 346 host methods including all nine new methods in both, SSH
20 method executions, 30 artifact plus two cleanup methods, and the native
proof with guest count 2 matching both wrong SYNs in the complete 31-frame
capture. The grant-authorized 3072-byte exchange and FIN/ACK/EOF also pass.
Exact raw identities, prior failures, independent review and resource
disposition are recorded in NATIVE-TCP-SERVER-PROOF.md. The historical
`a6fe` v2 proof had no guest observation; its separate bounded acceptance
does not accept this new telemetry. The steward independently accepted
`1476` with limits on 2026-10-18; its two wrong SYNs share a sequence, so it
does not distinguish first from last observation. A future varying-sequence
fixture and first-record substitution remain proposed on existing issue 29.
The later `9cde345e` adds the selected native boundary cases documented
separately; its explicit remaining limits still apply.

The history is Stack-local, begins at zero on open, and survives endpoint
close, rebind and fencing. Preserving these values does not revive a handle
or reserve a port. A new implementation generation reconstructs the Stack
and authority rather than importing native Rust layout. A future transfer
of this optional diagnostic would require an explicit versioned schema,
counter/saturation semantics and independent successor validation; it must
not transfer sockets, queues, grants or retired authority implicitly.

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
the original source tranche; its source-stage test descriptions were authored,
not executed at that freeze. The telemetry tests/native proof later passed
in the exact bounded `1476` occurrence; that does not expand the stated
proposition or the native cases exercised. A later model
must separate wire effects, tuple correlation and hardware exclusion instead
of treating local queue removal as rollback. Source/result identities belong
in the lane receipt and independent acceptance, not this document.

Root owns lane storage coordination; the steward owns aggregate ABSD storage.
The telemetry worktree initially allocated 30,113,792 bytes, with less than
128 KiB of added source forecast. These are observations/estimates, not a
per-lane quota. The hard free-space reserve remains 60 GiB independently on
`/` and `/data`. No targets, VMs, captures, package caches or keys are created
by this source task. Retain exact commits and minimal receipts for
review/integration/rollback; retire the reproducible worktree after those
consumers end. Root reviews custody at dependency end or
2026-10-18T23:59:59Z.
