# Delegated MTU checker and genuine Linux fixture

This additive checker consumes the delegated native source at
`757d99c417643f2cd2b46a5abd1254bcf305657a`, including the read-EOF/zero-write
distinction and final phase-completion clock checks. Existing LocalPipe/router
and malformed-advice proof sources and verdicts remain unchanged. All new
artifact methods, builds and native execution are UNRUN at source handoff.

The runner reuses the existing ordinary Linux TCP peer
`scripts/native-tcp-mtu-peer.py` and creates the same two isolated namespaces:
guest `192.0.2.100`, router `192.0.2.1` with egress `198.51.100.1`/MTU 576,
and peer `198.51.100.2`/MTU 1500. Only the router forwards. IPv6 and relevant
veth offloads are disabled and read back; exact addresses, MACs, routes,
process identities, namespace inodes and tool commands are retained. No raw
error or positive packets are constructed during the native proof.

Capture starts with `tcpdump --immediate-mode -U` before QEMU. Both complete
guest-facing and router-egress PCAPs are checked; no trailing frame is ignored
or inferred. The router capture must have exactly one canonical numeric terminal
record for each of captured, received by filter, and dropped by kernel. Captured
and received must both equal the complete egress PCAP frame count, with zero
kernel drops. QEMU's guest-facing dump has no tcpdump statistics; its full count
is checked against the actual native TX/RX census. Exact bytes must match all guest-facing
frames, with only the existing two narrow TX zero-padding relations. RX is
exact. Egress census allows only router TTL decrement and its corresponding
IPv4 checksum change. The actual peer SYNACK must advertise enough MSS; the
actual 1024-byte DF submission must exceed 576, remain absent from forwarded
application data, and receive a valid Linux ICMP type3/code4/576 quote of that
exact prior IP prefix. The peer independently records zero negative application
bytes and exactly 64 positive echoed bytes with half-close/EOF.

Guest-facing ARP also permits the observed Linux router's unicast neighbor
request: router Ethernet/source hardware and IPv4 sender, guest Ethernet
destination and IPv4 target, operation 1 and zero target hardware. Existing
broadcast request and unicast reply behavior remains unchanged. Ethernet/IPv4
ARP types, 6/4 address sizes, exact direction/endpoints and 42-or-60-byte length
with only zero padding remain mandatory. This prospective correction addresses
the retained `d893` frame; the historical whole/native FAIL remains unchanged.

The parser follows `NATIVE-TCP-MTU-DELEGATED-PROOF.md` literally. For each
child it independently reassembles owner and child observed request/reply
streams and requires exact equality despite different chunk boundaries.
The first 20 reply bytes are the exact MTUD bootstrap, bound to child logical
number, tuple and original consumer deadline; subsequent messages have ordinary
two-byte length prefixes and exact version4/family0 headers. No incomplete
prefix, omitted reply, different tuple, malformed count or unknown type is
accepted. Separately for each observer, the complete bootstrap precedes the first
request, every complete request precedes its first reply byte, and the complete
reply precedes the next request or actual owner request EOF. These are recorded
calls within one observer, not ordering inferred across processes. The first
child's complete final READ reply must be code17/detail576.
Both reported Stale8 operations require unchanged child byte/call counters
equal to the final child ledger totals. No later child pipe operation is hidden
by equal final byte counts.

Only `observer=owner direction=request` may carry zero-byte read EOF in this
successful fixture. Zero writes cannot establish EOF, and a failed ledger
cannot pass. Actual request EOF is bound to the owner's REAP receipt; normal
kernel exit, normal native reap, true result EOF and EOF-driven channel revoke
are required independently. The child's final DONE clock cannot exceed either
normal reap or true result EOF on the same guest boot clock. Each phase's before
census is published inside that phase before GRANT; its after census must follow
REAP and FRAME_SEAL and precede RETIRED, matching the source's actual drop and
census order. Equal early counts cannot substitute a post-retirement observation.
Explicit final revoke and actual process, handle,
pipe, cell and socket restoration must precede the fresh second grant. Handle
slot integers may be reused; the kernel must record two distinct child PIDs
and no descendant spawned by either pipe-only child. Allocator frames remain
observations, not a restoration predicate.

Buffered records are checked by observer-specific byte offsets, native frame
order and original clock bounds. Publication order is not substituted for
cross-process causality. Exact consumed ICMP bytes and actual received framed
terminal bytes are required together with source correspondence. Post-call
timestamps alone do not prove an event's cause. Old-tuple TX from consumed
error through explicit owner retirement is refused; afterward only a disclosed
generic RST without application bytes is permitted. An ambiguous equal-time
control cannot establish that it followed revocation. No host/capture and
guest-clock subtraction, authenticated ICMP, private grant-expiry, PMTU
recovery, live replacement, all-memory restoration or DMA claim is made.

On an authorized disposable compiler/runtime VM, retain both child and parent
ELFs, actual metadata/staged std/build receipts, the served kernel invocation,
kernel ELF and ISO extents. Child bytes must occur exactly once in the parent,
and parent bytes exactly once in the selected kernel. Then run:

```sh
python3 -I -B scripts/native-tcp-mtu-delegated-tests.py -v
python3 -I -B scripts/native-tcp-mtu-delegated-matrix.py "$EVIDENCE/native" \
  --client-elf "$BUILT/tcp-mtu-delegated-client.elf" \
  --elf "$BUILT/tcp-mtu-delegated-service-probe.elf" \
  --kernel-elf "$BUILT/absd-kernel" --timeout 120
```

The 34 authored methods call actual checker functions with synthetic byte
arrays and reports. They cover complete two-child acceptance; independent
chunk boundaries; record/schema and authority substitutions; bootstrap binding;
stream mismatch and framing; real EOF versus timeout or zero write; abnormal
reap; both stale operations; typed-reply substitution in both observers;
accepted body totals; original deadlines; actual object census; fresh authority
ordering; echo/half-close/EOF; complete capture/routing and literal quote;
frame census; kernel child/worker/FNV evidence; ELF embedding; canonical clocks;
and actual peer read-before-echo. A count/capture-consistent late target TX
control tests stopped egress independently of Client pipe fencing. Synthetic
methods are artifact controls and never count as native execution. Four added
methods preserve the original 29 and cover census relocation with identical
values; equal-clock request/reply reordering with unchanged per-direction bytes
and counts; final child clocks after reap or result EOF; and tcpdump count,
uniqueness and canonical-integer substitutions. The original `d1e1dcd8` source
notice remains unchanged and unrun; these are prospective checker corrections.
The added ARP method uses the exact retained 60-byte frame and keeps full native
and capture counts consistent while mutating direction, MAC/IP addresses,
protocol/header sizes, operation, target hardware, length and padding.

The runner retains exact input/source/tool and launch identities, raw serial,
all pipe/child/NIC observations, full captures, ordinary peer ready/result/logs,
topology, result and cleanup. Failure stays failure; exact owned process groups
and namespace identities are retired with explicit missing evidence if cleanup
fails. A separate durable producer/collector and strict whole-source BEFORE/
AFTER custody belong to the actual offhost occurrence, not this source task.

Creator `quic_next_tranche` owns successor run
`77b24614-01d9-4747-b8cc-d0c77ef2167b` and its isolated source worktree. Root
owns aggregate allocation, composition and execution sequencing; independent
steward acceptance remains separate. Practical finite checker mutations,
source review and future independent native/Linux raw readback suffice for
this bounded composition claim; no mechanized proof or runtime result is
claimed. Retire the creator-owned worktree after composition/review/rollback
dependencies end, or review at 2026-10-19T00:00Z. No VM, credential, compiler
target or current-resource hold is created by this source preparation.
