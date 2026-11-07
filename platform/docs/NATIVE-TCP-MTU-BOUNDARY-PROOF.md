# Native TCP malformed-advice and current-grant isolation

This is a prospective finite consumer for existing issue
#34. Source preparation
does not establish a host-test or native result. The earlier genuine Linux
MTU-router proof and its historical verdicts remain separate.

## Exact inputs and topology

The new matrix boots one `tcp-mtu-boundary-service-probe.elf` embedded exactly
once in the selected kernel. The probe uses actual experimental-v4
`stream::Client` and `Session::request` messages through its synchronous local
Pipe. It does not delegate a child or exercise kernel IPC. The guest consumer's
original outer budget is 30000 ms. Each GRANT records that original outer
deadline and requests its remaining lifetime at the recorded construction
call time. The Stack samples its own clock when constructing the private
grant expiry; that private sample and expiry are not exported or inferred by
this proof. Every consumer operation remains within the original outer budget.

Two isolated Linux namespaces provide a fixed-1500 router and an ordinary TCP
peer: guest `192.0.2.100`, router TAP `192.0.2.1/24`, router veth
`198.51.100.1/24`, peer `198.51.100.2/24`. The peer has only its connected route
and a route to `192.0.2.0/24` through the router. Forwarding is enabled only in
the router namespace. IPv6 and veth checksum/segmentation/coalescing offloads
are disabled and read back. Full guest-facing and router-egress captures retain
ARP and TCP rather than selecting only the five ICMP inputs.
Router tcpdump uses immediate delivery and packet-buffered output, avoiding
the capture buffering observed in the separate 46f49820 genuine-router run.
The complete ordered native/capture and routing comparisons remain required;
neither immediate mode nor a zero-drop counter alone establishes completeness.

The native owner grants target logical 1, `7100 -> 42100`, and unaffected
logical 2, `7101 -> 42101`, then connects both before any injected control.
The first CONNECT creates one engine socket; the second creates the second.
The target submits the complete 1024-byte literal `i % 251` using its actual
Client. The raw actor selects that complete DF TCP submission, validates the
IPv4 and TCP checksums, and waits for native `CONTROLS_READY`.

All five ICMP inputs here are **disclosed raw fixtures**, including the
matching fourth input. No result from this profile claims that Linux generated
an MTU error. Each input is a 70-byte Ethernet/IPv4/ICMP type 3 code 4 frame,
quoting the first 28 IPv4 bytes of the selected actual submission:

1. MTU 576 with an incorrect ICMP checksum.
2. MTU 576 with a valid checksum but quoted TCP sequence XOR 1.
3. A valid checksum and exact quote with MTU equal to the submitted IP length.
4. A valid exact quote and MTU 576.
5. The byte-identical fourth frame on a new empty-history reservation.

The actor waits for the native receive ordinal and actual STATUS outcome for
each input before sending the next. Thus labels alone do not establish receipt
or classification. Input 0, 1 and 2 each require actual v4 STATUS success,
connected true, and two engine sockets. Input 3 requires typed code 17/detail
576, target socket retirement, and the existing unaffected socket still live.
The old Client's read and write must both return Stale 8 with no new RPC or TX;
the owner then explicitly revokes that target session.

The already-connected logical 2 sends bytes 0 through 63, receives their exact
Linux echo, half-closes, observes EOF, and retires. There is no replacement
grant or reconnect for this positive step. The owner then reserves logical 3
using the old target tuple, without CONNECT or TX, and records actual STATUS
success with connected false before and after input 4. A reservation has live
authority but no engine socket: `EMPTY_READY`, CASE 4 and final retirement
therefore report zero engine sockets. This tests empty new history, not aged
history or authenticated ICMP provenance.

The peer deliberately holds the old target connection open through the
reservation check. It has received exactly 1024 bytes and sends no application
echo. It closes only after natural QEMU exit and capture closure, on the
runner's exact `PEER-STOP` file. The unaffected peer independently records
64 received and echoed bytes, native half-close, and its own half-close.

## Observations and refusal rules

`TCP MTU BOUNDARY <KIND> v=1` records retain all native TX/RX frames, their
per-direction ordinals and original boot timestamps, plus every actual v4 RPC
message excluding only its two-byte local framing prefix. Slot/logical identity,
phase, complete bytes, original deadline, CASE receive ordinal, typed outcomes,
fence counts, explicit revocation and terminal socket counts are checked.
Native records are bounded to 256 frames per direction and 256 transactions.

The checker binds the first selected submission, all five literal control
frames, native RX ordinals, subsequent actual STATUS messages, actor sends and
acknowledgements, both full captures, and ordinary peer event/body receipts.
From matching native RX through explicit target revocation, no target TX is
allowed. Later old-tuple application data is always refused; a post-revocation
generic RST is permitted without implying restored grant authority. No TX of
any kind is allowed during the empty new reservation.

Guest-facing native/capture correspondence is exact except for the unchanged
two bounded Ethernet relations from the prior TCP proof: successful TX ARP
42 bytes may match its exact prefix plus 18 zero bytes in a 60-byte capture;
successful TX TCP 54 bytes may match its exact prefix plus 6 zero bytes only
for checksummed IPv4 IHL 20/IP length 40/TCP header 20/no data and flags ACK,
FIN+ACK, RST+ACK or RST. RX remains exact. No generic padding removal occurs.
The egress TCP census permits only normal router TTL decrement and the
corresponding IPv4 header-checksum change.

Natural QEMU status 3, exact worker exit 0, complete external-output offsets,
length/FNV seal, boot markers, and NIC counters must agree with all native
frames. Separate host/capture and guest clocks are never subtracted. The
runner retains exact source/input ELF/kernel/ISO identities, both full PCAPs,
raw serial, actor and peer ready/result/logs, topology and cleanup. Every owned
process group and namespace must retire; failure artifacts remain failures.

## Offhost execution

Compose these five new paths with the reviewed native probe/core source before
freezing exact product/oracle/kernel inputs. Build the feature
`native-tcp-mtu-boundary-probe` with its owning native build script, and retain
the actual metadata, staged std, served kernel-wrapper invocation, and exact
owner/kernel ELFs under the occurrence's normal source/custody checks. On an
authorized disposable Linux VM, run the authored artifact controls and then:

```sh
python3 -I -B scripts/native-tcp-mtu-boundary-tests.py -v
python3 -I -B scripts/native-tcp-mtu-boundary-matrix.py "$EVIDENCE/native" \
  --elf "$BUILT/tcp-mtu-boundary-service-probe.elf" \
  --kernel-elf "$BUILT/absd-kernel" --timeout 120
```

The 25 authored methods use synthetic byte arrays and the actual checker;
passing them would not itself establish native behavior. They cover literal
input construction, checksums/quote identity, missing and substituted RX,
STATUS after RX, connection/socket counts, original clocks, typed target
fencing, the unchanged survivor, empty reservation, full capture/routing and
peer census, cleanup receipts, output seals and narrowly bounded padding.
One control inserts a fully counted and captured target retransmission after
the matching native RX, preserving FENCED counts and route correspondence so
the consumed-input stopped-egress predicate must refuse it.
Peer writes also require the actual port to have been accepted and their exact
bytes to be an already-read prefix at that event. Consistent negative histories
retain final bodies, counts and monotone event clocks while moving the write
before accept, before the first read, or before the remainder of a partial read.

## Formalization and custody

The durable proposition is bounded: invalid/inapplicable advice does not fence
the selected current flow; exact matching advice retires only that flow; a
separately connected flow remains usable; old wire bytes do not create TX
history or connection authority on a fresh unconnected reservation. Practical
source review, literal vectors, finite checker mutations and an independent
native/Linux readback are appropriate for this tranche. No mechanized proof
or model-to-driver correspondence is claimed. History remains bounded and
unauthenticated; later genuine transmissions with equal bytes can match by
design. Missing observations or expired history must fail the occurrence.

Creator `quic_next_tranche` owns these five source paths and the source-ready
receipt under run `0e55fd23-6c1e-4b40-9158-ec45006a7675`. Root owns composition,
aggregate storage coordination and integration; acceptance is separate. Retain
the exact commit and minimal replay inputs for composition/review/rollback.
Review the source worktree for scoped retirement when that dependency ends or
at 2026-10-19T00:00Z. This source task creates no VM, key, compiler target,
namespace, background producer or claim of live replacement, physical clock
accuracy, all-memory restoration, DMA transfer, or PMTU recovery.
