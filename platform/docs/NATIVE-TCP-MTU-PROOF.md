# Native TCP MTU refusal: prospective Linux router fixture

This is source-only preparation. Artifact controls and all Linux/native
execution are **UNRUN**. The old Echo wire runs and their verdicts are separate.

The owner fixture uses the explicit experimental stream-v4 API. Linux supplies
two ordinary TCP listeners and a router-generated fragmentation-needed error:

```
guest 192.0.2.100 -- TAP 192.0.2.1/24 [router namespace]
                           veth 198.51.100.1/24 MTU576
                             |
                           veth 198.51.100.2/24 MTU1500 [peer namespace]
                           TCP42100 refusal / TCP42101 fresh positive
```

Only these fresh namespaces are changed. IPv6 is disabled in both; forwarding
is enabled only in the router. The peer route to192.0.2.0/24 uses198.51.100.1.
The router has no external/default route. Addresses, routes, namespace inodes,
MTUs, MACs, forwarding and disabled segmentation/checksum offloads are retained.
No raw error/positive packet is constructed by the runtime peer.

The first grant is7100→42100. Actual public stream-v4 CONNECT/STATUS/WRITE/READ
messages and complete replies are recorded. Client.write must accept all1024
literal bytes(i%251). The peer SYNACK must advertise MSS>=1024; the native
Link must actually submit a checksummed DF IPv4/TCP packet carrying all1024
bytes and IP length>576. Linux's router must emit type3/code4, MTU576, with
a checksummed literal original IPv4/TCP prefix of at least28bytes. Its quote
is matched to an earlier complete successful native TX and full TAP capture.
There is no inferred effect from a queued WRITE alone.

The oracle deliberately requires the unchanged quoted IP prefix. Upstream
[Linux ip_forward.c](https://raw.githubusercontent.com/torvalds/linux/master/net/ipv4/ip_forward.c)
tests MTU and calls icmp_send before decrementing TTL. This source deduction
is not evidence about a future VM kernel: a different actual quote refuses.
The independent egress capture must show every small TCP packet forwarded
with exactly TTL-1 and its recomputed IP checksum, and no oversized error
application packet reaching the peer. All TCP checksums are checked.

The exact consumed ICMP receive record bounds the stopped-egress assertion:
no old-tuple TX from that receive through explicit Session.revoke. No later
old-tuple application bytes are allowed. A generic RST after explicit removal
is permitted without implying that grant authority survived. Actual RPC17/576,
socketcount0, unchanged first deadline, subsequent client Stale8 and unchanged
RPC/TX counts are required. Earlier effects remain unknown, not rolled back.
The error peer records zero application bytes in real bounded reads (or earlier
EOF/reset); this is a finite observation, not a proof about future traffic.

Only after explicit revoke is a fresh grant7101→42101 created. It accepts and
echoes literal bytes0..63, half-closes in both directions, drains actual EOF6
and ends with sockets0. Whole/refusal/positive guest budgets remain30000/12000/
at-most10000ms with every record inside its original phase bound. Host and
guest clocks are checked separately; none are subtracted across clock domains.

Capture and native per-direction ordinals, counts and bytes must correspond
completely. Two precise Ethernet minimum-length relations are allowed on TX:

- ARP42bytes may equal capture60bytes as the exact42-byte prefix plus18zeros.
- TCP54bytes may equal capture60bytes as the exact54-byte prefix plus6zeros,
  only for valid IPv4 IHL20/IPtotal40/protocol6 and TCPdoff5, no data and flags
  ACK0x10, FINACK0x11, RSTACK0x14 or RST0x04. Both checksums must validate.

RX, SYN/options/data, other sizes and nonzero suffixes remain exact. Original
native bytes and lengths remain in custody; nothing is stripped or normalized.

Offhost recipe after Root composes and freezes exact product/oracle sources:

```
python3 -I -B scripts/native-tcp-mtu-tests.py -v
sudo python3 -I -B scripts/native-tcp-mtu-matrix.py FRESH_OUTPUT \
  --elf EXACT_TCP_MTU_OWNER_ELF --kernel-elf EXACT_EMBEDDING_KERNEL_ELF
```

The actual wrapper, compiler/std/metadata/source/ELF/kernel/ISO provenance is a
separate executor obligation. The runner verifies exact owner embedding and
uses the existing served_qemu RAM policy. It retains full serial/FNV, both
captures, peer-ready/final receipts, namespace readback, command and exact
process/group cleanup. On failure it writes FAIL and keeps all existing raw
files; no automatic retry. Exact known processes are reaped before deleting
only the created namespaces; an unknown process prevents namespace deletion.

Router capture uses tcpdump immediate mode as well as packet-buffered output.
The earlier 46f49820 run remains FAIL: tcpdump reported 11 captured / 17 received,
zero kernel drops, and the routed capture omitted exactly six final control
packets. Every captured routed IP packet matched its corresponding original.
Immediate mode addresses acquisition buffering; the full ordered packet census
and byte-comparison predicates remain unchanged. A successor must pass those
same checks with newly acquired captures; this correction does not rescore 46f.

The36 artifact methods use literal synthetic byte vectors and the actual
checker. They cover quote/checksum/tuple/MTU/DF/submission correspondence,
complete census/routing, native RPC/status/fencing/deadlines/EOF, peer socket
reads, and every scoped padding boundary. The same-poll negative adds a full
extra original TX while keeping both native/capture counts and FENCED counters
consistent. These are checker controls, not native protocol results.

Formalization consideration: the durable proposition is finite observation
correspondence plus terminal authority fencing under the source-bound v4
state transition. Literal vectors, strict ordered ledgers and independent
mutation controls are appropriate for this increment; no new model framework.
Remaining assumptions include faithful native Link and local Session receipts,
Linux capture completeness, and source→ELF provenance from the executor.
Neither unauthenticated ICMP nor body matching establishes authenticated source
identity, arbitrary-network robustness, PMTU recovery, child/kernel IPC, full
memory restoration, physical DMA fencing or live generation transfer. A future
replacement must reconstruct authority explicitly and cannot revive this
fenced Client. Root/steward decide integration and any further formalization.

Source ownership is quic_next_tranche/James Beck; no VM/key is retained by this
source task. Root owns review/composition/rollback custody, with review at
dependency end or2026-10-19T00:00:00Z. Reproducible runtime substrate is retired
after exact raw custody, process/namespace quiet and the executor's closeout.
