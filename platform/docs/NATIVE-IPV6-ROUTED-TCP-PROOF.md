# Opted-in routed DNS TCP proof

This is a separate case and runner. The accepted UDP-only runner, its exact
criteria, source pins and historical results are unchanged. The product source
is `9ad4782088e40cbccd10c0fef1329d0892370b73`, tree
`1c2b3e671422a7a885b521c51a618f69bcb385f4`; the proof checkout has a separately
recorded revision and includes the matrix, controls and Linux application.
This 10e-based source has UNRUN expected counts of 293 default net methods
and 306 with DHCP. Earlier standalone f655 passed 285/298, SSH 3+0+17+0
and five bootstrap methods in occurrence
`014dfa09-4175-4cf7-aefa-9205f19f0582`. The eight focused routed methods passed.
The earlier e98 compile failure remains a separate result.

The new case uses genuine Linux IPv6 forwarding between the guest-facing TAP
and a separate veth-connected peer namespace. The router's egress has the
explicit `fe80::203` link-local required by Linux ND. Both links and both
captures have MTU 1500; the guest SYN must advertise its original MSS 1440.
Offloads are disabled, passive capture uses immediate mode, and there is no
userspace packet forwarder or host-local off-link address shortcut. This is
an explicit verified path profile, not Internet PMTU support.

The peer is `native-ipv6-routed-tcp-peer.py` with the exact schema documented
in NATIVE-IPV6-ROUTED-TCP-PEER.md. Linux supplies the transports; the Python
application supplies fixed DNS responses. The matrix independently checks
the peer observations instead of trusting its PASS label. Two complete UDP
transactions return TC with no partial answer. One TCP connection carries the
same two questions, including IDs, and full A/AAAA answers. Each TCP question
prefix must follow its own captured UDP TC response. The complete stream,
including length prefixes, is reconstructed from TCP sequences and must equal
both actual socket receives and sends. Conflicting retransmission bytes,
gaps, a second connection, missing FINs or missing FIN acknowledgements fail.
The matrix also checks actual socket I/O chunks, short sends, EOF, local write
shutdown and close. Linux timestamps establish only their own clock ordering.

Every classified transport packet has the exact IP/port/MAC tuple, valid
IPv6 pseudo-header checksum, bounded TCP header/options and expected hop
limit. The captures must have exact one-hop packet counterparts, including
TCP control packets. ND is restricted to the exact next-hop and Linux peer
adjacencies; unknown traffic fails. The two complete captures cannot establish
which particular DMA slot delivered a frame. The existing first-four-reason
accounting and readiness sidecar remain explicit limits, without a counter
deduction or packet-classification waiver.

The native report must show three UDP and three TCP framed wrong-tuple
denials, the selected capability's peer fields, A and AAAA success, explicit
close, an observed 1000 ms bounded drain, zero sockets and exact restoration
of processes/handles/pipes/cells. The unchanged outer 12000 ms guard surrounds
I/O and scheduling; each DNS lookup preserves its original resolver deadline.
The pre-poll 1100 ms setup interval assumes a continuous VM without pause or
icount; it is a fixed fixture preparation, not a hardware readiness theorem.

## Actual commands and build contract

Execute only in the admitted isolated Linux VM, using a fresh case UUID and
the original absolute resource lease. Keep at least 1200 seconds of outer
resource margin before a guest. There is one compiler/runtime owner and one
256 MiB TCG guest; use the existing `served_qemu` helper and actual RAM check.
The source-accurate commands are:

```
python3 -B scripts/native-ipv6-routed-tcp-peer-test.py -v
python3 -B scripts/native-ipv6-routed-tcp-matrix-test.py -v
sh scripts/build-native-ipv6-routed-tcp.sh
```

The platform build uses the exact product checkout named above, Rust 1.95, profile core and
canonical c354 patched std: 2251 files, 45,920,288 bytes, SHA-256
`c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c`.
The existing standalone QUIC f493 stage is a different input. Do not reuse it
as c354. The native recipe explicitly unsets inherited CARGO_TARGET_DIR because
its strip paths are relative to its own source target tree.

Archive and relocate only the two declared generated ELFs before checking
literal source cleanliness. Preserve actual recipe/output paths, modes,
hashes and relocation correspondence. Build exact kernel
`ed6a15ea7c7c999422e1e294e139b6119619b06c` with Rust 1.98 and the actual
`make external-build EXTERNAL_USER_ELF=... EXTERNAL_INPUT=... EXTERNAL_EXPECTED=...`
command, with both external byte streams empty. No kernel broker/reader or
optional feature is admitted implicitly.

The strict receipt schema is `absd-native-ipv6-routed-tcp-build/1`. Platform
and kernel rows bind exact revision/tree/clean and canonical source archive
path, byte count and SHA-256. Commands are actual argv lists. Toolchain and
build-log buffers have exact paths, lengths and hashes. `outputs` maps child,
parent and kernel to exactly `{bytes, sha256}`; rich paths/modes may be in an
additive receipt, never silently added to that strict object. The external
parent row names the relocated actual input to the kernel command.

The matrix requires unique child-in-parent, parent-in-kernel and critical
ISO directory extent correspondence. It retains exact source archives,
ELFs, boot config, ISO, raw captures, native output, peer records and the
evaluated byte index. Source/tool/actual compiler invocations and both actual
target-bin metadata checks belong to the occurrence's build custody. A clean
proof checkout is not relabelled as the product build source.

## Formalization and generation limits

The durable claims are exact capability tuple/next-hop separation, derived
live-flow ND, unchanged TCP ingress, original deadlines, and complete
stream/capture/EOF correspondence under a private single-producer fixture.
Finite real Stack/Channel/Link host tests and explicit packet/socket
substitution controls are proportionate for this bounded extension. They are
not a compiler-correctness proof or a general TCP/router model. A future model
could track capability, connect, closing and retired states with a fixed
neighbor route; no new formalization runtime is introduced here.

Route configuration is immutable in one Stack generation. Replacement needs
a fresh validated Stack, new explicit paired grants and fresh Linux fixture
resources; fenced endpoint handles never revive. Private bootstrap version 2
does not export Rust layout, transfer transport state, or establish hardware
quiescence, live kernel replacement, authority reconstruction or rollback
after visible network effects. There is no RA/SLAAC/default router, PMTU,
shared SSH startup change, public peer or new broker claim.

The creator owns temporary sources, targets, namespace mounts, process groups,
TAP/veth links and ISO substrate. Keep exact evaluated evidence and replay
inputs through the named root integration/readback event, review by
2026-10-18, and retire reproducible substrate after custody and consumers end.
Evidence creation does not establish permanent retention or acceptance.


## Current-platform replay identity

This proof changes only the four product identities in the existing matrix.
Its control methods, independent Linux peer, packet/deadline/authority predicates,
source cleanliness, executable embedding and cleanup requirements are unchanged.
The named product archive is 24463360 bytes, SHA256
`99291c06beb7cf4d7b9deb4344d7b68518a8813d7d67cb6cc232896ab4dabac7`.

Standalone e583/proof803d completed 287/300 network tests, SSH checks and native
routed A/AAAA DNS/TCP in d447. Its exact evidence does not qualify this product.
All current-platform host/native checks remain UNRUN at this proof preparation.
The prior mutation-target-reuse FAIL remains failed and separately recorded.
