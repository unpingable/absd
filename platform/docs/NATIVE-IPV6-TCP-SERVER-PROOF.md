# Native IPv6 exact-peer server proof

The repair profile is `ipv6-tcp-server-onlink-close-v2`, proof schema
`absd-native-ipv6-tcp-server-proof/2`; all execution at the repair is UNRUN.
Historical product 739f361b / oracle 62905a5e produced whole native FAIL at
ceb54c49 despite the independently observed 3072-byte Linux echo and EOF.
The missing child diagnostic and insufficient capture interval are recorded in
[NATIVE-IPV6-TCP-SERVER-REPAIR.md](NATIVE-IPV6-TCP-SERVER-REPAIR.md); that result
is preserved. Initial 64d03679 / 66c44e41 source stages are historical.

The prospective product is f84086e138170344c4c06e8f2eb92dc2b595b66f, tree
24ce9b888b668d8d2e71c0626843b13889b5ce70. Its prefix-free canonical Git tar is
26,583,040 bytes, SHA-256
`f32b8cda44efd417d87543341da1b91b9326f232c28789755b6faf0c1c04cb20`.
The independently source-pinned oracle is committed after that product; its
commit is supplied by the immutable handoff, without a self-reference. Kernel,
server library production bytes and acceptance predicates are unchanged.

The kernel is 2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b, tree
8763f164ddfed11aa2f55626bd8e85123c595a08. Its prefix-free canonical tar is
12,574,720 bytes, SHA-256
`fbfff7902d7bf6334b0c2d141558ef8cbdb23d56ce3db0c81dd32ebfb81be224`.
The mandatory served wrapper is `scripts/served_kernel.py`, SHA-256
`e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2`,
policy `frame-admission-v0`. The kernel build must use that wrapper and the
launch must use `served_ram.served_qemu` with at least 256 MiB.

## Exact contract

The native parent configures fd00:ab5d::1/64, owner scope 1, immutable IP MTU
1500. Its single grant allows only [fd00:ab5d::2]:42030 to local port 7005,
accept timeout 5 seconds from LISTEN, lifetime 10 seconds from owner construction.
The child has an original 8-second deadline, ordinary startup/pipe handles and
no NIC or spawn authority. A literal v3 wrong-peer-port LISTEN receives Denied=2
before the actual client calls LISTEN/ACCEPT. That IPC denial is distinct from
the independently observed wrong-source TCP SYN; it is not drop telemetry.

A fresh isolated Linux namespace owns one TAP, the independent AF_INET6 clients
and exact QEMU process group. The wrong-source client binds port 42031 and makes
one connection attempt with a 1.25-second timeout. After that timeout the wrong
socket closes, then a separate monotone 1100 ms wait completes (observed upper
bound 2000 ms, or the fixture fails). Only then may the authorized client launch
with source port 42030. Its receipt must start after the separate wait receipt.
This consumes the original owner/accept/child bounds; none is renewed. The complete
capture requires a matching kernel-generated Linux NS and guest NA before the
first wrong SYN, no guest TCP reply to the wrong tuple, more than one second
between the first wrong SYN and authorized SYN, and no late wrong SYN. No raw
ND injection or fixture-known neighbor pin is used; the captured actual Linux
ND exchange and following SYN establish observed on-wire readiness.

Configured-address NS-to-NA maintenance is the pre-existing NIC-owner effect.
It can remain before LISTEN and after endpoint fencing and is not delegated to
the child. No claim that all ND ceases is made. Server TCP/Flow/socket/queue
fencing is separate. An old delayed packet can satisfy a fresh same-tuple grant;
local endpoint epochs do not authenticate or label a physical wire generation.

The full PCAP census rejects unknown MACs, addresses, tuples, UDP, extensions,
fragments, bad checksums, unsupported TCP options, reset/urgent/ECN flags,
invalid SYN/SYN-ACK/MSS1440, data before handshake, unseen ACKs/sequence gaps,
altered body and missing/early FIN or ACK. Every admitted frame is an exact
peer ND, permitted Linux MLDv2 record, wrong-source SYN or the single authorized
TCP flow. Both reassembled streams must equal the fixed 3072-byte body; at least
two segments each, Linux FIN before guest FIN and causal final ACKs are required.
The independent Linux client also requires write shutdown, exact echoed body
and real read EOF. The guest child makes one terminal CLOSE after its READ EOF
and echoed body, allowing the owner to drain FIN/ACK after spending the endpoint.
It does not issue the redundant SHUTDOWN_WRITE before CLOSE.

Raw native chunks must reconstruct with contiguous offsets and the exact
FNV-1a32 end record. The seven exact owner/child records establish grant/listen,
body completion, normal child reap, actual protocol/result EOF, zero sockets,
retired authority, and unchanged syscall-41 process/handle/pipe/cell counts after
owned handles close. Frame counts are observed, not required to restore. The
terminal kernel status/accounting and NIC counters are checked separately.

The unchanged `native-ipv6-accounting.py` helper (SHA-256
`22d5f091c23c0d436be538d3695b43b3ed52b48ec5b4b30668be215a08001ad3`)
classifies ND/MLD and captures readiness prefix metadata. The new profile supplies
only explicit IP/TCP tuples; it does not change the helper's policy or globals.
A nonzero terminal NIC refusal must equal the complete post-observation Linux
MLD destination-refusal census. Pre-observation refusals or partial marker
records are inconclusive and fail. Guest/host clocks are never compared.

## Minimal separately admitted Linux recipe

Use a fresh private clean product checkout at f84086e1, exact kernel checkout,
and separate clean oracle checkout. Do not claim the oracle HEAD is the older
product HEAD. Use the existing authentic offline toolchain/cache closure,
Rust 1.95 and canonical staged std c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c
(2,251 files, 45,920,288 bytes). No new dependencies are needed.

On the product checkout, run the normal locked/offline net host harness with
`--lib --target x86_64-unknown-linux-gnu`, one test thread, first default then
`--features dhcpv4`, keeping raw stdout and JSON harness identity. Require all 30
new `ipv6::stream::server::tests` methods, including
`redundant_shutdown_then_close_can_lose_the_live_endpoint` and
`actual_client_single_close_ack_survives_fin_ack_and_socket_removal`. Retain the ordinary old IPv4 server,
outbound IPv6, DNS and routed regressions; run ordinary SSH tests as well. Full
method counts are actual runtime observations, not AST-derived PASS results.

On the oracle checkout run, offhost only:

```
python3 -I scripts/native-ipv6-tcp-server-matrix-test.py -v
```

There are 22 authored artifact methods. They import only exact first-party
proof/stdlib helpers; they execute no sockets or guest. Existing cleanup methods
may also run because `stop_group` and namespace cleanup are AST-identical to the
current IPv4 runner. Report those two methods separately, not as new controls.

On the product checkout:

```
sh scripts/build-native-ipv6-tcp-server.sh
```

Retain both actual Cargo bin metadata records and the full `cargo metadata
--format-version 1 --locked --offline --no-deps --features
native-ipv6-tcp-server-probe` output. Targets must name
`ipv6_tcp_server_echo` and `ipv6_tcp_server_service_probe`, kind bin, their
exact source paths and required feature. Build child then parent in fresh owned
targets. Record the staged std inventory and toolchain receipt. The parent must
uniquely embed the exact stripped child.

Build kernel2775 using the proof checkout's exact wrapper:

```
python3 scripts/served_kernel.py -C "$KERNEL" \
  EXTERNAL_USER_ELF="$PRODUCT/ipv6-tcp-server-service-probe.elf" \
  EXTERNAL_INPUT="$CASE/empty" EXTERNAL_EXPECTED="$CASE/empty" external-build
```

The wrapper directly prefixes `make`; it has no `--kernel-dir` option and does
not take a second `make` token. Retain the actual argv, `external-build`, parent
input and policy. Preserve all actual logs, source commit/tree/clean status,
canonical tar identities, target metadata, child/parent/kernel ELF identities
and staged std. The proof verifies the parent inside the kernel and kernel
inside its generated ISO.

`BUILD-RECEIPT.json` schema is `absd-native-ipv6-tcp-server-build/1`, with profile,
platform/kernel `{revision, tree, clean, archive:{path,bytes,sha256}}`, actual
`commands` argv arrays, retained `logs`, `toolchain_receipt`, `cargo_metadata`
`{path,bytes,sha256}`, `target: x86_64-unknown-absd`,
`staged_std:{sha256,files,bytes}`, served policy/hash and
`outputs:{child,parent,kernel}` each `{bytes,sha256}`. No invented placeholders
may be treated as actual receipts.

Run only in the admitted disposable Linux VM, with durable outer producer and
collector armed before waiting:

```
python3 -I scripts/native-ipv6-tcp-server-matrix.py "$CASE/proof" \
  --kernel-elf "$CASE/kernel.elf" \
  --elf "$PRODUCT/ipv6-tcp-server-service-probe.elf" \
  --child-elf "$PRODUCT/ipv6-tcp-server-echo.elf" \
  --build-receipt "$CASE/BUILD-RECEIPT.json" --timeout 120
```

Retain RESULT/LOCAL-CLEANUP, source/build/toolchain/metadata, LAUNCH/ISO,
serial/output/FNV, complete PCAP, readiness annotation, wrong/positive socket
receipts (including post-negative start/end/required interval) and logs. The
strict greater-than-one-second capture gap remains independently required;
a wall-time receipt cannot replace it. Exact owned process groups and namespace retire at terminal,
including known FAIL. No lease, resource or key is created by this source handoff.

## Limits and disposition

Native malformed/partial IPC, killed consumer, exhaustion/stale handles,
clock/link/pending-reply faults, deliberate loss, 1280 MTU, routed listener and
SSH coexistence remain UNRUN; host controls are not native execution. This is
not a telemetry extension, authenticated identity, hardware timing, full memory
restoration or live generation replacement proof. Raw evidence and acceptance
are separate; Root commissions source/readback and the steward owns independent
acceptance/promotion. Retain source/minimal receipts for that review/integration
and rollback; next custody review is dependency end or 2026-10-18T23:59:59Z.
Source allocation is observed/forecast against the shared 60 GiB free reserve on
both `/` and `/data`, not a per-lane quota. Reproducible offhost targets and
namespace/image scratch retire after their exact custody/replay dependency ends.
