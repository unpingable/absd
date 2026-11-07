# Independent Linux proof for the bounded native TCP server

## Executed native boundary qualification — 2026-10-18

The native boundary oracle selects
`tcp-server-native-boundary-v1`, with build/proof schemas
`absd-native-tcp-server-build/4` and `absd-native-tcp-server-proof/4`.
It pins product `137f6ac6b55fe92cee94816ce609658e96d1ec05`, tree
`18aa6d16d7d8293f360cd67ab5b5a2607bd6358d`; prefix-free canonical Git tar
26,388,480 bytes, SHA-256
`b4ab4a3ee760ee98411c034bb5f6fa06ed13692382228123b389e75268a0ab68`.
Kernel 2775 and served wrapper/policy remain unchanged. See
[NATIVE-TCP-SERVER-BOUNDARY.md](NATIVE-TCP-SERVER-BOUNDARY.md) for the exact
native grant/API/slot/interruption/census proposition and offhost recipe.
At source freeze all runtime actions were UNRUN. Fresh occurrence
`9cde345e-c72a-425d-a7c8-8b82f9878b2c` passed at this product, oracle
`f2d79c4b10e121d4c7b04094d9819645470359a6` and kernel
`2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b`. All six actual phases exited
zero: 39 artifact methods, two cleanup methods, the separate historical
short-gap capture diagnostic, fresh product build, fresh kernel build and
the native Linux proof. Net/runtime/broker, staged manifests/locks and
existing host inputs are byte-identical to `90ab`; prior 333/346 net and
20 SSH executions remain attributed to `1476` at `90ab`. They were not
rerun or relabeled at this native fixture revision.

The guest required nine invalid grants to return `Invalid(1)`, duplicate
port `InUse(3)`, a distinct ninth slot `Exhausted(4)`, and eight old
endpoints `Stale(8)` after fresh construction. Seven actual framed child
requests produced six exact `Invalid(1)` replies and one `Denied(2)`.
The 113-byte request ledger includes the completed LISTEN and one raw
prefix byte; the 113-byte reply ledger includes the complete LISTEN reply.
The separate seven-byte startup bootstrap is outside that reply ledger.

Actual guest ticks were: negative grant constructed 570, conservative bound
10570; partial pre-poll 663, observed byte 664, kill return zero at 665,
killed outcome kind 3 reaped at 669, true pipe EOF 669, retired channel and
zero sockets at 671. Thus retirement preceded pre-poll + 250 = 913 and
the original grant bound, without fallback fencing. The exact process
handle was `8589939968`, not a PID. After checked handle closure, census
values returned to processes 2, handles 13, pipes 2 and cells 1. Frames
changed from 192 to 195; this observed delta of three is allowed and is
not a full-memory restoration claim. The fresh positive owner bound was
711 through 10711 within the original whole-fixture end 20540.

The complete 31-frame capture has two ARP frames, two wrong-port SYNs at
indices 2/3, and the first authorized SYN at 4. The first-wrong interval is
1,382,818 microseconds; the last-wrong interval is 379,068 microseconds.
Guest count 2 and last sequence `3814115712` match those captured headers.
Both 3072-byte streams, FIN/ACK, Linux half-close and true EOF passed.
NIC RX 18 / TX 13 match the capture, with four refusal/missed/error fields
zero. Native output reconstructs to 3029 bytes with FNV-1a32 `3ccca357`.
The actual negative child was killed, the positive child and parent exited
zero, QEMU exited 3, sockets were zero and terminal workload accounting
was zero. All three source snapshots are clean and identical before/after.

Collector `f0ea5a0e-1d40-4f7c-a9af-728193b57902` retains the exact archive
under `archived-occurrence`:
31,174,253 bytes, SHA-256
`32145d8fdd9b65a3e0a90896bd5e56faa90dc706219ea7fcd284a44edb5295cf`.
Root independently verified all 82 regular members, 81 index rows, modes,
sizes, hashes, exact membership, source equality, actual method names and
serial byte offsets/digest. Root's `8da06e30-907d-4cfa-b937-bf0fcaf97c7b/`
`NATIVE-CUSTODY-READBACK.json` has SHA-256
`36629c7e4ce2f31799ae7246939bc43e858f9ad27ddf3c8a6cb89a0d7bf6dea5`.
Independent complete raw review `79b12192-f8a5-4e60-bd27-899f30b965a6`
reports `BOUNDED_RAW_CLEAR_9CDE`, with no findings. Its REVIEW SHA-256 is
`90c427caee21c39c287e840eeebdfcdacd5e2f44920ab2a7c0a2643c465550e4`.
It checked all 4339 source rows, complete packet checksums/sequence/body/
FIN/ACK, source/build/ELF/ISO containment and exact native records. The
reviewer is the same vendor and previously reviewed source; this engineering
readback is separate from steward acceptance.

Resource `a6ab0275-c810-47d5-93cb-d65d05022b31` is CLOSED. Exact VM,
firewall and provider-key GETs returned 404; fresh paginated listings
independently confirmed absence. Five scoped SSH files and their directory,
the six local units and fallback are retired, with no ambient-agent use.
No remote replay dependency remains. Its additive STORAGE-CLOSEOUT SHA-256
is `8304d01634f4f6a399c5402a1ff086d66e40d416d872877e286f623bfd03f3ae`:
5,912,092,672 measured guest bytes retired with the VM, and 32,768 measured
local temporary-script bytes reclaimed. These are separate from shared-host
free-space changes and from unmeasured key allocation. Root retains unique
source and minimal replay evidence through integration/rollback or review
at 2026-10-18T23:59:59Z.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Child ELF | 133120 | `74370a64f861fbe170702eca5e31b2e06f3939096ad09efd927ef2ace6ac851e` |
| Parent ELF | 448544 | `c5d2e40fd27882a72da9172952e77d6a20de0e6aa1f90f1a30dc1cfddb6f5327` |
| Kernel ELF | 9159136 | `bb7402ec637ad3bc4490c2d31c354c146ae1d1a3ed51642277d417673fb740e4` |
| ISO | 21035008 | `63237494d19db0ed5b3485b70e5c286a726c014e5f2da19f14cfb79f8d890f9d` |
| Full PCAP | 8500 | `2a58ec669ced7f1c75b23d9af044bc35500e848c76f4e75c9d8cf3fdae46dc99` |

Original intake `a6ab` remains FAIL: SSH refused its first read during
bootstrap, before any source transfer or qualification launch. Separate
intake `9d4b7d67` verified the ended original bootstrap and empty transfer
paths, then received and verified the exact inputs. Its PASS is separately
bound; it does not rewrite the failed intake. The sole native producer
was `absd-s2-tcp-produce-9cde345e.service`, original PID 6812/start 71760,
Invocation `a3eb2ed56a5f4abbb65ede75af472b21`; its OS exit zero and empty
original cgroup are retained. The actual collector's FIRST-AWAITING at
08:59:51.473650Z preceded producer start at 08:59:52.556213Z.

Remaining native limits include malformed outer lengths, isolated complete
oversized WRITE bodies, connected-data/pending-reply interruption, clock
and link faults, exhausted queues/rings/load, stale READ/WRITE or foreign
Stack handles, deliberate loss, general listener/backlog, routed PMTU,
live SSH coexistence, hardware and physical elapsed-time accuracy. This
finite fixture uses literal conformance checks and observed native
transitions, not a universal proof. It transfers no live state or authority.
Neither historical `1476` nor `a6fe` is rescored. Independent steward
acceptance and integration remain separate from the producer's PASS.

## Executed peer-refusal observation — 2026-10-18

Occurrence `14761ecf-2155-443b-af58-90415887c6b6` passed all ten phases at
product `90ab3973cf66200bf17da16eded0ea72ecf2eed6`, oracle
`8b7d12682f07057c88fc1c2985c4c6dcd66145f3` and kernel
`2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b`. The actual net host suites
passed **333 default** and **346 DHCP** methods, including all nine new
`tests::server_telemetry_cases::*` methods in each. SSH summaries were
`3 / 0 / 17 / 0`, with 20 passing method executions. All 30 artifact methods
and two cleanup methods passed: 32 distinct methods, with no doubled count
for reruns. The separate historical-capture diagnostic again observed the
exact short-gap refusal; it is not another method or a historical rescore.

The full 31-frame capture contains one host and one guest ARP frame, 17 host
TCP frames and 12 guest TCP frames. Readiness request/reply are at indices
0/1, the two same-attempt wrong-source SYNs at 2/3, and the grant-authorized
SYN at 4. The first-wrong gap is **1,368,725 microseconds**; the last-wrong
gap is **368,463 microseconds**. The explicit Linux permanent-neighbor pin
and matching raw ARP receipt remain separately verified. No guest response
to the wrong tuple appears.

The actual guest observation goes from zero to two and its last header
matches the capture exactly:

```text
TCP SERVER PEER REFUSAL BASELINE v=1 count=0 last=none
TCP SERVER PEER REFUSAL FINAL v=1 count=2 source=192.0.2.1:42031 destination=192.0.2.100:7005 expected_peer=192.0.2.1:42030 flags=2 seq=3186326534 frame_bytes=74
```

The reconstructed native output is 422 bytes with transport FNV-1a32
`d13e6104`; both native/owner success and the expected QEMU exit 3 are
retained. The subsequent plaintext grant-authorized flow transfers exactly
3072 bytes each way, across five host and seven guest data segments, with
the full expected body, both FINs and acknowledgments, write half-close and
true Linux EOF. NIC counters are RX 18 / TX 13, corresponding to the full
capture, with all four refusal/missed/error fields zero. Parent sockets and
the existing end-of-workload accounting fields are zero. These observations
are bounded runtime evidence, not full memory or hardware restoration.

The earlier `f9306d52-8828-410c-821f-2e293796fecc` remains **overall FAIL**:
its disposable wrapper expected 328 methods and rejected the actual
successful default suite of 333. Later phases in that occurrence remain
UNRUN. The new occurrence corrected only the wrapper's count forecast and
explicitly guarded reuse of that known-ended, exact-source default target.
DHCP and SSH targets were fresh. This is a disclosed warm default rerun,
not a second cold build; product, oracle, source-cleanliness and acceptance
predicates were unchanged. Completed child/parent ELFs were moved into
evidence before the strict source check. All three source roots finish
clean with exact tracked byte/mode/link equality before and after.

Collector `6187ba81-8320-44c3-92b9-9f8a15285d68` retains
`exact-tcp-evidence.tar.gz`, **47,077,956 bytes**, SHA-256
`5a4edba5f4c66412a5b015bd81f8a5f74cd863505582e210c9deed2d49a435bb`.
Root verified all 97 member sizes, modes, hashes and the exact set; its
`c3a3c538-4ba3-4b81-9cc6-e0b7a51eb703/SUCCESSOR-CUSTODY-READBACK.json`
has SHA-256 `51ab2e599e6acfd26569d6545e32807d0bcfc5109f9c660fdce459b63901b017`
under `archived-occurrence`.

Exact retained build and capture identities are:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Child ELF | 124928 | `bb42399816950c05d4b29a2c5eb300808886cdf31c93a62fc7b7db8375561777` |
| Parent ELF | 419872 | `db6af9ffee485a8ade99b8d5cfc6a5d0b124301c22046fd49de465f50b7b8660` |
| Kernel ELF | 9130768 | `cdaa6a1a5161c75a4a762f80fa76b4a5c3f546534df3d4b591d78d8c7c00d56b` |
| ISO | 21006336 | `680165ec9f05d3dec7855949dbeb80d9080f07e5de780ccee42326989e6536b4` |
| Full PCAP | 8500 | `ebaee3441957a54e5a12616d518f2b7d11a1965b57c91bcd5c2a628e7bf65963` |

`14761ecf-2155-443b-af58-90415887c6b6/RUN-SUMMARY.json`, SHA-256
`e73d80904f2d52ff3a6a088af988e7016eeadbe5f5cc9912fca78b72b7c2980c`,
binds the exact sources, build receipts/logs, executed harnesses and native
outcomes. Its execution COMPLETE is SHA-256
`d41398ace95b2f80d41567107ed4200ad9a162ec0dcd77ce354d0fd744e2d3e2`.
Resource `a762c897-e67e-4a1b-9805-3a9e3758dce6` is CLOSED: actual provider
GET 404 and fresh instance/bare-metal/firewall/key listing absence, five
scoped local SSH files and directory retired, six local units not found,
and fallback canceled only after absence. Its COMPLETE is SHA-256
`20d6c3cbeb2d637e5c06e4448e8956c5a68d7db54df7f100afb6c372fe3c891a`;
STORAGE-CLOSEOUT is SHA-256
`eaeb1885905a090896013ae9ce041569ad58260219c7dad409eb5b665b30040f`.
No VM, key, collector or timer dependency remains for local evidence review.

The independent same-vendor raw review is
`9772e07e-fc8c-497b-a5f4-8977df9dd0d5/REVIEW.json`, SHA-256
`0d2a6a8c930122c69c5858701c7f4a77845e8ea5a619f4fd9b98239eb3f38007`;
its COMPLETE is SHA-256
`8d76fd704448c51b1be24f375dc97b0dbd766c8086f7fc44a88b1d108e66e4cc`.
It independently checks the full member custody, sources, actual host/control
results, boot/ELF identities and complete wire/serial correspondence with no
concrete blocker. The reviewer authored neither this telemetry nor its
executor. Same-vendor raw clearance is distinct from cross-vendor/steward
integration acceptance, which remains separate as of this docs handoff.

This establishes a bounded guest filter observation for this exact tuple
and full capture. The last record is not a full-frame identity or
cryptographic peer authentication. Host and guest clocks are not compared;
continuous polling, physical timing, general loss accounting, hardware and
live-generation transfer are not established. Native malformed API/wire,
interrupted/partial pipe consumers, exhausted slots/queues, clock/link faults,
stale handles, deliberate-loss retransmission, SSH coexistence and routed
paths remain UNRUN. The prior `a6fe` v2 proof was accepted with limits;
that separate acceptance does not accept the new telemetry.

### Frozen source contract and source-stage history

The new profile `tcp-server-peer-refusal-telemetry-v1` adds one guest decision
observation to the existing separated-refusal proof. Product source is
`90ab3973cf66200bf17da16eded0ea72ecf2eed6`, tree
`c81f83d40058a782152706c1cbf547c79ccfe5a7`; its prefix-free canonical Git tar
is 26,337,280 bytes, SHA-256
`5b8f12cbce35c68914fed9f1f85dd4d063aa46d86f41b96588f9c75c2fd77a58`.
Kernel remains `2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b`, tree
`8763f164ddfed11aa2f55626bd8e85123c595a08`, canonical tar 12,574,720 bytes,
SHA-256 `fbfff7902d7bf6334b0c2d141558ef8cbdb23d56ce3db0c81dd32ebfb81be224`.
The oracle is a separate successor commit, so product archives do not include
a circular pin to their own commit. Both clean checkouts and their exact
source/archive/toolchain/build snapshots remain mandatory.

The build receipt is `absd-native-tcp-server-build/3`, with the exact
`profile` value above, the new product identity and all existing v2 fields.
The served wrapper remains SHA-256
`e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2`,
policy `frame-admission-v0`, and its actual `external-build` command is
required. The new terminal schema is `absd-native-tcp-server-proof/3`.
Historical v2 results and their executable oracle remain unchanged.

The unchanged native child still has no NIC and reports its separate
`denied=1` framed API refusal. The parent reports exactly one zero baseline
before constructing its grant, then one final observation after successful
child reap, bounded drain and socket fence, before DONE:

```text
TCP SERVER PEER REFUSAL BASELINE v=1 count=0 last=none
TCP SERVER PEER REFUSAL FINAL v=1 count=N source=192.0.2.1:42031 destination=192.0.2.100:7005 expected_peer=192.0.2.1:42030 flags=2 seq=S frame_bytes=L
```

`N` must equal the complete capture's wrong-source SYN count, be positive and
not saturated. `S` and `L` must equal the last captured wrong SYN's sequence
and full Ethernet frame length. The local, observed peer and expected peer
must match exactly. The capture still requires all wrong SYNs from one
attempt, before the grant-authorized flow, and no guest response to them.
All original ARP/neighbor readback, greater-than-one-second first-wrong gap,
3072 bytes each way, exact body, FIN/ACK, true Linux EOF, native exit,
object/NIC counters, build/ELF/ISO and resource cleanup checks remain.
Guest/host clocks are not compared and counter values are never substituted
for the full wire census. A final zero/none record, missing record, count
mismatch, altered tuple/flags/sequence/length or duplicate/reordered marker
fails. The child's `denied=1` cannot substitute for this observation.

The product classifier is observation-only and deliberately narrower than
the unchanged admission predicate. It excludes malformed lengths/checksums/
options, fragments, other local destinations and faulted rules; see
NATIVE-TCP-SERVER.md. Its fixed last record does not store a full-frame hash
or every previous packet. Under this fixture's complete census, count and
last-header correspondence supports actual guest filter observations of the
exact refused tuple. It is not a unique packet identity, cryptographic peer
identity, continuous polling, physical-time, general loss, full memory or
live-generation transfer proof. Inert Stack history grants no authority.
Root owns the bounded source/readback scope; the steward owns independent
acceptance. Finite host transitions and literal serial/packet substitutions
are the formalization method for this small proposition; hardware and
generalized state-transfer proofs remain outside it.

### Minimal offhost recipe for this successor

At the `90ab` / `8b7d` source handoff, all of these actions were **UNRUN**;
the actual `1476` results above postdate that freeze. The recipe is to run
the oracle's 30 artifact methods and two unchanged cleanup methods, then
both ordinary net host suites in fresh targets, retaining actual JSON
compiler output, executed harness ELF identity, method names and full raw
summaries. All nine `tests::server_telemetry_cases::*` methods must execute
and pass in both variants; report actual full counts. No test runs on build_host.

```sh
# From the exact oracle successor checkout:
python3 -B scripts/native-tcp-server-matrix-test.py -v
python3 -B scripts/native-tcp-server-cleanup-test.py -v
# From clean product90; use the authenticated offline Rust 1.95 closure.
env -C "$PRODUCT90" CARGO_TARGET_DIR="$CASE_ROOT/host-default" \
  cargo +1.95.0 test --manifest-path net/Cargo.toml --lib --locked --offline \
  --target x86_64-unknown-linux-gnu --message-format=json -- --test-threads=1
env -C "$PRODUCT90" CARGO_TARGET_DIR="$CASE_ROOT/host-dhcp" \
  cargo +1.95.0 test --manifest-path net/Cargo.toml --features dhcpv4 --lib --locked --offline \
  --target x86_64-unknown-linux-gnu --message-format=json -- --test-threads=1
env -C "$PRODUCT90" sh scripts/build-native-tcp-server.sh
# Remove only these known completed build outputs from the source root.
mv "$PRODUCT90/tcp-server-echo.elf" "$CASE_ROOT/tcp-server-echo.elf"
mv "$PRODUCT90/tcp-server-service-probe.elf" "$CASE_ROOT/tcp-server-service-probe.elf"
: > "$CASE_ROOT/empty"
python3 "$PRODUCT90/scripts/served_kernel.py" -C "$KERNEL2775" \
  EXTERNAL_USER_ELF="$CASE_ROOT/tcp-server-service-probe.elf" \
  EXTERNAL_INPUT="$CASE_ROOT/empty" EXTERNAL_EXPECTED="$CASE_ROOT/empty" external-build
# Bind actual v3 build receipt, source snapshots, commands/logs and ELF hashes.
sudo python3 -B scripts/native-tcp-server-matrix.py "$CASE_ROOT/native" \
  --child-elf "$CASE_ROOT/tcp-server-echo.elf" \
  --elf "$CASE_ROOT/tcp-server-service-probe.elf" \
  --kernel-elf "$KERNEL2775/build/external/target/debug/absd-kernel" \
  --build-receipt "$CASE_ROOT/build-receipt.json" --timeout 120
```

The native source's original five-second accept and ten-second lifetime,
the Linux client bounds and the served RAM policy are unchanged. No PKI,
additional guest, counter reset, new grant or broad telemetry framework is
needed. The external operator owns resource admission, durable collection,
source cleanliness and exact temporary substrate/key retirement. This source
task retains only commits and small receipts, reviewed at dependency end or
2026-10-18T23:59:59Z; it allocates no VM, target tree or large archive.

## Executed refusal-interval proof — 2026-10-18

Occurrence `a6febffd-4def-40fe-93e1-e7c4366de4bb` passed all six recorded
phases: 23 artifact methods, two cleanup methods, the separate historical
capture negative control, product build, kernel build and native proof. There
are **25 distinct unittest methods**, not 26 or a doubled count from rerunning
them. Oracle code remains `754f177dda6a8ea5874951ef8f8031d8d96a18bb`, product
`79f6d167046b9b4e3eac42e47c75e21371c9c8c1`, kernel
`2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b`, with the served wrapper and
`frame-admission-v0` policy recorded below. This documentation successor does
not change those executable sources or their result identities.

The complete 31-frame capture contains the actual ARP request and matching
guest reply at indices 0/1, followed by two same-attempt wrong-source SYNs at
indices 2/3 and the grant-authorized SYN at index 4. The first-wrong to first
grant-authorized SYN interval is **1,356,587 microseconds**; the last-wrong
interval is **294,874 microseconds**. The greater-than-one-second criterion
uses the first wrong SYN, including the observed retransmission in its full
census. No guest TCP response to that wrong tuple appears. The actual Linux
neighbor receipt separately verifies the explicit fixed-MAC `PERMANENT` pin;
the ARP exchange alone is not used to infer cache population.

The subsequent grant-authorized tuple is
`192.0.2.1:42030` → `192.0.2.100:7005`. It transfers exactly 3072 bytes each
way across multiple segments, reconstructs the expected body in both
directions, and captures both FINs and their acknowledgments. The Linux socket
receipt also requires write half-close and real receive EOF. Native child and
parent success, zero sockets and terminal accounting/NIC predicates pass.
This is plaintext IPv4 TCP under an IP/port grant, with no cryptographic peer
authentication or TLS claim.

The separate diagnostic passed the original 8410-byte historical capture to
the new oracle and observed the exact refusal
`captured wrong-source interval is not greater than one second`. It does not
rescore that historical occurrence. The first current attempt
`c33d3ea7-8ccc-4c7a-ac7a-bcbe87a966e2` likewise remains **overall FAIL**, even
though its native subphase passed: generated child/parent ELFs remained
untracked in the product source root and the final strict source check failed.
The distinct `a6fe` executor moved only its completed child/parent build outputs
into evidence before building the parent-containing kernel and doing the unchanged source
postcheck. It used warm targets/cache, not a second cold build. All three
source roots finish clean; tracked file bytes, modes and symlink targets are
identical before/after. The strict source predicate and oracle code were not
weakened.

Collector `e5130d38-4704-4878-8d31-2a5e3c7c2d40` retains
`exact-tcp-evidence.tar.gz`, 31,005,562 bytes, SHA-256
`4a49b647e453f00507f01f9166f28a0391c5c8044bea4b0fb489efca1f5bb10d`.
Root and the independent same-vendor reader verified all 80 member
sizes/hashes/modes and the raw correspondence. Exact retained identities are:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Child ELF | 124928 | `bb42399816950c05d4b29a2c5eb300808886cdf31c93a62fc7b7db8375561777` |
| Parent ELF | 415776 | `1b34ea97db031ef064058e860268d4da3cfaeebb366d049af47ba5395fb3a09e` |
| Kernel ELF | 9126488 | `ed1fb3e476371ff0e84d49956c8469261822f2c42403d6a2a737c6ea0ae95c00` |
| ISO | 21002240 | `9221389dbeb10b08e081beeb0783547fc5924db4ba282aae2ca6d104a5b03764` |
| Full PCAP | 8500 | `c56076ff2464bee89b0cc919b354ef110467661130e59c214a08003f9927327d` |
| Raw serial | 2871 | `7f1f4ed41be75a7a67fd7d273a22c38afd504433ceacd2f8e0467150eb8dfd88` |

The shared registry is `archived-occurrence`.
Its immutable pointers retain the complete build, source, socket, packet and
resource records:

- `a6febffd-4def-40fe-93e1-e7c4366de4bb/ARTIFACT-IDENTITIES.json`, SHA-256
  `e8eeae759b78b9626dcbcbe1a44363e42f82a7365de1cf1e58f3952746aaf6b3`.
- `a6febffd-4def-40fe-93e1-e7c4366de4bb/COMPLETE.json`, SHA-256
  `8875b778f0d116abed7ffbb63d30e8b66615f39adbe6f0139097e6f32e47e603`.
- Independent raw review `9c410de1-d87c-43a7-95f3-3eaec04fe2f8/REVIEW.json`,
  SHA-256 `07dfa83b776331a630c2f88cc60a2149ddfa9134239c222bcb76be4557b18d2e`;
  its `WORDING-ADDENDUM.json`, SHA-256
  `2ef13402346f8b83d0764e5d560046d46cd6593354ea726a8e754df1bef0f7b4`,
  explicitly uses grant-authorized IP/port authority, with no cryptographic
  authentication claim.
- Resource `df952e66-2ec5-4198-982e-daddcc72abd7/COMPLETE.json`, SHA-256
  `33e55d97950986f9bbd16df9f7d9868b4161705ca0ade1b14b51647916e35d69`:
  VM/firewall/provider-key GET 404 plus listing absence, five scoped local SSH
  files retired, exact local units/timer retired and fallback canceled after
  fresh provider absence. No VM or key dependency remains.

The engineering readback is same-vendor and bounded; cross-vendor/steward
integration acceptance is pending as of this documentation handoff. This one
TCG development occurrence does not establish physical elapsed-time accuracy,
guest drop-decision telemetry, universal filtering, full memory restoration,
hardware behavior or a release. The native malformed API/wire, cancellation,
partial expiry, clock/link faults, exhausted queues/slots, stale handles,
deliberate-loss retransmission, live SSH, backlog and routed/PMTU cases listed
below remain UNRUN. The existing finite raw tests and explicit assumptions
remain the formalization method; this documentation introduces no new
mechanism, general proof or live-generation transfer claim.

## Historical 2026-10-18 source freeze (runtime UNRUN at that time)

Coordination issue 29
already records the missing sustained wrong-source interval. The new oracle
source is a separate commit on `lane/native-tcp-server-refusal-codex-20261018`;
its exact identity and source-only checks belong to registry
`native-tcp-server-refusal-s2-20261018/4b036f50-9ae8-4da7-b340-49e8b546e6cb`.
It did not alter the old frozen source or verdicts described below. At the
`754f` source freeze, all new artifact controls, Linux actions, builds and
native execution were **UNRUN**; the executed `a6fe` result above postdates it.
No product TCP/net/kernel/consumer, grant, deadline, ABI, lock or dependency
changes are part of this fixture successor.

The new sequence is LISTEN observation → actual ARP request/reply → explicit
Linux neighbor pin and readback → one wrong-source-port connect → authorized
3072-byte each-way exchange. The runner sends one exact AF_PACKET ARP request
inside its own namespace on `tcps-tap0`, and accepts only the matching guest
reply with the fixed IP/MAC tuple. That probe has a three-second host bound
and at most 32 received frames. Only after the matching reply does it run
`ip neigh replace 192.0.2.100 lladdr 52:54:00:12:34:56 nud permanent dev tcps-tap0`
and verify the actual unfiltered `ip -j neigh show` output inside that namespace:
exactly one entry with the expected destination, device, MAC and `PERMANENT`
state. The command has no `dev` selector because iproute2 omits the JSON device
field for a selected device ([upstream print_neigh source](https://raw.githubusercontent.com/iproute2/iproute2/main/ip/ipneigh.c)).
The pin is fixture configuration, not discovered routing authority. Raw ARP
is **not** assumed to populate the Linux neighbor cache. The fresh namespace
and its neighbor table retire together on either result.

The wrong-port client makes one connect from 42031 with a 1.25-second timeout,
records the actual monotonic begin/end and emits no application bytes. A
short timeout, successful connect or connection-refused error cannot pass.
The positive peer starts only after that attempt ends, still uses one connect,
and retains its original four-second handshake/eight-second total budgets.
Its tuple, 3072 exact bytes, half-close and real receive EOF remain mandatory.
The native product's original ten-second lifetime is unchanged; if fixture
setup or the exchange cannot fit it, the new occurrence fails rather than
renewing authority or extending a deadline.

The complete unmodified PCAP must show the matching readiness exchange
before the **first** wrong-source SYN, then more than 1,000,000 captured
microseconds before the first authorized SYN. This is measured from the first
wrong SYN; permitted kernel retransmissions retain that attempt's sequence
identity. The result separately reports the last-wrong-SYN gap, which need
not exceed one second. Any wrong-tuple guest response, additional connection,
early authorized SYN, short/overlapping interval or unexplained frame fails.
The ARP receipt's exact bytes/hashes must match the capture; positive and
negative client monotonic intervals cannot overlap. Host and guest clocks
are never compared. The new condition is observed sustained wire refusal
under the known source predicate, not guest filter-drop telemetry, proof that
every guest poll ran, or a physical elapsed-time guarantee.

### Exact new build inputs and minimal offhost recipe

Build product and kernel from clean, separate frozen checkouts, not from the
oracle checkout while calling it product79. Prefix-free canonical archives
are defined by `git archive --format=tar REVISION` (no `--prefix`):

| Input | Revision / tree | Archive bytes / SHA-256 |
| --- | --- | --- |
| Product | `79f6d167046b9b4e3eac42e47c75e21371c9c8c1` / `b1cbd6ccba12d0f90de00c45e21fa39e60d817ec` |26286080 / `e91c27fc5748069a1c906c3441a7f3342cb529122580ad399754b221237f1cc2` |
| Kernel | `2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b` / `8763f164ddfed11aa2f55626bd8e85123c595a08` |12574720 / `fbfff7902d7bf6334b0c2d141558ef8cbdb23d56ce3db0c81dd32ebfb81be224` |

The source-only author computed these archive identities as streams and
discarded the bytes. The future operator retains exact archives, actual build
commands/logs and authentic toolchain/std/cache receipt as before. The product
build script is unchanged. The current kernel requires the existing served
wrapper `scripts/served_kernel.py`, SHA-256
`e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2`,
with `frame-admission-v0`. The new build receipt schema is
`absd-native-tcp-server-build/2`: retain all fields of the historical example
below, replace the product/kernel identities and exact archive sizes/hashes
with the table above, and add `served_kernel_policy: "frame-admission-v0"`
and `served_wrapper_sha256` with that exact wrapper hash. Its actual command
vector must include the served wrapper, `external-build` and
`EXTERNAL_USER_ELF=...`. Unwrapped `make` and an old ABI do not pass this profile.
Build/source, log/toolchain, unique child→parent→kernel→ISO containment and
all existing complete capture, native/accounting and resource assertions
remain required. Receipt attestation is not compiler correctness.

On the fresh isolated disposable Linux VM, with absolute paths bound to the
new occurrence, the minimal command sequence is:

```sh
# Run from the oracle checkout; these 25 authored controls are not run on build_host.
python3 -B scripts/native-tcp-server-matrix-test.py -v
python3 -B scripts/native-tcp-server-cleanup-test.py -v

# Build in clean PRODUCT79 using its authentic offline Rust/std closure.
env -C "$PRODUCT79" sh scripts/build-native-tcp-server.sh
: > "$CASE_ROOT/empty"
python3 "$PRODUCT79/scripts/served_kernel.py" -C "$KERNEL2775" \
  EXTERNAL_USER_ELF="$PRODUCT79/tcp-server-service-probe.elf" \
  EXTERNAL_INPUT="$CASE_ROOT/empty" EXTERNAL_EXPECTED="$CASE_ROOT/empty" external-build
# Retain actual logs and fill the v2 build receipt before the oracle call.
sudo python3 -B scripts/native-tcp-server-matrix.py "$CASE_ROOT/native" \
  --child-elf "$PRODUCT79/tcp-server-echo.elf" \
  --elf "$PRODUCT79/tcp-server-service-probe.elf" \
  --kernel-elf "$KERNEL2775/build/external/target/debug/absd-kernel" \
  --build-receipt "$CASE_ROOT/build-receipt.json" --timeout 120
```

No PKI, QUIC ordinary30 prerequisite or new
execution framework is needed for this fixture. The operator owns admission,
durable supervision around this foreground case, exact source/receipt binding,
custody and full resource/key cleanup. No source author-created VM, key, target,
capture or large source archive is retained here.

Twenty-three artifact methods are authored: the original 14 names retain
their positive/data/FIN/ACK/EOF/capture checks (with explicit v2 receipt input),
plus 9 methods for actual ARP/neighbor helper call ordering and readback,
wrong-client timeout call/duration, missing/late readiness, short/equal wire
intervals, retransmission identity, overlapping client receipts and false
timeout/pin evidence. Method controls substitute sockets/clock/OS calls; they
do not by themselves establish a real Linux neighbor effect. The two existing
cleanup methods remain unchanged. Every method was UNRUN at this source freeze;
the later `a6fe` occurrence executed all 25 as recorded above.

### Formalization and lifetime limits

The bounded proposition is that a real wrong-source SYN follows observed
neighbor readiness, has a separately captured interval greater than one
second with no response, and is followed by the complete authorized flow.
Finite literal/ordering substitutions and the eventual raw capture are
proportionate. Assumptions include the exact build/source correspondence,
timestamped full capture, trusted Linux socket/neighbor observations and
monotonic clock behavior. Timeout text alone cannot prove refusal; neither
can an ARP exchange prove a cache update. There is no universal TCP filter,
hardware ownership, memory-leak or physical timing proof. This fixture does
not change a live implementation generation or transfer state/authority;
any future replacement still reconstructs versioned state and fresh grants,
never native Rust layout. Root reviews this source/readback; the integration
steward owns independent acceptance. Review/retirement is at source handoff or
2026-10-18T23:59:59Z, with unique source/rollback custody retained.

## Historical accepted proof and source record (unchanged)

Current independent bounded acceptance covers runtime `2b2f882c`, proof/peer
`c1377f6c` and native `20b8bf78-03cc-41be-acac-3551cd8198d3` with lane kernel
`ed6a15ea`. The original source-dispatch descriptions below are historical.
Exact results and immutable prior failures are linked by shared registry run
`6d5dc6bd-3886-4c14-a4ad-6f827afc982a`. Composed kernel 7 + platform 10 replay
remains the steward's separate gate.

The retained wrong-port client's `connect-timeout` is not refusal evidence:
its 300 ms timeout elapsed before the guest's 737 ms ARP response, and the
SYN reached the wire only 22 microseconds before the authorized SYN. The
whole capture establishes the actual wrong-tuple SYN and absence of any
SYN-ACK, reset or other response. It does not establish a separate sustained
negative-client interval. The next occurrence should settle ARP first, use
a timeout above one second and separate the wrong and authorized attempts
in time while retaining the strict capture assertion. These are future
qualification changes, not a reinterpretation of the sealed result.

Guest-side filter-drop telemetry and the cause of the initial ARP delay are
open follow-ups on coordination issue 29. Only the existing capture and source
filter predicate establish this run's wire refusal. One native ACCEPT also
does not mean only one pre-ACCEPT transport handshake; see the core document.

This separate, unexecuted case qualifies the one IPv4 server consumer described
in NATIVE-TCP-SERVER.md. Product source is frozen at
2b2f882ce486ed85ba32b21e039e4521c96e2c63, tree
699e237c94e00dec19266ec1fb8c8a02d165e412. The runner does not compile code,
change the kernel or update an older runner/verdict. Source checks are not
host/native execution or independent acceptance. Release/main/U1/ABI holds
remain in place. The resource owner runs this foreground case serially only
inside the separately admitted disposable Linux VM, after source readback.

The three original additive files are `scripts/native-tcp-server-matrix.py`,
its artifact control file, and this document, first frozen unexecuted at
3bc9c2c586d092a32ca4dd6c4f449bb1271f9a2b. That source stays replayable and
was superseded before execution for the pending-response authority correction.
The 6334 source successor updated only the runner source binding and this doc.
A separate source successor under run 8ea6d20d-d9f1-4700-9973-efdca144151b
corrects directional ARP producer correspondence and adds one literal control.
All other TCP, native output, source, bounds and cleanup predicates stay unchanged.
The core, consumer, build script,
manifests, pins, lockfile and old runners remain byte-identical to the frozen
product revision. The independent Linux peer's single-connect correction is
described below; it is not an input to the native executable build.
The kernel input is the unchanged reviewed reason-log
successor ed6a15ea7c7c999422e1e294e139b6119619b06c, tree
5c3834dcdb8cf393c86bc0e436ae62c7cda67af5. No new dependency is introduced.

## Concrete input and build correspondence

The resource owner retains the clean build-source identities, complete build
command vectors, hashed build logs and pinned toolchain receipt. Before building,
create exact source replay archives with `git archive --format=tar REVISION`.
The platform archive SHA-256 is
75887cfefbf637a1806d912a5a3f703d8a638fb4bb13abc0382872f2f255dd9a;
the ed6 kernel archive SHA-256 is
568ac7c029d9d8e6e101519b1341c2e860300cb7dded1e65ea526efaa731212e.
These are canonical uncompressed Git archives, not directory snapshots that
silently include compiler output. Source-only production computed their hashes
as streams without retaining another archive or running a compiler.

Build the two frozen consumers with `scripts/build-native-tcp-server.sh`, then
build the ed6 dedicated kernel using `EXTERNAL_USER_ELF` set to the exact
`tcp-server-service-probe.elf`. Preserve the original source files and build
logs. The runner requires a JSON receipt with schema
`absd-native-tcp-server-build/1` and these fields:

```json
{
  "schema": "absd-native-tcp-server-build/1",
  "platform": {
    "revision": "2b2f882ce486ed85ba32b21e039e4521c96e2c63",
    "tree": "699e237c94e00dec19266ec1fb8c8a02d165e412",
    "clean": true,
    "archive": {"path": "/absolute/platform.tar", "bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"}
  },
  "kernel": {
    "revision": "ed6a15ea7c7c999422e1e294e139b6119619b06c",
    "tree": "5c3834dcdb8cf393c86bc0e436ae62c7cda67af5",
    "clean": true,
    "archive": {"path": "/absolute/kernel.tar", "bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"}
  },
  "commands": [["sh", "scripts/build-native-tcp-server.sh"], ["make", "EXTERNAL_USER_ELF=/absolute/parent.elf", "durable-iso"]],
  "logs": [{"path": "/absolute/build.log", "bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"}],
  "toolchain_receipt": {"path": "/absolute/toolchain.json", "bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"},
  "outputs": {
    "child": {"bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"},
    "parent": {"bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"},
    "kernel": {"bytes": 0, "sha256": "REQUIRED_ACTUAL_HASH"}
  }
}
```

This example is deliberately incomplete and cannot pass. Use actual commands,
sizes, hashes and custody paths from the serial build. The runner reads each
input once with a bound; the exact buffers define identities and retained
copies. It validates the reviewed archive hashes, build receipt/output hashes,
unique exact child containment in parent, and unique exact parent containment
in kernel. The same kernel buffer is staged into the ISO and must occur there
exactly once. Log and toolchain bytes are read, rehashed and retained too.
The receipt is the build owner's attestation of source/command consumption;
containment is direct byte evidence. Neither establishes compiler correctness
or proves the source of arbitrary supplied binaries without the build record.

The eventual resource-owner commands are:

```sh
python3 -B scripts/native-tcp-server-matrix-test.py
python3 -B scripts/native-tcp-server-cleanup-test.py
sudo python3 -B scripts/native-tcp-server-matrix.py FRESH_WORK \
  --child-elf /absolute/tcp-server-echo.elf \
  --elf /absolute/tcp-server-service-probe.elf \
  --kernel-elf /absolute/ed6-dedicated-kernel.elf \
  --build-receipt /absolute/build-receipt.json --timeout 120
```

Nothing in this source task executes those commands. A missing input, missing
predicate or cleanup failure is FAIL, never an implicit passing control.

## Independent peer and complete capture predicates

The runner creates a fresh named namespace and one TAP with Linux address
192.0.2.1/24, a fixed private fixture MAC and verified MTU 1500. IPv6 is disabled
in this IPv4-only namespace before creating the TAP. QEMU uses TCG, one CPU,
max/GenuineIntel/RDRAND and the fixed guest MAC. The raw QEMU capture is retained
unmodified. No synthetic readiness packet, capture rewrite, NIC counter reset,
readiness-based counter deduction or packet/SYN/MSS mutation is used.

The trusted parent emits LISTEN READY only after its channel processed LISTEN
and the sole socket exists. Only after observing that marker does the runner
launch a normal Linux AF_INET client bound to port 42031. Connect must time out
without data; the capture must contain its SYN and no server response or other
progress for that tuple. Then the unchanged independent Linux peer binds 42030,
connects, sends 3072 deterministic bytes, half-closes, checks every echoed byte,
observes EOF and exits normally. The serialized launch order and whole-capture
predicate require the refused SYN before the first authorized SYN; no eligible
SYN may precede it. The marker is a polled serial observation, not a clock
synchronization or hardware exclusion claim. Counter equality is unnecessary:
all four refusal/missed/TX-error counters must be zero over the complete boot.

The first native run `ec9cbda7` failed this strict capture check: the peer's
300 ms application connect/rebind loop abandoned an attempt, and Linux sent
a reset for its delayed SYN-ACK before the later connection completed. That
run remains FAIL. Its peer-only source successor makes one connect call after
LISTEN readiness, allowing four seconds for that handshake within one eight
second total peer budget. It performs no userspace reconnect; ordinary kernel
SYN retransmissions keep the same sequence identity. Product deadlines, exact
ELFs, source/packet predicates and the no-reset criterion remain unchanged.

Every captured frame must classify as exact peer ARP, an incoming wrong-port
SYN, or the exact authorized TCP tuple. The census checks Ethernet/IP tuples,
IPv4/TCP lengths, checksums, no fragments/options/extra protocols, bounded known
TCP options and MSS 1460 for both SYN directions on Ethernet1500. It reconstructs
3072 exact application bytes each way with consistent retransmissions, no
sequence gaps, ACKs bounded by already captured peer sequence space, peer FIN
before server FIN, and captured acknowledgement of both FINs. Both directions
need multiple data segments. Unknown peers, tuples, data, resets, malformed
frames or omitted capture records fail. The Linux socket result separately
requires the exact tuple/digest, write half-close and receive EOF.

Guest ARP requests require broadcast Ethernet destination and broadcast target
hardware bytes, as emitted by pinned smoltcp. Incoming Linux requests require
zero target hardware bytes and either broadcast or exact guest Ethernet
destination. Replies retain exact source/target IP and hardware tuples. A
literal control uses the unchanged 60-byte frame 12 from sealed native DHCP
run 46771e55-9091-4c55-8abd-cf98b1fc3173, capture SHA-256
fc2c88865999ee230df09a026dc3405670f3fdc1d9d164f1a726fd76aefd5fc0,
frame SHA-256 161373db3a1188391be4fa2f50c61e581f527a762a8941469636cc3515df9e2f.
Its producer, guest IP/MAC and peer IP match this profile; that request has no
peer MAC field. The pinned engine constructs the broadcast target hardware in
`smoltcp-0.14.0/src/iface/interface/mod.rs:1152`. Directional target/destination
substitutions must fail. This producer correspondence is existing DHCP packet
evidence, not TCP interoperability or a retroactive server execution verdict.

Native output requires exact ordered grant/listen/child/done markers, successful
child and parent accounting/exit, zero retained resources and positive traffic.
The wrong-port wire refusal is distinct from the child's actual framed wrong
peer denial and absent-NIC check. At this historical source freeze the host
core boundary tests were authored and UNRUN; the later exact host suites
are recorded above. Native negative cases other than that one source-port
case remain explicitly UNRUN.
This is not a general listener, backlog, routed-path, clock or live SSH proof.

## Bounds, cleanup and custody

The whole guest/client phase has one 10..180-second host deadline. Every regular
file produced by QEMU or clients is capped at 2 MiB with RLIMIT_FSIZE; logical
serial/log limits remain 8 MiB and capture 2 MiB/256 complete frames. Input ELFs
and replay archives are bounded 64 MiB each, ISO 128 MiB, disk 2 MiB. The resource
owner must admit aggregate temporary storage separately; an upper estimate is
1 GiB worst-case file allocation including exact retained copies, two source
archives, at most eight build logs, ISO and producer file caps. The owner
measures actual inputs and admits the resulting aggregate before launching.
The old 32 MiB source forecast was not runtime admission or a per-lane quota.
Actual aggregate allocation, evidence custody and the independent 60 GiB free
reserves on `/` and `/data` govern the resource occurrence.

The ISO builder and each long-lived process own a fresh session/process group.
The ISO builder has a 60-second bound and a 128 MiB file cap, with its log
checked against 8 MiB before success. Both
normal and failure paths terminate/wait exact owned groups, verify no group
remains, require the namespace have no processes, delete it and verify absence.
Cleanup addresses the original process group even if its leader has exited:
TERM is followed by a bounded group-absence wait and KILL if members remain.
Namespace creation is recorded as attempted before its control call, after an
initial exact-name absence check. Cleanup reconciles that name even if add
times out after mutation; it never deletes a pre-existing name without an
owned creation attempt. Unknown state, live namespace processes or residual
groups/namespaces fail cleanup. The original interruption remains a failed
run even when cleanup subsequently establishes resource absence.
This short foreground run assumes continued ownership of the original PGIDs
and that descendants stay in their owned session/group. It is not a general
PID-reuse or daemon-reparenting proof. Unknown control/identity state requires
resource-owner reconciliation instead of a cleanup success claim.
Cleanup failure overrides any pending PASS. Fresh RESULT, LAUNCH,
LISTEN-OBSERVED and LOCAL-CLEANUP records keep execution distinct from source
readiness. TERM/INT enters cleanup; SIGKILL/host loss cannot guarantee cleanup
and must be reconciled by the resource owner from LAUNCH before retrying.
This foreground case is not an unattended producer or supervisor-loss service.

Root coordinates lane storage; the steward owns aggregate ABSD storage.
Retain exact sources, replay archives,
ELFs/ISO, capture and minimal records until independent review/replay custody
ends. Retire reproducible staging/disk/log copies only after the named consumer
dependency ends and ownership checks; Root custody review is at dependency
end or 2026-10-18T23:59:59Z. No VM, key, namespace, compiler output or capture
is created by this docs-only source task; the actual runtime substrate was
retired under its separate resource receipt above.

## Formalization consideration

The proposition is limited: observed LISTEN precedes the controlled wrong-port
attempt, wrong-port traffic cannot consume the slot, and one authorized finite
flow corresponds across native result, Linux result and a fully explained
capture. Source/replay hashes constrain substitution; the trusted build owner,
capture completeness, Linux kernel and parser correspondence are assumptions.
The original fourteen pure artifact methods cover directional ARP correspondence,
missing/reordered refusal, wrong tuple,
checksum/data substitution, sequence/ACK gaps, FIN/EOF/MSS/reset omissions,
native counters/accounting and exact embed/source substitutions. They were
authored and UNEXECUTED at that historical freeze. The later full 30-method
artifact suite and two cleanup methods executed in `1476`, as recorded above.
The separate cleanup substitution controls preserve
the exited-leader/group case and namespace mutation followed by timeout,
including unknown/live residual refusal. They replace OS controls only within
those tests and create no real signal/namespace effect. The original fourteen
artifact methods remain unchanged. Practical finite controls and explicit prose are
proportional; no proof of arbitrary TCP, compiler trust, hardware ownership or
post-effect rollback is claimed. S2 root owns the decision and independent
acceptance remains external to this runner.
