# Linux closed-port proof source

## Candidate 10e composition scope

Candidate 10e carries runtime `f593c5da9e16268d68c18ffb8a8b75513ce6a58d`
and proof `b6c53d0dc58fd525d8d731765de7f7e84cfa3857` after the IPv6 HTTPS
carry. Native run `67b03770` qualifies that standalone f593 product with
kernel `ed6a15ea7c7c999422e1e294e139b6119619b06c` only. The composed
candidate 10e native feedback case is **UNRUN**. No standalone verdict is
transferred by composition.

The PRODUCT, PRODUCT_TREE and PRODUCT_ARCHIVE constants in
`scripts/native-ipv6-feedback-matrix.py` intentionally retain that standalone
f593 replay. Its KERNEL, KERNEL_TREE and KERNEL_ARCHIVE still select ed6,
not candidate kernel 8 `929a8efd7dee6a0f227c677cb453516b9a380c10`.
Before that matrix can qualify a composed native case, its source/archive
pins and fresh build receipts must be rebound to the intended pair and the
case must actually run. Keeping this standalone replay does not supply a
composed result.

The POLICY metadata at `scripts/native-ipv6-accounting.py:32-36` likewise
names reference kernel ed6 and its `docs/NETWORK.md` SHA256
`90d0f407ca26e1fe5ad814441d0b0105c08852278167b55aa657ead5d3380110`.
It is retained reference provenance, not an attestation of kernel 8's current
document. Kernel 8's document hash is
`e7a804b054eca264c3719032d901f8f60a73bafe1b7f706adc687ed26aea911e`.
The actual `src/e1000_ring.rs` buffer remains byte-identical at the two
revisions, SHA256
`205e033d5659afd61d7d3596dd85a7c0348ed859c1675af304b1390965ee2ae8`.
The helper bytes and every accounting predicate are unchanged by this scope
clarification; actual kernel input identity comes from the exact build and
source receipt, not from this reference label. Current IPv6 HTTPS replay
inputs are listed separately in `NATIVE-TLS-IPV6-PROOF.md`; they are also
preparation inputs, with composed native replay unrun.


This prospective replay pins the DNS advisory runtime
`f593c5da9e16268d68c18ffb8a8b75513ce6a58d`, independently of this proof
commit. Build the child and parent from that exact runtime revision, not the
proof tip. The unchanged ed6 kernel remains required. Only three runner source
identity constants and this document change; all 14 artifact methods, helper
bytes and strict native/build/accounting/cleanup predicates stay unchanged.
The streamed runtime archive is 22,292,480 bytes; no archive file was created.

The accepted native run `658621d9-a4ab-4e1e-ba31-dee31e44eb8e` applies to its
recorded 5df550 runtime and proof inputs. It does not qualify f593. The latter's
expected full host suites are 158 default network, 170 DHCP network and 17 SSH
methods; these and the artifact/native replay remain UNRUN by this source task.
Root coordinates their serial resource and custody after DAD. No old result is
relabeled and no TCP, engine, kernel or ABI behavior changes in this proof tip.

The source-binding result label now uses the enforced `PRODUCT` and `KERNEL`
identities, and CLI help describes those pins without a stale revision name.
This metadata-only successor leaves all core inputs, assertions, bounds,
accounting, cleanup and artifact methods unchanged.

Historical core binding successor `ab15bdd9-0760-4083-a921-b1d7bb8eb82f`
preserves every runtime and build input from core
`5df550ca4ee81f634a00b45a6ce7530e00fe8b8e`, tree
`e8c79af110367829bcf3515ce7ca9692cb21ad7c`. Only the three runner source
identity constants and this owning document change. The 14 artifact methods,
per-exact-quote prefix bound, accepted helpers and every native/build/cleanup
predicate remain unchanged. Core correction attempt
`adaf7b0f-f503-4a2e-8fc1-35adca830fad` initializes the shared transmit frame
before the pinned emitter, after the actual NA-to-error reused-byte diagnosis.
Original default `3ec5e8c9` and focused `6bc84cc6` failures remain immutable;
fixed-source compilation, consumer regressions and native proof are separate
resource-owner execution. This source producer executes none of them.

The preceding correlation correction `3c483535-07a1-4ad3-911c-66448e3226c4`
was frozen at `07817bd6` with core `86283e31`. The original proof attempt
`f49d1ef1-d670-4dad-af06-45e43918ea51` and source `ff5867da` remain immutable.
Independent readback `64dbdc3d-61d2-49ca-a669-41924ada1c64` found that a
global error count could borrow capacity from a different IPv6 header with
the same DNS question. That correlation correction strengthened the proof
predicate and added two artifact methods. It also pinned the then-current
core successor, whose only change supplied an empty observer to an existing
test initializer after the recorded compile failure `684f68dd`.
No runtime behavior or passing result is
inferred. Core review `ff1ec049-3c9d-4df5-8241-5bc2fedcb747` and all earlier
notices and results retain their original scopes; no test is executed by this
source producer.

The actual independent peer is the Linux kernel in a new isolated namespace,
with fd00:ab5d::2/64, MTU 1500 and 52:55:00:00:02:02 on one TAP. The guest is
fd00:ab5d::15/64, 52:54:00:ab:5d:15. Only IPv6 connected routes exist there;
RA, autoconfiguration and DAD are disabled for this static fixture. Normal
Linux MLD remains enabled. The runner verifies the exact address/MAC/MTU,
connected routes and no UDP listeners before and after the guest. Nothing
binds UDP 42019, sends a readiness datagram or supplies ICMP in userspace.
No host route, interface, service, clock or public connection is changed.

The resource owner supplies exact prebuilt runtime f593 child, parent and ed6
kernel ELFs plus a build attestation. The runner reads each bounded input
once, checks unique exact child-in-parent, parent-in-kernel and child-in-kernel,
retains those same buffers, writes the kernel into the boot tree and requires
its exact bytes once in the ISO. Final hashes bind all evaluated inputs to
retained evidence. Input paths are not re-read to define earlier identities.

Build attestation schema is `absd-native-ipv6-feedback-build/1`, with platform
and kernel objects containing `revision`, `tree`, `clean: true`, and `archive`
(`path`, actual positive `bytes`, `sha256`). It also carries actual `commands`
as nonempty argv arrays, one to eight hashed nonempty build `logs` with custody
paths, one hashed nonempty `toolchain_receipt`, and `outputs.child`,
`outputs.parent`, `outputs.kernel` each with exact `bytes` and `sha256`.
Commands must include `scripts/build-native-ipv6-feedback.sh` and an
`EXTERNAL_USER_ELF=` argument. The source replay archives must be exact
uncompressed `git archive --format=tar REVISION` streams:

| Source | Revision / tree | Archive SHA256 |
| --- | --- | --- |
| Platform | f593c5da9e16268d68c18ffb8a8b75513ce6a58d / 9e521573fed9a5d45dd6ce36037d9da9d4b8dbcf | c8fb1e3eb0786b9fc62a8577d1385008bcadaaddf3a3283886adc0ce55099e14 |
| Kernel | ed6a15ea7c7c999422e1e294e139b6119619b06c / 5c3834dcdb8cf393c86bc0e436ae62c7cda67af5 | 568ac7c029d9d8e6e101519b1341c2e860300cb7dded1e65ea526efaa731212e |

Actual archive/log/toolchain bytes are bounded, rehashed and retained too.
The receipt is the execution owner's attestation of clean source and command
consumption; exact containment is direct buffer evidence. Neither proves
compiler correctness or arbitrary binary provenance without that build record.
After source readback, only the admitted resource owner executes:

```sh
python3 -B scripts/native-ipv6-feedback-matrix-test.py
python3 -B scripts/native-ipv6-reason-accounting-test.py
python3 -B scripts/native-ipv6-accounting-test.py
python3 -B scripts/native-ipv6-feedback-matrix.py /owned/fresh-proof \
  --kernel-elf /owned/absd-kernel \
  --elf /owned/ipv6-feedback-service-probe.elf \
  --client-elf /owned/ipv6-feedback-client.elf \
  --build-receipt /owned/feedback-build.json --timeout 120
```

The runner launches one TCG CPU/256 MiB QEMU, exact e1000 MAC and one TAP/raw
PCAP, with no other guest network. PASS requires debug exit 3, boot/durable/link
markers, ordered exact owner-ready, child authority/no-NIC, one unauthenticated
Port Unreachable observation before the 3000 ms lookup bound, normal child reap
and zero sockets. Every output chunk is ordered and bounded. Boot observations
are scheduled elapsed samples, not physical-time precision or clock conversion.

Whole raw capture must contain guest NS and Linux NA before the first query,
valid strict direct-neighbor ND, explained Linux MLD, outgoing exact 7002 ->
42019 UDP DNS, and incoming exact Linux type 1/code 4 with zero unused detail
and complete original-packet quote. Original IPv6/UDP/ICMP checksums, endpoint
and MAC identities, lengths, question and quote bytes are checked. One to four
byte-identical DNS questions/IDs are permitted by the existing 3000/750 ms
resolver retry budget; accepted TCP evidence showed retries can overlap ND.
Every error must quote a previously captured complete query. Duplicate query
copies retain all compatible capture indices rather than inventing unique
packet delivery or generation. At each capture prefix, the error count for an
exact quoted IP-byte group must not exceed the number of earlier captured
requests in that same group. Different valid IPv6 headers do not share this
capacity, and a later request cannot justify an earlier extra error. This
bounds errors by copy multiplicity without a unique request-to-error
assignment. One consumed native diagnostic is required. Unknown traffic, extra
tuples, changed question/ID, omitted request/error/ND, corrupt/truncated bytes or more
retries fail. Later ignored diagnostic copies remain in the capture census.

The approved accounting and its tests are copied byte-identically from accepted
source `4a6e7c52124131b828e3ce093d504886d065657e`, also shared by TCP
`4f9331e45b61373369914947a8932112fc3b3984`. Their existing `udp` and `tcp`
profiles, first-four destination-reason policy and run633db4 sidecar-equality
correction remain unchanged. A separate adapter imports a private helper
instance, adds only exact profile `feedback` (UDP 7002/42019), and extends its
classifier solely for strict complete-quote ICMP type 1/code 4. The original
classifier handles ND, DNS and MLD unchanged. The unchanged reason evaluator
still decides the verdict: at most four exhaustive destination-refusal reasons,
matching compatible captured destinations, no unexplained or refused protocol
peer frame, no descriptor reasons, and zero missed/TX-refused/TX-error counters.
There is no new tolerance, counter subtraction or strict-zero IPv6 rule.

Ready observation is a sidecar, never a PCAP rewrite or synchronized DMA
boundary. The exact bounded serialized sidecar must equal its evaluated object;
raw serial/PCAP and reason-result buffers must agree across protocol inspection,
accounting and final artifact hashes. Capture-prefix and repeated-destination
ambiguities retain the accepted helper's stated limits. Native malformed,
exhausted, interrupted, fault, replay, PTB/routed recovery and live SSH cases
remain UNRUN; a positive Linux closed-port exchange cannot establish them.

Fourteen artifact methods author positive complete exchange and repeated-query
controls, retained MLD census, retry/error bounds, full valid-checksum quote
substitution, wrong tuple/MAC/length, checksum corruption, missing/reordered
ND/request/error, incoming UDP, capture truncation/extra protocol, output/exit
markers, and source/archive/output substitutions. The two correction methods
include same-DNS/different-hop-limit packets with recomputed valid outer ICMP
checksums, refused repeated quotes of just the first header, positive separate
header groups, and positive identical-copy multiplicity bounded by earlier
requests. Existing accounting/reason controls remain unchanged. None is
imported or executed by this source task.

Fresh outputs are mandatory. Outer timeout 10..180 seconds (default 120) covers
setup through protocol inspection, with a separate 60-second ISO deadline and
five-second control-command bounds. Files have polled/final limits: ELFs and
archives 64 MiB each, ISO 128 MiB, scratch 2 MiB, capture 2 MiB/256 frames,
serial/logs 8 MiB and decoded native output 16 KiB. A transient producer overshoot
can occur and fails; this is no instantaneous allocation/preemption guarantee.
The resource owner must separately admit actual runtime output; a conservative
1 GiB aggregate staging allowance covers retained inputs, archives/logs, ISO,
boot tree and temporary ISO work. Source 32 MiB alone admits no runtime output.

Each producer owns a new session/PGID. Cleanup handles exact original groups,
including descendants after leader exit, with bounded TERM then KILL/wait;
forced cleanup fails this case. Namespace creation is marked attempted before
the call and exact-name reconciliation runs even after an uncertain add result.
Only an empty owned namespace is deleted and absence verified. No unknown
process is killed. Pending PASS is overridden by residual groups, namespace
uncertainty, cleanup errors, artifact mutation or final bounds failure. No keys
or provider resources are created. Host loss/SIGKILL may leave no terminal
record: reconcile exact launch/groups/namespace before any successor; absence
is never PASS. This foreground task is not an unattended producer service.

Formalization consideration: exact source/build/buffer correspondence,
complete protocol census, unchanged bounded reason policy and cleanup absence
are a finite conjunction under trusted execution-owner attestation, truthful
Linux/runtime tools, complete PCAP and no concurrent mutation of the fresh
mode-0700 directory. Practical substitution controls and source invariants are
proportional. The explicit prefix/group counter addresses the finite observed
counterexample; no new general model is needed for this bounded proof
predicate. They do not prove compiler trust, authenticated peer identity,
physical deadlines, packet-specific delivery, general IPv6/ICMPv6 conformance
or hardware transfer. Already submitted I/O effects remain irreversible.
Root/steward own the decision and separate acceptance.

This is a proof implementation generation, with no live state transfer,
exported state schema, authority rebind, fenced-handle revival, kernel ABI or
post-effect rollback mechanism. This pin-only proof change preserves all f593
runtime/build inputs; old 5df550 evidence keeps its original scope. Release/main/U1
holds remain. Root owns aggregate storage and the
32 MiB source allowance. Retain
minimal commits/receipts and exact current replay inputs; root retires source
worktree and reproducible runtime staging/scratch after integration/review/
replay users end. Next custody review: 2026-10-17.
