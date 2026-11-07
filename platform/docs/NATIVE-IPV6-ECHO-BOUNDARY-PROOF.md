# Pinned native Echo boundary proof

Profile `ipv6-echo-responder-boundary-v1` selects one finite fixture, not a
conformance matrix. Product 63235f0fab9355f7cf15de31b70104c9196fc64c, tree
383c7d6b2e0c8ca2fe8b86d85f849acbaa5f824f has prefix-free canonical Git archive
26,757,120 bytes, SHA-256
`a5ff5049fd30a87848152e6582a2a2c9827b05b7850635523cdb21c7550eedc3`.
The independent oracle commit follows this product and is named by the immutable
lane handoff, not a self-reference. All build, host, Linux and native execution
at these sources is UNRUN. Prior 3cd/ed126 positive results and e565 source-stage
history remain separate. Old responder/TCP runners and verdicts are unchanged.

The 974 occurrence at product 4c22/oracle f622 passed all 21 artifact methods
but failed default host compilation before a harness ran: the shared fixture
lacked explicit `format` and `Vec` imports in the `no_std` crate's test module.
Its whole FAIL and later UNRUN phases remain unchanged. Product 27e82423 adds
only `use std::{format, vec::Vec};`; both consumers expose `std`, through the
native binary or the net crate's existing `cfg(test)` declaration. Recorder
logic, test methods and proof criteria are unchanged. Compilation and runtime
of this successor remain UNRUN until a fresh offhost occurrence.

The next 9df occurrence at product 27e82423/oracle 77faf541 passed all 21
artifact methods, then ran 365 default net methods with 364 passing and the
new actual-owner boundary method failing its missing warm NA assertion.
Its exact fixture expected flags 0x60, but pinned smoltcp 0.14 emits only
SOLICITED (0x40), without OVERRIDE, for this NS. Product 63235f0f corrects the
single golden NA and checksum; this oracle independently constructs that same
exact frame. Existing host and artifact methods explicitly refuse the old
checksum-valid 0x60 substitution. Full-frame equality and all protocol/authority
criteria remain strict; no production admission, engine or dependency changes.
The 9df whole FAIL and later UNRUN phases remain unchanged. All actual execution
of this corrected source remains UNRUN until fresh offhost qualification.

At unchanged product 63235f0f/oracle 1284dd54, occurrence 72a passed all 21
artifact methods, 365 default and 378 DHCPv4 methods, and both builds, then
failed the native warming bound. Its complete capture contained two MLD
reports and guest DAD, with no Linux NS or guest NA. That whole/native FAIL
remains unchanged. This oracle changes only the disclosed input setup below;
product 63235f0f, exact four negative vectors and authority bounds stay fixed.

Occurrence 41fd at the explicit-setup oracle a82e04db passed all 24 artifact
methods and completed raw warming, configured-neighbor readback and negative
input receipts, but failed while live stdout ended in the partial seventh line
`PING6 RESPONDER NEG COMPL`. That whole/native FAIL remains unchanged. This
observer successor waits for the seventh line's newline before calling the
unchanged exact validator. Every proper prefix remains unready; complete
malformed lines and early positive output still refuse. Product, terminal
evaluation and all deadlines are unchanged; new execution remains UNRUN.

Kernel 2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b, tree
8763f164ddfed11aa2f55626bd8e85123c595a08 uses canonical prefix-free archive
12,574,720 bytes, SHA-256
`fbfff7902d7bf6334b0c2d141558ef8cbdb23d56ce3db0c81dd32ebfb81be224`.
Current served wrapper SHA-256 is
`e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2`,
policy `frame-admission-v0`. The launch uses served_ram with at least 256 MiB.
The old ed6 pairing is not used by this profile.

## Exact observation chain

The fresh owned TAP initially has no IPv6 address. Set/inherit and verify
addr_gen_mode 1 to suppress automatic link-local generation. Observe the exact
raw kernel NETWORK LINK OK line through ReadyMarker with producer running,
then add and verify the sole exact fd00:ab5d::2/64 address. Retain the original
observation and before/after lists in PEER-ACTIVATION.json. This input ordering
is the corrected 262f lesson from the separate TCP proof; the import-only
product repair preserves this profile/build schema. Existing f03c remains frozen, all new
execution is UNRUN, and no previous TCP component result becomes Echo evidence.

DAD for candidate ::15 must complete; actual native READY must be observed as a
retained decoded worker-output prefix while QEMU is running. Raw NIC readiness
and worker READY are separate channels. After an empty neighbor readback, the
bounded raw fixture sends one exact ::2 NS with SLLA and waits for the actual
matching guest NA. Its socket closes before WARM-INPUT.json is written. The
parent requires both exact frames in the full capture, then administratively
sets the fixture-known guest MAC with `ip neigh replace ... nud reachable`.
The before/after JSON, exact command, raw socket receipt and capture-prefix
binding are retained in LINUX-NEIGHBOR-WARM.json. The exact TAP, destination,
MAC and configured REACHABLE state must read back. This is disclosed raw input
and administrator neighbor configuration, not automatic Linux kernel ND or an
independent NUD reachability measurement. A configured entry alone cannot
substitute for the actual NS/guest NA exchange. Device-filtered JSON can omit
`dev`, so readback uses `to ::15 nud all` without a device selector inside the
sole owned namespace. The original three-second warming bound is retained;
each raw exchange remains bounded by two seconds, without guest deadline renewal.

Next a bounded AF_PACKET fixture, disclosed in peer facts and not an Echo
responder, next sends one exact ::3 NS/SLLA. It must receive the actual matching guest
NA before sending four literal negative inputs, once each. All socket calls are
bounded before I/O by the case deadline/event budget; short send, missing NA or
unexpected output fails. A receipt retains complete raw send/receive bytes,
ordinals, monotone samples and socket close. There is no new public interface,
raw positive request, userspace reply, permanent neighbor entry or external host.

The native Link wrapper returns actual receive bytes unchanged through the real
Owner. Its raw four-input records and exact NS/NA observations must match full
capture bytes and incoming Link ordinals. Negative packets with deliberately
invalid checksum/shape are admitted by the *oracle census only as those exact
literal inputs*; other malformed frames remain unexplained and fail. Both
cache preconditions precede the inputs, no Echo reply or unresolved-neighbor NS
may stand in for a refusal, and the same Owner must remain Again/zero effects.

Only after the actual native NEG COMPLETE prefix does installed Linux `ping`
launch (`-6 -n -c 1 -W 2 -w 3 -s 56 -I fd00:ab5d::2 fd00:ab5d::15`). The capture
must show exactly one ordinary 64-byte positive Request and matching Reply with
valid checksum, endpoints, identifier, sequence 1 and entire body. Linux must
report exit 0, one transmitted/received and true positive data. Native successful
submission remains bounded by the original Owner stop, with possible effects 1
and zero sockets. Subsequent actual Owner methods require Spent, Exhausted and
retired Stale; no packet replay or expiry-stop claim follows.

All nine native records, contiguous output chunks/FNV, normal owner exit, no
child spawn, durable terminal accounting and complete capture are mandatory.
Retain WARM-INPUT.json, LINUX-NEIGHBOR-WARM.json and warm.log alongside the
existing negative-input receipt and raw artifacts. The new raw helper process
is owned, bounded and reaped separately; it is not a guest child.
The whole capture still starts at launch; there is no capture trimming,
counter reset or guest deadline renewal. The original first-four destination-
reason evaluator and immutable accounting helper
22d5f091c23c0d436be538d3695b43b3ed52b48ec5b4b30668be215a08001ad3
are reused unchanged. The evaluator binds sealed full-capture/serial and ready
prefix hashes, requires exact printed-reason cardinality at rx_refused <= 4,
and requires enough compatible refused-destination copies in the whole capture.
It rejects refused protocol-peer frames, unexplained traffic and other NIC errors.
It does not partition refused frames before/after the readiness observation or
uniquely assign a captured frame to a processed descriptor/DMA event. Extra
pre-observation MLD does not by itself fail this narrower evaluator. Delayed peer
activation may avoid early inputs but does not upgrade that accounting claim.
This is not the older strict post-ready-counter PASS. Host and guest clocks are
not compared. This is fixture observation, not a production drop
counter, full handle/memory restoration or hardware timing proof.

## Minimal offhost recipe

Use fresh clean product/oracle/kernel checkouts and isolated targets. Execute
all default/DHCPv4 net `--lib --target x86_64-unknown-linux-gnu` locked/offline,
single-thread tests, retaining actual full summaries and harness identities.
Require all 20 `ipv6::dad::echo_responder::tests` methods, including
`native_boundary_actual_owner_refuses_consumed_inputs_then_serves_same_activation`
and `native_boundary_trace_cannot_claim_missing_priming_duplicate_or_reordered_input`.
The unchanged TCP and other networking methods remain ordinary regression tests;
actual counts are observations, not static PASS claims.

Run the new 21 artifact controls offhost only:

```
python3 -I scripts/native-ipv6-echo-boundary-test.py -v
```

They include three actual empty-link/address-activation/raw-vs-worker helper
controls, plus the preserved actual raw-sender method controls, independent literal construction,
full capture/native/census substitutions, readiness, build/metadata/ELF/ISO,
terminal resources, exact counters and mutation-seal cases. The historical
`native-ipv6-echo-responder-test.py` remains unchanged and may run separately;
its controls are not new native boundary execution.

Build the existing declared native bin from the exact product:

```
sh scripts/build-native-ipv6-echo-responder.sh
python3 scripts/served_kernel.py -C "$KERNEL" \
  EXTERNAL_USER_ELF="$PRODUCT/ipv6-echo-responder-probe.elf" \
  EXTERNAL_INPUT="$CASE/empty" EXTERNAL_EXPECTED="$CASE/empty" external-build
```

The wrapper invokes make directly. Retain actual Cargo metadata for the
`ipv6_echo_responder_probe` bin and required feature, canonical staged std
c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c
(2251 files/45,920,288 bytes), Rust 1.95 toolchain and authentic offline closure.
No dependency change is needed.

Build receipt `absd-native-ipv6-echo-responder-build/2` requires exact profile,
platform/kernel clean revision/tree/archive `{path,bytes,sha256}`, actual command
argvs/log/toolchain receipts, outputs `{parent,kernel}` digests with unique
embedding, empty external input/expected and exact parent path, served policy
and wrapper hash, target, staged_std and actual cargo_metadata `{path,bytes,sha256}`.
Metadata bytes are retained and checked, not just a declared digest.

With the existing finite resource lease and durable outer collector/producer
armed before waiting, invoke the new oracle:

```
python3 -I scripts/native-ipv6-echo-boundary.py "$CASE/proof" \
  --run-id "$FRESH_UUID" --elf "$PRODUCT/ipv6-echo-responder-probe.elf" \
  --kernel-elf "$CASE/kernel.elf" --ping /usr/bin/ping \
  --build-receipt "$CASE/BUILD-RECEIPT.json" --lease-end "$LEASE_UTC" --timeout 120
```

Result schema is `absd-native-ipv6-echo-boundary-proof/2`. Retain all exact
source/build/metadata/ELF/ISO, serial/FNV, full PCAP, both readiness observations, PEER-ACTIVATION and prepared/pre-ping state,
neighbor warm snapshot, raw negative-input receipt/log, ping ELF/version/argv/
output, peer before/after and cleanup. Exact negative/ping/QEMU/ISO process groups
and namespace retire on PASS or known FAIL; no future consumer or source-created
key/resource is implied. Original DAD/8-second-active/12-second-invocation limits
are not restarted by any fixture phase. Source custody/formalization/authority
and evolution limits are those in NATIVE-IPV6-ECHO-BOUNDARY.md; Root reviews,
integration steward accepts independently. Runtime stays UNRUN until actual
separately frozen offhost evidence exists.
