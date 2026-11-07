# Native IPv4 Echo wire correlation fixture

This additive issue #34 fixture uses the current `echo::Owner` and its unchanged
smoltcp engine. The existing `ping-once`, IPC boundary children/parents and all
older proof profiles keep their own source and results. The new opt-in feature
`native-echo-wire-probe` selects `echo_wire_service_probe`; its sole output ELF
is `echo-wire-service-probe.elf`. There is no pipe child or IPC qualification in
this occurrence. The native NIC owner itself is the actual API consumer.

All new host, build and native execution is UNRUN at this source freeze.
The source task runs no product imports, compiler, tests, guest or provider
operations on build_host. Root owns a separately committed independent Linux peer,
full-capture oracle and controls. Source readiness is not acceptance.

## Finite input and observation contract

The owner constructs an ordinary 8 s Echo grant, calls its real START once,
and retains the exact successfully submitted 74-byte Ethernet/IPv4/ICMP
request. Linux ARP remains real; Linux automatic Echo replies are suppressed
for this negative grant. The independent AF_PACKET fixture derives nine
selected inputs from the actual captured request. It waits for the native
case acknowledgement before sending the next input:

| Index | Case | Change from the reflected reply |
|---|---|---|
| 0 | wrong-peer | IPv4 source becomes 192.0.2.2 |
| 1 | wrong-type | ICMP type becomes 3 |
| 2 | wrong-code | ICMP code becomes 1 |
| 3 | wrong-identifier | Frame byte 38 XOR 1 |
| 4 | wrong-sequence | Frame byte 40 XOR 1 |
| 5 | wrong-body | Frame byte 42 XOR 1 |
| 6 | wrong-epoch | Frame byte 58 XOR 1 |
| 7 | wrong-nonce | Frame byte 66 XOR 1 |
| 8 | bad-checksum | Frame byte 36 XOR 1 after checksum construction |

The reflected base copies the captured IPv4 header and body, swaps Ethernet
and IP endpoints, and changes ICMP type to Echo Reply. IPv4 and ICMP checksums
are recomputed for every selected input; only the last ICMP checksum is then
deliberately changed. The type-3 input is a malformed error carrying the Echo
body, not an Echo Request that could trigger an automatic guest response.
There is no general ICMP error qualification or type-8 refusal claim here.

`ReceiptLink` calls the real Link, records actual received bytes and returns
them unchanged. It records successful local sends separately; a failed send
still fails the invocation and absence in that transcript never proves absence
of an effect. There are at most 32 RX and 16 successful TX records. Each
versioned FRAME contains direction, per-direction ordinal spanning both grants,
phase, local boot time, exact length and full hex. No receipt is synthesized
from a host-send declaration or capture alone.

After real `Owner::poll` processes a selected RX, the native owner first
requires exact equality to its expected selected frame derived from its own
submitted request. Its actual `Owner::observe` must return Again (5), with
socket count 1 and exactly one successful Echo Request submission for the
negative grant. A CASE marker records the selected receive ordinal, time,
case index/name and result. Unexpected non-ARP frames, reordered cases or
multiple selected inputs before acknowledgement refuse the fixture. Root's
full-capture oracle independently checks every actual frame, checksum, tuple
and native/host/frame correspondence; the native equality is not a replacement
for that independent check.

Before sending the final bad-checksum input, the peer enables Linux automatic
Echo. It never sends a synthetic positive reply or replays the negative
request. After processing the final input and observing Again, the owner
explicitly closes the negative grant, requires zero sockets and Stale for its
old endpoint, and constructs a fresh grant. That new grant sends one genuine
request answered by the Linux kernel. The actual Observation supplies peer,
identifier, sequence, instance, epoch, nonce and boot RTT. It is consumed once,
then the endpoint is closed and checked Stale. Linux kernel capture and the
actual native observation must agree; user-generated matching bytes alone do
not establish the positive consumer.

The whole fixture has an explicit 20 s bound. The original negative grant and
separately constructed positive grant each retain their original 8 s bound;
the latter must fit within the whole bound. No arrival or case acknowledgement
renews a deadline. Checks run after poll/observe and at final completion.
The versioned native record order is BEGIN, actual FRAMEs interspersed with
nine CASEs, RETIRED, POSITIVE, actual positive FRAMEs, OBSERVED and DONE. All
records use the `ECHO WIRE` prefix; the full terminal stream and exact END/FNV
remain evidence, not reconstructed replacements.

## Build and controls

On the separately admitted compiler VM, run both locked offline net host
variants with fresh targets and retained actual harnesses. The eight new
methods in `net/src/echo/wire_tests.rs` use the real Owner/engine and shared
fixture observer, including all nine selected inputs, fresh positive authority,
actual byte/ordinal retention, failed send effects, transcript bounds and
original clock checks. Retain the actual complete host counts and all older
tests; do not infer PASS from static enumeration.

`ABSD_PROFILE=core scripts/build-native-echo-wire.sh` builds the single native
bin with the authentic staged std/toolchain. No negative or positive child ELF
is required or embedded. Root's independent wire profile takes the exact
parent ELF, served kernel and output locations, and uses the pinned
`served_kernel.py`/`served_ram.py` wrappers. Current kernel is
`2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b`; no kernel/dependency/ABI change is
introduced. Canonical product/oracle Git archive identities, actual build
commands, metadata, source before/after and ELF/kernel/ISO nesting are recorded
in the source handoff and subsequent execution receipts. Do not manufacture a
build result or carry an older runtime result onto this revision.

## Claim limits and evolution

These cases establish refusal of exact delivered current-packet substitutions.
`wrong-epoch` describes a byte mismatch in the echoed body. Equal wire bytes
cannot establish the originating owner generation, physical packet history,
authentication, replay provenance or a rule that old packets never reappear.
A fresh grant changes local authority; it does not authenticate a peer. The
matching-byte host control explicitly records this limitation.

The receipt ordinal is a local observation, not a hardware descriptor/DMA
identity. Local boot times are checked against local grant bounds and are not
compared with PCAP clocks as physical timing. No general ICMP conformance,
fragment/option/length matrix, connected/pending-reply interruption, native
link/device/clock fault, live SSH coexistence or full memory restoration is
claimed. The old boundary occurrence retains its own IPC/constructor/EOF
scope separately.

No state-transfer mechanism is added. Future implementation replacement must
quiesce queued traffic, retire fenced authority and explicitly reconstruct a
validated versioned state schema. Native Rust layout is not a transfer format;
rollback cannot undo observed effects. Exact shared native vectors, independent
host construction, actual-method controls and full native/capture correspondence
are proportionate for this finite claim; no universal schedule theorem follows.
Root owns engineering decisions; the integration steward accepts independently.

Root is lane storage allocator and the steward owns aggregate campaign storage.
Source allocation is forecast at 40 MB, measured separately in the lane receipt,
with 60 GiB reserved independently on `/` and `/data`. No per-lane quota or
local target/runtime is introduced. Keep this exact source tree for composition,
review and rollback until that dependency ends or Root review on
2026-10-19T00:00:00Z, then apply scoped creator retirement checks.

## Independent peer and oracle

`scripts/native-echo-wire-matrix.py OUTPUT --elf OWNER_ELF --kernel-elf KERNEL_ELF`
constructs a fresh ISO and isolated Linux namespace inside the disposable VM.
It starts `native-echo-wire-peer.py` before QEMU and requires a complete atomic
readiness record for the exact namespace and process. The peer waits for each
complete native CASE row and its exact received FRAME before its next send.
It enables Linux Echo before the final selected frame; only Linux answers the
new positive request. No request is replayed and no matching positive reply
is constructed by the actor. Exact process groups and the namespace are closed
on success or failure; full output, PCAP and actor/cleanup receipts are sealed.

The additive oracle verifies every per-direction native frame against the
complete capture, all nine literal mutations, original local bounds, typed
no-observation results, retired authority, fresh positive correlation, NIC
counters, normal process outcome and full END/FNV. It imports only unchanged
helper functions from the existing positive/boundary runner; no existing proof
profile or acceptance rule is modified. The new runner takes no child ELF and
makes no child/pipe or object-census claim.

`scripts/native-echo-wire-tests.py` contains 27 artifact-control methods. Its
literal vectors in `fixtures/native-echo/wire-v1.json` derive from the retained
native request identified there. Semantic negative controls recompute the
terminal digest so they exercise their intended predicate. These source files
and counts are not runtime results; the execution receipt supplies the actual
commands, complete output and verdicts for the frozen revision.

The first occurrence at oracle `ef09e3e1` failed its full-capture comparison:
the actual successful Link TX ARP submission was 42 bytes, while the capture
contained those exact bytes followed by 18 zero padding bytes. That occurrence
remains FAIL. The prospective correction admits only this TX ARP relation
between exactly 42 and 60 bytes. RX, all selected 74-byte ICMP frames and other
lengths keep exact correspondence; nonzero padding is refused. Actual Link
length and captured length remain separate evidence, with no general suffix
normalization or inference of native submission length from a capture alone.
