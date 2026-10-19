# Separate IPv6 TCP peer-accounting case

The original `scripts/native-ipv6-tcp-matrix.py` remains byte-identical to
9eb8b5c5, including its strict zero-refusal predicate. The new
`scripts/native-ipv6-tcp-accounting-matrix.py` is a separate additive case.
It uses the exact shared accounting helper and thirteen artifact-fixture tests
from reviewed source 6b9dbb16, with the explicit `tcp` profile. Product source,
native binaries, dependency manifests and locks are unchanged.

The original proof still requires Linux interface MTU 1500, smoltcp MSS 1440,
exact scoped UDP/TCP tuples, checksums, both directions of ND, a matching UDP
TC answer before the first native SYN, exact original query bytes/ID/QTYPE on
TCP fallback, A and AAAA answers, one reused connection, both FIN directions,
Linux EOF, native close/local retirement, absolute bounds and exact cleanup.
The peer is unchanged and normal Linux MLD stays enabled. No unexecuted API,
pipe or malformed-wire controls are reported as passed.

The helper records the first observed complete guest NIC-ready serial line
with before/after capture prefixes, record index/offset/timestamp and host
clock observation bounds. After QEMU ends, a sidecar binds that observation
to exact raw capture and serial hashes. It never changes either raw file or
adds a synthetic wire frame. All captured frames receive indexed, hashed
classifications. The exact profile uses fd00:ab5d::15 and fd00:ab5d::2, UDP
7202/42020 and TCP 7203/42020. Unknown addresses/tuples, truncated transport or
malformed ND/MLDv2 envelopes/checksums stay unexplained and fail.

Only post-marker incoming frames outside the recorded literal kernel MAC
rule enter expected_refused. PASS requires exact equality to rx_refused,
zero refused peer protocol frames, zero rx_missed/tx_refused/tx_errors, no
unexplained post-marker frame and no readiness ambiguity, in addition to all
original positive predicates. The kernel's bounded reason logs supplement
the raw evidence and cannot excuse a mismatch.

The ready line is polled and counters accumulate from boot. Device enable,
capture writes, serial observations, queued descriptors and terminal counter
sampling are not synchronized. Any incoming refusal before the marker or
partial capture record at it makes the result inconclusive/FAIL even when
counts match. There is no clock conversion, boundary adjustment, tolerance or
MLD suppression. Preserve an inconclusive run; a narrower observation profile
belongs to a separate steward decision.

In the already admitted isolated VM, after source/build correspondence and
independent review, execute these foreground commands serially:

```sh
python3 scripts/native-ipv6-accounting-test.py
python3 scripts/native-ipv6-tcp-accounting-matrix.py NEW_OUTPUT --kernel-elf EXACT_KERNEL_ELF --elf EXACT_TCP_PROBE_ELF
```

`--linux` exercises only the original independent Linux fixture controls; it
does not exercise the guest or accounting. Source syntax/provenance checks
and authored artifact fixtures are not native evidence. Preserve the raw
PCAP/serial, launch/result/cleanup records, readiness sidecar and accounting
census under the actual execution identity, including FAIL/inconclusive.

The S2 decision owner considered the bounded correspondence claim between a
polled ready observation, exact profile classification and boot counters.
Explicit failure on uncertainty plus practical artifact substitutions suffice
for this small harness. No synchronized ordering, hardware delivery, general
protocol conformance or live replacement property is established. Independent
acceptance and source/executable custody remain outside this runner.
