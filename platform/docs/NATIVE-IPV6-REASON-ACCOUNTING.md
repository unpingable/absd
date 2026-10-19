# Bounded IPv6 driver-reason correspondence successor

The steward decision `20261016T183242Z-steward-s2-accounting-profile-and-sntp.md`
admits this distinct measurement profile. Original b860a19b remains FAIL and
4428223d remains FAIL/inconclusive. Their runners, helper, artifact controls,
raw files and verdicts are unchanged. No past run is evaluated into PASS.

For UDP run `scripts/native-ipv6-reason-matrix.py`; for TCP run
`scripts/native-ipv6-tcp-reason-matrix.py`, in the owned disposable Linux VM with exact
prebuilt parent/kernel ELFs. This source adds no runtime, dependency, device
configuration, NIC ABI, counter or peer preconditioning. All previous boot,
protocol, consumer and packet checks are retained. Normal Linux MLD remains.

The new helper requires terminal rx_refused <= 4. More is INCONCLUSIVE/FAIL
because only the existing first-four driver diagnostic budget is exhaustive.
Every counted refusal must have exactly one complete literal lowercase
`NIC RX FILTERED dst=...` line; descriptor-error or malformed reasons fail.
Every logged destination must be refused by the fixed kernel MAC rule and
have a corresponding incoming frame in the full sealed capture. Distinct
reasons need sufficient distinct compatible frame records, without claiming
which repeated record reached the device. Peer refusals, unexplained frames
anywhere in the capture, rx_missed, tx_refused and tx_errors must all be zero.
The old pure classifier still validates exact configured IP/port profiles,
ND/MLD envelopes and checksums. Separate artifact fixtures include positive
prefix uncertainty, cardinality, budget, unknown frame, wrong profile,
substitution, raw mutation and protocol-peer negative controls.

Capture-prefix uncertainty is an explicit result. The observed NIC-ready
sidecar binds exact raw files and observed prefixes; it is not a reset or
synchronization point. No comparison equates boot-cumulative refusals with
post-marker packet counts. Capture starts before reception, so excluded
prefix frames can be recorded without reaching the device. Destination
correspondence does not establish exact frame delivery, physical timing,
DMA exclusion or post-effect rollback. This is the reviewed narrower claim.

Run identity `ad50dc4b-c0b0-4968-a2cc-cc43030574fd` records exact source/result
identities in the shared lane registry. Source checks alone do not execute
these fixtures or the native peer. Root queues one new native run per runner;
no unchanged repeat. Independent review/acceptance is separate from notice.

Formalization consideration: under the declared fixed filter, correct driver
counters and complete first-four logs, bounded reason cardinality and captured
destination compatibility can be exhaustively tested. The model excludes
capture/device scheduling, physical time and hardware transfer. Practical
negative fixtures and explicit prose suffice for this measurement tranche;
root and steward own that decision. Stable service/endpoint generations and
fenced handles remain governed by the unchanged runtime. This runner exports
no service state or authority and implements no live replacement mechanism.

Root owns existing S2 storage allocation. Retain exact commits and minimal
receipts; retire reproducible runner substrate after review/replay consumers
end. Next review 2026-10-17. Release, main, supported ABI and U1 holds remain.

Independent source preflight found that the serialized sidecar digest could
name content different from the in-memory evaluated annotation. Before any
execution, the new helper was corrected to read one bounded sidecar buffer,
require JSON equality with the evaluated annotation and hash that same buffer.
A sidecar-mutation refusal fixture covers the gap. Earlier source notices are
immutable and unexecuted; this correction changes no original runner/verdict.
