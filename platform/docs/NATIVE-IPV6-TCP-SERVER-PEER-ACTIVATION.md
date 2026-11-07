# Observe the NIC before activating the Linux peer

The exact product remains `f84086e138170344c4c06e8f2eb92dc2b595b66f`
and kernel remains `2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b`.
This is a prospective Linux fixture correction on oracle `877a122e`.
No product, kernel, builder, authority, deadline or packet verdict changes.

Execution `343b80c7-e78e-41c4-bc39-a2a8e184ec02` remains FAIL. Its complete
archive is 46,048,557 bytes, SHA256
`2fa7806124a1c037e4f61b51ecc265a878d64331dc8062d39f90caa02113d61d`.
All 22 artifact controls, two cleanup controls and full 363/376 host suites
passed. Each host suite included all 30 IPv6 server methods. Product and
kernel builds completed. The native consumer exited normally with 3,072
echoed bytes, both EOFs, a complete 654-byte output/FNV record and restored
owned process/handle/pipe/cell counts. Frames remain observed only. Actual
first wrong SYN to authorized SYN was 1,968,573 microseconds.

The unchanged counter predicate correctly refused the whole native proof:
three complete incoming Linux MLDv2 frames preceded the observed NIC-ready
boundary, and one followed it. The raw refusal count was two. The retained
sidecar cannot establish exactly which pre-observation packets contributed
to the boot-cumulative counter. Normal consumer completion does not resolve
that ambiguity, and this correction does not change the old verdict.

The fresh TAP is now created without an IPv6 address. Linux
`default.addr_gen_mode=1` suppresses automatic link-local generation; the
actual per-interface value and empty IPv6 address list are checked. After
QEMU starts, the actual running `NETWORK LINK OK` observation must be recorded
before the runner adds the exact `fd00:ab5d::2/64` peer address. It then checks
that this is the sole address and records the actual before/after lists and
NIC observation in `PEER-ACTIVATION.json`. The existing LISTEN observation,
wrong-source attempt, closed-socket wait and authorized Linux client follow.
The Linux setting is documented in
[IP Sysctl](https://docs.kernel.org/networking/ip-sysctl.html).

The complete QEMU capture still begins at launch. No counter is reset, no
frame is discarded, no timestamp is mapped between host and guest clocks,
and no guest authority deadline is renewed. Every existing capture,
counter, source/build, EOF and cleanup predicate remains unchanged. This
controlled peer configuration is not a claim about general Linux multicast
startup or ABSD MLD support. If any early traffic still makes accounting
ambiguous, the fresh run must fail under the same predicate.

Proof schema 3 adds the peer-activation receipt. The native product profile
`ipv6-tcp-server-onlink-close-v2` and build schema 1 stay unchanged. A fresh
oracle-only occurrence can therefore reuse the exact immutable build receipt
and executable bytes from 343b, with that attribution explicit. It must run
all 25 artifact controls, two separate cleanup controls and a fresh native
proof; the existing 363/376 results are carried, not rerun or reattributed.
The three added controls exercise the actual setup/activation/readiness helpers and
refuse automatic addresses, missing/nonrunning/wrong readiness and altered
address transitions. NIC readiness uses the actual raw-serial ReadyMarker
observation; LISTEN continues to use reconstructed worker output. Independent
source review found that oracle `00a7c3f3` incorrectly searched worker output
for the kernel NIC line. That source and its local-only frozen contract remain
UNRUN and are superseded, not silently changed. The third control distinguishes
the two channels. All new execution is UNRUN until recorded separately.

Formalization consideration: under the isolated Linux namespace and exact
observed interface configuration, explicit address activation occurs after
the recorded running NIC-ready event. Direct helper controls plus fresh
complete capture/counter correspondence are proportionate for this input
ordering. This is not an all-schedules or physical-time proof. Stable
capability identities, spent generations and replacement state are unchanged;
no live replacement, authority reconstruction or post-effect rollback is
implemented. Root owns this source decision; the steward independently
accepts integration. Source and minimal failed-run/replay inputs remain in
Root custody through integration/rollback review, next review at dependency
end or 2026-10-18T23:59:59Z; disposable VM/targets retire under their existing
resource occurrence and absolute teardown deadline.
