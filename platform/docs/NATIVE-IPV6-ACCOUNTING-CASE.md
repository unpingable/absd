# IPv6 peer refusal-accounting successor

`scripts/native-ipv6-matrix.py` remains the original strict zero-refusal case.
Its source, the frozen d6e2f50f input, and the b860a19b FAIL are unchanged.
`scripts/native-ipv6-accounting-matrix.py` is the separate successor case
`ipv6-post-ready-filter-accounting-v1`. It retains the original Linux peer,
normal MLDv2 traffic, native boundary markers, protocol checks, timeout and
capture bounds, exact ELF embedding check, and namespace/process cleanup.
There is no peer preconditioning, product filter or API change.

In the already admitted disposable Linux VM, using the exact existing kernel
and probe ELF inputs, the new command is:

```sh
python3 scripts/native-ipv6-accounting-matrix.py NEW_OUTPUT --kernel-elf KERNEL_ELF --elf PROBE_ELF
```

`--linux` runs only the unchanged independent Linux DNS fixture controls. It
does not exercise the guest, the readiness marker, or capture accounting.

The shared helper reads QEMU's append-only raw capture and serial files. On
the first observation of the complete `NETWORK LINK OK ...` line it records
the preceding ready-absent observation, capture prefixes before and after the
serial read, record index, byte offset, last PCAP timestamp, and host monotonic
and realtime observation bounds. After QEMU has ended it writes
`NIC-READY-CAPTURE.json`, bound to both exact raw-file SHA256 identities. The
marker is metadata immediately after the recorded complete capture record.
No wire packet is invented and QEMU's capture is never modified. Both raw files
are retained. The accounting result carries the sidecar hash.

The marker is an observed serial boundary. Device reception starts before the
kernel prints the line; serial polling and queued descriptors are not a
synchronized counter reset. PCAP and serial clocks are not converted or
assumed equal. An incoming MAC-filter-refused frame before the observed marker
can contribute to boot-cumulative counters, so it makes the result
inconclusive/FAIL. A partial PCAP record at the observation does too, even if
terminal counts happen to match. Incoming frames captured after the terminal
counter snapshot can also prevent exact equality. There is no tolerance,
counter adjustment, favorable boundary selection, or exception for setup
traffic. A mismatch stays FAIL. Separately reviewed kernel reason logs are
retained as supplementary observations and cannot excuse a mismatch.

The literal destination rule, unchanged from kernel 9b1f7b9d and recorded at
the reason-log successor ed6a15ea, accepts only the station MAC,
`ff:ff:ff:ff:ff:ff`, `33:33:00:00:00:01`, or `33:33:ff:*:*:*`.
The sidecar records its reference source/documentation hashes. The launch
records exact input ELF hashes; source-to-ELF custody remains the execution
owner's responsibility and is not inferred from captured traffic. Only incoming
post-marker frames outside that set contribute to `expected_refused`; for
example normal MLDv2 to `ff02::16` / `33:33:00:00:00:16`. The known isolated
TAP MACs establish incoming and outgoing direction. An unknown source MAC or
unrecognized protocol remains unexplained and fails. Every captured frame is
indexed, hashed and classified in `NIC-ACCOUNTING.json`; this includes every
post-marker frame in both directions.

The explicit `udp` profile recognizes only fd00:ab5d::15 port 7002 paired
with fd00:ab5d::2 port 42010. The `tcp` profile uses UDP 7202/42020 and TCP
7203/42020 at those same addresses. Transport lengths, checksums and Ethernet
destinations must match. ND must have the exact configured source, target,
destination and Ethernet LLA option, hop limit 255 and a valid checksum.
MLDv2 must have the Linux link-local or unspecified source, ff02::16
destination, hop limit 1, Router Alert, a bounded report envelope and a valid
checksum. Malformed or unrelated traffic remains unexplained and fails;
recognition here is a bounded capture profile, not general protocol conformance.

PASS requires exact `rx_refused == expected_refused`, no refused protocol-peer
ND/UDP/DNS frame (also TCP when this helper is reused there), zero `rx_missed`,
`tx_refused` and `tx_errors`, no unexplained post-marker frame, and no readiness
ambiguity. The original positive proof must pass too. Kernel device-descriptor
refusal logs are not MAC-filter evidence and fail this case. Filter reason logs
are recorded without assuming their bounded logging covers every refusal.
The reason-log successor emits `NIC RX FILTERED dst=…` in lowercase hex only
while the unchanged shared `rx_refused` counter is at most four. The counter
continues to increase for every refusal after that diagnostic budget ends.

The same `ReadyMarker` and `evaluate` helper are reusable by the separate TCP
successor: observe before launch and on each bounded loop iteration, observe
once more after QEMU ends, seal, then replace only its copied zero-refusal
predicate with `evaluate(..., profile="tcp")`. Keep every TCP SYN/TC-query-order, tuple,
MSS, checksum, A/AAAA fallback and FIN predicate intact. The frozen TCP source
is not changed by this commit; the integration owner applies the reviewed
helper there in a separate source identity.

`scripts/native-ipv6-accounting-test.py` contains thirteen pure artifact-fixture
tests, including eight tuple/address/checksum/transport substitution subcases,
for the literal rule, exact accounting and failed/ambiguous cases.
Run it in the isolated VM before the native successor. A fixture pass is not
native protocol evidence. Source syntax checks alone do not establish a pass.

The S2 decision owner considered the correspondence between a polled serial
observation, captured frames and boot-cumulative counters. Tests and explicit
refusal on uncertainty suffice for this bounded harness; no synchronized
cross-process ordering or hardware-delivery proof is claimed. The exact source
and executed result identities belong in the lane handoff. If exact accounting
is indeterminate, the steward decides the next minimal kernel observation
change; this case does not turn indeterminacy into acceptance.
