# Two distinct refused TCP connection attempts

This source-only follow-up belongs to existing
#29. It implements the
future-fixture request in steward acceptance note
`20261018T064757Z-steward-29-telemetry-accepted.md`: make the first and last
refused sequence numbers observably different. Historical refusal, telemetry
and native-boundary runs retain their exact sources and verdicts. All new
controls, builds and native execution are UNRUN at this handoff.

## Selected profile and finite timing

The new explicit selector is `--profile tcp-server-last-refusal-v1` on
`scripts/native-tcp-server-matrix.py`. The existing default
`tcp-server-native-boundary-v1` still selects one wrong connect, its old
product binding and original controls. Neither profile changes the native
parent, child, core, runtime, telemetry semantics, kernel or dependencies.

The fixture retains trusted LISTEN observation, the actual raw ARP request
and guest reply, and the exact permanent Linux neighbor pin/readback. It then
creates two separate genuine Linux TCP sockets serially. Each binds the same
`192.0.2.1:42031` source and makes exactly one connect call to
`192.0.2.100:7005`, with the existing 1.25-second timeout. Each socket closes
before the next connect. Each observed host duration must exceed one second;
connection success, an immediate refusal, a short timeout or a bind failure
cannot pass. No retry is used to obtain a preferred sequence number.

The nominal wrong-connect interval is now 2.5 seconds. The native accept,
grant, child and whole bounds remain 5000, 10000, 8000 and 20000 ms. Setup,
VM scheduling and socket completion consume those original budgets. No host
clock is subtracted from a guest clock to claim remaining authority, and no
deadline is widened if the original bounds cannot accommodate the fixture.

The complete guest-facing capture must contain exactly two distinct observed
wrong-tuple ISNs before the genuine authorized connection. Retransmissions
within either attempt are allowed and all are counted. An earlier sequence
that reappears after the second starts, a third sequence, an unchanged ISN,
missing input, any guest response to the wrong tuple or wrong input after the
authorized SYN refuses this finite profile. These are observed history
conditions, not a guarantee about every Linux scheduling or queue history.

Only after both wrong sockets finish does the unchanged real Linux client
connect from the granted `192.0.2.1:42030` tuple. The existing full 3072-byte
exchange, checksums, sequence reassembly, both FIN acknowledgements, half-close,
actual Linux EOF, NIC/source/embedding checks and exact cleanup all remain.
The captured first-wrong-to-authorized interval must still exceed one second.

## Last-observation correspondence

The guest interface is unchanged: one zero baseline and one final saturating
Stack-local count/last-header observation. The final count must equal every
captured wrong SYN, including retransmissions. The final tuple, flags,
sequence and frame length must match the last actual wrong SYN, which belongs
to the second distinct sequence group. Substituting the first group's header
while retaining correct counts and all other fields must fail.

The aggregate `wrong-port.json` uses schema
`absd-native-tcp-last-refusal-client/1`, with exactly two ordered original-shaped
attempt receipts. Each is also retained as `wrong-port-attempt-1.json` or
`wrong-port-attempt-2.json` immediately after that socket closes, so a second
failure does not erase the first completed observation. Both intervals follow
neighbor readback, do not overlap, and end before the authorized client starts.
Host monotonic receipt clocks and capture timestamps remain separate domains.
The source-bound sole fixture and complete tuple/sequence census relate the
attempts; timeout text or timestamps alone are not refusal evidence.

## Exact future build and execution inputs

The new profile binds product
`5775b70f6167e407bcc6253ef4de9d56b9cdb7cc`, tree
`c1d860be75d7db32c0835c1d07107b8376bffb62`, canonical prefix-free tar
27,392,000 bytes, SHA256
`fc55e9b71f2c77d6c6a46d30d6d7d1e3570148aa4689256ffb51fa1412c8cd1f`.
The oracle checkout has its own exact revision and archive. Product native
source, feature/bin entries, builder and all library source remain unchanged
by this follow-up. Combined-source runtime remains unrun; earlier component
acceptance does not become a result for this new source/profile.

Use the existing `native-tcp-server-probe` feature and
`scripts/build-native-tcp-server.sh`, Rust 1.95 and the canonical c354 staged
standard library. The two target bins are `tcp_server_echo` and
`tcp_server_service_probe`; retain the actual stripped `tcp-server-echo.elf`
and `tcp-server-service-probe.elf`, with exact child bytes embedded in parent.
Relocate completed outputs into occurrence evidence before source-after checks.
Bind actual Cargo metadata, selected source, target/features and staged std;
no compiler or metadata query runs on build_host during this source task.

Kernel remains `2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b`, with actual
`scripts/served_kernel.py` invocation, pinned wrapper
`e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2`
and `frame-admission-v0`. Build receipt remains
`absd-native-tcp-server-build/4`, with the selected new profile and exact product
binding. Proof schema remains `absd-native-tcp-server-proof/4`, distinguished
by its explicit profile; every original build/ELF/kernel/ISO predicate remains.

On a separately prepared finite disposable runtime, run all existing server
matrix controls and cleanup controls, plus the new last-refusal controls:

```sh
python3 -I -B scripts/native-tcp-server-matrix-test.py -v
python3 -I -B scripts/native-tcp-server-cleanup-test.py -v
python3 -I -B scripts/native-tcp-last-refusal-test.py -v
python3 -I -B scripts/native-tcp-server-matrix.py "$EVIDENCE/native" \
  --profile tcp-server-last-refusal-v1 \
  --child-elf "$BUILT/tcp-server-echo.elf" \
  --elf "$BUILT/tcp-server-service-probe.elf" \
  --kernel-elf "$BUILT/absd-kernel" --build-receipt "$EVIDENCE/build.json" \
  --timeout 120
```

Root separately selects any full host-suite/source correspondence requirement
and exact receiving/executor recipe before runtime. No source-only forecast is
a passed count. The producer/collector must retain both per-attempt receipts,
aggregate receipt, peer result, full capture/serial, build/source before/after,
executed inputs, cleanup and original execution identities, including on failure.

## Formalization and retirement

The bounded proposition is that two source-confined socket attempts produce
two distinct captured wrong-tuple sequences, and the guest's final header
matches the second actual sequence rather than the first. Practical finite
capture/report substitutions, source review and future independent raw native
readback suffice; no new model or telemetry framework is introduced. Twelve
new authored methods exercise the actual checker/helper with synthetic bytes
or mocked socket boundaries. They are artifact controls, not native results.

The count and last record remain inert Stack history across close/rebind/fence,
not per-grant stable identity, authenticated provenance, replacement state,
continuous polling, physical-time accuracy, DMA or full-memory restoration.
Fresh grants do not revive fenced authority. No state-export schema, kernel
generation replacement, authority reconstruction or post-effect rollback is
introduced. Existing L3/L4 and integration holds remain unchanged.

Creator `quic_next_tranche` owns the isolated source worktree and small receipts
in `native-tcp-last-refusal-s2-20261018/c2f738a6-e775-4f7c-acfe-ffb60e451bc2`.
Root owns aggregate allocation, review and sequencing; steward acceptance is
separate. Retire this exact worktree when review/integration/rollback custody
ends, or review at 2026-10-19T04:00:00Z. No compiler target, VM, key, source
transport or runtime holder is created by source preparation.


## Observed runtime result, 2026-10-19

The UNRUN statements above describe source handoff `c2f738a6`. A later,
separate execution `ea301a95-32e7-4e40-9439-51971f447e8a` reported PASS for all
six fresh phases: the 39 existing matrix controls, 2 cleanup controls, 12 new
last-refusal controls, child/parent build, kernel build and native proof. No
prior control or native result was carried into that PASS. The original
`eef88487-9f07-47dc-9964-425b4b801c8c` remains a whole FAIL: its disposable
entry pathname failed before any authored method, build or native execution.

The executed sources were product
`5775b70f6167e407bcc6253ef4de9d56b9cdb7cc`, oracle
`b02d8100eaa3fd6ba455c14ed9a80d9e3651dd3b` and kernel
`2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b`. The oracle came from
`lane/native-tcp-last-refusal-codex-20261018`; this appended documentation is a
successor record, not the oracle executed by that occurrence. The fresh child
was embedded once in the parent, parent once in kernel, and kernel once in ISO.
QEMU exited 3, with parent and positive child reporting exit 0.

The complete 33-frame capture contained two ordered wrong-SYN groups: ISN
2327588625 at zero-based indices 2 and 3, followed by ISN 2347231225 at indices
4 and 5. The guest reported count 4 and last sequence 2347231225, frame length
74. Both genuine Linux connect calls timed out after more than one second;
the first wrong SYN preceded the authorized SYN by 2,709,398 microseconds.
The separate authorized flow exchanged all 3072 bytes each way, with both FIN
acknowledgements and actual Linux EOF. Host receipt clocks, capture timestamps
and guest boot clocks remain separate domains.

Reconstructed guest stdout was 3029 bytes in 35 chunks, FNV32 `29385895`.
Terminal NIC observations were 20 RX and 13 TX frames, with `rx_refused`,
`rx_missed`, `tx_refused` and `tx_errors` all zero. Process, handle, pipe and
cell counts restored; allocator frames changed from 198 to 201. This is an
observed frame delta, not full-memory restoration.

Exact custody is collector `3735718d-960b-4737-be2f-f9cc07a394b5`,
`exact-tcp-evidence.tar.gz`, 34,067,190 bytes, SHA256
`bc7c3b0cd9b83cb342e247b9c53a98541e7d6ecbda8069d53a18a6d6143ada3d`,
under `archived-occurrence` (96 members).
Root's `11ed32ab-8a33-41f0-b938-80517a0d66fa/RAW-READBACK.json` has SHA256
`087f78cee2bbfb4f30168519d66718dc8e821cb392aee0b365f6e663e8648c55`.
At this documentation update, independent raw review, steward acceptance and
VM/key closeout are pending; neither acceptance nor provider closure is claimed.

The result is one finite exact-peer TCG occurrence. It does not establish
full TCP conformance, live TCP/SSH coexistence, a complete composed candidate
gate, full-memory restoration or live kernel replacement. No fresh net, SSH
or TLS host-suite result is claimed. The Stack-local observation remains
bounded inert history, not authenticated identity or exported replacement state.
