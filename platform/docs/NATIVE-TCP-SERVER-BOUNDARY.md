# Native TCP server boundary fixture

This fixture for existing coordination issue 29 exercises selected native
grant/API/interruption boundaries before the existing Linux echo proof.
All actions were UNRUN at product/oracle source freeze. Fresh occurrence
`9cde345e-c72a-425d-a7c8-8b82f9878b2c` subsequently passed all six phases
at product `137f6ac6` / oracle `f2d79c4b`, with unchanged kernel `2775bbaf`.
Exact execution, custody and limits are recorded in
[NATIVE-TCP-SERVER-PROOF.md](NATIVE-TCP-SERVER-PROOF.md). The earlier `1476`
telemetry result stays at `90ab` / `8b7d`; it is not relabeled here.

Only the private `tcp_server_service_probe`, its pipe-only
`tcp_server_echo` child and the parent-local `tcp_server_boundary` module
change. Net transport, framing, filtering, grants, kernel ABI, dependencies,
locks, build script and all published protocol constants are unchanged.
The child uses an existing startup argument to select its negative mode;
the ordinary echo child still gets no argument. Both use the existing five
explicit startup/pipe/result/console copies and SPAWN_NO_SPAWN, with no NIC.

## Single dedicated boot

The parent sets one whole-fixture 20-second boot-clock bound. It performs
the prelude before constructing the positive grant, and refuses if fewer
than the original ten seconds remain for that grant. No endpoint or frame
deadline is renewed. The negative grant retains the same five-second
LISTEN/accept and ten-second lifetime; its owner records a conservative
ten-second bound sampled immediately before construction. The positive
grant retains five/ten seconds and the echo child's eight-second bound.
Guest timestamps never claim physical time or compare to the Linux clock.

1. Using the actual native `stream_server_grant`, nine single-field invalid
   grants require `Invalid(1)`: privileged local port 1023, peer port zero,
   off-link peer, self peer, subnet broadcast, accept timeout 99 or 10001,
   lifetime below the accept timeout, and lifetime 60001. No LISTEN or
   Interface poll occurs. Exactly eight distinct local ports then reserve
   slots; the duplicate port requires `InUse(3)` and the distinct ninth
   port requires `Exhausted(4)`. Abort all eight, reconstruct eight fresh
   grants, require all old endpoints `Stale(8)` and abort the fresh grants.
   Sockets and Stack TX remain zero throughout. This is slot-constructor
   exhaustion, not TCP queue, memory or device exhaustion.
2. One real child sends seven complete 12-byte bodies through the actual
   length-prefixed kernel pipe. Wrong version, family, reserved request
   status, nonzero LISTEN length, CONNECT on a server session, and WRITE
   declaring 1025 bytes with no body require exact canonical
   `Invalid(1)` replies. The last case is **declared length/missing body**;
   it does not isolate a complete 1025-byte-body limit. Wrong peer requires
   `Denied(2)`. The parent delegates all reads/writes to `KernelPipe`,
   retains at most 512 actual bytes per direction and checks zero sockets
   and TX after each complete refusal reply. The native/oracle records
   bind literal framed requests and replies, rather than trusting a count.
3. The same child consumes the full successful LISTEN reply, with connected
   false and one socket, then writes exactly one raw `00` prefix byte and
   parks under its original deadline. After the parent's real pipe read
   consumes that byte, it kills that exact spawn-returned process handle
   and waits for the actual killed outcome, kind 3. The handle is not
   called a PID. A subsequent delegated read must return `Some(0)`, not
   None or timeout. Channel false and sockets zero must be observed before
   any explicit revoke/fence. Kill, reap, true EOF and retirement must all
   precede both the original negative owner bound and the first partial
   read's **pre-poll tick + 250 ms**. The conservative pre-poll timestamp
   precedes the channel's internal first-byte deadline; the check excludes
   frame expiry as a substitute for EOF-triggered retirement. No network
   Interface poll occurs during this prelude.
4. After true result-pipe EOF and successful reap, close the two exact
   parent protocol handles and the result reader, then read the existing
   syscall 41 census again. Occupied processes, live handle entries, pipe
   objects and cell objects must equal the concrete before-child snapshot
   in this dedicated otherwise quiescent boot. Both frame counts are
   reported without an equality requirement: parent allocator/Vec capacity
   growth may remain. Explicit closures, killed outcome, real EOF and zero
   sockets are separate assertions; global terminal accounting is not a
   per-phase restoration substitute.
5. Only after negative completion does the parent issue a fresh positive
   grant and start the original echo mode. Negative markers have a distinct
   `TCP SERVER NEG` prefix; the Linux fixture still waits for only
   `TCP SERVER LISTEN READY sockets=1`. Retain actual neighbor readiness,
   separated wrong-source interval, guest refusal count/last header, exact
   3072 bytes each way, FIN/ACK, true EOF, clean source/build/ELF/ISO binding
   and original end-of-workload/resource checks.

The bounded actual input ledger is 113 bytes: seven 14-byte malformed/wrong
peer frames, one 14-byte LISTEN frame and one incomplete byte. Actual output
is 113 bytes: seven 14-byte refusal replies and one 15-byte LISTEN reply.
The child result is separate from those protocol bytes. These are fixture
observations; there is no new client operation, production counter, reset
mechanism or generic telemetry framework. Any unexpected reply, byte,
deadline crossing, normal early child exit, missing EOF, residual socket,
object discrepancy or unknown result fails this occurrence.

## Proof and remaining limits

The oracle pins product `137f6ac6b55fe92cee94816ce609658e96d1ec05`, tree
`18aa6d16d7d8293f360cd67ab5b5a2607bd6358d`, canonical prefix-free Git tar
26,388,480 bytes / SHA-256
`b4ab4a3ee760ee98411c034bb5f6fa06ed13692382228123b389e75268a0ab68`.
Kernel stays `2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b`, tree
`8763f164ddfed11aa2f55626bd8e85123c595a08`, canonical tar 12,574,720 bytes /
SHA-256 `fbfff7902d7bf6334b0c2d141558ef8cbdb23d56ce3db0c81dd32ebfb81be224`.
Profile is `tcp-server-native-boundary-v1`; both build and terminal schemas
advance to version 4, retaining all previous fields and exact source/build
guards. New boundary records have explicit version 1 text and terminal
`absd-native-tcp-server-boundary/1`. The telemetry record remains version 1.

The offhost operator runs all **39 artifact methods** (the previous 30 names
plus nine new native-record controls) and two unchanged cleanup methods. No
control or compiler executes on build_host. With exact authenticated offline
toolchains/std/cache, build the unchanged native build script in a clean
product checkout, move only its completed child/parent ELFs into evidence,
then build kernel 2775 through the existing `served_kernel.py`, SHA-256
`e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2`
and `frame-admission-v0`. Retain actual commands/logs, clean source before
and after, compiler/toolchain provenance and exact ELF/ISO containment.
The existing net/SSH source and host methods are byte-identical to the
`1476` source; that correspondence is not a new host execution claim.

```sh
# Replay recipe using the exact separate oracle and product checkouts.
python3 -B scripts/native-tcp-server-matrix-test.py -v
python3 -B scripts/native-tcp-server-cleanup-test.py -v
env -C "$PRODUCT137" sh scripts/build-native-tcp-server.sh
mv "$PRODUCT137/tcp-server-echo.elf" "$CASE_ROOT/tcp-server-echo.elf"
mv "$PRODUCT137/tcp-server-service-probe.elf" "$CASE_ROOT/tcp-server-service-probe.elf"
: > "$CASE_ROOT/empty"
python3 "$PRODUCT137/scripts/served_kernel.py" -C "$KERNEL2775" \
  EXTERNAL_USER_ELF="$CASE_ROOT/tcp-server-service-probe.elf" \
  EXTERNAL_INPUT="$CASE_ROOT/empty" EXTERNAL_EXPECTED="$CASE_ROOT/empty" external-build
# Bind the actual schema4/profile/source/build receipt before this call.
sudo python3 -B scripts/native-tcp-server-matrix.py "$CASE_ROOT/native" \
  --child-elf "$CASE_ROOT/tcp-server-echo.elf" \
  --elf "$CASE_ROOT/tcp-server-service-probe.elf" \
  --kernel-elf "$KERNEL2775/build/external/target/debug/absd-kernel" \
  --build-receipt "$CASE_ROOT/build-receipt.json" --timeout 120
```

The separately committed oracle pins this exact product Git archive and
kernel 2775, uses a new explicit profile/schema, and adds finite literal,
status, byte-count, ordering, timestamp, EOF, census and positive-sequence
controls while retaining every existing positive proof predicate. The
existing offline native build/served-wrapper recipe remains applicable;
all exact source/helper/command/ELF/ISO and raw output identities must be
retained by the future offhost operator. The source handoff gives the final
product and oracle revisions without circular self-reference.

This tests one partial-prefix interruption while LISTEN is present, not a
connected-data or pending-reply interruption. Malformed outer lengths,
native clock/link failures, queue/ring/load exhaustion, deliberate loss,
routed behavior and live SSH coexistence remain UNRUN. There is no full
memory restoration, hardware, general TCP conformance or universal timing
claim. Literal byte checks and the finite observed native state transitions
are proportionate formalization for this bounded fixture; they depend on
faithful capture, exact builds and the single-owner/quiescent census scope.

Logical service identity remains distinct from implementation instance and
endpoint epoch. Old endpoints and killed consumers never revive. The
positive phase constructs fresh authority; it transfers no live state,
native Rust layout, queues or grants. Future generation replacement still
requires quiescence, fencing, explicit versioned reconstruction, external
successor validation and retirement. Rollback cannot undo emitted effects.
Root owns this engineering/readback scope; the independent steward decides
acceptance. Source/rollback and minimal receipts remain with Root until
that dependency ends or review at 2026-10-18T23:59:59Z. No VM, key, compiler
target or large artifact is created by this source task.
