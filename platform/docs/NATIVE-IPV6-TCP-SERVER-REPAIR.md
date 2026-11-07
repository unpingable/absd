# IPv6 TCP server close and refusal-interval repair

This is a source-only successor to product 739f361b / proof 62905a5e. Its new
host controls and native execution are UNRUN. The immutable ceb54c49 occurrence
remains FAIL (QEMU exit 7); it is not rescored by this change. The source archive
and actual evidence are separate identities supplied by the lane handoff.

## Observed failure and bounded counterexample

The sealed 31,233,714-byte archive has SHA-256
`72dd1fbbe9560f2a7278f08c46a22e781f728ed00182ce252de2b17efef98913`.
Linux received the exact 3072-byte echo and true EOF. The 40-frame capture
contains guest FIN at index 38 and Linux final ACK at index 39. The child exited
with status 1; the parent reported `consumer/EOF [1, 1, 0, 0]`. Its old error
branch discarded the captured child stderr before reporting the status, so the
exact failing child operation cannot be recovered from this evidence.

The actual source permits this alternate transition history: after peer EOF,
the child sends SHUTDOWN_WRITE, which calls the engine's close but leaves the
endpoint live. Owner polling can complete FIN/ACK before the following CLOSE
transaction. Server maintenance then records Closed and removes the live socket;
the next endpoint operation or still-pending framed reply fails. The previous
half-close host control did not force FIN completion before the close call.
This is a concrete source counterexample consistent with the capture, not a
claim that the missing child diagnostic was observed.

The echo consumer now makes one graceful CLOSE after peer EOF and all 3072
echoed bytes. CLOSE spends the application reference before FIN drain and
retains its bounded terminal acknowledgment. No server API, admission predicate,
shutdown-write behavior or library production code changes. A new actual
Client/transact/Channel/smoltcp-pair control forces socket removal before the
terminal reply, verifies the 3072-byte echo and peer EOF, and then consumes true
protocol EOF. A separate counterexample control retains the old redundant
shutdown/close sequence and checks its spent endpoint. These controls are
UNRUN until the offhost host harness executes them. The parent also exposes its
already-bounded child result as hex on failure, after result EOF and before the
unchanged failing status check. This diagnostic never substitutes for success.

## Wrong-source timing correction

The same capture has wrong-source SYNs at indices 6 and 7 and the authorized
SYN at index 8. The first-to-authorized interval is only 807,457 microseconds
(last-to-authorized 355,363). Cold neighbor discovery consumed part of the
1.25-second connect timeout. Socket-call elapsed time did not establish the
required wire interval. The prospective proof closes that socket and waits a
separate 1100 ms before authorized launch, recording monotone host observations.
The strict capture predicate remains greater than 1 second from the first
actual wrong SYN, with no wrong-tuple response or late wrong SYN. Actual ND,
full 3072-byte streams, FIN/ACK, EOF, resources, build and source predicates
remain mandatory. No host/guest clock comparison is introduced.

Original 5-second accept, 10-second owner and 8-second child bounds are retained;
the extra wait consumes those bounds rather than renewing them. A stalled or
late fixture fails. The separate boundary product e957e7e8 / proof c893cce4 is
immutable and must compose this repair into a distinct reviewed successor.

## Checks, evolution and disposition

The normal locked/offline net harness must execute both default and DHCPv4
variants, including the two new named tests in
`ipv6::stream::server::tests`, then rebuild both native bins and kernel2775 via
the pinned served wrapper. The proof successor separately pins the actual new
product commit/tree/canonical archive. No run result is inferred from source
inspection, Rust formatting or Python AST parsing.

Formalization consideration: the bounded proposition is that one terminal CLOSE
spends application authority before transport drain while preserving only its
original bounded acknowledgment; the fixture timing claim is independently
checked in the complete capture. Actual method/engine transition controls,
explicit counterexample and retained failure evidence are sufficient for this
small fixture repair. They do not prove every scheduler history, physical timing
or hardware fencing. Endpoint/implementation generations and authority rules are
unchanged; no replacement state, live rebind or post-effect rollback is added.
Root owns bounded source review, the integration steward owns acceptance.

The source author owns the new worktree and minimal receipts for review,
integration and rollback, until those dependencies end or custody review by
2026-10-18T23:59:59Z. Expected source allocation is at most 64 MiB, measured at
handoff; shared free reserve is 60 GiB independently on / and /data. No VM,
key, compiler target, generated transport or runtime allocation is created here.
