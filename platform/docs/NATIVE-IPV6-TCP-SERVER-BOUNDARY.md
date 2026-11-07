# Native IPv6 server boundary successor

This fixture-only successor starts from frozen proof62905a5e/product739f361b.
It changes no net, runtime, broker, kernel, dependency, framing or admission
semantics. The earlier positive source/results remain distinct. All execution
of this successor is UNRUN at source freeze.

Before a fresh positive grant, one no-Interface-poll prelude checks twelve
constructor refusals: nonprivileged-port boundary, zero peer port, off-link,
self, unspecified, multicast and zero/other scope return Denied=2; invalid
accept/lifetime bounds return Invalid=1. Eight endpoint reservations create
no sockets. Duplicate local port returns InUse=3; a distinct ninth unused port
returns Exhausted=4. Abort all, construct eight fresh epochs, refuse all old
references with Stale=8, then abort the fresh reservations. This is finite
constructor reservation exhaustion, not active socket/buffer exhaustion.

A real pipe-only child sends nine literal 28-byte v3/family-6 requests through
existing transact. Wrong version/family, reserved=127, nonzero LISTEN length,
CONNECT and WRITE declared1025-without-body return Invalid=1. Wrong peer port,
scope and IP return Denied=2. The reserved byte deliberately differs from the
error code, so a reply echo cannot pass. The missing WRITE body does not isolate
the 1025-byte API limit with a complete valid outer frame. Exact literals live
in `fixtures/native-ipv6-tcp-server/boundary-v3.txt`; the native parent retains
and prints actual kernel pipe bytes, never substitutes those expected bytes.

After all nine replies, the child consumes the complete successful LISTEN
reply, prints its bounded result record, writes one zero prefix byte and waits
under its original 8-second deadline. The owner observes that actual byte before
using its exact process handle to kill and reap kind3. The true protocol EOF,
Channel false and sockets0 must follow reap and occur strictly before both the
conservative pre-poll+250ms frame bound and original 10-second negative grant.
No explicit revoke/fence occurs first or receives credit. None and timeout are
not EOF. Failure never becomes success by fallback or a new grant.

The bounded pre-I/O ledger records 270 request/reply bytes for the nine refusals,
then 30 request/31 reply bytes for LISTEN, then one actual prefix byte: 301 bytes
each direction. The 23-byte peer bootstrap is outside that ledger; its completed write count
and exact written bytes have a separate BOOTSTRAP record. Exact actual
prefix hex/count, ledger totals, process handle, kill result, wait outcome,
pre/post observations and retirement timestamps are printed. Child result EOF
and the two owned protocol handles plus one result reader are explicitly closed.
Existing syscall 41 process/handle/pipe/cell counts must equal their prelude
baseline; frames are observed only. No Rust allocator/full-memory restoration
is inferred. No Interface poll occurs in the prelude, so its zero observed TX
is phase-local; ordinary configured-address NS maintenance remains allowed
when the subsequent positive network phase polls.

The whole fixture has a 20-second outer native bound. After negative retirement,
a new positive owner grant gets its original 5-second accept/10-second lifetime
and the original child gets 8 seconds. The new grant must fit entirely inside
the whole bound. Distinct `IPV6 TCP SERVER NEG` records cannot satisfy Linux's
unchanged exact positive LISTEN readiness marker. The original Linux wrong-port
separation, full 3072-byte streams, checksums, tuple/MSS1440, FIN/ACK, true EOF,
normal reap, resource and source/build predicates remain in force.

Formalization consideration: a finite literal/phase contract plus actual
syscall/pipe/clock/census observations and deterministic substitutions establish
only this one owner/generation fixture. No physical wire epoch, hardware fence,
post-effect rollback, state transfer or downgrade is introduced. Existing
logical service identity, implementation instance and checked endpoint epoch
remain distinct. Root owns fixture scope; the steward owns independent oracle
and integration acceptance. Connected-data/pending-output interruption,
malformed outer prefix, complete oversized body, clock/link faults, wire
malformations, routing, 1280-MTU server and live SSH remain unqualified natively.
