# SSH session heap regression

The successor `absd-20261003.1` attempt failed its mandatory 300-session
capacity gate: guest frames **753 → 770**, sshd mapped heap **314 → 331**.
That receipt remains a counterexample, not an accepted release. The sealed
`absd-20261002.3` pair is unchanged. Downstream update, rollback, backup and
reconstruction gates remain paused until the whole platform gate passes.

## Attribution

Two unmodified successor replays reproduced the 17-page increase, at
different session counts. A replay of the actual sealed `.3` services on
a newly prepared disk also grew, by 34 pages. This does not rewrite the
historical sealed qualification.
Runtime allocator and service sources were unchanged between those platform
revisions; this is not established as successor-only initialization.

Passive checkpoints cover 1, 2, 5, 10, 25, 50, 100 and 300 sessions.
Existing allocation-growth diagnostics, extended only in diagnostic copies
to count live/free regions, identified a 65,544-byte FSD reply clone
(normalized 65,552 bytes). The pool had 79,504 free bytes but its largest
region was 65,424 bytes, so this allocation mapped another 17 pages.
Settled live allocation bytes/count remained 940,368/45; all 69,632 added
bytes were free. This is **fragmentation followed by retained pooled
capacity**, not evidence of an unfreed live allocation.

Additional copies identified the TCP transmit buffer and Sunset's
35,000-byte buffers as other sources of transient growth. Removing one
copy or changing first-fit to best-fit did not restore the production
oracle reliably. Those failed candidates remain evidence; none is included
in this repair. A later flat campaign does not erase earlier growth.

## Repair and regression

The runtime gives normalized page-sized allocations fitting one map call
(at most 64 pages, alignment at most one page) exclusive mappings, then
returns those mappings on deallocation. Classification occurs before pool
lookup so the original Layout determines ownership unambiguously. Small
and highly aligned allocations retain the original coalescing first-fit
pool. The mapped-page counter decreases only after successful kernel
unmap; a refused unmap takes the existing allocation-free exit path.

Returned mappings create holes. Larger pooled growth therefore checks
actual contiguous fit after each map, with a finite budget matching the
current 32 MiB heap window. A failed growth can retain partial pooled
mappings for reuse; this repair does not claim transactional allocator
growth or elimination of all fragmentation. Kernel page tables can remain
until process teardown.

Since R16 (SPEC A23), pooled pages stay mapped until the process exits,
except that when a request for pages of its own (4096 bytes to 64 pages)
finds no room in the window, the allocator unmaps one free, page-aligned
pooled run of at most 64 pages and retries the request once; a block the
program still holds is never moved or unmapped, and a request that still
fails after the retry is refused as before (`tests/runtime_allocator.rs`,
`r16_*`, run by `scripts/check-runtime-allocator.sh`).

`scripts/check-runtime-allocator.sh`, included in `scripts/check-all.sh`,
imports the actual allocator into a bounded host page arena. It checks
exclusive page return with live neighbors, the concrete one-hole contiguous
growth case, realloc ownership, failed growth and refused unmap. Removing
unmap or reverting to nominal-total growth each fails its specific test.
The host arena does not qualify kernel TLBs or syscall accounting.

Three fresh production 300-session runs and one same-boot 600-session run
passed the original capacity and teardown oracle, without diagnostic
builds, extra warmup or equality allowances. Every requested checkpoint,
the 300-session midpoint and final endpoints held guest frames **595**,
sshd heap **218 pages**, fsd heap **12 pages**, with the original reusable
process/handle/pipe/channel/session capacities. Final teardown drained to
zero. Some intermediate global frame publications varied transiently;
the evidence does not claim constancy at every instant.

## Evidence and scope

Original run: `a2b08686-91b1-4f82-b473-58019f1fd984`, kernel `c406d803`,
platform `4ac76cab`. Original 132-file receipt manifest SHA-256:
`f85b72cda793e68a9e6ca6bb52a374192578faafdfe5881b11bd37bedb33986f`.
Retained receipt: kernel `build/successor-release-20261003-a2b0868691b1`.

Repair qualification run: `1f9069b6-d0ee-4263-a0d2-5a723dfac307`.
Five-file implementation/test patch SHA-256:
`5706e42d949086d96555b1fabeb30877db5b20f84200412a006c72024969b441`.
Independent review SHA-256:
`81315a0fa58e1f3c04c9909c7fdff9799ea58a433bcbd068a164fa7f71d18f3d`.
Receipts and passive checkpoint tables: kernel
`build/ssh-heap-20261003-94eb7cb4685a`.

Formalization consideration: the ownership proposition is scoped to valid
GlobalAlloc Layout contracts, current map/unmap ABI and single-threaded
processes. Source review, bounded imported-allocator tests, negative
controls and the unchanged production oracle suffice for this repair.
No SMP, RT latency or generic memory-bound claim is added. No serialized
state, wire ABI or authority transition changes. Allocator replacement
requires quiescence and preservation/reconstruction of mapping ownership,
or a restarted process: live dedicated mappings cannot be handed to the
old pool without explicit conversion. Native Rust layout
is not a transfer schema; no hardware-transfer or post-effect rollback
claim follows. The isolated candidate requires whole-platform qualification
before main integration; a passing heap matrix alone does not accept or
seal a release.

## A3 free-pool telemetry

The capacity readers now recognize a final `heap_free_pages=N` on
`SERVED CAPACITY ... heap_pages_peak=N link=up|down|unknown` and
`FSD CAPACITY ... heap_pages_peak=N`. Both current emitters append this field, sampled through
`absd_runtime::heap_free_pooled_pages()` before formatting. Historical readers
continue to accept older records without asserting that those implement A3.

The controller's A3 metric is `floor(sum(free-list byte lengths) / 4096)`:
process-local reusable pooled storage, including free-node storage. It
excludes held allocations and outstanding dedicated mappings. Fragment
bytes are summed before rounding; two disjoint 2048-byte free runs count
as one page-equivalent. This is not the number of page-aligned runs that
can be unmapped, the largest available allocation, or kernel free frames.
The production accessor traverses the free list under its existing allocator
lock, without allocation, logging, syscalls or callbacks; its guard drops before
returning to the emitter. It makes no change to allocation, insertion hints,
coalescing, growth or R16 trim/retry behavior. Cost is O(free nodes), only at
quiescent reporting boundaries, not per allocation. Separate capacity fields are not one atomic global
snapshot, and telemetry does not qualify live allocator replacement.

Named current consumers `contain-matrix.py`, `agent-exec.py` (also used by
`agent-job.py`), and `link-matrix.py` preserve their old line validation and
accept only this additional numeric tail. The first two preserve missing
telemetry as `None` (JSON `null`: unknown), not zero. Existing U1 and
frame-retention readers keep their prefix fields and do not interpret this
new metric; survival-recovery reads boot identity only. This field adds no
resource-equality or leak acceptance allowance. A check for the new A3
producer contract must require an actual numeric field; optional parsing
of an old receipt does not establish that the producer implements A3.
`scripts/test_capacity_line.py` covers old/new forms and malformed tails
without executing the guest harnesses. It derives new-contract fixture lines
from both actual producer format strings, checks the production accessor binding,
and also checks c-kit, cports, clang, agent-job and boot-only recovery readers.
Prefix readers retain earlier fields; they do not validate or infer the new
metric. Historical absent telemetry remains unknown.

Runtime host-model tests exercise the production sum against a separate visitor
oracle, including fragmented subpage totals, dedicated mappings, alignment,
coalescing and successful/refused R16 pool returns. They do not prove kernel
mapping effects or whole-platform guest behavior. Runtime source changes also
change the C kit and downstream binary identities: recompose and measure real
port hashes under steward authority; never silently reuse or repin accepted
PORTS.tsv digests.

Formalization consideration: the proposition is floor(sum(valid disjoint free
node bytes)/4096) under the existing exclusive lock, with unchanged allocation
transitions and explicit parser history boundaries. The bounded heap invariant
keeps this sum representable; practical oracle/transition/negative tests and
independent lock-lifetime review suffice for this observation change. This is
process-generation telemetry, not stable service identity or a transferred
allocator schema. Replacement still needs external quiescence/fencing and
explicit ownership reconstruction; no native Rust state transfer, successor
validation, rollback guarantee or authority revival is provided.
