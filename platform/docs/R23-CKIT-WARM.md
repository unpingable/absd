# R23 first bounded consumer: C kit

This source change applies the STAGE2 reusable-capacity contract to the existing
non-stopping C-kit matrix. Owner D30 and the accepted applicability amendment
716fe435b58e9dac5a04cea049d1e8cff42f54a8 govern the remaining scope. R23 remains
PARTIAL. The stopping sqlite.excl-crash/power-cut cases retain their exact checks;
their warm coverage is NOT_ESTABLISHED. Other harnesses are unchanged.

After boot, before opening a probe session, capture full paired SSH/FSD capacity.
Repeat the ordered shell probe, every selected case (including the complete
stdio write/cat/verify cleanup chain), held C/native concurrency, executable
startup vectors and final liveness. Encoder-refused vectors remain explicit
skips, not executed shapes. Semantic and file-content checks run in rehearsals;
resource growth is judged by the whole-group plateau. Rehearsal output is
prefixed and does not enter measured case totals. Pin authoring (`--pin`) retains its existing route and single concurrency
warmup, explicitly marked WARM NOT_ESTABLISHED reason=pin-authoring. Only
unpinned qualification runs execute the new plateau. The supported next action
after authoring remains independent review of the generated pins, followed by
a separate unpinned qualification run; authoring is never warm qualification.

Two equal consecutive full fingerprints after at least two complete groups
establish the baseline. A third unequal group fails; there is no last-reading
fallback. Boot identity and fresh SSH/FSD cumulative counters bind the samples.
SSH reclaimed sessions must equal the harness's opened-connection count. No
extra SSH session is opened merely to collect full capacity. The cold/warm
SSH heap, FSD heap and residual split is logged once. Residual warm growth over
six pages produces an owner-report flag, not an invented pass/fail threshold.

Existing measured per-case and concurrency resource comparisons remain exact.
The final group also checks the complete warm fingerprint: residual pages and
FSD heap remain exact; at most five cumulative mapped pages may be added to SSH
heap. This allowance cannot override existing exact comparisons. Repeated
measured groups, if a caller uses the helper again, must read flat. There is no
64-open FSD allowance in this C-kit workload. Page observations are not an
allocator correctness or zero-retained-byte proof.

Host validation: `python3 -B scripts/test-warm-baseline.py`. The state fixtures
check two/three-group settlement, third-group refusal, all fingerprint fields,
boot/counter freshness, omitted shapes, cumulative versus repeat allowances,
malformed latest records, normalized logs, residual owner reporting, and actual
C-kit ordered replay dispatch plus unchanged exact resource refusal. They do
not establish that a guest reaches a plateau or that every target runtime
capacity line is delivered on time. Guest qualification remains outstanding.

Formalization consideration: the bounded state machine has cold, rehearsing,
established and refused states; one establishment attempt per object/boot,
maximum three groups, and no failed attempt reset. Deterministic transition
fixtures suffice for this narrow Python change. They assume truthful capacity
records and complete caller-supplied workload identity; they do not prove kernel
sampling atomicity or runtime reclamation. Independent reviewer/controller owns
acceptance. No kernel generation or authority-transfer mechanism changes.
