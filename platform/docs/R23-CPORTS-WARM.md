# R23 Cports: explicit reset-first groups

This bounded consumer follows owner issue15/D30 and applicability amendment
716fe435. R23 remains PARTIAL. `sqlite.excl-crash` and `sqlite.power-cut` keep
all existing stop/restart and exact recovery-query checks; their warm coverage
is NOT_ESTABLISHED. No substituted stopping rehearsal or release waiver.

## Comparable boundaries

A complete group is an explicit reset-input-state prerequisite, session probes,
every selected non-stopping case in its original order, the existing held-session
warmup before the first scenario, then liveness. Cold reset may be a no-op;
subsequent groups remove only listed generated regular files on both the target
and Linux reference. The target uses the existing whole-system object inventory, with only its existing
four-log and recovery-state exclusions; effects outside /cports are not ignored.
The Linux reference uses its complete fixture tree. Both logical input states must match their captured
initial state (names, kinds, read-only/mode flags, file digests). Unknown objects,
input mutation, generated directories or symlinks refuse. Files are not restored
from an arbitrary snapshot. Object serial generations are not logical identity.

SQLite t.db/n.db and speedtest databases/journals reset explicitly. The exclusive
lock chain resets x.db and its journal: setup starts with no database and creates
two rows, readonly observes two, deny commits row3, later release/concurrency
cases retain three. Zlib requires ordered gzip/gunzip pairs; eight.bin is prepared
before cold sampling. Posix and Lua retain their real cleanup and semantic checks.
Any undeclared leftover makes the next reset fail. --only prefixes must retain
actual chain dependencies; unsupported case-table changes refuse instead of
silently adding preparatory workloads. Pin authoring remains its existing route
and reports NOT_ESTABLISHED.

Capacity is sampled at the group's END, when retained output files exist. Two
or three complete reset-first groups establish the same literal SSH/FSD capacity
fingerprint. The actual measured group then performs the SAME declared reset
before the existing case loop. It is logged separately and excluded from existing
case counts/timings. This restores setup prerequisites without hiding a different
operation. No final reset is performed before stopping cases: x.db/row3 must
remain available. Rehearsal-generated host output lives in distinct per-attempt
directories, so measured result files cannot inherit an earlier success.

Cold held-session rehearsal preserves image/kernel/file/settle checks but neither
uses nor charges the old measured five-page allowance. Cold mapped growth is
bounded by the two/three-group plateau, with residual growth above six pages
reported to the owner. The measured default warmup retains its original cap.

All existing measured per-case, repeat-round, output, normalizer, integrity,
semantic, resource and stopping methods remain unchanged. Before a first stop
(or at a non-stopping run's end), the additional post-warm check first requires
exact logical end-state file correspondence on BOTH sides to the last rehearsal.
Only then does it apply the unchanged full fingerprint and cumulative frame
rule. If file correspondence is absent, post-warm aggregate coverage is explicitly
NOT_ESTABLISHED; the existing measured correctness result remains independent.
No generated-file exemption or new tolerance is introduced. A real boot change
cannot reuse a predecessor baseline. Existing exact repeat-round witnesses retain
their own narrower same-state scope; they are not relabeled as R23 coverage.

## Expected failure and refusal

The selected size20 LIMIT workload is actually attempted with the same arguments
and timeout. Its partial output and outcome are retained separately for every
rehearsal. An expected timeout is not made to succeed. It can participate only
with observed bounded session reclamation and verified exact reset on both sides
before another attempt or the measured group. A reset/reclaim failure refuses
warm establishment and records NOT_ESTABLISHED; no measured result is inferred
and unsafe state is not reused. Original image-capacity NOT_RUN is explicit in
outcomes/coverage, never claimed executed. Other uncontracted timeouts fail closed.

The controller approved this same-shape prerequisite interpretation under existing
owner15 applicability, including expected LIMIT behavior; it is not a new owner
exception or broader release authority. Whole-run semantic failure is never
converted to successful coverage. Logs distinguish reported correctness, coverage,
NOT_RUN, and NOT_ESTABLISHED.

## Qualification boundary

`python3 -B scripts/test-cports-warm.py` exercises finite reset transitions,
final rehearsal→baseline→measured reset→setup/deny→matching end state, preservation
of stopping prerequisites, failed resets on both sides, unknown effects/input
mutation, chain/pair prerequisites, held-session accounting, stopping exclusions,
new-boot refusal, expected timeout output retention unreclaimed timeout
refusal, actual held-session cold-growth versus measured-cap controls, and
whole-system unrelated-file mutation refusal. It checks original correctness/stopping methods remain AST-identical.
These host fixtures do not prove guest convergence, runtime sampling atomicity,
or that every current full Cports case reaches a matching file boundary.

Formalization consideration: an explicit finite logical state/reset model is
exercised by deterministic fixtures, with exact source and receipt identities.
It assumes truthful runtime evidence and the original programs' semantics;
no general filesystem rollback or kernel-generation transfer guarantee is made.
Independent review and separately admitted guest qualification remain required.
