# R23 TCC warm baseline

This adapter covers the selected TCC main sequence: guest compile, copied ELF,
semantic reference comparison, held-session cleanup and loader-refusal control.
It preserves the original semantic/classification, measured per-case resource and later
highwater-repeat predicates. It does not qualify a guest or establish full R23.
Owner issue15 and the separately accepted applicability amendment retain all
stopping/recovery gates; no retrospective C5 result changes.

Each rehearsal and measured sequence begins with the same declared reset:
remove only existing selected tcc-out ELF files using native rm, verify their
absence and verify all non-log data unchanged (the existing Cports /var/log/ exclusion; log-byte stability is not established). The cold empty set uses a no-op
shell session. Reset traffic/timing is reported separately. No rm -f semantics
are assumed. The native rm image is explicitly imported. Initial/final stdio
state must be absent on both guest and Linux reference sides; only the existing
complete write→verify chain is supported. Unsupported reset shapes report
NOT_ESTABLISHED, then retain original checks. A failed reset after warming starts
aborts; it never falls back to success.

Two or three complete ordered groups must have equal adjacent full capacity
fingerprints on the same boot. Every held and ordinary SSH connection is counted;
capacity must account for all of them with no live image. No sampling SSH session
is added. Full non-log guest data bytes at each end must equal the final rehearsal
before the literal capacity comparison; no arbitrary filesystem object-count
subtraction is added. Existing rotated-log treatment remains in WarmBaseline.
Per-case hostcfg ELF and Linux semantic/file checks run during rehearsals too.

After establishing the end-state baseline, the next reset begins the measured
sequence and recreates all its outputs, so the first measured operation still
creates rather than overwrites. Measured counters/timings start fresh; actual
connection counters never reset. Rehearsal logs are prefixed. Existing later
highwater repeats remain separate exact checks, not replaced by rehearsal.

--pin keeps its original authoring path and PARTIAL status, with warm coverage
NOT_ESTABLISHED. --only retains PARTIAL and only claims the selected sequence;
an incomplete stdio chain cannot establish warm coverage. Existing timeout,
short.writer timing-range and classification exceptions remain unchanged.
Future guest admission must budget up to three complete rehearsals in addition
to measured cases and existing repeats; current source acceptance grants none.

Formalization: the accepted bounded WarmBaseline state machine governs telemetry
only. Adapter tests establish finite reset/sequence correspondence under an
explicit file/session fixture, including negative controls. They do not prove
runtime telemetry truth, atomic SSH/FSD observations, scheduler behavior or
live-generation transfer. No new runtime or authority mechanism is introduced.
Independent source review and live qualification remain required.

During rehearsal, stable sampling and image/kernel/file/rest-handle/rest-open/
draining guards remain enforced. Memory/FSD capacity growth is recorded without
charging the old measured frames-step cap or mutating highwater lists. A fixture
admits a100-page initial step followed by plateau and refuses a6-page later
measured step. The measured compare_census/frames_step path is unchanged.
