# MWM G1 implementation result

Status: **experimental component integrated, whole-G1 runtime not accepted**. The exact source, observer correction, and review packets are recorded in the owning #128 lane registry. This document is not supported ABI, a production compositor, a supported-hardware claim, or admission of #129–#132.

## Source and consumed artifacts

The original source branch was `research/mwm-g1-impl-20261103`, based on kernel `8d96b1f7597ee9e91e9d00e8ff464a463af02e2b`. The accepted design is `c6f3856174515d5a07720e9c7aa47ff5aac9bb0c`; its independent design verdict is retained separately. The component subsequently integrated into private kernel `latest` at `412d6eda060f805801e45ce9b1bbe55e3d6b0fe1`. Current observer-correction and artifact identities are recorded in the resume lane rather than by a self-referential hash in this file.

The original component build-route verification consumed these historical identities:

| Artifact | SHA-256 |
| --- | --- |
| `mwm.elf` | `7502627a0bfe57e88064e7607f24ff8f8e568c33442a57ee27ebfe55cb2e1478` |
| `init.elf` | `7c8af0d104037a5ecb274b9e60804856196c682c294324e1f78cd98fa6a997b3` |
| kernel ELF | `7292ff09f87dcf8431919da9b2254d17e8f513e7c7eaf1f51cb2ac398b965cf9` |
| normal-demo ISO | `247b155540b8adef0df6f84b720d9d4fb87b78cd8b2407bff5dd00dda1c1d42c` |
| fault-control ISO | `efad64359771eff3555ee594350d545f3c13331e5f273b2d26d25d6ff6d658d2` |

The current integrated-source rebuild at `afa575dd` produced kernel ELF `3ca221828fbc906ad1ef74afdc9282109b8f82d03cfe49b696a4c484623b27ab`, normal ISO `d08156c95a7a95d87c51ffb626fb0222b2403e7c0ef58daedc799b2656ab5fce`, and fault ISO `4d0574434670ced01c57ad79f6efc38d15b118ccedf28dfc3349f729f7b0af74`. MWM and init retained the two hashes above. Later observer changes do not alter these product inputs or rebuild the ISOs.

The same MWM, init, and kernel hashes appear in both ISO receipts. `make mwm-demo-iso` and `make mwm-fault-iso` create those receipts; they do not execute a guest. The test suite recomputes every hash from the named bytes, requires MWM and init to be distinct ELF64 images, and requires the two ISOs to differ. Ordinary init contains neither the MWM mask nor successor route.

## Verification evidence

The implementation ledger preserves task-level commands and results. Final host verification includes:

- default workspace tests: **541 passed, 0 failed, 1 pre-existing ignored**;
- `mwm-experiment` workspace tests: **565 passed, 0 failed, 1 pre-existing ignored**;
- 24 display-focused tests, including metadata/range/copy refusal and authority/refcount behavior;
- combined `mwm-experiment,native-pcm-experiment` workspace tests: **566 passed, 0 failed, 1 pre-existing ignored**, including the nine-kind accounting tripwire;
- eight exact acknowledgement/rectangle/geometry protocol and transport tests, including split-pipeline and bounded handoff cases;
- two coordinator tests against the real coordinator with a controlled syscall boundary, covering partial-spawn cleanup and readiness/second-open/kill ordering;
- two real build-route tests, with distinct MWM/init and four-hash ISO receipts;
- 19 current offline oracle tests, including normal terminal cleanup and later-fault refusal, initial HMP greeting, completed and stable fault evidence, early/incomplete capture controls, an HMP-error/stale-file refusal through the real Unix-socket adapter, wrong/reused/missing/out-of-order evidence, actual geometry mismatch, malformed/truncated PPM, and a real local Unix-socket/HMP adapter exchange;
- default, MWM-only, and combined-feature Clippy with `-D warnings`, rustfmt check, and `git diff --check`;
- `scripts/provenance.py check`: **UNCHANGED**. This does not remove the existing manual licensing/distribution hold.

- standard `make arm64-build`: PASS, producing ARM64 `kernel.img` SHA-256 `39803f028b9ca9d61fd91cae182daacf27f08281fe6245db43e32e30c8a292d6` without jobserver warnings;
- standard `make iommu-mutants`: **50 named mutants rejected**. The original 900-second invocation stopped after 34 with the next case indeterminate; after process reconciliation, the same full target completed with no timeout. No mutant was skipped and no historical result was relabeled;
- `scripts/test_provenance.py`: **133 tests passed**.

At the original source freeze, no `make check` or QEMU target had been used. The later ordinary integrated pair passed its stock build, eight kernel gates, and the 82-check served matrix; those health checks did not exercise the feature-gated MWM pixel sequence.

## Independent source-review correction

The first source/authority/pixel review returned **REJECT**, retained at SHA-256 `48322fde96e0d4234db03280fc79133466f73febdfea0f92a47136145a7c6403`. It found no kernel authority or staging-transaction defect, but six guest-fixture/apparatus defects. The corrected source is a new candidate, not a relabeling of the rejected freeze.

- Second-open refusal now follows MWM A readiness and precedes its kill, matching the coordinator's actual scheduling.
- The HMP adapter consumes the initial greeting prompt before issuing screendump commands. The local Unix-socket test exercises that exchange.
- The acknowledgement transport now requires a bounded quiet handoff after `GO\n`: another buffered byte produces an error instead of crossing into the next phase. The actual generic read loop, not only the parser, is tested with split pipelined input, trailing bytes, valid fragmentation, and timeout. The host still sends exactly one `GO\n` per completed capture; pipelining is forbidden. This is a bounded observation barrier, not a general input-security protocol.
- Every partial-spawn path closes the display and all acquired parent pipe copies, and coordinator abort paths clean up the child/readiness handles. Tests exercise the real coordinator with controlled syscall failures.
- Normal evidence now requires `USERSPACE BOOTSTRAP OK`, `EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0`, `EXTERNAL WORKLOAD OK`, and `ABSD BOOT OK`, and rejects any kernel-fault record. A later fault can no longer be accepted as normal completion.
- The combined-feature kind bitmap is `u16` with a mask derived from the actual kind count; the combined suite passes. Test-only mirror/emergency flags are thread-local so parallel host tests cannot change each other's expectations; the production flags are unchanged.

## Offline apparatus finding

The malformed-PPM control exposed an end-of-input loop in the shared `read_ppm` utility on `P6\n`. The offline test process was stopped, and the parser gained bounded header/comment/dimension handling. The same malformed/truncated controls then passed with the other oracle controls. No live occurrence was used to repair the apparatus, and no historical product or qualification verdict changed.

## 2026-11-04 observer correction

The preserved fault images exposed a capture race: the serial fault marker precedes the screen-only halt notice. Three new controls failed against the old observer and now pass with 15 original controls. The corrected observer requires a font-checked `ABSD HALT code=2` notice and retries incomplete or unstable pairs for at most 10 seconds. Replay verified all 43 preserved evidence-file hashes, rejected the original partial image, accepted the completed halt image, and passed normal evidence only after host logs were moved outside a fresh copy of the oracle root. The original normal/fault verdicts and unequal fault pair remain unchanged.

The first independent resume review rejected a separate HMP-error/stale-file path. A new real-adapter control failed before the correction. Each screendump now uses a fresh temporary file, rejects HMP errors, and atomically replaces the phase image only on success. A second offline real-QEMU normal/fault pair passed; all 29 copied files hash-verify and both evidence roots pass the independent checker. No final acceptance result is inferred from those apparatus validations.

## Evidence limits and next boundary

The earlier `b316a381` images supplied bounded component pixel observations, and the `afa575dd` integrated-source images passed two offline apparatus-validation pairs. The final normal/fault acceptance sequence has not run. No physical hardware or transport benchmark has run. The host evidence does not prove keyboard behavior, client composition, timing, throughput, or physical fatal rendering. The independent oracle has an admitted-socket driver but deliberately no QEMU launch path.

The next boundaries are the narrow independent re-review of the corrected HMP path and one final integrated-product normal-then-fault sequence. The execution envelope binds exact source/apparatus/artifact identities, one x86 QEMU GOP CPU, resource/storage limits, separated host logs, negative controls, recovery, and cleanup. No next gate, supported-ABI promotion, publication, or #129–#132 implementation follows automatically.

The finite authority proposition, identities, linear-chain scope, and unknowns were recorded in the accepted G0/G1 contracts. Practical host and adversarial tests are sufficient for this bounded implementation stage; no general election, serialized-export provenance, total retained-history guarantee, or unbounded state-machine proof is claimed.
