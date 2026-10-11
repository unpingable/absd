# Canonical qualification map

This is the command and scope map for canonical ABSD kernel/platform
qualification. The Makefile and owning platform drivers remain executable
authority; this document does not add a second orchestrator. Controller
snapshots and next-release candidates live in the coordination repository's
`campaign/ABSD-CONTROLLER.md`; GitHub Projects owns execution status.

Run targets serially: many share the kernel target tree, external image,
serial logs or scratch devices. Preserve per-target results before another
target overwrites them. Use the existing durable execution and storage
admission/closeout rules for a long aggregate. A command listed here is not
permission to modify a physical disk or provision a host.

| Class | Existing commands and scope | Recurring use |
| --- | --- | --- |
| PORTABLE_CANONICAL | `make check`: serialized lifetime model with eleven controls, closed RT fixture model with seven controls, workspace host tests, formatting, clippy, smoke, fault, kernel-fault, framebuffer, shell, fuzz, hostile, machine-recover and debug | Every canonical kernel integration |
| PORTABLE_CANONICAL | `make mutants`; `make spawn-image-test`; `make elf-matrix-test`; `make disclosure-probe-test`; `make broker-test` | Relevant authority/loader/startup/copyout changes and a next-release kernel candidate; separate from `make check` |
| PORTABLE_CANONICAL | `make rt-test`; `python3 scripts/test-rt-oracle.py build/rt.serial.log`; `make rt-class-test`; `python3 scripts/test-rt-class-oracle.py build/rtc.serial.log` | Scheduler, context-switch and RT changes; structural TCG evidence is not a hardware timing guarantee |
| PORTABLE_CANONICAL | `make smp-up-prep-test`; handoff/stop/pipe models; guarded driver with `ABSD_SMP_ACCEL=tcg` | CPU-local state, handoff, stop/reclaim and AP-boundary changes; AP userspace stays refused |
| KVM_CANONICAL | `make fpu-test`; `make fpu-mutants` | Context/FPU changes and next-release kernel candidates; real #XM required, no TCG substitution |
| KVM_CANONICAL | Guarded driver with `ABSD_SMP_ACCEL=kvm`; optional UP `make rt-test rt-class-test QEMU='qemu-system-x86_64 -accel kvm -cpu host'` with the same RT negative oracles | CPU-local/handoff/AP-boundary changes on a named KVM host; kernel-only AP, BSP userspace and RT behavior; separate guarded multicore fixtures below |
| EXPENSIVE_ACCEPTANCE | Kernel `block-probe-test` for ATA/NVMe, `nvme-test`, `net-test`, `durable-reader-test`, applicable external/live workloads and emulator image gates | Named device/workload changes and full release acceptance on disposable images |
| EXPENSIVE_ACCEPTANCE | Platform `scripts/check-all.sh` plus existing served-boot, release and reconstruction gates listed below | Exact paired release acceptance; component-only green checks do not qualify a new pair |
| HARDWARE_ONLY | Actual census, proof boot, survey/first-light and subsystem observations in the named-machine runbooks | Only the exact machine/release/device scope exercised; storage write gates remain separately authorized |
| RESEARCH_ONLY | Active successor lifetime-protocol SMP extensions, AP guard removal, native persistence prototypes, informational `laptop-matrix`, exploratory performance/soak and future IPC measurements | Isolated lane gates; no production support or automatic merge follows |

The class describes the execution envelope, not an automatic acceptance
verdict. TCG/KVM variants may share assertions while establishing different
claims. Neither KVM nor an emulator gate named `physical-iso-gate` proves
physical-device behavior. Never turn a missing KVM prerequisite into a skip
reported as success; retain pending KVM acceptance instead.

## Existing kernel-only SMP driver

Use the existing accelerator selector and a short, admitted output path
(at most 60 characters because NIC fixtures use Unix socket paths):

```sh
ABSD_SMP_ACCEL=kvm sh docs/hardware/smp-kvm.sh "$PWD" "$SMP_OUTPUT"   # development record; not in a source release
```

Use `tcg` for its portable structural column. The driver includes the BSP
compile guard, handoff refusal, parked AP, focused lifecycle/Created-stop,
ordinary and RT AP-return refusals, AP-online ordinary/RT/RT-class boots,
the RT negative oracles, real ATA/NVMe/NIC wait fixtures, served+AP refusal,
and the three bounded host models. Reuse it rather than recopying its cases.
It does not exercise AP userspace, migration, per-CPU run queues or cross-CPU
FPU handoff. Its host models establish only their stated bounded assumptions.

## Integrated guarded multicore fixtures

The closed multicore lane now provides canonical regression infrastructure
behind its existing compile-time feature and explicit qualification boot
selection. Production AP return guards remain enabled; default boot stays UP.
Build with `SMP_BUILD_FEATURE=smp-scheduler-test sh scripts/smp-user-verify.sh OUTPUT`.
Use the existing `smp-user-run.sh`, `smp-user-controls.sh`, `smp-nway-run.sh`,
`smp-fpu-migration-run.sh`, native `smp-app-matrix.py` / `smp-net-matrix.py`
and scaling drivers with their named qualified ELF/input/output arguments.
They are KVM qualification commands; FPU evidence requires real KVM, and an
isolated worktree plus admitted output/target paths prevents shared artifacts
from being overwritten. Do not put this expensive matrix in `make check`.

The integration record (development record, not in a source release) maps the
existing final owner protocols to 103 fresh captures and 2,417 emitted receipt
controls, plus actual FPU/queue controls and canonical gates. Preserve exact
queue generations, departure-before-transfer, saved timer/FPU witnesses,
process drain, capacity and complete resource census. The historical owner
2,418 includes a separately recorded offline control; current counts are
reported from actual emissions. `check-smp-transfer-model.py` and the existing
handoff/stop/pipe models retain their bounded assumptions.

The narrow exact-repeat stop repair is enforced by both existing production
lifecycle drivers: one departed-before-drain repeat witness and four original
drains. The original-ordering executable is retained as a failing control.
The RT-class negative generator removes the final teardown regardless of
optional idle diagnostics, retaining all eleven strict/structural rejections.
The composed replay preserves failed RT preparation, strict SMP ordinary
progress and original selector receipts. Strict canonical RT gates passed;
structural SMP correctness does not qualify isolated-core latency. Production
AP enablement, scaling, BKL splitting and wider application coverage remain
unearned. The closed common-path intake (development record, not in a source release) adds the bounded
serialized lifetime model to `make check`. Its offline COMMON/cache receipt
oracles and CPU-binding model require pinned research inputs, and remain
RESEARCH_ONLY. Production CPU lookup, boot options, timing probes and benchmark
fixtures are unchanged. `BKL_SPLIT_NOT_EARNED` and `SMP_SCALING_MIXED` preserve
the research conclusions, including unearned positive real-pipeline core scaling.
The active successor lifetime-protocol lane is excluded.

## Channel lifecycle regression and aggregate distinction

The channel repair integration record (development record, not in a source release)
maps focused platform Holder/ordering tests, actual HandleTable pressure,
Cell refusal effects, attenuation and stale/reissue controls to exact sources.
These are affected-surface checks; broad deputy/resource experiments remain on
the isolated authority-composition lane. Use the record's existing opt-in test
commands; no new release orchestration or recovery mechanism is introduced.

Candidate qualification and repository-global qualification are distinct claims.
`AFFECTED_SURFACE_VALIDATED` does not make a red aggregate green.
`GLOBAL_AGGREGATE_FAILED_ON_BASELINE_CONTROL` requires exact baseline/candidate
inputs, matched selectors, conditions and failure signatures, not merely an
unchanged source file. Preserve original failed occurrences and failed candidate
runs; neither label waives a release gate or promotes a sealed pin.

The guarded kernel-only RT-class fixture has a preserved case9 missing
cross-RT-peer SELECT failure, strict checker line222 and structural line160.
Both assertions reproduced on untouched `8501ff1`; the pre-port canonical
`b2923a0` differed only in documentation. Exact port `4dc54d6` then reproduced
the same signature in one of three fixed guarded captures (two passed). That establishes preexistence, not equal failure rates or
isolated-core timing. Selectors, assertions and AP guards stay unchanged. That occurrence
retains Limited/global-red standing. A later RT fixture reconciliation (development record, not in a source release)
qualifies an exact corrected closed fixture on both baseline and CpuLocal port;
it does not rewrite the historical aggregate or qualify physical timing. Formalization consideration:
exact trace/source correspondence supports this distinction; no scheduling model,
threshold or production policy is changed by the documentation.

## Full release acceptance

The platform's `scripts/check-all.sh` remains its aggregate gate. It does
not contain every served-boot or release qualification driver. Follow
the integrated release record (development record, not in a source release)
and install/update/recovery (development record, not in a source release) for the
existing additional drivers: `scripts/release-matrix.py`,
`scripts/survival-pre-ready.py`, `scripts/survival-recovery.py`,
served capacity/churn controls, manifest/input refusal and reconstruction.
Those commands need their existing named image, configuration and release
inputs; do not replace them with an unparameterized new aggregate.

The previous accepted release pins platform `e70af640`, whose
`scripts/check-all.sh` hardcodes sealed kernel
`4212fff26bb0b160eac718c26fcc7ed5d67034a7`; `ABSD_KERNEL_SOURCE`
selects a repository, not a revision. Current canonical platform
`c54dc90007fe509c0e118b7ec9c6cbd6ea9aa356` retains that default and
supports exact `ABSD_KERNEL_COMMIT` selection.

Historical successor run `a2b08686-91b1-4f82-b473-58019f1fd984`, using
kernel `c406d803` and platform `4ac76ca`, failed the original 300-session
capacity equality: frames 753 → 770 and sshd mapped pages 314 → 331.
Other reusable counts returned and final halt reclaimed all guest frames.
That occurrence stopped before building candidate `absd-20261003.1`.
Later bounded diagnostics identified fragmentation and retained free pool
capacity; qualified repair J became platform `c54dc90`. Its unchanged
300/600-session oracles passed, followed by independently accepted whole
platform run `4d8660cf-e799-46a6-bea5-4d013191fcb9` (kernel `f2c200b`,
platform `c54dc90`). That run's own 300-session baseline/final values were
594 frames, 218 SSH mapped pages and 12 FSD mapped pages, with zero teardown.
The original failed occurrence and sealed `.3` acceptance remain unchanged.
See platform `docs/SSH-HEAP.md` and kernel
`build/successor-platform-replay-20261003-4d8660cfe799` for scoped evidence.

Fresh run `dcfd9e69-bda7-486d-b6df-820a6dd9aee4`, using kernel
`fcfbab9867da40eebb0c4dd266b82484ae7e76c5` and platform `c54dc90`,
built B and completed 28 steps before its actual-release ELF gate failed:
first-template census (processes, handles, pipes, cells, frames)
`[5,80,30,1,627]` → `[5,78,30,1,625]`. The archive, source and protocol
hashes held. Completed local transitions included accepted A → B,
accepted B → A rollback with site state, and halted B backup/restore;
those passes do not accept the overall successor. The decrease's unique
cause remains unresolved. The original chain stopped without later gates.
Receipt: `build/successor-release-20261004-dcfd9e69bda7`.

Separate bounded replay `65121112-4a3e-4d85-a4eb-2a440df011f0` passed and
was independently accepted against that exact archived B kernel/ISO/services.
Test-only copies consume the current startup record and an explicit stdin
marker plus EOF before the three unchanged probe bodies. All 87 ELF cases,
per-case full census equality, post-case valid controls and sentinel held;
all 28 disclosure checks and existing spawn assertions held, with clean
served drain and final zero census in all three boots. This fences the
current parent spawn epilogue, not background service activity generally;
it does not uniquely attribute the earlier decrease. Receipt:
`build/successor-boundary-fence-20261004-651211124a3e`; independent
acceptance SHA-256
`ecff1cc074071ed3fc71496a6679aaeafadf5867617cc5e8f7aae51098f4853e`.
The earlier `e06dc33d` adapter build failed before any VM because its fixture
manifest omitted a direct local ABI dependency; that failure is preserved.
No production source, original probe body or case expectation changed.

The separately admitted six-step served continuation
`9a88f33c-ebf4-4982-9dd4-ccd3a59ca29d` completed all six gates at
2026-10-04 06:37Z. Independent tail acceptance SHA-256
`7d5f5f06dc20d6c255d4d55052a8523e36471ada4b5233df6f29c2f9138fb941`
verifies all 13 containment cases, strict actual-B 300-cycle return to
594 frames/218 SSH pages/12 FSD pages with original resource fields,
40-round framing/load and both source-control recovery cases. The load
claims framing/releases/persisted data/rebinding, not unauthorized-key login,
final global census or clean halt. Raw/control custody and key retirement
are in `build/successor-served-tail-20261004-9a88f33cebf4`.
Full manifest-guided reconstruction `5048b8a2-0294-448f-ad6c-a58564c3ee39`
completed at 07:16Z, using fresh pinned clones at the recorded platform path:
toolchain matches, 54 files byte-identical, two generated records not rebuilt,
GRUB exact, kernel matching the existing stripped/build-id normalization.
Whole ISO differs due to its wrapper stamps. Receipt:
`build/successor-reconstruction-20261004-5048b8a20294`.
Independent reconstruction acceptance `07f9b1bb` and overall exact-pair
acceptance `87cda7d9` establish the composed mandatory scopes. B is now
**validated and sealed locally** as `absd-20261003.1`; previous `.3` remains
immutable with qualified accepted-B → A rollback. The successor record (development record, not in a source release)
links exact source/archive/acceptance identities, commands and limitations.
No single uninterrupted green original producer is claimed.

Add the loader/disclosure/spawn targets and the KVM FPU targets above when
qualifying a release with the newer canonical kernel. Preserve host identity,
source and executable identities, individual oracles, terminal accounting,
mutation evidence and known limits. Advance a sealed component/release pin
only after the actual paired release process accepts that exact candidate.

## Failed evidence and active research

The strict SMT RT-class failure in preemptive-AP research remains a failed
topology result. Later passes do not erase it. Ordinary SMP correctness may
proceed separately; bounded RT's research topology rule is one physical
core with its SMT sibling parked/quiescent. This map neither enables AP
userspace nor weakens the timing bound. TCG's absent #XM remains a FPU
limitation; redb/RedoxFS recovery-cost results remain persistence donor
evidence. Active modern-SMP and native-persistence worktrees are not inputs
to canonical acceptance until their owners close their gates.

Formalization consideration: this status map composes existing commands,
unchanged oracles and immutable results at kernel `fcfbab9867da40eebb0c4dd266b82484ae7e76c5`
and platform `c54dc90007fe509c0e118b7ec9c6cbd6ea9aa356`; prior source/run
identities above remain historical. Source and receipt correspondence,
the existing bounded models and deterministic negative controls suffice
for this documentation change; no new runtime transition, model, timing
bound or capacity expectation is introduced. Unknowns include the unique
provenance of the original ELF census decrease, production live reachability,
physical timing/flush behavior,
production AP userspace and general cross-CPU FPU ownership beyond the
separately qualified CPU0↔CPU1 fixture. Decision owner: campaign controller
under the owner's integration scope. Live kernel evolution remains a design
constraint: these halted local operations and test-only startup ordering
establish no live hardware/state/authority transfer or post-effect rollback.

## CPU-local identity and physical handoff

The checked x86 GDT/CpuLocal implementation replaces repeated hot-path hardware
discovery; ARM per-CPU identity remains architecture-specific. See the
exact port (development record, not in a source release),
scaling conclusions (development record, not in a source release) and
Z2 next-lane handoff (development record, not in a source release).

`sh scripts/cpu-identity-controls.sh QUALIFIED_ELF FRESH_OUTPUT` is an explicit
KVM canonical regression alongside the existing guarded multicore drivers.
Build that ELF with `smp-scheduler-test`; its three initialization controls must
produce the direct identity refusal, not a successful boot. The geometry host
test is part of `make check`. Existing 2/4/6-CPU queue/migration/steal/FPU and
lifecycle oracles protect executing-CPU identity after task movement. The
old test-only CPU cache and operation observers remain research evidence.
