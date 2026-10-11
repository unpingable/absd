# ABSD userland and component lifecycle roadmap

The subsequent [system maturity map](SYSTEM-MATURITY-ROADMAP.md) reuses this
roadmap under R2–R6 and captures its broader operating prerequisites and
cross-cutting relationships. Userland U0–U6 scope and Project fields remain
with the existing items; no duplicate development/self-hosting roadmap is added.

Planning reconciliation, 2026-10-06; run
`4eb0aaf0-d7d9-448d-a0d7-da979b06ed94`. GitHub's
the ABSD Program project board owns status,
priority, assignment and sequencing. This document captures scope and proposed
acceptance, not implementation admission or qualification. No implementation or
qualification campaign starts in this tranche.

**Userland U0–U6** below is a separate namespace from the existing usability
U1 (named-machine sustained operation), U2 (native Constellation workloads)
and U3. Their operating gates, active owners and accepted evidence remain
unchanged. General package management remains deferred P4; this owner-requested
planning pass refines the native lifecycle and its future base userland without
making either a new prerequisite for those existing milestones.

## Reconciled current path

Inspected local source: kernel
`bb07bdbd0495dab954fd03626336988a5a8665ec`, platform
`60388b066fb341715ddea9773eac3f6c7d8da53a`, ABSD architecture
`742651a3a603ad84705fe0ff78cf856be3c18344`, and coordination
`c7ba0b49049e518904712325a06b6563fcf8c1c3`. These are local identities;
published default branches differ. GitHub planning does not imply a source push.

* Real applications live in the platform repository (`platform/` in a source release): restricted Rust `std`, runtime/CRT,
  native `spawn_image`, startup records, userspace FSD, format-2 persistence,
  `absd-sh`, and an SSH PTY line discipline. The PTY is not a general native
  terminal or POSIX contract. The kernel's embedded program catalog is a
  separate init/probe path, not a software-distribution system.
* Platform `src/bin` already contains `cat`, `cp`, `mv`, `rm`, `mkdir`, `ls`,
  `stat`, `df`, `head`, `tail`, `wc`, `uptime`, `uname`, and other commands.
  Its compatibility ledger records unchanged-source uutils `uniq` and other
  ports, plus JSON and single-threaded ripgrep cases. Reuse those sources and
  case identities; utility existence does not establish component lifecycle.
  Upstream uutils `cat` has a rustix/descriptor dependency cliff; the existing
  small native `src/bin/cat.rs` is the preferable first fixture.
* Cross-hosted build machinery already pins Rust 1.95.0, upstream `rust-src`,
  the ABSD target, a staged sysroot, compiler wrapper, local runtime dependencies
  and carried patches. The compatibility ledger distinguishes missing native
  facilities, wrappers, conditional-compilation assumptions and broader POSIX
  dependencies. It is measured evidence, not a blanket portability guarantee.
  SQLite's freestanding C helpers are not a general libc.
* Existing release operations verify a release manifest, stage halted-image
  trees under `/releases/<id>`, select `/absd/selected`, and check exact kernel,
  FSD, application and filesystem versions. FSD binds `/bin` once at boot.
  This is a live release consumer, not a dead format or an implemented
  independently activatable component system. Existing storage activation
  records are distinct from the software-generation contract proposed here.
* Accepted/sealed `absd-20261003.1` remains exact kernel
  `fcfbab9867da40eebb0c4dd266b82484ae7e76c5` / platform
  `c54dc90007fe509c0e118b7ec9c6cbd6ea9aa356`; previous `.3`, failed receipts,
  rollback lineage and reconstruction exclusions remain immutable. Local-QEMU
  release acceptance does not establish component activation, physical
  power-loss durability, lossless live replacement or multiweek usability.

Owning sources: [software lifecycle](GOVERNED-SOFTWARE-LIFECYCLE.md),
[ownership boundaries](OWNERSHIP-BOUNDARIES.md),
application interface (development record, not in a source release),
[usability roadmap](USABILITY-ROADMAP.md),
release successor (development record, not in a source release),
[live evolution](LIVE-EVOLUTION.md), and platform `docs/RELEASE.md`,
`docs/FILESYSTEM.md`, `docs/COMPATIBILITY-LEDGER.md`, `src/bin/cat.rs`,
`scripts/build-ports.sh` and `scripts/release_manifest.py` at the identities above.

## Primitive and boundaries

Use **component** for a logical software unit and **generation** for one exact
implementation/artifact set, provisionally. U0 settles the terms and encoding.
A friendly name/version, pathname or signature never identifies an authorized
activation by itself. Manifest declarations are inputs to trusted authorized
construction; they grant no capabilities. Keep exact source/build provenance,
artifact identity, stable logical identity, generation identity, activation
identity and launch authority distinct.

The smallest proof follows:

```text
artifact -> exact identity -> manifest -> verify/admit -> stage
         -> activate -> invoke -> replace -> rollback -> receipt
```

Verification and admission are separate decisions; custody must be established
before activation. Receipts also record intermediate dispositions and unknowns,
not just a final success. ABSD local correctness must stand without
Constellation. Align conceptually with exact identity, bounded effects, explicit
admission, custody and evidence; adopt no Constellation service, protocol or
retired WLP compatibility requirement.

## Userland U0 — one native utility lifecycle

Reuse native `cat`, with two exact generations distinguishable by identity and
controlled observation. A behavior-identical reproducible rebuild may have the
same content identity; define generation/run lineage separately rather than
calling identical bytes different artifacts. No rewrite of `cat` or additional
utility is required to begin the future proof.

Settle and document the following before implementation:

* Component/generation terms, identity domain, digest/canonicalization rules,
  manifest version and fields, exact artifact list and pre-resolved dependencies.
* Target architecture, native/foreign ABI identity, kernel/runtime/startup/FSD
  requirements and compatibility refusal; reuse current version checks only
  where their actual consumers and semantics fit.
* Requested capability roles versus authority actually supplied by the owning
  launcher, separate verify/admit owners and minimum grants for invocation.
* Inactive/staged storage, custody and immutability; active selection, launch
  binding, commit point, concurrent-writer serialization, partial staging and
  reconciliation. Choose the smallest existing path or bounded extension;
  fixed-per-boot `/bin` binding is a real constraint, not assumed mutable.
* What reboot reconstructs; declared orderly-halt/crash/device failure model;
  unsupported recovery must refuse or remain indeterminate. Logical atomicity
  never implies hardware power-loss durability. A reboot-based first proof is
  acceptable if explicitly chosen; live in-flight service replacement is not
  required.
* Replace/rollback semantics, old-generation references and retirement. At most
  restore a prior admitted executable selection for subsequent launches within
  the chosen scope; do not undo command output, owned data or schema changes,
  revive fenced handles, or assume an applied external effect has an inverse.
* Receipt identity, old/new generations, requester/owner, scope, preconditions,
  commit/disposition, evidence, observer outside the replaced utility, unknowns
  and recovery owner. Retain COMPLETED / REFUSED / INDETERMINATE meanings;
  process exit and planning completion are not independent acceptance.

Proposed acceptance: a fresh native environment acquires known bytes, verifies
and explicitly admits one `cat`, stages it without changing active selection,
activates and invokes it with exact input/output/exit evidence, replaces it,
rolls back, and after reboot inspects the selected identity and retained
receipts. Negative cases cover altered/missing bytes, incompatible runtime,
missing authority, partial staging, stale/concurrent selection and loss around
the named commit boundary. The pre-implementation decision selects an honest
minimal failure model and refusal rules. Qualification remains a later action.

Non-goals: generalized solver/semver, catalog/network acquisition, arbitrary
hooks, service manager, POSIX/libc, kernel live replacement, new kernel
primitive by assumption, full utility set or native toolchain. Pin any necessary
runtime dependency rather than earning U2 by assertion.

## Userland U1 — reproducibly composed minimal native base userland

Depends on U0. Inventory existing utility behavior and build identities before
adding commands; describe a bounded base composition using U0 manifests and
activation, with an exact list of generations and existing runtime closure.

Candidate families are filesystem (`cat cp mv rm mkdir rmdir ls stat df`),
text (`grep head tail wc sort uniq`), and supported operator inspection
(process/status, uptime, system identity, held authority and service/process
state). Choose the minimum useful set; missing `rmdir`, `grep`, `sort`, `ps` or
authority inspection is a scoped decision, not an automatic implementation
promise. Reuse `rg` or `uniq` only for behavior the ledger actually establishes.
Keep one tranche item instead of one issue per command. Full `sed` and `awk`
are later ports. Familiar names promise no POSIX semantics.

Proposed acceptance: a fresh boot supplies a coherent, reproducibly described
base toolbox entirely through native component lifecycle, with inspection of
active identities, documented behavior/limits and refusal cases. Existing shell
and PTY work is reused with its current boundaries. Link existing `std` mtime
presentation and on-box administration cards; do not duplicate or redefine
their gates. Stateful services remain outside this utility tranche.

## Userland U2 — exact dependency closures

Depends on U0 and one useful U1 composition as the operating baseline. Introduce
at least one real dependency relationship and an exact closure representation:

```text
friendly name/version request -> external or deterministic exact closure
                            -> ABSD verifies and activates the closure
```

Record closure identity, membership, dependency edges, providers/features,
target/ABI/runtime compatibility and active root selection. Settle cycles and
conflict refusal rather than assuming order. All required members must be in
verified custody before activation; staging alone does not expose a partial
active closure. Choose a commit/recovery contract at the actual filesystem and
launch boundary, without claiming a global transaction across services.

Proposed acceptance: positive native dependency invocation plus deterministic
cases for missing members, conflicting closure, ABI mismatch, dependency
replacement, rollback across dependent generations, partial staging and
crash/reboot during activation. Preserve the old usable closure where the
contract permits; otherwise surface refusal/indeterminate with a reconciliation
owner. SAT, broad semver, network resolution and service state migration remain
out of scope.

## Userland U3 — bounded catalog and distribution layer

Depends on U2. Reuse the deferred repository provenance/freshness item.

```text
catalog -> candidate resolution -> exact closure -> admissibility
        -> custody/download -> verification -> staging -> activation -> receipt
```

Settle one bounded repository's metadata, exact artifact identities, signatures
and provenance, trust ownership/key lifecycle, freshness, version/channel and
downgrade policy, mirrors, offline imports and unavailable evidence. Delivery
never confers launch rights. Coordinate with existing release-authenticity work,
but base-release signatures do not establish component-metadata authenticity.

Proposed acceptance: one bounded catalog/import path obtains a complete exact
closure and invokes U2's transition machinery, with content-mutation, stale
metadata, unavailable source, untrusted origin, incomplete closure and offline
cases. `pkg install ripgrep` is possible future syntax over these transitions,
not a selected command or semantic primitive. No Internet-scale repository
system, ecosystem choice or conventional package-manager port is selected.

Garbage collection must establish live, staged, rollback, replay and recovery
references and explicit custody/release authority before exact reclamation.
Unreachable registry entries alone do not establish safe deletion. Decide
retention bounds and interrupted collection; no collection daemon is admitted.

## Userland U4 — development artifacts and ordinary Rust cross-compilation

Depends on U0's identities and U2's real closure support; can proceed without
U3 using pinned offline custody. Uses the U1 runtime/base contract. Compilers,
linkers, libraries, sysroots and build tools are components with declared
execution target: a Linux-hosted compiler remains a host artifact, while its
ABSD sysroot/output is target-specific. Same identity/admission/custody rules
do not imply that host tools can execute on ABSD.

```text
Linux/dev host -> pinned toolchain -> ABSD target/sysroot -> native executable
```

Name owners for Rust target/PAL, restricted-std wrapper, CRT/runtime, linker
rules, sysroot construction, upstream-source pinning, locks and carried patches.
Distinguish application-source changes from build/manifest scaffolding. Reuse
the compatibility ledger and reconstruction receipts; track missing facilities
by OS/runtime boundary rather than accumulating application-specific patches.

Proposed acceptance: a reasonably ordinary independently selected Rust CLI
cross-compiles and runs without application-specific source changes, with
exact build inputs/closure, component admission, observed output/exit and a
facility-level blocker ledger. Existing unchanged-source successes are seed
evidence; known ripgrep stdin/thread divergences and rustix/libc cliffs remain
explicit. This is no universal Rust/POSIX guarantee and does not require Cargo
or a compiler on ABSD. Application-interface v0 is the existing contract owner;
resolve only the boundaries the selected application actually consumes.

## Userland U5 — eventual native development environment

Later; depends on U1, U2 and U4 plus demonstrated filesystem/process/runtime
facilities. U3 acquisition is optional for a pinned offline first environment.
Keep source trees and mutable build output separate from immutable components.
Inventory temporary files, process spawning/wait/error handling, filesystem
semantics, executable loading, resource limits and build-tool prerequisites.
Earn linker/build executor, compiler, then Cargo incrementally. Source and
dependency acquisition requires its own provenance/authority policy when used.

Proposed acceptance: an exact admitted toolchain builds a pinned small project
on ABSD (`ABSD$ cargo build`) and the resulting native executable passes an
independent invocation check with retained build identity. Missing native
facilities refuse visibly; no hidden host executor is called native building.
No self-hosting, full ecosystem compatibility or early dependency is promised.

## Userland U6 — self-hosting and reproducible OS builds

Longer-term north star; depends on U5 and the existing release/reconstruction
contract. First reproduce selected ABSD userspace, then consider complete
images/releases only under a separate bounded expansion. Build products flow
through exact identity, custody, admission, staging, activation and receipts.

Proposed acceptance: an independent rebuild reproduces the declared userspace
products from retained inputs and an admitted native environment. Record byte
comparison or exact permitted normalization and generated exclusions. Current
reconstruction's 54 identical files/two generated exclusions and normalized
kernel/GRUB comparison do not establish byte-identical whole ISOs. Native
self-hosting, reproducibility and release acceptance are three distinct claims.
No bootstrap compiler trust proof or full-system build guarantee is implied.

## Cross-cutting ownership and decisions

Keep one separate existing service-lifecycle integration item for concerns that
outlive U0's stateless utility boundary: versioned state schemas/conversion and
loss/refusal, authority reconstruction, quiescence/fencing, in-flight outcomes,
successor validation, bounded coexistence, commit/rollback and retirement.
Stable logical service identity never revives fenced authority. Replacement
success is assessed outside the replaced component. Live kernel evolution
remains a required architecture constraint and deferred mechanism lane.

Decision homes are U0 (identity/manifest, compatibility/authority declaration,
state model, staging/storage, activation/recovery, reboot, receipts, utility
rollback and minimal inspection), U1 (base composition/operator UX), U2
(dependency closure and dependent rollback), U3 (distribution/trust/GC), U4
(cross-toolchain/sysroot), U5 (native toolchain), and U6 (native reconstruction).
No new global taxonomy or lifecycle framework is required to capture them.

Foreign/Linux ABI work stays in
the kernel development repository's issue 2.
Manifests must distinguish native and any future admitted personality/runtime;
ELF64, a pathname or a generic OSABI byte alone cannot select that personality.
Native base userland does not depend on libc/POSIX or the foreign-ABI spike.
Application and service compatibility boundaries must be qualified when they
become independently versioned consumers. Any adopted shared normative format
must ship shared golden/conformance vectors with real consumers, not as later
follow-up. No new manifest wire format is adopted by this document.

ABSD architecture owner owns semantic decisions; platform owners own utility,
runtime, build and lifecycle implementation; release owners retain pair/release
gates; storage owners retain durability claims; kernel owners retain ABI and
authority enforcement. Assignments remain unset until explicit dispatch.
Cartography owns cross-project mapping and accepts/schedules no component work.

## Formalization consideration

Source identities are listed above; result identities are this document's
Git commit/blob and the hashed Project snapshots in the coordination run.
Decision owner is ABSD's architecture owner. Propositions are separation of
artifact/authority and staged/active state, exact closure selection, honest
rollback, and independent observation of an active generation. This planning
change proposes obligations; it proves none of them. Prose and source inspection
are sufficient for reconciliation, with no new model or executable test here.

Counterexamples/unknowns: pathname replacement between verification and load;
content mutation after staging; concurrent activation; interrupted selection
with a lost reply; a partially staged closure; stale ABI/state schema; old
handles surviving authority fencing; deleting rollback custody; and binary
downgrade after an externally visible effect. U0 should consider a small bounded
transition model covering two generations, one selector, one concurrent writer
and the chosen interruption points, with explicit correspondence to the actual
commit path. U2 should extend that bounded scope to a real dependent closure.
Neither model could establish physical storage durability, arbitrary live
service/kernel transfer or universal compatibility under unstated assumptions.
