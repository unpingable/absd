# Governed software and package lifecycle — deferred direction

The owner-requested 2026-10-06 [userland/component roadmap](USERLAND-COMPONENT-ROADMAP.md)
refines this direction into Userland U0–U6 planning in ABSD Program. It starts
with a future bounded native `cat` lifecycle proof and reuses existing utilities,
release and interface work. Planning opens no implementation/qualification
campaign and adds no prerequisite to the existing usability U1/U2 milestones.
General package management remains deferred P4; no format or resolver is chosen.

Disposition: `SOFTWARE_LIFECYCLE_CAPTURED_AND_DEFERRED`, by owner direction,
2026-10-04. The general package manager remains P4 in the
[maturity backlog](MATURITY-BACKLOG.md#p4--intentionally-deferred-until-the-platform-is-much-more-settled).
This note records semantics to preserve if a named consumer later earns that
work. It creates no implementation, package ecosystem choice, milestone, or
U1/U2 blocker. Existing paired release update and rollback remains the
current [U1 operation](USABILITY-ROADMAP.md#u1-named-machine-sustained-usability).

**Package management is a lifecycle mechanism, not an authority mechanism.**
**General package management is deferred; lifecycle semantics are not.**
The existing managed-resource boundaries constrain future mechanisms now,
without admitting implementation of those mechanisms.

## Identify content and the authorized transition

A future software lifecycle must distinguish logical software/service
identity, exact artifact/source identity, and the generation currently
installed or active. A package name, pathname, version range, verified
signature, or successful download is not authority to install or execute it.
Acquisition supplies candidate bytes; verification supplies evidence under
stated trust assumptions; planning describes a proposed transition. The
owning authority separately admits that transition and its bounded effects.

ABSD owns the authority, identity, refusal, activation, evidence and retirement
contract. Reused archive, transport, resolver, verification, or installation
engines may implement it through an adequate boundary; their native APIs
are not the ABSD contract. This is independent of Constellation and selects
no package format, repository service, resolver, or new kernel primitive.

## Preserve the lifecycle distinctions

These are phases a future contract must distinguish, not a prescribed
universal state enum or execution protocol:

| Phase | Required distinction |
| --- | --- |
| Exact identity and acquisition | Name source/artifact identity, origin and intended consumer; acquired content remains a candidate. |
| Verification | Establish declared integrity, provenance, authenticity and compatibility facts under named trust/freshness assumptions; verification does not grant authority. |
| Planning | Resolve the proposed dependency and configuration changes, effects, preconditions, budgets and recovery limits before requesting admission. |
| Admissibility | An authorized owner decides the exact scoped transition; observations or evaluator judgments remain evidence. |
| Staged installation | Construct and inspect candidate state separately, preserving the current generation and refusing failed preconditions. Installed does not mean active. |
| Activation | Name the generation becoming active, authority reconstruction, dependency effects and the commit/refusal boundary. |
| Independent post-verification | An observer outside the replaced component checks the stated postconditions; a component's own success message is insufficient. |
| Receipt | Preserve operation identity, exact old/new identities, covered effects, disposition, evidence and unresolved obligations. |
| Rollback or reconciliation | State what can be restored after each effect; retain lineage and resolve uncertain effects rather than infer refusal from a timeout. |
| Retirement and garbage collection | Fence or end old authority/execution, establish remaining references and custody obligations, then authorize reclamation of exact objects. Registry absence is not retirement. |

Use the existing `COMPLETED`, `REFUSED`, `INDETERMINATE`
[operation meanings](OWNERSHIP-BOUNDARIES.md#outcomes-describe-operations-not-transport-status).
No new ABI status is implied. Completion names the established postcondition;
refusal names a covered effect known not to have occurred; uncertainty has an
owner and reconciliation path. Transport success, process exit, installation,
activation, readiness and independent acceptance are separate observations.
Retry identity, lost replies and receipt retention must be explicit before
automatic state-changing retries are admitted.

## Configuration, secrets and owned data are separate

Immutable package content, operator configuration, generated runtime state,
secrets, and mutable application data are five distinct classes with separate
owners, authority, schemas and retention obligations. Runtime-state
reconstruction or disposal needs its own contract; it is not automatically
package content or application data. Removing a package cannot implicitly destroy owned data or keys;
installing one cannot silently acquire their authority. Config merging,
secret enrollment/rotation/retirement, and data migration require their own
preconditions and authorized effect scope. A binary rollback does not invert
a state-schema migration or undo an externally visible effect.

Prefer reconstruction from authoritative state. Any transferred component
state has an explicit versioned schema, conversion preconditions, and loss or
refusal conditions; native memory layout is not a transfer contract. Keep
stable identity separate from executable generation, never revive fenced
handles, and reconstruct or transfer authority only under an explicit rule.
Successor acceptance is independent of the component being replaced.

Optional installation, migration or removal hooks must have bounded input,
time, memory, output and effects, and explicitly authorized rights. Hook
completion is evidence only for its stated scope. Neither a general shell
hook nor a package's metadata acquires ambient rights. How hooks are admitted,
interrupted, reconciled, or forbidden remains open; no hook runtime is selected.

The [live-evolution constraints](LIVE-EVOLUTION.md) remain applicable:
quiescence and fencing precede reclamation; state and authority transfer are
selective; rollback is claimed only where honest; generations have explicit
retirement and bounded coexistence. Ordinary reboot-based L0 update remains
valid. A package lifecycle does not require or admit L1–L4 mechanisms.
Image and release-pair updates can coexist with a future independently managed
userspace package lifecycle; that lifecycle does not automatically replace them.

## Questions deferred with the mechanism

Dependency resolution must eventually specify exact identities versus ranges,
options/features, ABI/provider conflicts, architecture and foreign-ABI needs,
and reproducible selection under changing metadata. Supply-chain assumptions
must name acquisition origins, trust anchors, verification policy, metadata
freshness, replay or downgrade refusal, mirror content mutation, signer/key
lifecycle, offline operation and unavailable evidence. None is qualified here.
A future shared normative format needs common conformance vectors and current
consumers; no format is adopted merely by naming these questions.

Also open are the owner of activation and admissibility, independent
post-verification, partial staging cleanup, in-flight operations, schema/data
rollback, old-generation coexistence, retained replay/rollback references,
secret custody and authorized garbage collection. Transaction boundaries across
filesystem generations, service activation and crashes during installation or
activation remain unanswered; no global atomicity is promised. Do not expand the current
paired-release path into a general package or service framework from this note.

## Formalization consideration

Source identity: kernel base `f2c200b4c4b13662b582adb478cfdbb1260b74c4`,
tree `67f8dd60e8bbd13886202fb1bd2de87632a5dd2c`; exact source, doctrine,
coordination and proposed document hashes are recorded for design capture run
`c8ac65f1-87bc-4974-b416-46f949737f1b`. Decision owner: ABSD's architecture
owner; mechanism admission and acceptance remain separate decisions.

The propositions are separation of acquisition, verification, admission,
staging, activation and acceptance; distinct ownership of executable content,
configuration, secrets and data; and honest rollback and explicit retirement.
Counterexamples include treating installed as active, allowing a verified
archive to authorize its own hooks, undoing a schema change by selecting old
bytes, and deleting an unreachable generation still needed for rollback.
Prose is sufficient for this direction-only change: no implementation or
behavioral proof is introduced. Exact transition/state schemas, authority
construction, dependency algorithms, supply-chain trust/freshness and
post-effect recovery remain unknown. Later admitted contracts should consider
small bounded transition models with explicit construction correspondence;
this capture creates no model, qualification run or implementation lane.
