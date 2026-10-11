# ABSD live evolution and replacement

Disposition: `LIVE_EVOLUTION_CAPTURED_AND_DEFERRED`.

This note records a direction for replacing running code on an ABSD machine
without a reboot, assigns each form of it a class of `docs/MATURITY-BACKLOG.md`,
and names what would promote it. It opens no implementation lane, changes
nothing in the current `INSTALL_UPDATE_RECOVERY` tranche, and does not
reinterpret ordinary release update or rollback as live update. Where it
says "do not design", that is the instruction, not a gap to fill.

The [ownership boundaries](OWNERSHIP-BOUNDARIES.md) define restart classes
as falsifiable contracts. Restartable does not imply transparent restart;
reconstruction of a network stack does not preserve live TCP connections.
These classes are independent of the L0–L4 mechanism ladder. Stable logical
identity, versioned state schemas, explicit authorized rebind and successor
acceptance outside the replaced component constrain any future mechanism.
Whole-kernel generation replacement remains a required long-term capability
and a present architectural constraint; L3/L4 implementation remains deferred.

## Ordinary update is not live evolution

The supported direction for changing what a machine runs remains the staged,
rebootable release of `docs/USABILITY-ROADMAP.md` "Paired update and
rollback" and the platform's `docs/RELEASE.md`:

```text
known-good release A
        ↓
stage release B separately
        ↓
validate compatibility
        ↓
boot B
        ↓
accept or roll back to A
```

Live update is not required for U1, U2, install/update/recovery validation,
release reconstruction, or hardware qualification. A machine that must reboot
to install a new kernel satisfies every current usability goal. The roadmap
distinction is:

```text
ordinary release update        = current U1 work (L0 below)
live replacement or evolution  = future availability or research work (L1 to L4)
```

Do not blur the two.

## Why capture this now

ABSD has discussed three increasingly ambitious forms of live evolution:
bounded live patching, live component replacement with draining, state
transfer and fencing, and whole-kernel generation replacement. The direction
was explicitly not to copy Linux livepatch mechanically if ABSD's authority
and lifecycle model permits something cleaner. The strongest idea is:

> Treat replacement as a transition between authority generations: quiesce,
> fence old execution, reconstruct or transfer explicitly permitted state and
> authority, health-check the successor, commit the switch, and retain
> rollback lineage and evidence.

This note keeps that direction without committing to an implementation.

## Maturity order

### L0: staged release replacement (current architecture)

The existing install/update/recovery model: release A remains bootable,
release B is staged independently, compatibility is checked, the machine
boots B, B is accepted only after readiness and health criteria, and rollback
selects A if B fails. This is not live update. It is the baseline every later
live mechanism is judged against.

### L1: live userspace component replacement (P3, evidence-gated)

The first live mechanism worth considering if a real availability
requirement appears:

```text
old service instance
      ↓
stop accepting new work
      ↓
drain and fence existing work
      ↓
capture only explicitly transferable state
      ↓
start successor
      ↓
reconstruct or transfer authority
      ↓
health-check successor
      ↓
commit routing and ownership switch
      ↓
retire old generation
```

Candidate components might eventually include `fsd`, `sshd`, Constellation
services, and other userspace brokers. Do not assume every service is
replaceable. Questions a design must answer: what state is transferable;
what state must instead be reconstructed; which handles and authority may
cross generations; what "drained" means; what happens to in-flight requests;
how stale old-generation authority is fenced; when rollback may occur; and
how evidence identifies the old and new generations.

Two subclasses, by difficulty:

- **L1a, ordinary userspace service replacement:** `sshd`, brokers,
  stateless or reconstructable services.
- **L1b, device- or state-owning service replacement:** `fsd`, or any service
  owning storage, network, or device authority. L1b adds outstanding I/O
  disposition, queued requests, DMA quiescence where applicable, device
  ownership transfer or reset, durable-state synchronization, and hardware
  state reconstruction.

Success replacing an ordinary daemon must not imply that device-owning
services are safely replaceable.

**U1 crash recovery is L1 groundwork.** The served-boot recovery work
(`docs/served-boot-survival/README.md` and its amendments, the repair record
`docs/architecture-audit-20261002/REPAIR.md`) is expected to provide the
semantic foundation for eventual cooperative replacement. An unplanned
restart already forces answers to what state is authoritative, what state is
reconstructed, which authority survives, how stale references are refused,
how old-generation effects are fenced, and what evidence identifies the
transition. Future L1 replacement should reuse those semantics rather than
invent a parallel state-transfer model. This does not promote L1; it
establishes: recovery semantics first, cooperative replacement generalizes
them later.

Promotion trigger: a measured or operational requirement where rebooting the
machine or the whole served boot is materially unacceptable. Until then,
ordinary restart and reboot remain the simpler mechanism.

### L2: bounded kernel live patching (late P3 / early P4)

Do not implement merely because livepatch exists elsewhere. A future bounded
experiment may be justified for narrow fixes whose semantics are unusually
simple, under constraints such as: patch only explicitly marked sites; no
structure-layout, syscall or ABI semantic, object-model, or scheduler-state
changes; no authority migration; no patch while the target code is
executing; explicit old and new code identity; health check and evidence;
rollback only where technically honest.

Before implementation, require stable answers for SMP instruction
synchronization, executable mapping and W^X policy, instruction-cache and
CPU synchronization, stack and unwind interaction, patch-site quiescence,
crash semantics during application, release authenticity, provenance of the
applied patch, and reconstruction of the resulting running generation. The
goal would be narrow, explicit, evidence-producing code replacement, not
arbitrary kernel mutation while running.

**L2 is in tension with the generation principle.** The broader direction
prefers replacing an execution/authority generation over mutating the
internals of the currently authoritative one. Bounded livepatch is therefore
architecturally suspect even where technically feasible. Before L2 is ever
promoted, it must justify itself against the alternative: keep the kernel
small and sufficiently reconstructable that bounded kernel replacement or
handoff is safer and conceptually simpler than in-place patching. It is an
acceptable outcome if L2 is never implemented. The roadmap is not reordered
on this basis; the tension is recorded.

Promotion trigger: a concrete operational or security requirement that
reboot-based replacement fails to satisfy.

### L3: live component graph replacement (P4, intentionally deferred)

Broader than one daemon: replacing a cooperating set of platform components
while preserving selected machine state.

```text
generation A: components + authority + durable state
              ↓
        quiesce and fence
              ↓
    derive transferable state
              ↓
     instantiate generation B
              ↓
        reconstruct authority
              ↓
          health-check
              ↓
      commit ownership switch
```

This should use ABSD's lifecycle and authority machinery rather than invent
an unrelated deployment mechanism. Likely prerequisites: stable application
and platform interfaces, stable service protocols, explicit version
negotiation, release manifests, lifecycle fencing, robust persistent-state
migration, bounded diagnostics, rollback semantics, and mature hardware and
device behavior. Do not design detailed protocol semantics yet.

### L4: whole-kernel generation replacement (deep P4, do not design)

```text
kernel generation A
        ↓
quiesce userspace, devices, CPUs
        ↓
fence generation A from further effects
        ↓
construct generation B
        ↓
reconstruct machine authority and state
        ↓
validate devices, memory, processes
        ↓
health-check generation B
        ↓
commit
        ↓
retain rollback and evidence lineage where possible
```

The intuition worth retaining: a new kernel is a new execution/authority
generation, not arbitrary mutation of the old kernel's internals. Do not
freeze this design. Unsettled prerequisites include SMP execution and CPU
rendezvous, device ownership and reset semantics, DMA, persistent-storage
durability, the release and update format, the application ABI, kernel
object representation, memory ownership, RT placement, hardware
qualification, and what rollback means after state mutation. The promotion
trigger must be exceptionally strong. "Rebooting is inelegant" is not one.

## Principles any live mechanism must preserve

- **Explicit generation identity.** Every replacement identifies the old
  generation, the new generation, the transition attempt, and the accepted
  generation. "What code is this machine running?" never becomes ambiguous.
- **Generation identity reuses release identity.** Do not invent an
  independent identity namespace for live generations. A running generation
  is tied to the same provenance as releases and artifacts: release id,
  artifact hashes, source revisions, the accepted manifest (the platform's
  `docs/RELEASE.md` record and manifest). A transition attempt may have its
  own identity; the code generation itself does not. "What code is running?"
  has one answer across boot updates, recovery, and eventual live
  replacement.
- **Bounded simultaneous generations.** Do not permit unbounded accumulation
  of executable generations. The exact rule is not frozen; a future design
  should strongly prefer a small fixed bound, potentially old and current
  only, over arbitrary lineage staying live. If a newer generation would
  exceed the bound, old execution is first drained, terminated, or the
  transition is refused. (Compare the two-tree bound of the release layout
  and Erlang/OTP's old/current code.)
- **Quiescence before reclamation.** Replacement must not reclaim code,
  state, or authority still capable of producing effects. Reuse the process
  stop, departure, and reclamation discipline: request transition, quiesce,
  prove departure, reconstruct or transfer, retire the old generation.
- **Authority does not transfer implicitly.** A successor does not inherit
  authority because it replaced the old executable. Every transferred or
  reconstructed authority has an explicit rule.
- **State transfer is selective.** Prefer reconstruction from authoritative
  state over copying opaque process or kernel memory. Avoid
  checkpoint/restore by heap dump unless evidence proves it necessary.
- **Health before commit.** A successor demonstrates bounded health and
  readiness before becoming authoritative.
- **Rollback must be honest.** Do not claim rollback once irreversible
  durable-state changes have occurred.
- **Evidence lineage.** Record the source generation, target generation,
  transition reason, transferred and reconstructed state classes, authority
  changes, health result, commit or refusal, and any rollback. This is one
  of the areas where ABSD can be substantially cleaner than conventional
  live-update machinery.

## Relationship to the application interface

The application/platform interface (`docs/application-interface-v0/README.md`
on branch `lane/application-interface-spike-20261002`, when merged) is
designed without requiring live replacement. Once stable it should avoid
gratuitously making later component replacement impossible: explicit service
protocol versions, reconnectable handles where semantically valid, opaque
generation-aware identities, and clean refusal on stale generation
references are useful future properties. Do not add live-update concepts to
the v0 interface without a consumer.

## Relationship to deferred judgments and software lifecycle

[Bounded evaluators](BOUNDED-JUDGMENTS.md) and
[software/package lifecycle](GOVERNED-SOFTWARE-LIFECYCLE.md) preserve these
identity, state and authority constraints. An old judgment or verified
artifact does not grant successor authority. In-flight work and old receipts
need an explicit replacement contract; state uses versioned schemas with
conversion/loss/refusal rules, and independent acceptance precedes retirement.
Neither direction admits L1–L4 work or changes reboot-based U1 update.

## Relationship to graphics

Graphics (`docs/GRAPHICS-DIRECTION.md`) does not depend on live evolution,
and live evolution does not depend on graphics. If both someday exist, a
qualification case might ask whether a compositor and its clients survive a
platform-generation transition. That is not a roadmap dependency. Do not
create one.

## Prior art

When a live-evolution lane is eventually promoted, perform a focused
prior-art review to identify known hazards, not to choose the most familiar
implementation. MINIX-style service replacement and Erlang/OTP hot-code
semantics are the particularly relevant references: reconstructing services
instead of mutating opaque state, generation limits, old/current
coexistence, and failure containment. Linux livepatch, kpatch, kGraft,
Ksplice, microkernel service-restart approaches, and checkpoint/restart
systems are useful contrast, not necessarily the model to copy. ABSD's
lifecycle, authority, and evidence model determines the native mechanism.

## Roadmap placement

```text
NOW                         L0 staged reboot, update, rollback
AFTER U1, IF EARNED         L1 userspace component replacement (L1a before L1b)
ONLY WITH A CONCRETE NEED   L2 bounded kernel live patching
PLATFORM-MATURE FUTURE      L3 component-generation replacement
DO NOT TOUCH                L4 whole-kernel generation replacement
```

The ordering is intentionally conservative and reflects operational risk and
dependency maturity rather than the historical taxonomy, which discussed
bounded patching before component replacement. Userspace replacement is the
cheaper place to learn quiescence, generation, and state-transfer semantics
before attempting kernel mutation.

## Non-goals for current work

Do not add: live kernel patch machinery, executable-memory patch APIs,
checkpoint/restore, process migration, a state-transfer framework, a
generation manager, a deployment controller, a kernel-in-kernel loader,
kexec-like replacement merely to claim live update, or mandatory indirection
in current APIs "for future live replacement". Do not distort current simple
mechanisms to accommodate a hypothetical future feature.
