# ABSD mature-system maturity backlog

The owner-requested 2026-10-06 [system maturity map](SYSTEM-MATURITY-ROADMAP.md)
reconciles these questions with current source/evidence and ABSD Program's
existing items. System R0–R7 is an acceptance lens, not new implementation
admission or a change to these priority classes. It reuses
[Userland U0–U6](USERLAND-COMPONENT-ROADMAP.md) and preserves usability U1/U2.

This note sits beside `docs/USABILITY-ROADMAP.md`. The roadmap answers what
gets ABSD to U1 and U2; this note answers which mature-system questions are
lurking and when work on them is allowed. The standing instruction is
**record and cross-link; open no work from P2, P3, or P4 unless a current
tranche explicitly triggers it.** An item moves class only by an explicit
trigger named in the roadmap or in a gate record.

This document captures mature-OS concerns that ABSD should eventually have an explicit answer for.

It is **not a feature checklist**.

Its purpose is to distinguish:

- semantics that should be decided early,
- mechanisms required for U1/U2,
- questions that should wait for real workload evidence,
- conventional OS features ABSD should deliberately avoid designing until something earns them.

The guiding question is:

> What assumptions do applications and operators make about a mature machine that ABSD has not yet made explicit?

The answer need not match POSIX, Linux, Windows, or another existing system.

ABSD does need an answer.

---

## Priority classes

### P0 — specify now

Write down semantics soon, even if implementation is incomplete.

These choices constrain later storage, security, release, networking, and application-interface work. Deferring the implementation is fine; leaving the contract implicit is not.

### P1 — U1 work

Required or strongly implicated by:

> One operator can leave one supported ABSD machine running for weeks and administer, update, back up, and recover it without routine dependence on the build host.

These should be pulled into the four U1 workstreams (Served-boot lifecycle, Thin administration, Paired update and rollback, Backup/restore/recovery) as their dependencies become reachable.

### P2 — U2 / application-platform maturity

Important once ABSD becomes a stable host for native applications and Constellation, but not necessarily required to get the first machine operationally trustworthy.

### P3 — evidence-gated

Capture the question, but do not select a mechanism until workloads or measurements create a concrete requirement.

### P4 — intentionally deferred

Do not spend design effort yet.

A mature Unix-like OS may contain these mechanisms; that does not mean ABSD requires them.

---

# P0 — specify now

## 1. Clock and time semantics

Define:

- monotonic clock
- realtime/wall clock
- relationship between them
- boot-time RTC interpretation
- timer behavior when wall time changes
- whether wall-clock corrections step or slew
- which clock application deadlines use
- what survives reboot
- timezone responsibility

Likely direction:

- kernel supplies monotonic time
- realtime synchronization is platform/userspace policy
- timezones remain userspace
- monotonic timers never depend on wall-clock corrections

Implementation of DNS/NTP can wait.

The **clock contract should not**.

[Partly decided: `docs/TERMINOLOGY.md` "Time" and "Clock epoch".]

---

## 2. Entropy and cryptographic randomness

Define:

- entropy sources
- boot initialization state
- when cryptographic randomness becomes usable
- whether security-sensitive services refuse to start before initialization
- deterministic testing mechanism
- reseeding policy
- behavior if adequate entropy is unavailable

Required invariant:

> The platform must have an observable distinction between "random-looking bytes" and "cryptographically safe randomness is ready."

SSH alone makes this worth deciding before hardware deployment.

---

## 3. Resource exhaustion doctrine

Generalize the existing fixed-capacity philosophy.

For every bounded resource:

```text
processes
frames
handles
pipes
cells/objects
filesystem objects
TCP/session state
network buffers
queues
service tables
```

define:

- capacity
- reservation/claim point
- refusal result
- whether refusal has side effects
- reclamation point
- operator visibility
- whether one principal/source can monopolize it

Default doctrine:

> Exhaustion causes explicit bounded refusal, not unrelated reclamation, silent corruption, or an implicit OOM policy.

The Served-boot lifecycle workstream exercises this mechanically.

This document should make it systemic.

[Partly decided: `docs/USABILITY-ROADMAP.md` capacity paragraph; audit record `docs/architecture-audit-20261002/README.md` D4 and B6.]

---

## 4. Boot-failure semantics

Define expected behavior when a served boot cannot become served.

Cases include:

- incompatible image/kernel
- missing or malformed filesystem
- device unavailable
- invalid configuration
- unusable SSH host key
- impossible clock state
- service repeatedly fails
- required network interface unavailable

For each class decide whether the system:

- refuses and remains inspectable,
- enters a bounded recovery mode,
- reboots,
- or halts.

Avoid infinite opaque restart loops.

Required property:

> Failure to reach served state produces one durable/observable reason and a deterministic next state.

[Partly decided: `docs/PROCESS-STARTUP.md` "Served boot and orderly shutdown"; audit record C3, D1, and D2.]

---

## 5. Kernel/platform/application version discovery

ABSD should eventually expose explicit versions for:

- kernel ABI
- ABSD application/platform interface
- service protocols
- disk/filesystem format
- kernel/userspace image compatibility
- optional facilities

Applications should not discover compatibility by:

- parsing boot banners,
- probing undocumented syscalls,
- depending on syscall numbering,
- or inspecting implementation artifacts.

This is directly related to the future ABSD application contract.

See the existing [interface specification spike (development record, not in a source release)
in canonical source; SPECIFY_NEXT remains a planning recommendation, not an
accepted stable interface.]

---

## 6. Machine identity

Define which identity belongs to an installed machine.

Potential components:

- SSH host key
- machine identifier
- hostname
- Constellation identity
- installation identity

Explicitly define image cloning behavior.

Questions:

- What must regenerate when an installation is cloned?
- What remains part of the copied filesystem?
- Which identity is security-sensitive?
- Which identity may applications rely on?

Do not let "copy disk image" accidentally mean "duplicate machine identity."

---

## 7. Durability vocabulary

Before specifying exact filesystem implementation, define words such as:

```text
written
committed
durable
flushed
atomically replaced
recoverable after crash
```

Do not use these interchangeably.

This becomes mandatory once NVMe write qualification begins.

[Partly decided: `docs/TERMINOLOGY.md` "Storage" and "Failure and result language".]

---

## 8. Security-support claim

Maintain a short explicit statement of which security properties ABSD attempts to enforce.

Include existing mechanisms and assumptions such as:

- userspace/kernel isolation
- NX / CR0.WP
- user-copy validation
- authority/handle checks
- publish-after-build
- lifecycle fencing
- resource ownership
- executable mappings
- DMA assumptions
- current stack/fault protections

Also list things not currently claimed.

Do not accumulate mitigations merely because Linux has them.

The value is knowing what the security boundary actually is.

[Partly decided: `HANDOFF.md` "Canonical verification" (CR0.WP, interrupt gates) and `docs/HOSTILE-USERSPACE.md`.]

---

# P1 — U1 path

## 9. Power-loss and filesystem crash consistency

Once persistent writes move onto real storage, define and qualify:

- write ordering
- metadata/data ordering
- flush semantics
- controller cache semantics
- interrupted writes
- interrupted metadata updates
- recovery after machine reset/power loss
- atomic replacement
- filesystem consistency guarantees

Questions should include:

> If the machine dies immediately after operation X reports success, what is guaranteed after restart?

This is likely one of the largest remaining maturity cliffs.

Do not silently inherit POSIX `fsync()` semantics.

Define ABSD's own guarantees.

---

## 10. Filesystem semantic contract

Beyond basic reads/writes, eventually define:

- create
- exclusive create
- replace
- rename
- truncate
- append
- deletion
- open-object deletion semantics
- directory enumeration
- path and component limits
- case sensitivity
- path normalization
- timestamps
- malformed names
- crash behavior

`mtime` belongs here but is only one field.

Implement only what real applications require, but document the behavior of everything that exists.

---

## 11. Device timeout / failure / reset behavior

Qualification must eventually test hardware failure, not merely success.

Per supported device class define:

- command timeout
- reset
- link loss
- malformed completion
- outstanding request disposition
- recovery
- permanent failure
- resulting service behavior

Examples:

```text
NVMe command never completes
NIC stops transmitting
link disappears
controller reset succeeds
controller reset fails
```

A supported driver should eventually mean:

> The platform has defined behavior when the device misbehaves.

---

## 12. Postmortem process diagnostics

Provide a bounded answer to:

> Why did this process die?

Useful information may include:

- process identity
- executable/image identity
- exit/fault reason
- instruction pointer
- fault address
- register subset
- relevant authority/resource context
- parent/sponsor relationship if later present
- kernel-originated termination reason

Avoid a general core-dump system unless earned.

The immediate target is typed failure evidence rather than parsing console text.

---

## 13. Bounded logging

Define:

- storage capacity
- retention policy
- behavior when logs fill
- rotation/discard semantics
- whether critical records receive reserved capacity
- crash-safe append requirements
- attacker-controlled amplification limits

Required property:

> Logging an error cannot itself exhaust the machine indefinitely.

---

## 14. Administrative atomicity

For operator modifications such as:

- configuration
- SSH keys
- service limits
- application deployment
- policy files

prefer:

```text
write new
    ↓
validate
    ↓
atomic replace
```

rather than mutation in place.

Define failure behavior if power is lost at each step.

This belongs naturally in the Backup, restore, recovery workstream.

---

## 15. Recovery mode

Eventually provide one deliberately small degraded operational state.

Possible purpose:

- inspect storage
- repair/replace configuration
- install/roll back a release
- inspect failure records
- restore from backup

It should not become a second general-purpose OS environment.

Desired property:

> A broken served boot does not automatically require attaching Linux to repair ABSD.

Exact mechanism should wait until the Paired update and rollback workstream shows which recovery operations are actually needed.

---

## 16. Networking operational semantics

Beyond successful connections, define:

- connect timeout
- idle timeout
- retry policy
- listen/backlog exhaustion
- half-open connection lifetime
- close semantics
- reset behavior
- MTU assumptions
- network-interface disappearance
- address changes
- DNS timeout/failure semantics when DNS arrives
- keepalive behavior if supported

Do not emulate BSD sockets merely to acquire these semantics.

This is an operational contract over the existing networking architecture.

---

## 17. Release authenticity / update trust

The Paired update and rollback workstream must eventually answer:

- what constitutes an authentic ABSD release
- whether artifacts are signed
- what verifies them
- how corruption is detected
- rollback policy
- whether rollback attacks matter in the current threat model
- which artifacts form one compatible release set

Secure Boot is not automatically required.

A defined trust chain eventually is.

---

# P2 — U2 / application-platform maturity

## 18. Stable ABSD application/platform interface

Create a stable userspace-facing contract analogous in purpose, not semantics, to POSIX.

Candidate areas:

- process creation
- lifecycle/wait
- storage
- channels/pipes
- clocks/timers
- networking
- configuration
- introspection
- errors/refusals
- resource discovery
- authority transfer

Prefer:

```text
applications
      ↓
stable ABSD platform library/API
      ↓
service protocols + narrow kernel ABI
      ↓
kernel
```

Do not expose kernel implementation details merely because they already exist.

A spec-only design spike may happen earlier.

See the existing [interface specification spike (development record, not in a source release)
in canonical source; SPECIFY_NEXT remains a planning recommendation, not an
accepted stable interface.]

Implementation should follow stable U1 semantics.

---

## 19. Typed application resource model

Evaluate whether application-facing APIs should distinguish:

```text
ProcessHandle
FileHandle
PipeReader
PipeWriter
NetworkConnection
CellHandle
...
```

even if the low-level ABI internally uses compact numeric handle slots.

Do not recreate Unix's "all integers are file descriptors" assumption without need.

---

## 20. Compatibility policy

Once a stable application contract exists, define:

- major/minor version meaning
- binary compatibility expectations
- service protocol compatibility
- unknown field behavior
- feature negotiation
- deprecation
- minimum supported versions
- refusal behavior for incompatible applications

Do not commit to long compatibility windows until an actual release exists.

But once compatibility is promised, make it explicit.

---

## 21. Encoding / text conventions

Likely choose UTF-8 and keep the rules simple.

Eventually specify representation for:

- filenames
- config
- argv-like argument data
- environment-like data if such a concept exists
- console text
- protocol-visible strings

Define invalid UTF-8 behavior and normalization policy.

Default candidate:

> UTF-8 required; no implicit Unicode normalization.

Wait for the application API before freezing all details.

---

## 22. Typed introspection

Expand only where real operator/application questions require it.

Possible stable queries:

- process identities/state
- exit reasons
- resource limits/current usage
- boot identity/version
- service health
- device qualification/status

Do not build `/proc`.

Do not make text console logs the machine interface.

---

# P3 — evidence-gated questions

These should remain visible but should not select architecture yet.

## 23. ASLR and additional exploit mitigations

Evaluate only after:

- memory layout stabilizes,
- application ABI stabilizes,
- threat model identifies the value.

Do not implement as maturity theater.

---

## 24. More sophisticated scheduler topology

Includes:

- per-CPU run queues
- migration
- load balancing
- RT placement
- CPU affinity

Current rule remains:

> Further SMP execution is earned by KVM/native measurement.

---

## 25. Governed RT admission

Already parked.

Resume after:

- SMP placement semantics are settled,
- a workload needs bounded RT execution,
- application/platform boundary is clearer.

Do not expand RT merely because the scheduler supports it.

---

## 26. Sponsorship/resource-accounting hierarchy

Run E2 first.

Only introduce sponsor/job/space-bank-like machinery if measured residue or operational limits require it.

Keep the question captured because it may eventually become central to unattended lifecycle management.

---

## 27. Dynamic allocation / flexible table sizing

Keep fixed tables until actual capacity measurements make them harmful.

Possible future mechanisms should be selected from evidence, not an assumption that "mature OSes allocate dynamically."

---

## 28. General service-management mechanism

Do not design until served-boot operation demonstrates multiple independently restartable units with genuinely distinct lifecycle requirements.

Current default:

> The served boot remains the recovery unit.

---

## 29. Live userspace component replacement

Captured in `docs/LIVE-EVOLUTION.md` as L1 (L1a ordinary services, L1b
device- or state-owning services), with bounded kernel live patching as L2
(late P3 / early P4). Ordinary release update stays the reboot-based L0 of
the Paired update and rollback workstream; served-boot recovery semantics are
the groundwork L1 would generalize. Promotion needs a measured requirement
where rebooting the machine or the served boot is materially unacceptable.

---

# P4 — intentionally deferred until the platform is much more settled

Do not design these merely to fill perceived gaps against Linux/POSIX.

- Linux binary compatibility
- general POSIX compatibility layer
- `fork()`
- native signals
- pthreads / general threads
- dynamic ELF/shared libraries
- conventional libc beyond actual porting needs
- users/groups / general multi-principal model
- package manager (semantic direction captured in
  [governed software lifecycle](GOVERNED-SOFTWARE-LIFECYCLE.md); deferred)
- general service manager
- kernel socket API
- `/proc`
- swap
- memory overcommit
- OOM killer
- containers/namespaces
- NUMA
- CPU hotplug
- device hotplug
- suspend/resume
- broad ACPI support
- generic USB stack
- Wi-Fi
- Bluetooth
- graphics/windowing (direction captured in `docs/GRAPHICS-DIRECTION.md`; deferred)
- audio
- arbitrary hardware-family support
- on-target compiler/toolchain
- live kernel update and whole-kernel generation replacement (direction
  captured in `docs/LIVE-EVOLUTION.md` as L3 and L4; deferred)

Any item may move upward if a concrete U1/U2 requirement names it.

Until then:

> Absence is not technical debt.

The graphics and live-evolution notes record directions, not plans.
The [bounded judgments](BOUNDED-JUDGMENTS.md) and
[software lifecycle](GOVERNED-SOFTWARE-LIFECYCLE.md) notes likewise capture
future constraints without selecting mechanisms, adding milestones or becoming
U1/U2 blockers. Judgment is evidence, never authority.

---

# Suggested execution order

The maturity backlog should not become another giant campaign.

Near-term sequence:

```text
current served-boot survival work
        ↓
P0 semantic notes where dependencies appear
        ↓
KVM + exact hardware qualification
        ↓
storage durability / device failure semantics
        ↓
install / update / rollback / recovery
        ↓
bounded logging + diagnostics + admin atomicity
        ↓
U1
        ↓
stable ABSD application/platform contract
        ↓
native Constellation workload
        ↓
U2
```

Work in P3 moves forward only after an explicit trigger.

Work in P4 does not move forward merely because another mature OS has it.

---

# Immediate triage

Capture now, with no large implementation campaign:

```text
P0:
clock contract
entropy/RNG contract
resource-exhaustion doctrine
boot-failure semantics
version/feature discovery
machine identity
durability vocabulary
security claim
```

Pull directly into ongoing U1 tranches when reachable:

```text
P1:
power-loss consistency
filesystem semantics
device failure/reset
postmortem diagnostics
bounded logging
administrative atomicity
recovery mode
network operational semantics
release authenticity
```

Spec after U1 begins stabilizing:

```text
P2:
ABSD application contract
typed application handles
compatibility policy
encoding conventions
typed introspection
```

Evidence-gated:

```text
P3:
ASLR
advanced SMP
governed RT
sponsorship
dynamic allocation
service manager
live userspace component replacement
```

Leave alone until the platform has changed substantially:

```text
P4:
POSIX/Linux personality work
threads
signals
packages
multi-user
dynamic linking
general ACPI/USB/hotplug
swap/overcommit
containers
graphics
broad hardware support
live kernel replacement
```

The purpose of capturing this list is not to make ABSD resemble a mature Unix.

It is to ensure that when ABSD deliberately differs from mature systems, the difference is **chosen, documented, and tested rather than merely absent**.
