# Design influences

These are implementation notes, not a roadmap, compatibility promise, or
mandate to reproduce another operating system. ABSD should adopt a pattern
only when a concrete workload exposes the problem it solves, the smallest
experiment fits the existing object model, and executable tests can state the
new invariant. Names from source systems are attribution here, not proposed
kernel vocabulary.

The [ownership boundaries](OWNERSHIP-BOUNDARIES.md) record the target
Native/Adapted/Commodity split, adapter cost brake, restart claims and
substrate assumptions. Own semantics before implementations; reuse a
component when a bounded adapter can enforce the native invariant. This is
a constraint on choices, not a new implementation sequence. smoltcp is
current bootstrap machinery, not the specification of ABSD networking.

## Guardrails for using these notes

Apply the [economical-with-danger principle](OWNERSHIP-BOUNDARIES.md#economical-with-danger)
when choosing mechanisms and safeguards: spend rigor where uncertainty and
consequence justify it, count complexity and attention costs, and preserve the
actual invariant. Ceremony is not evidence; this does not waive the guardrails
or current qualification gates.

- **G1 — Justified authority:** Protected operations and transfers require
  explicit authority. Parentage, naming, restart responsibility, and
  convenience do not create it; delegation does not imply universal
  revocation.
- **G2 — Accountable resource commitments:** Every retained commitment needs
  an accountable sponsor and reclamation story, without inventing fictional
  exclusive ownership. ABSD has no generalized sponsorship model yet.
- **G3 — Admission versus best effort:** A guarantee is distinct from an
  optimistic request. Admission, overload, refusal, timeout, and degradation
  must be explicit; no reservation system exists yet.
- **G4 — Failure and recovery contracts:** Restart is not recovery. State what
  died, survived, noticed, reconstructs state, supplies replacement authority,
  happens to in-flight work, and triggers escalation. Do not claim universal
  restartability.
- **G5 — Mutable-state consistency:** Choose an explicit consistency story per
  object: ownership, locking, versioning, replication, or message ownership.
  Versioned cells are the current bounded experiment, not a universal answer.
- **G6 — Explicit durability:** Distinguish not committed, committed generation
  G, and indeterminate outcomes. This note does not propose a storage design.
- **G7 — Bounded and authorized evidence:** Important transitions should
  eventually be inspectable, while evidence collection remains authorized and
  bounded in resource use and sensitivity. Do not assume universal tracing.
- **G8 — Justified trust boundaries:** Placement, separation, IPC, or shared
  memory must earn their cost through concrete containment, enforcement,
  restartability, isolation, performance, or verification benefit—not
  doctrine.
- **G9 — Native semantic integrity:** Compatibility personalities may
  translate ABSD semantics but must not silently weaken them. Do not force a
  Unix model onto native objects.
- **G10 — Mechanism and policy stay separate:** The classic separation of
  mechanism from policy, with information hiding, applied to every boundary:
  a kernel mechanism knows only what implementing it requires, and
  higher-level interpretations stay with the layer that owns them, even when
  kernel objects could represent them. Review question: why does this layer
  know that? Examples: handles with rights in the kernel, while integer fds
  would be a userspace personality table over them; native processes (PID,
  parent, wait, outcome) without fork, signals, or process groups; a block
  device by sector, while files and directories live in the userspace
  filesystem; the spawn right in the kernel, while which programs a worker
  may start is init's broker policy.
- **G11 — No sacred abstractions:** Historical OS abstractions are
  contingent. Keep each abstraction narrow enough that it stays
  semantically true: a file is a file, a process a process, an observation
  an observation, a command a command, an event an event, and authority is
  modeled as authority, never inferred from an unrelated mechanism. Shared
  machinery underneath (handles, object identities, typed messages,
  namespaces, rights checks) is fine; making fundamentally different things
  masquerade as one another because an old interface found it convenient is
  not. This is not a "go full Plan 9" rule: no single universal model is
  forced on everything. Layering runs one way: ABSD semantics, then a stable
  native interface, then native tools and services, then compatibility
  adapters; POSIX, procfs, or ioctl-style interfaces never define the
  internal architecture (G9 keeps the adapters from weakening what they
  translate). Review question for any inherited Unix mechanism: does the
  abstraction still accurately represent what it controls or observes? If
  not, prefer a native primitive plus a compatibility adapter over
  extending the historical fiction. A design constraint, not a refactor
  mandate: existing interfaces change when work touches them.

Parentage, authority, resource sponsorship, supervision, dependency, durable
reachability, and mutable ownership are separate graphs. Some edges coincide
in today's small system, but no future design may infer one from another: for
example, adopting an orphan does not itself grant its handles, fund its
resources, supervise its restart, or own its durable state.

### Research tripwires

- **Revocation/recovery promise:** Before serious revocable or durable
  authority, test the promise across transfer, in-flight operations,
  replacement, recovery, and rollback.
- **Actual-memory sponsorship:** Before caches, aggregate quotas, job budgets,
  or shared retained state, charge and reclaim actual backing memory through
  the proposed sponsor path rather than a parallel counter.
- **Durability crash test:** Before storage commitments, define explicit
  commit outcomes and crash-test a small persistent object representation so
  committed generations are distinguishable from indeterminate writes.
- Supervisor-owned reserve exhaustion -> `budget_compliance_does_not_imply_viability`, `preserves_required_reserve_implies_viable`, `visible_green_does_not_imply_recovery_margin` -> what must remain for mandatory post-run obligations?
- First consumer surviving service replacement -> `freshSigned_but_stale_epoch`, `fresh_signed_artifact_does_not_imply_live_epoch` -> how is the current service generation fenced?
- Proposal for cascading kernel revocation -> `naive_reachability_cascade_overreaches`, `support_sensitive_cascade_preserves_independent_support`, `ancestor_live_keeps_smaller_mutation_footprint` -> exact or support-sensitive revocation?
- Second non-delegable object/handle case -> `possession_does_not_authorize_delegation`, `possession_alone_does_not_enable_subdelegation`, `use_does_not_imply_grant` -> must use and delegation become separate rights?
- First restricted/non-ambient spawn target -> `permission_without_sufficient_authority`, `emergency_need_does_not_create_root`, `necessity_does_not_mint_issuance` -> what authority names actor, program, and action?
- First invariant spanning multiple kernel objects -> `exact_local_warrants_do_not_force_global_realizability`, `resource_establishment_validity_is_state_relative` -> one state object or an explicit protocol?
- Second live writer invalidating occurrence attribution -> `no_present_state_derived_record_recovers_occurrence`, `present_state_settlement_does_not_upgrade_historical_claims`, `matching_state_does_not_mint_native_occurrence` -> how is occurrence distinguished from current state?
- First genuinely indeterminate durable operation -> `unresolved_step_cannot_produce_receipt`, `recovery_receipt_is_not_direct`, `fabricated_success_after_ambiguity_is_refused` -> how is an unresolved then reconciled result represented?
- SMP or preemptible-kernel work -> `locally_bridged_branches_can_merge_with_stale_evidence`, `consumed_prefix_invalidates_exact_pair_certificate` -> how are check-then-claim decisions made atomic and current? Revalidate the single-core termination fence, in-flight syscalls, handle draining, and parent notification.
- Supervisor replacement or explicit handoff -> `restart_with_pending_successor_does_not_complete_it`, `proposed_successor_cannot_self_complete`, `completed_transition_without_custody_has_no_local_capability` -> how does handoff complete with exactly one holder?

## Maintenance and evolution constraints

These are project-maintenance constraints, separate from the runtime
architectural guardrails above. Do not turn them into kernel objects or
syscall policy: maintainability is not a kernel object.

The central rule is to acquire continuing obligations more slowly than
implementation capability: **cheap exploration, expensive acceptance**. A
passing implementation is not by itself a permanent architecture, interface,
hardware promise, compatibility promise, durable format, or dependency.

- **M1 — Name support boundaries:** A support claim names its scope or
  consumer, supporting evidence, applicable version and environment, and who
  is responsible for it. Code existing does not make it supported. Small
  experiments need not carry this declaration until someone proposes support.
- **M2 — Freeze only real boundaries:** Version relationships belong where
  components evolve or deploy independently, cross an external boundary, or
  store durable data. Internals rebuilt together need not become stable
  protocols.
- **M3 — Preserve reconstruction evidence:** A named release or important
  failure must be reconstructible without the original agent session from the
  required source, build inputs, configuration, durable migration material,
  and diagnostics. Preserve operationally necessary evidence, not every
  development transcript.
- **M4 — Explain external fork deltas:** A carried fork records its base, why
  the delta exists, how it is validated, its update strategy, and the
  condition for removal. Forks are not forbidden; unexplained forks are not
  maintainable.
- **M5 — Keep retirement possible:** Once persistence or upgrades exist, an
  obsolete mechanism needs a path to migrate users and retire. This does not
  justify migration infrastructure today.
- **M6 — Tie declarations to evidence:** An experiment is not support,
  implementation is not qualification, and declared recovery is not
  demonstrated recovery. Keep those distinctions connected to executable or
  operational evidence without building status bureaucracy.

Compatibility owns translation of foreign state and policy; native ABSD
enforcement remains authoritative. Any downward concession is explicit and
justified. Foreign pressure may reveal a coherent native primitive, but a
foreign ABI is not the native specification.

Estimate maintenance cost by propagation and fan-out, not lines of code. Ask:
how many independently changing callers, stored representations, platforms,
tests, recovery paths, and external projects must change together? These are
design questions, not a request for a metrics system.

A demonstration proves one run, not a supported lifecycle. A hardware support
envelope identifies which initialization, ordinary operation, error/timeout,
reset/recovery, removal, and shutdown conditions are covered, along with the
exact build and platform/firmware assumptions. QEMU is the development lab;
claims about real hardware require repeatable real-hardware evidence.

AI-assisted work must avoid oracle capture: important tests should use
independent contracts, adversarial checks, reference behavior, or
property/fuzz evidence where appropriate rather than all deriving from the
implementation under test. Before accepting an abstraction, apply a
second-use or change test so one successful example does not create excess
framework. Record short negative knowledge only when rediscovery is costly.
Acceptance is scarcer than implementation capacity, so compare alternatives
and delete rejected experiments when their evidence is no longer needed.

### Maintenance tripwires

Do not run these projects now; each is a gate for a future support promise.

- **Compatibility pressure:** Before a broad Unix or Linux binary promise,
  test real compatibility pressure while keeping foreign policy in the
  compatibility layer and native enforcement explicit.
- **Upgrade, rollback, and deletion:** Before declaring a persistent format or
  independently evolving interface stable, demonstrate upgrade and rollback
  and show that the predecessor can actually be retired.
- **Physical-platform lifecycle:** Before naming a first supported machine,
  demonstrate an exact build, repeatable install/boot, console access,
  reset/recovery, and reproducible diagnosis of failures on that hardware.

Minimum viable civilization permits reuse of surrounding toolchains,
bootloaders, libraries, and applications. Reuse creates adapter and update
responsibility, not a duty to reimplement everything. Be especially cautious
about owning browser engines, divergent compilers or languages, cryptography,
large patched application sets, or universal persistent execution. Agents
being able to build something is not a reason to accept its maintenance cost.

**Hard gate:** Do not expand the support promise when the current supported
release cannot be reconstructed, diagnosed, or recovered under its declared
conditions.

## Typed conditions and recovery

- **Pattern:** Separate a typed failure from the policy that chooses retry,
  fallback, or termination.
- **Source system:** VMS/OpenVMS condition handling; Common Lisp conditions
  and restarts are a secondary comparison.
- **Problem it solved there:** Let lower layers report precise failures while
  callers select recovery without hard-wiring it into the failing routine.
- **Possible ABSD use:** Typed userspace error records or restart choices for a
  service protocol; kernel syscall errors should remain small and mechanical.
- **Why it fits / may not fit:** It supports explicit failure handling, but a
  general condition runtime would be disproportionate in the kernel.
- **Trigger to revisit:** Two real userspace services need different recovery
  policies for the same structured failure.
- **Status:** Reference note; not adopted.

## Quotas and jobs

- **Pattern:** Group processes and charge bounded resources to the group.
- **Source system:** OpenVMS quotas and process/job control; Windows NT job
  objects and Unix resource limits.
- **Problem it solved there:** Contain a process tree's CPU, memory, process,
  and lifetime consumption as one administrative unit.
- **Possible ABSD use:** A handle-mediated job carrying process, frame, handle,
  or object limits, with explicit membership and teardown.
- **Why it fits / may not fit:** It matches bounded tables and explicit
  ownership; it is premature until one workload needs accounting across more
  than a parent-child relationship.
- **Trigger to revisit:** A shell or service manager must contain several
  cooperating processes under one enforceable budget.
- **Status:** Reference note; not adopted.

## Handles and access masks

- **Pattern:** Name kernel objects with process-local opaque handles whose
  access masks are checked on each operation and may be narrowed.
- **Source system:** Windows NT object handles and access masks.
- **Problem it solved there:** Decouple object identity and lifetime from user
  addresses while making granted authority explicit.
- **Possible ABSD use:** Continue refining copy/move transfer, lifecycle, and
  object-specific rights only as existing syscalls require them.
- **Why it fits / may not fit:** ABSD already has opaque handles and narrowing;
  NT's large generic access machinery would add policy without current value.
- **Trigger to revisit:** A new object exposes an operation that current
  read/write/wait rights cannot distinguish safely.
- **Status:** Partially present; extend through executable needs only.

## Capability delegation

- **Pattern:** Delegate only an explicit object reference and a bounded subset
  of its authority, without ambient lookup.
- **Source system:** KeyKOS, EROS, and CapROS capability systems; seL4's
  capability model.
- **Problem it solved there:** Make authority flow inspectable and support
  strong isolation by construction.
- **Possible ABSD use:** Strengthen spawn transfer and service bootstrap so a
  child receives exactly the objects it needs.
- **Why it fits / may not fit:** It aligns with ABSD's handle direction, but a
  formal capability algebra or universal object graph is unnecessary now.
- **Trigger to revisit:** Ambient process privileges appear, or delegation
  cannot be expressed as a narrowed handle transfer.
- **Status:** Directional influence; no formal capability model adopted.
  Ending the machine was the last authority gated on the boot mode rather
  than held: it is now a machine handle init holds and copies narrowly
  (docs/PROCESS-STARTUP.md, "Machine authority").

### Handle-model scaling tripwires

These current-head triggers preserve the existing small model; they do not
authorize the deferred mechanisms they name. Their source audit is preserved
in the development record `absd-handle-model-review.md` (pinned to `e551ea8`); revalidate
its premises against current source whenever a trigger fires.

- **W1 — Kind lookup:** Seven live `Object` variants exist now (`Console`,
  `Process`, `Cell`, `Pipe`, `Block`, `Nic`, `Machine`; `None` is empty). Before
  an eighth, or an object-specific syscall accepting three or more kinds,
  remeasure the need for one kind-aware lookup seam instead of adding ad hoc
  resolver branches. `src/handle.rs` has an exhaustive seven-kind test that
  requires a deliberate update when the enum grows. U1 adds no eighth kind
  and no sponsor: first measure E2 orphan residue, cleanup outcomes, and
  returned capacity, then decide whether a new seam is justified.
- **W2 — Blocking representation:** Third blockable object kind, or first
  multi-object wait -> reconsider the process's per-kind wait fields and
  whole-process-table wake scans.
- **W3 — Rights vocabulary:** First operation that cannot honestly be named
  read, write, wait, or kill -> widen rights with per-kind meanings and masks,
  without generic-access mappings.
- **W4 — Delegation policy:** Second non-delegable kind, or first kind that may
  transfer but not duplicate -> use the existing “second non-delegable
  object” research tripwire to decide whether use and delegation need
  separate rights.
- **W5 — Resource liability:** First kernel heap or object backed by dynamic
  memory rather than a fixed table -> use the actual-memory sponsorship
  tripwire to decide who is charged and what happens when that sponsor dies.
- **W6 — Kernel liveness policy:** Second well-authorized spawn configuration
  refused only to prevent a likely userspace deadlock -> reconsider whether
  such policy belongs in userspace spawn wrappers.
- **W7 — Post-spawn delegation:** Real running service needs a replacement to
  receive an endpoint after startup while preserving honest pipe EOF -> use
  the existing pipe-endpoint handoff tripwire; do not transfer process
  handles as a shortcut.
- **W8 — Process observation lifetime:** Non-parent must observe or stop a
  process after its parent may reap it -> reconsider parent-local process
  handles, record lifetime, and `has_child` checks together; compare pidfds
  then.
- **W9 — Program identity:** The first foreign-built ELF substitution has
  fired this trigger narrowly by replacing the existing multi-start
  `external-workload` image. Before a second external workload or entry
  convention, make entry ABI explicit per catalog image and converge spawn on
  one startup-vector contract; do not add another index special case.
- **W10 — Atomicity:** First SMP or preemptible-kernel work -> apply the
  existing SMP tripwire first to handle check-then-act paths, termination
  drain, wakeups, and spawn publication.

#### First-SMP audit gate

At that trigger, revalidate the audit preserved at
the development record `absd-smp-assumption-inventory.md` (pinned to `e551ea8`) against
then-current HEAD. Begin with a non-preemptible kernel, one task per process,
and one global kernel lock that preserves today's serialized entries; do not
scatter subsystem locks in advance. No application processor may run
userspace until `current`, entry/report/double-fault stacks, TSS state, fault
state, and FPU scratch are per-CPU. Replace the outgoing-kernel-stack context
switch before CPU1 can schedule, and require a stop/quiescence fence before
termination reclaims a victim. A terminal `wait` must remain a total fence:
the instance is stopped and its process resources and handles are drained
before the outcome is observable.

## Event and message IPC

- **Pattern:** Exchange bounded messages or event notifications instead of
  sharing implementation state.
- **Source system:** OpenVMS mailboxes and event flags; OS/2 queues and named
  pipes; Mach ports and QNX channels.
- **Problem it solved there:** Provide explicit communication, wakeup, and
  service boundaries across protection domains.
- **Possible ABSD use:** Add a bounded message or event object if pipes and
  versioned cells cannot express a concrete request/reply or readiness case.
- **Why it fits / may not fit:** Handle-mediated endpoints fit naturally;
  port sets, routing layers, and out-of-line payload machinery do not yet.
- **Trigger to revisit:** A real service needs atomic message boundaries or to
  wait on several heterogeneous events.
- **Status:** Reference note; pipes and cells remain sufficient today.

## Bring-up console authority

- **Pattern:** Treat the current serial console as explicit bring-up ambient
  authority rather than pretending it has mature object identity or lifetime.
- **Source system:** ABSD's single global COM1 development console.
- **Problem it solved there:** Every early process needs deterministic
  diagnostics before device discovery or console policy exists.
- **Possible ABSD use:** Keep the current inherited console convention while
  there is exactly one development endpoint.
- **Why it fits / may not fit:** The handle checks still bound operations, but
  all console handles name the same immortal endpoint; that is not meaningful
  delegation among devices.
- **Trigger to revisit:** Multiple consoles/devices or a real console
  delegation/lifetime requirement.
- **Status:** Intentional bring-up exception; do not redesign yet.

## Task and thread split

- **Pattern:** Separate an address-space/resource container from schedulable
  execution contexts.
- **Source system:** OS/2 processes and threads; Mach tasks and threads.
- **Problem it solved there:** Allow multiple execution contexts to share one
  protection domain and resource set.
- **Possible ABSD use:** Split the current process only if userspace needs
  multiple threads sharing handles and virtual memory.
- **Why it fits / may not fit:** The distinction is coherent, but it would
  complicate exit, fault, wait, and teardown semantics throughout the kernel.
- **Trigger to revisit:** A demonstrated workload cannot be structured as
  communicating processes without unacceptable duplication or latency.
- **Status:** Deferred; one task per process is intentional.

## DragonFlyBSD

DragonFlyBSD is evidence that explicit ownership, locality, and
message-oriented coordination do not require a microkernel boundary.

### CPU-local ownership and in-kernel messaging

- **Pattern:** Assign mutable kernel work and state to CPUs and use lightweight
  messages across ownership boundaries instead of defaulting every shared
  structure to a heavily locked global object.
- **Possible ABSD use:** Compare shared locking, per-CPU ownership and
  messaging, immutable/versioned read-mostly state, and isolated-service
  boundaries during the first serious SMP design. Keep “who owns this state?”
  separate from “which privilege domain contains this code?”
- **Trigger to revisit:** First serious ABSD SMP design work.
- **Tripwire:** The current no-stale-instance and synchronous-termination
  properties depend on one core. SMP or kernel preemption reopens termination
  fencing, in-flight syscalls, handle draining, notification ordering, and
  replacement semantics. Do not preselect one kernel-wide SMP ideology.
- **Status:** Note; future experiment only.

### Hosted-kernel development

- **Pattern:** DragonFly's vkernel runs a real kernel as a host process for
  faster, debugger-friendly testing and fault injection.
- **Possible ABSD use:** Accelerate scheduler, process, object, SMP, storage,
  and high-volume fuzz work while retaining QEMU, reference-machine tests, and
  eventual physical-hardware qualification.
- **Trigger to revisit:** QEMU iteration cost materially slows development,
  especially for SMP, storage, or high-volume fuzzing.
- **Tripwire:** A hosted mode is another maintained instrument; do not build it
  merely because it is elegant.
- **Status:** Note.

### HAMMER and HAMMER2

- **Pattern:** Explicit generations, snapshots and historical views,
  copy-on-write recovery, and inspectable committed state.
- **Possible ABSD use:** Input to future durability-domain and storage
  experiments, including the retention and reclamation costs of history.
- **Trigger to revisit:** Before committing to native persistent-storage
  semantics.
- **Status:** Note; neither filesystem is presumed to be ABSD's model.

## OpenBSD

OpenBSD is useful here primarily for security defaults and explicit authority
reduction, not as a foreign syscall or credential model.

### Process authority reduction

- **Pattern:** A process voluntarily and monotonically narrows the classes of
  operations it may perform after initialization, as in `pledge`.
- **Problem it solved there:** Make discarded privilege enforceable rather
  than relying on later code not to use it.
- **Possible ABSD use:** Process-level authority reduction after the object and
  syscall surface has a concrete consumer for it.
- **Why it fits / may not fit:** Monotonic reduction matches ABSD's direction,
  but per-handle narrowing may already solve the real problem. Do not copy
  promise strings or Unix syscall classes, or add an overlapping authority
  system without evidence.
- **Trigger to revisit:** ABSD has enough object/syscall breadth for a real
  post-initialization authority-reduction workload.
- **Status:** Note.

### Namespace restriction

- **Pattern:** Explicitly constrain which named resources remain resolvable,
  as in `unveil`.
- **Possible ABSD use:** A native or compatibility namespace with ambient
  resolution may eventually need a bounded process view.
- **Why it fits / may not fit:** There is currently no meaningful namespace to
  restrict; inventing the restriction first would create policy without a
  consumer.
- **Trigger to revisit:** First real native or compatibility namespace with
  ambient resolution.
- **Status:** Note.

### Secure defaults

- **Pattern:** Conservative memory permissions, W^X-style rules, exploit
  mitigation, and reduced ambient privilege are ordinary defaults rather than
  an optional hardening profile.
- **Possible ABSD use:** Apply that posture as corresponding VM, loader, and
  authority mechanisms become real.
- **Trigger to revisit:** Each concrete mechanism exists and has an executable
  enforcement boundary.
- **Status:** Engineering posture; no promise to copy exact mitigations.

## Qubes OS

### Visible authority and isolation boundaries

- **Pattern:** Domain identity remains perceptible in ordinary operation;
  [window labels and colors](https://www.qubes-os.org/doc/getting-started/)
  help the operator identify the qube in use.
- **Possible ABSD use:** Present bounded execution identity, grants, borrowed
  services and retirement state from the owning facts through CLI and eventual
  graphical interfaces. [Legibility must be architecturally earned](OWNERSHIP-BOUNDARIES.md#legibility-must-be-architecturally-earned).
- **Trigger to revisit:** First define the operator-facing authority/isolation
  story and concrete scenarios; then identify missing enforceable contracts.
- **Status:** Design reference for visibility, not adopted architecture. No
  Qubes clone, hypervisor, GUI, workspace framework or U1/U2 dependency follows.

## NetBSD

NetBSD is especially relevant to testable subsystem structure and containment
of hardware variation.

### Rump kernels and anykernel interfaces

- **Pattern:** Run kernel-quality subsystems independently of a complete
  kernel through narrow host-independent interfaces.
- **Problem it solved there:** Filesystems, networking, and other state
  machines can be tested, fuzzed, and reused without full-system boot cost.
- **Possible ABSD use:** Hosted filesystem/network development, subsystem
  fuzzing, high-volume state-machine tests, and faster CI experiments.
- **Why it fits / may not fit:** Unlike DragonFly's whole hosted vkernel, this
  hosts individual subsystems. The boundary is valuable only when it reduces
  measured iteration cost; simple kernel code should not be contorted merely
  to become rump-compatible.
- **Trigger to revisit:** First substantial filesystem or network subsystem,
  or QEMU becomes the dominant iteration bottleneck. Ask which implementation
  can run both in-kernel and against a narrow hosted interface.
- **Status:** High-value future pattern; not adopted. The first network
  subsystem met this trigger without a kernel boundary: the stack is
  smoltcp in userspace behind a frame `Link` trait, and the platform's
  `absd-net` host tests run two stacks over an in-memory wire
  (docs/NETWORK.md).

### Hardware access abstraction

- **Pattern:** `bus_space`/`bus_dma` separate driver logic from machine-specific
  MMIO or port I/O, DMA mapping and segmentation, synchronization, and
  allocation constraints.
- **Possible ABSD use:** Contain hardware variation instead of scattering it
  through drivers.
- **Why it fits / may not fit:** The abstraction should follow demonstrated
  platform differences, not hypothetical architectures.
- **Trigger to revisit:** First serious physical device driver or second CPU/
  platform architecture.
- **Status:** Note. The polled NVMe backend is the first physical-class
  driver; it has one DMA consumer (static identity-mapped pages) and one
  MMIO window, so nothing here is adopted yet.

### Authorization policy separation

- **Pattern:** Separate a mechanism's authorization request from a policy
  decision, as NetBSD's kauth demonstrates.
- **Possible ABSD use:** A native operation or compatibility personality that
  genuinely needs policy beyond possession of a direct handle/right.
- **Why it fits / may not fit:** ABSD should not import Unix credentials or
  kauth semantics; explicit handles remain the default authorization answer.
- **Trigger to revisit:** First concrete operation where handle possession is
  insufficient and separately pluggable policy is demonstrably required.
- **Status:** Note; do not add speculatively.

## Cross-system lessons

### Placement is not the invariant

DragonFly shows explicit ownership and message coordination inside a privileged
kernel; NetBSD shows kernel subsystems executing outside one; OpenBSD shows
authority reduction and secure defaults as ordinary runtime policy. Ask what
property must be enforced before deciding where code must live.

### Testability is architectural

A narrow hosted interface can enable heavier fuzzing, cheaper debugging, more
failure injection, and more effective review. Its abstraction is also
maintenance surface, so introduce it only when validation or iteration cost is
measurably reduced.

### Security reductions should compose with handles

Before adding process-wide restriction, check whether explicit handles and
rights already provide the required narrowing. Prefer one coherent authority
model over overlapping security systems.

## Linux mechanisms

Treat these as independent wells, not a package of Linux semantics.

- **RCU:** Revisit for read-mostly shared state when SMP makes reader locking a
  measured problem; define reclamation and grace-period evidence first.
- **cgroups v2:** Revisit when ABSD needs to distinguish accounting, hard
  limits, weights, protection, and actual reservation for a concrete resource.
- **pidfds:** Compare stable process-instance references with ABSD's existing
  opaque process handles when process observation must outgrow parent-local
  wait/kill authority.
- **seccomp and Landlock:** Revisit for process-wide authority reduction only
  after checking whether explicit handle rights already express the needed
  narrowing.
- **io_uring:** Study when real asynchronous I/O needs shared submission and
  completion machinery; treat its expanding semantic surface as a warning as
  well as an optimization example.
- **eBPF verifier:** Revisit only for a real constrained privileged-extension
  workload. Execution safety does not establish policy correctness.
- **PSI:** Revisit when a workload needs explicit pressure and degradation
  evidence rather than allocation refusal counters alone.
- **Namespaces:** Revisit when contextual resource views solve a real native or
  compatibility problem; account for the resulting compatibility-state
  complexity.
- **Status:** Notes; none adopted.

## Reproducible construction and deployment

### Nix and NixOS

- **Pattern:** Explicit build inputs, derivation/generation identity,
  immutable outputs, activation separate from construction, rollback,
  closure/reachability, and garbage collection.
- **Possible ABSD use:** Evidence for reproducible system generations and
  package or deployment work.
- **Why it fits / may not fit:** The properties are useful without presuming
  Nix the language or Nix-store semantics.
- **Trigger to revisit:** Reproducible system generations or package/deployment
  work becomes concrete.
- **Status:** Note.

### OSTree, Silverblue, and rpm-ostree

- **Pattern:** Bootable deployment generations, atomic activation, a retained
  previous deployment, inspectable deployment identity, and separation of
  base-system state from mutable application/user state.
- **Trigger to revisit:** First real ABSD self-update or deployment mechanism.
- **Status:** Note.

### Android and ChromeOS

- **Pattern:** A/B deployments, boot-success marking, verified boot, rollback
  protection, and disposable/reconstructable system images.
- **Possible ABSD use:** Early appliance-image deployment and recovery.
- **Why it fits / may not fit:** Rolling back code does not imply rolling back
  mutable data; those histories require separate contracts.
- **Trigger to revisit:** ABSD needs an appliance image, verified boot chain,
  or failure-tolerant self-update.
- **Status:** Note.

### XNU and macOS

- **Pattern:** Mach-port native mechanisms beneath compatibility personalities,
  launchd-style activation, IOKit driver lifecycle, and APFS snapshot/
  generation ideas.
- **Trigger to revisit:** Consult the relevant mechanism on demand when ABSD
  reaches service activation, driver lifecycle, personality layering, or
  persistent generations.
- **Status:** Reference only; not a general design dependency.

Historical mechanisms are revisited only when a concrete ABSD problem appears.
Do not collect operating systems as features: precedent is evidence, not
authority.

## Live update and self-healing tracks

Self-healing and future live update may share instance/generation identity,
explicit state and resource ownership, quiescence and fencing, replacement
authority, conditional transitions, health verification, rollback/escalation,
bounded evidence, and temporary coexistence headroom. That shared substrate
does not make the mechanisms equivalent: self-healing is not kernel live
update, and live patching, component replacement, and whole-kernel replacement
are separate tracks.

### Live patching

- **Pattern:** Replace bounded executable code while preserving the running
  kernel instance and most state representation.
- **Possible ABSD use:** An urgent, narrowly scoped bug or security fix without
  reboot.
- **Why it fits / may not fit:** Applicability must name one exact kernel
  generation and prove old code is no longer executing, instruction/text
  synchronization, stack/reference safety, and data-layout compatibility.
- **Trigger to revisit:** Stable enough kernel interfaces plus a concrete
  operational need for a bounded no-reboot fix.
- **Status:** Future; do not design now.

### Live component replacement

- **Pattern:** Stop new work, quiesce and drain an explicitly owned subsystem,
  establish a replacement, transfer or reconstruct state, grant authority and
  resources explicitly, fence the old instance, verify health, then reclaim
  it.
- **Possible ABSD use:** A driver, privileged service, policy module, or other
  subsystem whose independent replacement buys real containment or
  maintenance value.
- **Why it fits / may not fit:** It is closest to current service recovery, but
  replacement started is not component recovered. State migration, outstanding
  operations, device state, and uncertain external effects still require
  reconciliation. Do not force universal replaceability.
- **Trigger to revisit:** First subsystem with a concrete independent-recovery
  benefit.
- **Status:** Future; architecturally adjacent to self-healing.

### Whole-kernel generation replacement

- **Pattern:** Move from kernel generation G to G+1 while treating global
  state change as explicit rather than pretending the kernel instance is
  unchanged.
- **Possible ABSD use:** Classify scheduler, processes, page tables, objects,
  interrupts, CPUs, syscalls, DMA/devices, timers, stacks, and allocators as
  transferred exactly, reconstructed, invalidated/recreated, or requiring a
  refused live update and reboot.
- **Why it fits / may not fit:** Old/new co-residency, syscall continuity, and
  partial-activation rollback make this substantially harder than patching or
  one-component replacement; not every data structure should be migratable.
- **Trigger to revisit:** Mature SMP, storage, device lifecycle, and update
  semantics plus a concrete reason to avoid a complete reboot.
- **Status:** Deliberately deferred high-risk research.

### Optionality and progression

Where otherwise sensible, explicit ownership, narrow boundaries, handles
rather than exposed kernel addresses, reconstructable caches, explicit
lifecycle/generation state, local invariants, bounded unsafe regions, and clear
drain points preserve options. Do not distort simple current code for a
hypothetical updater; optionality is only a tie-breaker.

The evidence progression is userspace process replacement, userspace service
recovery, replaceable privileged services, replaceable drivers/components,
bounded live patching, and only then possible whole-kernel replacement. Each
level must earn the next. Today the kernel is the trusted cleanup substrate;
replacing it makes that assumption recursive.

### Fencing, history, and maintenance tripwires

The existing single-core warning applies directly: SMP or kernel preemption
reopens in-flight execution fencing, concurrent handle/resource drain,
stale-generation execution, notification ordering, and component quiescence.
Stable SMP is a prerequisite for meaningful live-update fencing experiments.

Rolling back code does not roll back durable state, network traffic, device
commands, or externally observed results: kernel rollback is not world
rollback. Before accepting any live-update support promise, ABSD must retain
the participating generation identities and compatibility/migration contract,
test interrupted activation, diagnose failure, and be able to retire obsolete
migration paths. Agent implementation capacity is not justification.

## Restartable services and supervision

- **Pattern:** Keep failure domains small and let a supervisor restart a
  failed service from known inputs.
- **Source system:** MINIX 3 reincarnation/service management and QNX process
  monitoring; Erlang/OTP supervision trees are a secondary comparison.
- **Problem it solved there:** Turn component failure into a routine lifecycle
  event instead of corrupting an entire application.
- **Possible ABSD use:** A userspace init could spawn, observe, and restart
  services using process handles and explicitly supplied dependencies.
- **Why it fits / may not fit:** Existing fault isolation and wait outcomes
  provide a base; restart policy does not belong in the scheduler. Today's
  bounded probe keeps parentage, reaping, and supervision coincident
  only as an implementation convenience: adoption does not grant authority,
  and a spawned replacement is not recovered until its outcome and retained
  state are reconciled.
- **Trigger to revisit:** ABSD has a persistent userspace service whose failure
  should not end the session.
- **Status:** Small userspace experiment; no general service manager adopted.

Any future long-lived supervisor test must itself accept an explicit bounded
stop request (a versioned control cell is sufficient today) and have a harness
deadline. A healthy forever-loop is otherwise operationally indistinguishable
from a wedged CI boot. A served boot is the deliberate exception: its worker
serves without an in-guest deadline, accepts the explicit stop request (an
operator's `shutdown`), and its harness keeps the host-side deadline.

The volatile recovery workload proves that correct retained state and current
authority do not guarantee replacement viability when process capacity is
full. Recovery remains explicitly best effort; a future guarantee would first
trigger accountable reservation of actual process, frame, and handle capacity.

**FORMALIZE LATER:** The bounded worker classifies its retained cell as
pre-request, applied to the named request, or conflicting, then applies once,
reconciles without mutation, or refuses. Formalize only this transition
function if a second real service needs it; add no general recovery framework.

**FORMALIZE LATER:** If this surviving-client protocol gains a second real
consumer, prove that client-visible completion is never upgraded from
unknown or not-performed solely because a replacement instance exists.

The surviving-client experiment reaches the consumer-generation and bounded
multi-object-invariant tripwires. Today it resolves them by fully reaping each
predecessor, publishing a monotonic single-writer status/control handshake,
and treating one cell as authoritative state. This is not concurrent-instance
fencing or a general transaction; overlapping workers, a second live writer,
or SMP must reopen those questions.

### Pipe endpoints across replacement

- **Pattern:** Preserve byte-stream EOF as “no write-capable handle remains,”
  rather than tying it to parent exit or a nominal service lifetime.
- **Source system:** ABSD pipe experiment; capability IPC lifetime lessons.
- **Problem it solved there:** Readers need an unambiguous end-of-stream while
  a supervisor may separately want authority to start a future writer.
- **Possible ABSD use:** Revisit resource sponsorship or post-spawn transfer
  only if a real service handoff must grant a replacement an endpoint later.
- **Why it fits / may not fit:** Retaining a write handle enables replacement
  but suppresses EOF; closing it preserves EOF but today's spawn-only transfer
  cannot regrant it. Changing pipe semantics would hide this real distinction.
- **Trigger to revisit:** A supervised pipe service must preserve both stable
  EOF and explicitly authorized replacement handoff.
- **Status:** Negative knowledge; do not solve speculatively.

## Versioned persistent objects

- **Pattern:** Apply a state transition only when the object's observed
  version still matches, and persist or replicate the accepted version.
- **Source system:** OpenVMS file generations; optimistic concurrency control
  in databases and object stores; ABSD's current versioned cells.
- **Problem it solved there:** Prevent lost updates without holding a lock
  across independent work or failures.
- **Possible ABSD use:** Evolve the versioned cell experiment only when a real
  object needs conditional update, recovery, or durable state.
- **Why it fits / may not fit:** The in-memory compare-and-transition rule is
  already useful; persistence would require storage, recovery, and ordering
  contracts that ABSD does not have.
- **Trigger to revisit:** A concrete object must survive restart or coordinate
  updates that outlive a process.
- **Status:** Conditional in-memory transition exists; persistence is not
  adopted.

## Observability and resource controls

- **Pattern:** Make resource ownership, limits, waits, failures, and cleanup
  measurable at the boundary where they are enforced.
- **Source system:** Solaris/illumos observability and resource controls;
  FreeBSD accounting/jails and Linux cgroups/tracing where applicable.
- **Problem it solved there:** Diagnose contention and enforce limits using
  evidence tied to responsible workloads.
- **Possible ABSD use:** Add small counters or query records for actual
  scheduler, VM, handle, and object pressure before adding new limits.
- **Why it fits / may not fit:** Deterministic counters already strengthen the
  test suite; a general tracing framework would consume scarce kernel memory
  and distort behavior.
- **Trigger to revisit:** A repeatable failure cannot be attributed with the
  current serial diagnostics and aggregate counters.
- **Status:** Basic counters exist; broader telemetry is deferred.

## Selective namespaces

- **Pattern:** Present a process with a deliberately selected view of named
  services or resources.
- **Source system:** Plan 9 per-process namespaces and Unix mount namespaces.
- **Problem it solved there:** Compose an environment by controlling which
  names resolve for each process.
- **Possible ABSD use:** A small userspace service directory could distribute
  handles explicitly if bootstrap by fixed argument vectors stops scaling.
- **Why it fits / may not fit:** Selective visibility can reduce ambient
  authority, but a universal namespace or “everything is a file” model would
  obscure ABSD's typed objects and explicit transfers. Never go full Plan 9.
- **Trigger to revisit:** Several independent services need discovery and
  passing every handle directly becomes the dominant bootstrap complexity.
- **Status:** Reference note; no global namespace planned.

## Process mobility and checkpointing

- **Pattern:** Before claiming transparent checkpoint or migration, classify
  every resource reachable by the process as transferable, reconstructable,
  proxyable, rebindable, or non-migratable.
- **Possible ABSD use:** Keep stable logical identity independent of physical
  locality where that distinction is useful, while making every exceptional
  resource disposition explicit.
- **Why it fits / may not fit:** Complete reachable-resource coverage is a
  prerequisite for a migration claim; ABSD currently needs no migration
  traits, relocatability flags, freezer, migration graph, remote-process
  support, or checkpoint machinery.
- **Trigger to revisit:** First real process-checkpoint, suspend, or migration
  experiment.
- **Status:** Note; deliberately deferred.

## Distributed locking and clustering

- **Pattern:** Coordinate ownership and state transitions across nodes with
  explicit membership, failure, and lock-recovery rules.
- **Source system:** VMScluster/OpenVMS Distributed Lock Manager.
- **Problem it solved there:** Keep shared resources coherent when several
  machines access them and membership changes.
- **Possible ABSD use:** Long-horizon guidance if ABSD ever shares persistent
  objects across machines; keep any local conditional-transition API neutral
  enough not to preclude later coordination.
- **Why it fits / may not fit:** Versioned transitions offer a useful local
  primitive, but distributed failure detection and recovery are far beyond a
  single-node kernel and should not shape current code speculatively.
- **Trigger to revisit:** Two real ABSD nodes must concurrently update the same
  durable object under tested partition and recovery behavior.
- **Status:** Long-horizon reference only; no clustering work planned.

## Native hardware tripwires

Recorded while preparing the first physical boot (framebuffer console,
polled NVMe). Each names what was deliberately not built.

- **PCI:** `src/pci.rs` is a configuration-mechanism-#1 scan, one memory
  BAR, and command-register bits for exactly one consumer, the NVMe driver.
  No enumeration model, resource ownership, MSI/MSI-X, or interrupt routing.
  *Trigger:* a second PCI consumer (virtio, a NIC, xHCI). Then design device
  ownership and BAR/DMA access once, against two real drivers.
  *Fired (2026-09-26)* with the e1000 NIC (docs/NETWORK.md). What was built,
  against NVMe and e1000: one kernel owner per function for the boot
  (`pci::claim` before any BAR mapping or bus-master enable; a second claim
  is refused by name), `find_id` and `memory_bar(n)`, and DMA only into
  static identity-mapped kernel memory. Still not built: MSI/MSI-X,
  interrupt routing, an enumeration model, and any user-visible device
  access. Next trigger: a device that needs interrupts or an IOMMU.
- **Legacy timer and interrupts:** the kernel uses only the 8254 PIT through
  the 8259 PIC. *Trigger:* the first physical boot shows `TIMER FAILED`,
  stalled timed waits, or no preemption (docs/PHYSICAL-BOOT.md). Then
  evaluate the LAPIC timer and LAPIC/IOAPIC routing; not before. QEMU
  `-machine pit=off` or `pic=off` reproduces the tripwire screen exactly
  (`make laptop-matrix`). The unpromoted branch `lane/laptop-lapic`
  (`lapic-timer-probe` boot option) shows the xAPIC timer at 0xfee00000
  counting (~290k counts per 2^24 TSC cycles at divide 16 under TCG) and
  delivering five interrupts on vector 32 with both 8259s masked, under
  `pit=off` and `pic=off` alike. What it lacks for promotion: an absolute
  calibration source (CPUID 15h/16h, the ACPI PM timer, or HPET), since
  the TSC rate is itself unknown on hardware.
- **NVMe depth:** one I/O queue pair, one 512-byte block per command through
  a static bounce page, polled completion, 512-byte LBA formats only.
  *Trigger:* a real workload whose throughput or latency is bounded by this,
  or a sacrificial physical disk that only offers 4 KiB LBAs.
- **Device mappings:** a 4 GiB kernel window of 2 MiB uncached pages from a
  static pool, never unmapped. *Trigger:* device hotplug, unmapping, or more
  device memory than the window.
- **Framebuffer console:** output only, a ring of rows with no scrolling, one
  embedded 8x13 font, no keyboard. *Trigger:* interactive use on hardware
  without a serial port. A framebuffer that firmware places in RAM below
  1 GiB (QEMU `ramfb`) is refused by the device-mapping window
  (`Map(InFirstGigabyte)`) and the boot runs blind. *Trigger:* a physical
  boot that shows GRUB and then nothing.

## Dogfooding Constellation on ABSD development

- **Intent:** ABSD development should eventually be a real workload governed
  by Constellation, not only something Constellation is meant to run. The
  point is pressure, not ceremony: real development work tests whether
  Constellation can bind an exact source/worktree basis, a bounded agentic
  attempt, its permitted local effects, the resulting tree/commit identity,
  independent build/test evidence, qualification, and integration.
- **Stages:**
  0. *Shadow custody.* Observe an ordinary attempt after the fact and
     reconstruct starting tree, objective, resulting tree, commands/tests run,
     and terminal outcome, without influencing the work.
  1. *Governed qualification.* The agent edits freely in a disposable
     worktree; Constellation owns or independently runs qualification (exact
     resulting tree, exact build/test command, retained evidence, verdict).
     An agent reporting "make check passed" is not evidence.
  2. *Governed local attempt.* Constellation authorizes and launches one
     bounded attempt: one repository/worktree, one starting tree, one
     objective, local disposable mutation, local builds/tests, no push, no
     public effects, no unrelated checkout mutation. Iteration inside that
     boundary needs no per-edit authorization.
  3. *Governed acceptance.* A resulting tree enters the canonical line only
     after independent qualification binds evidence to that exact tree:
     authorized attempt, resulting tree, independent qualification, qualified
     tree, local integration. This is where Constellation first materially
     governs ABSD development.
  4. *External effects.* Pushes, issue mutation, and releases are a separate,
     later boundary, not granted because local dogfooding works.
- **First acceptance target:** an agent fixes one real ABSD defect in a
  disposable worktree; Constellation binds the attempt to the exact starting
  tree and objective, independently qualifies the exact resulting tree,
  records the evidence, and permits local integration only after
  qualification. Nothing is pushed.
- **Expected pressure:** repository/worktree observation, tree identity,
  agent/provider invocation custody, bounded development authority, build/test
  evidence, attempt iteration, result-tree custody, qualification, and
  settlement. Build none of these ahead of a dogfood step that demonstrates
  the need.
- **Later:** ABSD running Constellation that governs an agent modifying ABSD.
  Not required first; Constellation may run on the Linux development host.
- **Guardrail:** no K-series-style ceremony. Govern only boundaries where
  authority, evidence, or irreversible effects matter; disposable
  implementation stays cheap, and stronger evidence belongs at qualification
  and acceptance.
- **Trigger to revisit:** existing Constellation components can plausibly bind
  an exact ABSD source tree and independently qualify a resulting tree without
  a new shared ontology or campaign framework.
- **Status:** Guidepost; deliberately deferred until a bounded experiment is
  cheap. Not a prerequisite for current ABSD work.

## Linux compatibility as a personality, not a native specification

Status: future compatibility tripwire, deliberately deferred. No code, no
roadmap commitment, no compatibility claim.

ABSD may eventually run unmodified Linux binaries. If it does, that is an
opt-in personality above native mechanisms:

    Linux ELF / process personality
      -> Linux syscall ABI dispatcher
        -> native ABSD: handles, rights, processes, files, VM,
           sockets and waits as actually implemented

The layer translates observable Linux behavior into native mechanisms; it
never redefines native behavior in Linux terms. Linux compatibility is a
membrane and native semantics stay authoritative. Native interfaces are not
shaped to ease emulation unless a native workload independently earns the
same mechanism.

Layers, strongest first: native ABSD programs (the native ABI); the Unix-style
ABSD personality (argv/env/cwd, userspace fd tables, file/socket APIs,
errno-style translation) for source ports; the Linux personality for
software not worth porting. The last two do not specify the native design.
The Unix-style layer has begun as argv, environment, working directory, and
filesystem execution in the Rust platform's runtime over one native call,
`spawn_image` (docs/PROCESS-STARTUP.md); its fd table is deferred until a
consumer needs integer descriptors.

- **Trigger:** Unix-style userspace (SSH, shell, ordinary programs) runs
  comfortably. Then one bounded spike: the minimum additional surface to run
  one unmodified static Linux x86-64 binary (a static musl build, e.g.
  BusyBox, chosen from evidence then). Measure syscalls reached, ABI
  translation, VM/mmap, PID, fd, filesystem, clock, and socket assumptions,
  and the code it costs. Unsupported syscalls return `ENOSYS`.
- **Expansion rule:** a Linux behavior enters only because a real binary
  needs it, with a regression case tied to that binary. The Linux syscall
  table is not a requirements document.
- **Expected later cliffs (triggers, not commitments):** dynamic ELF and
  `PT_INTERP`, glibc startup, TLS, signals, `clone`/threads, futex, robust
  lists, rseq, epoll, PTYs and job control, procfs, sysfs, netlink, ioctl,
  mmap/file corner cases, credentials, namespace/cgroup/seccomp
  expectations. glibc plus threads is its own cliff; it does not follow
  from static-binary support.
- **Identity mapping:** Linux fds and PIDs are compatibility
  representations (fd -> personality table -> handle; PID -> compatibility
  identity -> native process handle). Native stale-reference and
  generation guarantees are not weakened to mimic Linux integers.
- **Errors and durability:** where Linux behavior differs, emulate it in the
  layer where practical, document what is unsupported, and never weaken a
  native guarantee silently. A Linux binary that runs does not make the
  native API Linux-compatible.
- **Not KLinux:** the Linux K/N experiment asks what guarantees Linux itself
  can enforce at an effect boundary; this asks how much Linux userspace ABI
  ABSD can emulate above its own semantics. They stay separate projects; no
  ABSD-Linux derivative.
- **Stop rule:** if the work starts pulling native ABSD toward Linux-internal
  semantics, Linux object models, or kernel-wide Linux ABI assumptions
  rather than a bounded personality, stop and reassess.

## Multi-principal authority (future tranche)

Status: deferred planning note. No design, API, or implementation is
committed here. Begin only after the SSH and file-server integration is
complete and qualified.

Today ABSD supports several concurrent, isolated SSH sessions for one
authenticated operator identity: multi-session, not multi-user. The next
hill, stated as a hypothesis to refine: two independently authenticated
principals operate concurrently holding different explicit authorities, and
neither can exercise or observe authority not granted to it.

Possible progression: one operator; concurrent isolated sessions (current);
independently authenticated principals; scoped authority per principal;
delegation and revocation; optional personality-level account semantics.

Open questions, not answers:

- **Identity:** what a native principal is; whether it is durable across
  boots; whether it is a kernel concept, a service concept, or only an
  opaque handle.
- **Authentication binding:** what a successful SSH authentication binds to
  (a principal, a role, an authority bundle, something else).
  Authentication (who presented acceptable credentials) and authority (what
  this principal or session may do) stay separate questions.
- **Authority:** how rights attach to a principal (handles, grants,
  service-owned policy such as file-server bindings, or another existing
  mechanism), without assuming UID/GID.
- **Storage:** what two principals accessing objects differently means;
  whether storage knows principals or an owning service mediates; no "file
  owner" kernel primitive by default.
- **Observability:** what one principal may observe of another (sessions,
  processes, storage objects, failures, resource use).
- **Delegation:** whether and how a principal grants part of its authority,
  and the minimum native mechanism for it.
- **Revocation:** whether delegated authority can be withdrawn, what happens
  to open handles and sessions, and whether revocation is immediate,
  generation-based, session-scoped, or service-owned.
- **System services:** how init, brokers, and servers act without an
  accidental root.
- **Personality:** which Unix concepts (users, groups, UIDs, mode bits,
  passwd databases) a personality can synthesize above native mechanisms.

Constraints carried forward: G1 (no ambient authority; parentage and
convenience do not create it), G9, G10 (why does this layer know that?),
and one principal's many sessions stay distinct from many principals.
Illustrative future gates (not tests): principal A and B authenticate;
distinct authority; cross-principal access refused; concurrent principals;
principal failure isolation; delegation; revocation. Not implied:
accounts, passwd, UID/GID, groups, mode bits, PAM, sudo, root, RBAC, a
central identity database, a kernel-global user object, or a policy
language.

Related notes: "Process authority reduction", "Namespace restriction",
"Security reductions should compose with handles", "Authorization policy
separation", and the delegation and revocation research tripwires.
Terminology: Constellation's AG uses "principal" (issuer principal chains)
with its own meaning; an ABSD principal must be defined independently.
