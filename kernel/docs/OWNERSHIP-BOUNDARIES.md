# ABSD semantic ownership and implementation boundaries

Architecture direction recorded by explicit user instruction, 2026-10-03.
This constrains future choices; it opens no implementation, replacement, or
benchmark lane. The [U1 workstreams](USABILITY-ROADMAP.md#u1-named-machine-sustained-usability)
remain unchanged. Read this with architecture intent (development record, not in a source release),
the [design guardrails](DESIGN-INFLUENCES.md#guardrails-for-using-these-notes),
and [live evolution](LIVE-EVOLUTION.md).

## Economical with danger

Governing philosophy recorded by user direction, 2026-10-05:

> Treat scarce resources—authority, complexity, attention, certainty—as things that must be budgeted, not ambiently assumed.

**Rigor is a scarce resource. Spend it where uncertainty and consequence
justify it. Attention is part of the safety budget. Ceremony is not evidence.**
An understood, reversible change with bounded consequences should be cheap to
perform. Uncertainty about consequential or irreversible effects warrants
stopping, narrowing the action, or obtaining the evidence needed to proceed.
Claims of understanding and reversibility must themselves have a basis;
confidence, experience or completed paperwork cannot establish an invariant.

Procedure adherence is a measurable proxy, not the outcome the procedure was
meant to protect. Applying the same burden regardless of uncertainty and
consequence can reward legible safety signals while consuming the judgment
needed for unusual cases. Review the continuing value of controls rather than
allowing procedure completion to become the objective.

Every rule has maintenance cost, every checkpoint consumes attention, every
handoff adds failure modes, and every abstraction has carrying cost. Evaluate
safeguards by the failure they prevent and their continuing cost. A safeguard
that consumes more judgment than the risk warrants can become a hazard by
displacing attention from unusual cases or encouraging an unofficial path
around it. Removing or simplifying a safeguard still requires understanding
which invariant it protects and how that invariant will remain enforced.

These principles apply together:

- Complexity must justify its carrying cost; do not universalize a mechanism
  merely because it worked once.
- Authority should be explicit, narrow and inspectable. Do not spend
  privileged complexity where a narrower mechanism will do.
- Mechanism should enforce invariants; policy should remain replaceable where
  its replacement preserves those invariants.
- Failure should be legible, with residual effects, uncertainty and recovery
  obligations visible, rather than merely leaving the system running.
- Make the safe path cheap and the dangerous path conspicuous. Administrative
  friction and procedure completion are not measures of safety by themselves.

The corresponding evidence/authority discipline is: **do not spend authority
where evidence and refusal will do**. The operational discipline is: **do not
spend human attention proving seriousness about safety instead of reducing
risk**. Certainty here means the strength of an established claim, not a
numeric resource that paperwork can manufacture; refusal and indeterminate
outcomes preserve uncertainty honestly.

This constrains the design and review of mechanisms and safeguards. It does
not waive current authorization, storage admission, qualification, failed
evidence or release gates. Proportional rigor is a judgment about uncertainty
and consequence, not a new universal workflow, process tier or scoring system.

## Warranted belief is an engineering output

Architecture canon recorded by user direction, 2026-10-05:

> Code was never the scarce resource. Warranted belief about what the code does was.

Treat this as a design maxim, not a claim that implementation effort or
compute has no cost. Cheaper construction can raise the feasible complexity
ceiling without making that complexity understood. **The software crisis is
increasingly a crisis of warranted belief, not code production.** ABSD should
make understanding a first-class output: what behavior is established, under
which assumptions, what changed, which authority caused an effect, whether it
finished, and how another observer can check that conclusion.

Distinguish a knowingly accepted local shortcut against future work
(*technical debt*) from diffuse carrying costs whose owner or origin is unclear
(*complexity pollution*). Both require attention; lower code-production cost
is not evidence that either cost disappeared. Configuration that computes
consequential decisions needs explicit semantics, review and observation just
as source code does; its representation does not exempt it from reasoning.

Models can help upstream of formalization: expand an intent, challenge an
architecture, identify counterexamples, and construct models, fixtures and
oracles. This is a possible way to narrow the gap between machine capability
and human comprehension, not an established reliability guarantee. Cheap,
fluent analysis can also manufacture convincing errors. Model agreement,
review count and a plausible explanation are not independent evidence.

Spend computation and human attention producing claims that can be checked,
rather than systems whose correctness must merely be trusted:

    intent -> challenge / formalize -> checkable artifact
           -> execution / verification -> evidence -> reconciliation

A useful loop preserves source identities, assumptions, negative controls,
failed receipts and independent acceptance, then states a bounded claim. It
should make rejecting an attractive idea cheap. Do not spend the surplus only
on generating larger systems, and do not universalize this loop into ceremony
for understood, reversible work. The isolated capability result (development record, not in a source release)
is one concrete example of a limited result rejecting a broader architectural
interpretation; it is not proof of this maxim or permission to merge research.

This philosophy aligns with Constellation's evidence/authority distinction
without creating a dependency or shared ontology. Neither synthetic judgment
nor observation grants authority. An observer may be wrong; observations and
acceptance must retain enough identity and scope to be challenged.

## Own semantics before implementations

ABSD owns the meaning of authority, identity, observation, refusal, resource
accountability, lifecycle, and durable outcomes. Choose implementations after
those boundaries are explicit. Reuse of an engine does not make its native
API the ABSD specification.

| Ownership class | Meaning and continuing obligation |
| --- | --- |
| Native | ABSD specifies the semantics and owns their contract and qualification; lower-level implementation components may still be reused. Native code is not automatically qualified or preferable. |
| Adapted | ABSD owns a boundary over a reused implementation: translation, authority checks, state ownership, failure behavior, and update obligations. The implementation may contribute to the trusted path. |
| Commodity | Reuse an existing tool, engine, protocol implementation, cryptographic library, or application with minimal local delta where its contract fits. Its guarantees still have named assumptions and consumers. |

These classes describe ownership, not evidence strength or trust level. One
component can contain native policy, an adapted interface, and a commodity
engine. Borrowed applications, protocol stacks, and cryptography are not
automatically untrusted; conversely, putting a wrapper around them does not
remove them from a trusted path.

The decision is: **can an adapter outside the reused component enforce the
required invariant?** If yes, reuse the component and own the adapter. If
no, own the semantic layer. Own the underlying implementation only when
that implementation is itself necessary to enforce the invariant. A failure
that merely changes an application result is not sufficient reason to
acquire a new subsystem implementation.

The cost brake is an adapter decision before an engine rewrite. Record the
consumer and invariant, the smallest translation, carried patches, upstream
update strategy, refusal/loss behavior, and removal condition. Compare
continuing obligations and independently changing callers, not just code
size. Refuse an adapter that silently weakens a native guarantee; reconsider
the engine or the proposed guarantee before acquiring a large fork. Reuse
does not authorize a rewrite or a new compatibility promise.

For storage, prefer a boring, well-understood reusable engine when it can
represent the native identity, authority, commit, recovery, and refusal
contract through a bounded adapter. Owning those semantics does not require
owning every index, allocator, cache, or on-disk implementation. Engine
selection remains conditional on a named workload and evidence. Current
main uses native `absd-fs`; this direction neither selects a successor nor
promotes held-out storage experiments.

## Storage engines and consumer qualification profiles

User direction recorded on 2026-10-05:

> Native persistence is one storage-engine implementation behind the ABSD storage/service authority boundary, not an architectural requirement that all ABSD volumes use this engine.

> ABSD defines the authority, lifecycle, durability, refusal, recovery and service semantics exposed above the storage boundary. The implementation beneath that boundary is replaceable machinery, provided it satisfies the qualification profile required by its consumers.

> Storage engines are admitted against explicit semantic qualification profiles. A weaker engine does not silently weaken the ABSD contract; it is refused for consumers whose requirements it cannot satisfy.

Treat an engine's qualified profile `E` and a consumer's requirements `R` as
typed semantic descriptions: admit that engine for that consumer only where
the evidence establishes that `E` satisfies `R` under the named substrate and
failure assumptions. A profile distinguishes authority and identity rules,
commit/durability meaning, supported failure and recovery behavior, resource
bounds, and lifecycle/replacement obligations. An unknown or unsupported
requirement causes refusal; it is not silently omitted, emulated with a weaker
promise, or reduced to a lowest common denominator. These descriptions are a
design constraint, not an implemented profile registry, negotiation protocol,
Rust trait or new ABI. New profiles require a separately admitted specification
and corresponding qualification.

Future profile properties may include durability ordering and strength/device
assumptions, crash consistency, bounded recovery, stale-state rejection,
integrity level, atomic replacement, reclamation/capacity guarantees,
lost-reply semantics, recovery/refusal precision, and observation/receipt
support. This is a review inventory, not a frozen ABI or a requirement that
every engine implement identical semantics.

Different engines may serve different volumes or consumers under explicit
profiles. ABSD authority remains native above the boundary: an engine's UID,
GID, `root`, pathname permissions or internal ownership fields do not create
ABSD grants. An adapter must preserve the authorized view and effect-time
checks, including refusal, rather than importing foreign superuser semantics.
An engine qualification result is evidence for a scoped claim; it neither
grants operational authority nor authorizes construction or activation.

Current platform main `c54dc90007fe509c0e118b7ec9c6cbd6ea9aa356` has a narrower
operational path: `fsd/Cargo.toml` directly depends on `absd-fs`, the runtime's
`storage::mount_handle` mounts that implementation, and `release::FS_FORMAT`
is 2 with exact release-record comparison. SQLite's native VFS uses that same
mounted filesystem; it is not a second volume engine. Existing release and
filesystem qualification therefore require the current engine/format. There
is no current multi-engine admission mechanism or newly qualified profile.
This note changes neither that release path nor the sealed release claims.

Native implementation work has a concrete research rationale, not an
architectural monopoly. The platform's donor study (`4aaef7c`), corrected
Fable counter-study (`1da6916`), and redb prototype closeout (`ec684259`)
record actual reuse investigations. The tested redb configuration and pinned
RedoxFS control failed the required bounded-recovery property through eager
volume-proportional allocator reconstruction. That finding does not reject
every configuration or future engine, prove a native successor correct, or
remove the adapter cost brake. The maturity direction (`bb956fcd`) likewise
distinguishes present implementation limits from the platform's growth intent.

The native research owner's receipt at `503807ef` reports an intact abandoned
same-incarnation record accepted after generation reuse at accepted generation
4, under a home-only valid-frame substitution, despite its self-checksum and
structural audit. Six controls passed. This is a reported integrity limitation
under an additional storage-fault model, not a refutation of the separately
scoped pure-crash results under truthful flushes. That research implementation
is not canonical; identity representations are being compared, with no
production profile or remedy accepted by this note.

The acceptance question is:

> Is every piece of authoritative persistent state — including allocation and reclamation state — transitively bound to the accepted generation?

A locally valid checksum alone does not establish that a record belongs to
the accepted state. The question covers metadata and allocation/reclamation
decisions as well as application contents. A proposed engine must state the
binding and validation rule under its admitted failure model; this does not
require a single Merkle tree or prescribe any other representation. Validation
and acceptance remain outside the component being replaced. Replacement must
retain versioned state, authorized authority reconstruction, explicit
conversion/refusal conditions and retirement obligations; choosing another
engine does not make downgrade or post-effect rollback automatic.

Candidate machinery may include the native ABSD engine, selected foreign or
embedded engines, rump/anykernel-backed filesystems, 9P or 9P-inspired remote
adapters, and other qualified storage services. They may coexist. None is an
implementation commitment or permission to dilute a consumer's contract.
Constellation may eventually consume these profile claims as evidence;
authority to select/use an engine or volume remains separately governed.
ABSD does not depend on a Constellation integration to enforce that separation.

Future rump/foreign-filesystem adapters and 9P gateways remain deferred,
separately qualified choices for named consumers. This direction selects no
9P native API, foreign authority model, exokernel architecture, dependency or
implementation lane. It adds no U1/U2 workstream or blocker.

Deferred planning pointers (execution status and sequencing belong to GitHub):
semantic profiles (project board),
foreign-engine admission (project board),
rump filesystem experiment (project board),
and remote storage interoperability (project board).
Prior-art/integrity closeout stays with the
existing native-storage lane (project board),
item `PVTI_lAHOAFshrM4Blhg0zg-VqVM`; this note does not admit a second lane.

## Semantic dependency graph

```text
authority + IPC + logical identity
                 ↓
        lifecycle and failure contracts
                 ↓
        persistence and recovery contracts
                 ↓
       update and replacement contracts

network and time adapters cross these boundaries:
authority/identity → state ownership → lifecycle → durable evidence
```

This is a graph of claims that depend on one another, not a work schedule.
Storage recovery cannot manufacture authority; a service restart cannot
define identity by accident; an update cannot promise rollback without a
state-conversion and effect contract. Network and time implementations can
already exist while wider guarantees remain unqualified. Authority and IPC
semantics precede stronger persistence claims logically; their future design
does not block or reorder the admitted U1 work.

Parentage, sponsorship, supervision, mutable ownership, durable reachability,
and dependency remain separate graphs. Declarative system or authority
descriptions are inputs to trusted authorized construction and bounded
modeling, not grants. A model must state how its assumptions correspond to
that construction.

The target native surfaces are explicit; this table declares no new API:

| Semantic surface | What ABSD should own |
| --- | --- |
| Authority, identity, IPC | Native principal and logical service identity; endpoint authority; explicit delegation/revocation rules, generation binding and request attribution. UID/GID and Unix sockets may be compatibility representations, not the native object model. Revocation is a property to qualify, not implied by existing handle delegation. |
| Lifecycle | For managed resources, dependency and owner identity, resource-specific state transitions, quiescence, stop/depart/reclaim, restart boundaries, replacement and explicit old-generation retirement. Basic progress, ordinary runtime objects, and ordinary process completion do not by themselves require a managed lifecycle contract. |
| Persistence | Durable object identity distinct from pathname; generations, tombstones/explicit retirement, provenance/custody metadata and transactional replacement. This semantic layer is separate from crash-consistency, allocation and recovery machinery in the storage engine. |
| Update/state deployment | Activation, compatibility contracts, migration preconditions, authority transfer, honest rollback/refusal, dependency transitions and retirement evidence. Archive/compression/transport formats may remain borrowed. |
| Network control | Interface and endpoint ownership, bind/listen/connect authorization, routing/configuration authority, flow attribution and generation lifecycle. TCP/IP mechanics need not be native implementations. |
| Time | Monotonic and wall-time contracts, external assertions, boot/execution identity and the evidence required for event ordering. |

Future adapted boundaries may translate OpenSSH authentication into an
authorized native grant, DHCP results into permitted network configuration,
NTP/PTP results into externally asserted time, or POSIX calls into native
process/object operations. These are examples, not current implementations.
The adapter is trusted ABSD code; authenticating a key is not itself a grant.
A future POSIX personality needs particular scrutiny for accumulating
compatibility policy and authority. Reuse shells, editors, compilers, text
utilities, libc components where practical, DNS/DHCP/NTP implementations,
routing protocols, compression, crypto and TLS through the boundaries their
actual effects require. Reuse is not a claim that their failures are harmless.

## Managed-resource lifecycle contracts

Apply a managed lifecycle only where authority, durability, availability, or
cleanup obligations require an accountable resource boundary. Do not turn
ordinary progress, every runtime object, or every process exit into a
workflow. Separate three layers: ABSD owns the common lifecycle envelope;
subsystems define resource-specific states and edges; orchestration composes
operations above those contracts. This does not put fleet scheduling or
operational escalation policy into the kernel or base OS. Orchestration
does not own or redefine the resource's truth.

A lifecycle contract has a small common envelope: logical resource identity
and generation; purpose/provenance; current state and prior transition
evidence; request identity and authority; transition
preconditions; directly establishable obligations; accountable owner;
effect scope; and an operation disposition with a retained receipt or
evidence pointer. Resource-specific states and named edges carry the actual
meaning. There is no universal state enum, lifecycle protocol, or workflow
engine. Obligations state observable facts required of a transition, not
application policy or business logic.

For each managed resource, name the state machine and permitted transitions.
Each edge identifies who may request it, which generation it addresses,
what must be true before and after, and what evidence establishes that
result. `COMPLETED` means the scoped postcondition is established;
`REFUSED` means the covered effect did not occur; `INDETERMINATE` means
available evidence cannot establish either. A receipt identifies the
request, resource/generation, effect scope, disposition, and evidence needed
for inspection or reconciliation. A timeout or missing reply is not a
refusal, and elapsed time alone cannot resolve uncertainty.
Disposition reports what is known about the effect; notification,
escalation, and retry are separate authorized policy. The accountable owner
may differ from the transition executor, but ownership of unresolved
evidence and the next inspection must remain explicit.

State names belong to each resource. A release may distinguish staged,
selected, accepted, and retired; a service may distinguish started, ready,
quiescing, fenced, and stopped. These examples do not prescribe one enum or
assert that every resource uses these states. An edge is admitted only with
its resource-specific authority, evidence, and failure meaning.

Steady state alone is insufficient: a serving generation can coexist with a
drained predecessor whose references or obligations still prevent retirement.
An incomplete transition exposes its owner, remaining scoped obligations, and
inspection/reconciliation path. Suitable obligations include authority fenced
or expired, owned endpoints released, successor validated, state transferred
under its schema, or references zero, where the resource contract requires
them. An external approval becomes a fact only through an authorized boundary;
arbitrary business logic is not a native lifecycle obligation. If
it has a deadline, identify the valid monotonic clock domain, the event that
starts the bound, and what the owner can observe when the bound expires or
the clock becomes unavailable. Otherwise state that it has no deadline.
The failure disposition and any required operator action must be visible;
an orchestration layer cannot silently turn a pending or indeterminate
resource transition into success or failure.

Retirement is an explicit lifecycle transition with an owner, preconditions,
effect scope, evidence, and disposition. Absence from a registry or loss of
reachability is not retirement and does not prove physical destruction.
Fencing prevents old-generation authority or effects from continuing; it
does not revive handles or transfer state. Any successor receives only
explicitly authorized state under versioned schemas with conversion
preconditions and loss/refusal conditions. An independent authority decides
whether the successor is accepted and the old generation may retire.

These rules selectively apply to resources whose managed authority,
durability, availability, or cleanup claim needs them. They do not mandate a
resource manager or common workflow service. Existing component contracts
remain authoritative until a separately admitted change names a consumer,
source, transition history, and qualification scope.

### Channel composition: authority lifetime and uncertain custody

A process lifecycle boundary is not necessarily an authority-lifetime boundary
when independently held, adopted, or transferred endpoints survive the apparent
owner. This principle was established for channel/endpoint composition; it does
not assert survival for every object type or introduce general handle transfer.
Killing or replacing the apparent owner does not prove remaining endpoint/borrow
obligations discharged. Accountable owner, handle holder and obligation holder
may differ.

When custody of a live authority/borrow cannot be established, ABSD may
quarantine the affected authority rather than assume ownership has returned.
Reuse of an old channel requires complete holder teardown, lifetime fencing,
proof outstanding borrowers/endpoints are gone and authorized rebinding under
the server's currentness and quiescence rules. Process replacement alone is
insufficient because live children may be adopted with their endpoints intact.
A successor generation never revives fenced authority implicitly.

The current runtime's `Untracked` holder is one implementation of this rule,
not a universal architecture state. It has no in-process discharge. Exceptional
tracking failure can lose local availability indefinitely while keeping ordinary
parent requests, channel reuse and DERIVE through the quarantined own channel
refused. Independently authorized channels remain usable under their own gates
and capacity. Raw/trusted paths, direct-child tracking limits, negative INFO
retirement, unchecked CLOSE and descendant recovery remain outside this bounded
guarantee. No new recovery protocol or authority is supplied.

The selective integration record (development record, not in a source release)
names production correspondence and regression scope. Formalization consideration:
the existing bounded borrower model and exact-module effect witness support the
local exclusion property. Complete holder discovery and recovery remain unknown.
Decision owner: ABSD controller; future exported recovery state needs explicit
schemas, reconstruction rules and acceptance outside the replaced component.

## Restart contracts must be falsifiable

Assign a class to a named component under a named failure mode, not to every
service merely because it runs in userspace:

| Class | Claim that qualification must distinguish |
| --- | --- |
| restartable-lossless | After the named failure and bounded restart, all state and client obligations covered by the contract survive; no covered operation or result is lost. |
| restartable-with-reconstruction | The successor reconstructs the specified state from authoritative retained or durable inputs; anything unreconstructable is refused or separately classified. |
| restartable-with-client-visible-loss | The successor can resume service, but named sessions, queued requests, buffers, or results are lost; clients observe that loss and follow an explicit reconnect/retry rule. |
| non-restartable-without-system-transition | Safe continuation requires a declared larger transition, such as device reset, whole-system reset, or release rollback. Starting another process alone is insufficient. |

Every qualification receipt for such a claim answers seven fields: declared
failure mode; observed failure mode; state lost?; authority preserved?;
evidence emitted?; client-visible?; recovery bounded? Answers name the scope,
bound, observer, and supporting result rather than seven unexplained yes/no
values. Include in-flight work, refusal/indeterminate outcomes, escalation,
and retained state; distinguish restarting execution from recovering it.

The current served-boot recovery (development record, not in a source release) and
integration repair (development record, not in a source release) use a whole-machine
reset for the named component failures. They do not demonstrate independent
lossless sshd, filesystem, or network-service restart. Current TCP and SSH
session state lives in sshd. Recreating that stack does not preserve live TCP
connections, authentication state, pending buffers, or already emitted
network effects. A future separate network service must declare these losses
or demonstrate an explicit transfer; `netd` is not an implemented boundary.

Multiple servers alone are not a new mechanism or a qualification result.
The distinction to earn is an evidence-backed native contract: who owns
state and authority, how refusal and loss are observed, and what recovery
actually preserves.

## Current trusted boundary adapters

This bounded inventory comes from live platform main
`e70af640f09c7cd1cf293da852bb044e5189311c`, tree
`aa66e79479cd09eeaab422b66f22aa460fa8a8eb`. A manifest dependency and source
import establish each current consumer; historical experiment references do
not. Paths below are relative to that platform repository, inspected in its
development checkout. These revisions are local;
no publication is implied. Evidence paths identify existing checks; they do
not imply that every failure class in the table was exercised.

| Boundary and consumer | Authority and state | Failure obligation and qualification paths |
| --- | --- | --- |
| `absd-net` → smoltcp `0.14.0`; `net/Cargo.toml`, imports in `net/src/lib.rs`; sshd embeds `Stack<NicLink>` in `ssh/src/absd.rs` | `Link`/`NicLink` translates the startup NIC handle, frame calls, and tick time. TCP sockets and protocol buffers belong to the holder process, not kernel socket objects. | Preserve native handle rights, frame bounds, explicit errors, deadlines, and declared session loss on replacement. `net/src/tests.rs`, `scripts/run-net-matrix.sh`; kernel [NETWORK.md](NETWORK.md). Independent network restart is unqualified. |
| `absd-sshd` → sunset `0.6.0`; `ssh/Cargo.toml`, `ssh/src/conn.rs`, `ssh/src/keys.rs` | SSH protocol/cryptography is reused; ABSD owns admission, authenticated session policy, filesystem bindings, child grants, and lifecycle. Connection state belongs to sshd. | Carry and validate `patches/sunset-server-channel.patch`; keep authentication separate from native authority. `scripts/run-ssh-matrix.sh`, `scripts/ssh-matrix.py`, served-boot receipts. This is sunset, not an OpenSSH implementation. |
| Patched Rust `std` → `absd-runtime`; `patches/`, `runtime/src/lib.rs`, `runtime/src/process.rs`, `runtime/src/storage.rs`, `runtime/src/fsd.rs` | Runtime hooks translate startup records, handles, process operations, storage, and time. Foreign API shapes do not grant ambient authority or define kernel objects. | Unsupported operations refuse explicitly; retain startup/ABI/version checks and native rights/refusal semantics. `PATCH_AUDIT.md`, `docs/COMPATIBILITY-LEDGER.md`, `scripts/run-exec-matrix.sh`, `scripts/check-all.sh`. Source compatibility does not establish POSIX or Linux ABI support. |
| SQLite → native ABSD VFS; `sqlite/Cargo.toml`, `sqlite/src/lib.rs`, `sqlite/src/vfs.rs` | Bundled `libsqlite3-sys` is the reused engine. The VFS maps files, locks, and shared-memory interfaces onto `absd-fs`/runtime state; there is no POSIX substrate beneath it. | Preserve the engine's required locking, sync, and error contract under the named storage law. `docs/FILESYSTEM.md` SQLite VFS/failure-model sections, storage/durability cases in `scripts/check-all.sh`. Engine commit and substrate durability are distinct claims. |

Inventory completeness is unproven. This is not a universal TCB inventory,
an assertion that other dependencies are untrusted, or permission to audit
additional surfaces. Each boundary's source, version, patch, native
invariants, failure assumptions, consumer, and qualification remain with its
owning repository. The historical claims matrix (development record, not in a source release)
uses evidence-strength classes and keeps its original pins; ownership
classes do not revise its historical verdicts.

## Networking preserves a replaceable implementation boundary

smoltcp is a bootstrap dependency, not ABSD's architectural identity. Keep
the direction explicit:

```text
application / network API
          ↓
ABSD networking and service semantics
          ↓
replaceable transport implementation
          ↓
NIC / device interface
```

The stable connection, listener, timeout, and authority contract must not
be defined as smoltcp's internal API. Current `absd-net` exposes some
smoltcp types; this constraint does not claim that the separation is already
complete or mandate a wrapper library now. Continue the bootstrap engine
until a measured limit justifies changing it, while preserving an explicit
option to replace the transport without redefining native semantics.

Future measurement triggers include receive-side scaling and multiple
receive/transmit queues; per-CPU/NUMA placement; zero-copy and high connection
counts; pacing and congestion control; checksum and TSO/GSO offloads for
25/100 GbE; interrupt moderation versus polling; and observable admission
and overload behavior. These are questions for a separately admitted
workload and machine envelope, not current driver features or implementation
requirements. The ambition spans embedded machines through server-scale
and hyperscaler workloads. That ambition is neither a support claim nor
an open performance or networking lane.

## Durability and time belong to explicit domains

"Substrate" means the ABSD platform as a whole, including an authorized
userspace storage service. It does not mandate a kernel journal. A reused
engine cannot guarantee more than the substrate's write ordering, atomic
unit, cache-flush, and failure model. Name the device/controller assumptions,
acknowledgement and commit points, uncertain outcomes, and recovery rule.
Separate logical guest-reset/model evidence from physical power-loss
qualification. Current platform `docs/FILESYSTEM.md`, `docs/POWER-LOSS.md`,
and `docs/RELEASE.md` name different bounded claims; do not combine them into
an unrestricted durability guarantee.

Distinguish monotonic time within a boot/clock epoch, wall time, externally
asserted time, and boot/execution identity. An NTP/PTP result is an external
assertion; applying it to clock state and evidence crosses an owned adapter
boundary. It does not automatically establish trustworthy ordering. Durable
commit/version ordering and causal relationships are additional evidence,
not substitute clock readings. [Boot identity and ticks](TERMINOLOGY.md#time) identify an
epoch-local observation; boot IDs do not supply a total cross-boot ordering.
Wall clocks can be unavailable or corrected. A durable predecessor link,
commit sequence, or explicit handoff can establish particular ordering
edges across boots; unrelated events remain partially ordered or unknown.
VM snapshot restore remains outside the current clock-validity model.

## Replacement identity, schemas, and acceptance

A stable logical object/service identity is distinct from its current code
implementation and authority generations. Code provenance uses release and
artifact identities; a runtime instance and transition attempt also need
their stated identities. Preserving a name never revives fenced handles or
authority. Any rebind requires an explicit authorized rule.

Exported replacement state uses versioned schemas, conversion preconditions,
and explicit loss/refusal conditions. A component state schema is part of
its ABI; native Rust layout is not a transfer protocol. Reconstruct authority
through named rules rather than copying opaque memory. Downgrade requires
its own qualification and is not automatically the inverse conversion,
especially after externally visible effects.

Follow [live-evolution principles](LIVE-EVOLUTION.md#principles-any-live-mechanism-must-preserve):
quiesce and fence old execution and effects; transfer or reconstruct only
authorized state; validate the successor; commit or refuse; and retire the
old generation after its consumers depart. Success is decided outside the
component being replaced. Retained old code and a host test do not prove
safe device transfer or post-effect rollback. This direction preserves the
fixed internally componentized kernel preference and userspace drivers/
services where practical; it authorizes no loadable-module default, L3/L4
mechanism, runtime, broker, or replacement supervisor.

## Legibility must be architecturally earned

Design constraint recorded 2026-10-05; future research, not an implemented
execution-domain API, desktop commitment, or additional U1/U2 gate.

**Legibility must be architecturally earned.** Operator tools should reveal
enforced identities, authority, provenance and lifetimes. Presentation cannot
manufacture those facts. The target is an OS whose authority model admits a
comprehensible operator interface, including an eventual desktop.

Bounded execution contexts should be cheap enough to be routine/default,
without requiring expert assembly of an isolation policy. "Cheap" needs a
named workload and measurements of creation, steady-state and retirement cost;
it is not a present performance or isolation guarantee. Existing process/handle
isolation does not by itself establish a workspace or execution-domain contract.
Reuse an adapter where it can preserve the invariant; no mechanism is selected.

The architectural hypothesis requires truthful things to expose:

- A bounded context has logical identity distinct from its implementation
  generation, with enforced membership/boundaries rather than a conventionally
  grouped process list. Placement is an attribute, not identity.
- Authority records identify the grantor, recipient, scope, provenance,
  delegation rules and applicable expiry/revocation contract. Inspection itself
  has authority and disclosure limits; legibility is not unrestricted visibility.
- Borrowed privileged functionality has a named service/generation and narrow
  authorized interface. Elevation does not imply global authority. IPC forwarding
  and service composition must not recreate ambient authority.
- Revocation and retirement expose fencing, remaining holders/leases, cleanup
  obligations and operation disposition. Closing a window is not automatically
  completed retirement, nor does retiring a client destroy a shared service.
- CLI, logs, diagnostics, GUI and possible Constellation consumers project the
  same owning enforcement/observation facts. They identify target generation,
  acquisition/currentness and missing evidence; stale or unavailable observations
  remain explicit. No frontend maintains a competing authority interpretation.

The future elevated-userspace or "mandarin" idea, proposed civild mediation,
and [rump/AnyKernel decomposition](DESIGN-INFLUENCES.md#rump-kernels-and-anykernel-interfaces)
share this pressure: supply useful functionality without making callers globally
privileged. These are hypotheses, not deployed components. Current civild owns
bounded observations, not grants or general lifecycle actuation; the
known semantic expansion (development record, not in a source release)
and institutional-control-plane hypothesis (development record, not in a source release)
retain that separation. AnyKernel research and foreign-ABI personalities do not
establish execution-domain isolation or admit a general service runtime.

Qubes OS is a reference for making domain identity perceptible in ordinary use;
see its [Color & Security documentation](https://www.qubes-os.org/doc/getting-started/).
The ABSD inference is that meaningful presentation needs enforced boundaries
and a trustworthy route from those facts to the operator. Color alone is not
enforcement. No Qubes hypervisor, VM layout, compositor or labeling scheme is
adopted. Security state should remain visible through the normal interface,
including refusal, uncertainty and residual obligations.

Illustrative scenarios for the deferred operator-facing model, not new tests:

| Scenario | Facts the operator should be able to establish |
| --- | --- |
| Open a bounded workspace | Context identity/generation, membership, available authorities and refused resources; no implied access to one global namespace. |
| Borrow an elevated service | Which service is used, for which scoped operation, under whose grant; the caller acquires no global privilege. |
| Close or retire the workspace | Which authority is fenced/expired, which holders remain, and whether retirement completed, was refused or is indeterminate. |
| Replace a borrowed service | Stable logical identity versus new generation; explicit authorized rebind, with no revival of fenced handles. |
| Inspect during a partial failure | Owning facts, observation age and missing evidence; the interface cannot turn an unavailable observation into a successful transition. |

First deliverable: a one-page operator model and three to five concrete
scenarios, naming required facts, owners, observation authority and smallest
missing contracts. Open questions include context membership, cost bounds,
revocation latency, trusted presentation and observation freshness. Do not build
a GUI, workspace manager, new privilege tier or general isolation framework.

Formalization consideration: this is a source-scoped design constraint, not a
claim of enforcement. Existing identity/lifecycle/operation contracts and the
scenarios expose the unknowns; prose is sufficient for capture. An admitted
mechanism must select a bounded model or executable counterexamples for its
membership, delegation, observation and retirement claims. Replacement must
preserve fencing, versioned state/authority reconstruction and external
acceptance; a truthful label proves no hardware or live-generation transfer.
Inspected sources: kernel `85efdcd94df7cf8f83b91c64988841a884736237`,
civild `45b1420c0357800e9d5371f463529318aceafd87`, architecture intent
`742651a3a603ad84705fe0ff78cf856be3c18344`. Result scope is design capture
only, with no runtime qualification. Decision owner: ABSD controller; no model
or implementation lane opens here.

## Preserve semantic intent across subsystem boundaries

Design direction recorded 2026-10-05. DNS is an ontology probe for the
[legibility constraint](#legibility-must-be-architecturally-earned), not a
resolver implementation order. A convenient application request should retain
its intended identity and constraints when another subsystem resolves it into
an operational location. A name, a resolved address, an observed fact and an
authority grant are different things; lowering to an endpoint must not silently
erase the distinctions on which the consumer relies.

The [current network path](NETWORK.md) remains static IPv4/TCP over a NIC
handle. At platform `c54dc90007fe509c0e118b7ec9c6cbd6ea9aa356`, `net/Cargo.toml`
does not enable DNS, and sshd embeds `Stack<NicLink>` rather than calling a
resolver service. No DNS resolver or attributed lookup API is present in the
inspected native consumers. The following is future semantics, not a current
observation facility or a claim of full POSIX networking support.

A future resolver owns the attributed facts it can actually establish:
requested name and observable search rewrites; answer and source; cache versus
fresh acquisition; observed TTL and remaining lifetime with their clock/domain
context; applicable network context; and observed CNAME/delegation steps and
DNSSEC validation state. Retain these only where available. Do not fabricate a
complete delegation chain, upstream acquisition history or validation result
from an endpoint-only reply. Unobservable facts and unknown validation remain
explicit. Fresh, cached, stale, negative and missing knowledge require distinct
context; absence of an observation is not an established negative result.

The native concept is a richer reference: application identity/intent,
resolution observations, their acquisition/currentness context and the
constraints relevant to using them. Retention is bounded, with explicit access
and disclosure rules, privacy costs, expiry and missing-evidence behavior.
This selects no record layout, storage service or new reference ABI. A
compatibility projection, such as a future `getaddrinfo`-shaped result or plain
endpoint list, may discard information; its loss must be named, and it cannot
claim to preserve the richer contract. Application callers should express
ordinary intent conveniently without having to assemble a DNS expert's policy;
the owning boundary remains responsible for honest resolution semantics.

Resolution is observation, not connection authority. A DNS answer does not
grant permission to connect, authenticate a peer or authorize its effects.
Requested network identity, resolved location and independently authenticated
identity/constraints, including a future TLS boundary, remain distinct.
Selection and effect-time authority belong to the authorized network/service
contract, not to an answer's apparent success. A grant scoped to a naming
mechanism is a future hypothesis requiring a real enforcement boundary: an
outbound HTTPS grant alone cannot prove that arbitrary encrypted DNS obeys
that naming route. No such enforcement is claimed here.

The same question applies elsewhere: storage opening lowers a pathname through
a namespace into an actual object under authority; IPC endpoint selection must
identify the actual service generation; device access must identify the device,
authority and lifetime. These are review questions, not new open/IPC APIs.
Logical identity is distinct from implementation generation; resolution or
rebind cannot revive fenced authority. Any future replacement retains versioned
state and authorized transfer/refusal, with acceptance outside the component.

No civild lookup broker, hot-path IPC requirement, `absdnsd`, dependency,
protocol, ABI, milestone or U1/U2 blocker follows from this note. It preserves
the [replaceable network boundary](#networking-preserves-a-replaceable-implementation-boundary)
and admits no implementation or qualification lane. The deferred
semantic-intent planning item (project board)
keeps this review question visible without scheduling resolver work.

Formalization consideration: source scope is kernel
`2c02e124060a6f512842159ee10467c329843715` and platform
`c54dc90007fe509c0e118b7ec9c6cbd6ea9aa356`; result scope is documentation only.
Decision owner is the user's 2026-10-05 semantic-intent direction, recorded by
the integration supervisor. Propositions are identity/location separation,
attributed observations with explicit projection loss, and effect authority
separate from knowledge. Counterexamples are treating an absent observation
as a negative answer or an address result as an authorized authenticated peer.
Practical source inspection and prose suffice for this constraint; no model or
kernel mechanism is introduced. Native reference schemas, observable resolver
facts, freshness/retention rules, privacy budgets and enforceable naming grants
remain unknown until a consumer and contract are separately admitted.

## Shell and operator interfaces

An operator interface adapts user intent to a governed ABSD operation. The
interface owns input and presentation; the operation boundary owns authority,
target identity, preconditions, effect scope, disposition, and evidence.
Its presentation must satisfy the [legibility constraint](#legibility-must-be-architecturally-earned).
CLI, GUI, remote, and automated callers must use the same governed
operations. A frontend does not grant authority or decide whether an effect
committed.

Ordinary command execution composes programs under the handles and rights
already held. Administration changes configuration, keys, service
lifecycle, installed releases, or recovery state and therefore needs
explicit operation authority and named targets. A command's process exit
status is not the operation disposition. In particular, `absd-sh`'s integer
status and session-control replies do not establish the common
`COMPLETED`/`REFUSED`/`INDETERMINATE` contract or a durable receipt.

Bootstrap and recovery need a minimal local entry that can identify the
booted release and readiness, inspect named failure evidence, and reach the
admitted paired-release recovery path when ordinary services or remote
access are unavailable. The existing kernel serial shell boot mode and
platform `absd-sh` are distinct, limited command paths; this direction adds
no kernel monitor or recovery program. A future `absdctl`-style adapter may
present governed administration if it preserves targets, preconditions,
authority, disposition, and evidence.

Use the same operation contracts from local CLI, GUI, remote, and automation
frontends. No frontend may acquire broader implicit rights, map an uncertain
result to success or refusal, or retry a state-changing operation without
the operation's identity and retry/reconciliation rule. Keep management
policy in the owning authority and resource boundaries; do not create a
frontend authority engine.

Where practical, reuse conventional shells and tools through a prospective
limited-authority POSIX personality. That is an adapter boundary, not
ABSD's native process, object, filesystem, or authority model. Source
compatibility does not promise Linux ABI support, and POSIX-shaped calls
cannot create ambient authority or erase a refusal.

A separate control language requires a demonstrated invariant that ordinary
composition cannot preserve, such as a lossy integer status, an untyped
target name that can resolve to a different identity, or missing evidence
for reconciling a lost reply. Record the concrete counterexample and the
smallest preserving adapter or representation first. Convenience or
speculative future use is insufficient. This section admits no new syntax,
shell feature, `absdctl`, GUI, remote automation, or general POSIX port.

## IPC cost must be measured before expanding boundaries

When separately admitted for a named decision, record four comparable
baselines: syscall roundtrip; same-address-space abstraction baseline;
cross-address-space IPC roundtrip; and IPC plus the minimal native authority
check. Report distributions including p50/p95/p99, throughput, bytes/copies,
waits/context switches where observable, resource use, and refusal behavior.
Distinguish warmed and cold-ish execution with explicit preparation, sample
counts, machine/accelerator identity, and kernel/platform/workload revisions.
Use 1-vCPU results and SMP comparisons only where those environments are
separately admitted and qualified. Do not infer SMP from UP or TCG results.

Use the owning campaign's existing receipt mechanism, linked to the
[UP measurement decision](USABILITY-ROADMAP.md#decision-before-any-ap-userspace-admission).
No benchmark, IPC engine, test framework, or implementation lane is opened
by this note. Placement earns its cost through a measured benefit and the
native invariants it preserves.

## Composition from embedded machines to fleets

Additional owner direction, 2026-10-03: preserve authority, logical identity,
generation, retirement, lifecycle and evidence semantics as mechanisms change
from a small one-core machine to many hosts. Fleet scale is a design horizon,
not a support claim. Avoid assumptions that force a global lock, namespace,
metadata root, generation counter or manager without a demonstrated invariant
requiring it. Current bounded tables and the kernel lock remain valid local
mechanisms; this constraint does not order their replacement.

| Possible profile | Mechanisms appropriate to its scope |
| --- | --- |
| Embedded | Small local filesystem and authority implementations, simple networking and few services. |
| Server | Qualified SMP/NUMA placement, richer services and a suitable durable metadata engine. |
| Fleet | Scoped authority delegation, partitioned object/service metadata, placement/migration and hierarchical evidence custody. |

These are conceptual profiles, not implemented configuration modes or a reason
to put fleet machinery on every instance. Declare locality and failure domains:
CPU, NUMA node, host, rack, cluster and region may matter differently. Name
correlated failures and cross-domain dependencies; do not assume a single
nested hierarchy or global agreement for every transition. Stop, quiescence,
reclaim and retirement should have bounded ownership/dependency scopes,
without a universe-wide metadata scan. Namespace partitioning must preserve
identity and authority; a pathname, PID or placement address is not a stable
logical identity. Location is an attribute or binding changed by an authorized
transition. Migration never revives fenced handles.

Failure is a normal input to lifecycle contracts. Local fast-path IPC and a
future remote transport should admit compatible authority and operation
semantics while exposing different reachability, timing and failure evidence.
This does not promise transparent distributed objects or implement remote IPC.

### Outcomes describe operations, not transport status

For a named request and covered effect, the target contract admits:

| Operation disposition | Evidence required |
| --- | --- |
| COMPLETED | The specified effect/postcondition is established under its contract; the result or receipt names that scope. Durability and receipt availability need their own stated guarantees. |
| REFUSED | The covered effect is established not to have occurred. This is a claim about that effect, not a claim that no diagnostic or caller-authorized output changed. |
| INDETERMINATE | Available evidence cannot establish whether the covered effect occurred. Reconciliation may later resolve it; elapsed time alone cannot. |

Connection failure is not operation refusal. Even a local service can commit
an effect and die before replying. Conversely, a completed transport exchange
does not prove the requested effect. The semantic distinction should survive
same-core, cross-core, service, host and region boundaries. Remote uncertainty
must not force a new authority model or be disguised as definitive failure.

This is the semantic mapping of the governor's existing `succeeded`,
`known-not-performed`, `indeterminate` vocabulary in ABSD
`ARCHITECTURE-INTENT.md` §3. It does not replace the kernel ABI's process
termination `Outcome` (`Exited`, `Faulted`, `Killed`) or add a syscall status.
Current FSD status errors/timeouts are not an implemented three-state effect
protocol; a timeout after request transmission is not evidence of no commit.
Existing syscall partial-copyout contracts remain unchanged.

Every future state-changing request contract must distinguish retrying the
same logical operation from issuing another identical-looking operation.
Use operation identity or an equivalent specified rule, with issuer/client
scope, service/authority generation binding, effect scope, and retention of
the information needed to answer retries. Current FSD PID/counter reply
correlation does not establish durable deduplication across boots or services.
An ID alone proves neither idempotence nor exactly-once execution. Define
deduplication lifetime, in-flight duplicates, result loss, expired records and
reconciliation before authorizing automatic retry after INDETERMINATE.

### Coordinate the invariant, within its owning domain

The decision procedure is to name the invariant, permitted transitions,
reachable histories and merge/reconciliation rule. Ask whether independently
valid states from a common ancestor can combine into an invalid state.
If so, local validity alone is insufficient: constrain execution or coordinate
acceptance at the smallest authority domain that owns the invariant. Reconcile
without coordination only where the stated composition preserves it.

[CALM](https://arxiv.org/abs/1901.01930v2) relates coordination-free consistent
computation to monotonicity. [Invariant confluence](https://arxiv.org/abs/1402.2237v4)
examines invariant preservation under independent transactions and merge;
[Bailis's thesis, chapter 3](https://www.bailis.org/papers/bailis-thesis.pdf)
states the common-ancestor criterion. Applying these results to ABSD is a
design method under explicit assumptions, not a proof that its mechanisms
already satisfy them or that arbitrary distributed effects can be reconciled.

| Candidate operation | Invariant-specific question |
| --- | --- |
| Append independent evidence | Can records merge without violating uniqueness, retention obligations, quotas or authority? Append-only shape alone is insufficient. |
| Create unrelated objects | Are identifiers disjoint and shared quotas, naming and ownership obligations still valid? |
| Accept exactly one current generation | Can two successors both act before reconciliation? If yes, require scoped acceptance/fencing; a later winner does not undo earlier effects. |
| Exercise exclusive or single-use authority | Which resource validates ownership, epoch or reservation, including during partitions? |
| Assign a unique human-readable name | Which namespace partition owns uniqueness and its acceptance rule? |

Coordination need does not prescribe a consensus implementation. A single
authorized local owner or preallocated disjoint rights can bound some cases;
replicated owners need their own failure/availability contract. Avoid global
consensus where scoped authority and later reconciliation suffice. Epochs and
fencing tokens only work when the effect boundary actually validates them
against authoritative state; a larger number alone does not revoke anything.
Refusing a stale operation cannot retroactively erase an already applied effect.

### Locally checked authority has a revocation contract

Future delegated grants must name issuer, subject, authority/object/action
scope, authority epoch, validity and local verification inputs. No concrete
grant encoding is selected here. Declare delegation limits, verification cost,
and the retention/freshness assumptions allowing exercise without consulting
a central issuer on every message or lookup.

Offline validation, issuer-independent delegation and partition tolerance
cannot also promise instantaneous issuer-driven revocation everywhere. State
the effective revocation bound X for each authority class, measured from a
named event under declared connectivity and clock assumptions. Finite leases,
epoch changes and propagated revocation state are possible mechanisms, not
implemented guarantees. Distinguish stopping new grants from fencing existing
exercise. If freshness or valid time cannot be established, specify refusal
or loss of availability rather than silently extending authority. A lease
needs clock-domain, drift/skew, suspend/reboot and expiry assumptions; wall
clock ordering does not supply those guarantees.

Existing local handles remain table-scoped capabilities checked by rights.
Closing one copied handle is not fleet revocation; current diagnostic
replacement generations are not authority epochs. This direction changes
neither handle ABI nor current delegation semantics.

### Evidence integrity and availability are separate claims

Bound evidence production and storage. Define observation levels, segment
bounds, aggregation/compression semantics, retention policy, custody and
retrieval responsibility. A summary states what it preserves and loses; it
cannot establish facts that its retained material no longer supports.

Merkle-style segment commitments and identified/authenticated receipts may
compose into higher-level commitments. Under their stated cryptographic and
canonical-encoding assumptions, supplied leaves/proofs can be checked against
a trusted root. A root does not reconstruct deleted details, prove that all
events were captured, or establish that asserted events occurred. Provenance,
integrity, completeness and availability are separate claims. Name who keeps
the material and proofs, for how long and in which failure domain; classify
missing evidence explicitly rather than manufacturing a successful check.
This selects no hash format, signing scheme, evidence service or retention daemon.

### Five constraints for future identity and IPC design

1. Semantic identifiers have room for issuer/domain/scope and collision/reuse
   rules. Today's small local encoding is not the future identity definition;
   no existing ABI is widened by this note.
2. Replacement generations advance per logical identity, without a required
   machine/fleet counter or global ordering. Slot reuse, authority epochs,
   storage versions and clock epochs remain distinct.
3. Wall time is an observation, never the authority or ordering primitive.
   Use causal links, scoped sequences/generations and monotonic time within
   its valid domain; cross-domain order requires additional evidence.
4. INDETERMINATE is legal for local as well as remote operation contracts.
   A definite current API result must not become a blanket no-effect claim.
5. State-changing operations have specified identity/retry semantics; neither
   a repeated message nor a new request ID alone establishes safe retry.

These are review constraints for admitted future designs, not a U1 work order.
No identity migration, ABI redesign, grant service, consensus system, remote
transport, new test or active-lane change follows from recording them.

## Deferred judgment and software lifecycle directions

[Bounded judgments](BOUNDED-JUDGMENTS.md) capture evaluations as evidence,
never authority, under scoped schemas and budgets. Evaluators remain
low-authority replaceable userspace; the note adopts no kernel primitive.
[Governed software lifecycle](GOVERNED-SOFTWARE-LIFECYCLE.md) captures the
distinctions between verified content, admitted transitions, staged and active
generations, independent acceptance, rollback and retirement. Configuration,
secrets and owned data retain separate authority and custody. Both directions
remain deferred, independent of Constellation, and create no U1/U2 blocker,
package/service framework, implementation or qualification lane.

## Formalization consideration

Warranted-belief addendum source: kernel
`8501ff1f28172d70f3dddbaba61da4e55d837713`, and isolated capability report
`9cd2d4372fc377133eaa1382c5f3875564f56764`. Result is this documentation
constraint; decision owner is the ABSD controller recording user direction.
Its proposition is that construction leverage alone does not establish
behavior, and checkable claims should accompany consequential mechanisms.
Counterexamples include agreement on a false model, a test without a
sensitive negative control, or a receipt from the wrong executable. Prose and
source correspondence suffice for the philosophy; no historical, numerical
productivity or model-reliability claim is qualified here. Specific mechanisms
still require their scoped executable qualification. No new lane is admitted.

Proportional-rigor addendum source: kernel
`2a72e73de963390288bb61ce3c2dfcc138732301`; result is this documentation-only
constraint, recorded by the ABSD controller from user direction on 2026-10-05.
The proposition is that authority, mechanism complexity and operator attention
have continuing costs that safeguards must justify against their protected
invariants. Counterexamples include completed procedure without the claimed
safety property, a purportedly cheap change with unknown irreversible effects,
or removal of a checkpoint without preserving its invariant. Practical prose
and correspondence to existing guardrails suffice; no measurable safety model
or universal risk ordering is claimed, and no model is selected. Specific
mechanisms still require scoped qualification; human attention costs and
institutional effects remain contextual, not established numerical bounds.

Decision owner: user architecture direction of 2026-10-03, recorded by the
integration supervisor. Source scope: kernel
`5b05da6bfd317b08a65847f8b293e54ff4a0d6c7`, tree
`e75d7b43a44cc4c3e57a35a80a3ddc79b4ecd377`, and the platform source/tree
identified above. Result scope: this document records constraints and source
inventory, not demonstrated new runtime behavior.

The propositions are separation of semantic ownership from engine choice,
explicit authority reconstruction, bounded restart claims, substrate-limited
durability, and partial cross-epoch ordering. Practical source inspection and
prose are sufficient for this documentation change: it introduces no runtime
state machine or universal preservation claim. No new model is selected
here. Future admitted durable transition claims should prefer small bounded
models with explicit construction correspondence and counterexamples.
Known limits are inventory incompleteness, absent IPC measurements for this
proposal, unqualified independent service/device replacement, physical
flush behavior, conversion/downgrade contracts not yet designed, and
cross-boot relationships lacking an ordering witness. Existing qualification
results keep their original scope and identities.

Scale addendum source scope: kernel `a3cef963daea8c9d6c4995ae6cd5fcd4e26becad`,
canonical platform `e70af640` and ABSD doctrine `fb6b540`; decision owner is
the user's additional 2026-10-03 direction. Recorded counterexamples include
commit-before-lost-reply, two independently accepted successors whose union
violates exclusive current-generation ownership, and a retained root with no
available leaves/proofs. Practical source inspection and these explicit
counterexamples suffice for recording future constraints without a runtime
change. No new executable model is admitted. Actual protocols must separately
model reachable transitions, reconciliation, effect fencing, lease freshness
and retry retention under their chosen failure assumptions. Remote transport,
fleet identity, bounded distributed revocation and evidence completeness remain
unimplemented/unproven; current qualified behavior keeps its existing scope.

Managed lifecycle and interface addendum source scope: kernel base
`c406d803f202f72c5c154da09804c0db3b2e2891`, tree
`aea268ddbacfe3c996e6976486ae50865935aa49`; platform shell source
`4ac76cab82adc1591a2a996292126e765134534b`. The proposition is selective
application of resource-specific transitions and a shared operation
disposition/evidence boundary for managed resources and all frontend forms.
Counterexamples are treating registry absence as retirement, process exit
status as proof of an operation effect, or an incomplete transition without
a valid inspection/deadline rule as complete. The exact resource state
machines, clock domains, obligations, and receipts remain unknown until a
named consumer and failure scope are admitted. Practical prose is sufficient
for this constraint-only change; no transition implementation or universal
state claim is introduced, so no model is selected. Decision owner: the
architecture/qualification owner when a named managed resource or frontend
is admitted.

Storage-profile addendum source scope: kernel base
`afad805353b49b7396e63d035ae881e7e74684c5` and canonical platform
`c54dc90007fe509c0e118b7ec9c6cbd6ea9aa356`; historical platform records
`bb956fcd2b1064a52432a80f8e77480f1f20aae4`,
`4aaef7cbe880b94a48d1a3ae207bc71de17d9ad9`,
`1da6916f11aa5f060e7fdacaa8e42a4d81115aab`,
`ec684259e5f63c121dda8b268550a8e5d04d3ea3`, and owner research receipt
`503807efefe2ee5b112d279b4dc84f057668faba` (producer source
`71d4dadffa922f67c5403675789c5745d6dba617`), path
`docs/native-persistence-engine/EVIDENCE/native-valid-record-regression-1-root-receipt.json`,
SHA256 `cc00ccfc049e969063b3a8e67afd444030a909f03357cdf9244140fa702088ef`.
Decision owner: the user's
2026-10-05 storage direction, recorded by the integration supervisor. The
propositions are consumer-specific profile satisfaction, authority distinct
from qualification evidence, and accepted-generation binding of all
authoritative persistent state. Counterexamples are silently weakening `R`
to fit an engine and accepting a self-checksummed abandoned record as current.
Practical source inspection, existing scoped receipts and prose suffice for
this documentation constraint; no runtime or transition model changes, and no
new model is selected. Future profile schemas, engine construction
correspondence, failure laws, generation-binding representations, migration
and downgrade rules remain unqualified until separately specified and admitted.
