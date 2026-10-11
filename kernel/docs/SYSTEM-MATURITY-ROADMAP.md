# ABSD system maturity: toward an ordinary, maintainable host

Owner-requested planning reconciliation, 2026-10-06, run
`1df4caa4-2230-4312-95a7-6a8c9a5f246c`. Execution ownership, status and
priority remain in the ABSD Program project board.
This is a capability/acceptance map, not implementation admission, a new
qualification campaign or a change to accepted releases. Ordinary operation
should become boring within declared hardware, failure and resource limits.

## Current evidence and distinct namespaces

Inspected local kernel `7fda64f3377d5ff28c6e670a5991a1222a4e56b4`, platform
`60388b066fb341715ddea9773eac3f6c7d8da53a`, coordination
`74196728e2057efaf7bfc8e5ab86b3dcf858225a`, architecture
`742651a3a603ad84705fe0ff78cf856be3c18344`, repository issues and all 49
pre-existing Project items. Local source is not automatically published or
release-qualified. The accepted/sealed `absd-20261003.1` remains exact kernel
`fcfbab9867da40eebb0c4dd266b82484ae7e76c5` / platform
`c54dc90007fe509c0e118b7ec9c6cbd6ea9aa356`, with previous `.3`, failed
occurrences, actual accepted-B-to-A rollback and reconstruction exclusions
preserved. Newer accepted component work is not a newer accepted release pair.

The existing [usability roadmap](USABILITY-ROADMAP.md) owns usability U1
(weeks on a named machine without a build host in normal operation) and U2
(native Pulse/NQ/Nightshift/AG/Docket workloads). The separate
[Userland U0–U6 roadmap](USERLAND-COMPONENT-ROADMAP.md) owns software lifecycle,
base composition, closures, catalogs and development/self-hosting. **System
R0–R7** adds a maturity lens; it renames neither namespace and adds no new
mandatory gate to their established scope. The categories overlap: existing
cross-compilation can advance before all maintainability work closes.

Evidence words retain their exact scopes: implemented, locally validated,
independently accepted, release-qualified, blocked, planned, and speculative
are different. A completed scoped component item is not an entire R-level
completion. No R-level is promoted by this document.

## Maturity ladder

| Level | Observable acceptance direction | Current reconciliation |
| --- | --- | --- |
| R0 — boots reliably | Identified boot media/kernel/platform reaches the stated native operating entry on its named environment, with useful failure diagnosis. | Existing boot/loader/isolation foundations and exact local release are evidence. Physical survey and controller preparation have narrower receipts; no new R0 campaign. |
| R1 — survives | Declared persistent state, process isolation, bounded resources, shutdown/reset and ordinary failure recovery remain correct on the stated machine/failure model. | Served UP fault cases recover by whole-machine reset. Local release capacity/recovery and scoped SMP/FPU/RT/ARM integration are retained. Physical faults/durability/timing and production AP admission remain distinct open gates. |
| R2 — inhabitable | An operator logs in, uses a coherent toolbox and persistent home, inspects time/network/storage/services/logs, administers bounded configuration and returns cleanly to service. | SSH, shell/PTY, native commands, home state, static IPv4 and bounded logs exist. Existing usability U1 is the exact-machine/weeks acceptance home; normal boot/admin and missing status/time/network contracts remain gaps. |
| R3 — maintainable | An admitted system/config/software generation can be staged, activated, observed, recovered or rolled back within its contract without bespoke host surgery. | Exact reboot-based paired release operations are accepted locally but remain host-side. Reuse Userland U0–U3, on-box administration, release trust and recovery items; configuration and essential-service operating contracts need explicit homes. |
| R4 — programmable | A moderately ordinary Rust CLI targets the documented interface/sysroot and runs without application-specific source changes; failures name missing facilities. | Restricted Rust std/CRT/target and unchanged-source ports exist, with measured divergences. Reuse interface v0 and Userland U4; stable SDK, compatibility policy, symbols/debug/test contracts remain decisions. Native compilation is unnecessary. |
| R5 — self-developing | Admitted native tools operate on source/temp trees, spawn build/link/test work, and honestly produce/run a small project using `ABSD$ cargo build`. | Userland U5, Later; no native compiler/Cargo capability is claimed. |
| R6 — self-hosting | An independently reproducible native build produces explicitly named ABSD userspace/base products, possibly images later, under exact input/output identity. | Userland U6, Later. Existing host reconstruction is seed evidence, not native self-hosting or byte-identical whole ISO proof. |
| R7 — boring | Months of unattended operation on a declared host envelope, clean reboot, bounded service/storage/network failures, interrupted-update recovery, rollback, retained state/evidence and remote inspection without routine archaeology. | North-star acceptance state inside the umbrella, not one implementation issue, deadline or current support claim. |

## Evidence-backed capability map

| Capability | Existing path/evidence | Missing decision/work home |
| --- | --- | --- |
| Base system | Platform native commands, shell pipes/redirection, argv/env/cwd and standard streams; SSH PTY line discipline. | Reuse Userland U0/U1; document composition, temp/scripting/path limits. No POSIX promise or one-card-per-command list. |
| Process/service lifecycle | Kernel init starts embedded FSD/sshd, waits/reaps and applies served readiness/shutdown/reset behavior. Controlled FSD/SSH failure receipts validate reset, not transparent service restart. | Essential-service operating contract below; existing deferred service-generation item owns later independent replacement. General manager stays evidence-gated P3/P4. |
| Identity/authority | Generation-tagged handles/rights and channel mount bindings; one SSH operator authorization set, protected host identity and no Unix account separation. | Existing authority-legibility item owns the broader human/service/credential/delegation/secret/ownership model. Service/config cards name actual grants and machine/installation identity; no uid/root grant or new privilege tier. |
| Networking | Kernel frame/NIC grants; userspace smoltcp static IPv4/TCP/ARP/ICMP in the NIC holder; `/etc/network.conf` is read at startup. | Administered-network contract below: static configuration/status/failures first, DNS/DHCP/routing/runtime/TLS policy staged only when facilities are earned. |
| Storage | Userspace FSD owns writable block authority, format-2 namespace, mount lists and capacity; host tools operate on accepted images. | Existing administration, power-loss and storage-profile items: exact device/volume discovery, mount/activation, capacity/metadata/access, refusal/restore and bounded diagnostics. No repair utility, removable-media lifecycle or snapshot engine exists by assumption. |
| Time | Kernel delivered ticks with boot epoch; RTC is interpreted as UTC whole seconds, refusals exposed; date/uptime and filesystem mtime exist. | Explicit clock/time infrastructure contract below. No RTC correction, timezone model or NTP facility is implied. |
| Observability | Typed info/pipe/census/NIC fields; console fault markers; bounded FSD/SSH file logs and drop accounting. | Native observation/failure contract below: identity/currentness, bounded persistence and local/machine consumers. General crash archive, debugger, trace/profiler are not established. |
| Boot/install/recovery | GRUB/UEFI media and local halted-image install/stage/select/backup/restore; active exact-USB Linux controller lane. | Normal native boot/recovery path below, after current exact-hardware owner gates; no physical installer/write authorization or native USB driver follows. |
| Updates/releases | Manifest/digest plus exact kernel/FSD/app/fs versions, fixed-per-boot `/bin`, preserved site state, accepted A/B rollback and explicit migration refusals. | Existing on-box administration, release authenticity and Userland lifecycle; investigate shared transition semantics, signatures/channel/downgrade/fallback and interruption handling without replacing the existing release unit. |
| Configuration | Startup parses network/SSH files; immutable release content is separate from site config, keys and mutable data. | Configuration generations below: desired/actual identity, validate/admit/materialize/activate/receipt, overrides, migration and honest rollback. Files remain possible interfaces. |
| Compatibility | Native platform/runtime, restricted std successes/ledger; narrow freestanding SQLite C helpers; kernel foreign-ABI and anykernel research items. | Extend existing interface-v0 planning with compatibility rings below; no new porting epic or native Linux semantics. |
| Development | Pinned Rust target/std/sysroot/wrapper/runtime and linker rules, source compatibility probes, host/QEMU test machinery and exact reconstruction receipts. | Reuse Userland U4/U5/U6; interface-v0 owns stable SDK/versioning and bounded symbol/debug/test expectations. No new debugger/toolchain issue until a concrete consumer needs implementation. |
| Hardware breadth | Named x86 VM/device and physical-survey/controller records; independently accepted ARM B1–B4 VM port, B5 not started. | Existing hardware cards and bounded support view below; diagnostic framebuffer is separate from deferred graphics. Audio/workstation breadth does not gate server maturity. |

Primary evidence: served survival (development record, not in a source release),
paired release successor (development record, not in a source release),
RT correspondence (development record, not in a source release),
ARM integration (development record, not in a source release),
[network](NETWORK.md), [startup](PROCESS-STARTUP.md),
[terminology](TERMINOLOGY.md), interface v0 (development record, not in a source release),
[maturity backlog](MATURITY-BACKLOG.md), [ownership](OWNERSHIP-BOUNDARIES.md),
physical handoff (development record, not in a source release) and
[graphics direction](GRAPHICS-DIRECTION.md). Platform source at the identity
above: `net/src/lib.rs`, `ssh/src/absd.rs`, `ssh/src/oplog.rs`, `fsd/src/log.rs`,
`src/bin/date.rs`, `runtime/src/lib.rs`, `docs/FILESYSTEM.md`,
`docs/POWER-LOSS.md`, `docs/RELEASE.md` and `docs/COMPATIBILITY-LEDGER.md`.

The filesystem's earlier host/guest power-loss device-law tests cover stated
flush and aligned-unit assumptions. They are real evidence, not a physical
drive guarantee. The accepted paired-release operations have their own
halted-image/logical durability bounds. Keep both scopes; do not claim either
proves the other's failure model or reopen accepted work merely for a new name.

## Essential-service operating contract — R2/R3

Inventory actual init/FSD/SSH startup order, identity/generation, grants,
readiness versus liveness, ownership, fault/stall, draining, shutdown and reset.
For each transition name the trigger, responsible owner, observable reason,
bounded next state and retained evidence. A failed FSD must lead to deterministic
inspectable behavior within the chosen scope; existing whole-machine reset is
a valid current answer. Pre-ready refusal must not become an opaque reset loop.

Proposed design acceptance: a source/evidence-backed operating table and the
smallest missing operator query/diagnostic contract. Any later change must
exercise only demonstrated gaps. Independent service restart needs actual
quiescence/fencing, state/authority reconstruction and outside-successor
validation under the existing deferred service-generation item. Dependency
orders are explicit and bounded; dynamic unit registries, general timers/jobs,
systemd semantics and automatic restart policy engines remain Later/unselected.

## Configuration generations — R2/R3

Investigate an explicit native contract:

```text
desired config -> exact identity -> validate -> separately admit
               -> render/materialize -> stage -> activate -> observe/receipt
```

Begin with a named consumer such as existing network/SSH configuration, not
every mutable file. Decide typed schema versus bounded opaque component input,
version/canonicalization, owner, materializer, validation policy, immutable
generation identity, local override precedence, drift/currentness, restart or
reboot requirement, concurrent-writer serialization and transition commit point.
Secrets stay separately owned and protected; a config receipt does not contain
private material or grant access. Distinguish desired and observed active state.

Proposed design acceptance: current startup consumption and a two-generation
transition/refusal/reconciliation table, including invalid input, old schema,
partial rendering, stale preconditions, loss around activation and unavailable
services. Rollback may restore an admitted prior config selection but not undo
data migration or externally visible effects. State conversion/loss/refusal and
authority reconstruction are explicit. Reuse software/system semantics where
they fit; do not select a declarative DSL, central policy daemon, global
transaction coordinator or native `/etc` replacement implementation here.

## Time infrastructure — R2/R3, also R4–R7

Reconcile RTC UTC interpretation, monotonic delivered ticks and boot epoch,
unreadable/invalid time, reboot/snapshot discontinuity, persistent timestamps,
timezone presentation and correction authority. Specify precision/uncertainty,
step/slew policy when correction is earned, deadline behavior and no implicit
ordering/authority from wall time. Existing mtime presentation is a separate
card; missing RTC evidence must not be printed as trustworthy time.

Proposed design acceptance: one current/future clock contract and consumer
matrix covering logs, config/component/release freshness, signature validity,
TLS certificates and deterministic build timestamps. Name behavior without
synchronized time and without connectivity. NTP/time service follows earned
network transport and policy; it is not present because RTC/date works.
Reproducible builds use explicit timestamp inputs, not live NTP. Do not change
the scheduler/timer or add a kernel wall-clock adjustment API by assumption.

## Administered networking — R2/R3

The [future networking direction](NETWORK.md#future-architecture-direction--2026-10-07)
selects VirtIO/QEMU first, then shared native PCI/DMA substrate, one native NIC
preferably under passthrough/VFIO, and bare-metal acceptance last. Current QEMU
e1000 remains the implemented path. This ordering adds no filesystem blocker or
near-term native-NIC milestone.

Separate exact driver/link evidence from address configuration and usable
operator networking. Start with current static IPv4, prefix/default gateway,
interface identity, link/disabled state, finite connection limits/timeouts,
startup config failure and status/refusal. Account for who owns the NIC/stack,
configuration activation and the effect on an operator's remote connection.

Proposed design acceptance: source-backed current operations/status matrix and
bounded desired/actual config transition, including missing NIC, wrong config,
link loss, address/route change and unreachable management. Stage DNS timeout/
cache/currentness, DHCP lease/expiry, routing breadth, hostname, application
connection interfaces, TLS trust roots/time and later firewall/policy as explicit
facilities/dependencies. Current stack has no UDP, DNS, DHCP, general std::net
or native kernel sockets. Do not promise these by layering new CLI syntax.
The existing DNS ontology probe is separate deferred semantic research, not a
resolver implementation or a blocker to useful static networking.

## Native observations and failure handling — R2/R3

Define the minimum structured facts an operator needs: boot/system/component
identity, service/process state and fault/exit causes, readiness, actual grants
within disclosure authority, limits/resource accounting, memory/storage/network
and exact device status. Facts carry owner, generation, observation epoch/time,
freshness and loss/unknown state; snapshots are not permission guarantees.

Inventory existing typed ABI/runtime observations and bounded log queues,
rotation/drop behavior. Define bounded durable fault/critical record needs and
their commit/failure model, retention/export custody, capacity refusal and
behavior when FSD or networking is unavailable. Console output is useful
diagnosis, not a durable machine-readable interface by itself.

Proposed design acceptance: a native observation schema/ownership matrix and
3–5 operator questions with exact fact sources, gaps and local plus optional
remote presentation. Reuse current log/source facts, not a new metrics daemon,
`/proc` clone, unconditional census disclosure or a general core-dump/tracing
framework. Later tracing/profiling/debugger work requires a named consumer.

## Normal boot, install and recovery — R2/R3

Distinguish the active Linux USB qualification controller from an installed
native ABSD host. It is a test controller, not proof of native networking or
routine boot. Reconcile exact firmware/GRUB path, reproducible media, system/site
initialization, boot configuration, known-good generation, pre-ready refusal,
fallback and a deliberately small recovery environment. Routine operation's
acceptance must not require F9/manual media selection or an attached build host.

Proposed design acceptance: one source/evidence-backed supported-host state
table covering cold boot, clean reboot/shutdown, unusable config/key/storage,
failed activation, interrupted update and loss of management connectivity,
with explicit observer, fallback/refusal and recovery obligations. Current
halted-image install/restore remains seed evidence; future physical provisioning
needs its own exact-device authority and qualification. No disk write, firmware
mutation, new installer, native USB stack or automatic boot fallback is admitted
here. Remote provisioning is Later. Hardware ownership/gates stay unchanged.

## Candidate shared lifecycle semantics, not one implementation

Explicit design question: **which semantics should software components,
configuration generations, services and whole-system updates share, and which
must remain distinct?** Put the comparison in this umbrella and existing
Userland U0/deferred service design; create no general lifecycle engine issue.

Candidate common envelope: logical identity and exact generation/provenance;
validation separated from admission; named owner/grants and preconditions;
custody/staging distinct from activation; explicit commit, operation identity,
COMPLETED/REFUSED/INDETERMINATE; independent post-state observation; receipts,
honest rollback and reference-aware retirement/GC. Manifests/config declarations
are inputs to trusted authorized construction, not grants by themselves.

Distinct contracts remain: software bytes/dependency closures and launch
binding; config schemas/overrides/materialization/drift; service readiness,
in-flight requests, versioned state/authority reconstruction and quiescence;
whole-system kernel/runtime/fs compatibility, firmware/boot selection and
migration. There may be different commit points and recovery units. No global
atomicity or post-effect inverse is promised. Stable logical identity never
revives fenced handles; external successor assessment and generation retirement
remain required. Live kernel evolution is a present architectural constraint,
with L3/L4 mechanisms still deferred. Current reboot-based L0 is valid.

## Compatibility rings and development contract

| Ring | Current/intended disposition | Boundary |
| --- | --- | --- |
| ABSD native | Intended, implemented subset; interface-v0 specification remains planned. | Native handles, spawn/wait, authority, storage, error and lifecycle semantics own correctness. |
| Rust std/source | Intended portable source subset, experimental restricted target and measured unchanged-source successes. | Unsupported facilities stay explicit; build scaffolding differs from application source changes. Reuse compatibility ledger and Userland U4. |
| POSIX source/libc | Broad layer explicitly deferred P4; narrow real-consumer adapters/SQLite helpers are explored/implemented within their scopes. | No full libc, fd, fork, signals, threads or POSIX conformance is claimed. Unix object models are not native defaults. |
| Unix ABI | No general native Unix/FreeBSD binary compatibility selected. | Earlier FreeBSD governor portability is a distinct historical surface, not ABSD-native ABI support. |
| Linux binary | Explicitly deferred P4, bounded service-personality design explored in kernel issue #2. | Native translation, selective LKL facilities and a full Linux VM control are hypotheses/alternatives, not installed support or a required kernel personality. |

The rejected architectural shortcut is letting incidental Unix/Linux assumptions
redefine native authority, object or error semantics. This does not reject every
future bounded adapter. Unsupported compatibility returns honest refusal; no
fake success or silent number forwarding. Each promised boundary needs current
consumers, exact compatibility/version/refusal rules and shared conformance
vectors when it becomes a normative cross-repository format. Retired WLP is
not reintroduced. Rump storage research and anykernel/foreign-ABI issues keep
their distinct scopes and do not gate native server maturity.

Interface-v0 planning also owns SDK/sysroot/runtime/linker/version discovery,
symbols and the smallest meaningful debugging/test-runner interface. Host-side
ELF/disassembly/serial/probe tooling does not prove an on-target debugger.
Select a debugging requirement only for an actual application/service failure;
define authority and observation effects before any attach mechanism. Native
Cargo/rustc and self-hosting remain Userland U5/U6, not new implementation cards.

## Bounded hardware-support view

Server/appliance viability: exact CPU/memory/firmware/PCI discovery, timer and
interrupt path, supported storage with declared failure/flush/reset behavior,
one exact NIC, useful early framebuffer/console, power/reboot and independent
recovery observation. These are eventual exact-host acceptance requirements;
native networking follows the virtualized architecture and passthrough stages,
not current storage work. Existing cards own these. The active Z2 controller
reports onboard I219-LM `8086:15b7`; the older physical-target I219-LM card is
`8086:15bb`. They are different device targets. QEMU e1000 `8086:100e`
does not qualify either. Keep read-only physical observations, controller
local-VM validation, independent preparation review and native physical
acceptance separate. No surveyed machine earns family support by model name.

Workstation viability is separate Later work: input ownership/keyboard/pointing,
userspace display/graphics, interactive tooling and possibly audio. A generic
USB stack, removable-media/hotplug, additional NIC/storage families, broad ACPI,
suspend/resume and physical additional architectures are evidence-gated, not
implicitly required. Diagnostic framebuffer output must remain available
independently of a future compositor. ARM VM B1–B4 is accepted source work;
GICv3, physical ARM, B5 filesystem admission and served ARM release remain
outside that claim. No new hardware implementation/support epic is created.

## Dependency leverage and near-term recommendation

This is a partial-order map, not a requirement that every category execute:

```text
existing exact release + current hardware owner gates
    -> normal reachable boot/recovery -> thin on-box administration -> sustained U1

existing storage/runtime/authority
    -> essential-service operating contract + bounded observations
    -> inspectable local host operations

Userland U0 -> U1 -> U2 -> U3 (existing software roadmap)
        \-> configuration transition comparison -> maintainable generations
           (services/system updates keep their own commit/recovery contracts)

interface v0 + Userland U4 -> earned native facilities + U5 -> U6
sustained usability U1 -> native Constellation workload usability U2
```

Networking, time, identity, observations and boot/recovery intersect multiple
edges. Static networking can be useful without DNS/DHCP; accurate time-dependent
trust/freshness needs an explicit time contract; NTP needs earned transport.
Cross-development already works before R3 is complete. Stateful service restart
does not block the stateless native-cat proof or current whole-machine recovery.

1. Respect the existing physical controller/operator and exact-hardware gates;
   the next accepted reachable host path is not another speculative SMP/BKL run.
2. Refine the smallest essential-service/observation/time/network operating
   contract from current UP served behavior, then use existing on-box
   administration after its exact-hardware prerequisite. Show actual status,
   bounded logs, static config and explicit missing/unknown time/network inputs.
   These are planning decisions, not parallel implementation dispatches.
3. First software-lifecycle implementation tranche remains existing Userland
   U0 plus native `cat`; base composition follows its accepted contract. Compare
   software/config/release transitions before choosing reusable machinery.
4. Earn bounded config generations and native operational updates/known-good
   recovery at their actual consumers; use existing release authenticity and
   power-loss gates when their scope is required, without borrowing host-law
   evidence as physical proof.
5. Record sustained exact-machine usability U1, then native Constellation
   workload/observer evidence under existing U2. R5–R7 remain Later/north-star.

## Constellation, reconciliation and formalization

ABSD local boot, recovery, administration, authority and receipts must work
without Constellation. Pulse/NQ/Nightshift/AG/Docket are existing native consumer
workloads, not a new observer-daemon project. Optional consumers can read host
observations, component/config/release identities, activation receipts,
health/status and failures under their own authority. An observation or remote
judgment is not an activation grant. Cartography owns cross-project mapping,
not execution or component acceptance.

No duplicate Userland R5/R6 issues, utility issues, R0/R1 campaigns, graphics/
audio prerequisites or general service manager are opened. Date-scoped hardware,
SMP, served-survival and backlog language can predate later accepted work;
current controller/source records delimit scope without rewriting old receipts.
The existing interface-v0 note is already in canonical source, so its older
"when merged" pointers are documentation references to reconcile, not an open
merge task. Existing Done/Limited, Candidate/Qualification and blocked hardware
states remain distinct even when another later item records narrower acceptance.

Formalization consideration: source identities are recorded above; result
identity is this document's Git commit/blob and the hashed mutation/readback
records in the coordination run. Decision owner: ABSD architecture owner,
with platform/release/storage/kernel owners retaining their contracts. This
planning asserts scope distinctions and proposes acceptance, not proven runtime
behavior. Prose/source inspection is sufficient here. Later configuration and
shared-lifecycle decisions should consider a small bounded model of two
generations, one concurrent writer, the named commit/failure points and observed
desired/actual state, with construction correspondence. Counterexamples include
commit before lost reply, partial materialization, stale grants/schema,
reboot/epoch ambiguity, unflushed state, deleting rollback custody, and selecting
old bytes after an irreversible effect. Such models cannot prove hardware
durability, arbitrary service/kernel transfer, months of uptime or universal
source compatibility. No model or qualification is started by this capture.
