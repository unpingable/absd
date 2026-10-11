# ABSD usability roadmap after the kernel-only AP gate

The [system maturity map](SYSTEM-MATURITY-ROADMAP.md), captured 2026-10-06,
places current evidence and gaps under System R0–R7. It preserves this
document's usability U1/U2 gates and the separate Userland U0–U6 scope.
It is planning only and promotes no release, hardware or maturity acceptance.

The separate [userland/component roadmap](USERLAND-COMPONENT-ROADMAP.md),
captured 2026-10-06, uses the explicit namespace **Userland U0–U6**. Its Project
planning leaves this document's usability U1/U2/U3, operating gates and release
boundaries unchanged and starts no implementation or qualification campaign.

This is a sequence of **qualification decisions**, not an activation plan
for AP userspace. The bounded RT gate (`8bc81ef`), UP handoff preparation
(`a8f2691`), and kernel-only AP serialization/lifecycle gate (`0b73cd6`)
are closed within their respective receipts. CPU 1 exists only for fixed
CPL0 fixtures; its executable ordinary/RT user-return refusal remains in
force. Served-boot survival and install/update/recovery are now qualified
for the exact local release scope recorded in
the integration receipt (development record, not in a source release).
That result does not establish multiweek named-machine U1 operation or
independent lossless service restart. No later milestone follows automatically.

The [ownership boundaries](OWNERSHIP-BOUNDARIES.md) describe the target
semantic architecture, not implementation priority. U1 remains the current
product milestone. Introduce native subsystems only for a demonstrated U1/U2
invariant blocked by the current implementation or a separately admitted
bounded architectural experiment. The authority/IPC/lifecycle/storage
dependency graph opens no new lanes. Eventual IPC measurements attach to
existing qualification receipts and do not authorize optimization work.

## Decision before any AP userspace admission

Measure the current **UP** system first. Establish a KVM performance and
concurrency matrix for the named ordinary, file-server, network, and RT
workloads, with workload inputs, machine identity, image/kernel/platform
revisions, and comparable latency/throughput counters. Identify an actual
UP bottleneck and decide whether SMP addresses it. Further AP userspace
activation or SMP-scale investment needs that measured need decision; the
earlier correctness preparation did not require a performance-need proof.
The current HEAD's supported machine envelope is **unknown until
inventoried**; do not infer
hardware support from QEMU device names or an older survey. QEMU TCG runs
establish structural entry/transition behavior, not native multicore
memory-order correctness. `/dev/kvm` is absent in the current sandbox
qualification namespace, although KVM access has been confirmed in the host
context. The required KVM or exact-hardware matrix has not yet run for this
gate and remains a prerequisite before the AP userspace guard can be removed.
That later gate also needs its own
ordinary concurrent userspace, stop/reclaim, idle/tick, device, and CPU0-only
RT qualification. The kernel-only AP result does not grant it.

## U1: named-machine sustained usability

U1 targets a named machine that can be administered, updated, backed up,
and recovered **without a build host in its normal operating path**, and can
run for weeks under its documented limits. Choose the exact hardware and
enumerate its timer/LAPIC, console, NVMe, NIC, and
memory behavior before making a support claim. Keep the U1 path valid on
UP unless the measured decision above justifies a separate AP userspace
gate. The workstreams below describe dependencies, not a calendar or a weekly
maintenance obligation.

| Workstream | Work and observable exit condition |
| --- | --- |
| Served-boot lifecycle | Run restart of sshd and fsd, a second boot from the same durable image, and hundreds-of-session churn. Record process, pipe, channel, and filesystem-object baseline/return counts; print exact capacities and refuse full tables by name. Bound pre-authentication resources by source, fix/qualify the interactive TCP idle timeout, and measure orphan residue after forced session ends. Use that experiment to decide whether a sponsor/object-kind seam is necessary; do not add one by presumption. Qualify the file-server BIND keeper-departure fence on its own exact platform revision before claiming slot authority across abrupt keeper death. |
| Thin administration | Provide the smallest native commands for configuration read/write, host-key rotation, lifecycle control, and explicit limits. Show logs, wall time, uptime, DNS/NTP status, minimal process/device status, and named exit causes. Refused writes and missing time/network inputs must be explicit. Keep the interface tied to current ABSD handles and rights; no general service or package framework. |
| Paired update and rollback | Install a kernel image and runtime together with an explicit version compatibility check that refuses a mismatched pair before booting the new runtime. Qualify a previous-pair rollback after failed update and power loss. Decide and test filesystem-format migration and file modification time if either is absent, including refusal of an unsupported image. Reconstruct the release from a reproducible toolchain pinned to real upstream `rust-src`; a development host may produce a release, but routine operation must not require it. |
| Backup, restore, recovery | Define a halted-image backup boundary, restore that image to the same named machine class, and demonstrate a fresh reconstruction from release artifacts and documented configuration/keys. Qualify restart after sshd/fsd fault or stall, second-boot mount, login, and explicit failure diagnosis. State what data is durable at each checkpoint and which credential material needs separate custody. The operator should be able to restore the previous known-good kernel/runtime pair without compiling on the target. |

Capacity claims must name the exercised boundary. The served local VM case
reaches the four-connection SSH limit, observes prompt refusal, and serves an
authenticated connection after a slot is released. The default non-served
boot suite separately exercises process, handle, cell, and pipe full-table
refusal and immediate reuse. The fixed limits are 16 processes, 64 handles
per process, 32 cells, 48 pipes, and 11 file-server channels (one control
and ten client slots); the accepted unauthenticated SSH source limit is two.
Printed limits and instantaneous resource censuses do not prove that every
kernel table was exhausted during served operation. Frame ownership checks
do not establish frame exhaustion.

At the U1 exit, record sustained multiweek operation of the exact paired
release on the named machine, including normal administration and recovery
from the qualified fault cases, then rerun the workload and capacity cases.
Scale a table, queue, or driver only in response to a
measured bound. A passing local VM is useful evidence for a local VM, not an
unqualified physical-machine support claim.

## U2: native Constellation workloads

After U1's operating path is stable, qualify Pulse, NQ, Nightshift, AG, and
Docket as **native ABSD workloads**, including their process/handle,
storage, restart, and observation needs. Record the smallest missing native
primitive demonstrated by each workload and its authority boundary; change
the kernel or runtime only for a named consumer and a measured qualification
case. Do not build a parallel Linux-shaped interface merely to run a twin.
Keep each workload's release and recovery evidence tied to the paired image
and the same named-machine envelope.

## U3 and separate research

U3 is deferred until U1 and U2 have concrete operating receipts. It carries
no current implementation or operator action. SMP beyond measured need,
governed RT grants/admission, sponsorship/subtree policy, formalization
beyond focused transition models, and wider authority design remain separate
research decisions, not implicit U1 dependencies. No general hardware
matrix, heap/dynamic-table expansion, package manager, service framework,
or broad operator workflow is authorized by this roadmap.

The deferred [bounded-judgment direction](BOUNDED-JUDGMENTS.md) and
[governed software lifecycle](GOVERNED-SOFTWARE-LIFECYCLE.md) record semantic
constraints, not additional U1/U2 workstreams or blockers. The general package
manager remains P4. ABSD is independent of Constellation; future evaluators
and package mechanisms require separately admitted consumers and contracts.

The deferred [operator-facing authority/isolation story](OWNERSHIP-BOUNDARIES.md#legibility-must-be-architecturally-earned)
starts with a one-page model and three to five scenarios. Legibility must be
architecturally earned; this adds no GUI, execution-domain implementation,
privilege tier or U1/U2 blocker, and does not admit existing AnyKernel research.

The deferred [semantic-intent direction](OWNERSHIP-BOUNDARIES.md#preserve-semantic-intent-across-subsystem-boundaries)
uses DNS as an ontology probe: retain identity, attributed observations,
currentness and explicit projection loss without confusing knowledge with
authority. It opens no resolver/service, protocol, ABI or U1/U2 milestone.

ABSD's `ARCHITECTURE-INTENT.md` now clarifies that "substrate" means the ABSD
platform as a whole, not necessarily the kernel. Userspace FSD may provide
durability when its authority and commit contract are sufficient; claims
remain bounded by the storage substrate. This adds no kernel API or U1 dependency.

The [storage-engine/profile direction](OWNERSHIP-BOUNDARIES.md#storage-engines-and-consumer-qualification-profiles)
keeps ABSD semantics above replaceable engines and admits each engine only for
consumer requirements its qualified profile satisfies, with explicit refusal
otherwise. Native persistence is one implementation, not a requirement for all
volumes. Current `absd-fs` format-2 release qualification remains unchanged;
new profiles, engines, rump/foreign adapters and 9P gateways remain separately
admitted future work, with no native-API selection or U1/U2 blocker.

`docs/MATURITY-BACKLOG.md` records the mature-system questions ABSD has not
yet answered, in priority classes. Its rule: record and cross-link; open no
work from P2, P3, or P4 unless a current tranche explicitly triggers it.

`docs/LIVE-EVOLUTION.md` records live evolution and replacement (userspace
component replacement, bounded kernel patching, component-graph and
whole-kernel generation replacement) as separate future work. The Paired
update and rollback workstream is reboot-based and does not depend on it.
