# Bounded ARM64 virtual platform

The source port derives from accepted ARM executable boundary `15651dc`.
Prior exact artifacts remain at custody commit `5b23232`; independent bounded
B1–B4 review is `dfaabb9`. Those evidence/review commits are references, not
ancestors imported into canonical source. This integration requires fresh
qualification of its exact combined source before acceptance.

`make arm64-build` builds the one-vCPU ARM kernel and shared portability task.
`make arm64-smp-build` enables the explicit qualification feature. SMP also
requires matching `absd-arm-smp=2` or `absd-arm-smp=4` boot arguments. Production
x86 AP guards and existing canonical authority targets remain intact.
`ABSD_ARM_BUILD` selects compiler output; qualification outputs use admitted
bulk storage. `make arm64-weak-memory-test` runs the existing bounded model.
`make portability-x86-test` and `make semantic-differential X86_TRACE=...
ARM_TRACE=... DIFF_RESULT=...` exercise the same fixed-width semantic workload.

The platform boundary is QEMU `virt-8.2`, explicit Mac/HVF, GICv2, one/two/four
vCPUs, RAM base `0x40000000`, and the previously bounded RAM/device variants.
GICv3 remains refused. B1 covers synchronization, migration, stop/reclamation
and controlled memory probes; B2 covers the deterministic cross-ISA corpus;
B3 covers normalized user faults, stack growth and exact reclamation; B4 covers
the bounded RAM/virtio placement variants. A0–A3 runtime prerequisites provide
boot/MMU/EL0 and raw block/flush/readback/local Ethernet mechanisms.

B5 is **NOT STARTED**. Raw sector device checks are not filesystem format or
cross-ISA filesystem qualification. No physical ARM, arbitrary platform, served
boot, release, unbounded SMP/memory-model or live-generation transfer claim is
created by this source port. Context/frame representation stays ISA-local;
generic process/object/handle/authority policy consumes semantic accessors.
No exported replacement state schema or authority-rebinding rule is added.

Architecture/research campaigns that may outlive their starting canonical base
must receive an isolated branch and worktree at campaign inception. This keeps
accepted executable source, evidence custody and later canonical integration
as distinct boundaries. No branch-management framework is required.
