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

The platform boundary is QEMU `virt-8.2`, explicit Mac/HVF, GICv2 or GICv3,
one/two/four vCPUs, RAM base `0x40000000`, and the previously bounded RAM/device
variants. GICv3 (2026-10-09): the tree's `arm,gic-v3` node selects a
system-register CPU interface (ICC_SRE/PMR/BPR1/IGRPEN1, IAR1/EOIR1, SGI1R),
one redistributor region whose per-CPU frame is found by affinity in
GICR_TYPER and woken through GICR_WAKER, the local interrupts (virtual timer
PPI 27, SGIs 1 and 2; no SPI is used) in group 1 and enabled per CPU, and
the distributor with affinity routing and group 1 enabled, an explicit
priority for each local interrupt and EOI mode 0; GICD_PIDR2 must say
architecture revision 3. GICv2 programming is unchanged (v2 boots gain the
`ARM GIC version=2` line, and the tree's GIC `reg` must now name two regions).
`make arm64-gic-test` (`scripts/arm64-gic-qualify.py`, receipts in
`docs/arm64-gic-20261009/`) is the acceptance: one vCPU under both versions
through the whole A2 suite, QEMU's own GICv3 tree re-packed and passed back,
that tree with an unknown `compatible` or two redistributor regions refused
by name before any GIC access, and two and four vCPUs under both versions
with every CPU receiving timer and IPI interrupts; the whole B1 suite on those
SMP boots is HVF-only (`--full-smp`): under TCG the weak-memory litmus cases
report a forbidden outcome, observed for GICv2 as well. The GICD_PIDR2 and
VLPI refusals have no control (QEMU offers no such tree) and are untested.
Under HVF the CPU's ID_AA64PFR0_EL1.GIC field reads 0 while QEMU still serves
the ICC registers, so the kernel reports that field and does not require it.
Entry at EL2 (2026-10-09, the same lane): the stub sets the minimum
ARMv8.0 non-VHE EL2 state before dropping to EL1 (HCR_EL2.RW only,
CNTHCTL/CNTVOFF, VTTBR, VPIDR/VMPIDR from MIDR/MPIDR, CPTR_EL2 with no
FP/SIMD or trace trap, HSTR clear, MDCR with the PMU left to EL1,
ICC_SRE_EL2 enabled when the CPU has the GIC system registers, SCTLR_EL1
at the ARMv8.0 RES1 value with MMU and caches off), records the entry
level, refuses EL3 entry and an EL2 whose E2H cannot be cleared, and PSCI
is reached by the conduit the tree's `psci` node names (`hvc` or `smc`, a
PSCI 0.2 or later binding required; anything else is refused by name,
untested, since QEMU regenerates the `psci` node of a passed-in tree). A
refusal before the tree is parsed powers off by `smc` when entered at EL2.
`ARM BOOT entry_el=N psci=...` is the first line after the banner once the
tree is parsed. The qualification repeats the single-vCPU and SMP boots
with `virtualization=on` (entry at EL2, conduit `smc`, as EL3 firmware and
U-Boot hand a kernel over), never skipped under TCG and skipped with a
recorded reason only where the accelerator fails before the guest runs
(HVF today). Not covered: FEAT_FGT/HCRX traps, FEAT_SVE/SME state,
SYSTEM_RESET by `smc`, firmware-left state beyond the registers the stub
sets, and CPUs newer than the Cortex-A72 model TCG ran. The kernel still
runs at EL1 only; no EL2 kernel or EL3 is claimed. No ITS, LPI, SPI, GICv4 or physical-board claim is made. B1 covers
synchronization, migration, stop/reclamation
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
