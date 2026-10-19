.arch armv8-a+simd
.section .boot,"ax"
.global _start
_start:
 b start
 .long 0
 .quad 0x80000
 .quad __kernel_size
 .quad 0
 .quad 0,0,0
 .long 0x644d5241
 .long 0
start:
 msr daifset, #15
 mov x20, x0
 mrs x21, CurrentEL
 cmp x21, #8
 b.ne 1f
 mov x1, #0x80000000
 msr hcr_el2, x1
 mrs x1, hcr_el2
 lsr x1, x1, #34
 and x1, x1, #1
 orr x21, x21, x1, lsl #8
 mov x1, #3
 msr cnthctl_el2, x1
 msr cntvoff_el2, xzr
 msr vttbr_el2, xzr
 // The minimum ARMv8.0 non-VHE EL2 state for an EL1 kernel: EL1 sees
 // the real MIDR/MPIDR, no FP/SIMD or trace trap, no debug or coarse
 // system-register traps, the PMU left to EL1, and the GICv3 system
 // register interface enabled for EL1 when the CPU has one.
 mrs x1, midr_el1
 msr vpidr_el2, x1
 mrs x1, mpidr_el1
 msr vmpidr_el2, x1
 mov x1, #0x33ff
 msr cptr_el2, x1
 msr hstr_el2, xzr
 mrs x1, pmcr_el0
 ubfx x1, x1, #11, #5
 msr mdcr_el2, x1
 mrs x1, id_aa64pfr0_el1
 ubfx x1, x1, #24, #4
 cbz x1, 4f
 mov x1, #0xf
 msr S3_4_C12_C9_5, x1
4:
 mov x1, #0x0800
 movk x1, #0x30d0, lsl #16
 msr sctlr_el1, x1
 isb
 adr x1, 1f
 msr elr_el2, x1
 mov x1, #0x3c5
 msr spsr_el2, x1
 eret
1:
 adrp x1, __bss_start
 add x1, x1, :lo12:__bss_start
 adrp x2, __bss_end
 add x2, x2, :lo12:__bss_end
2:
 cmp x1, x2
 b.hs 3f
 str xzr, [x1], #8
 b 2b
3:
 adrp x1, ARM_ENTRY_EL
 add x1, x1, :lo12:ARM_ENTRY_EL
 // CurrentEL>>2 in bits [3:0]; bit 8 set when HCR_EL2.E2H would not clear.
 lsr x2, x21, #2
 and x2, x2, #0xf
 and x21, x21, #0x100
 orr x2, x2, x21
 str x2, [x1]
 adrp x1, ARM_CPU_LOCAL
 add x1, x1, :lo12:ARM_CPU_LOCAL
 msr tpidr_el1, x1
 ldr x2, ={cpu_entry_top}
 add x1, x1, x2
 mov sp, x1
 mov x1, #(3 << 20)
 msr cpacr_el1, x1
 isb
 adrp x1, vectors
 add x1, x1, :lo12:vectors
 msr vbar_el1, x1
 isb
 mov x0, x20
 bl arm_main
 b .

.balign 2048
vectors:
.macro vector target
 b \target
 .balign 128
.endm
 vector unexpected
 vector unexpected
 vector unexpected
 vector unexpected
 vector sync_kernel
 vector irq_kernel
 vector unexpected
 vector unexpected
 vector sync_user
 vector irq_user
 vector unexpected
 vector unexpected
 vector unexpected
 vector unexpected
 vector unexpected
 vector unexpected

.macro save
 sub sp, sp, #800
 stp x0, x1, [sp, #0]
 stp x2, x3, [sp, #16]
 stp x4, x5, [sp, #32]
 stp x6, x7, [sp, #48]
 stp x8, x9, [sp, #64]
 stp x10, x11, [sp, #80]
 stp x12, x13, [sp, #96]
 stp x14, x15, [sp, #112]
 stp x16, x17, [sp, #128]
 stp x18, x19, [sp, #144]
 stp x20, x21, [sp, #160]
 stp x22, x23, [sp, #176]
 stp x24, x25, [sp, #192]
 stp x26, x27, [sp, #208]
 stp x28, x29, [sp, #224]
 str x30, [sp, #240]
 mrs x0, sp_el0
 mrs x1, elr_el1
 stp x0, x1, [sp, #248]
 mrs x0, spsr_el1
 str x0, [sp, #264]
 stp q0, q1, [sp, #272]
 stp q2, q3, [sp, #304]
 stp q4, q5, [sp, #336]
 stp q6, q7, [sp, #368]
 stp q8, q9, [sp, #400]
 stp q10, q11, [sp, #432]
 stp q12, q13, [sp, #464]
 stp q14, q15, [sp, #496]
 stp q16, q17, [sp, #528]
 stp q18, q19, [sp, #560]
 stp q20, q21, [sp, #592]
 stp q22, q23, [sp, #624]
 stp q24, q25, [sp, #656]
 stp q26, q27, [sp, #688]
 stp q28, q29, [sp, #720]
 stp q30, q31, [sp, #752]
 mrs x0, fpcr
 mrs x1, fpsr
 str x0, [sp, #784]
 str x1, [sp, #792]
.endm
.macro trap kind
 save
 mov x0, sp
 mov x1, #\kind
 bl arm_exception
 b restore
.endm
sync_kernel: trap 0
irq_kernel: trap 1
sync_user: trap 2
irq_user: trap 3
unexpected: trap 4

.global arm_enter
// x0 = context, x1 = FP state, x2 = task kernel stack, x3 = TTBR0
arm_enter:
 msr daifset, #15
 msr ttbr0_el1, x3
 dsb ish
 tlbi vmalle1
 dsb ish
 isb
 mov sp, x2
 sub sp, sp, #800
 mov x4, sp
 mov x5, #34
4:
 ldr x6, [x0], #8
 str x6, [x4], #8
 subs x5, x5, #1
 b.ne 4b
 mov x5, #66
5:
 ldr x6, [x1], #8
 str x6, [x4], #8
 subs x5, x5, #1
 b.ne 5b
 bl arm_kernel_leave
restore:
 ldr x0, [sp, #784]
 ldr x1, [sp, #792]
 msr fpcr, x0
 msr fpsr, x1
 ldp q0, q1, [sp, #272]
 ldp q2, q3, [sp, #304]
 ldp q4, q5, [sp, #336]
 ldp q6, q7, [sp, #368]
 ldp q8, q9, [sp, #400]
 ldp q10, q11, [sp, #432]
 ldp q12, q13, [sp, #464]
 ldp q14, q15, [sp, #496]
 ldp q16, q17, [sp, #528]
 ldp q18, q19, [sp, #560]
 ldp q20, q21, [sp, #592]
 ldp q22, q23, [sp, #624]
 ldp q24, q25, [sp, #656]
 ldp q26, q27, [sp, #688]
 ldp q28, q29, [sp, #720]
 ldp q30, q31, [sp, #752]
 ldp x0, x1, [sp, #248]
 msr sp_el0, x0
 msr elr_el1, x1
 ldr x0, [sp, #264]
 msr spsr_el1, x0
 ldp x0, x1, [sp, #0]
 ldp x2, x3, [sp, #16]
 ldp x4, x5, [sp, #32]
 ldp x6, x7, [sp, #48]
 ldp x8, x9, [sp, #64]
 ldp x10, x11, [sp, #80]
 ldp x12, x13, [sp, #96]
 ldp x14, x15, [sp, #112]
 ldp x16, x17, [sp, #128]
 ldp x18, x19, [sp, #144]
 ldp x20, x21, [sp, #160]
 ldp x22, x23, [sp, #176]
 ldp x24, x25, [sp, #192]
 ldp x26, x27, [sp, #208]
 ldp x28, x29, [sp, #224]
 ldr x30, [sp, #240]
 add sp, sp, #800
 eret

.global arm_depart
// Leaves task-owned stack/root before any reclamation or publication.
arm_depart:
 msr daifset, #15
 msr ttbr0_el1, x0
 dsb ish
 tlbi vmalle1
 dsb ish
 isb
 mrs x2, tpidr_el1
 ldr x3, ={cpu_transition_top}
 add x2, x2, x3
 mov sp, x2
 br x1

.section .bss,"aw",%nobits
.balign 4096
entry_stack:
 .skip 65536
.global entry_stack_top
entry_stack_top:

.section .text,"ax"
.global arm_secondary_entry
arm_secondary_entry:
 msr daifset, #15
 mov x20, x0
 mrs x1, CurrentEL
 cmp x1, #8
 b.ne 6f
 mov x1, #0x80000000
 msr hcr_el2, x1
 mov x1, #3
 msr cnthctl_el2, x1
 msr cntvoff_el2, xzr
 msr vttbr_el2, xzr
 // The minimum ARMv8.0 non-VHE EL2 state for an EL1 kernel: EL1 sees
 // the real MIDR/MPIDR, no FP/SIMD or trace trap, no debug or coarse
 // system-register traps, the PMU left to EL1, and the GICv3 system
 // register interface enabled for EL1 when the CPU has one.
 mrs x1, midr_el1
 msr vpidr_el2, x1
 mrs x1, mpidr_el1
 msr vmpidr_el2, x1
 mov x1, #0x33ff
 msr cptr_el2, x1
 msr hstr_el2, xzr
 mrs x1, pmcr_el0
 ubfx x1, x1, #11, #5
 msr mdcr_el2, x1
 mrs x1, id_aa64pfr0_el1
 ubfx x1, x1, #24, #4
 cbz x1, 7f
 mov x1, #0xf
 msr S3_4_C12_C9_5, x1
7:
 mov x1, #0x0800
 movk x1, #0x30d0, lsl #16
 msr sctlr_el1, x1
 isb
 adr x1, 6f
 msr elr_el2, x1
 mov x1, #0x3c5
 msr spsr_el2, x1
 eret
6:
 adrp x1, ARM_CPU_LOCAL
 add x1, x1, :lo12:ARM_CPU_LOCAL
 ldr x2, ={cpu_local_bytes}
 madd x1, x20, x2, x1
 msr tpidr_el1, x1
 ldr x2, ={cpu_entry_top}
 add x1, x1, x2
 mov sp, x1
 mov x1, #(3 << 20)
 msr cpacr_el1, x1
 adrp x1, vectors
 add x1, x1, :lo12:vectors
 msr vbar_el1, x1
 isb
 mov x0, x20
 bl arm_secondary
 b .

.ltorg
