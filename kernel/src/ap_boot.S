/* One relocatable real-mode SIPI image, copied to the verified 0x7000 page.
   Every data reference in the 16-bit stage is relative to the call/pop IP;
   all long-mode data references stay within the copied image via RIP.
   The Rust installer patches GDTR base, far target, CR3, AP stack and entry. */

.section .text.ap_trampoline,"ax",@progbits
.code16
.global ap_trampoline_start
ap_trampoline_start:
    cli
    movw %cs, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw $0x0ff0, %sp              /* last 256 bytes of the same page */
    callw 1f
1:
    popw %bx                       /* current offset within SIPI segment */
    lgdtl ap_trampoline_gdtr-1b(%bx)
    movl ap_trampoline_cr3-1b(%bx), %eax
    movl %eax, %cr3
    movl %cr4, %eax
    orl $0x20, %eax                /* PAE */
    movl %eax, %cr4
    movl $0xc0000080, %ecx
    rdmsr
    orl $0x900, %eax               /* EFER.LME | EFER.NXE */
    wrmsr
    movl %cr0, %eax
    orl $0x80000001, %eax          /* PG | PE */
    movl %eax, %cr0
    ljmpl *ap_trampoline_far-1b(%bx)

.align 8
.global ap_trampoline_gdtr
ap_trampoline_gdtr:
    .word 3*8-1
    .long 0                        /* installer: physical GDT base */
.global ap_trampoline_far
ap_trampoline_far:
    .long 0                        /* installer: physical long-mode RIP */
    .word 0x08
.global ap_trampoline_cr3
ap_trampoline_cr3:
    .long 0                        /* installer: physical boot PML4 */
.align 8
.global ap_trampoline_gdt
ap_trampoline_gdt:
    .quad 0
    .quad 0x00af9a000000ffff      /* CPL0 long code */
    .quad 0x00af92000000ffff      /* CPL0 data */
.global ap_trampoline_stack
ap_trampoline_stack:
    .quad 0                        /* installer: AP_BOOT_STACK top */
.global ap_trampoline_entry
ap_trampoline_entry:
    .quad 0                        /* installer: ap_kernel_main address */

.code64
.global ap_trampoline_long
ap_trampoline_long:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movq ap_trampoline_stack(%rip), %rsp
    andq $-16, %rsp
    movq %cr0, %rax
    andq $~0x4, %rax               /* CR0.EM = 0 */
    orq $0x2, %rax                 /* CR0.MP = 1 */
    movq %rax, %cr0
    movq %cr4, %rax
    orq $0x600, %rax               /* OSFXSR | OSXMMEXCPT */
    movq %rax, %cr4
    movq ap_trampoline_entry(%rip), %rax
    call *%rax
    ud2
.global ap_trampoline_end
ap_trampoline_end:

/* Kernel-resident AP entry stubs; these are not part of the low copy. */
.section .text.ap_entry,"ax",@progbits
.code64
.global ap_ipi_stub
ap_ipi_stub:
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    cld
    fxsave AP_IRQ_FXSAVE(%rip)
    movq %rsp, %r12
    andq $-16, %rsp
    call ap_ipi_observe
    movq %r12, %rsp
    fxrstor AP_IRQ_FXSAVE(%rip)
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rax
    iretq

.global ap_spurious_stub
ap_spurious_stub:
    iretq                           /* xAPIC spurious vector gets no EOI */

.global ap_unexpected_stub
ap_unexpected_stub:
    andq $-16, %rsp
    call ap_unexpected              /* marks failure and exits local VM */
    ud2

/* Called on AP-owned RSP with IF=0. Save only that AP return pointer, then
   make victim RSP/CR3/TSS.rsp0 genuinely active. The gate runs with IF=0
   on victim RSP and suppresses callback if a stop was already requested.
   After callback, never return through a victim frame: pivot RSP first,
   boot CR3 second, AP entry TSS.rsp0 third, then return to AP Rust. */
.global ap_enter_victim
.type ap_enter_victim, @function
ap_enter_victim:
    cli
    movq %rsp, AP_SAVED_RSP(%rip)
    movq AP_TSS_RSP0_ADDRESS(%rip), %r9
    movq %rdx, (%r9)
    movq %rdi, %cr3
    movq %rsi, %rsp
    andq $-16, %rsp
    call ap_victim_entry_gate
    testq %rax, %rax
    jz .Lap_victim_done
    sti
    call ap_fixture_run_current
.Lap_victim_done:
    cli
    movq AP_SAVED_RSP(%rip), %rsp
    movq AP_BOOT_CR3(%rip), %rax
    movq %rax, %cr3
    movq AP_TSS_RSP0_ADDRESS(%rip), %r9
    movq AP_ENTRY_STACK_TOP(%rip), %rax
    movq %rax, (%r9)
    xorq %rdi, %rdi
    xorq %rsi, %rsi
    xorq %rdx, %rdx
    ret
