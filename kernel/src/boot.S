.section .multiboot
.align 8
header_start:
    .long 0xe85250d6                 /* multiboot2 magic */
    .long 0                          /* i386 protected mode */
    .long header_end - header_start
    .long -(0xe85250d6 + 0 + (header_end - header_start))
    /* Framebuffer request, optional (flags bit 0): GRUB sets a linear
       framebuffer through VBE or GOP and reports it in boot tag 8. The
       size is a preference; GRUB falls back to any mode it can set. */
    .short 5
    .short 1
    .long 20
    .long 1024
    .long 768
    .long 32
    .long 0                          /* pad the next tag to 8 bytes */
    .short 0                         /* end tag */
    .short 0
    .long 8
header_end:

.section .bss
.align 16
.global boot_stack_canary
boot_stack_canary:
    /* One stack-probe interval outside the usable stack. This detects
       writes past the bottom; it is not an unmapped guard page. */
    .skip 4096
.global boot_stack_bottom
boot_stack_bottom:
stack_bottom:
    /* ACPI's bounded by-value root/MADT readers exceed 16 KiB together.
       Keep measured margin on this BSP-only stack before task entry. */
    .skip 32768
.global boot_stack_top
boot_stack_top:
stack_top:
.align 4096
.global boot_pml4
boot_pml4:
pml4:
    .skip 4096
pdpt:
    .skip 4096
pd:
    .skip 4096

.section .text
.code32
.global multiboot_entry
.type multiboot_entry, @function
multiboot_entry:
    cli
    mov %ebx, %edi                   /* preserve Multiboot info across CPUID */
    /* Refuse an AP before touching the shared boot stack, page tables, or
       GDT. A CPU without an APIC has no APIC startup path to admit. */
    mov $1, %eax
    cpuid
    test $0x200, %edx               /* CPUID.1:EDX.APIC */
    jz .Lbsp_guard_done
    mov $0x1b, %ecx                 /* IA32_APIC_BASE */
    rdmsr
    test $0x100, %eax               /* BSP flag */
    jz .Lrefuse_ap
.Lbsp_guard_done:
    mov $stack_top, %esp

    /* Identity map the first GiB with 2 MiB pages. */
    mov $pdpt, %eax
    or $0x3, %eax
    mov %eax, pml4
    mov $pd, %eax
    or $0x3, %eax
    mov %eax, pdpt
    xor %ecx, %ecx
1:
    mov %ecx, %eax
    shl $21, %eax
    or $0x83, %eax                   /* present, writable, huge */
    mov %eax, pd(,%ecx,8)
    inc %ecx
    cmp $512, %ecx
    jne 1b

    mov $pml4, %eax
    mov %eax, %cr3
    mov %cr4, %eax
    or $0x20, %eax                   /* PAE */
    mov %eax, %cr4
    mov $0xc0000080, %ecx
    rdmsr
    or $0x900, %eax                  /* EFER.LME | EFER.NXE */
    wrmsr
    mov %cr0, %eax
    or $0x80000001, %eax             /* PG | PE */
    mov %eax, %cr0
    lgdt gdt64_pointer
    ljmp $0x08, $long_mode_entry
.Lrefuse_ap:
    mov $0xf4, %dx
    mov $5, %eax                    /* QEMU debug-exit process status 11 */
    out %eax, %dx
1:
    hlt
    jmp 1b

.code64
long_mode_entry:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $stack_top, %rsp
    /* Paint before any Rust call, preserving the Multiboot pointer. */
    mov %rdi, %r8
    lea boot_stack_canary(%rip), %rdi
    mov $((stack_top - boot_stack_canary) / 8), %ecx
    movabs $0xa55aa55aa55aa55a, %rax
    cld
    rep stosq
    mov %r8, %rdi
    /* Rust may use scalar XMM moves while constructing fixed user programs. */
    mov %cr0, %rax
    and $~0x4, %rax                 /* CR0.EM = 0 */
    or $0x2, %rax                   /* CR0.MP = 1 */
    mov %rax, %cr0
    mov %cr4, %rax
    or $0x600, %rax                 /* OSFXSR | OSXMMEXCPT */
    mov %rax, %cr4
    mov %rdi, %rdi
    call kernel_main
2:
    hlt
    jmp 2b

.align 8
.global boot_gdt64
boot_gdt64:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00af92000000ffff
    .quad 0                         /* 64-bit TSS, low descriptor */
    .quad 0                         /* 64-bit TSS, high descriptor */
    .quad 0x00affa000000ffff        /* user 64-bit code, DPL 3 */
    .quad 0x00aff2000000ffff        /* user data, DPL 3 */
boot_gdt64_end:
gdt64_pointer:
    .word boot_gdt64_end - boot_gdt64 - 1
    .long boot_gdt64

.global breakpoint_stub
.type breakpoint_stub, @function
breakpoint_stub:
    nway_epoch 8
    movb $1, BSP_CPU_LOCAL+{cpu_breakpoint_seen}(%rip)
    iretq

/* Vector 14 keeps its own entry so the boot-time controlled kernel fault can
   recover; it is honoured only while Rust has armed kernel_fault_expected.
   Every other CPL0 page fault, and every CPL3 page fault, takes the common
   exception path. */
.global page_fault_stub
.type page_fault_stub, @function
page_fault_stub:
    nway_epoch 16
    testb $3, 16(%rsp)               /* error, RIP, CS */
    jnz .Luser_stack_fault
    cmpb $0, BSP_CPU_LOCAL+{cpu_kernel_fault_expected}(%rip)
    je .Lpage_fault_common
    movb $0, BSP_CPU_LOCAL+{cpu_kernel_fault_expected}(%rip)
    movb $1, BSP_CPU_LOCAL+{cpu_page_fault_seen}(%rip)
    movq $page_fault_recover, 8(%rsp) /* error code, then saved RIP */
    addq $8, %rsp
    iretq
.Lpage_fault_common:
    pushq $14
    jmp exception_common

/* A growable user-stack fault is the sole resumable exception. Preserve the
   same 15-GPR order used by syscall/preemption frames, then save FPU/SSE
   before Rust can touch it. At this point offsets from RSP are:
   error 120, RIP 128, CS 136, RFLAGS 144, user RSP 152, SS 160. The extra
   eight-byte subtraction gives the Rust call SysV alignment. */
.Luser_stack_fault:
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
    fxsave BSP_CPU_LOCAL+{cpu_user_fpu}(%rip)
    subq $8, %rsp
    call bsp_kernel_enter
    addq $8, %rsp
    subq $8, %rsp
    call bsp_pagefault_stop_guard
    addq $8, %rsp
    movq %rsp, %rdi                  /* complete saved frame base */
    movq %cr2, %rsi                  /* faulting linear address */
    movq 120(%rsp), %rdx             /* page-fault error */
    movq 152(%rsp), %rcx             /* interrupted user RSP */
    subq $8, %rsp
    call user_stack_page_fault
    addq $8, %rsp
    testq %rax, %rax
    jz .Luser_stack_fault_refused
    subq $8, %rsp
    call bsp_pagefault_stop_guard
    addq $8, %rsp
    subq $8, %rsp
    call bsp_kernel_leave
    addq $8, %rsp
    fxrstor BSP_CPU_LOCAL+{cpu_user_fpu}(%rip)
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
    addq $8, %rsp                    /* discard hardware error only */
    iretq
.Luser_stack_fault_refused:
    fxrstor BSP_CPU_LOCAL+{cpu_user_fpu}(%rip)
    subq $8, %rsp
    call bsp_kernel_leave
    addq $8, %rsp
    addq $120, %rsp                  /* discard saved GPRs, keep error */
    pushq $14
    jmp exception_common

.global trigger_page_fault
.type trigger_page_fault, @function
trigger_page_fault:
    movabs $0x0000400000000000, %rax
    movq (%rax), %rax
.global page_fault_recover
page_fault_recover:
    ret

/* One stub per CPU exception vector. Vectors without a hardware error code
   push a zero so the common path always sees [vector][error][RIP][CS]... */
.macro exception_stub vector, has_error
.type exception_stub_\vector, @function
exception_stub_\vector:
.if \has_error == 0
    pushq $0
.endif
    pushq $\vector
    jmp exception_common
.endm
exception_stub 0, 0
exception_stub 1, 0
exception_stub 2, 0
exception_stub 3, 0
exception_stub 4, 0
exception_stub 5, 0
exception_stub 6, 0
exception_stub 7, 0
exception_stub 8, 1
exception_stub 9, 0
exception_stub 10, 1
exception_stub 11, 1
exception_stub 12, 1
exception_stub 13, 1
exception_stub 14, 1
exception_stub 15, 0
exception_stub 16, 0
exception_stub 17, 1
exception_stub 18, 0
exception_stub 19, 0
exception_stub 20, 0
exception_stub 21, 1
exception_stub 22, 0
exception_stub 23, 0
exception_stub 24, 0
exception_stub 25, 0
exception_stub 26, 0
exception_stub 27, 0
exception_stub 28, 0
exception_stub 29, 1
exception_stub 30, 1
exception_stub 31, 0

.section .rodata
.align 8
.global exception_stub_table
exception_stub_table:
    .quad exception_stub_0, exception_stub_1, exception_stub_2, exception_stub_3
    .quad exception_stub_4, exception_stub_5, exception_stub_6, exception_stub_7
    .quad exception_stub_8, exception_stub_9, exception_stub_10, exception_stub_11
    .quad exception_stub_12, exception_stub_13, exception_stub_14, exception_stub_15
    .quad exception_stub_16, exception_stub_17, exception_stub_18, exception_stub_19
    .quad exception_stub_20, exception_stub_21, exception_stub_22, exception_stub_23
    .quad exception_stub_24, exception_stub_25, exception_stub_26, exception_stub_27
    .quad exception_stub_28, exception_stub_29, exception_stub_30, exception_stub_31
.section .text

/* A ring-3 exception is that process's failure: leave its address space and
   kernel stack behind and let Rust record the outcome and reclaim. A ring-0
   exception is a kernel bug: report it on the spare double-fault stack. */
exception_common:
    nway_epoch 24
    cld
    movq (%rsp), %rdi                /* vector */
    movq 8(%rsp), %rsi               /* error code */
    movq 16(%rsp), %rdx              /* faulting RIP */
    testb $3, 24(%rsp)               /* CS */
    jz 2f
    movq %rdi, %r12
    movq %rsi, %r13
    movq %rdx, %r14
    movq $boot_pml4, %rax
    movq %rax, %cr3
    leaq BSP_CPU_LOCAL+{cpu_entry_stack_top}(%rip), %rsp
    movq %rsp, BSP_CPU_LOCAL+{cpu_tss_rsp0}(%rip)
    call bsp_kernel_enter
    movq %r12, %rdi
    movq %r13, %rsi
    movq %r14, %rdx
    call user_exception
    hlt
2:
    leaq BSP_CPU_LOCAL+{cpu_report_stack_top}(%rip), %rsp
    call kernel_exception_report
    hlt

/* Spurious interrupts from the legacy PICs (IRQ7 and IRQ15 arrive even
   while masked) must neither be acknowledged nor treated as a fault. */
.global spurious_interrupt_stub
.type spurious_interrupt_stub, @function
spurious_interrupt_stub:
    nway_epoch 8
    iretq

.global syscall_stub
.type syscall_stub, @function
syscall_stub:
    nway_epoch 8
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
    fxsave BSP_CPU_LOCAL+{cpu_user_fpu}(%rip)
    call bsp_kernel_enter
    movq %rsp, %rdi
    call user_syscall_dispatch
    movq %rax, %r12
    call bsp_kernel_leave
    movq %r12, %rax
    movq %rax, %cr3
    jmp restore_user_frame

/* Terminal disposition must not run on the exiting process's kernel stack
   or page tables, since both are about to be freed. */
.global enter_kernel_context_and_reap
.type enter_kernel_context_and_reap, @function
enter_kernel_context_and_reap:
    cli
    movq $boot_pml4, %rax
    movq %rax, %cr3
    leaq BSP_CPU_LOCAL+{cpu_entry_stack_top}(%rip), %rsp
    movq %rsp, BSP_CPU_LOCAL+{cpu_tss_rsp0}(%rip)
    call reap_current_and_schedule
    hlt

.global double_fault_stub
.type double_fault_stub, @function
double_fault_stub:
    nway_epoch 16
    movb $1, BSP_CPU_LOCAL+{cpu_double_fault_seen}(%rip)
    movq $8, %rdi
    movq (%rsp), %rsi                /* error code, always zero */
    movq 8(%rsp), %rdx               /* RIP */
    call kernel_exception_report
    cli
3:
    hlt
    jmp 3b

/* COM1 receive interrupt (IRQ4, vector 36): move the UART's bytes into the
   kernel's input ring and acknowledge. Never schedules; blocked readers are
   woken at the next scheduling decision or from the idle loop. */
.global serial_stub
.type serial_stub, @function
serial_stub:
    nway_epoch 8
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    cld
    fxsave BSP_CPU_LOCAL+{cpu_serial_fpu}(%rip)
    movq %rsp, %r12
    andq $-16, %rsp
    call serial_input_interrupt
    movq %r12, %rsp
    fxrstor BSP_CPU_LOCAL+{cpu_serial_fpu}(%rip)
    movb $0x20, %al
    outb %al, $0x20
    popq %r12
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

/* IRQ14: the primary IDE channel finished a command. The block driver
   polls the status register after waking, so the stub only acknowledges
   both PICs and lets `hlt` in the driver return. */
.global block_stub
.type block_stub, @function
block_stub:
    nway_epoch 8
    pushq %rax
    incq block_interrupts(%rip)
    movb $0x20, %al
    outb %al, $0xa0
    outb %al, $0x20
    popq %rax
    iretq

/* Kernel-only AP completion wakes a BSP parked in hlt. The handler only
   acknowledges the LAPIC; process-table completion is polled later under
   serialization. It must work while a driver has yielded the BKL. */
.global bsp_ap_ack_stub
.type bsp_ap_ack_stub, @function
bsp_ap_ack_stub:
    nway_epoch 8
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    cld
    fxsave BSP_CPU_LOCAL+{cpu_serial_fpu}(%rip)
    movq %rsp, %r12
    andq $-16, %rsp
    call bsp_ap_ack_interrupt
    movq %r12, %rsp
    fxrstor BSP_CPU_LOCAL+{cpu_serial_fpu}(%rip)
    popq %r12
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

/* USB MSI-X: BSP-only, no kernel lock, foreground owns all event TRBs.
   Retain this gate and handler for late delivery after controller stop. */
.global xhci_interrupt_stub
.type xhci_interrupt_stub, @function
xhci_interrupt_stub:
    nway_epoch 8
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    cld
    fxsave BSP_CPU_LOCAL+{cpu_serial_fpu}(%rip)
    movq %rsp, %r12
    andq $-16, %rsp
    call xhci_interrupt
    movq %r12, %rsp
    fxrstor BSP_CPU_LOCAL+{cpu_serial_fpu}(%rip)
    popq %r12
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

.global timer_stub
.type timer_stub, @function
timer_stub:
    nway_epoch 8
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
    lock incq timer_ticks(%rip)
    movb $0x20, %al
    outb %al, $0x20
    testb $3, 128(%rsp)              /* saved user CS after fifteen pushes */
    jz 6f
    cld
    fxsave BSP_CPU_LOCAL+{cpu_user_fpu}(%rip)
    call bsp_kernel_enter
    movq %rsp, %rdi
    call user_timer_schedule
    ud2                              /* scheduler handoff never returns */
restore_user_frame:
    fxrstor BSP_CPU_LOCAL+{cpu_user_fpu}(%rip)
6:
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

.global resume_user_context
.type resume_user_context, @function
resume_user_context:
    /* rdi: saved frame, rsi: new CR3 root, rdx: kernel stack top.
       Pop the return frame from CPU-owned storage, never a task stack. */
    movq %rdx, BSP_CPU_LOCAL+{cpu_tss_rsp0}(%rip)
    movq %rsi, %r8
    movq %rdi, %rsi
    leaq BSP_CPU_LOCAL+{cpu_return_frame}(%rip), %rdi
    movq $20, %rcx
    cld
    rep movsq
    /* The incoming frame is now CPU-owned; leave serialization before
       loading its CR3 and entering user mode. */
    movq %r8, %r15
    subq $8, %rsp
    call bsp_kernel_leave
    addq $8, %rsp
    movq %r15, %r8
    leaq BSP_CPU_LOCAL+{cpu_return_frame}(%rip), %rsp
    movq %r8, %cr3
    fxrstor BSP_CPU_LOCAL+{cpu_user_fpu}(%rip)
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

/* A scheduling entry saves the outgoing frame before reaching here. Abandon
   every Rust call frame on that task's stack, then leave both its CR3 and
   TSS.rsp0 before Rust can publish it Runnable. */
.global enter_cpu_switch
.type enter_cpu_switch, @function
enter_cpu_switch:
    cli
    leaq BSP_CPU_LOCAL+{cpu_transition_stack_top}(%rip), %rsp
    movq $boot_pml4, %rax
    movq %rax, %cr3
    leaq BSP_CPU_LOCAL+{cpu_entry_stack_top}(%rip), %rax
    movq %rax, BSP_CPU_LOCAL+{cpu_tss_rsp0}(%rip)
    call commit_cpu_switch
    ud2

.purgem nway_epoch

.purgem ap_local
