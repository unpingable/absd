/* Test-mode AP-owned int80, exception, return and departure entries.
   Ordinary boot never installs these gates. Frame ABI matches boot.S. */

.section .text.ap_user,"ax",@progbits
.code64
.global ap_user_spurious_stub
ap_user_spurious_stub:
    nway_epoch 8, 1
    iretq
.global ap_enter_user_idle
ap_enter_user_idle:
    ap_local %r14
    cli
    movq $boot_pml4, %rax
    movq %rax, %cr3
    leaq {cpu_entry_stack_top}(%r14), %rsp
    movq %rsp, {cpu_tss_rsp0}(%r14)
    call ap_user_idle
    ud2
.global ap_user_syscall_stub
.type ap_user_syscall_stub, @function
ap_user_syscall_stub:
    nway_epoch 8, 1
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
    ap_local %r14
    fxsave {cpu_user_fpu}(%r14)
    call ap_user_kernel_enter
    movq %rsp, %rdi
    call user_syscall_dispatch
    movq %rax, %r12
    call ap_user_kernel_leave
    movq %r12, %rax
    movq %rax, %cr3
    jmp ap_restore_user_frame

.global ap_enter_kernel_context_and_reap
.type ap_enter_kernel_context_and_reap, @function
ap_enter_kernel_context_and_reap:
    ap_local %r14
    cli
    movq $boot_pml4, %rax
    movq %rax, %cr3
    leaq {cpu_entry_stack_top}(%r14), %rsp
    movq %rsp, {cpu_tss_rsp0}(%r14)
    call reap_current_and_schedule
    hlt

.global ap_resume_user_context
.type ap_resume_user_context, @function
ap_resume_user_context:
    ap_local %r14
    /* rdi: saved frame, rsi: new CR3 root, rdx: kernel stack top.
       Pop the return frame from CPU-owned storage, never a task stack. */
    movq %rdx, {cpu_tss_rsp0}(%r14)
    movq %rsi, %r8
    movq %rdi, %rsi
    leaq {cpu_return_frame}(%r14), %rdi
    movq $20, %rcx
    cld
    rep movsq
    /* The incoming frame is now CPU-owned; leave serialization before
       loading its CR3 and entering user mode. */
    movq %r8, %r15
    subq $8, %rsp
    call ap_user_kernel_leave
    addq $8, %rsp
    movq %r15, %r8
    leaq {cpu_return_frame}(%r14), %rsp
    movq %r8, %cr3
    fxrstor {cpu_user_fpu}(%r14)
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

.global ap_enter_cpu_switch
.type ap_enter_cpu_switch, @function
ap_enter_cpu_switch:
    ap_local %r14
    cli
    leaq {cpu_transition_stack_top}(%r14), %rsp
    movq $boot_pml4, %rax
    movq %rax, %cr3
    leaq {cpu_entry_stack_top}(%r14), %rax
    movq %rax, {cpu_tss_rsp0}(%r14)
    call commit_cpu_switch
    ud2
ap_restore_user_frame:
    fxrstor {cpu_user_fpu}(%r14)
ap_restore_gprs:
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

ap_user_page_fault:
    nway_epoch 16, 1
    testb $3, 16(%rsp)
    jnz .Lap_user_stack_fault
    pushq $14
    jmp ap_user_exception_common
.Lap_user_stack_fault:
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
    ap_local %r14
    fxsave {cpu_user_fpu}(%r14)
    subq $8, %rsp
    call ap_user_kernel_enter
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
    jz .Lap_user_stack_fault_refused
    subq $8, %rsp
    call bsp_pagefault_stop_guard
    addq $8, %rsp
    subq $8, %rsp
    call ap_user_kernel_leave
    addq $8, %rsp
    fxrstor {cpu_user_fpu}(%r14)
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
.Lap_user_stack_fault_refused:
    fxrstor {cpu_user_fpu}(%r14)
    subq $8, %rsp
    call ap_user_kernel_leave
    addq $8, %rsp
    addq $120, %rsp                  /* discard saved GPRs, keep error */
    pushq $14
    jmp ap_user_exception_common

ap_user_exception_common:
    nway_epoch 24, 1
    cld
    ap_local %r15
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
    leaq {cpu_entry_stack_top}(%r15), %rsp
    movq %rsp, {cpu_tss_rsp0}(%r15)
    call ap_user_kernel_enter
    movq %r12, %rdi
    movq %r13, %rsi
    movq %r14, %rdx
    call user_exception
    hlt
2:
    leaq {cpu_report_stack_top}(%r15), %rsp
    call kernel_exception_report
    hlt

.macro ap_exception vector, has_error
ap_user_exception_\vector:
.if \vector == 14
    jmp ap_user_page_fault
.else
.if \has_error == 0
    pushq $0
.endif
    pushq $\vector
    jmp ap_user_exception_common
.endif
.endm
ap_exception 0, 0
ap_exception 1, 0
ap_exception 2, 0
ap_exception 3, 0
ap_exception 4, 0
ap_exception 5, 0
ap_exception 6, 0
ap_exception 7, 0
ap_exception 8, 1
ap_exception 9, 0
ap_exception 10, 1
ap_exception 11, 1
ap_exception 12, 1
ap_exception 13, 1
ap_exception 14, 1
ap_exception 15, 0
ap_exception 16, 0
ap_exception 17, 1
ap_exception 18, 0
ap_exception 19, 0
ap_exception 20, 0
ap_exception 21, 1
ap_exception 22, 0
ap_exception 23, 0
ap_exception 24, 0
ap_exception 25, 0
ap_exception 26, 0
ap_exception 27, 0
ap_exception 28, 0
ap_exception 29, 1
ap_exception 30, 1
ap_exception 31, 0
.section .rodata.ap_user,"a",@progbits
.global ap_user_exception_table
ap_user_exception_table:
    .quad ap_user_exception_0
    .quad ap_user_exception_1
    .quad ap_user_exception_2
    .quad ap_user_exception_3
    .quad ap_user_exception_4
    .quad ap_user_exception_5
    .quad ap_user_exception_6
    .quad ap_user_exception_7
    .quad ap_user_exception_8
    .quad ap_user_exception_9
    .quad ap_user_exception_10
    .quad ap_user_exception_11
    .quad ap_user_exception_12
    .quad ap_user_exception_13
    .quad ap_user_exception_14
    .quad ap_user_exception_15
    .quad ap_user_exception_16
    .quad ap_user_exception_17
    .quad ap_user_exception_18
    .quad ap_user_exception_19
    .quad ap_user_exception_20
    .quad ap_user_exception_21
    .quad ap_user_exception_22
    .quad ap_user_exception_23
    .quad ap_user_exception_24
    .quad ap_user_exception_25
    .quad ap_user_exception_26
    .quad ap_user_exception_27
    .quad ap_user_exception_28
    .quad ap_user_exception_29
    .quad ap_user_exception_30
    .quad ap_user_exception_31
.section .text.ap_user,"ax",@progbits
/* IST stop entry preserves ring-0 scratch separately. A ring-3 request
   never returns through this frame: Rust enters the normal departure path. */
.macro stop_entry name, storage
.global \name
\name:
.ifc \storage,AP_USER_CPU_LOCAL
    nway_epoch 8, 1
.else
    nway_epoch 8
.endif
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
.ifc \storage,AP_USER_CPU_LOCAL
    ap_local %r14
.else
    leaq BSP_CPU_LOCAL(%rip), %r14
.endif
    testb $3, 128(%rsp)
    jz 1f
    fxsave {cpu_user_fpu}(%r14)
    jmp 2f
1:
    fxsave {cpu_serial_fpu}(%r14)
2:
    movq %rsp, %r12
    movq %rsp, %rdi
    andq $-16, %rsp
    call user_stop_ipi
    movq %r12, %rsp
    testb $3, 128(%rsp)
    jz 3f
    fxrstor {cpu_user_fpu}(%r14)
    jmp 4f
3:
    fxrstor {cpu_serial_fpu}(%r14)
4:
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
.endm
stop_entry ap_user_stop_stub, AP_USER_CPU_LOCAL
stop_entry bsp_user_stop_stub, BSP_CPU_LOCAL

/* Local timer uses the ordinary task entry stack for CPL3. CPL0 returns
   through its existing continuation and must preserve kernel FPU scratch. */
.global ap_user_timer_stub
ap_user_timer_stub:
    nway_epoch 8, 1
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
    ap_local %r14
    testb $3, 128(%rsp)
    jz 1f
    fxsave {cpu_user_fpu}(%r14)
    jmp 2f
1:
    fxsave {cpu_serial_fpu}(%r14)
2:
    movq %rsp, %r12
    movq %rsp, %rdi
    andq $-16, %rsp
    call ap_user_timer
    movq %r12, %rsp
    testb $3, 128(%rsp)
    jz 3f
    fxrstor {cpu_user_fpu}(%r14)
    jmp 4f
3:
    fxrstor {cpu_serial_fpu}(%r14)
4:
    jmp ap_restore_gprs

/* Invalid identity exits without Rust, indexed storage or stack selection. */
.Lap_bad_cpu:
    cli
    movl $6, %eax
    movw $0xf4, %dx
    outl %eax, %dx
1:  hlt
    jmp 1b

.purgem nway_epoch

.purgem ap_local
