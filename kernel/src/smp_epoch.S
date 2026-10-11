/* Closed qualification telemetry: invalidate a user interval at the first
   vector instructions, before BKL/EOI/context handling. CS offsets refer to
   the unmodified hardware frame. Preserve every scratch register used by the identity decoder. */
.macro nway_epoch cs_offset, ap=0
    testb $3, \cs_offset(%rsp)
    jz 9f
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    movq SMP_NWAY_EPOCH_PTR(%rip), %rax
    testq %rax, %rax
    jz 8f
.if \ap
    pushq %rsi
    ap_local %rsi
    movzbl {cpu_identity_id}(%rsi), %ebx
    popq %rsi
    movq SMP_NWAY_EPOCH_PTR(%rip), %rax
.else
    xorl %ebx, %ebx
.endif
    lock incq (%rax,%rbx,8)
8:
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
9:
.endm
