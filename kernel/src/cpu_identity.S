/* GP-only private-GDTR identity. No user GS dependency and no call before
   FXSAVE. Scratch is entirely below saved GPRs; the input frame is unchanged.
   Output must not alias RAX/RBX/RCX/RDX. Geometry precedes metadata reads. */
.macro ap_local base
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    subq $16, %rsp
    sgdt (%rsp)
    cmpw $55, (%rsp)
    jne 78f
    movq 2(%rsp), %rax
    subq ${cpu_gdt}, %rax
    leaq AP_USER_CPU_LOCAL(%rip), %rcx
    subq %rcx, %rax
    cmpq $({cpu_local_bytes} * 5), %rax
    jae 78f
    xorl %edx, %edx
    movq ${cpu_local_bytes}, %rbx
    divq %rbx
    testq %rdx, %rdx
    jnz 78f
    incq %rax
    cmpl AP_CPU_COUNT(%rip), %eax
    jae 78f
    movq 2(%rsp), \base
    subq ${cpu_gdt}, \base
    cmpb $1, {cpu_identity_ready}(\base)
    jne 78f
    cmpb %al, {cpu_identity_id}(\base)
    jne 78f
    addq $16, %rsp
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    jmp 79f
78:
    cli
    movl $3, %eax
    movw $0xf4, %dx
    outl %eax, %dx
77:
    hlt
    jmp 77b
79:
.endm
