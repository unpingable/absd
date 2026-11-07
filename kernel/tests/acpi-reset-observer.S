.code16
.section .text
.global _start, fixture_entry, fixture_reset, fixture_return
_start:
    ljmp $0, $boot
boot:
    cli
    xor %ax, %ax
    mov %ax, %ds
    mov %ax, %ss
    mov %ax, %es
    mov $0x7c00, %sp
    cld
    mov $0x3f9, %dx
    out %al, %dx
    mov $0x3fb, %dx
    mov $0x80, %al
    out %al, %dx
    mov $0x3f8, %dx
    mov $3, %al
    out %al, %dx
    inc %dx
    xor %al, %al
    out %al, %dx
    mov $0x3fb, %dx
    mov $3, %al
    out %al, %dx
    mov $0x3fa, %dx
    mov $0xc7, %al
    out %al, %dx
    mov $prefix, %si
send:
    lodsb
    test %al, %al
    jz drain
    push %ax
    mov $0xffff, %cx
    mov $0x3fd, %dx
wait_tx:
    in %dx, %al
    test $0x20, %al
    jnz ready
    loop wait_tx
ready:
    pop %ax
    mov $0x3f8, %dx
    out %al, %dx
    jmp send
drain:
    mov $0xffff, %cx
    mov $0x3fd, %dx
wait_empty:
    in %dx, %al
    test $0x40, %al
    jnz effect
    loop wait_empty
effect:
    xor %eax, %eax
    mov $0x1000, %di
    mov $3072, %cx
    rep stosl
    movl $0x2003, 0x1000
    movl $0x3003, 0x2000
    movl $0x83, 0x3000
    lgdt gdt_descriptor
    mov %cr4, %eax
    or $0x20, %eax
    mov %eax, %cr4
    mov $0x1000, %eax
    mov %eax, %cr3
    mov $0xc0000080, %ecx
    rdmsr
    or $0x100, %eax
    wrmsr
    mov %cr0, %eax
    or $0x80000001, %eax
    mov %eax, %cr0
    ljmp $8, $fixture_entry
.code64
fixture_entry:
    mov $0x7000, %rsp
    call fixture_reset
fixture_return:
    lidt empty_idt(%rip)
    ud2
    hlt
    jmp fixture_return
fixture_reset:
.if MODE == 4
    jmp no_effect
.endif
.if MODE != 3
    mov $0xcf9, %dx
.if MODE == 1
    mov $2, %al
.elseif MODE == 2
    mov $14, %al
.else
    mov $15, %al
.endif
.global fixture_out_0, fixture_after_0
fixture_out_0:
    out %al, %dx
fixture_after_0:
    nop
.if MODE == 1
    mov $6, %al
.global fixture_out_1, fixture_after_1
fixture_out_1:
    out %al, %dx
fixture_after_1:
    nop
.endif
.endif
no_effect:
    ret
.if MODE == 1
# Unreachable sites exercise the same four-hardware-breakpoint capacity used
# by the product observer. Neither extra instruction is executed.
.global fixture_out_2, fixture_out_3
fixture_out_2:
    out %al, %dx
fixture_out_3:
    out %al, %dx
.endif
.align 8
gdt:
    .quad 0
    .quad 0x00af9a000000ffff
gdt_descriptor:
    .word 15
    .long gdt
empty_idt:
    .word 0
    .quad 0
prefix:
    .asciz "FIXTURE REQUEST reset\nFIXTURE ATTEMPT cf9\n"
.org 510
.word 0xaa55
