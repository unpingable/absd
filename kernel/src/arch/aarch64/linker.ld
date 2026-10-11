OUTPUT_ARCH(aarch64)
ENTRY(_start)
SECTIONS {
 . = 0x40080000;
 __kernel_start = .;
 .text : { KEEP(*(.boot)) *(.text .text.*) }
 .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
 .data : ALIGN(4096) { *(.data .data.*) }
 .bss (NOLOAD) : ALIGN(4096) { __bss_start = .; *(.bss .bss.* COMMON) . = ALIGN(16); __bss_end = .; }
 . = ALIGN(4096); __kernel_end = .; __kernel_size = __kernel_end - __kernel_start;
 /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.note*) }
}
