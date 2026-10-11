OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(multiboot_entry)

SECTIONS
{
  . = 1M;
  __kernel_start = .;
  /* Keep the Multiboot header in the first loadable segment. Rust's linker
     otherwise leaves this custom section as an unloaded orphan at address 0. */
  .text : ALIGN(4K) { KEEP(*(.multiboot)) *(.text .text.*) }
  .rodata : ALIGN(4K) { *(.rodata .rodata.*) }
  .data : ALIGN(4K) { *(.data .data.*) }
  .bss : ALIGN(4K) {
    *(COMMON)
    *(.bss .bss.*)
  }
  __kernel_end = .;
}
