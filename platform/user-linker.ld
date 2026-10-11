OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
  text PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = 0x0000008000400000;
  .text : ALIGN(0x1000) { *(.text .text.* .ltext .ltext.*) } :text
  .rodata : ALIGN(16) { *(.rodata .rodata.* .lrodata .lrodata.*) } :text
  .data : ALIGN(0x1000) { *(.data .data.* .ldata .ldata.* .got .got.* .lgot .lgot.*) } :data
  .bss (NOLOAD) : ALIGN(0x1000) { *(.bss .bss.* .lbss .lbss.* COMMON) } :data
  /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) }
}

