OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
ENTRY(_start)

/* The image window begins at absd_abi::layout::USER_IMAGE_MIN. Programs are
   built with the large code model, so the .l* section variants must be
   captured alongside their ordinary counterparts. */

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
