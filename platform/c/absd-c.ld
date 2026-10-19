/* ABSD C kit link form: static ET_EXEC, two PT_LOAD segments, image window
   0x80_0040_0000..0x80_0400_0000, no notes, no TLS, init/fini arrays kept.
   Picolibc's __libc_init_array walks __bothinit_array_start..end (preinit
   then init); its atexit runner lives in .fini_array_onexit, so every
   .fini_array* section is kept. */
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
  .data : ALIGN(0x1000) {
    *(.data .data.* .ldata .ldata.* .got .got.* .lgot .lgot.*)
    . = ALIGN(8);
    __preinit_array_start = .;
    __bothinit_array_start = .;
    KEEP(*(.preinit_array))
    __preinit_array_end = .;
    __init_array_start = .;
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
    KEEP(*(.init_array))
    __init_array_end = .;
    __bothinit_array_end = .;
    __fini_array_start = .;
    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
    KEEP(*(.fini_array))
    KEEP(*(.fini_array*))
    __fini_array_end = .;
  } :data
  .bss (NOLOAD) : ALIGN(0x1000) { *(.bss .bss.* .lbss .lbss.* COMMON) } :data
  /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) *(.eh_frame_hdr) *(.gcc_except_table*) }
}
