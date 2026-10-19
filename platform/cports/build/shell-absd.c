/* ABSD build of the SQLite shell: Picolibc's sys/ioctl.h lacks struct winsize,
   which shell.c reaches under _GNU_SOURCE; sys/termios.h declares it.
   The upstream file is included unchanged (WORKAROUNDS.md, SQLite). */
#include <sys/termios.h>
#include "shell.c"
