/* The C program's entry on ABSD. `_start` is the runtime's (it validates
   the machine state and parses the startup record); with the runtime's
   `c-entry` feature it then calls __absd_program_main(argc, argv, envp).
   This file turns that into a C `main`: stack pre-touch (spec A4), the
   environment pointer, Picolibc's constructors, main, and libc exit so
   atexit handlers and stdio flushes run (spec A1). */
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "absd/kit.h"
#include "absd/runtime.h"

extern int main(int argc, char **argv, char **envp);
extern void __libc_init_array(void);
extern void __absd_c_anchor(void);
extern char *_user_strerror(int errnum, int internal, int *errptr);

/* R13: Picolibc's strerror references its _user_strerror hook only weakly,
   and a weak reference never pulls an archive member, so this strong one
   brings the kit's definition (strerror_hook.c, in libabs.a) into every link
   that has crt0; --gc-sections drops both when nothing calls strerror. */
__attribute__((used)) static char *(*const absd_strerror_hook)(int, int, int *) = _user_strerror;

char **environ;

/* Touch one byte per page from the current stack page down to `bytes`
   below it, moving RSP page by page: the kernel grows the stack only on a
   write fault to the page directly below the mapped bottom while RSP lies
   in that page (or 128 bytes above the fault). A loop that only wrote to
   addresses, with RSP left high, would be refused as a wild access. */
static void pretouch_stack(size_t bytes) {
    size_t pages = bytes / 4096;
    __asm__ volatile(
        "mov %%rsp, %%r11\n\t"
        "1:\n\t"
        "sub $4096, %%rsp\n\t"
        "movb $0, (%%rsp)\n\t"
        "dec %0\n\t"
        "jnz 1b\n\t"
        "mov %%r11, %%rsp\n\t"
        : "+r"(pages) : : "r11", "memory", "cc");
}

int __absd_program_main(long argc, char **argv, char **envp) {
    __absd_c_anchor();
    pretouch_stack(ABSD_STACK_PRETOUCH_BYTES);
    environ = envp;
    __libc_init_array();
    exit(main((int)argc, argv, envp));
}

_Noreturn void _exit(int status) { __absd_std_exit((int32_t)status); }
