/* Picolibc's strerror hook (R13). Picolibc 1.8.12's _strerror_r
   (src/libc/string/strerror.c:338-354) answers from its own table first and
   calls `char *_user_strerror(int, int, int *) __weak;` (strerror.c:336) only
   for a number the table has no text for, and only when the hook is defined
   (`&_user_strerror != NULL`, strerror.c:351); strerror, strerror_l,
   strerror_r and perror (src/libc/stdio/perror.c:44) all reach it. Left
   undefined, every program that calls any of them carries a weak-undefined
   `_user_strerror`, which scripts/check-c-elf.py refuses (it admits only the
   weak `stdin` and `stdout`, bufio.c's guarded references), so the kit
   defines it here.
   It never replaces the table's text. It names the one number the kit
   produces that the table lacks, ESTALE (errno_map.c, native -116), with
   Linux's wording, and answers every other number with "Unknown error N"
   (N in decimal, as glibc words it) instead of Picolibc's bare "Unknown
   error". errnum, errno and *errptr are never written. The text of an unknown
   number lives in a static buffer that the next unknown number overwrites:
   one for strerror/strerror_l (internal 0), which ISO C 7.24.6.2 lets the
   next strerror call overwrite, and a separate one for strerror_r and
   __xpg_strerror_r (internal 1), which copy it out at once, as Picolibc's
   strerror_r.c:39-41 requires of a hook ("uses separate storage according
   to whether the second argument ... is non-zero"; the kit is
   single-threaded). Residual: Picolibc's perror calls strerror
   (perror.c:44), so for an unknown number only it overwrites the text a
   program still holds from strerror, where ISO C 7.24.6.2 asks the library
   to behave as if no library function calls strerror.
   A weak reference never pulls an archive member, so crt0.c holds a strong
   reference to this definition: every program linked with the kit's crt0
   (absd-cc, tcc's crt1.o) gets it from libabs.a, and --gc-sections drops it
   from a program that never calls strerror. */
#include <errno.h>
#include <stddef.h>

#ifdef ABSD_HOST_TEST
#define _user_strerror absd_user_strerror
#endif

char *_user_strerror(int errnum, int internal, int *errptr);

char *_user_strerror(int errnum, int internal, int *errptr) {
    static char unknown[2][sizeof "Unknown error -2147483648"] = { "Unknown error ", "Unknown error " };
    char *text = unknown[internal != 0];
    (void)errptr;
    switch (errnum) {
    case ESTALE: return (char *)"Stale file handle";
    default: break;
    }
    /* digits of |errnum|, computed on unsigned so INT_MIN is exact */
    unsigned int value = errnum < 0 ? 0u - (unsigned int)errnum : (unsigned int)errnum;
    char digits[10];
    size_t count = 0;
    do { digits[count++] = (char)('0' + value % 10u); value /= 10u; } while (value != 0);
    size_t at = sizeof "Unknown error " - 1;
    if (errnum < 0) text[at++] = '-';
    while (count != 0) text[at++] = digits[--count];
    text[at] = '\0';
    return text;
}
