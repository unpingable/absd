/* setlocale, replacing Picolibc's (R14, catalog CPA-048). The kit's Picolibc
   1.8.12 is built with mb-capable=false, so its only locale is "C" (ASCII):
   localeconv, the ctype tables and strtod never change. Its setlocale
   (src/libc/locale/setlocale.c over __find_locale in locale_names.c) still
   succeeds for any name whose charset part it knows or that has none, such as
   "pt_BR", and answers "C": the program is told a locale was selected that the
   library does not implement. ISO C 7.11.1.1 requires a null pointer when the
   selection cannot be honoured.
   This setlocale accepts exactly the names of the one locale there is: "C",
   "POSIX", "" (the native environment, which is the C locale here) and "C"
   with an ASCII charset ("C.ASCII", "C.US-ASCII"; ASCII case and every '-',
   '_' and '.' in the charset are ignored, the whole charset must match, and
   no "/..." iconv suffix is accepted: close to, not the same as, Picolibc's
   __match_charset, which differs on trailing separators and "//TRANSLIT"). Every other
   name returns NULL and changes nothing. A query (name NULL) and every
   accepted name answer "C". An unknown category is EINVAL, as in Picolibc.
   Picolibc's member libc_locale_setlocale.c.o defines only setlocale, so this
   definition (libabs.a, linked ahead of libc.a) replaces it whole, and
   scripts/check-c-elf.py (kit_c lists locale.o) refuses that member if a map
   shows it pulled. Picolibc's global locale is
   never written: with mb-capable=false it can only be its initial value, C.
   newlocale, uselocale and the *_l functions are Picolibc's, unchanged:
   newlocale(LC_ALL_MASK, "pt_BR", 0) still succeeds (residual, outside R14;
   no Stage 2 program, tcc or the POSIX adapter calls them). */
#include <errno.h>
#include <locale.h>
#include <stddef.h>
#include <string.h>

#if defined(__MB_CAPABLE)
#error "locale.c assumes Picolibc built with mb-capable=false (one locale, C)"
#endif

#ifdef ABSD_HOST_TEST
#define setlocale absd_setlocale
#endif

char *setlocale(int category, const char *name);

static int valid_category(int category) {
    switch (category) {
    case LC_ALL: case LC_COLLATE: case LC_CTYPE: case LC_MONETARY:
    case LC_NUMERIC: case LC_TIME:
#if defined(_LC_MESSAGES)
    case _LC_MESSAGES:
#elif defined(LC_MESSAGES)
    case LC_MESSAGES:
#endif
        return 1;
    default:
        return 0;
    }
}

/* s equals want, ignoring ASCII case and every '-', '_' and '.' in s;
   want is lowercase letters only. */
static int charset_is(const char *s, const char *want) {
    for (;;) {
        while (*s == '-' || *s == '_' || *s == '.') s++;
        char c = *s;
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != *want) return 0;
        if (c == '\0') return 1;
        s++; want++;
    }
}

static int is_c_locale_name(const char *name) {
    if (name[0] == '\0' || strcmp(name, "C") == 0 || strcmp(name, "POSIX") == 0) return 1;
    if (name[0] == 'C' && name[1] == '.' && name[2] != '\0')
        return charset_is(name + 2, "ascii") || charset_is(name + 2, "usascii");
    return 0;
}

char *setlocale(int category, const char *name) {
    static char c_name[] = "C";
    if (!valid_category(category)) { errno = EINVAL; return NULL; }
    if (name != NULL && !is_c_locale_name(name)) return NULL;
    return c_name;
}
