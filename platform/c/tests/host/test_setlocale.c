/* R14 / CPA-048: the kit's setlocale (c/libabs/locale.c) accepts only the
   names of the C locale and refuses every other name with NULL, leaving the
   locale unchanged. Named absd_setlocale in the host build (ABSD_HOST_TEST)
   so it does not collide with glibc's. */
#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

char *absd_setlocale(int, const char *);

static const int cats[] = { LC_ALL, LC_COLLATE, LC_CTYPE, LC_MONETARY, LC_NUMERIC, LC_TIME, LC_MESSAGES };

static void is_c(const char *got) { assert(got != NULL && strcmp(got, "C") == 0); }

static void refused(int cat, const char *name) {
    errno = 0;
    assert(absd_setlocale(cat, name) == NULL);
    assert(errno == 0);                                  /* a refusal is not an error number */
    is_c(absd_setlocale(cat, NULL));                     /* query unchanged */
    is_c(absd_setlocale(LC_ALL, NULL));
}

int main(void) {
    static const char *const accepted[] = { "C", "POSIX", "", "C.ASCII", "C.US-ASCII", "C.us_ascii", "C.ascii", "C.Us-AsCiI" };
    static const char *const refuse[] = {
        "pt_BR", "ptb", "pt_BR.ISO-8859-1", "pt_BR.ASCII", "en_US.UTF-8", "C.UTF-8", "C.utf8",
        "POSIX.ASCII", "c", "posix", "C.", "C.ISO-8859-1", "C_ASCII", "CC", " C", "C ", "de_DE@euro",
        "C.ASCIIX", "C.US-ASCII8", "C.ASCII//TRANSLIT", "C.ASC",
    };
    for (size_t c = 0; c < sizeof cats / sizeof cats[0]; c++) {
        is_c(absd_setlocale(cats[c], NULL));
        for (size_t i = 0; i < sizeof accepted / sizeof accepted[0]; i++) is_c(absd_setlocale(cats[c], accepted[i]));
        for (size_t i = 0; i < sizeof refuse / sizeof refuse[0]; i++) refused(cats[c], refuse[i]);
    }
    /* the R14 case: Lua's literals.lua:297 os.setlocale("pt_BR") must see nil */
    assert(absd_setlocale(LC_ALL, "pt_BR") == NULL);
    is_c(absd_setlocale(LC_ALL, "C"));
    is_c(absd_setlocale(LC_ALL, NULL));
    /* an unknown category is EINVAL, also for a query */
    errno = 0; assert(absd_setlocale(-1, "C") == NULL && errno == EINVAL);
    errno = 0; assert(absd_setlocale(99, NULL) == NULL && errno == EINVAL);
    is_c(absd_setlocale(LC_ALL, NULL));
    printf("test_setlocale OK\n");
    return 0;
}
