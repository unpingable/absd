/* R13: the kit's Picolibc strerror hook (c/libabs/strerror_hook.c), named
   absd_user_strerror in the host build (ABSD_HOST_TEST). Picolibc's own
   table answers every number it has text for and never reaches the hook;
   the hook names ESTALE, the one number the kit produces that the table
   lacks, and words every other number "Unknown error N". strerror and perror
   themselves are Picolibc's and cannot run here (this is glibc): the guest
   case c/tests/kit/errmsg.c runs them against the Linux reference. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

char *absd_user_strerror(int errnum, int internal, int *errptr);

static void says(int errnum, const char *want) {
    int local = 77;
    errno = 1234;
    const char *got = absd_user_strerror(errnum, 0, NULL);
    assert(got != NULL && strcmp(got, want) == 0);
    assert(errno == 1234);                               /* errno is never written */
    got = absd_user_strerror(errnum, 1, &local);         /* strerror_r's call */
    assert(got != NULL && strcmp(got, want) == 0);
    assert(local == 77 && errno == 1234);                /* nor *errptr */
}

int main(void) {
    says(ESTALE, "Stale file handle");
    says(9999, "Unknown error 9999");
    says(4096, "Unknown error 4096");
    says(0, "Unknown error 0");
    says(7, "Unknown error 7");
    says(-1, "Unknown error -1");
    says(INT_MAX, "Unknown error 2147483647");
    says(INT_MIN, "Unknown error -2147483648");
    /* one buffer per kind of caller: a shorter number after the longest is terminated */
    const char *a = absd_user_strerror(INT_MIN, 0, NULL);
    const char *b = absd_user_strerror(12, 0, NULL);
    assert(a == b && strcmp(b, "Unknown error 12") == 0);
    a = absd_user_strerror(INT_MIN, 1, NULL);
    b = absd_user_strerror(12, 1, NULL);
    assert(a == b && strcmp(b, "Unknown error 12") == 0);
    /* strerror_r's call (internal 1) leaves a string still held from strerror
       (internal 0) intact, and the other way round (strerror_r.c:39-41) */
    const char *held = absd_user_strerror(9999, 0, NULL);
    const char *r = absd_user_strerror(-5, 1, NULL);
    assert(held != r && strcmp(held, "Unknown error 9999") == 0 && strcmp(r, "Unknown error -5") == 0);
    absd_user_strerror(4242, 0, NULL);
    assert(strcmp(r, "Unknown error -5") == 0);
    /* ESTALE's text is a constant, untouched by the buffer */
    const char *s = absd_user_strerror(ESTALE, 0, NULL);
    absd_user_strerror(5000, 0, NULL);
    assert(strcmp(s, "Stale file handle") == 0);
    printf("test_strerror OK\n");
    return 0;
}
