#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "mock_runtime.h"

int main(void) {
    /* malloc(0) is a unique, freeable pointer */
    void *a = malloc(0), *b = malloc(0);
    assert(a && b && a != b);
    free(a); free(b);
    /* 16-byte alignment and header bookkeeping */
    for (size_t size = 1; size <= 70000; size = size * 3 + 1) {
        unsigned char *p = malloc(size);
        assert(p && ((uintptr_t)p % 16) == 0);
        memset(p, 0xA5, size);
        free(p);
    }
    assert(mock_live_bytes() == 0);
    /* calloc zeroes and refuses overflow */
    unsigned *z = calloc(1000, sizeof *z);
    assert(z);
    for (int i = 0; i < 1000; i++) assert(z[i] == 0);
    free(z);
    errno = 0;
    volatile size_t huge = SIZE_MAX / 2;  /* opaque, so gcc cannot reject the call at compile time */
    assert(calloc(huge, 4) == NULL && errno == ENOMEM);
    /* realloc preserves content, and failure leaves the original intact */
    char *r = malloc(10); memcpy(r, "0123456789", 10);
    r = realloc(r, 1000); assert(r && memcmp(r, "0123456789", 10) == 0);
    mock_fail_next_alloc(1);
    errno = 0;
    char *r2 = realloc(r, 2000);
    assert(r2 == NULL && errno == ENOMEM && memcmp(r, "0123456789", 10) == 0);
    free(r);
    /* aligned_alloc: powers of two from 16 to 4096, EINVAL otherwise */
    for (size_t align = 16; align <= 4096; align *= 2) {
        void *q = aligned_alloc(align, 100);
        assert(q && ((uintptr_t)q % align) == 0);
        memset(q, 1, 100);
        free(q);
    }
    errno = 0;
    assert(aligned_alloc(24, 100) == NULL && errno == EINVAL);
    void *pm = NULL;
    assert(posix_memalign(&pm, 64, 10) == 0 && pm && ((uintptr_t)pm % 64) == 0);
    free(pm);
    /* impossible sizes and alignments are refused and allocate nothing */
    size_t before = mock_live_bytes();
    volatile size_t most = SIZE_MAX;
    errno = 0; assert(malloc(most) == NULL && errno == ENOMEM);
    volatile size_t giant = (size_t)1 << 62;
    errno = 0; assert(aligned_alloc(giant, 16) == NULL && errno == ENOMEM);
    void *untouched = &before;
    assert(posix_memalign(&untouched, giant, 16) == ENOMEM && untouched == &before);
    assert(posix_memalign(&untouched, (size_t)1 << 63, 16) == ENOMEM && untouched == &before);
    assert(mock_live_bytes() == before);
    /* exhaustion returns NULL/ENOMEM and the program continues */
    mock_set_budget(1 << 20);
    void *big = malloc(2u << 20);
    assert(big == NULL && errno == ENOMEM);
    void *small = malloc(100); assert(small); free(small);
    mock_set_budget(0);
    free(NULL);
    assert(mock_live_bytes() == 0);
    puts("test_malloc OK");
    return 0;
}
