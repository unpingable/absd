#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
static uint32_t rng = 12345; static uint32_t next(void) { rng = rng * 1103515245u + 12345u; return rng >> 8; }
int main(void) {
    enum { N = 100000 }; static unsigned char *blocks[N]; static size_t sizes[N];
    size_t live = 0;
    for (int i = 0; i < N; i++) {
        size_t size = 1 + next() % 4096; if (next() % 100 == 0) size = 1 + next() % (1u << 20);
        blocks[i] = malloc(size); sizes[i] = size;
        if (!blocks[i]) { printf("malloc(%zu) failed at %d live=%zu\n", size, i, live); break; }
        memset(blocks[i], (int)(i & 0xff), size); live += size;
        if (next() % 3 == 0) { int j = (int)(next() % (uint32_t)(i + 1)); if (blocks[j]) { free(blocks[j]); live -= sizes[j]; blocks[j] = NULL; } }
    }
    unsigned long sum = 0; int kept = 0;
    for (int i = 0; i < N; i++) if (blocks[i]) { kept++; for (size_t k = 0; k < sizes[i]; k++) sum += blocks[i][k]; if (blocks[i][0] != (i & 0xff)) printf("corrupt %d\n", i); free(blocks[i]); }
    printf("kept=%d sum=%lu\n", kept, sum);
    void *big = malloc((size_t)40 << 20);            /* past the 32 MiB window */
    printf("40MiB: %s\n", big ? "allocated" : "refused");
    free(big);
    char *r = malloc(16); strcpy(r, "intact");
    char *r2 = realloc(r, (size_t)40 << 20);
    printf("realloc huge: %s, original %s\n", r2 ? "grew" : "refused", r2 ? r2 : r);
    free(r2 ? r2 : r);
    return 0;
}
