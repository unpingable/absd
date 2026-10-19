#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#if __has_include(<absd/kit.h>)
#include <absd/kit.h>
#else
#define ABSD_STACK_PRETOUCH_BYTES (256u * 1024u)   /* the Linux reference build: the kit's value */
#endif
static int deep(int n, volatile unsigned char *mark) { volatile unsigned char frame[512]; frame[0] = (unsigned char)n; if (n == 0) return mark[0] + frame[0]; return deep(n - 1, frame) + 1; }
static int bigframe(void) { volatile unsigned char frame[8192]; memset((void *)frame, 1, sizeof frame); return frame[100] + frame[8000]; }

/* One 1 MiB frame (spec A4): the compiler's stack-clash probe loop moves RSP
   down page by page through it; the writes below land past the 256 KiB the
   crt0 pre-touch covers (frame[0] is about 1 MiB below the caller). */
static __attribute__((noinline)) int frame1m(void) {
    volatile unsigned char frame[1 << 20];      /* offsets read at run time: the whole frame is laid out */
    static volatile size_t at[] = { 0, 4096, 100000, (1 << 20) - (300u << 10), 1 << 19, (1 << 20) - 1 };
    int sum = 0;
    for (size_t i = 0; i < sizeof at / sizeof at[0]; i++) frame[at[i]] = (unsigned char)(i + 1);
    for (size_t i = 0; i < sizeof at / sizeof at[0]; i++) sum += frame[at[i]];
    return sum;
}

/* Walk the stack down by frames of just under a page, writing one byte per
   frame (a stride under 4096 bytes, so no page is skipped and each new page
   is reached by write faults, the growth the kernel supports), down to
   3.5 MiB below main's frame: within the 4 MiB stack.
   `crossed` records that the walk passed the pre-touch depth. */
#define WALK_LIMIT (3584u * 1024u)
static uintptr_t walk_top; static int crossed;
static __attribute__((noinline)) unsigned walk(unsigned frames) {
    volatile unsigned char frame[3840];
    frame[0] = (unsigned char)frames;
    uintptr_t depth = walk_top - (uintptr_t)&frame[0];
    if (depth >= ABSD_STACK_PRETOUCH_BYTES) crossed = 1;
    if (depth >= WALK_LIMIT) return frames;
    unsigned r = walk(frames + 1);
    frame[1] = (unsigned char)r;               /* keeps the frame live across the call: no tail call */
    return r;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "inside";
    volatile unsigned char top = 7;
    if (strcmp(mode, "inside") == 0) { printf("bigframe=%d deep=%d\n", bigframe(), deep(300, &top)); }
    else if (strcmp(mode, "beyond") == 0) { printf("deep beyond pretouch=%d\n", deep(2000, &top)); }     /* ~1.2 MiB: past 256 KiB, within 4 MiB; probes carry it */
    else if (strcmp(mode, "frame1m") == 0) { printf("frame1m sum=%d\n", frame1m()); }
    else if (strcmp(mode, "touchdepth") == 0) {
        walk_top = (uintptr_t)&top;
        unsigned frames = walk(0);
        printf("touchdepth: leaves the pre-touched region at depth %u (%u pages); walked to %u KiB one byte per page: %s\n",
               ABSD_STACK_PRETOUCH_BYTES, ABSD_STACK_PRETOUCH_BYTES / 4096, WALK_LIMIT / 1024,
               crossed && frames > WALK_LIMIT / 4096 ? "ok" : "short");
    }
    else if (strcmp(mode, "overflow") == 0) { printf("about to overflow\n"); fflush(stdout); printf("%d\n", deep(100000, &top)); }
    else { fprintf(stderr, "stack: unknown mode %s\n", mode); return 2; }
    return 0;
}
