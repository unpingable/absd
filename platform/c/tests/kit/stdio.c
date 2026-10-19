/* stdio over the kit's descriptors, in two processes (spec Stage 1):
   `write` builds the file with fprintf (text) and fwrite (binary blocks),
   fflushes it and ends with _exit, so whatever a later process reads got
   there by fflush, not by fclose or exit; the file is kept. A second
   process (the matrix runs the native cat on it) observes the bytes.
   `verify` reopens it, reads it back with fread/fgets/fgetc, appends,
   removes it and prints `removed`. The scratch name is cwd-relative
   (contract 6). */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "errname.h"
#define PATH "c-stdio.dat"
#define LINES 1000                         /* "line %04d\n": 10 bytes each */
#define BLOCK 3000
#define BLOCKS 3
static void block(unsigned char *b, int k) { for (int i = 0; i < BLOCK; i++) b[i] = (unsigned char)(i * 37 + 11 * k + 5); }

static int do_write(void) {
    FILE *f = fopen(PATH, "w"); if (!f) { printf("fopen w: %s\n", errname(errno)); return 1; }
    long text = 0;
    for (int i = 0; i < LINES; i++) { int n = fprintf(f, "line %04d\n", i); if (n < 0) { printf("fprintf: %s\n", errname(errno)); return 1; } text += n; }
    static unsigned char b[BLOCK];
    size_t items = 0;
    for (int k = 0; k < BLOCKS; k++) { block(b, k); items += fwrite(b, BLOCK, 1, f); }
    if (fflush(f) != 0) { printf("fflush: %s\n", errname(errno)); return 1; }
    printf("fprintf bytes=%ld fwrite items=%zu of %d bytes ftell=%ld\n", text, items, BLOCK, ftell(f));
    fflush(stdout);
    _exit(0);                               /* no fclose, no exit-time flush */
}

static int do_verify(void) {
    FILE *f = fopen(PATH, "r"); if (!f) { printf("fopen r: %s\n", errname(errno)); return 1; }
    fseek(f, 0, SEEK_END); long size = ftell(f); printf("size=%ld\n", size);
    rewind(f);
    static char text[LINES * 10], want[LINES * 10 + 1];
    for (int i = 0; i < LINES; i++) snprintf(want + i * 10, 11, "line %04d\n", i);
    size_t got = fread(text, 1, sizeof text, f);
    printf("fread text=%zu equal=%d\n", got, got == sizeof text && memcmp(text, want, sizeof text) == 0);
    static unsigned char b[BLOCK], w[BLOCK];
    int good = 0;
    for (int k = 0; k < BLOCKS; k++) { block(w, k); if (fread(b, BLOCK, 1, f) == 1 && memcmp(b, w, BLOCK) == 0) good++; }
    printf("fread blocks equal=%d of %d\n", good, BLOCKS);
    char one; size_t past = fread(&one, 1, 1, f);
    printf("fread at end=%zu eof=%d\n", past, feof(f) != 0);
    char buf[64];
    fseek(f, 10 * 500, SEEK_SET); if (!fgets(buf, sizeof buf, f)) return 1;
    printf("line at 5000: %s", buf);
    rewind(f); int lines = 0, c; long n = 0; while ((c = fgetc(f)) != EOF && n++ < LINES * 10) if (c == '\n') lines++;
    printf("text lines=%d\n", lines);
    fclose(f);
    f = fopen(PATH, "a"); if (!f) return 1; fputs("tail\n", f); fclose(f);
    f = fopen(PATH, "r"); if (!f) return 1; fseek(f, -5, SEEK_END); if (!fgets(buf, sizeof buf, f)) return 1;
    printf("appended: %s", buf); fclose(f);
    if (remove(PATH) != 0) printf("remove: %s\n", errname(errno)); else printf("removed\n");
    if (fopen(PATH, "r") == NULL) printf("gone: %s\n", errname(errno));
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "write") == 0) return do_write();
    if (argc > 1 && strcmp(argv[1], "verify") == 0) return do_verify();
    fprintf(stderr, "usage: stdio write|verify\n");
    return 2;
}
