#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "writer") == 0) {        /* case 3: the reader stops early */
        static char line[300]; memset(line, 'w', 299); line[299] = '\n';
        long total = 0; for (int i = 0; i < 100; i++) { ssize_t n = write(1, line, 300); if (n < 0) { fprintf(stderr, "write failed after %ld bytes\n", total); return 0; } total += n; }
        fprintf(stderr, "wrote %ld bytes\n", total); return 0;
    }
    static char buf[70000]; size_t total = 0; ssize_t n;                    /* cases 1, 2: count stdin */
    while ((n = read(0, buf, sizeof buf)) > 0) total += (size_t)n;
    printf("read %zu bytes, final read %zd\n", total, n);
    return 0;
}
