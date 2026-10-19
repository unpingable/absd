#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void bye1(void) { printf("atexit 1\n"); }
static void bye2(void) { printf("atexit 2\n"); }
__attribute__((constructor)) static void ctor(void) { printf("ctor\n"); }
__attribute__((destructor)) static void dtor(void) { printf("dtor\n"); }
static void nested(int code) { printf("nested exit %d\n", code); exit(code); }
int main(int argc, char **argv) {
    atexit(bye1); atexit(bye2);
    printf("main\n");
    if (argc > 1 && strcmp(argv[1], "nested") == 0) nested(3);
    if (argc > 1 && strcmp(argv[1], "_Exit") == 0) { printf("_Exit 5\n"); fflush(stdout); _Exit(5); }
    if (argc > 1 && strcmp(argv[1], "return") == 0) return 7;
    /* abort(): no atexit handlers, no destructors; flushed first so the
       bytes are the same in both worlds (Linux: SIGABRT; ABSD: status 134) */
    if (argc > 1 && strcmp(argv[1], "abort") == 0) { printf("abort\n"); fflush(stdout); abort(); }
    printf("return 0\n");
    return 0;
}
