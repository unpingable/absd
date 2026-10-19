#include <setjmp.h>
#include <stdio.h>
static jmp_buf back;
static void three(void) { printf("three\n"); longjmp(back, 42); }
static void two(void) { printf("two\n"); three(); printf("unreachable\n"); }
static void one(void) { printf("one\n"); two(); }
int main(void) {
    volatile int count = 0;
    int v = setjmp(back);
    printf("setjmp=%d\n", v);
    if (v == 0) { count = 1; one(); }
    printf("count=%d\n", count);
    return 0;
}
