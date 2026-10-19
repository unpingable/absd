/* Stage-0 probe: link form only. Writes through the raw console syscall
   (write, number 1, handle in RDI at entry) and exits with the raw exit
   syscall. Pulls one libm and one builtins symbol so the archives are
   really linked at this address. */
#include <stdint.h>
#include <math.h>

static long absd_sys3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "memory");
    return r;
}

/* External linkage: only the asm stub writes console, and a static would be
   folded to 0; wide must not be folded either, or no builtins call is made. */
uint64_t console;
__int128 wide = 1;

__attribute__((noreturn)) void absd_c_main(void) {
    const char text[] = "hello from C on ABSD\n";
    double d = sqrt(16.0);           /* libm */
    wide = wide * 3 / (wide + 1);    /* 3/2: non-constant divisor, so __divti3 */
    if (d != 4.0 || (long)wide != 1) absd_sys3(3, 2, 0, 0);
    for (unsigned off = 0; off < sizeof text - 1; ) {
        long n = absd_sys3(1, (long)console, (long)(text + off), (long)(sizeof text - 1 - off));
        if (n <= 0) absd_sys3(3, 1, 0, 0);
        off += (unsigned)n;
    }
    absd_sys3(3, 0, 0, 0);
    __builtin_unreachable();
}

__asm__(".globl _start\n_start:\n"
        "  mov %rdi, console(%rip)\n"
        "  call absd_c_main\n"
        "  ud2\n");
