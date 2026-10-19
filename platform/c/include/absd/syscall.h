/* The one direct kernel-call shim the C kit uses (kernel contract:
   `int $0x80`, number in RAX, arguments in RDI, RSI, RDX, result in RAX).
   Everything else goes through the runtime's __absd_std_* hooks. The
   numbers match runtime/src/lib.rs (SYS_TIME, SYS_SLEEP). */
#ifndef ABSD_SYSCALL_H
#define ABSD_SYSCALL_H

#define ABSD_SYS_TIME  17
#define ABSD_SYS_SLEEP 18   /* argument: timer ticks (about 1 ms each); zero yields */

static inline long absd_sys3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "memory");
    return r;
}

#endif
