/* The one direct kernel-call shim the C kit uses (kernel contract:
   `int $0x80`, number in RAX, arguments in RDI, RSI, RDX, result in RAX).
   Everything else goes through the runtime's __absd_std_* hooks. The
   numbers match runtime/src/lib.rs (SYS_TIME, SYS_SLEEP). */
#ifndef ABSD_SYSCALL_H
#define ABSD_SYSCALL_H

#include <stdint.h>

#define ABSD_SYS_TIME  17
#define ABSD_SYS_SLEEP 18   /* argument: timer ticks (about 1 ms each); zero yields */
#define ABSD_SYS_WAIT_READABLE 0x7fa8
#define ABSD_WAIT_READABLE_MAX 11
#define ABSD_WAIT_READABLE_POLL UINT64_MAX

static inline long absd_sys3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "memory");
    return r;
}

/* ABI 1 additive call. Kernel validation applies even for count zero;
   old kernels return -38. Returns a positional ready mask or negative error. */
static inline int64_t absd_wait_readable(const uint64_t *handles,
                                       uint64_t count, uint64_t ticks) {
    return absd_sys3(ABSD_SYS_WAIT_READABLE, (long)(uintptr_t)handles,
                     (long)count, (long)ticks);
}

#endif
