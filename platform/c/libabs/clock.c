/* Clocks and the small OS functions Picolibc may reference (upstream
   doc/os.md): gettimeofday from the kernel's wall clock (whole seconds;
   refused honestly when the RTC has no stable reading), times from ticks
   (about 1 kHz), clock from the same ticks scaled to CLOCKS_PER_SEC (ruling
   R12, so Picolibc's unscaled clock() never links), getentropy from RDRAND, getpid. sbrk is refused: there
   is no brk and exactly one allocator (malloc.c). isatty is always false:
   a console is not a terminal. raise/kill: there is no signal delivery;
   raise(SIGABRT), abort's call, ends the process with status 134; signal 0
   and out-of-range numbers are EINVAL, every other signal ENOSYS.
   Sleeps go to the kernel sleep call in whole ticks (1 tick = 1 ms, rounded
   up, at least one tick for any positive duration). sysconf, pathconf,
   fpathconf and sigprocmask are defined here so that none of Picolibc's
   silent libos fallbacks links: each answer is a kit-owned value or a
   refusal. */
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>
#include "absd/kit.h"
#include "absd/runtime.h"
#include "absd/syscall.h"

int gettimeofday(struct timeval *tv, void *tz) {
    (void)tz;
    int64_t seconds = __absd_std_wall_clock_seconds();
    if (seconds < 0) { errno = absd_errno_from_native((long)seconds); return -1; }
    tv->tv_sec = (time_t)seconds;
    tv->tv_usec = 0;                       /* whole seconds only: the kernel's contract */
    return 0;
}

clock_t times(struct tms *buf) {
    uint64_t ticks = __absd_std_ticks();
    if (buf) { buf->tms_utime = (clock_t)ticks; buf->tms_stime = 0; buf->tms_cutime = 0; buf->tms_cstime = 0; }
    return (clock_t)ticks;
}

/* Ruling R12: ticks (1 tick taken as 1 ms) times CLOCKS_PER_SEC / 1000,
   saturating at the clock_t maximum. Boot time, not process CPU time, as
   times() reports it. */
_Static_assert((clock_t)-1 > 0 && sizeof(clock_t) == sizeof(uint64_t), "clock_t is uint64_t");
_Static_assert(CLOCKS_PER_SEC % 1000 == 0, "CLOCKS_PER_SEC is a whole multiple of 1000");
clock_t clock(void) {
    uint64_t ticks = __absd_std_ticks();
    const uint64_t scale = CLOCKS_PER_SEC / 1000;
    if (ticks > UINT64_MAX / scale) return (clock_t)UINT64_MAX;
    return (clock_t)(ticks * scale);
}

int getentropy(void *buffer, size_t length) {
    if (length > 256) { errno = EIO; return -1; }
    unsigned char *out = buffer;
    for (size_t i = 0; i < length; ) {
        unsigned long long value; int tries = 0;
        while (!__builtin_ia32_rdrand64_step(&value)) { if (++tries > 100) { errno = EIO; return -1; } }
        for (int b = 0; b < 8 && i < length; b++, i++) out[i] = (unsigned char)(value >> (8 * b));
    }
    return 0;
}

pid_t getpid(void) { return (pid_t)__absd_std_getpid(); }

void *sbrk(intptr_t increment) { (void)increment; errno = ENOMEM; return (void *)-1; }

int isatty(int fd) { (void)fd; errno = ENOTTY; return 0; }

int raise(int sig) {
    if (sig == SIGABRT) _exit(134);        /* abort(): 128 + SIGABRT, as a host shell reports it */
    if (sig <= 0 || sig >= _NSIG) { errno = EINVAL; return -1; }
    errno = ENOSYS;                        /* no delivery exists */
    return -1;
}
int kill(pid_t pid, int sig) { (void)pid; (void)sig; errno = ENOSYS; return -1; }

/* Sleeping: whole ticks, 1 tick = 1 ms (PIT divisor 1193), rounded up.
   The kernel call has no failure result (the runtime ignores it too); a
   zero-tick request is never sent for a positive duration. Saturates at
   LONG_MAX ticks. */
static void sleep_ms(uint64_t ms) {
    if (ms == 0) return;
    if (ms > (uint64_t)LONG_MAX) ms = (uint64_t)LONG_MAX;
    (void)absd_sys3(ABSD_SYS_SLEEP, (long)ms, 0, 0);
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
    if (!req || req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec > 999999999L) {
        errno = EINVAL; return -1;
    }
    uint64_t sec = (uint64_t)req->tv_sec;
    uint64_t ms = (uint64_t)((req->tv_nsec + 999999L) / 1000000L);
    if (sec > ((uint64_t)LONG_MAX - ms) / 1000u) ms = (uint64_t)LONG_MAX;
    else ms += sec * 1000u;
    sleep_ms(ms);
    if (rem) { rem->tv_sec = 0; rem->tv_nsec = 0; }
    return 0;
}

int usleep(useconds_t us) {
    sleep_ms(((uint64_t)us + 999u) / 1000u);
    return 0;
}

unsigned sleep(unsigned s) {
    sleep_ms((uint64_t)s * 1000u);
    return 0;
}

long sysconf(int name) {
    switch (name) {
#ifdef _SC_PAGESIZE
    case _SC_PAGESIZE: return 4096;        /* also _SC_PAGE_SIZE where it aliases */
#endif
#if defined(_SC_PAGE_SIZE) && defined(_SC_PAGESIZE) && _SC_PAGE_SIZE != _SC_PAGESIZE
    case _SC_PAGE_SIZE: return 4096;
#endif
#ifdef _SC_OPEN_MAX
    case _SC_OPEN_MAX: return ABSD_FD_MAX;
#endif
#ifdef _SC_NPROCESSORS_ONLN
    case _SC_NPROCESSORS_ONLN: return 1;   /* one task per process */
#endif
#ifdef _SC_NPROCESSORS_CONF
    case _SC_NPROCESSORS_CONF: return 1;
#endif
#ifdef _SC_CLK_TCK
    case _SC_CLK_TCK: return 1000;         /* ticks per second as times() reports them */
#endif
    default: errno = EINVAL; return -1;
    }
}

static long path_limit(int name) {
    switch (name) {
#ifdef _PC_PATH_MAX
    case _PC_PATH_MAX: return 1024;        /* the record's and the PAL's limit */
#endif
#ifdef _PC_NAME_MAX
    case _PC_NAME_MAX: return 256;
#endif
    default: errno = EINVAL; return -1;
    }
}

long pathconf(const char *path, int name) { (void)path; return path_limit(name); }
long fpathconf(int fd, int name) { (void)fd; return path_limit(name); }

int sigprocmask(int how, const sigset_t *set, sigset_t *old) {
    (void)how; (void)set; (void)old; errno = ENOSYS; return -1;
}
