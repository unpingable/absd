#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include "mock_runtime.h"
#include "mock_posix.h"

int absd_posix_system(const char *); FILE *absd_posix_popen(const char *, const char *); int absd_posix_pclose(FILE *);
void (*absd_posix_signal(int, void (*)(int)))(int);
int absd_posix_ioctl(int, unsigned long, void *); int absd_posix_getrusage(int, struct rusage *);
int absd_posix_utimes(const char *, const struct timeval[2]);
static void handler(int s) { (void)s; }

int main(void) {
    errno = 0; assert(absd_posix_system(NULL) == 0);                                    /* no command processor: ISO C says 0 */
    errno = 0; assert(absd_posix_system("echo x") == -1 && errno == ENOSYS);
    errno = 0; assert(absd_posix_popen("echo x", "r") == NULL && errno == ENOSYS);
    errno = 0; assert(absd_posix_pclose(stdout) == -1 && errno == ECHILD);
    errno = 0; assert(absd_posix_signal(SIGINT, handler) == SIG_ERR && errno == ENOSYS);
    errno = 0; assert(absd_posix_signal(SIGINT, SIG_DFL) == SIG_ERR && errno == ENOSYS);
    errno = 0; assert(absd_posix_signal(SIGPIPE, SIG_IGN) == SIG_ERR && errno == ENOSYS);
    errno = 0; assert(absd_posix_signal(SIGABRT, SIG_IGN) == SIG_ERR && errno == ENOSYS);
    int w = 0; errno = 0; assert(absd_posix_ioctl(1, 0x5413, &w) == -1 && errno == ENOTTY && w == 0);
    struct rusage ru; memset(&ru, 0x5a, sizeof ru);
    errno = 0; assert(absd_posix_getrusage(0, &ru) == -1 && errno == ENOSYS && ((unsigned char *)&ru)[0] == 0x5a);
    struct timeval tv[2] = {{1, 2}, {3, 4}};
    errno = 0; assert(absd_posix_utimes("/x", tv) == -1 && errno == ENOSYS);
    puts("test_refusals OK");
    return 0;
}
