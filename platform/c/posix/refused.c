/* sys/ioctl.h, sys/resource.h, sys/time.h: refused (ADAPTER-DESIGN.md 2.8). */
#include <errno.h>
#include <sys/resource.h>
#include <sys/time.h>
#ifndef ABSD_HOST_TEST
#include <sys/ioctl.h>          /* the guest build checks the definition against Picolibc's prototype */
#endif
#include "posix_names.h"
#ifdef ABSD_HOST_TEST
/* glibc's ioctl is variadic, so the host cannot check the renamed
   definition against a header; this is Picolibc's prototype
   (sys/ioctl.h:44) restated, and the guest build (scripts/build-posix.sh,
   -Werror) checks the definition against the header itself. */
int POSIX_FN(ioctl)(int fd, unsigned long op, void *param);
#endif

/* No terminal exists; the SQLite shell falls back to its default width. */
int POSIX_FN(ioctl)(int fd, unsigned long op, void *param) { (void)fd; (void)op; (void)param; errno = ENOTTY; return -1; }
/* The kernel keeps no per-process CPU time; *ru untouched. */
int POSIX_FN(getrusage)(int who, struct rusage *ru) { (void)who; (void)ru; errno = ENOSYS; return -1; }
/* Only the file server's clock sets mtime. */
int POSIX_FN(utimes)(const char *path, const struct timeval times[2]) { (void)path; (void)times; errno = ENOSYS; return -1; }
