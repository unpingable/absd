#ifndef ABSD_POSIX_NAMES_H
#define ABSD_POSIX_NAMES_H
#include <errno.h>
#include <sys/stat.h>
#include "absd/kit.h"
#include "absd/runtime.h"
/* Host unit tests (ABSD_HOST_TEST) compile the adapter against glibc, so
   every POSIX name the adapter defines is renamed absd_posix_<name>, and
   the kit's calls it uses are the kit's host names (c/libabs/fd.c, R2). */
#ifdef ABSD_HOST_TEST
#define POSIX_FN(name) absd_posix_##name
int absd_open(const char *, int, ...);
int absd_close(int);
#define KIT_OPEN absd_open
#define KIT_CLOSE absd_close
#else
#define POSIX_FN(name) name
#define KIT_OPEN open
#define KIT_CLOSE close
#endif
/* A hook refusal (negative, Linux-numbered) as -1 with the libc errno. */
static inline int absd_posix_fail(long rc) { errno = absd_errno_from_native(rc); return -1; }
#define ABSD_POSIX_UID 1000   /* SPEC A8: synthetic, conveys no authority */
#define ABSD_POSIX_GID 1000   /* SPEC A8: the same synthetic value for the group */
#endif
