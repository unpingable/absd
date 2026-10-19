/* The C kit's own interface: the userspace descriptor table over runtime
   handles (spec 3.2). Descriptors are a compatibility representation; a
   descriptor never outlives its handle and is never a kernel object. */
#ifndef ABSD_KIT_H
#define ABSD_KIT_H
#include <stddef.h>
#include <stdint.h>

#define ABSD_FD_MAX 67                 /* 3 stdio + the channel's 64 open files */
#define ABSD_STACK_PRETOUCH_BYTES (256u * 1024u)   /* crt0 pre-touch depth; spec 3.2 (A4) */
_Static_assert(ABSD_STACK_PRETOUCH_BYTES >= 4096 && ABSD_STACK_PRETOUCH_BYTES % 4096 == 0,
               "ABSD_STACK_PRETOUCH_BYTES is a whole number of 4 KiB pages, at least one");

struct absd_raw_attr;
struct stat;

int absd_errno_from_native(long code);          /* errno_map.c */
int absd_fd_install_file(uint64_t handle, int append);
int absd_fd_is_open(int fd);
uint64_t absd_fd_handle(int fd);
/* O_RDONLY, O_WRONLY or O_RDWR for an open descriptor; -1 with EBADF. */
int absd_fd_access_mode(int fd);
/* The RawAttr -> struct stat conversion fstat uses (stat() shares it).
   0, or -1 with EIO for an attribute kind other than 1 (file) or 2
   (directory): the kit never chooses a mode for an object kind it does not
   know (SPEC A13, C-INTERFACE.md 6). */
int absd_stat_from_attr(const struct absd_raw_attr *attr, struct stat *out);
/* Advisory lock on a file descriptor: mode 0 unlock, 1 shared, 2 exclusive.
   Never waits: a conflicting lock is -1 with EAGAIN. */
int absd_fd_lock(int fd, int mode);
#endif
