#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "absd/kit.h"
#include "absd/runtime.h"
#include "mock_runtime.h"
#include "mock_posix.h"

int absd_open(const char *, int, ...); int absd_close(int);
int absd_posix_fcntl(int, int, ...);

static struct flock L(short type, off_t start, off_t len) { struct flock l = {0}; l.l_type = type; l.l_whence = SEEK_SET; l.l_start = start; l.l_len = len; return l; }
static int lock(int fd, short type, off_t start, off_t len) { struct flock l = L(type, start, len); return absd_posix_fcntl(fd, F_SETLK, &l); }

int main(void) {
    char root[] = "/tmp/posixlockXXXXXX"; assert(mkdtemp(root));
    mock_fs_root(root); mock_posix_root(root); mock_posix_reset();
    int a = absd_open("/f", O_RDWR | O_CREAT), b = absd_open("/f", O_RDWR), r = absd_open("/f", O_RDONLY), w = absd_open("/f", O_WRONLY);
    assert(a >= 3 && b >= 3 && r >= 3 && w >= 3);
    /* whole-file requests: the two-handle conflict table of the kit's lock */
    assert(lock(a, F_WRLCK, 0, 0) == 0);
    errno = 0; assert(lock(b, F_RDLCK, 0, 0) == -1 && errno == EAGAIN);
    errno = 0; assert(lock(b, F_WRLCK, 0, 0) == -1 && errno == EAGAIN);
    assert(lock(a, F_RDLCK, 0, 0) == 0);                                 /* downgrade always succeeds */
    assert(lock(b, F_RDLCK, 0, 0) == 0);                                 /* shared + shared */
    errno = 0; assert(lock(a, F_WRLCK, 0, 0) == -1 && errno == EAGAIN);  /* upgrade refused while b holds shared; a's lock intact: */
    errno = 0; assert(lock(w, F_WRLCK, 0, 0) == -1 && errno == EAGAIN);
    assert(lock(b, F_UNLCK, 0, 0) == 0 && lock(b, F_UNLCK, 0, 0) == 0);  /* unlock is always 0 */
    assert(lock(a, F_WRLCK, 0, 0) == 0);
    assert(lock(a, F_UNLCK, 0, 0) == 0);
    /* access mode: a read lock on a write-only, or a write lock on a read-only descriptor, is EBADF (nothing locked) */
    int calls = mock_lock_calls();
    errno = 0; assert(lock(w, F_RDLCK, 0, 0) == -1 && errno == EBADF);
    errno = 0; assert(lock(r, F_WRLCK, 0, 0) == -1 && errno == EBADF);
    assert(mock_lock_calls() == calls);
    assert(lock(r, F_RDLCK, 0, 0) == 0 && lock(r, F_UNLCK, 0, 0) == 0 && lock(w, F_WRLCK, 0, 0) == 0 && lock(w, F_UNLCK, 0, 0) == 0);
    /* every other range: EINVAL and nothing locked (A10); SQLite's unix VFS sequence fails at its first call */
    calls = mock_lock_calls();
    errno = 0; assert(lock(a, F_RDLCK, 1, 1) == -1 && errno == EINVAL);
    errno = 0; assert(lock(a, F_WRLCK, 0, 1) == -1 && errno == EINVAL);
    errno = 0; assert(lock(a, F_RDLCK, 0x40000002, 510) == -1 && errno == EINVAL);     /* SHARED range read lock (unix VFS) */
    errno = 0; assert(lock(a, F_WRLCK, 0x40000000, 1) == -1 && errno == EINVAL);       /* PENDING byte */
    errno = 0; assert(lock(a, F_WRLCK, 0x40000001, 1) == -1 && errno == EINVAL);       /* RESERVED byte */
    errno = 0; assert(lock(a, F_UNLCK, 1, 0) == -1 && errno == EINVAL);
    struct flock cur = L(F_WRLCK, 0, 0); cur.l_whence = SEEK_CUR;
    errno = 0; assert(absd_posix_fcntl(a, F_SETLK, &cur) == -1 && errno == EINVAL);
    struct flock end = L(F_WRLCK, 0, 0); end.l_whence = SEEK_END;
    errno = 0; assert(absd_posix_fcntl(a, F_SETLK, &end) == -1 && errno == EINVAL);
    errno = 0; assert(lock(a, F_WRLCK, -1, 0) == -1 && errno == EINVAL);                 /* negative start */
    errno = 0; assert(lock(a, F_RDLCK, 0, -1) == -1 && errno == EINVAL);                 /* negative length */
    errno = 0; assert(lock(a, 99, 0, 0) == -1 && errno == EINVAL);                       /* whole-file, an odd l_type */
    errno = 0; assert(lock(w, F_RDLCK, 1, 1) == -1 && errno == EINVAL);                  /* P3: read range on write-only: EINVAL */
    errno = 0; assert(lock(r, F_WRLCK, 1, 1) == -1 && errno == EBADF);                   /* P3: write range on read-only: EBADF */
    assert(mock_lock_calls() == calls);
    assert(lock(b, F_WRLCK, 0, 0) == 0 && lock(b, F_UNLCK, 0, 0) == 0);   /* nothing was locked by the refused requests */
    /* the admitted SQLite unix-excl range (A17): exactly F_WRLCK, SEEK_SET, SHARED_FIRST, SHARED_SIZE, on a read-write descriptor */
    assert(lock(a, F_WRLCK, 0x40000002, 510) == 0);
    errno = 0; assert(lock(b, F_RDLCK, 0, 0) == -1 && errno == EAGAIN);                /* it is the native exclusive lock */
    errno = 0; assert(lock(b, F_WRLCK, 0x40000002, 510) == -1 && errno == EAGAIN);     /* a second unix-excl connection is denied */
    calls = mock_lock_calls();
    errno = 0; assert(lock(r, F_WRLCK, 0x40000002, 510) == -1 && errno == EBADF);      /* read-only descriptor: ordinary path, EBADF before EINVAL */
    errno = 0; assert(lock(w, F_WRLCK, 0x40000002, 510) == -1 && errno == EINVAL);     /* write-only descriptor: not admitted */
    errno = 0; assert(lock(a, F_WRLCK, 0x40000002, 511) == -1 && errno == EINVAL);     /* not the range: refused */
    errno = 0; assert(lock(a, F_WRLCK, 0x40000003, 510) == -1 && errno == EINVAL);
    errno = 0; assert(lock(a, F_RDLCK, 0x40000002, 510) == -1 && errno == EINVAL);     /* not the type */
    assert(mock_lock_calls() == calls);                                               /* the refusals never reached the lock */
    assert(lock(a, F_UNLCK, 0, 0) == 0);                                              /* whole-file unlock releases it */
    assert(lock(b, F_WRLCK, 0, 0) == 0 && lock(b, F_UNLCK, 0, 0) == 0);
    assert(lock(a, F_WRLCK, 0x40000002, 510) == 0);
    assert(absd_close(a) == 0);                                                       /* close drops the lock */
    assert(lock(b, F_WRLCK, 0x40000002, 510) == 0 && lock(b, F_UNLCK, 0, 0) == 0);
    /* other commands: refused; stdio and closed descriptors EBADF */
    struct flock l = L(F_RDLCK, 0, 0);
    errno = 0; assert(absd_posix_fcntl(b, F_GETLK, &l) == -1 && errno == EINVAL);
    errno = 0; assert(absd_posix_fcntl(b, F_SETLKW, &l) == -1 && errno == EINVAL);
    errno = 0; assert(absd_posix_fcntl(b, F_GETFD) == -1 && errno == EINVAL);
    errno = 0; assert(absd_posix_fcntl(b, F_SETFD, 1) == -1 && errno == EINVAL);
    errno = 0; assert(absd_posix_fcntl(b, F_GETFL) == -1 && errno == EINVAL);
    errno = 0; assert(absd_posix_fcntl(b, F_SETFL, 0) == -1 && errno == EINVAL);
    errno = 0; assert(absd_posix_fcntl(b, F_DUPFD, 10) == -1 && errno == EINVAL);
    errno = 0; assert(absd_posix_fcntl(b, F_SETLK, NULL) == -1 && errno == EINVAL);
    errno = 0; assert(absd_posix_fcntl(1, F_SETLK, &l) == -1 && errno == EBADF);     /* F_RDLCK on write-only stdout: access mode */
    for (int fd = 0; fd <= 2; fd++)                                                   /* every stdio descriptor and lock type */
        for (int t = 0; t < 3; t++) {
            struct flock s = L(t == 0 ? F_RDLCK : t == 1 ? F_WRLCK : F_UNLCK, 0, 0);
            errno = 0; assert(absd_posix_fcntl(fd, F_SETLK, &s) == -1 && errno == EBADF);
        }
    errno = 0; assert(absd_posix_fcntl(40, F_SETLK, &l) == -1 && errno == EBADF);
    assert(absd_close(b) == 0 && absd_close(r) == 0 && absd_close(w) == 0);
    errno = 0; assert(absd_posix_fcntl(b, F_SETLK, &l) == -1 && errno == EBADF);
    assert(__absd_std_fs_unlink((const unsigned char *)"/f", 2) == 0 && rmdir(root) == 0);
    puts("test_fcntl_lock OK");
    return 0;
}
