#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "absd/kit.h"
#include "absd/runtime.h"
#include "mock_runtime.h"
#include "mock_posix.h"

int absd_open(const char *, int, ...); int absd_close(int);
int absd_posix_rename(const char *, const char *); char *absd_posix_realpath(const char *, char *);
int absd_posix_chdir(const char *);
#define P(s) (const unsigned char *)(s), strlen(s)
static void touch(const char *path) { int fd = absd_open(path, O_RDWR | O_CREAT); assert(fd >= 3 && absd_close(fd) == 0); }

int main(void) {
    char root[] = "/tmp/posixrenXXXXXX"; assert(mkdtemp(root));
    mock_fs_root(root); mock_posix_root(root); mock_posix_reset();
    assert(__absd_std_fs_mkdir(P("/d")) == 0 && __absd_std_fs_mkdir(P("/d/s1")) == 0 && __absd_std_fs_mkdir(P("/d/s2")) == 0);
    touch("/d/a"); touch("/d/b");
    /* rename: a file replaces a file in one commit; directory over directory refused (CPA-033) */
    assert(absd_posix_rename("/d/a", "/d/c") == 0);
    assert(absd_open("/d/a", O_RDONLY) == -1 && errno == ENOENT);
    assert(absd_posix_rename("/d/b", "/d/c") == 0);                                     /* replace */
    errno = 0; assert(absd_posix_rename("/d/s1", "/d/s2") == -1 && errno == EISDIR);
    errno = 0; assert(absd_posix_rename("/d/none", "/d/x") == -1 && errno == ENOENT);
    errno = 0; assert(absd_posix_rename("", "/d/x") == -1 && errno == ENOENT);
    errno = 0; assert(absd_posix_rename("/d/c", "") == -1 && errno == ENOENT);
    mock_fs_readonly(1); errno = 0; assert(absd_posix_rename("/d/c", "/d/e") == -1 && errno == EROFS); mock_fs_readonly(0);
    /* realpath: canonical path of an existing object; relative against the cwd; NULL output allocates */
    char out[PATH_MAX];
    assert(absd_posix_realpath("/d//s1/../c", out) == out && strcmp(out, "/d/c") == 0);
    assert(absd_posix_chdir("/d/s1") == 0);
    assert(absd_posix_realpath("../c", out) == out && strcmp(out, "/d/c") == 0);
    assert(absd_posix_realpath(".", out) == out && strcmp(out, "/d/s1") == 0);
    char *own = absd_posix_realpath("..", NULL); assert(own && strcmp(own, "/d") == 0); free(own);
    errno = 0; assert(absd_posix_realpath("/d/none", out) == NULL && errno == ENOENT);
    errno = 0; assert(absd_posix_realpath("", out) == NULL && errno == ENOENT);
    assert(absd_posix_chdir("/") == 0);
    /* a path too long to canonicalize is ENAMETOOLONG. The mock, like the
       runtime, refuses a path of 1024 bytes or more (-36, the record's limit)
       before PATH_MAX - 1 is reached, so the loop stops at the first
       component the hook refuses and realpath is asked for that path. */
    char deep[PATH_MAX + 64] = "/d"; size_t at = 2; int64_t made = 0;
    while (at + 64 < sizeof deep - 1) {
        memcpy(deep + at, "/ddddddddddddddddddddddddddddddd", 32); at += 32; deep[at] = 0;
        made = __absd_std_fs_mkdir(P(deep)); if (made == -36) break; assert(made == 0);
    }
    assert(made == -36);
    errno = 0; assert(absd_posix_realpath(deep, out) == NULL && errno == ENAMETOOLONG);
    at -= 32; deep[at] = 0;                                                             /* never made */
    while (at > 2) { assert(__absd_std_fs_rmdir(P(deep)) == 0); at -= 32; deep[at] = 0; }
    assert(__absd_std_fs_unlink(P("/d/c")) == 0 && __absd_std_fs_rmdir(P("/d/s1")) == 0 && __absd_std_fs_rmdir(P("/d/s2")) == 0 && __absd_std_fs_rmdir(P("/d")) == 0);
    assert(rmdir(root) == 0);
    /* the hook's -22 (capacity) is ENAMETOOLONG; another refusal keeps its own errno; an allocated buffer is freed */
    size_t live = mock_live_bytes();
    mock_posix_next_canonical(-22);
    errno = 0; assert(absd_posix_realpath("/d", NULL) == NULL && errno == ENAMETOOLONG && mock_live_bytes() == live);
    mock_posix_next_canonical(-5);
    errno = 0; assert(absd_posix_realpath("/d", out) == NULL && errno == EIO);
    puts("test_rename_realpath OK");
    return 0;
}
