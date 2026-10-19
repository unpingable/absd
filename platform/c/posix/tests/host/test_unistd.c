#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "absd/kit.h"
#include "absd/runtime.h"
#include "mock_runtime.h"
#include "mock_posix.h"

int absd_open(const char *, int, ...); int absd_close(int);
int absd_posix_chdir(const char *); char *absd_posix_getcwd(char *, size_t); int absd_posix_rmdir(const char *);
ssize_t absd_posix_readlink(const char *, char *, size_t); int absd_posix_access(const char *, int);
int absd_posix_fchown(int, uid_t, gid_t); int absd_posix_chown(const char *, uid_t, gid_t); int absd_posix_lchown(const char *, uid_t, gid_t);
uid_t absd_posix_getuid(void); uid_t absd_posix_geteuid(void); gid_t absd_posix_getgid(void); gid_t absd_posix_getegid(void);
int absd_posix_setuid(uid_t); int absd_posix_seteuid(uid_t); int absd_posix_setgid(gid_t); int absd_posix_setegid(gid_t);
int absd_posix_symlink(const char *, const char *); int absd_posix_gethostname(char *, size_t);
#define P(s) (const unsigned char *)(s), strlen(s)

static int listing_count(const char *dir) {
    unsigned char name[256]; struct absd_raw_attr attr; int n = 0;
    while (__absd_std_fs_readdir(P(dir), (uint64_t)n, name, 256, &attr) > 0) n++;
    return n;
}

int main(void) {
    char root[] = "/tmp/posixuniXXXXXX"; assert(mkdtemp(root));
    mock_fs_root(root); mock_posix_root(root); mock_posix_reset();
    assert(__absd_std_fs_mkdir(P("/d")) == 0);
    int fd = absd_open("/d/f", O_RDWR | O_CREAT); assert(fd >= 3);
    /* chdir and getcwd */
    assert(absd_posix_chdir("/d") == 0);
    char buf[32];
    assert(absd_posix_getcwd(buf, sizeof buf) == buf && strcmp(buf, "/d") == 0);
    assert(absd_posix_getcwd(buf, 3) == buf && strcmp(buf, "/d") == 0);                 /* exactly path + NUL fits */
    memset(buf, 'x', sizeof buf); errno = 0; assert(absd_posix_getcwd(buf, 2) == NULL && errno == ERANGE && buf[0] == 'x');
    errno = 0; assert(absd_posix_getcwd(buf, 0) == NULL && errno == EINVAL);
    char *own = absd_posix_getcwd(NULL, 0); assert(own && strcmp(own, "/d") == 0); free(own);
    own = absd_posix_getcwd(NULL, 8); assert(own && strcmp(own, "/d") == 0); free(own);
    errno = 0; assert(absd_posix_getcwd(NULL, 2) == NULL && errno == ERANGE);
    errno = 0; assert(absd_posix_chdir("/none") == -1 && errno == ENOENT);
    errno = 0; assert(absd_posix_chdir("/d/f") == -1 && errno == ENOTDIR);
    errno = 0; assert(absd_posix_chdir("") == -1 && errno == ENOENT);
    assert(absd_posix_chdir("/") == 0);
    /* readlink: no object is a link */
    errno = 0; assert(absd_posix_readlink("/d/f", buf, sizeof buf) == -1 && errno == EINVAL);
    errno = 0; assert(absd_posix_readlink("/d", buf, sizeof buf) == -1 && errno == EINVAL);
    errno = 0; assert(absd_posix_readlink("/none", buf, sizeof buf) == -1 && errno == ENOENT);
    /* access: F_OK; R_OK and W_OK probes on a file; W_OK on a directory refused with the listing unchanged; X_OK */
    assert(absd_posix_access("/d/f", F_OK) == 0 && absd_posix_access("/d", F_OK) == 0);
    errno = 0; assert(absd_posix_access("/none", F_OK) == -1 && errno == ENOENT);
    errno = 0; assert(absd_posix_access("", F_OK) == -1 && errno == ENOENT);
    int handles = mock_open_handles();
    assert(absd_posix_access("/d/f", R_OK) == 0 && absd_posix_access("/d/f", W_OK) == 0 && absd_posix_access("/d/f", R_OK | W_OK) == 0);
    assert(mock_open_handles() == handles);                                               /* probes close what they open */
    assert(absd_posix_access("/d", R_OK) == 0 && absd_posix_access("/d", X_OK) == 0 && absd_posix_access("/d", R_OK | X_OK) == 0);
    int entries = listing_count("/d");
    errno = 0; assert(absd_posix_access("/d", W_OK) == -1 && errno == ENOSYS);
    errno = 0; assert(absd_posix_access("/d", R_OK | W_OK | X_OK) == -1 && errno == ENOSYS);
    assert(listing_count("/d") == entries);                                               /* no probe file was created */
    errno = 0; assert(absd_posix_access("/d/f", X_OK) == -1 && errno == EINVAL);
    errno = 0; assert(absd_posix_access("/d/f", 8) == -1 && errno == EINVAL);
    assert(__absd_std_fs_set_readonly_path(P("/d/f"), 1) == 0);
    assert(absd_posix_access("/d/f", R_OK) == 0);
    if (geteuid() != 0) { errno = 0; assert(absd_posix_access("/d/f", W_OK) == -1 && errno == EACCES); }  /* the object is marked read-only */
    else puts("test_unistd: access W_OK EACCES row skipped: root bypasses the host's 0444 mode the mock relies on");
    assert(__absd_std_fs_set_readonly_path(P("/d/f"), 0) == 0);
    mock_fs_readonly(1);
    errno = 0; assert(absd_posix_access("/d/f", W_OK) == -1 && errno == EROFS);           /* a read-only mount */
    assert(absd_posix_access("/d/f", R_OK) == 0);
    mock_fs_readonly(0);
    /* identity: synthetic 1000, no authority; the setuid and chown families refused */
    assert(absd_posix_getuid() == 1000 && absd_posix_geteuid() == 1000 && absd_posix_getgid() == 1000 && absd_posix_getegid() == 1000);
    errno = 0; assert(absd_posix_fchown(fd, 0, 0) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_fchown(fd, 1000, 1000) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_fchown(40, 1000, 1000) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_chown("/d/f", 1000, 1000) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_lchown("/d/f", 1000, 1000) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_setuid(1000) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_seteuid(0) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_setgid(1000) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_setegid(1000) == -1 && errno == EPERM);
    /* symlink and gethostname refused */
    errno = 0; assert(absd_posix_symlink("/d/f", "/d/l") == -1 && errno == EPERM);
    assert(absd_posix_access("/d/l", F_OK) == -1);
    errno = 0; assert(absd_posix_gethostname(buf, sizeof buf) == -1 && errno == ENOSYS);
    /* rmdir */
    errno = 0; assert(absd_posix_rmdir("/d") == -1 && errno == ENOTEMPTY);
    errno = 0; assert(absd_posix_rmdir("/d/f") == -1 && errno == ENOTDIR);
    errno = 0; assert(absd_posix_rmdir("/none") == -1 && errno == ENOENT);
    errno = 0; assert(absd_posix_rmdir("") == -1 && errno == ENOENT);
    assert(absd_close(fd) == 0 && __absd_std_fs_unlink(P("/d/f")) == 0 && absd_posix_rmdir("/d") == 0);
    assert(rmdir(root) == 0);
    puts("test_unistd OK");
    return 0;
}
