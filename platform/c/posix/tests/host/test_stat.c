#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "absd/kit.h"
#include "absd/runtime.h"
#include "mock_runtime.h"
#include "mock_posix.h"

int absd_open(const char *, int, ...); int absd_close(int); int absd_fstat(int, struct stat *);
int absd_posix_stat(const char *, struct stat *); int absd_posix_lstat(const char *, struct stat *);
int absd_posix_mkdir(const char *, mode_t); int absd_posix_chmod(const char *, mode_t); int absd_posix_fchmod(int, mode_t);

int main(void) {
    char root[] = "/tmp/posixstatXXXXXX"; assert(mkdtemp(root));
    mock_fs_root(root); mock_posix_root(root); mock_posix_reset();
    struct stat a, b;
    /* a file: stat equals fstat field by field (the kit's converter) */
    int fd = absd_open("/f.txt", O_RDWR | O_CREAT); assert(fd >= 3);
    assert(absd_fstat(fd, &a) == 0 && absd_posix_stat("/f.txt", &b) == 0);
    assert(memcmp(&a, &b, sizeof a) == 0);
    assert(S_ISREG(b.st_mode) && (b.st_mode & 07777) == 0644 && b.st_uid == 1000 && b.st_gid == 1000 && b.st_mtime == 0);
    assert(absd_posix_lstat("/f.txt", &a) == 0 && memcmp(&a, &b, sizeof a) == 0);   /* no symbolic links exist (A13) */
    /* refusals: empty path, missing, a file as a directory component */
    errno = 0; assert(absd_posix_stat("", &a) == -1 && errno == ENOENT);
    errno = 0; assert(absd_posix_stat("/none", &a) == -1 && errno == ENOENT);
    errno = 0; assert(absd_posix_stat("/f.txt/x", &a) == -1 && errno == ENOTDIR);
    /* mkdir: created, reported as the kit's directory mode (declared divergence CPA-014), EEXIST, read-only mode refused */
    assert(absd_posix_mkdir("/d", 0777) == 0);
    assert(absd_posix_stat("/d", &a) == 0 && S_ISDIR(a.st_mode) && (a.st_mode & 07777) == 0644);
    errno = 0; assert(absd_posix_mkdir("/d", 0777) == -1 && errno == EEXIST);
    errno = 0; assert(absd_posix_mkdir("/d/x/y", 0777) == -1 && errno == ENOENT);
    errno = 0; assert(absd_posix_mkdir("/ro", 0555) == -1 && errno == EPERM);
    assert(absd_posix_stat("/ro", &a) == -1);                                   /* nothing created */
    errno = 0; assert(absd_posix_mkdir("", 0777) == -1 && errno == ENOENT);
    /* chmod: 0444 and 0644 round trip through the mark; every other mode EPERM; directories EPERM */
    assert(absd_posix_chmod("/f.txt", 0444) == 0 && mock_posix_readonly("/f.txt") == 1);
    if (geteuid() != 0) { errno = 0; assert(absd_open("/f.txt", O_WRONLY) == -1 && errno == EACCES); }  /* the object marked read-only refuses a write open */
    else puts("test_stat: write-open EACCES row skipped: root bypasses the host's 0444 mode the mock relies on");
    assert(absd_posix_chmod("/f.txt", 0644) == 0 && mock_posix_readonly("/f.txt") == 0);
    errno = 0; assert(absd_posix_chmod("/f.txt", 0666) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_chmod("/f.txt", 0600) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_chmod("/f.txt", 0755) == -1 && errno == EPERM);
    assert(mock_posix_readonly("/f.txt") == 0);
    errno = 0; assert(absd_posix_chmod("/d", 0644) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_chmod("/d", 0444) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_chmod("/none", 0644) == -1 && errno == ENOENT);
    /* fchmod: the same by descriptor; stdio and closed descriptors EBADF */
    assert(absd_posix_fchmod(fd, 0444) == 0 && mock_posix_readonly("/f.txt") == 1);
    assert(absd_posix_fchmod(fd, 0644) == 0 && mock_posix_readonly("/f.txt") == 0);
    errno = 0; assert(absd_posix_fchmod(fd, 0600) == -1 && errno == EPERM);
    errno = 0; assert(absd_posix_fchmod(1, 0644) == -1 && errno == EBADF);
    errno = 0; assert(absd_posix_fchmod(40, 0644) == -1 && errno == EBADF);
    assert(absd_close(fd) == 0);
    errno = 0; assert(absd_posix_fchmod(fd, 0644) == -1 && errno == EBADF);
    /* a read-only mount: mkdir and chmod are EROFS, stat still answers */
    mock_fs_readonly(1);
    errno = 0; assert(absd_posix_mkdir("/d2", 0777) == -1 && errno == EROFS);
    errno = 0; assert(absd_posix_chmod("/f.txt", 0444) == -1 && errno == EROFS);
    assert(absd_posix_stat("/f.txt", &a) == 0);
    mock_fs_readonly(0);
    /* an attribute kind outside 1..2 is EIO, no mode chosen (A13) */
    fd = absd_open("/f.txt", O_RDONLY); assert(fd >= 3);
    mock_next_fstat_kind(3);
    errno = 0; assert(absd_posix_fchmod(fd, 0644) == -1 && errno == EIO);
    assert(absd_close(fd) == 0);
    /* the path route: chmod and stat on a kind outside 1..2 are EIO too, and nothing is marked */
    mock_posix_next_stat_kind(3);
    errno = 0; assert(absd_posix_chmod("/f.txt", 0444) == -1 && errno == EIO && mock_posix_readonly("/f.txt") == 0);
    mock_posix_next_stat_kind(3);
    errno = 0; assert(absd_posix_stat("/f.txt", &a) == -1 && errno == EIO);
    assert(__absd_std_fs_unlink((const unsigned char *)"/f.txt", 6) == 0 && __absd_std_fs_rmdir((const unsigned char *)"/d", 2) == 0);
    assert(rmdir(root) == 0);
    puts("test_stat OK");
    return 0;
}
