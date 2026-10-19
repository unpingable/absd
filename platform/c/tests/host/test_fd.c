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

/* The kit's five calls are named absd_* in the host build (ABSD_HOST_TEST)
   so they do not collide with glibc's; in the guest they are open/close/... */
int absd_open(const char *, int, ...); int absd_close(int);
ssize_t absd_read(int, void *, size_t); ssize_t absd_write(int, const void *, size_t);
off_t absd_lseek(int, off_t, int);
int absd_unlink(const char *); int absd_fstat(int, struct stat *); int absd_ftruncate(int, off_t);

static void test_lock(void) {
    /* two descriptors on one file: exclusive on one refuses shared on the other */
    int a = absd_open("a.txt", O_RDWR), b = absd_open("a.txt", O_RDONLY);
    assert(a >= 3 && b >= 3 && a != b);
    assert(absd_fd_lock(a, 2) == 0);
    errno = 0; assert(absd_fd_lock(b, 1) == -1 && errno == EAGAIN);
    errno = 0; assert(absd_fd_lock(b, 2) == -1 && errno == EAGAIN);
    assert(absd_fd_lock(a, 1) == 0);                                   /* atomic downgrade */
    assert(absd_fd_lock(b, 1) == 0);                                   /* shared + shared */
    errno = 0; assert(absd_fd_lock(a, 2) == -1 && errno == EAGAIN);   /* upgrade blocked by b */
    assert(absd_fd_lock(b, 0) == 0 && absd_fd_lock(b, 0) == 0);        /* unlock is always 0 */
    assert(absd_fd_lock(a, 2) == 0);                                   /* now the upgrade lands */
    int calls = mock_lock_calls();                                     /* refused before the runtime: */
    errno = 0; assert(absd_fd_lock(b, 9) == -1 && errno == EINVAL);
    errno = 0; assert(absd_fd_lock(b, 3) == -1 && errno == EINVAL);
    errno = 0; assert(absd_fd_lock(b, -1) == -1 && errno == EINVAL);
    assert(mock_lock_calls() == calls);
    errno = 0; assert(absd_fd_lock(1, 1) == -1 && errno == EBADF);     /* not a file */
    errno = 0; assert(absd_fd_lock(40, 1) == -1 && errno == EBADF);
    assert(absd_close(a) == 0);                                        /* close drops a's lock */
    assert(absd_fd_lock(b, 2) == 0);
    assert(absd_close(b) == 0);
}

int main(void) {
    char dir[] = "/tmp/ckit-fd.XXXXXX"; assert(mkdtemp(dir)); mock_fs_root(dir);
    /* stdio descriptors exist and nothing else */
    assert(absd_fd_is_open(0) && absd_fd_is_open(1) && absd_fd_is_open(2) && !absd_fd_is_open(3));
    assert(absd_fd_access_mode(0) == O_RDONLY && absd_fd_access_mode(1) == O_WRONLY && absd_fd_access_mode(2) == O_WRONLY);
    errno = 0; assert(absd_fd_access_mode(3) == -1 && errno == EBADF);
    /* create, write, seek, read back; lowest free descriptor is 3 */
    int fd = absd_open("a.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(fd == 3);
    assert(absd_fd_access_mode(fd) == O_WRONLY);
    assert(absd_write(fd, "hello world\n", 12) == 12);
    assert(absd_lseek(fd, 0, SEEK_CUR) == 12);
    assert(absd_close(fd) == 0 && !absd_fd_is_open(3));
    errno = 0; assert(absd_close(fd) == -1 && errno == EBADF);          /* stale descriptor refused */
    fd = absd_open("a.txt", O_RDONLY);
    char buf[64] = {0};
    errno = 0; assert(absd_write(0, "x", 1) == -1 && errno == EBADF);   /* stdin is not writable */
    errno = 0; assert(absd_read(1, buf, 1) == -1 && errno == EBADF);    /* stdout is not readable */
    assert(absd_lseek(fd, 6, SEEK_SET) == 6 && absd_read(fd, buf, sizeof buf) == 6 && memcmp(buf, "world\n", 6) == 0);
    assert(absd_read(fd, buf, sizeof buf) == 0);                        /* EOF */
    assert(absd_lseek(fd, 0, SEEK_END) == 12);
    errno = 0; assert(absd_lseek(fd, -20, SEEK_SET) == -1 && errno == EINVAL);
    errno = 0; assert(absd_lseek(fd, 0, 7) == -1 && errno == EINVAL);
    /* fstat goes through absd_stat_from_attr */
    struct stat st;
    assert(absd_fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0644 && st.st_blksize == 65536);
    assert(st.st_size == 12 && st.st_nlink == 1 && st.st_uid == 1000 && st.st_gid == 1000 && st.st_mtime == 0);
    mock_next_fstat_kind(3); errno = 0; assert(absd_fstat(fd, &st) == -1 && errno == EIO);   /* kind 3: refused */
    assert(absd_fstat(fd, &st) == 0 && S_ISREG(st.st_mode));                                 /* one-shot */
    assert(absd_close(fd) == 0);
    struct absd_raw_attr attr = { 2, 1, 4096, 7, 99, 3 };
    assert(absd_stat_from_attr(&attr, &st) == 0);
    assert(S_ISDIR(st.st_mode) && (st.st_mode & 0777) == 0444 && st.st_size == 4096);
    assert((st.st_mode & S_IXUSR) == 0 && st.st_blksize == 65536);    /* no search bits; MAX_IO */
    /* an attribute kind outside 1 and 2 is refused, never given a mode (A13) */
    struct absd_raw_attr link = { 3, 0, 1, 7, 100, 1 };
    errno = 0; assert(absd_stat_from_attr(&link, &st) == -1 && errno == EIO);
    link.kind = 0; errno = 0; assert(absd_stat_from_attr(&link, &st) == -1 && errno == EIO);
    assert(st.st_dev == 7 && st.st_ino == 99 && st.st_nlink == 3 && st.st_uid == 1000 && st.st_gid == 1000);
    /* O_EXCL on an existing file: EEXIST, nothing changed */
    errno = 0; assert(absd_open("a.txt", O_WRONLY | O_CREAT | O_EXCL, 0644) == -1 && errno == EEXIST);
    /* append: every write lands at the end */
    fd = absd_open("a.txt", O_WRONLY | O_APPEND); assert(fd == 3);
    assert(absd_write(fd, "tail\n", 5) == 5 && absd_lseek(fd, 0, SEEK_CUR) == 17);
    absd_close(fd);
    /* truncate */
    fd = absd_open("a.txt", O_WRONLY | O_TRUNC); assert(absd_lseek(fd, 0, SEEK_END) == 0); absd_close(fd);
    /* unsupported flag bits are refused, not ignored */
    errno = 0; assert(absd_open("a.txt", O_RDONLY | O_NONBLOCK) == -1 && errno == EINVAL);
    /* O_CLOEXEC is an honest no-op (no exec on ABSD) */
    fd = absd_open("a.txt", O_RDONLY | O_CLOEXEC); assert(fd == 3 && absd_fd_access_mode(fd) == O_RDONLY); absd_close(fd);
#ifdef O_NOFOLLOW
    fd = absd_open("a.txt", O_RDONLY | O_NOFOLLOW); assert(fd == 3); absd_close(fd);   /* no symlinks: no-op */
#endif
    errno = 0; assert(absd_open("a.txt", O_ACCMODE) == -1 && errno == EINVAL);        /* access mode 3 */
    /* O_RDONLY|O_TRUNC is refused and truncates nothing */
    fd = absd_open("app", O_WRONLY | O_CREAT | O_TRUNC, 0644); assert(absd_write(fd, "0123", 4) == 4); absd_close(fd);
    errno = 0; assert(absd_open("app", O_RDONLY | O_TRUNC) == -1 && errno == EINVAL);
    /* O_EXCL without O_CREAT is ignored, as on Linux */
    fd = absd_open("app", O_RDONLY | O_EXCL); assert(fd == 3 && absd_lseek(fd, 0, SEEK_END) == 4); absd_close(fd);
    /* append lands at the end after an intervening lseek and after a second write */
    fd = absd_open("app", O_WRONLY | O_APPEND); assert(fd == 3);
    assert(absd_lseek(fd, 0, SEEK_SET) == 0 && absd_write(fd, "ab", 2) == 2 && absd_lseek(fd, 0, SEEK_CUR) == 6);
    assert(absd_write(fd, "cd", 2) == 2 && absd_lseek(fd, 0, SEEK_CUR) == 8);
    /* when the size cannot be read, append and SEEK_END fail and change nothing */
    assert(absd_lseek(fd, 1, SEEK_SET) == 1);
    mock_fail_next_fstat(1); errno = 0; assert(absd_write(fd, "zz", 2) == -1 && errno == EIO);
    assert(absd_lseek(fd, 0, SEEK_CUR) == 1);
    mock_fail_next_fstat(1); errno = 0; assert(absd_lseek(fd, 0, SEEK_END) == -1 && errno == EIO);
    assert(absd_lseek(fd, 0, SEEK_CUR) == 1);
    /* ftruncate: negative length and stdio descriptors are EINVAL */
    errno = 0; assert(absd_ftruncate(fd, -1) == -1 && errno == EINVAL);
    errno = 0; assert(absd_ftruncate(1, 0) == -1 && errno == EINVAL);
    absd_close(fd);
    { char app[16] = {0}; fd = absd_open("app", O_RDONLY);
      assert(absd_read(fd, app, sizeof app) == 8 && memcmp(app, "0123abcd", 8) == 0); absd_close(fd); }
    fd = absd_open("a.txt", O_RDWR); assert(absd_fd_access_mode(fd) == O_RDWR); absd_close(fd);
    /* read-only mount: EROFS, nothing created */
    mock_fs_readonly(1);
    errno = 0; assert(absd_open("b.txt", O_WRONLY | O_CREAT, 0644) == -1 && errno == EROFS);
    errno = 0; assert(absd_open("a.txt", O_WRONLY | O_TRUNC) == -1 && errno == EROFS);
    mock_fs_readonly(0);
    /* missing path */
    errno = 0; assert(absd_open("nope", O_RDONLY) == -1 && errno == ENOENT);
    /* unlink: an existing file goes, a second unlink is ENOENT */
    fd = absd_open("gone", O_WRONLY | O_CREAT, 0644); absd_close(fd);
    assert(absd_unlink("gone") == 0);
    errno = 0; assert(absd_unlink("gone") == -1 && errno == ENOENT);
    /* writes larger than one transfer are completed; zero-length is a no-op */
    static char big[70000]; memset(big, 'x', sizeof big);
    fd = absd_open("big", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(absd_write(fd, big, sizeof big) == (ssize_t)sizeof big && absd_write(fd, big, 0) == 0);
    absd_close(fd);
    fd = absd_open("big", O_RDONLY); static char back[70000];
    assert(absd_read(fd, back, sizeof back) == (ssize_t)sizeof back && memcmp(big, back, sizeof big) == 0);
    absd_close(fd);
    /* stdout: 256-byte transfers are looped; no reader is EPIPE and the program continues */
    assert(absd_write(1, big, 1000) == 1000);
    size_t n; mock_stdout(&n); assert(n == 1000);
    mock_stdout_broken(1); errno = 0;
    assert(absd_write(1, "x", 1) == -1 && errno == EPIPE);
    mock_stdout_broken(0);
    /* stdin from the mock, in 256-byte pieces, then EOF */
    mock_stdin("abc", 3); assert(absd_read(0, buf, sizeof buf) == 3 && absd_read(0, buf, sizeof buf) == 0);
    errno = 0; assert(absd_lseek(0, 0, SEEK_SET) == -1 && errno == ESPIPE);
    test_lock();
    /* table exhaustion: EMFILE at the cap, and descriptors come back after close */
    int fds[ABSD_FD_MAX]; int opened = 0; int handles = mock_open_handles();
    for (;;) { int f = absd_open("a.txt", O_RDONLY); if (f < 0) { assert(errno == EMFILE); break; } fds[opened++] = f; }
    assert(opened == ABSD_FD_MAX - 3);
    assert(mock_open_handles() == handles + opened);   /* the refused open closed its native handle */
    for (int i = 0; i < opened; i++) assert(absd_close(fds[i]) == 0);
    assert(mock_open_handles() == handles);
    assert(absd_open("a.txt", O_RDONLY) == 3);
    absd_close(3);
    /* closed stdio descriptors are EBADF, and open never hands out 0, 1, 2 */
    assert(absd_close(0) == 0 && absd_close(1) == 0 && absd_close(2) == 0);
    errno = 0; assert(absd_read(0, buf, 1) == -1 && errno == EBADF);
    errno = 0; assert(absd_write(1, "x", 1) == -1 && errno == EBADF);
    errno = 0; assert(absd_write(2, "x", 1) == -1 && errno == EBADF);
    assert(absd_open("a.txt", O_RDONLY) == 3);
    absd_close(3);
    assert(mock_open_handles() == 0);
    /* remove the scratch directory (glibc unlink and rmdir, not the kit's) */
    const char *names[] = { "a.txt", "big", "app" };
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        char path[sizeof dir + 16]; snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        assert(unlink(path) == 0);
    }
    assert(rmdir(dir) == 0);
    puts("test_fd OK");
    return 0;
}
