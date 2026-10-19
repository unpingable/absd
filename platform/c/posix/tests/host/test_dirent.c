#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "absd/runtime.h"
#include "absd_dirent.h"
#include "mock_runtime.h"
#include "mock_posix.h"

ABSD_DIR *absd_posix_opendir(const char *); struct absd_dirent *absd_posix_readdir(ABSD_DIR *); int absd_posix_closedir(ABSD_DIR *);
#define P(s) (const unsigned char *)(s), strlen(s)

static void touch(const char *path) {
    int64_t h = __absd_std_fs_open(P(path), 1u | 2u | 8u); assert(h >= 1000); assert(__absd_std_fs_close((uint64_t)h) == 0);
}

int main(void) {
    char root[] = "/tmp/posixdirXXXXXX"; assert(mkdtemp(root));
    mock_fs_root(root); mock_posix_root(root); mock_posix_reset();
    assert(__absd_std_fs_mkdir(P("/d")) == 0 && __absd_std_fs_mkdir(P("/d/sub")) == 0 && __absd_std_fs_mkdir(P("/e")) == 0);
    touch("/d/b.txt"); touch("/d/a.txt"); touch("/e/only");
    /* listing in the native (name) order, types and serials, no dot entries, end is NULL with errno unchanged */
    ABSD_DIR *d = absd_posix_opendir("/d"); assert(d != NULL);
    struct absd_dirent *e;
    e = absd_posix_readdir(d); assert(e && strcmp(e->d_name, "a.txt") == 0 && e->d_type == ABSD_DT_REG && e->d_ino != 0);
    e = absd_posix_readdir(d); assert(e && strcmp(e->d_name, "b.txt") == 0 && e->d_type == ABSD_DT_REG);
    e = absd_posix_readdir(d); assert(e && strcmp(e->d_name, "sub") == 0 && e->d_type == ABSD_DT_DIR);
    errno = 7; e = absd_posix_readdir(d); assert(e == NULL && errno == 7);
    e = absd_posix_readdir(d); assert(e == NULL && errno == 7);                       /* stays at the end */
    assert(absd_posix_closedir(d) == 0);
    /* the snapshot is taken at opendir: one fetch there, none at readdir */
    int fetches = mock_posix_readdir_fetches();
    ABSD_DIR *x = absd_posix_opendir("/d"); assert(x && mock_posix_readdir_fetches() == fetches + 1);
    e = absd_posix_readdir(x); assert(e && mock_posix_readdir_fetches() == fetches + 1);
    assert(absd_posix_closedir(x) == 0);
    /* interleaved streams, an entry removed before x's cursor: x lists exactly what it had at opendir */
    x = absd_posix_opendir("/d"); ABSD_DIR *y = absd_posix_opendir("/e"); assert(x && y);
    e = absd_posix_readdir(x); assert(e && strcmp(e->d_name, "a.txt") == 0);
    e = absd_posix_readdir(y); assert(e && strcmp(e->d_name, "only") == 0);
    assert(__absd_std_fs_unlink(P("/d/a.txt")) == 0);                                /* before x's cursor */
    e = absd_posix_readdir(x); assert(e && strcmp(e->d_name, "b.txt") == 0);         /* not lost */
    e = absd_posix_readdir(x); assert(e && strcmp(e->d_name, "sub") == 0);
    e = absd_posix_readdir(x); assert(e == NULL);
    e = absd_posix_readdir(y); assert(e == NULL);
    assert(absd_posix_closedir(x) == 0 && absd_posix_closedir(y) == 0);
    /* interleaved streams, an entry inserted before x's cursor: nothing repeated, the new entry not seen */
    x = absd_posix_opendir("/d"); y = absd_posix_opendir("/e"); assert(x && y);
    e = absd_posix_readdir(x); assert(e && strcmp(e->d_name, "b.txt") == 0);
    e = absd_posix_readdir(y); assert(e && strcmp(e->d_name, "only") == 0);
    touch("/d/a.txt");                                                                 /* sorts before x's cursor */
    e = absd_posix_readdir(x); assert(e && strcmp(e->d_name, "sub") == 0);           /* b.txt not repeated */
    e = absd_posix_readdir(x); assert(e == NULL);
    assert(absd_posix_closedir(x) == 0 && absd_posix_closedir(y) == 0);
    /* a relative path is resolved once, at opendir: a later chdir does not move the stream */
    assert(__absd_std_chdir(P("/")) == 0);
    x = absd_posix_opendir("d"); assert(x);
    assert(__absd_std_chdir(P("/e")) == 0);
    e = absd_posix_readdir(x); assert(e && strcmp(e->d_name, "a.txt") == 0);
    e = absd_posix_readdir(x); assert(e && strcmp(e->d_name, "b.txt") == 0);
    e = absd_posix_readdir(x); assert(e && strcmp(e->d_name, "sub") == 0);
    e = absd_posix_readdir(x); assert(e == NULL);
    assert(absd_posix_closedir(x) == 0 && __absd_std_chdir(P("/")) == 0);
    /* an empty directory: the end at once */
    size_t live = mock_live_bytes();
    x = absd_posix_opendir("/d/sub"); assert(x);
    errno = 7; assert(absd_posix_readdir(x) == NULL && errno == 7 && absd_posix_closedir(x) == 0);
    assert(mock_live_bytes() == live);
    /* NULL streams */
    errno = 0; assert(absd_posix_readdir(NULL) == NULL && errno == EBADF);
    errno = 0; assert(absd_posix_closedir(NULL) == -1 && errno == EBADF);
    /* refusals */
    errno = 0; assert(absd_posix_opendir("/d/a.txt") == NULL && errno == ENOTDIR);
    errno = 0; assert(absd_posix_opendir("/none") == NULL && errno == ENOENT);
    errno = 0; assert(absd_posix_opendir("") == NULL && errno == ENOENT);
    /* a long path (longer than DIR's 512-byte buffer) is carried whole */
    /* three 200-byte components: one 600-byte component would exceed the host's NAME_MAX */
    char longdir[700] = "/d"; size_t ends[3];
    for (int i = 0; i < 3; i++) {
        size_t n = strlen(longdir); longdir[n] = '/'; memset(longdir + n + 1, 'n', 200); longdir[n + 201] = 0;
        ends[i] = n + 201; assert(__absd_std_fs_mkdir(P(longdir)) == 0);
    }
    assert(strlen(longdir) > 512);
    d = absd_posix_opendir(longdir); assert(d && absd_posix_readdir(d) == NULL && absd_posix_closedir(d) == 0);
    for (int i = 2; i >= 0; i--) { longdir[ends[i]] = 0; assert(__absd_std_fs_rmdir(P(longdir)) == 0); }
    /* memory: the stream frees what it allocated; every allocation failure is ENOMEM and keeps nothing */
    live = mock_live_bytes();
    d = absd_posix_opendir("/d"); assert(d && absd_posix_closedir(d) == 0 && mock_live_bytes() == live);
    mock_fail_next_alloc(1); errno = 0; assert(absd_posix_opendir("/d") == NULL && errno == ENOMEM);
    assert(mock_live_bytes() == live);
    int refused = 0;
    for (size_t budget = live + 1;; budget += 16) {                                   /* each failure point in turn */
        mock_set_budget(budget); errno = 0;
        d = absd_posix_opendir("/d");
        mock_set_budget(0);
        if (d) { assert(absd_posix_closedir(d) == 0); break; }
        assert(errno == ENOMEM && mock_live_bytes() == live); refused++;
    }
    assert(refused > 0 && mock_live_bytes() == live);
    /* a refusal from the hook part-way through the listing keeps nothing (the mock refuses -12 past 1024 entries) */
    assert(__absd_std_fs_mkdir(P("/many")) == 0);
    char many[32];
    for (int i = 0; i <= 1024; i++) { snprintf(many, sizeof many, "/many/%04d", i); touch(many); }
    errno = 0; assert(absd_posix_opendir("/many") == NULL && errno == ENOMEM && mock_live_bytes() == live);
    for (int i = 0; i <= 1024; i++) { snprintf(many, sizeof many, "/many/%04d", i); assert(__absd_std_fs_unlink(P(many)) == 0); }
    assert(__absd_std_fs_rmdir(P("/many")) == 0);
    /* cleanup */
    assert(__absd_std_fs_unlink(P("/d/a.txt")) == 0 && __absd_std_fs_unlink(P("/d/b.txt")) == 0);
    assert(__absd_std_fs_unlink(P("/e/only")) == 0 && __absd_std_fs_rmdir(P("/d/sub")) == 0 && __absd_std_fs_rmdir(P("/d")) == 0 && __absd_std_fs_rmdir(P("/e")) == 0);
    assert(rmdir(root) == 0);
    puts("test_dirent OK");
    return 0;
}
