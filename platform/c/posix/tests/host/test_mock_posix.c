#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "absd/runtime.h"
#include "mock_runtime.h"
#include "mock_posix.h"

static unsigned char name[256]; static struct absd_raw_attr attr;
#define P(s) (const unsigned char *)(s), strlen(s)

int main(void) {
    char root[] = "/tmp/posixmockXXXXXX"; assert(mkdtemp(root));
    mock_fs_root(root); mock_posix_root(root); mock_posix_reset();
    assert(strcmp(mock_posix_cwd(), "/") == 0);
    /* mkdir, nested, EEXIST, missing parent */
    assert(__absd_std_fs_mkdir(P("/d")) == 0);
    assert(__absd_std_fs_mkdir(P("/d")) == -17);
    assert(__absd_std_fs_mkdir(P("/x/y")) == -2);
    assert(__absd_std_fs_mkdir(P("/d/sub")) == 0);
    /* chdir and getcwd: lexical, normalized, -22 when the buffer is short */
    assert(__absd_std_chdir(P("/d")) == 0 && strcmp(mock_posix_cwd(), "/d") == 0);
    assert(__absd_std_chdir(P("sub/../sub/.")) == 0 && strcmp(mock_posix_cwd(), "/d/sub") == 0);
    assert(__absd_std_chdir(P("")) == -2 && __absd_std_chdir(P("/nothing")) == -2);
    unsigned char cwd[16]; assert(__absd_std_getcwd(cwd, 6) == 6 && memcmp(cwd, "/d/sub", 6) == 0);
    assert(__absd_std_getcwd(cwd, 5) == -22);
    assert(__absd_std_chdir(P("/")) == 0);
    /* files for the listing: created through the kit mock's open */
    int64_t h = __absd_std_fs_open(P("/d/b.txt"), 1u | 2u | 8u); assert(h >= 1000);
    assert(__absd_std_fs_write_at((uint64_t)h, 0, (const unsigned char *)"hi", 2) == 2);
    assert(__absd_std_fs_close((uint64_t)h) == 0);
    h = __absd_std_fs_open(P("/d/a.txt"), 1u | 2u | 8u); assert(h >= 1000); assert(__absd_std_fs_close((uint64_t)h) == 0);
    assert(__absd_std_chdir(P("/d")) == 0 && __absd_std_fs_mkdir(P("sub2")) == 0);   /* relative paths resolve against the cwd */
    assert(__absd_std_chdir(P("/")) == 0);
    /* readdir: name order, no dot entries, snapshot at index 0, 0 at the end, attributes */
    int fetches = mock_posix_readdir_fetches();
    assert(__absd_std_fs_readdir(P("/d"), 0, name, 256, &attr) == 5 && memcmp(name, "a.txt", 5) == 0 && attr.kind == 1 && attr.size == 0);
    assert(mock_posix_readdir_fetches() == fetches + 1);
    assert(__absd_std_fs_mkdir(P("/d/zz")) == 0);                      /* changes after the snapshot are not seen by this stream */
    assert(__absd_std_fs_readdir(P("/d"), 1, name, 256, &attr) == 5 && memcmp(name, "b.txt", 5) == 0 && attr.size == 2);
    assert(__absd_std_fs_readdir(P("/d"), 2, name, 256, &attr) == 3 && memcmp(name, "sub", 3) == 0 && attr.kind == 2);
    assert(__absd_std_fs_readdir(P("/d"), 3, name, 256, &attr) == 4 && memcmp(name, "sub2", 4) == 0);
    assert(__absd_std_fs_readdir(P("/d"), 4, name, 256, &attr) == 0);
    assert(mock_posix_readdir_fetches() == fetches + 1);
    assert(__absd_std_fs_readdir(P("/d/sub"), 0, name, 256, &attr) == 0 && mock_posix_readdir_fetches() == fetches + 2);  /* another path: a new fetch */
    assert(__absd_std_fs_readdir(P("/d"), 0, name, 256, &attr) == 5 && mock_posix_readdir_fetches() == fetches + 3);
    assert(__absd_std_fs_readdir(P("/d"), 4, name, 256, &attr) == 2 && memcmp(name, "zz", 2) == 0);   /* the new snapshot has it */
    assert(__absd_std_fs_readdir(P("/d"), 0, name, 2, &attr) == -22);  /* name longer than the capacity */
    assert(__absd_std_fs_readdir(P("/d/a.txt"), 0, name, 256, &attr) == -20);
    assert(__absd_std_fs_readdir(P("/none"), 0, name, 256, &attr) == -2);
    /* canonical: lexical, must exist, -22 when too long for the buffer */
    unsigned char out[64];
    assert(__absd_std_chdir(P("/d/sub")) == 0);
    assert(__absd_std_fs_canonical(P("../b.txt"), out, 64) == 8 && memcmp(out, "/d/b.txt", 8) == 0);
    assert(__absd_std_fs_canonical(P("/d//sub/./../a.txt"), out, 64) == 8 && memcmp(out, "/d/a.txt", 8) == 0);
    assert(__absd_std_fs_canonical(P("/d/none"), out, 64) == -2);
    assert(__absd_std_fs_canonical(P("/d/b.txt"), out, 7) == -22);
    assert(__absd_std_chdir(P("/")) == 0);
    /* rename: replace a file, noreplace refused, directory over directory refused */
    assert(__absd_std_fs_rename(P("/d/a.txt"), P("/d/c.txt"), 0) == 0);
    assert(__absd_std_fs_rename(P("/d/b.txt"), P("/d/c.txt"), 1) == -17);
    assert(__absd_std_fs_rename(P("/d/b.txt"), P("/d/c.txt"), 0) == 0);
    assert(__absd_std_fs_rename(P("/d/sub"), P("/d/sub2"), 0) == -21);
    assert(__absd_std_fs_rename(P("/d/none"), P("/d/x"), 0) == -2);
    /* rmdir: not empty, then empty */
    assert(__absd_std_fs_rmdir(P("/d")) == -39);
    assert(__absd_std_fs_rmdir(P("/d/sub2")) == 0 && __absd_std_fs_rmdir(P("/d/c.txt")) == -20 && __absd_std_fs_rmdir(P("/d/none")) == -2);
    /* read-only mark: by path and by handle; a write open is then refused with -13 */
    assert(__absd_std_fs_set_readonly_path(P("/d/c.txt"), 1) == 0 && mock_posix_readonly("/d/c.txt") == 1);
    assert(__absd_std_fs_open(P("/d/c.txt"), 2u) == -13);
    h = __absd_std_fs_open(P("/d/c.txt"), 1u); assert(h >= 1000);
    assert(__absd_std_fs_set_readonly((uint64_t)h, 0) == 0 && mock_posix_readonly("/d/c.txt") == 0);
    assert(__absd_std_fs_close((uint64_t)h) == 0);
    assert(__absd_std_fs_set_readonly((uint64_t)h, 1) == -9);
    assert(__absd_std_fs_set_readonly_path(P("/d/none"), 1) == -2);
    /* the read-only mock refuses every mutation with -30 */
    mock_fs_readonly(1);
    assert(__absd_std_fs_mkdir(P("/e")) == -30 && __absd_std_fs_rmdir(P("/d/sub")) == -30);
    assert(__absd_std_fs_rename(P("/d/c.txt"), P("/d/d.txt"), 0) == -30 && __absd_std_fs_set_readonly_path(P("/d/c.txt"), 1) == -30);
    mock_fs_readonly(0);
    /* cleanup */
    assert(__absd_std_fs_unlink(P("/d/c.txt")) == 0 && __absd_std_fs_rmdir(P("/d/zz")) == 0 && __absd_std_fs_rmdir(P("/d/sub")) == 0 && __absd_std_fs_rmdir(P("/d")) == 0);
    assert(rmdir(root) == 0);
    puts("test_mock_posix OK");
    return 0;
}
