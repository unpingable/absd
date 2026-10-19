/* dirent.h over __absd_std_fs_readdir (ADAPTER-DESIGN.md 2.2). Picolibc
   declares DIR and struct dirent (sys/dirent.h) but defines no functions.
   A stream owns a snapshot of the whole listing, taken at opendir: records
   of {serial (8 bytes), d_type (1), name length (1), name}, in the native
   order. `buf` holds the snapshot's pointer, `count` its length in bytes,
   `offset` the byte cursor; `fd` is -1 (no directory descriptor exists). */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "posix_names.h"
#ifdef ABSD_HOST_TEST
#include "absd_dirent.h"
typedef ABSD_DIR posix_dir; typedef struct absd_dirent posix_dirent;
#define POSIX_DT_DIR ABSD_DT_DIR
#define POSIX_DT_REG ABSD_DT_REG
#define POSIX_DT_UNKNOWN ABSD_DT_UNKNOWN
#else
#include <dirent.h>
typedef DIR posix_dir; typedef struct dirent posix_dirent;
#define POSIX_DT_DIR DT_DIR
#define POSIX_DT_REG DT_REG
#define POSIX_DT_UNKNOWN DT_UNKNOWN
#endif

#define RECORD_HEAD 10                       /* serial, d_type, name length */
#define NAME_CAP (sizeof ((posix_dirent *)0)->d_name - 1)
_Static_assert(NAME_CAP <= 255, "a name length is one byte of the record");

static unsigned char *snapshot_of(const posix_dir *dir) {
    unsigned char *bytes; memcpy(&bytes, dir->buf, sizeof bytes); return bytes;
}

/* Grows *bytes (capacity *cap) to hold at least `need` bytes: malloc, copy,
   free (the kit exports no realloc). 0, or -1 with the old buffer kept. */
static int grow(unsigned char **bytes, size_t *cap, size_t used, size_t need) {
    if (need <= *cap) return 0;
    size_t next = *cap ? *cap : 512;
    while (next < need) next *= 2;
    unsigned char *fresh = malloc(next);
    if (fresh == NULL) return -1;
    if (used) memcpy(fresh, *bytes, used);
    free(*bytes);
    *bytes = fresh; *cap = next;
    return 0;
}

/* Truth source: __absd_std_fs_stat reported a directory, then the file
   server's listing at opendir: one synchronous loop over the readdir hook
   by index, which serves the snapshot the hook takes at index 0 (CPA-032:
   no `.`/`..`, native order). Nothing else runs in between in a
   single-threaded process. The stream never reads the path again, so a
   later chdir or a change to the directory does not reach it. Failure
   keeps nothing: NULL with errno (ENOMEM when an allocation fails). */
posix_dir *POSIX_FN(opendir)(const char *path) {
    struct absd_raw_attr attr;
    if (path == NULL || *path == '\0') { errno = ENOENT; return NULL; }
    size_t len = strlen(path);
    int64_t rc = __absd_std_fs_stat((const unsigned char *)path, len, &attr);
    if (rc < 0) { absd_posix_fail(rc); return NULL; }
    if (attr.kind != 2) { errno = attr.kind == 1 ? ENOTDIR : EIO; return NULL; }
    posix_dir *dir = malloc(sizeof *dir);
    if (dir == NULL) { errno = ENOMEM; return NULL; }
    unsigned char *bytes = NULL; size_t cap = 0, used = 0;
    unsigned char name[NAME_CAP];
    for (uint64_t index = 0;; index++) {
        ptrdiff_t n = __absd_std_fs_readdir((const unsigned char *)path, len, index, name, sizeof name, &attr);
        if (n == 0) break;
        if (n < 0) { free(bytes); free(dir); absd_posix_fail(n); return NULL; }
        if (grow(&bytes, &cap, used, used + RECORD_HEAD + (size_t)n) < 0) {
            free(bytes); free(dir); errno = ENOMEM; return NULL;
        }
        uint64_t serial = attr.serial;
        /* A21: a kind this adapter does not know is represented as unknown */
        unsigned char type = attr.kind == 1 ? POSIX_DT_REG : attr.kind == 2 ? POSIX_DT_DIR : POSIX_DT_UNKNOWN;
        memcpy(bytes + used, &serial, 8);
        bytes[used + 8] = type;
        bytes[used + 9] = (unsigned char)n;
        memcpy(bytes + used + RECORD_HEAD, name, (size_t)n);
        used += RECORD_HEAD + (size_t)n;
    }
    memset(dir, 0, sizeof *dir);
    dir->fd = -1;
    memcpy(dir->buf, &bytes, sizeof bytes);
    dir->count = used;
    return dir;
}

/* Truth source: the next record of the stream's own snapshot (opendir's).
   The end is NULL with errno unchanged, and stays the end. */
posix_dirent *POSIX_FN(readdir)(posix_dir *dir) {
    if (dir == NULL) { errno = EBADF; return NULL; }
    if (dir->offset >= dir->count) return NULL;
    const unsigned char *record = snapshot_of(dir) + dir->offset;
    posix_dirent *e = &dir->dirent;
    uint64_t serial; memcpy(&serial, record, 8);
    size_t n = record[9];
    memcpy(e->d_name, record + RECORD_HEAD, n);
    e->d_name[n] = '\0';
    e->d_ino = (ino_t)serial;
    e->d_type = record[8];
    dir->offset += RECORD_HEAD + n;
    return e;
}

/* Truth source: none needed; it releases only what opendir allocated (the
   snapshot and the DIR). No handle exists to close. */
int POSIX_FN(closedir)(posix_dir *dir) {
    if (dir == NULL) { errno = EBADF; return -1; }
    free(snapshot_of(dir));
    free(dir);
    return 0;
}
