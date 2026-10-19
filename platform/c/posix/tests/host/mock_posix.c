/* Host mock of the runtime hooks the POSIX adapter adds to the kit's set
   (directories, rename, listing, canonical paths, the read-only mark, the
   working directory). It sits beside c/tests/host/mock_runtime.c, which is
   frozen: that file's root and host_path are static, so this file keeps its
   own copy of the root (mock_posix_root) and its own resolver. Every host
   call below is glibc's. Results are Linux-numbered negatives, as the
   runtime returns them (C-INTERFACE.md section 12).

   Limits of the mock, where it differs from the runtime (final review P13):
   - a path whose normalized form reaches 1024 bytes is refused -36 by every
     hook here, including chdir, where the contract says -22 (normalize);
   - a listing above 1024 entries is refused -12 (fetch), a mock capacity,
     not the file server's;
   - the set_readonly hook accepts any live host regular file whose
     descriptor is the handle minus 1000: it cannot tell the kit mock's
     handles from other host descriptors;
   - the kit mock's path stat cannot report an unknown kind, so the test
     build wraps it (-Wl,--wrap=__absd_std_fs_stat, check-posix-host.sh) and
     mock_posix_next_stat_kind forces one;
   - mock_posix_next_canonical makes the next canonical call return a given
     refusal (the runtime's -22 for capacity is otherwise unreachable here:
     normalize refuses -36 first). */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "absd/runtime.h"
#include "mock_posix.h"

/* The kit mock's read-only switch: its static flag has no getter, so ask it
   the way a caller would. A write-class open of nothing refuses -30 when it
   is on, before any host call; otherwise the host open fails or succeeds on
   a name that never exists. */
static int kit_readonly(void) {
    static const char probe[] = "\x01mock-posix-probe\x01";
    int64_t h = __absd_std_fs_open((const unsigned char *)probe, sizeof probe - 1, ABSD_FS_WRITE);
    if (h >= 1000) __absd_std_fs_close((uint64_t)h);
    return h == -30;
}

#define MOCK_PATH 1024                       /* the record's limit, as the kit mock */
static char root[4096] = ".";
static char cwd[MOCK_PATH] = "/";
void mock_posix_root(const char *dir) { snprintf(root, sizeof root, "%s", dir); }
const char *mock_posix_cwd(void) { return cwd; }

/* Join with the cwd when relative, then normalize lexically: "." dropped,
   ".." pops (never above "/"), repeated "/" collapsed. out is absolute. */
static int normalize(const unsigned char *path, size_t length, char *out, size_t cap) {
    if (length == 0) return -2;
    if (length >= MOCK_PATH) return -36;
    for (size_t i = 0; i < length; i++) if (path[i] == 0) return -22;
    char joined[2 * MOCK_PATH + 2];
    if (path[0] == '/') snprintf(joined, sizeof joined, "%.*s", (int)length, (const char *)path);
    else snprintf(joined, sizeof joined, "%s/%.*s", cwd, (int)length, (const char *)path);
    size_t n = 0; out[n] = 0;
    for (char *p = joined; *p;) {
        while (*p == '/') p++;
        char *start = p; while (*p && *p != '/') p++;
        size_t len = (size_t)(p - start);
        if (len == 0 || (len == 1 && start[0] == '.')) continue;
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            while (n > 0 && out[n - 1] != '/') n--;
            if (n > 0) n--;
            out[n] = 0;
            continue;
        }
        if (n + 1 + len >= cap) return -36;
        out[n++] = '/'; memcpy(out + n, start, len); n += len; out[n] = 0;
    }
    if (n == 0) { out[0] = '/'; out[1] = 0; }
    return 0;
}
static int host_of(const char *virt, char *out, size_t cap) {
    if ((size_t)snprintf(out, cap, "%s%s", root, virt) >= cap) return -36;
    return 0;
}
static int resolve(const unsigned char *path, size_t length, char *virt, char *host) {
    int rc = normalize(path, length, virt, MOCK_PATH); if (rc) return rc;
    return host_of(virt, host, 4200 + MOCK_PATH);
}
#define HOST_CAP (4200 + MOCK_PATH)

/* The read-only mark, keyed to the object by device and inode so a mark
   made through a handle and one made by path name the same entry. */
#define MOCK_MARKS 256
static struct { int used; dev_t dev; ino_t ino; } marks[MOCK_MARKS];
static void mark(const struct stat *st, int ro) {
    for (int i = 0; i < MOCK_MARKS; i++)
        if (marks[i].used && marks[i].dev == st->st_dev && marks[i].ino == st->st_ino) { marks[i].used = ro; return; }
    if (!ro) return;
    for (int i = 0; i < MOCK_MARKS; i++)
        if (!marks[i].used) { marks[i].used = 1; marks[i].dev = st->st_dev; marks[i].ino = st->st_ino; return; }
}
int mock_posix_readonly(const char *path) {
    char virt[MOCK_PATH], host[HOST_CAP]; struct stat st;
    if (resolve((const unsigned char *)path, strlen(path), virt, host) || stat(host, &st) < 0) return 0;
    for (int i = 0; i < MOCK_MARKS; i++)
        if (marks[i].used && marks[i].dev == st.st_dev && marks[i].ino == st.st_ino)
            return !(st.st_mode & S_IWUSR);
    return 0;
}

/* The listing snapshot: fetched at index 0 or when the path changes. */
#define MOCK_ENTRIES 1024
static char snap_path[MOCK_PATH]; static int snap_valid, fetches;
static char snap_names[MOCK_ENTRIES][256]; static size_t snap_count;
int mock_posix_readdir_fetches(void) { return fetches; }

static unsigned forced_stat_kind; static ptrdiff_t forced_canonical;
void mock_posix_next_stat_kind(unsigned kind) { forced_stat_kind = kind; }
void mock_posix_next_canonical(ptrdiff_t code) { forced_canonical = code; }
int64_t __real___absd_std_fs_stat(const unsigned char *path, size_t length, struct absd_raw_attr *out);
int64_t __wrap___absd_std_fs_stat(const unsigned char *path, size_t length, struct absd_raw_attr *out) {
    int64_t rc = __real___absd_std_fs_stat(path, length, out);
    if (rc == 0 && forced_stat_kind) { out->kind = forced_stat_kind; forced_stat_kind = 0; }
    return rc;
}

void mock_posix_reset(void) {
    snprintf(cwd, sizeof cwd, "/");
    memset(marks, 0, sizeof marks);
    snap_valid = 0; snap_count = 0; snap_path[0] = 0; fetches = 0;
    forced_stat_kind = 0; forced_canonical = 0;
}

ptrdiff_t __absd_std_getcwd(unsigned char *out, size_t capacity) {
    size_t n = strlen(cwd);
    if (capacity < n) return -22;
    memcpy(out, cwd, n);
    return (ptrdiff_t)n;
}
int64_t __absd_std_chdir(const unsigned char *path, size_t length) {
    char virt[MOCK_PATH], host[HOST_CAP]; struct stat st;
    int rc = resolve(path, length, virt, host); if (rc) return rc;
    if (stat(host, &st) < 0) return -errno;
    if (!S_ISDIR(st.st_mode)) return -20;
    snprintf(cwd, sizeof cwd, "%s", virt);
    return 0;
}

int64_t __absd_std_fs_mkdir(const unsigned char *path, size_t length) {
    char virt[MOCK_PATH], host[HOST_CAP];
    int rc = resolve(path, length, virt, host); if (rc) return rc;
    if (kit_readonly()) return -30;
    return mkdir(host, 0755) < 0 ? -errno : 0;
}
int64_t __absd_std_fs_rmdir(const unsigned char *path, size_t length) {
    char virt[MOCK_PATH], host[HOST_CAP];
    int rc = resolve(path, length, virt, host); if (rc) return rc;
    if (kit_readonly()) return -30;
    if (rmdir(host) == 0) return 0;
    return (errno == ENOTEMPTY || errno == EEXIST) ? -39 : -errno;
}
int64_t __absd_std_fs_rename(const unsigned char *from, size_t from_length,
                             const unsigned char *to, size_t to_length, uint32_t noreplace) {
    char fvirt[MOCK_PATH], fhost[HOST_CAP], tvirt[MOCK_PATH], thost[HOST_CAP];
    int rc = resolve(from, from_length, fvirt, fhost); if (rc) return rc;
    rc = resolve(to, to_length, tvirt, thost); if (rc) return rc;
    if (kit_readonly()) return -30;
    struct stat fst, tst;
    if (lstat(fhost, &fst) < 0) return -errno;
    if (lstat(thost, &tst) == 0) {
        if (noreplace) return -17;
        /* the native refusal: glibc would replace an empty directory */
        if (S_ISDIR(fst.st_mode) && S_ISDIR(tst.st_mode)) return -21;
    }
    return rename(fhost, thost) < 0 ? -errno : 0;
}

static void attr_of(const struct stat *st, struct absd_raw_attr *out) {
    *out = (struct absd_raw_attr){ S_ISDIR(st->st_mode) ? 2u : 1u, (st->st_mode & S_IWUSR) ? 0u : 1u,
                                   (uint64_t)st->st_size, 1, (uint64_t)st->st_ino, 1 };
}
static int by_name(const void *a, const void *b) { return strcmp((const char *)a, (const char *)b); }
static int fetch(const char *virt, const char *host) {
    DIR *d = opendir(host); if (!d) return -errno;
    snap_count = 0;
    for (struct dirent *e; (e = readdir(d)) != NULL;) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if (snap_count == MOCK_ENTRIES) { closedir(d); snap_valid = 0; return -12; }
        snprintf(snap_names[snap_count++], 256, "%s", e->d_name);
    }
    closedir(d);
    qsort(snap_names, snap_count, sizeof snap_names[0], by_name);   /* the native name order */
    snprintf(snap_path, sizeof snap_path, "%s", virt);
    snap_valid = 1; fetches++;
    return 0;
}
ptrdiff_t __absd_std_fs_readdir(const unsigned char *path, size_t length, uint64_t index,
                                unsigned char *name, size_t capacity, struct absd_raw_attr *out) {
    char virt[MOCK_PATH], host[HOST_CAP]; struct stat st;
    int rc = resolve(path, length, virt, host); if (rc) return rc;
    if (stat(host, &st) < 0) return -errno;
    if (!S_ISDIR(st.st_mode)) return -20;
    if (index == 0 || !snap_valid || strcmp(virt, snap_path) != 0) { rc = fetch(virt, host); if (rc) return rc; }
    if (index >= snap_count) return 0;
    const char *entry = snap_names[index]; size_t n = strlen(entry);
    if (n > capacity) return -22;
    char ehost[HOST_CAP + 257];
    snprintf(ehost, sizeof ehost, "%s/%s", host, entry);
    if (stat(ehost, &st) < 0) return -errno;
    attr_of(&st, out);
    memcpy(name, entry, n);
    return (ptrdiff_t)n;
}
ptrdiff_t __absd_std_fs_canonical(const unsigned char *path, size_t length, unsigned char *out, size_t capacity) {
    char virt[MOCK_PATH], host[HOST_CAP]; struct stat st;
    if (forced_canonical) { ptrdiff_t rc = forced_canonical; forced_canonical = 0; return rc; }
    int rc = resolve(path, length, virt, host); if (rc) return rc;
    if (stat(host, &st) < 0) return -errno;
    size_t n = strlen(virt);
    if (n > capacity) return -22;
    memcpy(out, virt, n);
    return (ptrdiff_t)n;
}

int64_t __absd_std_fs_set_readonly(uint64_t handle, uint32_t readonly) {
    int fd = (int)handle - 1000; struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) return -9;
    if (kit_readonly()) return -30;
    if (fchmod(fd, readonly ? 0444 : 0644) < 0) return -errno;
    mark(&st, readonly != 0);
    return 0;
}
int64_t __absd_std_fs_set_readonly_path(const unsigned char *path, size_t length, uint32_t readonly) {
    char virt[MOCK_PATH], host[HOST_CAP]; struct stat st;
    int rc = resolve(path, length, virt, host); if (rc) return rc;
    if (kit_readonly()) return -30;
    if (stat(host, &st) < 0) return -errno;
    if (chmod(host, readonly ? 0444 : 0644) < 0) return -errno;
    mark(&st, readonly != 0);
    return 0;
}
