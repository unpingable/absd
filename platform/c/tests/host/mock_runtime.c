/* Host mock of the runtime hooks. Allocation is backed by mmap, never by
   the C allocator: the kit's malloc.c is linked into the same test binary
   and its malloc/free/posix_memalign override glibc's, so calling any of
   them here would recurse into the code under test. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "mock_runtime.h"
#include "absd/runtime.h"

#define MOCK_MAPPINGS 4096

/* size and align are what __absd_std_alloc was given; the matching
   __absd_std_dealloc must name the same pair (the runtime frees by layout). */
struct mock_mapping { unsigned char *user; void *base; size_t length, size, align; };
static struct mock_mapping mappings[MOCK_MAPPINGS];

static size_t live, budget; static int fail_next;
size_t mock_live_bytes(void) { return live; }
void mock_fail_next_alloc(int n) { fail_next = n; }
void mock_set_budget(size_t bytes) { budget = bytes; }

static void mock_die(const char *what, const void *ptr) {
    fprintf(stderr, "mock_runtime: %s %p\n", what, ptr);
    _exit(70);
}

unsigned char *__absd_std_alloc(size_t size, size_t align) {
    if (fail_next > 0) { fail_next--; return NULL; }
    if (budget && live + size > budget) return NULL;
    if (align == 0 || (align & (align - 1)) != 0) return NULL;
    /* Rust's Layout: size rounded up to align must not exceed isize::MAX */
    if (align > (size_t)PTRDIFF_MAX || size > (size_t)PTRDIFF_MAX - (align - 1)) return NULL;
    size_t page = (size_t)sysconf(_SC_PAGESIZE), length;
    if (__builtin_add_overflow(size ? size : 1, align, &length)) return NULL;
    if (length > SIZE_MAX - page) return NULL;
    length = (length + page - 1) & ~(page - 1);
    struct mock_mapping *entry = NULL;
    for (size_t i = 0; i < MOCK_MAPPINGS; i++)
        if (mappings[i].user == NULL) { entry = &mappings[i]; break; }
    if (entry == NULL) mock_die("mapping table full at", NULL);
    void *base = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return NULL;
    uintptr_t user = ((uintptr_t)base + align - 1) & ~(uintptr_t)(align - 1);
    entry->user = (unsigned char *)user;
    entry->base = base;
    entry->length = length;
    entry->size = size;
    entry->align = align;
    live += size;
    return entry->user;
}

void __absd_std_dealloc(unsigned char *ptr, size_t size, size_t align) {
    for (size_t i = 0; i < MOCK_MAPPINGS; i++) {
        if (mappings[i].user == ptr && ptr != NULL) {
            if (mappings[i].size != size || mappings[i].align != align) {
                fprintf(stderr, "mock_runtime: alloc was size=%zu align=%zu, dealloc says size=%zu align=%zu\n",
                        mappings[i].size, mappings[i].align, size, align);
                mock_die("sized dealloc mismatch at", ptr);
            }
            munmap(mappings[i].base, mappings[i].length);
            mappings[i].user = NULL;
            live -= size;
            return;
        }
    }
    mock_die("dealloc of unknown pointer", ptr);
}

unsigned char *__absd_std_realloc(unsigned char *ptr, size_t old_size, size_t align, size_t new_size) {
    unsigned char *n = __absd_std_alloc(new_size, align);
    if (!n) return NULL;
    memcpy(n, ptr, old_size < new_size ? old_size : new_size);
    __absd_std_dealloc(ptr, old_size, align);
    return n;
}

_Noreturn void __absd_std_exit(int32_t code) { fflush(NULL); _exit(code); }
uint32_t __absd_std_getpid(void) { return (uint32_t)getpid(); }

/* Files over a host directory. Every call below is glibc's: the kit's
   fd.c names its calls absd_* under ABSD_HOST_TEST, so open, close, read,
   unlink and the rest here never resolve to the code under test. */
static char fs_root[4096] = "."; static int fs_ro, stdout_broken;
void mock_fs_root(const char *dir) { snprintf(fs_root, sizeof fs_root, "%s", dir); }
void mock_fs_readonly(int on) { fs_ro = on; }
void mock_stdout_broken(int on) { stdout_broken = on; }

static int host_path(const unsigned char *path, size_t length, char *out, size_t cap) {
    if (length >= 1024) return -36;                 /* ENAMETOOLONG, the record's limit */
    for (size_t i = 0; i < length; i++) if (path[i] == 0) return -22;
    snprintf(out, cap, "%s/%.*s", fs_root, (int)length, (const char *)path);
    return 0;
}

/* Advisory locks per handle (mode 0 none, 1 shared, 2 exclusive), keyed to
   the file by the host descriptor's device and inode. */
#define MOCK_LOCK_SLOTS 4096
static struct { uint32_t mode; dev_t dev; ino_t ino; } locks[MOCK_LOCK_SLOTS];
static int fail_fstat, open_handles, lock_calls;
void mock_fail_next_fstat(int n) { fail_fstat = n; }
static unsigned forced_kind;
void mock_next_fstat_kind(unsigned kind) { forced_kind = kind; }
int mock_lock_calls(void) { return lock_calls; }
int mock_open_handles(void) { return open_handles; }

int64_t __absd_std_fs_open(const unsigned char *path, size_t length, uint32_t flags) {
    char host[4200]; int rc = host_path(path, length, host, sizeof host); if (rc) return rc;
    if ((flags & ~(ABSD_FS_READ | ABSD_FS_WRITE | ABSD_FS_CREATE | ABSD_FS_CREATE_NEW | ABSD_FS_TRUNCATE)) != 0) return -22;
    if (fs_ro && (flags & (ABSD_FS_WRITE | ABSD_FS_CREATE | ABSD_FS_CREATE_NEW | ABSD_FS_TRUNCATE))) return -30;
    int o = ((flags & ABSD_FS_WRITE) ? ((flags & ABSD_FS_READ) ? O_RDWR : O_WRONLY) : O_RDONLY);
    if (flags & ABSD_FS_CREATE) o |= O_CREAT;
    if (flags & ABSD_FS_CREATE_NEW) o |= O_CREAT | O_EXCL;
    if (flags & ABSD_FS_TRUNCATE) o |= O_TRUNC;
    int fd = open(host, o, 0644);
    if (fd >= MOCK_LOCK_SLOTS) { close(fd); return -24; }
    if (fd < 0) return -errno;
    open_handles++;
    return (int64_t)fd + 1000;    /* handles are not descriptors: offset them */
}
int64_t __absd_std_fs_close(uint64_t handle) {
    int fd = (int)handle - 1000;
    if (fd >= 0 && fd < MOCK_LOCK_SLOTS) locks[fd].mode = 0;
    if (close(fd) < 0) return -errno;
    open_handles--;
    return 0;
}
ptrdiff_t __absd_std_fs_read_at(uint64_t h, uint64_t off, unsigned char *b, size_t n) {
    if (n > 65536) n = 65536;                        /* MAX_IO per request */
    ssize_t r = pread((int)h - 1000, b, n, (off_t)off); return r < 0 ? -errno : r;
}
ptrdiff_t __absd_std_fs_write_at(uint64_t h, uint64_t off, const unsigned char *b, size_t n) {
    if (fs_ro) return -30;
    if (n > 65536) n = 65536;
    ssize_t r = pwrite((int)h - 1000, b, n, (off_t)off); return r < 0 ? -errno : r;
}
int64_t __absd_std_fs_set_len(uint64_t h, uint64_t len) { return ftruncate((int)h - 1000, (off_t)len) < 0 ? -errno : 0; }
int64_t __absd_std_fs_sync(uint64_t h) { return fsync((int)h - 1000) < 0 ? -errno : 0; }
int64_t __absd_std_fs_fstat(uint64_t h, struct absd_raw_attr *out) {
    if (fail_fstat > 0) { fail_fstat--; return -5; }
    struct stat st; if (fstat((int)h - 1000, &st) < 0) return -errno;
    *out = (struct absd_raw_attr){ S_ISDIR(st.st_mode) ? 2u : 1u, 0, (uint64_t)st.st_size, 1, (uint64_t)st.st_ino, 1 };
    if (forced_kind) { out->kind = forced_kind; forced_kind = 0; }
    return 0;
}
int64_t __absd_std_fs_stat(const unsigned char *path, size_t length, struct absd_raw_attr *out) {
    char host[4200]; int rc = host_path(path, length, host, sizeof host); if (rc) return rc;
    struct stat st; if (stat(host, &st) < 0) return -errno;
    *out = (struct absd_raw_attr){ S_ISDIR(st.st_mode) ? 2u : 1u, 0, (uint64_t)st.st_size, 1, (uint64_t)st.st_ino, 1 };
    return 0;
}
int64_t __absd_std_fs_unlink(const unsigned char *path, size_t length) {
    char host[4200]; int rc = host_path(path, length, host, sizeof host); if (rc) return rc;
    return unlink(host) < 0 ? -errno : 0;
}
/* Never waits: -11 on a conflict (exclusive against anything, shared
   against exclusive); upgrade and downgrade are one step; unlock is 0. */
int64_t __absd_std_fs_lock(uint64_t h, uint32_t mode) {
    lock_calls++;
    int fd = (int)h - 1000;
    struct stat st;
    if (fd < 0 || fd >= MOCK_LOCK_SLOTS || fstat(fd, &st) < 0) return -9;
    if (mode > 2) return -22;
    if (mode == 0) { locks[fd].mode = 0; return 0; }
    for (int other = 0; other < MOCK_LOCK_SLOTS; other++) {
        if (other == fd || locks[other].mode == 0) continue;
        if (locks[other].dev != st.st_dev || locks[other].ino != st.st_ino) continue;
        if (mode == 2 || locks[other].mode == 2) return -11;
    }
    locks[fd].mode = mode; locks[fd].dev = st.st_dev; locks[fd].ino = st.st_ino;
    return 0;
}

/* stdio: 256 bytes per call like the kernel; stdout can be made "no reader" */
static unsigned char stdin_data[8192]; static size_t stdin_len, stdin_pos;
void mock_stdin(const void *data, size_t len) { memcpy(stdin_data, data, len); stdin_len = len; stdin_pos = 0; }
ptrdiff_t __absd_std_read(unsigned char *b, size_t n) {
    if (n == 0) return 0;
    if (stdin_pos >= stdin_len) return 0;
    if (n > 256) n = 256;
    if (n > stdin_len - stdin_pos) n = stdin_len - stdin_pos;
    memcpy(b, stdin_data + stdin_pos, n); stdin_pos += n; return (ptrdiff_t)n;
}
static unsigned char out_data[1 << 20]; static size_t out_len;
const unsigned char *mock_stdout(size_t *len) { *len = out_len; return out_data; }
ptrdiff_t __absd_std_write(const unsigned char *b, size_t n) {
    if (n == 0) return 0;
    if (stdout_broken) return -32;
    if (n > 256) n = 256;
    memcpy(out_data + out_len, b, n); out_len += n; return (ptrdiff_t)n;
}
ptrdiff_t __absd_std_stderr_write(const unsigned char *b, size_t n) { return __absd_std_write(b, n); }
