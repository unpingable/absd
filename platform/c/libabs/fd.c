/* The userspace descriptor table over runtime handles, and the five calls
   Picolibc's stdio needs (spec 3.2, A3): open, close, read, write, lseek.
   Plus fsync, ftruncate and fstat, which fopen's users reach for next, and
   unlink, which remove() needs. Descriptors 0, 1, 2 are the startup
   record's stdin, stdout, stderr and go through the runtime's stdio hooks;
   every other descriptor is a file opened through __absd_std_fs_open with
   its own position. open allocates the lowest free number from 3; 0, 1
   and 2 are the reserved stdio numbers, never handed out by open, and a
   closed 0, 1 or 2 stays EBADF. dup/dup2 are deferred (CPA-036: no
   consumer yet); when they come, the POSIX adapter follows them
   (ADAPTER-DESIGN.md, dup/dup2 sharing one open file description) and
   dup2 is what may rebind 0-2. Any other closed number is EBADF until
   reused.
   Nothing here is a kernel object. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "absd/kit.h"
#include "absd/runtime.h"

#ifdef ABSD_HOST_TEST
#define open absd_open
#define close absd_close
#define read absd_read
#define write absd_write
#define lseek absd_lseek
#define fsync absd_fsync
#define ftruncate absd_ftruncate
#define fstat absd_fstat
#define unlink absd_unlink
#endif

enum kind { FREE = 0, STDIN_KIND, STDOUT_KIND, STDERR_KIND, FILE_KIND };
struct entry { enum kind kind; uint64_t handle; uint64_t position; int append; int access; };

static struct entry table[ABSD_FD_MAX] = {
    [0] = { STDIN_KIND, 0, 0, 0, O_RDONLY }, [1] = { STDOUT_KIND, 0, 0, 0, O_WRONLY },
    [2] = { STDERR_KIND, 0, 0, 0, O_WRONLY },
};

/* Synthetic identity (owner decision A8): every file belongs to 1000:1000. */
#define ABSD_SYNTHETIC_ID 1000

static int refuse(long native) { errno = absd_errno_from_native(native); return -1; }

int absd_fd_is_open(int fd) { return fd >= 0 && fd < ABSD_FD_MAX && table[fd].kind != FREE; }
uint64_t absd_fd_handle(int fd) { return absd_fd_is_open(fd) ? table[fd].handle : 0; }

int absd_fd_access_mode(int fd) {
    if (!absd_fd_is_open(fd)) { errno = EBADF; return -1; }
    return table[fd].access;
}

static int install(uint64_t handle, int append, int access) {
    for (int fd = 3; fd < ABSD_FD_MAX; fd++) {
        if (table[fd].kind == FREE) {
            table[fd] = (struct entry){ FILE_KIND, handle, 0, append, access };
            return fd;
        }
    }
    errno = EMFILE;
    return -1;
}

/* A handle installed without open() (an inherited or adopted file) is
   recorded read-write: the runtime refuses whatever its rights do not allow. */
int absd_fd_install_file(uint64_t handle, int append) { return install(handle, append, O_RDWR); }

static struct entry *file_entry(int fd) {
    if (!absd_fd_is_open(fd)) { errno = EBADF; return NULL; }
    return &table[fd];
}

/* Preferred I/O size: the file server's per-request transfer cap
   (MAX_IO, fsd/src/proto.rs). */
#define ABSD_BLKSIZE 65536

int absd_stat_from_attr(const struct absd_raw_attr *attr, struct stat *out) {
    mode_t type;
    if (attr->kind == 1) type = S_IFREG;
    else if (attr->kind == 2) type = S_IFDIR;
    else { errno = EIO; return -1; }            /* unknown kind: refuse, never choose (A13) */
    memset(out, 0, sizeof *out);
    out->st_mode = type | (attr->readonly ? 0444 : 0644);   /* no execute/search bits */
    out->st_blksize = ABSD_BLKSIZE;
    out->st_size = (off_t)attr->size;
    out->st_ino = (ino_t)attr->serial;
    out->st_dev = (dev_t)attr->filesystem;
    out->st_nlink = (nlink_t)attr->links;
    out->st_uid = ABSD_SYNTHETIC_ID;
    out->st_gid = ABSD_SYNTHETIC_ID;
    out->st_mtime = 0;                          /* no timestamps yet (deferred, R3) */
    return 0;
}

int open(const char *path, int flags, ...) {
    int access = flags & O_ACCMODE;
    uint32_t native = 0;
    if (access == O_RDONLY) native = ABSD_FS_READ;
    else if (access == O_WRONLY) native = ABSD_FS_WRITE;
    else if (access == O_RDWR) native = ABSD_FS_READ | ABSD_FS_WRITE;
    else { errno = EINVAL; return -1; }
    int known = O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND;
#ifdef O_CLOEXEC
    known |= O_CLOEXEC;                         /* honest no-op: ABSD has no exec */
#endif
#ifdef O_NOFOLLOW
    known |= O_NOFOLLOW;                        /* honest no-op: ABSD has no symlinks */
#endif
    if ((flags & ~known) != 0) { errno = EINVAL; return -1; }   /* refuse, never approximate */
    /* POSIX leaves O_RDONLY|O_TRUNC unspecified; refuse it rather than ask
       the runtime to truncate through a read-only open. */
    if ((flags & O_TRUNC) && access == O_RDONLY) { errno = EINVAL; return -1; }
    /* O_EXCL without O_CREAT is ignored, as on Linux. */
    if (flags & O_CREAT) native |= (flags & O_EXCL) ? ABSD_FS_CREATE_NEW : ABSD_FS_CREATE;
    if (flags & O_TRUNC) native |= ABSD_FS_TRUNCATE;
    int64_t handle = __absd_std_fs_open((const unsigned char *)path, strlen(path), native);
    if (handle < 0) return refuse((long)handle);
    int fd = install((uint64_t)handle, (flags & O_APPEND) != 0, access);
    if (fd < 0) __absd_std_fs_close((uint64_t)handle);
    return fd;
}

int unlink(const char *path) {
    int64_t result = __absd_std_fs_unlink((const unsigned char *)path, strlen(path));
    return result < 0 ? refuse((long)result) : 0;
}

int close(int fd) {
    struct entry *entry = file_entry(fd);
    if (entry == NULL) return -1;
    int64_t result = 0;
    if (entry->kind == FILE_KIND) result = __absd_std_fs_close(entry->handle);
    entry->kind = FREE;                         /* stdio descriptors just close in the table */
    return result < 0 ? refuse((long)result) : 0;
}

/* The file's current size, or -1 with errno set when the runtime cannot
   say: callers that need the end (O_APPEND, SEEK_END) then fail rather
   than guess. */
static int end_of(struct entry *entry, uint64_t *end) {
    struct absd_raw_attr attr;
    int64_t result = __absd_std_fs_fstat(entry->handle, &attr);
    if (result < 0) return refuse((long)result);
    *end = attr.size;
    return 0;
}

ssize_t read(int fd, void *buffer, size_t count) {
    struct entry *entry = file_entry(fd);
    if (entry == NULL) return -1;
    if (count == 0) return 0;
    unsigned char *bytes = buffer;
    if (entry->kind == STDIN_KIND) {
        ptrdiff_t n = __absd_std_read(bytes, count);   /* one transfer: short counts are honest */
        return n < 0 ? refuse((long)n) : n;
    }
    if (entry->kind != FILE_KIND) { errno = EBADF; return -1; }
    size_t done = 0;
    while (done < count) {
        ptrdiff_t n = __absd_std_fs_read_at(entry->handle, entry->position, bytes + done, count - done);
        if (n < 0) return done ? (ssize_t)done : refuse((long)n);
        if (n == 0) break;
        done += (size_t)n;
        entry->position += (uint64_t)n;
    }
    return (ssize_t)done;
}

ssize_t write(int fd, const void *buffer, size_t count) {
    struct entry *entry = file_entry(fd);
    if (entry == NULL) return -1;
    if (count == 0) return 0;                   /* the kernel refuses zero-length transfers */
    const unsigned char *bytes = buffer;
    if (entry->kind == STDOUT_KIND || entry->kind == STDERR_KIND) {
        size_t done = 0;
        while (done < count) {
            ptrdiff_t n = entry->kind == STDOUT_KIND ? __absd_std_write(bytes + done, count - done)
                                                     : __absd_std_stderr_write(bytes + done, count - done);
            if (n < 0) return done ? (ssize_t)done : refuse((long)n);   /* -32: EPIPE, no signal */
            if (n == 0) break;                  /* the hook moved nothing: report what did move, possibly 0 */
            done += (size_t)n;
        }
        return (ssize_t)done;
    }
    if (entry->kind != FILE_KIND) { errno = EBADF; return -1; }
    if (entry->append) {
        uint64_t end = 0;
        if (end_of(entry, &end) < 0) return -1;   /* nothing written, position unchanged */
        entry->position = end;
    }
    size_t done = 0;
    while (done < count) {
        ptrdiff_t n = __absd_std_fs_write_at(entry->handle, entry->position, bytes + done, count - done);
        if (n < 0) return done ? (ssize_t)done : refuse((long)n);
        if (n == 0) break;
        done += (size_t)n;
        entry->position += (uint64_t)n;
    }
    return (ssize_t)done;
}

off_t lseek(int fd, off_t offset, int whence) {
    struct entry *entry = file_entry(fd);
    if (entry == NULL) return -1;
    if (entry->kind != FILE_KIND) { errno = ESPIPE; return -1; }
    int64_t base;
    switch (whence) {
    case SEEK_SET: base = 0; break;
    case SEEK_CUR: base = (int64_t)entry->position; break;
    case SEEK_END: {
        uint64_t end = 0;
        if (end_of(entry, &end) < 0) return -1;
        base = (int64_t)end;
        break;
    }
    default: errno = EINVAL; return -1;
    }
    int64_t target;
    if (__builtin_add_overflow(base, (int64_t)offset, &target) || target < 0) { errno = EINVAL; return -1; }
    entry->position = (uint64_t)target;
    return (off_t)target;
}

int fsync(int fd) {
    struct entry *entry = file_entry(fd);
    if (entry == NULL) return -1;
    if (entry->kind != FILE_KIND) return 0;
    int64_t result = __absd_std_fs_sync(entry->handle);   /* returns only after the server's commit */
    return result < 0 ? refuse((long)result) : 0;
}

int ftruncate(int fd, off_t length) {
    struct entry *entry = file_entry(fd);
    if (entry == NULL) return -1;
    if (entry->kind != FILE_KIND || length < 0) { errno = EINVAL; return -1; }
    int64_t result = __absd_std_fs_set_len(entry->handle, (uint64_t)length);
    return result < 0 ? refuse((long)result) : 0;
}

int fstat(int fd, struct stat *out) {
    struct entry *entry = file_entry(fd);
    if (entry == NULL) return -1;
    if (entry->kind != FILE_KIND) {
        memset(out, 0, sizeof *out);
        out->st_mode = S_IFCHR | 0600;
        out->st_uid = ABSD_SYNTHETIC_ID;
        out->st_gid = ABSD_SYNTHETIC_ID;
        return 0;
    }
    struct absd_raw_attr attr;
    int64_t result = __absd_std_fs_fstat(entry->handle, &attr);
    if (result < 0) return refuse((long)result);
    return absd_stat_from_attr(&attr, out);
}

/* The POSIX lane's fcntl(F_SETLK) adapter calls this. Never waits: a
   conflicting lock is the runtime's -11, EAGAIN. */
int absd_fd_lock(int fd, int mode) {
    struct entry *entry = file_entry(fd);
    if (entry == NULL) return -1;
    if (entry->kind != FILE_KIND) { errno = EBADF; return -1; }
    if (mode < 0 || mode > 2) { errno = EINVAL; return -1; }   /* refused before the runtime sees it */
    int64_t result = __absd_std_fs_lock(entry->handle, (uint32_t)mode);
    return result < 0 ? refuse((long)result) : 0;
}
