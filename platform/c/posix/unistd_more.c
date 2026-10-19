/* unistd.h functions of the stage-2 demand (ADAPTER-DESIGN.md 2.4; SPEC A8, A11, A13). */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "posix_names.h"

static int path_attr(const char *path, struct absd_raw_attr *attr) {
    if (path == NULL || *path == '\0') { errno = ENOENT; return -1; }
    int64_t rc = __absd_std_fs_stat((const unsigned char *)path, strlen(path), attr);
    return rc < 0 ? absd_posix_fail(rc) : 0;
}

/* Truth source: the runtime checked an existing directory and set its cwd. */
int POSIX_FN(chdir)(const char *path) {
    if (path == NULL || *path == '\0') { errno = ENOENT; return -1; }
    int64_t rc = __absd_std_chdir((const unsigned char *)path, strlen(path));
    return rc < 0 ? absd_posix_fail(rc) : 0;
}

/* Truth source: the runtime's working directory, a lexical absolute path
   (CPA-047). A NULL buffer allocates `size` bytes, or PATH_MAX when size is 0. */
char *POSIX_FN(getcwd)(char *buf, size_t size) {
    char *out = buf; size_t capacity = size;
    if (buf == NULL) {
        capacity = size ? size : PATH_MAX;
        out = malloc(capacity);
        if (out == NULL) { errno = ENOMEM; return NULL; }
    } else if (size == 0) { errno = EINVAL; return NULL; }
    ptrdiff_t n = __absd_std_getcwd((unsigned char *)out, capacity - 1);
    if (n < 0) {
        if (buf == NULL) free(out);
        errno = n == -22 ? ERANGE : absd_errno_from_native(n);
        return NULL;
    }
    out[n] = '\0';
    return out;
}

/* Truth source: the namespace commit before the reply. */
int POSIX_FN(rmdir)(const char *path) {
    if (path == NULL || *path == '\0') { errno = ENOENT; return -1; }
    int64_t rc = __absd_std_fs_rmdir((const unsigned char *)path, strlen(path));
    return rc < 0 ? absd_posix_fail(rc) : 0;
}

/* Never succeeds: an existing object is not a link (A13), EINVAL. */
ssize_t POSIX_FN(readlink)(const char *path, char *buf, size_t n) {
    struct absd_raw_attr attr; (void)buf; (void)n;
    if (path_attr(path, &attr) < 0) return -1;
    errno = EINVAL;
    return -1;
}

static int probe(const char *path, int flags) {
    int fd = KIT_OPEN(path, flags);
    if (fd < 0) return -1;
    KIT_CLOSE(fd);                 /* nothing was written: the close commits nothing */
    return 0;
}

/* F_OK: stat succeeded. R_OK: an open-for-read the server granted, then
   closed. W_OK on a file: an open-for-write (no create, no truncate) the
   server granted, then closed. W_OK on a directory: ENOSYS, a documented
   refusal (A11; the mount-authority query of A19 is platform work).
   X_OK on a directory: stat says directory (path resolution has no
   separate search right); on a file EINVAL (no execute permission exists). */
int POSIX_FN(access)(const char *path, int mode) {
    struct absd_raw_attr attr;
    if ((mode & ~(R_OK | W_OK | X_OK)) != 0) { errno = EINVAL; return -1; }
    if (path_attr(path, &attr) < 0) return -1;
    if (attr.kind != 1 && attr.kind != 2) { errno = EIO; return -1; }
    if (attr.kind == 2 && (mode & W_OK)) { errno = ENOSYS; return -1; }
    if ((mode & R_OK) && probe(path, O_RDONLY) < 0) return -1;
    if ((mode & W_OK) && probe(path, O_WRONLY) < 0) return -1;
    if ((mode & X_OK) && attr.kind != 2) { errno = EINVAL; return -1; }
    return 0;
}

/* SPEC A8: a synthetic identity, no authority, no ownership; the setuid and
   chown families are refused. */
uid_t POSIX_FN(getuid)(void) { return ABSD_POSIX_UID; }
uid_t POSIX_FN(geteuid)(void) { return ABSD_POSIX_UID; }
gid_t POSIX_FN(getgid)(void) { return ABSD_POSIX_GID; }
gid_t POSIX_FN(getegid)(void) { return ABSD_POSIX_GID; }
int POSIX_FN(setuid)(uid_t u) { (void)u; errno = EPERM; return -1; }
int POSIX_FN(seteuid)(uid_t u) { (void)u; errno = EPERM; return -1; }
int POSIX_FN(setgid)(gid_t g) { (void)g; errno = EPERM; return -1; }
int POSIX_FN(setegid)(gid_t g) { (void)g; errno = EPERM; return -1; }
int POSIX_FN(fchown)(int fd, uid_t u, gid_t g) { (void)fd; (void)u; (void)g; errno = EPERM; return -1; }
int POSIX_FN(chown)(const char *p, uid_t u, gid_t g) { (void)p; (void)u; (void)g; errno = EPERM; return -1; }
int POSIX_FN(lchown)(const char *p, uid_t u, gid_t g) { (void)p; (void)u; (void)g; errno = EPERM; return -1; }

/* The filesystem has no symbolic links; ABSD has no host name. */
int POSIX_FN(symlink)(const char *a, const char *b) { (void)a; (void)b; errno = EPERM; return -1; }
int POSIX_FN(gethostname)(char *name, size_t n) { (void)name; (void)n; errno = ENOSYS; return -1; }
