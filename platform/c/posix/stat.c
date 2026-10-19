/* sys/stat.h over the runtime hooks and the kit's converter
   (docs/c-ecosystem-20261010/posix/ADAPTER-DESIGN.md 2.1, 6.1). */
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include "posix_names.h"

static int path_attr(const char *path, struct absd_raw_attr *attr) {
    if (path == NULL || *path == '\0') { errno = ENOENT; return -1; }
    int64_t rc = __absd_std_fs_stat((const unsigned char *)path, strlen(path), attr);
    return rc < 0 ? absd_posix_fail(rc) : 0;
}

/* Truth source: the object's attribute record from the file server (or the
   mounted filesystem); fields from the kit's converter, so stat == fstat. */
int POSIX_FN(stat)(const char *path, struct stat *st) {
    struct absd_raw_attr attr;
    if (path_attr(path, &attr) < 0) return -1;
    return absd_stat_from_attr(&attr, st);           /* -1/EIO for a kind outside 1..2 (A13) */
}

/* No symbolic link can exist (A13 invariant, checked by scripts/check-fs-kinds.py). */
int POSIX_FN(lstat)(const char *path, struct stat *st) { return POSIX_FN(stat)(path, st); }

/* Truth source: the namespace commit before the hook's reply. The mode is
   not applied (the directory then reports the kit's fixed mode): declared
   divergence CPA-014. A mode without owner write would ask for a read-only
   directory, which does not exist: EPERM, nothing created. */
int POSIX_FN(mkdir)(const char *path, mode_t mode) {
    if (path == NULL || *path == '\0') { errno = ENOENT; return -1; }
    if ((mode & S_IWUSR) == 0) { errno = EPERM; return -1; }
    int64_t rc = __absd_std_fs_mkdir((const unsigned char *)path, strlen(path));
    return rc < 0 ? absd_posix_fail(rc) : 0;
}

/* The only permission state is the read-only flag: 0444 sets it, 0644
   clears it, every other mode is EPERM; directories carry no permission
   state at all (EPERM for every mode: a success would change nothing a
   later stat shows). A kind outside 1..2 is EIO (A13). */
static int readonly_for(uint32_t kind, mode_t mode, uint32_t *readonly) {
    if (kind == 2) { errno = EPERM; return -1; }
    if (kind != 1) { errno = EIO; return -1; }
    switch (mode & 07777) {
    case 0444: *readonly = 1; return 0;
    case 0644: *readonly = 0; return 0;
    default: errno = EPERM; return -1;
    }
}

/* Truth source: the flag set and committed before the reply; stat then shows exactly that mode. */
int POSIX_FN(chmod)(const char *path, mode_t mode) {
    struct absd_raw_attr attr; uint32_t readonly;
    if (path_attr(path, &attr) < 0) return -1;
    if (readonly_for(attr.kind, mode, &readonly) < 0) return -1;
    int64_t rc = __absd_std_fs_set_readonly_path((const unsigned char *)path, strlen(path), readonly);
    return rc < 0 ? absd_posix_fail(rc) : 0;
}

int POSIX_FN(fchmod)(int fd, mode_t mode) {
    struct absd_raw_attr attr; uint32_t readonly;
    if (fd < 3 || !absd_fd_is_open(fd)) { errno = EBADF; return -1; }
    int64_t rc = __absd_std_fs_fstat(absd_fd_handle(fd), &attr);
    if (rc < 0) return absd_posix_fail(rc);
    if (readonly_for(attr.kind, mode, &readonly) < 0) return -1;
    rc = __absd_std_fs_set_readonly(absd_fd_handle(fd), readonly);
    return rc < 0 ? absd_posix_fail(rc) : 0;
}
