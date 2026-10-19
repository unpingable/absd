/* fcntl.h: F_SETLK only (ADAPTER-DESIGN.md 2.3; SPEC A10, A17). A request
   is whole-file when l_whence is SEEK_SET and l_start and l_len are 0; it
   maps to the kit's advisory lock (absd_fd_lock: 0 unlock, 1 shared, 2
   exclusive; never waits, EAGAIN on conflict). Any other range is EINVAL
   with nothing locked, except the one request below. Every other command
   is EINVAL (CPA-009, CPA-034). */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <unistd.h>
#include "posix_names.h"

/* SQLite unix-excl (A17): the single range lock a read-write unix-excl
   connection takes and holds until close: F_WRLCK over SHARED_FIRST
   (PENDING_BYTE 0x40000000 + 2) for SHARED_SIZE (510) bytes (sqlite3.c
   unixFileLock, UNIXFILE_EXCL). Mapped to the native exclusive whole-file
   lock, and only on an O_RDWR descriptor (O_RDONLY: EBADF; O_WRONLY:
   EINVAL; see below). The request is recognised by its range signature alone, not by
   consumer: any program linking this archive that issues exactly this
   fcntl gets the whole-file lock (A17; the divergence is
   cports/divergences.txt sqlite.excl-concurrency-loss), never general
   POSIX behaviour. Admitted
   conditional on the guest scenarios (sqlite.excl-busy, -release, -crash,
   -concurrency-loss) passing; if they fail, this recognition is removed
   before acceptance (ADAPTER-DESIGN.md 2.3). */
#define ABSD_SQLITE_SHARED_FIRST 0x40000002L
#define ABSD_SQLITE_SHARED_SIZE 510L

static int is_whole_file(const struct flock *l) { return l->l_whence == SEEK_SET && l->l_start == 0 && l->l_len == 0; }
static int is_sqlite_excl(const struct flock *l) {
    return l->l_type == F_WRLCK && l->l_whence == SEEK_SET &&
           l->l_start == ABSD_SQLITE_SHARED_FIRST && l->l_len == ABSD_SQLITE_SHARED_SIZE;
}

int POSIX_FN(fcntl)(int fd, int cmd, ...) {
    va_list ap; struct flock *l; int mode;
    if (!absd_fd_is_open(fd)) { errno = EBADF; return -1; }
    if (cmd != F_SETLK) { errno = EINVAL; return -1; }
    va_start(ap, cmd); l = va_arg(ap, struct flock *); va_end(ap);
    if (l == NULL) { errno = EINVAL; return -1; }
    /* Open (checked above), so the access mode is defined: stdio has one too
       (0 read-only, 1 and 2 write-only). A stdio descriptor's EBADF comes
       from the access-mode checks below or from absd_fd_lock's kind check. */
    mode = absd_fd_access_mode(fd);
    if (is_whole_file(l)) {
        switch (l->l_type) {
        case F_UNLCK: return absd_fd_lock(fd, 0);         /* truth: the holder removed at the file server */
        case F_RDLCK: if (mode == O_WRONLY) { errno = EBADF; return -1; } return absd_fd_lock(fd, 1);
        case F_WRLCK: if (mode == O_RDONLY) { errno = EBADF; return -1; } return absd_fd_lock(fd, 2);
        default: errno = EINVAL; return -1;
        }
    }
    /* Not whole-file. A write lock on a read-only descriptor is EBADF before
       the range is judged (POSIX's order); a read lock on a write-only one
       reaches the range refusal (EINVAL), since no read range is admitted
       (ADAPTER-DESIGN.md 2.3). */
    if (l->l_type == F_WRLCK && mode == O_RDONLY) { errno = EBADF; return -1; }
    if (is_sqlite_excl(l) && mode == O_RDWR) return absd_fd_lock(fd, 2);
    errno = EINVAL;                                       /* nothing locked (A10) */
    return -1;
}
