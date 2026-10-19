/* strerror and perror (R13) after real failed calls. Every text printed is
   one Picolibc 1.8.12 and glibc word the same, so the run must equal the
   Linux reference byte for byte: ENOENT, EEXIST and ESPIPE from Picolibc's
   table, ESTALE and unknown numbers from the kit's hook
   (c/libabs/strerror_hook.c). perror goes to stderr (fd 2) as
   "prefix: text\n", or "text\n" for a null or empty prefix, and leaves errno
   as it found it after its first call (glibc's first perror leaves EINVAL
   behind, and ISO C promises nothing either way, so the first call, of
   errno 0, goes unchecked); strerror leaves errno alone. Every errno the kit's
   errno_map.c produces must have text, not the unknown-number fallback (the
   wording of several differs from glibc, so only the count is printed). The
   scratch file is cwd-relative (contract 6) and removed. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "errname.h"
#define PATH "c-errmsg.tmp"

static void report(const char *what, int rc) {
    int e = errno;
    printf("%s: %d %s %s\n", what, rc, errname(e), strerror(e));
    errno = e;
    perror(what);
    printf("%s: errno kept by perror %d\n", what, errno == e);
}

int main(void) {
    errno = 0;
    perror("errmsg");
    printf("strerror(0): %s\n", strerror(0));
    int fd = open("/nonexistent/x", O_RDONLY);
    report("open missing", fd);
    errno = ENOENT;
    perror(NULL);
    perror("");
    fd = open(PATH, O_WRONLY | O_CREAT | O_EXCL, 0644);
    printf("excl first: %d\n", fd >= 0);
    if (fd >= 0) close(fd);
    fd = open(PATH, O_WRONLY | O_CREAT | O_EXCL, 0644);
    report("excl again", fd);
    if (fd >= 0) close(fd);
    errno = 0;
    long off = (long)lseek(0, 0, SEEK_SET);
    report("lseek stdin", (int)off);
    printf("stale: %s\n", strerror(ESTALE));
    errno = EEXIST;
    printf("unknown 9999: %s\n", strerror(9999));
    printf("unknown -1: %s\n", strerror(-1));
    printf("errno kept by strerror %d\n", errno == EEXIST);
    errno = 9999;
    perror("unknown");
    static const int mapped[] = {
        EPERM, ENOENT, EIO, EBADF, ECHILD, EAGAIN, ENOMEM, EACCES, EFAULT, EBUSY, EEXIST, ENOTDIR, EISDIR, EINVAL,
        EMFILE, EFBIG, ENOSPC, ESPIPE, EROFS, EPIPE, ENAMETOOLONG, ENOSYS, ENOTEMPTY, EBADMSG, EOVERFLOW, ENOTSUP,
        ETIMEDOUT, ESTALE,
    };
    int known = 0, total = (int)(sizeof mapped / sizeof mapped[0]);
    for (int i = 0; i < total; i++) {
        const char *text = strerror(mapped[i]);
        if (text[0] != '\0' && strncmp(text, "Unknown error", 13) != 0) known++;
        else printf("no text for %s\n", errname(mapped[i]));
    }
    printf("known: %d of %d\n", known, total);
    int rc = unlink(PATH);
    fd = open(PATH, O_RDONLY);
    printf("cleanup: unlink %d, reopen %d %s\n", rc, fd, fd < 0 ? errname(errno) : "");
    if (fd >= 0) close(fd);
    return 0;
}
