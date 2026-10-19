#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "errname.h"
int main(void) {
    int fd = open("/nonexistent/x", O_RDONLY); printf("missing: %d %s\n", fd, fd < 0 ? errname(errno) : "");
    fd = open("/bin/newfile", O_WRONLY | O_CREAT, 0644); printf("create in /bin: %d %s\n", fd, fd < 0 ? errname(errno) : ""); if (fd >= 0) close(fd);
    fd = open("/etc/motd", O_WRONLY); printf("write-open /etc: %d %s\n", fd, fd < 0 ? errname(errno) : ""); if (fd >= 0) close(fd);
    fd = open("x", O_WRONLY | O_CREAT | O_EXCL, 0644); printf("excl first: %d\n", fd >= 0); if (fd >= 0) close(fd);
    fd = open("x", O_WRONLY | O_CREAT | O_EXCL, 0644); printf("excl again: %d %s\n", fd, fd < 0 ? errname(errno) : ""); if (fd >= 0) close(fd);
    errno = 0; int rc = close(99); printf("close stale: %d %s\n", rc, errname(errno));
    errno = 0; long off = (long)lseek(0, 0, SEEK_SET); printf("lseek stdin: %ld %s\n", off, errname(errno));
    unlink("x");
    return 0;
}
