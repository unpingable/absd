/* perror in a program whose stdio never names stdout (R13, F1): Picolibc's
   bufio.c keeps its weak `stdout` reference undefined here, which the ELF
   check admits beside `stdin` (scripts/check-c-elf.py). Nothing goes to
   stdout; two real failures are reported on stderr (fd 2), and the scratch
   file is created with open/write, not stdio, and removed (contract 6:
   cwd-relative). Every text is worded the same by Picolibc and glibc. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#define PATH "c-errout.tmp"

int main(void) {
    int fd = open(PATH, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) { perror("errout: create"); return 1; }
    if (write(fd, "x\n", 2) != 2) { perror("errout: write"); return 1; }
    close(fd);
    if (open(PATH, O_WRONLY | O_CREAT | O_EXCL, 0644) >= 0) return 1;
    perror("errout: create again");
    if (unlink(PATH) != 0) { perror("errout: unlink"); return 1; }
    if (open(PATH, O_RDONLY) >= 0) return 1;
    int gone = errno == ENOENT;
    perror("errout: reopen after unlink");
    return gone ? 0 : 1;
}
