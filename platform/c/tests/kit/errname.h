/* errno by name, never strerror text: Picolibc and glibc word (and, for
   several codes, number) errors differently, so the kit programs compare
   names. Anything outside the table prints as errno=<n>. */
#include <errno.h>
#include <stdio.h>
static const char *errname(int e) {
    static char other[32];
    switch (e) {
    case 0: return "0";
    case ENOENT: return "ENOENT";
    case EACCES: return "EACCES";
    case EROFS: return "EROFS";
    case EEXIST: return "EEXIST";
    case EBADF: return "EBADF";
    case ESPIPE: return "ESPIPE";
    case EINVAL: return "EINVAL";
    case EMFILE: return "EMFILE";
    case ENOTDIR: return "ENOTDIR";
    case EISDIR: return "EISDIR";
    default: snprintf(other, sizeof other, "errno=%d", e); return other;
    }
}
