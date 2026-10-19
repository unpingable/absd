/* stdlib.h: realpath over the canonical hook; system refused. */
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "posix_names.h"

/* Truth source: the filesystem's normalized path of an existing object
   (no links, no dot components). A NULL output allocates PATH_MAX. */
char *POSIX_FN(realpath)(const char *path, char *out) {
    char *result = out;
    if (path == NULL || *path == '\0') { errno = ENOENT; return NULL; }
    if (result == NULL) { result = malloc(PATH_MAX); if (result == NULL) { errno = ENOMEM; return NULL; } }
    ptrdiff_t n = __absd_std_fs_canonical((const unsigned char *)path, strlen(path), (unsigned char *)result, PATH_MAX - 1);
    if (n < 0) {
        if (out == NULL) free(result);
        errno = n == -22 ? ENAMETOOLONG : absd_errno_from_native(n);
        return NULL;
    }
    result[n] = '\0';
    return result;
}

/* Truth source for system(NULL) == 0: the invariant that a C program has
   no command processor (no fork, no exec; a shell-started program holds no
   spawn right). system(cmd) is refused. Replaces Picolibc's, whose
   system(NULL) would fork (CPA-003). */
int POSIX_FN(system)(const char *command) {
    if (command == NULL) return 0;
    errno = ENOSYS;
    return -1;
}
