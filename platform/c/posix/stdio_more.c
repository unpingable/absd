/* stdio.h: rename over the rename hook; popen/pclose refused (no fork, no exec; CPA-003). */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "posix_names.h"

/* Truth source: one commit at the file server; a file replaces a file in
   that commit. A directory over an existing directory is the native
   refusal (CPA-033). */
int POSIX_FN(rename)(const char *from, const char *to) {
    if (from == NULL || *from == '\0' || to == NULL || *to == '\0') { errno = ENOENT; return -1; }
    int64_t rc = __absd_std_fs_rename((const unsigned char *)from, strlen(from), (const unsigned char *)to, strlen(to), 0);
    return rc < 0 ? absd_posix_fail(rc) : 0;
}

FILE *POSIX_FN(popen)(const char *command, const char *mode) { (void)command; (void)mode; errno = ENOSYS; return NULL; }
int POSIX_FN(pclose)(FILE *stream) { (void)stream; errno = ECHILD; return -1; }   /* no stream came from popen */
