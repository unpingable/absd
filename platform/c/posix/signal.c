/* signal.h: no signal source exists on ABSD (no terminal, no kill
   delivery, EPIPE without a signal), so no disposition is meaningful:
   SIG_ERR/ENOSYS for every signal and handler, SIG_DFL and SIG_IGN
   included (CPA-004). Replaces Picolibc's libos fallback, which recorded
   handlers nothing could call; consistent with the kit's raise (SIGABRT
   ends the process with 134, everything else ENOSYS). */
#include <errno.h>
#include <signal.h>
#include "posix_names.h"

void (*POSIX_FN(signal)(int sig, void (*handler)(int)))(int) {
    (void)sig; (void)handler;
    errno = ENOSYS;
    return SIG_ERR;
}
