/* Native refusals (negative, Linux-numbered, as the runtime and file
   server report them) to this libc's errno constants, by name. Picolibc
   numbers several of these differently from Linux (ENOSYS, ENOTEMPTY,
   ENAMETOOLONG, EOVERFLOW, ETIMEDOUT, ESTALE), so the map is symbolic. */
#include <errno.h>
#include "absd/kit.h"

int absd_errno_from_native(long code) {
    switch (code) {
    case -1: return EPERM;      case -2: return ENOENT;     case -5: return EIO;
    case -9: return EBADF;      case -10: return ECHILD;    case -11: return EAGAIN;
    case -12: return ENOMEM;    case -13: return EACCES;    case -14: return EFAULT;
    case -16: return EBUSY;     case -17: return EEXIST;    case -20: return ENOTDIR;
    case -21: return EISDIR;    case -22: return EINVAL;    case -24: return EMFILE;
    case -27: return EFBIG;     case -28: return ENOSPC;    case -29: return ESPIPE;
    case -30: return EROFS;     case -32: return EPIPE;     case -36: return ENAMETOOLONG;
    case -38: return ENOSYS;    case -39: return ENOTEMPTY; case -74: return EBADMSG;
    case -75: return EOVERFLOW; case -95: return ENOTSUP;   case -110: return ETIMEDOUT;
    case -116: return ESTALE;
    default: return EIO;
    }
}
