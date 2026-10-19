#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "absd/kit.h"

int main(void) {
    /* Linux-numbered natives (what the runtime returns) to this libc's errno */
    assert(absd_errno_from_native(-1) == EPERM);
    assert(absd_errno_from_native(-2) == ENOENT);
    assert(absd_errno_from_native(-5) == EIO);
    assert(absd_errno_from_native(-9) == EBADF);
    assert(absd_errno_from_native(-11) == EAGAIN);
    assert(absd_errno_from_native(-12) == ENOMEM);
    assert(absd_errno_from_native(-13) == EACCES);
    assert(absd_errno_from_native(-17) == EEXIST);
    assert(absd_errno_from_native(-20) == ENOTDIR);
    assert(absd_errno_from_native(-21) == EISDIR);
    assert(absd_errno_from_native(-22) == EINVAL);
    assert(absd_errno_from_native(-24) == EMFILE);
    assert(absd_errno_from_native(-28) == ENOSPC);
    assert(absd_errno_from_native(-30) == EROFS);
    assert(absd_errno_from_native(-32) == EPIPE);
    assert(absd_errno_from_native(-36) == ENAMETOOLONG);
    assert(absd_errno_from_native(-38) == ENOSYS);
    assert(absd_errno_from_native(-39) == ENOTEMPTY);
    assert(absd_errno_from_native(-75) == EOVERFLOW);
    assert(absd_errno_from_native(-95) == ENOTSUP);
    assert(absd_errno_from_native(-110) == ETIMEDOUT);
    assert(absd_errno_from_native(-116) == ESTALE);
    assert(absd_errno_from_native(-9999) == EIO);
    assert(absd_errno_from_native(0) == EIO && absd_errno_from_native(7) == EIO);
    puts("test_errno OK");
    return 0;
}
