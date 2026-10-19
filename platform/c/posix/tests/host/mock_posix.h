#ifndef MOCK_POSIX_H
#define MOCK_POSIX_H
#include <stddef.h>
/* Host stand-in for the POSIX adapter's runtime hooks (mock_posix.c), over
   the kit's mock (c/tests/host/mock_runtime.c). Set both roots from one
   string, in this order: mock_fs_root(dir); mock_posix_root(dir); mock_posix_reset(); */
void mock_posix_root(const char *dir);       /* the same directory mock_fs_root was given */
void mock_posix_reset(void);                 /* cwd "/", readonly table cleared, snapshot dropped, counters 0 */
const char *mock_posix_cwd(void);            /* the lexical cwd the chdir hook keeps */
int mock_posix_readonly(const char *path);   /* 1 when the hooks marked this path read-only (host mode lacks S_IWUSR) */
int mock_posix_readdir_fetches(void);        /* listings fetched (index 0 or path change): the snapshot rule */
void mock_posix_next_stat_kind(unsigned kind);  /* the next successful path stat reports this kind (via --wrap) */
void mock_posix_next_canonical(ptrdiff_t code); /* the next canonical call returns this refusal */
#endif
