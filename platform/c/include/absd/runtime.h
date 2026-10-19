/* ABSD runtime hooks reachable from C. Generated-equivalent: every
   prototype and constant below is checked against the runtime/src Rust
   sources by scripts/check-c-headers.py; edit the Rust first, then this file. */
#ifndef ABSD_RUNTIME_H
#define ABSD_RUNTIME_H
#include <stddef.h>
#include <stdint.h>

/* Memory (runtime/src/lib.rs). Sized: dealloc needs the same size and align. */
unsigned char *__absd_std_alloc(size_t size, size_t align);
void __absd_std_dealloc(unsigned char *ptr, size_t size, size_t align);
unsigned char *__absd_std_realloc(unsigned char *ptr, size_t old_size, size_t align, size_t new_size);

/* Process and stdio (runtime/src/lib.rs). Stdio moves at most 256 bytes per call. */
ptrdiff_t __absd_std_read(unsigned char *bytes, size_t length);
ptrdiff_t __absd_std_write(const unsigned char *bytes, size_t length);
ptrdiff_t __absd_std_stderr_write(const unsigned char *bytes, size_t length);
uint32_t __absd_std_getpid(void);
_Noreturn void __absd_std_exit(int32_t code);
const size_t (*__absd_std_environ(size_t *count))[2];
uint64_t __absd_std_ticks(void);
int64_t __absd_std_wall_clock_seconds(void);

/* Working directory (runtime/src/cwd.rs). */
ptrdiff_t __absd_std_getcwd(unsigned char *out, size_t capacity);
int64_t __absd_std_chdir(const unsigned char *path, size_t length);

/* Files (runtime/src/storage.rs). Paths are byte strings with lengths, not
   NUL-terminated. Handles are the runtime's, never descriptors. Results:
   non-negative, or a negative Linux-numbered errno. */
#define ABSD_FS_READ        1u
#define ABSD_FS_WRITE       2u
#define ABSD_FS_CREATE      8u
#define ABSD_FS_CREATE_NEW 16u
#define ABSD_FS_TRUNCATE   32u

struct absd_raw_attr {           /* RawAttr V1: fixed 40-byte layout */
    uint32_t kind;               /* 1 file, 2 directory; 0 unknown (readdir entry only) */
    uint32_t readonly;
    uint64_t size;
    uint64_t filesystem;
    uint64_t serial;
    uint64_t links;
};

/* Internal platform V2. Existing C-kit consumers keep V1 above and below.
   A V2 hook writes 48 bytes; never pass a V1 buffer to one. */
struct absd_raw_attr_v2 {
    uint32_t kind;
    uint32_t readonly;
    uint64_t size;
    uint64_t filesystem;
    uint64_t serial;
    uint64_t links;
    uint64_t mtime;             /* whole UTC Unix seconds; 0 unknown */
};
int64_t __absd_std_fs_fstat_v2(uint64_t handle, struct absd_raw_attr_v2 *out);
int64_t __absd_std_fs_stat_v2(const unsigned char *path, size_t length, struct absd_raw_attr_v2 *out);
ptrdiff_t __absd_std_fs_readdir_v2(const unsigned char *path, size_t length, uint64_t index,
                                   unsigned char *name, size_t capacity, struct absd_raw_attr_v2 *out);

int64_t __absd_std_fs_open(const unsigned char *path, size_t length, uint32_t flags);
int64_t __absd_std_fs_close(uint64_t handle);
ptrdiff_t __absd_std_fs_read_at(uint64_t handle, uint64_t offset, unsigned char *bytes, size_t length);
ptrdiff_t __absd_std_fs_write_at(uint64_t handle, uint64_t offset, const unsigned char *bytes, size_t length);
int64_t __absd_std_fs_set_len(uint64_t handle, uint64_t length);
int64_t __absd_std_fs_sync(uint64_t handle);
int64_t __absd_std_fs_fstat(uint64_t handle, struct absd_raw_attr *out);
int64_t __absd_std_fs_stat(const unsigned char *path, size_t length, struct absd_raw_attr *out);
int64_t __absd_std_fs_unlink(const unsigned char *path, size_t length);
int64_t __absd_std_fs_lock(uint64_t handle, uint32_t mode);   /* 0 unlock, 1 shared, 2 exclusive; never waits */
int64_t __absd_std_fs_set_readonly(uint64_t handle, uint32_t readonly);
int64_t __absd_std_fs_set_readonly_path(const unsigned char *path, size_t length, uint32_t readonly);
int64_t __absd_std_fs_mkdir(const unsigned char *path, size_t length);
int64_t __absd_std_fs_rmdir(const unsigned char *path, size_t length);
int64_t __absd_std_fs_rename(const unsigned char *from, size_t from_length,
                             const unsigned char *to, size_t to_length, uint32_t noreplace);
ptrdiff_t __absd_std_fs_readdir(const unsigned char *path, size_t length, uint64_t index,
                                unsigned char *name, size_t capacity, struct absd_raw_attr *out);
ptrdiff_t __absd_std_fs_canonical(const unsigned char *path, size_t length, unsigned char *out, size_t capacity);

/* Processes (runtime/src/process.rs, runtime/src/broker.rs). RawSpawn is
   opaque here until the process lane lays it out: process.rs:68-82. */
struct absd_raw_spawn;
uint64_t __absd_std_process_brokered(void);
int64_t __absd_std_process_spawn_image(const struct absd_raw_spawn *request, uint64_t (*out)[5]);
int64_t __absd_std_process_kill(uint64_t token);
int64_t __absd_std_process_spawn(const unsigned char *path, size_t path_length,
                                 const size_t (*args)[2], size_t argc, uint64_t (*out)[5]);
int64_t __absd_std_process_wait(uint64_t slot, uint64_t nonblocking, int64_t *value);
ptrdiff_t __absd_std_handle_read(uint64_t handle, unsigned char *bytes, size_t length, uint64_t timeout);
ptrdiff_t __absd_std_handle_write(uint64_t handle, const unsigned char *bytes, size_t length);
int64_t __absd_std_handle_close(uint64_t handle);

#endif
