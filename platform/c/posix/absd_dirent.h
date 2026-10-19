#ifndef ABSD_DIRENT_H
#define ABSD_DIRENT_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#define ABSD_NAME_MAX 255
struct absd_dirent { ino_t d_ino; uint8_t d_type; char d_name[ABSD_NAME_MAX + 1]; };
typedef struct { int fd; size_t offset; size_t count; struct absd_dirent dirent;
                 union { char buf[512]; uint64_t align; }; } ABSD_DIR;
#define ABSD_DT_UNKNOWN 0
#define ABSD_DT_DIR 3
#define ABSD_DT_REG 6
#endif
