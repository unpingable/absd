#ifndef MOCK_RUNTIME_H
#define MOCK_RUNTIME_H
#include <stddef.h>
/* Host stand-in for the __absd_std_* hooks (c/tests/host/mock_runtime.c). */
size_t mock_live_bytes(void);        /* bytes currently allocated through the hooks */
void mock_fail_next_alloc(int n);     /* make the next n allocations fail */
void mock_set_budget(size_t bytes);  /* 0 = unlimited; else refuse past this many live bytes */
void mock_fs_root(const char *dir);  /* directory the fs hooks operate in (Task 7) */
void mock_fs_readonly(int on);       /* make every write refuse -30 (Task 7) */
void mock_stdout_broken(int on);     /* make __absd_std_write return -32 (Task 7) */
void mock_stdin(const void *data, size_t len);      /* bytes __absd_std_read hands out */
const unsigned char *mock_stdout(size_t *len);      /* everything __absd_std_write took */
void mock_fail_next_fstat(int n);   /* make the next n __absd_std_fs_fstat calls return -5 */
void mock_next_fstat_kind(unsigned kind);  /* the next __absd_std_fs_fstat reports this kind */
int mock_open_handles(void);         /* host files the fs hooks hold open */
int mock_lock_calls(void);           /* __absd_std_fs_lock calls so far */
#endif
