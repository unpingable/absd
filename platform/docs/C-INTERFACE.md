# C interface contract (libabs and the C kit)

Status: Stage 1 of `docs/c-ecosystem-20261010/SPEC.md`. It describes the
kit at the commit that contains this file on `lane/c-kit-20261010`
(2026-10-11); the changelog at the end lists its amendments.
This document is the authoritative, language-neutral description of what a
C program on ABSD may rely on. The Rust runtime (`runtime/`) implements it;
the C headers (`c/include/absd/`) bind it; `scripts/check-c-headers.py`
holds the two together. Where this document and the code disagree, the
code is wrong until this document is amended.

It claims no POSIX or libc conformance. The kit is a narrow, consumer-driven
Unix-style personality in userspace over the native ABI: descriptors are a
userspace table over runtime handles, and anything the kit does not provide
is refused or absent, never approximated (section 10). POSIX compatibility is a service ABSD offers to programs, not a set of obligations ABSD assumes internally (owner's standing principle, recorded 2026-10-12 from the integration steward's boundary assessment).

Pieces and where they live:

| piece | file | what it is |
|---|---|---|
| runtime hooks | `c/include/absd/runtime.h` | the 38 `__absd_std_*` C-ABI functions the runtime exports, `ABSD_FS_*` open flags, `struct absd_raw_attr`; each one specified in section 12 |
| kit interface | `c/include/absd/kit.h` | `ABSD_FD_MAX`, `ABSD_STACK_PRETOUCH_BYTES`, the descriptor-table helpers the POSIX lane builds on |
| raw syscall shim | `c/include/absd/syscall.h` | `absd_sys3` (`int $0x80`), `ABSD_SYS_TIME` 17, `ABSD_SYS_SLEEP` 18; the kit uses it only for sleep |
| C entry | `c/libabs/crt0.c` | `__absd_program_main`, stack pre-touch, `environ`, `_exit` |
| allocation | `c/libabs/malloc.c` | malloc family over the runtime's sized allocator |
| descriptors | `c/libabs/fd.c` | descriptor table, open/close/read/write/lseek, fsync/ftruncate/fstat/unlink, `absd_fd_*` |
| errno | `c/libabs/errno_map.c` | native refusal to errno, by name |
| clocks and OS stubs | `c/libabs/clock.c` | gettimeofday, times, clock, getentropy, getpid, sbrk, isatty, raise, kill, sleeps, sysconf, pathconf, sigprocmask |
| locale | `c/libabs/locale.c` | setlocale: the C locale's names only ("C", "POSIX", "", "C.ASCII", "C.US-ASCII"), NULL for any other name (R14, CPA-048); `newlocale`/`uselocale` stay Picolibc's and still accept e.g. "pt_BR" (residual, outside R14; unreached by every Stage 2 program, tcc and the adapter) |
| error text | `c/libabs/strerror_hook.c` | Picolibc's `_user_strerror` hook (R13): ESTALE's text and "Unknown error N" for numbers Picolibc's table has no text for; `crt0.c` references it so every link pulls it (section 5) |
| panic handler | `c/absd-c/src/lib.rs` | the Rust panic handler for a link without std (status 101) |
| driver, link form | `c/bin/absd-cc`, `c/absd-c.ld`, `scripts/check-c-elf.py` | section 8 |

## 1. Process entry

**What the kernel guarantees at entry (KERNEL_ABI 1).** RIP is the ELF
entry; RFLAGS is 0x202 (IF set, DF clear); every general register is zero
except RDI (the console handle, or 0), RSI (address of the handle vector,
8 bytes per handle, little endian) and RDX (the handle count); RSP is
16-byte aligned and the handle vector lies just above it; SSE is enabled
(no AVX, no XSAVE); the FPU image is fresh with FCW 0x037f and MXCSR 0x1f80;
FS and GS base are never set by the kernel, so any `%fs:`/`%gs:` access
(TLS, a `%fs:0x28` stack canary) faults (CPA-062).

**What the runtime's `_start` does, in order** (`runtime/src/lib.rs`):

1. Checks RSP is 16-byte aligned, DF is clear and IF is set. Otherwise it
   exits with status 103 at once, without a message. (FCW, MXCSR and the
   registers are the kernel's guarantee; `_start` does not re-check them.)
2. Asks the kernel's ABI generation (syscall 42). Unless it is 1, writes
   `ABI REFUSED kernel=<answer> required=1` and a newline on the console
   and exits 103, before reading the record or allocating.
3. Checks the handle vector shape: 2 handles (`[stdin pipe, console]`, the
   embedded route), 4 (`[stdin pipe, block, step cell, console]`), or 5 or
   more (`[startup pipe, ..., console]`); the last handle must equal RDI.
   Any other shape exits 102.
4. With 5 or more handles, reads the startup pipe to end of file (at most
   8192 bytes; more, or a read failure, exits 102), closes it, and parses
   it as an ABSDSU01 record for that vector (section 9). A malformed record
   or one that does not name every position between the startup pipe and
   the console exactly once exits 102.
5. Installs what the record grants: stdin, stderr (else the console),
   the working directory, the environment, and either a read-only
   filesystem view (role 11) or the file-server client for the record's
   channels (roles 13/14). A view that fails to mount is left unmounted,
   silently, and the runtime still records the view's device as its block
   handle (lib.rs:706-712); file hooks then take the no-filesystem route
   of section 12 (so `ledger` would be tried on the view device, and
   `""` and `.` open a directory handle).
6. With a file-server channel, runs the protocol handshake. If the server
   does not answer or speaks another protocol, writes one
   `FSD PROTOCOL REFUSED ...` line on stderr and exits 104.
7. Calls `__absd_program_main(argc, argv, envp)` (the `c-entry` build of
   the runtime).

**What a C program sees.**

- `argv[0]` is the record's program name; with no record, or a record
  without a name, it is the name the image was built with
  (`ABSD_PROGRAM_NAME`, else `absd-std-probe`). `argv[1..]` are the
  record's arguments; with no record arguments and no record name, the
  build-time `ABSD_PROGRAM_ARGS` words. `argv[argc]` is NULL.
- `envp` holds the record's environment as `KEY=VALUE` C strings in record
  order, NULL-terminated, empty (just NULL) without one. The strings live
  until exit. `environ` is set to `envp` before any constructor runs.
- The working directory is the record's cwd, else `/`.
- Descriptors 0, 1, 2 are stdin, stdout, stderr (section 4). stdout is
  always the vector's last handle, the console position: a parent that
  captures a child's output (Rust `Command`) places its stdout pipe there.

**The C entry** (`c/libabs/crt0.c`, `__absd_program_main`): pre-touches
`ABSD_STACK_PRETOUCH_BYTES` (262144 bytes, 64 pages) of stack below the
current stack pointer, moving RSP page by page as the kernel's growth rule
requires (section 2); sets `environ`; runs `__libc_init_array()`, which
calls every preinit-array then init-array entry (so every
`__attribute__((constructor))`) in order; calls `main(argc, argv, envp)`;
passes its return value to libc `exit`. Picolibc's `exit` runs the fini
array from last entry to first, which yields, in order: the `atexit`
handlers in reverse order of registration (Picolibc's runner,
`.fini_array_onexit`), the program's destructors, then the stdout flush;
then `_exit`. A program that registers `bye1` then `bye2` and has a
constructor and a destructor prints `ctor`, main's output, `atexit 2`,
`atexit 1`, `dtor`, as on Linux (`c/tests/kit/exit.c`). `_exit` and
`_Exit` end the process through the runtime's exit with the status
unchanged, without handlers; `_Exit` after an `fflush` keeps the flushed
output.

**Exit statuses reserved by the runtime and kit.**

| status | meaning |
|---|---|
| 101 | Rust panic in the runtime (the message goes to stderr as `panic: ...`) or a runtime invariant failure (e.g. a refused unmap) |
| 102 | malformed handle vector or startup record (step 3 or 4) |
| 103 | entry state refused (step 1) or kernel ABI generation not 1 (step 2) |
| 104 | the file server refused the handshake (step 6) |
| 134 | `raise(SIGABRT)`, hence `abort()` (128 + SIGABRT, the status a host shell reports for an aborted program; section 10) |

A process that faults is ended by the kernel; its parent's wait reports the
fault, which the platform's runtime encodes as status `-1000 - vector`
(e.g. -1014 for a page fault). A process killed by its parent is -1.

## 2. Limits

From the kernel at ABI 1 and the platform at this revision.

| limit | value |
|---|---|
| bytes per kernel read or write | 1 to 256; the kit loops (section 4) |
| file-server request | at most 64 KiB of data per read or write request; path at most 4096 bytes |
| heap window | 32 MiB per process; map granularity 4 KiB; at most 64 pages (256 KiB) per map call; memory is zeroed when mapped; heap pages are never executable |
| stack | 8 KiB mapped at entry, 4 MiB reservation with a guard page below. The kernel adds one zeroed page per write fault on the page directly below the mapped bottom, only while RSP lies in that page (or at most 128 bytes above the fault). A first read of an unmapped page, or a frame that moves RSP more than a page below the mapped bottom before touching it, faults (vector 14). The kit pre-touches 256 KiB at entry (64 frames per process) |
| syscall buffers | the kernel never grows the stack for a syscall buffer: a buffer on an untouched stack page is refused (EFAULT) |
| handles per process | 64 |
| open files per file-server channel | 64; the descriptor table has 67 entries (`ABSD_FD_MAX`: 0-2 and 64 files) |
| startup record | 8192 bytes; at most 32 arguments (no per-argument limit beyond the record size); at most 32 environment entries of at most 1024 bytes each; cwd at most 1024 bytes; name 1 to 1024 bytes |
| processes, kernel-wide (including unreaped) | 16 |
| pipes, kernel-wide | 48; capacity 1024 bytes each |
| image | ELF64 ET_EXEC, x86-64, PT_LOAD only (PT_NULL skipped), at most 8, input at most 32 MiB, every segment inside 0x80_0040_0000..0x80_0400_0000, no two segments sharing a 4 KiB page |
| page tables per process | 32, each covering 2 MiB, shared by image, stack and heap and never freed |
| frames | no per-process quota: one global pool |
| threads | one task per process |

## 3. Memory

One allocator: the runtime's (`__absd_std_alloc`, `_dealloc`, `_realloc`),
reached through `c/libabs/malloc.c`. Picolibc's malloc is not built.

- Every block carries a 16-byte header `{size, align}` immediately before
  the returned pointer; the block starts `max(align, 16)` bytes before the
  pointer. The pointer is 16-byte aligned, or aligned to the requested
  larger alignment.
- `malloc(0)` returns a unique pointer that `free` accepts.
- `calloc(n, size)` refuses a multiplication overflow with NULL and ENOMEM,
  allocating nothing; otherwise the block is zeroed.
- `realloc(NULL, n)` is `malloc(n)`. Otherwise it allocates a new block
  with the old alignment, copies `min(old, new)` bytes and frees the old
  block. On failure it returns NULL with ENOMEM and the original block is
  valid and unchanged. `realloc(p, 0)` returns a new unique pointer and
  frees `p`.
- `aligned_alloc(align, size)` refuses an alignment that is 0 or not a
  power of two (NULL, EINVAL). `size` need not be a multiple of `align`.
  Alignments below 16 are raised to 16.
- `posix_memalign(&p, align, size)` returns EINVAL for an alignment that is
  0, not a power of two or not a multiple of `sizeof(void *)`, ENOMEM on
  exhaustion, else 0.
- `malloc_usable_size(p)` is the size requested (0 for NULL).
- Exhaustion of the 32 MiB window (or the page-table budget, or the global
  frame pool) returns NULL with ENOMEM and the program continues. A size
  the allocator cannot describe (overflowing with the header, e.g.
  `malloc(SIZE_MAX)`) or an alignment the runtime's layout refuses (e.g.
  `aligned_alloc(1 << 62, 16)`) is the same, allocating nothing.
- `free(NULL)` does nothing. Double free and freeing a pointer the kit did
  not return are undefined and not detected.
- Return to the kernel: the runtime is asked for `size + slot` bytes,
  where `slot = max(align, 16)`. A request of at least 4096 bytes and at
  most 64 pages (256 KiB), with alignment at most 4096, has pages of its
  own and they are unmapped by `free`. Every other block comes
  from a pooled first-fit list with coalescing; pooled pages stay mapped
  until the process exits, except that when a request for pages of its own
  (4096 bytes to 64 pages) finds no room in the window, the allocator
  unmaps one free, page-aligned pooled run of at most 64 pages and retries
  the request once; a block the program still holds is never moved or
  unmapped, and a request that still fails after the retry is refused as
  before.
- `sbrk` is refused: `(void *)-1` with ENOMEM. There is no `brk`, no
  `mmap`, no shared memory and no file mapping.

## 4. Descriptors and the five calls

A descriptor is an index into a userspace table of 67 entries in the
process (`c/libabs/fd.c`). It is never a kernel object and never outlives
the runtime handle it names. Entries 0, 1 and 2 are the record's stdin,
stdout and stderr streams, served by the runtime's stdio hooks; every
other open entry is a file handle from `__absd_std_fs_open` with its own
position. With no record, stdin is the vector's first handle and stdout
and stderr are the console.

**Table rules.**

| rule | behaviour |
|---|---|
| allocation | `open` takes the lowest free number from 3. Numbers 0, 1 and 2 are never allocated by `open`, even after they are closed (no `dup2` exists in the kit or the adapter, CPA-036; a closed 0, 1 or 2 stays closed for the life of the process) |
| stale or never-opened number | every call refuses it with EBADF (including `close` of a closed number); a number is reused only by a later `open` |
| table full | EMFILE; the runtime handle just opened is closed again. The open did happen first, so an `O_CREAT` that created the file or an `O_TRUNC` that truncated it stays done (fd.c:116-120) |
| channel full | with 64 files already open on the channel, the server refuses the 65th open (-24, `server.rs:693`) and it is EMFILE |
| `close(0..2)` | marks the entry closed; the runtime's stream is untouched |
| `close(file)` | closes the runtime handle (the file server commits a file its writer closes) and frees the entry; if the runtime refuses, the entry is freed anyway and `close` returns -1 with the mapped errno |
| inherited handle | `absd_fd_install_file(handle, append)` installs it lowest-free from 3, recorded as `O_RDWR` (`fd.c:64-66`); the runtime refuses whatever the handle's rights do not allow: it alone decides the handle's rights, so the table never widens authority |

**`open(path, flags, ...)`.** The path is a C string, absolute or relative
to the working directory (resolved lexically by the runtime; ABSD has no
symbolic links). The mode argument is not read; new files are created
writable (`st_mode` 0644). On the no-filesystem route (section 12) the
only names are `ledger`, `""` and `.`: `open("", O_RDONLY)` and
`open(".", O_RDONLY)` return a descriptor for a directory handle, and
everything else is ENOENT or EINVAL as that section states.

| flags | result |
|---|---|
| `O_RDONLY`, `O_WRONLY`, `O_RDWR` | runtime READ (1), WRITE (2), READ\|WRITE |
| any other access mode value | EINVAL |
| `O_CREAT` | CREATE (8) |
| `O_CREAT\|O_EXCL` | CREATE_NEW (16): EEXIST if the name exists |
| `O_EXCL` without `O_CREAT` | ignored, as on Linux |
| `O_TRUNC` | TRUNCATE (32) |
| `O_RDONLY\|O_TRUNC` | EINVAL (refused, not passed on) |
| `O_APPEND` | accepted; emulated in `write` (below) |
| `O_CLOEXEC` | accepted, no effect: ABSD has no exec, so no descriptor crosses one |
| `O_NOFOLLOW` | accepted, no effect: ABSD has no symbolic links |
| any other bit (`O_NONBLOCK`, `O_NOCTTY`, `O_DIRECTORY`, `O_SYNC`, ...) | EINVAL, nothing opened |

**`read(fd, buf, n)`.**

| case | behaviour |
|---|---|
| `n == 0` | returns 0 without a call (after the EBADF check) |
| stdin | one transfer of at most 256 bytes: a short count is honest; 0 is end of file (a pipe with no writer left, or no stdin handle at all); the console never reports end of file |
| file | positional reads from the descriptor's position, looping until `n` bytes, end of file (0), or a refusal; returns the bytes read and advances the position; a refusal after some bytes returns the count, a refusal before any returns -1 |
| stdout, stderr | EBADF |
| directory | EISDIR (from the server) |

**`write(fd, buf, n)`.**

| case | behaviour |
|---|---|
| `n == 0` | returns 0 without a call (the kernel refuses zero-length transfers) |
| stdout, stderr | loops in transfers of at most 256 bytes until `n` bytes; a hook result of 0 stops the loop and returns what moved, possibly 0; a refusal after some bytes returns the count; a refusal before any is -1 with the errno; a pipe with no reader left is EPIPE, with no signal |
| file | positional writes from the position, looping as `read` does |
| file with `O_APPEND` | before each `write`, the position is set to the file's current size from fstat; if that fstat is refused, `write` returns -1 with its errno, writes nothing and leaves the position unchanged. Two descriptors on one file keep separate positions and cross-process append atomicity is not provided |
| stdin | EBADF |
| no output handle | the runtime's -1, so EPERM |

**`lseek(fd, offset, whence)`** is position arithmetic in the table; it
calls nothing except for `SEEK_END`.

| case | behaviour |
|---|---|
| `SEEK_SET`, `SEEK_CUR` | base 0 or the current position |
| `SEEK_END` | base is the size from fstat; if fstat is refused, -1 with its errno and the position unchanged |
| other `whence` | EINVAL |
| result negative or overflowing | EINVAL, position unchanged |
| stdin, stdout, stderr | ESPIPE |
| past the end | allowed; a later write there extends the file |

**The other descriptor calls the kit provides.**

| call | behaviour |
|---|---|
| `fsync(fd)` | on a file, returns after the file server (or the in-process filesystem) has committed; the server's commit covers the whole filesystem, not only this file. On 0, 1, 2 returns 0 |
| `ftruncate(fd, len)` | sets the file's length; EINVAL for a negative length or a stdio descriptor |
| `fstat(fd, &st)` | on a file: `st_mode` `S_IFREG` (attribute kind 1) or `S_IFDIR` (kind 2) with 0644, or 0444 when the object is read-only; any other attribute kind is -1 with EIO, no mode chosen (section 6, SPEC A13); `st_size`; `st_ino` the object serial; `st_dev` the filesystem id; `st_nlink`; `st_uid` and `st_gid` 1000 (the synthetic identity of SPEC A8: no authority, no ownership); `st_blksize` 65536, the file server's per-request transfer cap (`MAX_IO`, fsd/src/proto.rs), as the preferred I/O size; `st_mtime` 0 (no timestamps reach C at Stage 1); every other field 0. Directories report 0644 (or 0444) with no search bits: the kit has no execute or search notion, so `S_IXUSR` (and any `S_IX*`) tests on a directory are false by design. On 0, 1, 2: `S_IFCHR\|0600`, uid and gid 1000, all else 0 |
| `unlink(path)` | removes the name through the runtime; refusals as in section 5 |
| `absd_fd_access_mode(fd)` | `O_RDONLY`, `O_WRONLY` or `O_RDWR` as opened; -1 with EBADF |
| `absd_fd_lock(fd, mode)` | advisory whole-file lock on the file's handle: 0 unlock, 1 shared, 2 exclusive; never waits, a conflict is EAGAIN; EBADF on a stdio descriptor, EINVAL for a mode outside 0..2 (refused by the kit before the runtime sees it). Whether it excludes another process is the file server's lock (SPEC A7, a POSIX-lane qualification case) |
| `absd_stat_from_attr(attr, st)` | the conversion `fstat` uses, exported so a path `stat` gives identical fields; 0, or -1 with EIO for an attribute kind other than 1 or 2 (`*st` then untouched) |

**Access mode and the server.** The table records the access mode but
`read` and `write` do not check it: the runtime refuses an operation the
open did not request with EACCES (where Linux says EBADF). Writes through
a read-only mount are EROFS at open time.

## 5. Refusals and errno

A runtime or file-server refusal is a negative, Linux-numbered code. The
kit turns it into -1 (or NULL) with `errno` set by name
(`c/libabs/errno_map.c`); Picolibc numbers several of these differently from
Linux, so the map never passes a number through. A refused call changed
nothing: no bytes moved, no position moved, no descriptor was allocated
(except: `close`, whose entry is freed whatever the runtime answers; the
counted results of a partial `read`/`write`; and `open` refused with
EMFILE by a full table after the runtime opened the file, where a create
or truncate has already happened).

| native | errno | what produces it at this revision |
|---|---|---|
| -1 | EPERM | the kernel's rights refusal; the filesystem device refused for rights; a stdio write with no output handle |
| -2 | ENOENT | no such name; a path outside every mount of the channel that is not on the way to one; an unformatted filesystem; on the no-filesystem route (no channel, no mounted view: section 12) every path except `ledger`, `""` and `.`, and `ledger` without a durable boot's block handle |
| -5 | EIO | device failure; the RTC has no stable reading (`gettimeofday`) |
| -9 | EBADF | a runtime handle the server or filesystem does not know |
| -10 | ECHILD | process wait with no such child (process hooks only) |
| -11 | EAGAIN | a lock held by another handle; the channel is lent to a child; no free process slot |
| -12 | ENOMEM | the kernel refused a map (allocation reports ENOMEM itself) |
| -13 | EACCES | a write or truncate on a handle opened without write; a write to an object marked read-only; a read on a handle opened without read |
| -14 | EFAULT | a buffer the kernel cannot use (unmapped, or an untouched stack page) |
| -16 | EBUSY | removing or renaming a mount point; a released channel's work not yet drained |
| -17 | EEXIST | `O_CREAT\|O_EXCL` on an existing name; formatting a non-blank device |
| -20 | ENOTDIR | a path component that is a file |
| -21 | EISDIR | read or write on a directory |
| -22 | EINVAL | a malformed request: empty or unnormalizable path (over 4096 bytes, NUL), bad flags at the runtime, a buffer too small for getcwd |
| -24 | EMFILE | the channel's 64 open files; the kernel's 64 handles |
| -27 | EFBIG | a whole-file read over its limit (runtime-internal readers; not reached by the five calls) |
| -28 | ENOSPC | the filesystem is full |
| -29 | ESPIPE | mapped for completeness; the kit's own `lseek` on a stream sets it directly |
| -30 | EROFS | open for writing, create, truncate or a mutation in a read-only mount or the read-only view |
| -32 | EPIPE | write to a pipe with no reader (no signal) |
| -36 | ENAMETOOLONG | not produced by the runtime or file server at this revision; mapped so a later refusal is named |
| -38 | ENOSYS | a syscall the kernel does not have |
| -39 | ENOTEMPTY | removing a non-empty directory |
| -74 | EBADMSG | the filesystem found corruption |
| -75 | EOVERFLOW | the kernel's PID space is exhausted |
| -95 | ENOTSUP | another filesystem format version; truncating the runtime's ledger file; every mutation, lock, readdir and canonical on the no-filesystem route |
| -110 | ETIMEDOUT | a timed handle read passed its timeout |
| -116 | ESTALE | the filesystem is poisoned (an earlier device failure left memory ahead of the device); a stale cell version |
| any other | EIO | an unnamed refusal is never passed through as a number |

Errors the kit sets itself, without a native code: EBADF (descriptor
checks), EMFILE (table full), EINVAL (open flags, lseek, ftruncate, the
malloc family's alignments, nanosleep, sysconf/pathconf names), ESPIPE
(lseek on a stream), ENOMEM (allocation, sbrk), EIO (getentropy), ENOTTY
(isatty), ENOSYS (kill, sigprocmask).

**Error text (R13).** `strerror`, `strerror_l`, `strerror_r` and `perror`
are Picolibc 1.8.12's. Its table (`src/libc/string/strerror.c`) has text
for every errno above but ESTALE, which the kit's hook
(`c/libabs/strerror_hook.c`) names "Stale file handle"; a number with no
text reads "Unknown error N" (N in decimal, in a static buffer the next
unknown number overwrites; `strerror_r` uses a separate buffer, so it never
overwrites a string held from `strerror`, but `perror` calls `strerror`, so
for an unknown number only it does: ISO C 7.24.6.2 asks that no library
function seem to call `strerror`; residual). `strerror` never changes
`errno`. Several texts differ from glibc's (EPERM "Not owner", EBADF "Bad
file number", ENOMEM "Not enough space", EAGAIN "No more processes",
ECHILD "No children", EMFILE "File descriptor value too large",
ENAMETOOLONG "File or path name too long", ENOTSUP "Not supported"):
compare `errno`, never the text. `perror(s)` reads `errno` first, then
writes `s: text\n` (`text\n` when `s` is NULL or empty) to `stderr`,
descriptor 2 through the kit's `write` and the runtime's stderr hook, and leaves `errno` as it was when
the writes succeed.

## 6. Authority

- A C process holds exactly the handles its startup vector carries and its
  record names; the kit opens nothing else and asks for nothing else.
- Files are reached only through the file-server channel or the read-only
  filesystem view the record granted (or, in a durable boot, the
  runtime's own ledger file). There is no `/`-rooted global namespace
  beyond the channel's mounts.
- The shell route (SPEC 3.5), as observed by `scripts/c-kit-matrix.py`
  (Task 12): a program absd-sh starts in an SSH session inherits the
  session's mounts, `/bin`, `/etc`, `/share` and `/var/log` read-only and
  `/home/operator` and the session's own `/tmp/session-<n>` writable.
  `/tmp` itself is a read-only ancestor, not a writable place: creating
  `/tmp/name` is ENOENT. Another session's `/tmp/session-<m>` is not
  visible. The environment is empty (sshd's policy; absd-sh has no
  variables), and the working directory is `/` as sshd sets it
  (ssh/src/absd.rs), also read-only, until the shell's `cd` changes it.
  A program's writable scratch is its working directory, so it must be
  started in a writable one (`cd /home/operator` or the session's
  `/tmp/session-<n>`, then the program) and name its scratch files
  relative to it. Picolibc's `P_tmpdir` as installed is `""`
  (`__P_tmpdir` is not defined by the build; `stdio.h` falls back to the
  empty string, as preprocessing it against the kit's `include/` shows),
  so the names `tmpnam` and `tmpfile` make are relative to the working
  directory, and they land somewhere writable only when the program was
  started in a writable directory; what more they need belongs to the
  POSIX lane (a request is filed).
- The filesystem has exactly two object kinds, file (attribute kind 1) and
  directory (2), and no symbolic link. `O_NOFOLLOW` as an accepted no-op
  (section 4), and the POSIX lane's `lstat` equal to `stat` and `readlink`
  EINVAL, are honest only while that holds (SPEC A13): it is an invariant
  kept by checks, not an assumption. `scripts/check-fs-kinds.py` (run by
  `scripts/build-c-kit.sh` and `scripts/check-c-kit-host.sh`, with a
  `--self-test` that adds a third kind at each site and expects refusal)
  holds the `Kind` enum and every encoding of it (fs/src/image.rs encoder
  and decoder, fsd/src/server.rs `attr_bytes`, runtime/src/storage.rs
  `fill`, scripts/absd_fs.py) to exactly 1 and 2; the `fs` crate's host test
  `object_kinds_are_exactly_file_and_dir` (fs/src/tests.rs) matches `Kind`
  with no wildcard arm, so a new variant does not compile; and
  `absd_stat_from_attr` refuses any other kind with EIO rather than
  choosing a mode. A link kind would amend this section first.
- The file server judges every path: a path outside the channel's mounts
  that is not an ancestor of one is ENOENT; an ancestor of a mount is
  visible read-only; opening for write, creating or mutating under a
  read-only mount (or an ancestor) is EROFS; writing an object marked
  read-only is EACCES. The kit never retries a refused operation through
  another route.
- Descriptor numbers are a userspace representation over runtime handles.
  They are not kernel objects, do not survive their handle, and confer no
  authority of their own.
- The uid and gid 1000 the kit reports are an observational convention
  (SPEC A8): no decision rests on them.
- No fork, no exec, no signals, no threads, no ambient namespace, no
  kernel file-descriptor table. The kit adds no syscall use beyond the
  runtime's, except the sleep call (18) in section 7.

## 7. Clocks

| call | behaviour |
|---|---|
| `gettimeofday(tv, tz)` | `tv_sec` from the kernel's RTC (syscall 30): whole seconds since the epoch, UTC, no correction; `tv_usec` always 0; `tz` ignored. Without a stable RTC reading: -1 with EIO |
| `time(t)` | Picolibc's, over `gettimeofday` |
| `times(buf)` | returns timer ticks since boot (syscall 17, PIT, a tick is 1193/1193181.67 s, about 0.99985 ms); `tms_utime` = ticks, the other fields 0. It is boot time, not process CPU time |
| `clock()` | the kit's (`clock.c`, ruling R12): the tick count of `times()` taken as milliseconds and scaled to `CLOCKS_PER_SEC` (1000000) units, ticks × (`CLOCKS_PER_SEC` / 1000), saturating at the `clock_t` maximum (`clock_t` is 64-bit unsigned). Like `times()` it counts from boot, not process CPU time. Picolibc's unscaled `clock()` is never linked (the map check refuses its member) |
| `sysconf(_SC_CLK_TCK)` | 1000 |
| `nanosleep(req, rem)` | EINVAL for a NULL `req`, negative fields or `tv_nsec` above 999999999. Otherwise the duration is rounded up to whole milliseconds and the kernel sleep (syscall 18) is asked for that many ticks (1 ms = 1 tick); the kernel returns after at least that many full ticks. A zero duration makes no call. Saturates at `LONG_MAX` ticks. Always returns 0 and sets `*rem` to zero (nothing interrupts a sleep) |
| `usleep(us)` | `ceil(us / 1000)` ticks; returns 0 |
| `sleep(s)` | `s * 1000` ticks; returns 0 |

Known limitations at Stage 1:

- Sleeps map milliseconds to ticks 1:1, and a tick is 0.99985 ms, so a
  sleep can end up to 0.015% early in wall time (about 0.5 s in an hour).
  Short sleeps are never early by a whole tick: the rounding is up.
- `clock()` takes a tick as exactly 1 ms, so it shares the sleeps'
  0.015% error, and it counts from boot rather than process start.
- Under emulation the tick counter may run slow against host time.

## 8. Toolchain and link form

**Compiler.** `absd-cc` drives host clang 18 (`clang-18`, or `ABSD_CLANG`;
any other major version is refused, and the builtins archive linked is that
compiler's; each link writes `OUT.toolchain` naming the compiler, the linker
and the builtins archive with its sha256) with these flags, fixed:

    --target=x86_64-unknown-none-elf -ffreestanding -nostdinc -nostdlib
    -mcmodel=large -fno-pic -fno-pie -fno-stack-protector -mno-avx
    -march=x86-64 -fno-asynchronous-unwind-tables -ffunction-sections
    -fdata-sections -Xclang -fstack-clash-protection
    -isystem <kit>/include -isystem <clang resource dir>/include

All user addresses lie above 4 GiB, hence the large code model; the red
zone stays enabled (the kernel honours it); `-fstack-clash-protection`
is passed to cc1 directly because the driver drops it for a non-Linux
triple. `<kit>/include` holds the Picolibc headers and `absd/*.h`.

`absd-cc [-c] [-o OUT] [-O0..3] [-I dir] [-D...] FILE...` accepts `.c`,
`.s` and `.S` sources (compiled) and other files (objects, archives)
passed to the link; it passes `-I`, `-D`, `-U`, `-W`, `-f`, `-g` and
`-std=` options through, defaults to `-O2` and `a.out`, and refuses (exit
2) `-Wl,*`, `-fpic`, `-fPIC`, `-fpie`, `-fPIE`, `-fstack-protector*`,
`-mcmodel=*`, `-march=*` and every other option. `ABSD_CC_VERBOSE=1`
prints the commands.

**Link.** `ld.lld-17 -static -no-pie --gc-sections -T <kit>/absd-c.ld
-Map=OUT.map`, then `crt0.o`, the objects, and one group in this order:
`libabs.a`, `libc.a`, `libm.a`, `libabs_builtins.a`,
`libclang_rt.builtins-x86_64.a`. Static ET_EXEC only, no PIE (CPA-063).

| archive | contents | why at that place |
|---|---|---|
| `libabs.a` | the Rust runtime and `absd-c` (as a staticlib) plus the kit's C objects crt0, malloc, fd, errno_map, clock | first, so the kit's definitions and the runtime's `memcpy`/`memmove`/`memset`/`memcmp` win over Picolibc's libos fallbacks and string routines |
| `libc.a` | Picolibc 1.8.12 (its libm is folded in), built by `scripts/build-picolibc.sh` from the pinned tarball; its sha256 is pinned in `c/picolibc/PIN` and checked by every kit build | |
| `libm.a` | Picolibc's installed libm.a, an empty stub | kept so a program that names it links |
| `libabs_builtins.a` | the Rust `compiler_builtins` member, moved out of `libabs.a` | after libc: its ~76 weak libm definitions must lose to Picolibc's strong ones |
| clang builtins | `libclang_rt.builtins-x86_64.a` | last: compiler support routines |

The linker script (`c/absd-c.ld`): entry `_start`; two program headers,
`text` (R+X) and `data` (R+W); `.text` page-aligned at 0x8000400000 then
`.rodata` in `text`; `.data` page-aligned (with `.got` and the large-model
`.ldata`), then the preinit, init and fini arrays between
`__preinit_array_start/end`, `__init_array_start/end` (sorted by
priority) and `__fini_array_start/end`, then `.bss` (NOLOAD), in `data`.
It also defines the bounds Picolibc's `__libc_init_array` walks,
`__bothinit_array_start` (= preinit start) and `__bothinit_array_end`
(= init end), and keeps every `.fini_array*` input section, including
Picolibc's `.fini_array_onexit` (the `atexit` runner);
`.note*`, `.comment*`, `.eh_frame*`, `.eh_frame_hdr` and
`.gcc_except_table*` discarded.

**Host checks** (`scripts/check-c-elf.py ELF [--map OUT.map]`) refuse any
image that is not ET_EXEC x86-64; has a program header other than PT_LOAD
(PT_NULL skipped) or more than 8; has a segment with memsz 0, filesz above
memsz, a vaddr not page-aligned or not congruent with its offset, or
outside the image window; has two segments in one page; has a `.tdata`,
`.tbss`, `.note*`, `.rel*`/`.rela*`, `.plt`, `.got.plt`, `.dynamic`,
`.interp` or `.dynsym` section; has an entry outside every segment; or has
an undefined symbol other than Picolibc's weak `stdin` and `stdout`
references. That is a named allowance, not a general one: their only weak
references are in Picolibc's `src/libc/stdio/bufio.c` (declared weak at
162-163), whose one use, the flush of stdout before a stdin read (191-193),
tests `&stdin != NULL && &stdout != NULL` first, so an absent stream
resolves to 0 and is skipped, never dereferenced (`stdout` admitted by the
steward's R13 decision, 2026-10-12). Any other weak-undefined name is
refused. An undefined
`__bothinit_array_start/end` is refused: it would silently skip every
constructor. With the map they also refuse (SPEC A9): any member pulled from
`libgcc.a`, or members `bid*.o`, `generic-morestack*.o`, `_eprintf.o` from
any archive; any Picolibc libm symbol whose definition came from
`libabs.a`/`libabs_builtins.a`; any Picolibc `libos_*` fallback member; and
any `libc.a` member pulled for a symbol the kit's C objects or the
runtime's mem* functions define; any fortify `*_chk` symbol resolved from
an archive (absd-cc and the gcc pass compile with `-U_FORTIFY_SOURCE`);
and Picolibc's `libc_stdlib_exitprocs.c.o` pulled without its
`.fini_array_onexit` section. A statically resolved `.got` inside the
data segment is accepted. On success: `C ELF OK <path> loads=<n>` (with
`map=checked`).

**Header check.** `scripts/build-c-kit.sh` runs
`scripts/check-c-headers.py` and fails the build unless every prototype in
`runtime.h` matches the Rust definition and every Rust hook is declared, every `ABSD_FS_*` constant equals
the bit both the runtime's and the file server's open test, and
`struct absd_raw_attr` matches `RawAttr`
(`C HEADERS OK hooks=38 constants=5`). `--self-test` shows it refusing an
injected parameter, return, constant and struct-field change and a removed
prototype.

**Compilers.** The Stage 0 verdict
(`docs/c-ecosystem-20261010/c-kit/receipts/stage0/verdict.md`): clang is
usable; gcc is usable with a restriction (libgcc.a only without its
decimal-float, split-stack and `_eprintf` members; the builtins archive is
the fallback). `absd-cc` drives clang only. The Stage 0 gcc build
(`c/tests/stage0/build.sh`) used the same code-generation flags plus
`-fcf-protection=none` and the same linker script, outside the driver. **Link sets differ by driver.** `absd-cc` links crt0, `libabs.a`, `libc.a` (Picolibc), `libm.a`, `libabs_builtins.a` and the clang builtins (`c/bin/absd-cc:52-54`); it does not link the POSIX adapter. `/share/absd-c/lib/libc.a` for tcc is a GROUP of `libabsd-posix.a libabs.a libc-picolibc.a libm.a libabs_builtins.a` (`tcc/build/libc.a.group:2`), so every tcc-compiled program carries the adapter, including the A17 range-lock recognition (CPA-057; STAGE3 section 7).

## 9. Formats that cross the language line

**The startup record (ABSDSU01)** is written by a Rust parent and read by
the runtime linked into a C program. Little endian throughout:

    "ABSDSU01"
    u16 role_count, then role_count x {u8 role, u8 vector index}
    u16 argc, then argc x {u16 length, bytes}      arguments after argv[0]
    [u16 envc, then envc x {u16 length, "KEY=VALUE"}]   optional
    [u16 length, cwd]                                  optional, only after env
    [u16 length, program name]                         optional, only after cwd

Roles: 1 stdin, 2 stdout, 3 stderr, 4 block, 5 step cell, 6/7 broker
request/reply, 8/9/10 broker slot stdin/stdout/stderr, 11 read-only
filesystem view, 12 NIC, 13/14 file-server request/reply, 15 machine,
16/17 session events/requests. Index 0 is the startup pipe and the last
index the console; every index between them carries exactly one role.
The parser refuses: more than 8192 bytes; a vector of fewer than 5 or more
than 64 handles; an unknown role; a repeated single role; incomplete slot
triples (at most 8) or unpaired file-server ends (at most 16 pairs); a
slot without the broker pair; one session role without the other; both a
view and a channel, or a block and a view; more than 32 arguments or
environment entries; a NUL in any string; an environment entry over 1024
bytes, without `=`, with an empty key, or repeating an earlier key; a cwd
that is not absolute, is over 1024 bytes, or has an empty, `.` or `..`
component (`/` itself is allowed); an empty or over-1024-byte name;
trailing bytes. Any refusal is status 102 before `main`.

Vectors: `c/vectors/startup/` holds records emitted by the Rust encoder
(`broker/src/tests.rs`, `emit_startup_vectors`) with what a child must
observe: `empty`, `args`, `env`, `utf8`, `maximal-fitting` (7 arguments of
1024 bytes and 32 one-character environment entries, 7377 bytes, the
largest the limit admits), and `maximal.json` recording that 32 arguments
and 32 environment entries of 1024 bytes are refused with the encoder's
`TooLarge`. The emitting test parses every record back and asserts argv,
environment, cwd, name and roles equal its inputs.

**The file-server wire protocol** does not cross the language line: it
stays inside the runtime, and C sees only the `__absd_std_fs_*` hooks.

**`struct absd_raw_attr`** (the hooks' attribute record) is
`{u32 kind (1 file, 2 directory; 0 unknown, in a readdir entry only),
u32 readonly, u64 size, u64 filesystem, u64 serial, u64 links}`, checked
against `RawAttr` by the header check. It has no timestamp. The internal
platform V2 hooks (`__absd_std_fs_{stat,fstat,readdir}_v2`) use a separate
48-byte `absd_raw_attr_v2`, adding whole-second mtime (0 unknown) at offset40.
The pinned Rust std uses V2. The C kit remains on V1, so `st_mtime` stays0;
its consumers and old40-byte buffers are unchanged. Both versions share
the runtime decoder; V2 requires matching runtime symbols at link time.
A file server
kind word outside 1..2 is never passed through and never converted
(SPEC A21): stat and fstat refuse the object with -5, and readdir lists the
entry marked 0, neither file nor directory (storage.rs:776-814).

## 10. What is not provided (refused, not approximated)

The kit defines only what this document names. Each of these is refused,
answered with a fixed value stated here, or left to the POSIX lane, and a
Picolibc `libos` fallback that would answer silently is refused at link
time (section 8).

| facility | at Stage 1 |
|---|---|
| `fork`, `exec*`, `posix_spawn`, `wait*` | not provided by the kit. The runtime's spawn, wait and kill hooks are declared in `runtime.h`; a POSIX spawn adapter is the POSIX lane's |
| signals | none: no signal is ever delivered. `raise(SIGABRT)` ends the process with status 134 (so `abort` does, without atexit handlers or destructors); `raise` of signal 0 or of a number outside 1..31 is -1 with EINVAL; `raise` of any other signal is -1 with ENOSYS and the process continues; `kill` is -1 with ENOSYS; `sigprocmask` is -1 with ENOSYS; `signal`, `sigaction`, `alarm`, `sigsetjmp` with a mask are not provided by the kit |
| threads, TLS | none; errno is a plain global (CPA-062) |
| `mmap`, `munmap`, `brk`, shared memory | not provided; `sbrk` is refused with ENOMEM |
| `dup`, `dup2`, `pipe`, `fcntl` | not provided by the kit (POSIX lane); the adapter provides none of `dup`, `dup2`, `pipe` (CPA-036) and only `fcntl` `F_SETLK` |
| `stat`, `lstat`, `access`, `mkdir`, `rmdir`, `rename`, `opendir`/`readdir`, `getcwd`, `chdir`, `realpath` | not provided by the kit (POSIX lane, over the hooks section 12 specifies). `access` stays unprovided by the kit; the POSIX lane's `access(dir, W_OK)` is a documented refusal (ENOSYS) under owner decision A11, not a creation probe |
| `getuid`, `getgid` and the `set*id`/`chown` family | POSIX lane (SPEC A8: 1000, setters refused with EPERM) |
| `isatty` | always 0 with ENOTTY: the console is not a terminal |
| termios, `select`, `poll`, sockets | not provided |
| `sysconf` | `_SC_PAGESIZE`/`_SC_PAGE_SIZE` 4096, `_SC_OPEN_MAX` 67, `_SC_NPROCESSORS_ONLN` and `_SC_NPROCESSORS_CONF` 1, `_SC_CLK_TCK` 1000; any other name -1 with EINVAL |
| `pathconf`, `fpathconf` | `_PC_PATH_MAX` 1024, `_PC_NAME_MAX` 256 for any path or descriptor; any other name -1 with EINVAL |
| `getentropy(buf, n)` | RDRAND bytes; `n` above 256 is -1 with EIO; RDRAND failing 100 times in a row is -1 with EIO |
| `getpid` | the kernel's PID |
| file timestamps | `st_mtime` (and every other time field) is 0: the attribute record carries no time at Stage 1 |
| `setjmp`/`longjmp` | Picolibc's; crosses no kernel boundary |

## 11. Stage 1 limitations, collected

- `st_mtime` is 0 for every file (no timestamp reaches C; deferred).
- The kit provides no `access`, `stat`, `dup`, `pipe` or spawn; those are
  the POSIX lane's.
- Sleeps can end up to 0.015% early (1 ms requested per tick of 0.99985 ms).
- `clock()` counts boot time in 1 ms ticks scaled to `CLOCKS_PER_SEC`, not process CPU time (section 7).
- `write` on a descriptor opened read-only (or `read` on one opened
  write-only) is EACCES from the runtime, not EBADF.
- The stack pre-touch protects only frames within 256 KiB of the entry; a
  frame that crosses it relies on the compiler's stack-clash probes.
- `fsync` commits the whole filesystem on the file-server route.
- A program whose stdio never names `stdout` (only `perror` or
  `fprintf(stderr, ...)`, or only `fopen`ed files) keeps Picolibc's weak
  `stdout` reference (`bufio.c`) undefined; the host check admits it by
  name beside `stdin`, because `bufio.c:191-193` tests it before use
  (section 8; R13 record F1, resolved). The allowance is exactly these two
  names.
- `arc4random` is refused by the host check: its weak `arc4random_abort`
  and `arc4random_fork_detect` hooks are undefined in the kit. Open (R13
  record, F2).

## 12. Runtime hooks (`c/include/absd/runtime.h`)

The 38 `__absd_std_*` functions are the runtime's C ABI; the kit's C code
and the POSIX lane's adapter are built on them. Each is checked against
its Rust definition by `scripts/check-c-headers.py` (both directions).

**Conventions.**

- Results: a non-negative value is success (a count, a handle, a length,
  0); a negative value is a refusal, normally a Linux-numbered errno as
  section 5 lists. The process hooks also return the runtime's own codes
  at -2000 and below (listed with them); the kit's errno map does not
  name those, so they would become EIO if passed through it.
- Paths are byte strings with a length, never NUL-terminated. A relative
  path is resolved against the working directory lexically
  (`runtime/src/cwd.rs:34-39`); an empty path stays empty and names
  nothing.
- Handles are the runtime's (file handles from `__absd_std_fs_open`, or
  kernel handles for the `handle_*` and process hooks), never descriptors.
- Filesystem routes. Every file hook first asks whether a file-server
  channel is installed (`fsd::active()`); this section calls that the
  **server route**. Otherwise a mounted in-process filesystem (the
  record's read-only view, or one the process mounted itself) serves it:
  the **mounted route**. With neither, the **no-filesystem route** serves
  only the runtime's ledger convention (storage.rs:523-636). After a failed read-only view mount, `BLOCK` still names the view device (lib.rs:706-712), so this route's `ledger` is tried on it. On the server
  route the refusals are as the file server reports them
  (`fsd/src/server.rs` `errno` and `proto::status`), plus the client's
  own: -2 when the process holds no channel of its own and -11 while its
  channel is lent to a running child (`runtime/src/fsd.rs:273-282`). On
  the mounted route they are the filesystem's errors as
  `storage.rs:324-345` maps them; a read-only view refuses mutation with
  -30.
- `struct absd_raw_attr` is filled on success only.

**Memory** (`runtime/src/lib.rs:489-514`)

| prototype | meaning and arguments | result and refusals |
|---|---|---|
| `unsigned char *__absd_std_alloc(size_t size, size_t align)` | a block of `size` bytes aligned to `align` (a power of two) from the process allocator (section 3 states which blocks get their own pages) | the block, or NULL when `(size, align)` is not a valid layout (align not a power of two, size overflowing when rounded) or memory is exhausted |
| `void __absd_std_dealloc(unsigned char *ptr, size_t size, size_t align)` | frees a block; `size` and `align` must be the ones it was allocated with | none; an invalid layout is ignored (nothing freed); a kernel refusal to unmap a dedicated block ends the process with 101 (lib.rs:367-374) |
| `unsigned char *__absd_std_realloc(unsigned char *ptr, size_t old_size, size_t align, size_t new_size)` | resizes a block keeping its alignment, copying `min(old, new)` bytes | the block, or NULL for an invalid `(old_size, align)` or exhaustion; on NULL the original block is unchanged and still owned by the caller |

**Process and stdio** (`runtime/src/lib.rs`)

| prototype | meaning and arguments | result and refusals |
|---|---|---|
| `ptrdiff_t __absd_std_read(unsigned char *bytes, size_t length)` | one kernel read of at most 256 bytes from stdin (lib.rs:517-533) | bytes read; 0 for `length` 0, for no stdin handle, or end of file on a pipe; kernel refusals (-9 bad handle, -14 unusable buffer, -1 no read right) |
| `ptrdiff_t __absd_std_write(const unsigned char *bytes, size_t length)` | one kernel write of at most 256 bytes to stdout, the vector's console position (lib.rs:536-552) | bytes written (may be short on a pipe); 0 for `length` 0; -1 with no output handle; -32 when a pipe has no reader (no signal); kernel -9, -14 |
| `ptrdiff_t __absd_std_stderr_write(const unsigned char *bytes, size_t length)` | as `write`, to the record's stderr, else the console (lib.rs:555-574) | as `write` |
| `uint32_t __absd_std_getpid(void)` | the kernel's PID for this process | always succeeds |
| `_Noreturn void __absd_std_exit(int32_t code)` | ends the process with `code` as its status | never returns |
| `const size_t (*__absd_std_environ(size_t *count))[2]` | the record's environment: stores the entry count at `*count` and returns an array of `count` `[pointer, length]` pairs, each a `KEY=VALUE` byte string without a NUL, in record order; valid until exit (lib.rs:88-99) | with no environment, `*count` is 0 and the pointer is NULL |
| `uint64_t __absd_std_ticks(void)` | timer ticks since boot (about 0.99985 ms each) | always succeeds |
| `int64_t __absd_std_wall_clock_seconds(void)` | seconds since the epoch from the RTC, whole seconds, UTC (lib.rs:205-228) | seconds, or the kernel's refusal: -5 without a stable reading, -38 from a kernel without the call |

**Working directory** (`runtime/src/cwd.rs`)

| prototype | meaning and arguments | result and refusals |
|---|---|---|
| `ptrdiff_t __absd_std_getcwd(unsigned char *out, size_t capacity)` | copies the working directory (absolute, normalized, no NUL appended) into `out` (cwd.rs:74-84) | its length; -22 when `capacity` is smaller; same on every route |
| `int64_t __absd_std_chdir(const unsigned char *path, size_t length)` | resolves `path` lexically against the working directory and makes it the working directory if it is an existing directory (cwd.rs:86-114) | 0; -2 for an empty path; -20 for a file; -5 for an object of unknown kind (server route, SPEC A21); the stat refusal of the route (server or mounted); on the no-filesystem route only `/` is accepted, anything else -2; -22 for a result that is not a valid record cwd (over 1024 bytes) |

**Files** (`runtime/src/storage.rs`; flags `ABSD_FS_READ` 1, `ABSD_FS_WRITE` 2, `ABSD_FS_CREATE` 8, `ABSD_FS_CREATE_NEW` 16, `ABSD_FS_TRUNCATE` 32)

| prototype | meaning and arguments | result and refusals |
|---|---|---|
| `int64_t __absd_std_fs_open(const unsigned char *path, size_t length, uint32_t flags)` | opens `path` with the flag bits above (storage.rs:597-636). Server route: the raw flags are forwarded; the server refuses -2 outside the channel's mounts (not an ancestor of one), -30 for any of write/truncate/create/create_new in a read-only mount or an ancestor, -24 when the channel already holds 64 open files (server.rs:676-697), -22 for a path over 4096 bytes or with NUL, then the filesystem's errors (-2, -17 for create_new on an existing name, -20, -21, -28, ...). Mounted route: the filesystem's errors. No-filesystem route: `ledger` opens the runtime's ledger file (needs the block handle of a durable boot, else -2; truncate -95; create_new on a non-empty ledger -17); `""` or `.` opens a directory handle unless write, truncate or create_new is asked (-22); every other path -2 | a handle (non-negative) |
| `int64_t __absd_std_fs_close(uint64_t handle)` | closes the handle (storage.rs:638-647). Server route: a file this handle wrote is committed before the reply (server.rs:564-573) | 0; -9 for an unknown handle (server and mounted routes); the no-filesystem route always answers 0 |
| `ptrdiff_t __absd_std_fs_read_at(uint64_t handle, uint64_t offset, unsigned char *bytes, size_t length)` | reads at `offset` without any position (storage.rs:649-664) | bytes read, 0 at or past the end; may be short (the server route moves at most 64 KiB per call); -13 on a handle opened without read; -21 on a directory; -9; no-filesystem route: the ledger file reads, any other handle -21 |
| `ptrdiff_t __absd_std_fs_write_at(uint64_t handle, uint64_t offset, const unsigned char *bytes, size_t length)` | writes at `offset`, extending the file when the write ends past it (storage.rs:666-687) | bytes written; may be short (server route: at most 64 KiB per call); -13 on a handle opened without write, an object marked read-only, or (server route) an open in a non-writable mount (server.rs:574-587); -28; -21; no-filesystem route: the ledger file appends only at its current end (-22 elsewhere), any other handle -21 |
| `int64_t __absd_std_fs_set_len(uint64_t handle, uint64_t length)` | sets the file length (storage.rs:689-698) | 0; -13 as for write; -28; no-filesystem route -95 |
| `int64_t __absd_std_fs_sync(uint64_t handle)` | commits (storage.rs:700-713). Server route: the server syncs the whole filesystem (server.rs:598-602). Mounted route: the filesystem's sync. No-filesystem route: flushes the ledger | 0; -9 (server route) for an unknown handle; no-filesystem route -2 when nothing is open |
| `int64_t __absd_std_fs_fstat(uint64_t handle, struct absd_raw_attr *out)` | the object's attributes (storage.rs:721-743). Server route: the first 40 bytes of the server's attribute record; its mtime word is dropped; a kind outside 1..2 is refused, `out` untouched (storage.rs:776-814) | 0; -9; -5 for an object of unknown kind (server route); no-filesystem route: the ledger file and directory handles, any other -9 |
| `int64_t __absd_std_fs_stat(const unsigned char *path, size_t length, struct absd_raw_attr *out)` | attributes by path (storage.rs:745-774) | 0; the route's refusals (-2, -20, ...); -5 for an object of unknown kind (server route, `out` untouched); no-filesystem route: `ledger`, `""` and `.`, any other -2 |
| `int64_t __absd_std_fs_unlink(const unsigned char *path, size_t length)` | removes a file name (storage.rs:835-842) | 0; -2, -21 for a directory, -30, -16 for a mount point (server route); no-filesystem route -95 |
| `int64_t __absd_std_fs_lock(uint64_t handle, uint32_t mode)` | advisory whole-object lock held by the handle: 0 unlock, 1 shared, 2 exclusive; upgrade and downgrade are atomic; never waits (storage.rs:944-955, fs/src/lib.rs:1224-1259) | 0; -11 when another handle's lock conflicts; -22 for another mode (mounted route; the server route answers as the server does); -9; no-filesystem route -95 |
| `int64_t __absd_std_fs_set_readonly(uint64_t handle, uint32_t readonly)` | marks the open object read-only (non-zero) or writable (0) (storage.rs:800-806) | 0; -30 on the server route when the open's mount is not writable (server.rs:603-610); -9; no-filesystem route -95 |
| `int64_t __absd_std_fs_set_readonly_path(const unsigned char *path, size_t length, uint32_t readonly)` | the same, by path (storage.rs:808-815) | 0; the route's path refusals (-2, -30); no-filesystem route -95 |
| `int64_t __absd_std_fs_mkdir(const unsigned char *path, size_t length)` | creates a directory (storage.rs:817-824) | 0; -17, -2 for a missing parent, -30; no-filesystem route -95 |
| `int64_t __absd_std_fs_rmdir(const unsigned char *path, size_t length)` | removes an empty directory (storage.rs:826-833) | 0; -39 not empty, -20, -2, -30, -16 for a mount point (server route); no-filesystem route -95 |
| `int64_t __absd_std_fs_rename(const unsigned char *from, size_t from_length, const unsigned char *to, size_t to_length, uint32_t noreplace)` | renames `from` to `to`; with `noreplace` non-zero an existing `to` is refused, otherwise a file replaces a file (storage.rs:844-857, fs/src/lib.rs:941-) | 0; -17 for an existing target under `noreplace`; -21, -20 for kind mismatches; -22; server route: -22 before sending when `from` exceeds 4096 bytes (fsd.rs:548-551), -30 and -16 from the mount checks; no-filesystem route -95 |
| `ptrdiff_t __absd_std_fs_readdir(const unsigned char *path, size_t length, uint64_t index, unsigned char *name, size_t capacity, struct absd_raw_attr *out)` | entry number `index` (from 0, in name order) of the directory at `path`: copies the entry's name (no NUL) into `name` and its attributes into `out` (storage.rs:882-918) | the name's length (at least 1); **0 past the last entry: the end of the listing**; -22 when the name exceeds `capacity`; the route's path refusals. Server route: the whole listing is fetched at index 0 (or when `path` changes) and later indices are served from that snapshot (`read_dir_entry`, fsd.rs:568-589); mounted route: the directory is read again on every call. Server route: an entry whose kind is outside 1..2 is still listed, with kind 0 (unknown, never a file or a directory; storage.rs:792-797). No-filesystem route -95 |
| `ptrdiff_t __absd_std_fs_canonical(const unsigned char *path, size_t length, unsigned char *out, size_t capacity)` | the normalized absolute path of an existing object (no links, no dot components) copied into `out` without a NUL (storage.rs:920-942, fs/src/lib.rs:810-825) | its length; -2 when the object does not exist; no-filesystem route -95; -22 only when the result is longer than `capacity`, a component is over 255 bytes, the path is empty, holds a NUL or (server route) is over 4096 bytes once resolved against the working directory, or (mounted route, which does not normalize an absolute `path`) has a `.` or `..` component, so through `realpath` (non-empty, NUL-free) every server-route -22 is a buffer, name or path too long and ENAMETOOLONG is exact, while the mounted route's dot case is not (fsd `canonical_refuses_invalid_only_for_long_names_and_long_paths`, fs `canonical_invalid_is_a_long_component_or_a_dot_component`) |

**Processes and handles** (`runtime/src/process.rs`, `runtime/src/broker.rs`)

A child is named by a token: an image child (started from a file) is
`IMAGE_CHILD` (bit 63) or-ed with its process handle; a brokered child is
its slot number (below bit 63). Outcome values use the broker's encoding:
the exit status; a fault `-1000 - vector`; killed -1 (process.rs:433-442).

| prototype | meaning and arguments | result and refusals |
|---|---|---|
| `uint64_t __absd_std_process_brokered(void)` | whether children go through init's broker (a brokered worker) rather than being started from files (process.rs:130-134) | 1 or 0 |
| `int64_t __absd_std_process_spawn_image(const struct absd_raw_spawn *request, uint64_t (*out)[5])` | starts the file at `request->path` as a child with its own startup record. `struct absd_raw_spawn` is laid out by `RawSpawn` (process.rs:68-82, opaque in `runtime.h`): path and length, `args` (`[pointer, length]` pairs, after argv[0]) and count, `env` (`KEY=VALUE` pairs, the child's whole environment) and count, `cwd` and length (empty: ours), `stdio[3]` (0 null, 1 pipe, 2 inherit, 3 our stdout, 4 our stderr, 5 a handle we pass), `handles[3]` (the pipe end for each mode-5 stream). The child gets this process's file-server channel or a derived one per the runtime's policy (fsd.rs:396-) | 0 with `*out` = `[IMAGE_CHILD \| process handle, pid, stdin writer, stdout reader, stderr reader]` (an end not piped is 0; the three ends belong to the caller) (process.rs:224-239). Refusals (process.rs:242-432): -2002 empty path, NUL, an unknown stdio mode or mode 5 with handle 0; -2010 a path without `/` (no search path); -2011 an environment entry without `=` or with an empty key; -2014 cwd not a directory, -2 cwd missing, -5 cwd of unknown kind (server route); -2012 not a regular file (a directory), -5 an image of unknown kind (server route); -2013 image over 32 MiB; -2003 record too large or too many arguments; the image read's refusals (route as for files); the kernel's `spawn_image`, `pipe_create` and `duplicate` refusals (-1 no spawn right, -24, -11 no process slot, -75, -8 not an executable image, -12, -14, -22); the file server's refusal to derive a channel. If the record cannot be delivered the child is killed and reaped and the write or info refusal returned |
| `int64_t __absd_std_process_kill(uint64_t token)` | ends an image child at once (process.rs:462-470) | 0; -2000 for a token without `IMAGE_CHILD` (brokered children cannot be killed here); the kernel's kill refusals (-9, -1 without the kill right) |
| `int64_t __absd_std_process_spawn(const unsigned char *path, size_t path_length, const size_t (*args)[2], size_t argc, uint64_t (*out)[5])` | asks init's broker to start `path` with `argc` `[pointer, length]` arguments, in the next unspent slot (broker.rs:112-160) | 0 with `*out` = `[slot, pid, stdin writer, stdout reader, stderr reader]`, the ends owned by the caller. Refusals: -2000 no broker; -2005 the broker channel is poisoned (protocol error); -2001 no unspent slot; -2002 invalid request; -2003 too large; `-2100 - code` when init refuses (code 1 not permitted, 2 slot unavailable, 3 malformed, 4 no resources); -2006 init closed the reply channel; the kernel's write and read refusals |
| `int64_t __absd_std_process_wait(uint64_t slot, uint64_t nonblocking, int64_t *value)` | waits for a child named by its token (image child) or slot (brokered); `nonblocking` non-zero waits about one tick at most (broker.rs:165-189, process.rs:444-460) | 1 with `*value` set to the outcome (an image child is then reaped and its handle closed by the kernel); 0 when `nonblocking` and it has not ended; -10 no such child, -9, -2000 no broker for a slot, -2005, -22 (a slot with no pending child), the kernel's wait refusals |
| `ptrdiff_t __absd_std_handle_read(uint64_t handle, unsigned char *bytes, size_t length, uint64_t timeout)` | one read of at most 256 bytes from a kernel handle (a pipe end); `timeout` in ticks, 0 for none (broker.rs:68-75, 191-205) | bytes read; 0 for `length` 0 or end of file; -110 when the timeout passes first; kernel -9, -14, -1 |
| `ptrdiff_t __absd_std_handle_write(uint64_t handle, const unsigned char *bytes, size_t length)` | one write of at most 256 bytes to a kernel handle (broker.rs:207-214) | bytes written; 0 for `length` 0; -32 no reader (no signal); kernel -9, -14, -1 |
| `int64_t __absd_std_handle_close(uint64_t handle)` | closes a kernel handle this process owns (broker.rs:216-219) | 0; -9 |

## Changelog

Error text R13 (c-ecosystem REQUESTS.md, 2026-10-12): the kit defines Picolibc's `_user_strerror` hook (`c/libabs/strerror_hook.c`, referenced from `crt0.c`), so programs that call `strerror` or `perror` pass the host check without widening it; ESTALE has text and unknown numbers read "Unknown error N" (section 5); the POSIX adapter's interim hook (`c/posix/picolibc_hooks.c`) is withdrawn; the host check admits Picolibc's weak `stdout` beside `stdin`, a named allowance grounded in `bufio.c:162-163, 191-193` (section 8), so stdio programs that never name stdout (perror-only, files-only) pass; `arc4random`'s weak hooks stay refused and open (section 11).

Allocator R16 (c-ecosystem REQUESTS.md, SPEC A23, 2026-10-12): a request for pages of its own that finds no room in the window unmaps one free, page-aligned pooled run of at most 64 pages and is retried once; held blocks are never moved or unmapped (section 3); the 32 MiB window, the limits (section 2) and the exhaustion clause are unchanged.

R12 `clock()` scaled to CLOCKS_PER_SEC (section 7); R13 constructors and atexit handlers run (sections 1, 8); R15 session mounts and cwd-relative scratch (section 6); R16 (earlier kit request list, not the allocator R16 above) no contract change (gap closure); final fix wave (2026-10-11): `raise` refuses every signal but SIGABRT (sections 1, 10), `absd_fd_lock` refuses modes above 2 itself (section 4), impossible sizes and alignments stated (section 3), Picolibc built in-tree with its archive hash pinned (section 8; the cross file gains `-fdebug-compilation-dir=.`, no code change).

R11 and N1 (2026-10-11, SPEC A11/A13): attribute kinds other than 1 and 2 are refused with EIO by `fstat` and `absd_stat_from_attr` (section 4), held by `scripts/check-fs-kinds.py` and the `fs` test `object_kinds_are_exactly_file_and_dir` (section 6); `st_blksize` is 65536 (`MAX_IO`) and directories have no search bits, stated (section 4); `P_tmpdir` corrected to `""`, names relative to the working directory (section 6); `access(dir, W_OK)` is the POSIX lane's refusal under A11, not a creation probe (section 10).

Records correction (2026-10-12; R19, N9 and the integration steward's POSIX boundary assessment; records correction; no behaviour change):
- (a) preamble: the standing principle that POSIX compatibility is a service ABSD offers to programs, not an obligation ABSD assumes internally; records correction; no behaviour change.
- (b) section 4, `allocation`: no `dup2` exists (CPA-036), a closed 0, 1 or 2 stays closed; records correction; no behaviour change.
- (c) section 4, `table full`: the EMFILE close is cited at `fd.c:116-120` (was `fd.c:106-109`); records correction; no behaviour change.
- (d) section 4, `file with O_APPEND`: separate positions per descriptor, cross-process append atomicity not provided; records correction; no behaviour change.
- (e) section 4, `inherited handle`: recorded `O_RDWR` (`fd.c:64-66`), rights decided by the runtime, the table never widens authority; records correction; no behaviour change.
- (f) section 8, `Compilers`: link sets differ by driver (absd-cc without the adapter; tcc's GROUP with it); records correction; no behaviour change.
- (g) sections 1, 8 and 10: cross-references CPA-062 (TLS) and CPA-063 (static ET_EXEC only); records correction; no behaviour change.

Kernel ABI facts (consistency lane, 2026-10-12; `docs/consistency-20261012/RECORD.md`; no contract change): the values section 2 takes "from the kernel" are now compared with kernel source on every `scripts/check-all.sh` run, both profiles, right after the ABI-generation check. `python3 -I scripts/check-abi-elf.py --kernel KERNEL_DIR [--root PLATFORM_DIR]` reads `MAX_LOAD_SEGMENTS` (`src/elf.rs`), `USER_IMAGE_MIN`/`USER_IMAGE_MAX` and `USER_HEAP_PAGES` (`abi/src/layout.rs`), `MAX_SPAWN_IMAGE_BYTES` and `MAX_MAP_PAGES` (`abi/src/syscall.rs`) by anchored patterns at their definitions and enforcing sites, and compares each with these copies: the `heap window` and `image` rows of section 2, `check-abi-elf.py`'s own constants, `check-c-elf.py`'s window and segment cap, the link scripts (`c/absd-c.ld`, `user-linker.ld`, also read through `ssh/user-linker.ld` and `integration/user-linker.ld`, which are symlinks to it today) and the runtime (`process.rs` `MAX_IMAGE`, `allocator.rs` `MAX_MAP_PAGES`, `MAX_GROW_PAGES`). It prints one `ABI FACT <name> kernel=<v> <file:line>=<v> OK|MISMATCH|NARROWER|UNKNOWN` line per comparison, one `ABI FACTS NOT_CHECKED` line naming what it does not cover, and `ABI FACTS OK checked=N narrower=M` (exit 0), `ABI FACTS MISMATCH ...` (exit 1) or `ABI FACTS UNKNOWN ...` (exit 2: an anchor that does not match exactly one line; never OK). A copy that may be stricter than the kernel (the kit's two-PT_LOAD link form against the loader's eight) is NARROWER, named and not a failure. The check reports disagreement; it rewrites nothing and does not decide which side is right. Restatements elsewhere (section 3 prose, CPA-060, `SSH-HEAP.md`, the c-ecosystem SPEC, `build-tcc.sh`'s `-Ttext`, the exec probe's boundary) are named NOT_CHECKED. Passing it says these 27 comparisons (23 distinct, over 7 files) agree, nothing more.
