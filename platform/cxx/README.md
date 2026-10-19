# C++0: the bounded C++ runtime for ABSD

C++0 lets a C++ program be built for ABSD with the C kit
([`../c/README.md`](../c/README.md), contract
[`../docs/C-INTERFACE.md`](../docs/C-INTERFACE.md)): libc++ and libc++abi
from LLVM 18.1.8, built static for `x86_64-unknown-none-elf` against the
kit's Picolibc headers under the kit's own flags, and a driver,
`absd-c++`, that compiles C++ and links like `absd-cc`. It is task T1 of
the native-Clang campaign (owner direction 2026-10-12): the runtime that
a native Clang will later need, and useful on its own. It adds nothing to
the kernel, the runtime, the kit or the POSIX adapter, and nothing to the
process model: one task, no TLS, no mmap, static ET_EXEC only.

## What it provides

| facility | how |
|---|---|
| classes, virtual calls, templates, lambdas | the compiler; vtables need nothing from the runtime (`-fno-rtti`) |
| global constructors and destructors | constructors from `.init_array` (sorted, walked by Picolibc as for C); destructors registered with Picolibc's `__cxa_atexit` against its `__dso_handle` and run by `exit` (after `main` returns), in reverse order |
| function-local statics | libc++abi's no-threads `__cxa_guard_acquire/release` (a byte flag; `LIBCXXABI_ENABLE_THREADS=OFF`) |
| `operator new`/`delete`, `new[]`, aligned and nothrow forms | libc++abi's definitions (weak, so a program may replace them) over the kit's `malloc`/`free`/`aligned_alloc` (C-INTERFACE.md section 3). Exhaustion has no `bad_alloc` to throw: the throwing forms call `abort` **silently**, status 134 with no message (libc++abi's `abort_message` prints only without `NDEBUG` or without `LIBCXXABI_BAREMETAL`; this build has both, and `abort_message.cpp.obj` imports only `abort`); the `nothrow` forms return null. A program that replaces `operator new(size_t)` must replace its `nothrow` form too: libc++abi's `nothrow` new aborts when it detects the plain form replaced |
| containers, strings, algorithms, smart pointers, `<functional>`, `<optional>`, `<variant>`, `<atomic>`, `<random>` engines, `<chrono>` `system_clock`, `<format>` (C++20) | libc++, header code plus `libc++.a` |
| output | `<cstdio>` (`printf`, `fprintf`, `FILE *`) from Picolibc |

## What it refuses

Each is a configuration choice of the build (`scripts/build-cxx-runtime.sh`)
or a fixed flag of the driver, checked in the generated `__config_site`:

| facility | at C++0 |
|---|---|
| exceptions | none. Everything is built `-fno-exceptions`; the kit's linker script discards `.eh_frame` and `.gcc_except_table` and there is no unwinder. `absd-c++` refuses `-fexceptions`/`-fcxx-exceptions`. A libc++ precondition failure that would throw (`std::vector::at` out of range, `std::stoi` on bad input, `length_error`) prints libc++'s text on stderr (`__libcpp_verbose_abort`) and aborts, status 134. A libc++abi failure (allocation exhaustion in throwing `operator new`, a pure or deleted virtual call, recursive initialisation of a function-local static, a bad array-new length) aborts **silently**, status 134, no message (`NDEBUG` + `LIBCXXABI_BAREMETAL`; see above). A message there would be a later, declared glue change |
| RTTI | none for programs: `-fno-rtti`, so `typeid` and `dynamic_cast` do not compile (`-frtti` refused). libc++abi itself is built with RTTI (it implements `type_info` and refuses to compile without it); a `-fno-rtti` program pulls none of it |
| threads | none (`_LIBCPP_HAS_NO_THREADS`): no `<thread>`, `std::mutex`, `std::condition_variable`, `std::shared_mutex`; `std::call_once` works single-task. `-pthread` and `-fthreadsafe-statics` are refused |
| localization, iostreams | none (`_LIBCPP_HAS_NO_LOCALIZATION`): no `<iostream>`, `<fstream>`, `<sstream>`, `<locale>`; use `<cstdio>` |
| wide characters | none (`_LIBCPP_HAS_NO_WIDE_CHARACTERS`) |
| `std::filesystem` | not built (`_LIBCPP_HAS_NO_FILESYSTEM`); header-only parts of `path` may compile, nothing that reaches the library links |
| `std::random_device` | not built (`_LIBCPP_HAS_NO_RANDOM_DEVICE`); the engines work |
| `steady_clock` | not provided (`_LIBCPP_HAS_NO_MONOTONIC_CLOCK`); `system_clock` reads the kit's `clock_gettime` |
| time-zone database | not built |
| shared libraries, PIC | static archives only; the kit fixes the code model and link form as for C |

## Stubs and workarounds

None for C++0: no file C++0 uses replaces or patches anything in libc++,
libc++abi, Picolibc, the kit or the runtime, and no lock is stubbed. With
threads off, libc++abi's guard is its own no-threads implementation and
libc++ declares no mutex, so the no-op single-task lock considered in the
scout was not needed for C++0. LLVM itself, which holds mutexes regardless
of `LLVM_ENABLE_THREADS`, uses a second build of the runtime with libc++'s
external thread API and declared patches: "The C++ runtime, LLVM profile",
below.

Three deviations from upstream defaults or the C kit, all in the build
script or the driver and each stated where it is made:

- **C++ is compiled hosted.** The C kit compiles `-ffreestanding`. Under
  `-ffreestanding` clang gives C++ no special `main` (it is mangled
  `_Z4mainv`, and crt0's reference to `main` is unresolved), and libc++ is
  a hosted library. C++ translation units (libc++, libc++abi and the
  program) take `-fno-builtin` in place of `-ffreestanding`, which keeps
  what freestanding meant for code generation; every other flag is the
  kit's, read from its `bin/absd-cc`. C sources given to `absd-c++` keep
  the kit's flags unchanged. Built both ways, `libc++.a` and `libc++abi.a`
  were byte-identical.
- **CMake's library probes are answered NO.** With
  `CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY` the probes only compile,
  so libc++ concluded that `librt`, `libpthread` and `libatomic` exist and
  embedded `#pragma comment(lib, "rt")` in `chrono.cpp` (a `.deplibs`
  record ld.lld refuses: "unable to find library ... rt"). The build sets
  `LIBCXX_HAS_{PTHREAD,RT,ATOMIC}_LIB=NO` and
  `LIBCXXABI_HAS_{PTHREAD,DL}_LIB=NO`,
  `LIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL=NO`, and refuses an archive with a
  `.deplibs` section.
- **`__lcxx_override`.** libc++abi places the replaceable `operator new`
  forms in a section of that name and compares function addresses with
  `__start___lcxx_override`/`__stop___lcxx_override` to tell whether a
  program replaced them (its `nothrow` forms depend on it). The kit's
  linker script (`c/absd-c.ld`) has no rule for it; ld.lld places the
  orphan section after `.text` in the R+X segment and defines both bounds.
  The gate accepts the result; a later revision of the linker script could
  name it explicitly (c/ is not this lane's to change).

## Build

```sh
sh scripts/stage-llvm.sh          # once: download (sha256 checked first), extract read-only
ABSD_CKIT=<kit> sh scripts/build-cxx-runtime.sh
sh cxx/tests/check-cxx0.sh
```

`stage-llvm.sh` downloads the tarball named in `PIN` into
`upstream/llvm-project/dl/` beside the repository (only if absent, into an
empty directory, verified before it is kept), extracts it into
`upstream/llvm-project/src/`, makes the tree read-only, and checks
`LICENSE.TXT` against `cxx/llvm-project.LICENSE` and the version in
`llvm/CMakeLists.txt` against the pin. It prints `LLVM STAGE OK ...`.

`build-cxx-runtime.sh` configures `runtimes/` with
`cxx/absd-toolchain.cmake` (clang-18, `llvm-ar-18`, no link during
configuration), builds and installs into `cxx-build/` beside the
repository (`ABSD_CXX_BUILD` names another directory): `lib/libc++.a`,
`lib/libc++abi.a`, `include/c++/v1/`, `bin/absd-c++` (a copy of
`cxx/bin/absd-c++`), `BUILT-FROM` (source commit, pin, toolchain, the kit
and its archive hashes, flags, build time, archive hashes) and
`cmake-cache.txt`. The kit is `ABSD_CKIT` (default `ckit-build/kit` beside
the repository; `scripts/build-c-kit.sh`). Every step runs under
`nice -n 19` with at most 4 jobs and waits while the 1-minute load exceeds
8 (`ABSD_CXX_JOBS`, `ABSD_CXX_MAX_LOAD`). Source and build paths are
remapped (`-ffile-prefix-map`), so the archives do not depend on where
either lives. It prints `CXX RUNTIME OK libc++.a=<bytes> libc++abi.a=<bytes> ...`.

## Use

```sh
cxx-build/bin/absd-c++ -O2 -o prog prog.cpp
python3 -I scripts/check-c-elf.py prog --map prog.map
```

`absd-c++ [-c] [-o OUT] [-O..] [-I dir] [-D...] [-std=...] FILE...` takes
`.cpp`, `.cc`, `.cxx`, `.C` (C++), `.c`, `.s`, `.S`, objects and
archives; it passes `-I`, `-D`, `-U`, `-W`, `-f`, `-g` and `-std=` through
(default `-O2`, clang's default `-std=gnu++17`) and refuses what `absd-cc`
refuses plus `-ffreestanding` (it would mangle `main`, above), `-fexceptions`, `-fcxx-exceptions`, `-frtti`, `-pthread`,
`-fthreadsafe-statics`, `-stdlib=` and `-nostdinc++`. It links
`ld.lld-17 -static -no-pie --gc-sections -T <kit>/absd-c.ld -Map=OUT.map`
with `crt0.o`, the objects, `libc++.a`, `libc++abi.a`, then the kit's group
(`libabs.a libc.a libm.a libabs_builtins.a` and clang's builtins), and
writes `OUT.toolchain`. It refuses a kit whose `libc.a` is not the one the
runtime was built against (`BUILT-FROM`). `ABSD_CC_VERBOSE=1` prints the
commands.

## The C++0 probe

`tests/cxx0.cpp` exercises the exit criterion of the scout (section 5):
classes with virtual calls through `std::unique_ptr`, a final class,
templates (a class template, a member template, a function template),
lambdas, a global object whose constructor and destructor print (static
initialisation, then `__cxa_atexit` at exit), a function-local static,
`new[]`/`delete[]`, aligned `new` and `new[]` (64-byte alignment checked),
`nothrow` new of 100,000 bytes, a class counted across 50 `new`/`delete`,
`std::vector`, `std::sort`/`std::unique`, `std::string` (including a
5,000-byte one, which takes pages of its own), `std::to_string`,
`std::map`, `std::shared_ptr`; output by `printf` only, none of it
dependent on the library's growth policy or layout. `tests/cxx0.expected`
is the output of the Linux builds (g++ 13.3 and clang++ 18 with
libstdc++, `-O2 -fno-exceptions -fno-rtti`), which agree byte for byte.

`tests/check-cxx0.sh` builds the probe twice in different directories with
`absd-c++ -Oz` (the ELFs must be identical), gates it with
`check-c-elf.py --map`, requires its only undefined symbol to be
Picolibc's weak `stdin`, rebuilds and reruns both Linux references against
`cxx0.expected`, and leaves the ELF at `cxx-build/tests/cxx0` with its map
and toolchain record. It prints the gate line and
`CXX0 HOST OK bytes=... text=... data=... bss=... loads=2 sha256=...`.

## The guest run (steward)

Performed 2026-10-13 against kernel 5a29fba: passed. The output was
byte-equal to `tests/cxx0.expected` and the `EXTERNAL status=0` line was
present. See `docs/native-clang-20261012/GUEST-RESULT.md`, "The C++0 probe".

The probe has no input and no arguments and writes only to stdout, so it
runs on the C kit's embedded route exactly as `scripts/run-c-kit.sh` runs
a kit case:

```sh
: > /tmp/cxx0.input
make -C <disposable kernel clone> external-test \
    QEMU="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand" \
    EXTERNAL_USER_ELF=<camp>/cxx-build/tests/cxx0 \
    EXTERNAL_INPUT=/tmp/cxx0.input \
    EXTERNAL_EXPECTED=<repo>/cxx/tests/cxx0.expected
grep -qx 'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0' <kernel>/build/external.serial.log
```

Pass: the program's output is byte-equal to `tests/cxx0.expected`, these
23 lines, the last printed by the global destructor after `main` returns,

```
global ctor value=41
C++0 probe start global=41
shape rect area=12
shape square area=25
shape shape area=21
shapes=3 total=58
ring count=4 sum=180 max=60
vector unique=1000 front=0 back=1008 squares=339589992
string absd-0-1-4-9-16 len=15 find=12 big=5001 sum=592600395265380198
word apple=1
word fig=2
word pear=3
new[] sum=32640
aligned new align64=1 byte=171
aligned new[] align64=1
nothrow new ok=1
counted live=50
counted live=0 made=50
local static init
local static value=9 events=2
shared use=2 second=three
C++0 probe end
global dtor value=41 events=2
```

and the serial log carries `EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0`.
The ELF booted must be the one whose sha256 `check-cxx0.sh` printed.

## The C++ runtime, LLVM profile

A second build of the same libc++ and libc++abi, made for LLVM, Clang and
LLD (`ABSD_CXX_PROFILE=llvm sh scripts/build-cxx-runtime.sh`, normally run
by `scripts/build-llvm-kit.sh`, output `llvm-build/cxx` beside the
repository). It exists because LLVM holds `std::mutex`, `std::call_once`
and `std::recursive_mutex` whatever `LLVM_ENABLE_THREADS` says, and uses
`std::wstring` and `std::stringstream`. **It is not the C++0 contract**:
everything in the sections above describes C++0 (`cxx-build`), whose
archives this profile leaves byte for byte unchanged. A program can be
built against it with that build's `bin/absd-c++` plus `-D_GNU_SOURCE`
(its `<locale>` calls Picolibc's `*_l` functions, which Picolibc declares
only under `_GNU_SOURCE`; LLVM is compiled with it).

| facility | C++0 | LLVM profile |
|---|---|---|
| `std::mutex`, `recursive_mutex`, `call_once`, `condition_variable`, `<thread>` | not declared (`_LIBCPP_HAS_NO_THREADS`) | declared, over libc++'s external thread API answered by `glue/libcxx/__external_threading` (below) |
| `steady_clock` | not provided | the kit's `times()` tick count as milliseconds (boot ticks, ~0.99985 ms each; patch 0001) |
| localization, iostreams, `<sstream>`, `<locale>`, `<regex>` | none | on, over Picolibc's C-locale functions (only the C locale's names; setlocale is the kit's, R14) |
| wide characters | none | on (Picolibc's wide-character functions) |
| `std::filesystem`, `std::random_device`, exceptions, RTTI for programs | off | off, as C++0 |
| libc++abi | no-threads guard | the same build options (no-threads guard) |

**The external thread API, one task per process.** Every primitive is the
one task's bookkeeping; nothing creates a task, executes a lock
instruction or calls the kernel:

| primitive | behaviour |
|---|---|
| mutex | a flag. Lock of a free mutex takes it; try-lock of a held one answers false |
| recursive mutex | a count (overflow: EAGAIN) |
| condition variable | signal and broadcast wake nobody |
| once | runs the routine once |
| thread | create refused (EAGAIN, so `std::thread` aborts); join and detach of the null thread EINVAL; one thread id |
| thread-local keys | a table of 64 plain slots (no TLS); destructors are not run at exit, as for a main thread |
| sleep | the kit's `nanosleep` |

**Abort on every would-wait path.** Locking a mutex the task already
holds, any condition-variable wait (timed or not), and a once-routine
re-entered from itself could only be ended by another task, and there is
none. Each **aborts** with `libc++ (ABSD, one task per process): <what>
would wait for another task, and none exists; aborting` on stderr
(libc++'s verbose abort, status 134). None returns an error: libc++'s
own callers do not all check (`call_once.cpp` waits in a loop, so a
`std::call_once` re-entered on its own flag would spin; `memory.cpp`'s
shared_ptr lock pool and `random_shuffle.cpp`'s generator proceed as if
locked). Upstream these are deadlocks; here they stop. Not covered:
`std::atomic<T>::wait` on a value nothing changes is libc++'s timed
backoff polling (`atomic.cpp`), never a call into the glue.

The probes in `tests/llvm-profile/` (`check-llvm-profile.sh` builds and
gates them; the guest run is the steward's, the host cannot run ABSD
programs and the Linux twin links libstdc++): `ok` (mutexes, try-lock,
recursive mutex, nested `call_once` on different flags, shared_ptr atomic
access, `random_shuffle`, `steady_clock`; status 0, `ok.expected`), and
`relock`, `call_once_reentry`, `condvar_wait`, `sp_mut_nested`,
`rs_nested`, each status 134 after its first stdout line, with the abort
message on stderr.

Archives at 0e5fb12e (`llvm-build/cxx/BUILT-FROM`, dirty no): `libc++.a`
1,652,102 B sha256 907b4109…6dc2, `libc++abi.a` 438,298 B sha256
81796368…697e.

**Patches** (to the build copy only): 0001 (`chrono.cpp`, steady_clock over
`times()`) and 0002 (`regex.cpp`, Picolibc's signed `char` ctype mask: the
class table did not compile, and widened directly `[[:blank:]]` and
`[[:print:]]` would have matched `_` as a word character).

## LLVM on the kit

Task T2 of the native-Clang campaign: LLVM, Clang and LLD 18.1.8 (the pin
above) built as static ABSD programs for `x86_64-unknown-none-elf`
against the C kit, in the kit's single-task profile: one task, no TLS, no
mmap, no signals, no program execution, static ET_EXEC. Built on the host. In
the guest run of 2026-10-13, lld, cc1-fe-o0 and llc started on ABSD and
compiled, linked and ran `hello.c` at -O0. The single-process clang-18
was not run: it is over the spawn cap (D-19). See
`docs/native-clang-20261012/GUEST-RESULT.md`.

Nothing in the kernel, the runtime, the kit, the POSIX adapter, `c/` or
`scripts/check-c-elf.py` changed: every alternative is a CMake setting,
a declared patch to a build copy of LLVM, or a file under `cxx/glue/`.

```sh
ABSD_CKIT=<kit> sh scripts/build-llvm-kit.sh     # every step; or name steps:
#   source cxx posix tblgen configure support clang lld gate alternatives twin
```

Output goes to `llvm-build/` beside the repository (`ABSD_LLVM_BUILD`):
`src/` (the staged source copied, `patches/llvm/*.patch` applied, the
`glue/llvm-support/*.inc` OS layer and the generated `PassRegistryO0.def`
added), `cxx/` (the runtime, below), `posix/` (`libabsd-posix.a`, built by
`scripts/build-posix.sh` unchanged), `tblgen/` (host `llvm-tblgen` and
`clang-tblgen` from the pinned source), `kit/` (the ABSD build; images in
`kit/bin`, each with `.map`, `.toolchain`, `.stripped` and `.gate`) and
`twin/` (the Linux twin and its `MEASURE`). Every build runs under
`nice -n 19`, at most 4 jobs (`ABSD_LLVM_JOBS`), waiting while the 1-minute
load exceeds 8 (`ABSD_LLVM_MAX_LOAD`).

**Toolchain.** `absd-llvm-toolchain.cmake` names a CMake platform `ABSD`
(`cmake/Platform/ABSD.cmake`: Unix paths, static only), so LLVM takes its
Unix code paths (`LLVM_ON_UNIX`). Compile flags are the kit's, read from its
`bin/absd-cc` as `build-cxx-runtime.sh` reads them (C++ units with
`-fno-builtin` in place of `-ffreestanding`), plus `-D_GNU_SOURCE` (LLVM is
compiled strict C++17, under which Picolibc hides its POSIX, BSD and GNU
declarations; clang++ predefines `_GNU_SOURCE` for a glibc host) and
`-DLLVM_ABSD_KIT=1`, which selects the port. Every executable, including
CMake's configuration probes, is linked by `bin/absd-llvm-link`: the
`absd-c++` link (ld.lld-17, `absd-c.ld`, crt0, libc++, libc++abi, then the
kit's group headed by the POSIX adapter, as tcc's share `libc.a` has it)
with `--icf=all`, refusing any link option it does not know. So a probe
for a function the kit does not define fails to link and LLVM's
`config.h` records what the kit really offers. (Clang's driver cannot be
the linker for `x86_64-unknown-none-elf`: it hands such links to the host
`g++`.)

**Configuration.** MinSizeRel at `-Oz`; X86 only; projects clang and lld;
default triple `x86_64-unknown-none-elf`; `LLVM_ENABLE_THREADS`, EH, RTTI,
assertions, zlib, zstd, libxml2, terminfo, libedit, libpfm, FFI, curl,
httplib, backtraces, crash overrides, plugins, PIC, unwind tables, assembly
files (BLAKE3 portable), bindings, tests, benchmarks, examples, docs, utils
and the version-control revision all off; `LLVM_BUILD_STATIC`; static
analyzer, ARCMT and clang plugins off; `CLANG_SPAWN_CC1=OFF` (cc1 runs in
the driver's process), `CLANG_DEFAULT_LINKER=lld`. Kit-only:
`CLANG_HAVE_RLIMITS=OFF` (a header probe would answer yes; the kit has no
getrlimit and the stack is a fixed 4 MiB reservation; with threads off,
clang's `runWithSufficientStackSpace` does not check either, so input
deep enough to need more than 4 MiB of stack is a page fault, status
-1000 - 14 to the parent, with no "stack nearly exhausted" diagnostic) and
`HAVE_DECL_ARC4RANDOM=0` (Picolibc's arc4random leaves weak references the
gate refuses). `LLVM_ENABLE_LIBCXX` and `LLVM_STATIC_LINK_CXX_STDLIB` are
not used: the link names the runtime's archives itself.

**The C++ runtime.** LLVM links the LLVM profile of the runtime ("The C++
runtime, LLVM profile", above), not C++0's.

**What LLVM's Support layer needed that the kit does not provide, and what
it became** (`kit/support-audit.txt` is empty: every C symbol LLVMSupport
references is defined by the kit, the adapter, the runtime or LLVM):

| need | alternative |
|---|---|
| `mmap`/`munmap`/`posix_madvise` (mapped files) | read-only and private regions are the file read into a page-aligned heap block; shared (write-through) regions refused; MemoryBuffer never maps; FileOutputBuffer builds in memory and writes on commit (0005) |
| `mmap`/`mprotect` (memory blocks) | page-aligned heap blocks, read+write only; executable or read-only protection refused (`glue/llvm-support/Memory.inc`) |
| `sigaction`, `sigaltstack`, `backtrace`, `dl_iterate_phdr` | no handlers, no stack trace; files registered for removal are removed by the explicit cleanup paths (`Signals.inc`) only, so after an abort (status 134) or a fault, clang's temporary and partial output files stay behind; CrashRecoveryContext installs nothing (0004) |
| `fork`/`execve`/`posix_spawn`/`wait4` | refused with a message; `Wait` reports no child (`Program.inc`); cc1 runs in process |
| `alarm` (watchdog) | does nothing (`Watchdog.inc`) |
| `sigprocmask` around close, `dup2` for closed 0-2 | plain close; nothing to fix up, the kit never hands 0-2 to `open` (0004) |
| `/dev/urandom` seed, `arc4random`, `std::random_device` | the kit's `getentropy` (RDRAND) (0003, 0004, 0008) |
| `getsid` (lock owner alive?) | assumed alive (0004) |
| `statvfs` (`is_local`, `disk_space`) | local for anything stat-able (no remote filesystem); disk space refused (0005) |
| `link`, `umask` | hard links refused; umask is 022, the mask the kit's fixed 0644 implies (0005) |
| `dladdr`, `/proc` (main executable) | argv[0] resolved against the cwd or PATH with the adapter's `realpath` (0005) |
| `uname` (triple OS version) | none; the triple has no OS version (0006) |
| `getrlimit`/`setrlimit` (cc1 stack) | not asked (`CLANG_HAVE_RLIMITS=OFF`) |
| `pread`, `getrusage`, `futimens`, `sysexits.h`, sockets | LLVM's existing fallbacks (lseek+read; zero times; timestamps not set, as the kit has none); `EX_IOERR` 74 (0003); socket streams not built (0003) |
| `thread_local` (lld's allocator) | a plain static with threads off (0008) |
| `std::ifstream` (clang layout files) | `llvm::MemoryBuffer` (0007) |
| `dlopen` (plugins) | not built (`LLVM_ENABLE_PLUGINS=OFF`, no `dlfcn.h`): `DynamicLibrary` reports it unsupported |

Runtime refusals the port relies on rather than hides: `lockFile` (a
blocking `F_SETLKW`) gets the adapter's refusal, `tryLockFile` works through
`F_SETLK`; `GetMallocUsage` is 0 (no mallinfo); `isatty` is 0, so no colour.

**Patches** (`patches/llvm/`, each with failure, change, behaviour
preserved and upstreamability in its header):

| patch | where |
|---|---|
| 0001-libcxx-steady-clock-absd-ticks | libcxx/src/chrono.cpp |
| 0002-libcxx-regex-newlib-mask | libcxx/src/regex.cpp |
| 0003-support-cxx-runtime-profile | Support: `<cctype>` includes, ARMBuildAttrs, ExitCodes.h, LockFileManager seed, raw_os_ostream, raw_socket_stream |
| 0004-support-absd-os-layer | Signals/Program/Memory/Watchdog.cpp select `ABSD/*.inc`; CrashRecoveryContext, Unix/Process.inc, LockFileManager |
| 0005-support-files-without-mmap | Unix/Path.inc, MemoryBuffer.cpp, FileOutputBuffer.cpp |
| 0006-targetparser-host-without-uname | TargetParser/Unix/Host.inc |
| 0007-clang-frontend-files-without-fstream | clang Frontend: CompilerInvocation.cpp, LayoutOverrideSource.cpp |
| 0008-lld-no-tls-without-threads | lld Common/Memory.h, ELF/Writer.cpp |
| 0009-passes-o0-only-option | Passes: PassBuilder.cpp, PassBuilderPipelines.cpp (only with `LLVM_ABSD_O0_ONLY`) |

**Images** (`gate` and `alternatives` steps; all `C ELF OK ... loads=2
map=checked`, the only undefined symbol Picolibc's weak `stdin`; sizes in
bytes; the spawn cap is 33,554,432):

| image | stripped | text | rodata | data+bss | over the cap |
|---|---|---|---|---|---|
| `clang-18` (driver + cc1) | 47,528,448 | 35,172,296 | 12,063,920 | 652,296 | yes, by 13,974,016 |
| `lld` | 26,525,192 | 20,417,192 | 6,076,272 | 417,328 | no |
| `cc1` (no driver) | 46,397,904 | 34,174,232 | 11,933,456 | 652,024 | yes |
| `clang-o0` (-O0 pipeline only) | 44,545,928 | 32,381,128 | 11,872,544 | 582,896 | yes |
| `cc1-fe` (front end, no code generator) | 35,976,184 | 27,895,656 | 7,791,136 | 616,704 | yes, by 2,421,752 |
| `cc1-fe-o0` (front end, -O0 only) | 32,862,592 | 24,977,464 | 7,594,368 | 547,256 | no, 691,840 under |
| `llc` (back end of the split) | 18,146,552 | 12,763,800 | 5,366,864 | 394,544 | no |

So one image set fits the cap today: `cc1-fe-o0` (C to bitcode at -O0) +
`llc` (bitcode to object) + `lld`. Whether the margin is enough is T3's: the
spawner holds the whole image in its own 32 MiB heap
(`runtime/src/process.rs`), and each image's span also spends page tables
(32 per process, 2 MiB each, shared with stack and heap: `clang-18` needs
23, leaving 7 for the heap, 14 MiB of mappings).

**The Linux twin** (`twin` step): the same common options built for
x86_64-linux with host clang 18, libstdc++ and glibc's malloc, without the
kit-only settings (`LLVM_HOST_TRIPLE` is the host's, `CLANG_HAVE_RLIMITS`
is on so cc1 raises its stack with setrlimit, arc4random is glibc's), with `LLVM_ABSD_KIT` defined so that it
reads files into the heap and writes output from memory as the port does,
compiling the kit's `tests/llvm/hello.c` and `tests/llvm/c500.c` (the
scout's inputs) at `-O0` with the kit's flags and headers. Heap peak
(program break growth plus live anonymous mappings, `scripts/llvm-heap-peak.py`):
hello 2,289,664 B, 500 lines 4,980,736 B; lld linking hello 5,931,008 B;
no file was mapped. The -O0-only twin produces byte-identical objects and
refuses -O2; the split pipeline (cc1-fe then llc) produces an object whose
link passes the gate. Figures and the run in `llvm-build/twin/MEASURE`.

## Licences

libc++ and libc++abi are LLVM 18.1.8, Apache-2.0 WITH LLVM-exception
(`llvm-project.LICENSE`, LLVM's `LICENSE.TXT` verbatim, which also
reproduces the legacy NCSA licence LLVM keeps for older contributions). The
source is pinned by sha256 in `PIN`, staged beside the repository, never
vendored. A program linked by `absd-c++` embeds libc++/libc++abi object
code; the LLVM exception lets such embedded portions be redistributed in
object form without the notice conditions of sections 4(a), 4(b) and 4(d).
Distributing the archives or headers themselves carries the licence text.
Everything under `cxx/` other than `llvm-project.LICENSE`, `patches/llvm/`
and `glue/llvm-support/` is first-party, Apache-2.0 (`provenance.toml`).
The patches are LLVM's files with ABSD's changes (their context and
removed lines are LLVM's) and the `glue/llvm-support/*.inc` files keep
LLVM's Unix/ interfaces and some of its code: both are recorded as adapted
from llvm-project 18.1.8 under Apache-2.0 WITH LLVM-exception. The kit's
clang and lld images embed LLVM object code throughout.
