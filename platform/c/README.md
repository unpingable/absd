# The ABSD C application kit

A C program built with this kit is a static x86-64 ELF that runs on ABSD
over the native runtime, with Picolibc as its C library. What a program
may rely on, and what it is refused, is the contract
[`../docs/C-INTERFACE.md`](../docs/C-INTERFACE.md); this file says how to
build, use and test the kit. The lane record (inventory, acceptance,
limitations, receipts) is
[`../docs/c-ecosystem-20261010/c-kit/README.md`](../docs/c-ecosystem-20261010/c-kit/README.md).

## Layout

| path | what |
|---|---|
| `absd-c/` | the runtime (`runtime/`, feature `c-entry`) as a staticlib, `libabsd_c.a` |
| `libabs/` | the kit's C objects: `crt0.c` (entry, stack pre-touch), `malloc.c` (allocation adapter), `fd.c` (descriptor table and the five calls, plus `fsync`, `ftruncate`, `fstat`, `unlink`), `errno_map.c`, `clock.c` (clocks, sleeps, `getentropy`, the fixed answers and refusals that replace Picolibc's libos fallbacks), `locale.c` (`setlocale` refusing every locale but C, R14), `strerror_hook.c` (Picolibc's `_user_strerror` hook, R13) |
| `include/absd/` | `runtime.h` (every `__absd_std_*` hook, checked against the Rust source by `scripts/check-c-headers.py`), `kit.h` (kit extensions), `syscall.h` |
| `absd-c.ld` | the link form: ET_EXEC at the image window, two PT_LOAD segments, init/fini arrays as Picolibc walks them |
| `bin/absd-cc` | the compiler and linker driver |
| `picolibc/` | `PIN` (meson, ninja, Picolibc 1.8.12 with sha256, and the installed `libc.a`/`libm.a` hashes), `cross-absd.txt`, `options.txt`; built by `scripts/build-picolibc.sh` |
| `vectors/startup/` | startup-record vectors emitted by the broker's tests |
| `tests/host/` | host unit tests against a mock of the runtime hooks |
| `tests/kit/` | kit test programs, `cases.tsv`, `divergences.txt`, pinned ABSD outputs |
| `tests/stage0/` | the Stage 0 link-form probe |

## Build

```sh
ABSD_PROFILE=core sh scripts/build-c-kit.sh
```

On a fresh clone, run `scripts/fetch-crates.sh` once first (every build is
`--offline`; the top-level README's "Building from a fresh clone"), and set
`ABSD_PROFILE=core`: when the standard library is not staged yet the kit
build stages it, and that check asks for the Pulse, AG, Nightshift and NQ
sources in the default `full` profile of a Git clone.

The kit is built outside the tree, in `ckit-build/kit` in the directory
that holds this clone (`ABSD_CKIT_BUILD` names another directory; the kit
is then `$ABSD_CKIT_BUILD/kit`): `lib/libabs.a` (kit C
objects and the Rust runtime), `lib/libabs_builtins.a` (the Rust
`compiler_builtins` member, split out so it links after Picolibc),
`lib/crt0.o`, Picolibc's `lib/libc.a` and `lib/libm.a`, the headers,
`bin/absd-cc` and `BUILT-FROM` (the source commit, whether the tree had
changes, its path, the toolchain versions and the archives' hashes;
`scripts/run-c-kit.sh` refuses a kit whose stamp names another commit or
whose archives differ from it). Picolibc is built once,
before the kit, by

```sh
sh scripts/build-picolibc.sh
```

Ninja runs with four jobs by default. Set `ABSD_PICOLIBC_JOBS=1`, `2`,
`3` or `4` to select a smaller admitted build envelope; empty, zero and
other values are refused before downloads or staging. This bounds only
this build's Ninja jobs, not aggregate host work; host resource admission
still applies independently of `CARGO_BUILD_JOBS`.

The script bootstraps a Python venv (`venv/` beside the repository; it needs
network once, for the wheels and the tarball) from the
pinned meson and ninja wheels, downloads and checks the pinned tarball,
configures with `picolibc/cross-absd.txt` and `picolibc/options.txt`,
asserts the eight options the contract depends on, and installs into
`picolibc/install` beside the repository (`ABSD_PICOLIBC_PREFIX` builds
elsewhere). The kit build does not rebuild it, and refuses a `libc.a` or
`libm.a` whose sha256 is not the `picolibc-libc.a`/`picolibc-libm.a` line of
`picolibc/PIN`; the archives hash the same under any prefix. The kit's
`lib/libc.a` and `lib/libm.a` are debug-stripped copies of the pinned
archives (`llvm-strip-18 --strip-debug`; the DWARF named the host's clang
include directory), and the kit build prints both hashes. Builds are
reproducible across checkout paths, at the toolchain the kit's `BUILT-FROM`
stamp records and the pinned Picolibc: the runtime archive's source paths are
remapped to `/absd` and its crates' Cargo metadata is hashed from paths
relative to `c/absd-c` (`c/absd-c/Cargo.toml`, `scripts/build-c-kit.sh`).

## Use

```sh
ckit-build/kit/bin/absd-cc -o hello hello.c
python3 -I scripts/check-c-elf.py hello --map hello.map
```

`absd-cc` compiles with host clang under the kit flags (`-mcmodel=large`,
no PIC, no stack protector, no AVX, `-ffreestanding`, stack-clash probes,
`-U_FORTIFY_SOURCE`) and links with ld.lld-17 in the order
`crt0.o`, objects, then `libabs.a libc.a libm.a libabs_builtins.a`
and clang's builtins archive in one group. It writes the link map to
`OUT.map`. It refuses options that would change the code model, PIC, the
stack protector or the link form (`-Wl,`, `-fpic`, `-mcmodel=`, `-march=`
and similar). Accepted: `-c`, `-o`, `-O0..3`, `-I`, `-D`, `-U`, `-W`, `-f`,
`-g`, `-std=`; `.c`, `.s` and `.S` inputs. Every image should pass
`check-c-elf.py --map` before it is booted; the gate does this for every
kit program.

`strerror` and `perror` work: Picolibc's `strerror` calls a weak hook,
`_user_strerror`, for numbers its table has no text for, and the kit defines
it (`libabs/strerror_hook.c`, pulled by `crt0.o`; R13). Its texts are
Picolibc's and differ from glibc's for several codes, so compare `errno`
(by name, as `tests/kit/errname.h` does), not the text. A program whose
stdio never names `stdout` (only `perror` or `fprintf(stderr, ...)`, or
only files) is accepted too: the ELF check admits Picolibc's guarded weak
`stdout` beside `stdin`, and no other weak-undefined name
(docs/C-INTERFACE.md sections 8 and 11).

## Test

```sh
sh scripts/check-c-kit-host.sh                     # host tests: test_malloc, test_fd, test_errno, test_setlocale, test_strerror
ABSD_KERNEL_RUN=<disposable kernel clone> sh scripts/run-c-kit.sh
```

`run-c-kit.sh` (also run by `scripts/check-all.sh`) does, in order: two
clean kit builds that must hash identically (skipped with
`ABSD_SKIP_BUILD=1`), the host tests, the header check, the self-checks,
a build and ELF/map check of every program in `tests/kit/cases.tsv`, every
embedded case booted through the kernel's `external-test` and compared
with the Linux build of the same source, the same with gcc when
`ABSD_C_GCC=1`, then the shell-route matrix (`scripts/c-kit-matrix.py`:
each case as absd-sh's child in an SSH exec session, compared with the
Linux build, with startup vectors and a resource census around each
case). The last line is
`ABSD C KIT OK embedded=<n> shell=<n> shell_defects=<n>`.

A case whose ABSD output differs from Linux by contract is listed in
`tests/kit/divergences.txt` with its class and contract section, its ABSD
output is pinned (`tests/kit/absd-expected/`, `tests/kit/shell-expected/`),
and the run requires the output to match the pin and to differ from Linux.
An ABSD-only observation pinned in `tests/kit/shell-expected/` (the
shell's own `exit status` line) must still equal Linux in stdout and
status, unless it is a fault (`stack overflow`, `exit abort`: Linux reports
a signal), which is judged by the kernel's serial line instead; a pin for a
case that is not in `cases.tsv` fails the matrix. `abort()` is covered by
the `exit abort` case (status 134, `USER EXIT ... status=134`).
A difference the contract does not explain goes in
`tests/kit/shell-expected/DEFECTS` and fails the matrix.

## Contract

`docs/C-INTERFACE.md` is the contract: process entry (constructors, `main`,
`atexit`, destructors, exit statuses), limits, memory, descriptors and the
five calls, the errno table, authority, clocks, toolchain and link form,
the formats that cross the language line, what is not provided, Stage 1
limitations, and every runtime hook. A kit change that changes what a
program observes changes the contract in the same commit.

## Pins

- Picolibc 1.8.12, tarball sha256
  `64e8c412e1c40fa6eb1a72d2b5cdbcbfe6ceca4cbea454edbad54557ffc747fa`
  (`picolibc/PIN`), built with meson 1.9.1 and ninja 1.13.0 from the
  venv, cross file `picolibc/cross-absd.txt`, options
  `picolibc/options.txt`, by `scripts/build-picolibc.sh`; installed
  `libc.a` sha256
  `7924073af8c975a4d623917070cbe098276632f0e332accfd82e11cdb7975f20`
  (`picolibc/PIN`, any build prefix). The full configuration is the meson
  introspection in
  `docs/c-ecosystem-20261010/c-kit/receipts/picolibc-buildoptions.json`
  (Stage 0's, before `-fdebug-compilation-dir=.`, is in `receipts/stage0/`).
- Host toolchain: clang 18.1.3, gcc 13.3.0, ld.lld-17, Rust 1.95.0.
- Kernel for the gate's boots: the commit `kernel_commit=` in
  `scripts/check-all.sh` names (5a29fba at this writing).

**Picolibc options change only with a contract amendment.** The options
decide TLS, errno, locking, the allocator, stdio and the C library's
system interface, which are the contract's subject. A change to
`picolibc/options.txt`, `picolibc/cross-absd.txt` or the Picolibc pin is
made together with the amendment to `docs/C-INTERFACE.md` (and to the
campaign spec where it names the option), and the kit is requalified with
`run-c-kit.sh`.
