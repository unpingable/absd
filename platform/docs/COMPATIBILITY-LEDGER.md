# Source-compatibility ledger

The original nineteen-program measurement below is historical and retains its
original outcomes. The exact accepted-with-limits platform base investigated by S3 is
`bf8c7583` with kernel `f8184ca`, including twelve refreshed C ports in
`userland/PORTS.tsv`; the original "C programs" section describes its earlier
probe, not today's C kit (see [C interface](C-INTERFACE.md)).

S3 in coordination tranche #24 investigates a separate independently selected
Rust documentation application using the existing native interface:
[pulldown-cmark workflow and fixture](../compat/native-markdown/README.md).
This does not change the original cases, reference output, divergence list or
verdict. Cross-compilation is distinct from native on-target development;
Userland U4's component-closure gate and U5/U6 remain deferred.

## S3 native application result — 2026-10-15

Independently selected `pulldown-cmark` 0.13.4, default `getopts`/`html`
features: **cross-build and native execution PASS for the selected cases**.
No application or dependency Rust source changed. The only application-tree
scaffolding is an ABSD-only runtime dependency and an additive lock preserving
all 23 published upstream package identities. The existing restricted-std
wrapper and patched platform std remain necessary experimental scaffolding.

Two local KVM boots imported/read back eight files, then started twelve native
application images from the filesystem. All twelve cases agreed byte for byte
with the untouched Linux reference and a reference committed before guest
execution: stdout, stderr and status, including status 1 for invalid options
and rejected broken links. Terminal frames/processes/cells/pipes were all zero.
This exercises the in-process read-only filesystem route, not served FSD/SSH.
The empty-stdin case uses event mode (`-e`). Both boots used KVM; TCG was
not run. Native release settings force panic=abort, LTO, opt-level z and one
codegen unit, plus std optimize_for_size; the Linux reference uses upstream
release settings. Unchanged source does not mean identical build profiles.

| Facility | Observed result | Blocker or limitation |
| --- | --- | --- |
| Native application entry, allocation, arguments and normal/error exit | Used by the unchanged CLI; selected cases pass. | No missing runtime facility found on this consumed path. |
| Unicode file reads, piped/null stdin, buffered stdout/stderr | Selected rendering, help/events and multi-chunk cases pass. | Writable files, missing-file panic diagnostics, interactive terminal behavior and capacity limits were not qualified. |
| External Cargo cross-build entry point | New reusable `scripts/build-native-app.sh` accepts a manifest/binary and fresh output directory; uses existing target/std/wrapper/linker. | Existing compatibility scripts recreate shared staging; the new helper avoids that coupling without changing those qualification scripts. |
| Stable SDK/interface version contract | Exact compiler, source, lock, target, runtime and ELF identities recorded. | Interface-v0 remains experimental/planned; this fixed-pair run does not establish independently versioned SDK/runtime compatibility. |
| Threads, signals, mappings, general networking, Unix descriptors | Not requested by this application fixture. | Existing ledger limitations remain; no new support or new blocker measurement is claimed. |
| Native Cargo/compiler and component closures | Not exercised. | Linux runs the toolchain; Userland U4's component gate and U5/U6 remain deferred. |

No runtime or kernel change was justified by this application; none was made.
This finite result does not qualify an R-level, a release, U1, the entire
application, arbitrary Rust crates or the C/POSIX surface. No catalog entry,
main merge, source push, publication or release pin changed.

Exact source, execution identities, assumptions and evidence:
[S3 report](s3-native-programmability/REPORT.md). The runnable
workflow and inputs live in [the fixture](../compat/native-markdown/README.md).
“Reproducible” here describes the pinned replay procedure; a second clean
bit-identical rebuild was not measured.

## Original nineteen-program measurement

How far does ordinary, unmodified source travel on this platform's Rust
`std` before Unix or Linux assumptions dominate? This ledger records one
deliberate probe: nineteen published crates.io programs, chosen because
they are small, widely used, and conventional, built for
`x86_64-unknown-absd` without changing a source file, and the ones that
build run on ABSD against the same cases as their Linux build.

It is a measurement, not a roadmap. Nothing here adds integer file
descriptors, POSIX, threads, or signals; the kernel's
`docs/DESIGN-INFLUENCES.md` ("Linux compatibility as a personality") keeps
those out of the native design unless a native workload earns them.

## How a program is ported

`scripts/stage-compat.sh` extracts each registry archive of
`compat/programs.tsv` (checked against its crates.io checksum) twice,
beside this repository in `absd-std-staged-compat/`:

- `linux/<crate>`: exactly as published, built for Linux with the archive's
  own `Cargo.lock` (the reference);
- `absd/<crate>`: the same tree with one stanza appended to `Cargo.toml`,
  `absd-runtime` as an ABSD-only dependency, and the lock pinned in
  `pins/compat/`. The pin may only add packages (the runtime and its
  closure) or drop unused ones; the stage script refuses a pin that changes
  any upstream package's version line or checksum. xsv 0.13.0 ships no
  lock, so its pin is a resolution from the local cache.

`scripts/build-compat.sh` builds them with the repository's staged `std`
and compiler wrapper. With `ABSD_RESTRICTED_STD_ALL=1` the wrapper does two
things for crates it does not know by name: it gates each one with
`feature(restricted_std)` (compiling a `no_std` crate again without the
gate when rustc calls the feature unknown), and it links `absd-runtime`
with `--extern force:`, because an unmodified program never names the crate
that holds its CRT entry, allocator, and `std` hooks. Both are build
scaffolding of the experimental target, not semantics. The runtime stanza
is the only manifest change; no program source is touched.

`scripts/run-compat-probe.sh` then installs the ten ABSD binaries and the
inputs (`compat/data`, plus a generated 200,000-byte `blob.bin`) into the
filesystem with the fixture importer and boots `compat-launch` as the
durable worker. It runs the 25 cases of `compat/cases.tsv` through
`std::process::Command` (every program read from the filesystem and
started with `spawn_image`), each in `/data` with an empty environment,
piped stdout and stderr, and a null or piped stdin. The same cases run on
Linux against the reference build with the same `argv[0]`. The ABSD
capture must equal `compat-expected.txt`; every case must equal Linux byte
for byte (stdout, stderr, exit status) except the six in
`compat/divergences.txt`, each of which must really differ; and the
kernel's accounting line must be zero. It prints
`COMPAT PROBE OK built=10 ran=9`: ten programs build and start, nine agree
with Linux on at least one case. `ABSD_COMPAT_FAILURES=1` also rebuilds
each failing program and requires the signature recorded below.

## Classes

- **NATIVE SEMANTIC MISSING**: ABSD has no such mechanism (threads,
  signals, terminals, memory-mapped files). Only a native workload that
  needs it should add it.
- **CONVENTIONAL WRAPPER MISSING**: the native mechanism exists but the
  conventional name for it does not (RDRAND exists; `rand` 0.4 has no way
  to reach it).
- **IRRELEVANT POSIX ASSUMPTION**: the code needs nothing Unix-specific but
  is written as if every target were Unix or Windows (`cfg(not(windows))`
  meaning Unix, `libc::ESPIPE` to recognise an unseekable stream).
- **BROAD COMPATIBILITY CLIFF**: a dependency that is the POSIX surface
  itself (rustix, libc, a C runtime); porting past it means providing that
  surface.

## Programs

Versions are the crates.io releases in `compat/programs.tsv`.

| Program | Builds | Runs | Result on ABSD |
| --- | --- | --- | --- |
| uutils `basename` 0.12.0 | yes | yes | 2/2 cases equal Linux |
| uutils `seq` 0.12.0 | yes | yes | 3/3 equal (integer, separator/width, decimal steps) |
| uutils `cut` 0.12.0 | yes | yes | 2/3 equal; missing file: same status, different message |
| uutils `fold` 0.12.0 | yes | yes | 1/1 equal (byte folding across UTF-8) |
| uutils `nl` 0.12.0 | yes | yes | 1/1 equal |
| uutils `uniq` 0.12.0 | yes | yes | 2/2 equal (piped stdin and file) |
| uutils `base64` 0.12.0 | yes | yes | 2/2 equal (encode stdin, decode file) |
| jsonxf 1.1.1 | yes | yes | 2/2 equal (pretty-print file, minimize stdin) |
| ripgrep 15.2.0 (`rg`) | yes | yes | 4/6 equal: recursive search with `--sort path`, `--files`, case-insensitive count, UTF-8 `-o`; `-j2` and stdin diverge |
| | | | (installed as `/bin/rg` since 2026-10-08, with both divergences documented: README "Commands", rg(1), `docs/user-tools-20261008/`) |
| b3sum 1.8.7 | yes | starts, 0/3 | every case fails: threads |
| uutils `wc`, `head`, `cat` 0.12.0 | no | | rustix (via uucore `fs`/`pipes`) |
| uutils `sort` 0.12.0 | no | | rustix, and `ctrlc` (signals) |
| hexyl 0.17.0 | no | | rustix (via `terminal_size`), then `libc::ESPIPE` |
| sd 1.0.0 | no | | rustix (via `is-terminal`, `terminal_size`) |
| jaq 3.1.1 | no | | mimalloc (C allocator), `fd-lock`, `dirs` (via rustyline) |
| xsv 0.13.0 | no | | `rand` 0.4 `OsRng`, `filetime` 0.1 |
| fd-find 10.5.0 (`fd`) | no | | `ctrlc` (signals), configured-away `nix`, then fd's own file-type checks |

What works needs only arguments, the read-only environment, the working
directory, `std::fs` (open, read, metadata, `read_dir`), piped stdio,
`std::process::exit`, and `std::io::IsTerminal`, which already answers
`false` on ABSD (upstream's unsupported implementation; a console is not a
terminal here) so every program takes its pipe path, as it does on Linux
under a pipe. ripgrep's single-threaded walker, `memchr`, `regex`, the
`ignore` crate's directory traversal, clap, fluent and ICU localisation in
uutils, and serde-free JSON reformatting all run unchanged.

## Walls, with the exact symbol

Signatures marked (checked) are required by `ABSD_COMPAT_FAILURES=1`. The
walls behind the first were found by substituting the first wall in a
scratch build (an empty `rustix`, the existing `ctrlc` stub, an empty
`nix`); those substitutes are not committed, because none of them makes a
program run.

| Program | Wall | Class |
| --- | --- | --- |
| uu_wc, uu_head, uu_cat, uu_sort, hexyl, sd | `errno` 0.3: `compile_error!("The target OS is not yet supported in the errno crate.")` / `mod sys` not found, reached through **rustix** 1.1 (uucore features `fs`, `pipes`, `mode`, `entries`) and 0.38 (`terminal_size` under `cfg(not(windows))`, `is-terminal` under `cfg(not(any(windows, hermit, unknown)))`) (checked) | BROAD COMPATIBILITY CLIFF |
| uucore (`fs`), behind rustix | `std::os::fd::{AsFd, OwnedFd}` in `mods/io.rs` under `cfg(not(windows))`; `rustix::fs::symlinkat`; `PartialEq for FileInformation` only for `unix`/`windows` | BROAD COMPATIBILITY CLIFF (integer descriptors) |
| terminal_size 0.3/0.4 | manifest selects rustix for `cfg(not(windows))` although its code already returns `None` off Unix and Windows | IRRELEVANT POSIX ASSUMPTION |
| hexyl, behind rustix | `libc::ESPIPE` compared with `raw_os_error()` in `src/input.rs` to detect an unseekable input; ABSD's `io::Error` carries no errno (`ErrorKind::NotSeekable` is the portable test) | IRRELEVANT POSIX ASSUMPTION |
| sd, behind rustix | `is-terminal` 0.4.9: `rustix::fd::AsFd` (superseded by `std::io::IsTerminal`, which works) | IRRELEVANT POSIX ASSUMPTION |
| uu_sort, fd-find | `ctrlc` 3.5: `platform::Signal`, `platform::Error` absent (checked for fd) | NATIVE SEMANTIC MISSING (signals) |
| fd-find, behind ctrlc | `nix` 0.30 is `#![cfg(unix)]`: the configured-away crate still receives the restricted `std` prelude and the injected gate is configured away with it (E0658); `vendor/nix-absd` solves the same for 0.29 | build scaffolding |
| fd-find, behind nix | fd's `filesystem::is_block_device`, `is_char_device`, `is_socket`, `is_pipe` exist only for `cfg(any(unix, target_os = "redox"))` and Windows | IRRELEVANT POSIX ASSUMPTION |
| jaq | `libmimalloc-sys` build script: `target_family not defined!` (default feature `mimalloc`) (checked) | BROAD COMPATIBILITY CLIFF (C runtime) |
| jaq (also without `mimalloc`) | rustyline 13 (REPL, unconditional): `fd-lock` 4.0.4's *unsupported* backend imports `std::os::unix::io::AsRawFd`; `dirs` 6 `lin.rs` (anything not Windows or macOS is Linux) calls `dirs_sys::home_dir` | NATIVE SEMANTIC MISSING (line editing needs a terminal) and IRRELEVANT POSIX ASSUMPTION |
| xsv | `rand` 0.4.6 `os.rs`: no `imp::OsRng` for this OS (checked) | CONVENTIONAL WRAPPER MISSING (RDRAND serves `getrandom` 0.2/0.3/0.4, not rand 0.4) |
| xsv | `filetime` 0.1.15: `cfg(not(windows))` selects `extern crate libc` and `std::os::unix::prelude` | IRRELEVANT POSIX ASSUMPTION |

## Runtime divergences

`compat/divergences.txt` lists each, and the matrix requires it to differ.

- **b3sum, every case** (NATIVE SEMANTIC MISSING, threads): `main` always
  builds a rayon `ThreadPool` (`thread_pool_builder.build()?`, even for one
  thread), whose worker spawn returns `ErrorKind::Unsupported`: `Error:
  operation not supported on this platform`, status 1. Memory mapping
  never comes into it.
- **`rg -j2`** (NATIVE SEMANTIC MISSING, threads): the parallel walker's
  spawn fails and ripgrep reports `rg: unsupported platform`, status 2.
  Without `-j`, ripgrep asks `available_parallelism`, gets an error, uses
  one thread, and matches Linux.
- **`rg PATTERN` with piped stdin** (IRRELEVANT POSIX ASSUMPTION):
  grep-cli's `is_readable_stdin` is `false` off Unix and Windows, so rg
  searches `./` recursively instead of stdin. The standard library could
  not answer this either: it offers no "stdin is a pipe or file" query.
- **`cut -f1 missing.txt`** (IRRELEVANT POSIX ASSUMPTION): same kind
  (`NotFound`) and status 1, but the text is `std`'s ABSD message (`ABSD
  path not found`) where Linux prints `strerror(ENOENT)` (`No such file or
  directory`). Scripts that match error text will notice; code that matches
  `ErrorKind` will not.

## C programs

There is no C path. The platform's C surface is the fourteen functions
`sqlite/src/libc.rs` defines for the SQLite amalgamation (`malloc`,
`strlen`, `qsort`, ...) plus the runtime's `mem*`, with freestanding headers in `sqlite/include`.
`hello.c` fails at `printf` (the `stdio.h` there declares nothing), a
`cat.c` at `#include <fcntl.h>`; there is no `crt0` to call a C `main`, no
`unistd.h`, no descriptors, and no musl or glibc build for the target.
BROAD COMPATIBILITY CLIFF.

## The next cliff

One wall stops most of what fails: **rustix**, the Rust ecosystem's POSIX
layer. Six of the nine failing programs stop there first. For hexyl and sd
it arrives through code that needs nothing from it (terminal width,
`is-terminal`), because manifests say `cfg(not(windows))` where they mean
Unix. Behind it for uutils is the real cliff, **integer file descriptors**
(`std::os::fd`): uucore's `fs` feature (enabled directly by `head`, `cat`,
`sort`, `tr`, and `tac`, and through `pipes` by `wc`) needs them. The
runtime cliff for what does build is **threads**: two of ten programs
reach a thread spawn, one of them always. Signals are next (`ctrlc` in
`sort` and `fd`).

None of these was implemented. An empty `rustix` would only move each
failure to its call site; a userspace fd table is the Unix personality's
deferred work, due when a native consumer needs it; threads and signals are
kernel semantics. The small shims that were honest (`IsTerminal` answering
`false`, an `available_parallelism` error that ripgrep turns into one
thread) already exist.
