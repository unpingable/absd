# Base userland: sbase and bounded Toybox ports on the C kit

Familiar text and file tools for ABSD, built from
[sbase](https://core.suckless.org/sbase/) (MIT) through the C application kit
(`c/`, `docs/C-INTERFACE.md`) and the POSIX adapter (`c/posix/`). This is a
set of bounded ports, not a promise of a Unix environment: a tool that needs
something ABSD does not provide is patched to refuse that feature explicitly,
or is not ported. No kernel, kit or adapter semantics were added for these
tools (owner direction, `DIRECTIVE-base-userland-20261012`).

Status: **host-built and host-checked only.** The ABSD ELFs pass the kit's
gate and resolve every name, and `scripts/build-ports.sh` installs them
for `/bin` (below, "Installed"), but none has run on ABSD yet. What they
do on ABSD is unverified until the guest qualification (T5).

The following original T2/T3 tables describe sbase. The Toybox pipeline
addition and its separate qualification limits are recorded at the end.

## Ported (T2, T3)

| tool | sbase source | patches | ABSD ELF bytes |
|---|---|---|---:|
| `printf` | `printf.c` | none | 202,448 |
| `test` | `test.c` | `test-access-mtime.patch`, `test-stdout-gate.patch` | 225,536 |
| `grep` | `grep.c` | none | 255,984 |
| `sort` | `sort.c` | none | 243,832 |
| `sed` | `sed.c` | none | 283,400 |
| `od` | `od.c` | none | 220,816 |
| `cmp` | `cmp.c` | none | 216,312 |
| `ed` | `ed.c` | `ed-absd.patch` | 288,192 |
| `find` | `find.c` | `find-absd.patch` | 252,256 |

Each tool links `libutil.a` and `libutf.a` built from the same sbase tree.
The table's sizes are the gated ELFs; the installed files are stripped
(`PORTS.tsv`).

## Installed (T4)

`PORTS.tsv` is the manifest: one row per utility with its `/bin` name, the
`PIN` row it comes from, its upstream source, the build output, the digest of
the gated ELF, and the digest and size of the installed file (the gated
ELF stripped with `llvm-strip-18`, as the Rust ports are; the program
headers are checked unchanged and the gate is run again).
`scripts/install-userland-ports.sh`, run by `scripts/build-ports.sh` after
the Rust ports, builds the ports with `build-userland.sh` if they are not
built, refuses any build output or installed file whose digest is not the
recorded one, and copies each into `ports/NAME`. A digest changes only
with the kit, the adapter, a patch or the pin; record the new rows
(`install-userland-ports.sh --print`) with that change, once reviewed.
The image's command list is `scripts/operator_image.py` PORTS, which the
operator image, a release (`scripts/release.py`) and the operator matrix
read; it must name the nine for the image to carry them.

Names. None of the nine is a native command (`cat ls cp mv rm mkdir head
tail wc echo pwd printenv uname sha256sum stat df sync man date uptime
release sysinfo absd-sh`), a Rust port (`basename seq cut fold nl uniq
base64 rg`), an `absd-sh` builtin (`cd exit shutdown reboot pwd echo
status ps help`), or a name `scripts/cmds-matrix.py` asserts absent (`kill
chmod chown touch ln top mount`, and `ps`); `grep` is a name of its own
beside `rg`. `scripts/cmds-matrix.py --host-check` checks all of this
without a boot: `PORTS.tsv` names exactly the nine, the image's list
names them, every `ports/NAME` is at its recorded digest, each has a page
`man/NAME.1` referring to sbase(7), and the rendered sbase(7) carries
every line of `sbase.LICENSE` (in ASCII). It prints `COMMAND SBASE
EXPECTED OK names=...`; the install runs it with `--without-image-list`.
The guest command matrix installs the nine and checks that `/bin` holds
them; their behaviour is T5's.

The manual: `man/printf.1`, `test.1`, `grep.1`, `sort.1`, `sed.1`,
`od.1`, `cmp.1`, `ed.1` and `find.1`, each with an "UNSUPPORTED ON ABSD"
section in the words of the table below, and `man/sbase.7`, which lists
them and reproduces sbase's licence, so that an image carrying the
binaries carries the notice (`/share/man/cat7/sbase.0`). Provenance: one
inventory row per utility (`sbase-NAME 0.1`, MIT, the tarball's sha256)
in `provenance/inventory/operator-image.tsv`, from the `userland-ports`
unit of `provenance/config.toml`; `provenance.py notices` copies
`sbase.LICENSE` for each.

## Build and check

```sh
ABSD_PROFILE=core sh scripts/build-c-kit.sh   # once; the kit
sh scripts/stage-userland.sh                  # once; sbase per userland/PIN
python3 -I scripts/userland-demand.py         # the demand probe (DEMAND.tsv)
sh scripts/build-userland.sh                  # ports, gate, demand, host cases
```

`scripts/stage-userland.sh` downloads the tarball named in `PIN` into an
empty directory (`<campaign>/upstream/sbase/dl/`), refuses it unless its
sha256 is the pinned one, extracts it into `<campaign>/upstream/sbase/src/`,
makes the tree read-only and refuses it if its `LICENSE` differs from
`sbase.LICENSE` here. It prints `USERLAND STAGE OK sbase 0.1 ...`.

`scripts/build-userland.sh` copies the staged tree to
`<campaign>/userland-build/src`, applies every `patches/*.patch` there (each
must apply and reverse cleanly), builds the ports twice for ABSD with
`absd-cc` (the adapter archive rebuilt each round; both rounds must hash
equal), builds the same patched sources with host gcc against glibc as the
REFERENCE, and runs `scripts/check-userland.py`:

- **gate**: `check-c-elf.py --map` on every ABSD ELF;
- **demand**: the names each port's ABSD objects (and the libutil/libutf
  members they pull) need, classified as the probe classifies; every one
  must be defined by Picolibc, the kit or the adapter; the set is compared
  with the probe's rows and with the reference objects' demand
  (`<build>/demand/<tool>.txt`);
- **host cases**: every row of `cases.tsv` run on the REFERENCE binary
  (argv[0] `/bin/<tool>`, empty environment, a fresh directory of the fixtures in
  `check-userland.py`), compared with its pin in `expected/`.

**The gate needs the C kit before `build-ports.sh`.** `scripts/build-ports.sh`
now installs these ports (`scripts/install-userland-ports.sh`), building
them with `build-userland.sh` if they are not built, which needs the kit
and the adapter. `scripts/check-all.sh` runs `build-ports.sh` at line 261
in both profiles, but builds the kit only at line 264, inside the
`extended` `run-c-kit.sh` (full profile only). On a host without a kit
`check-all.sh` therefore stops at line 261. Whoever merges this lane must
add, before line 261 and outside `extended`:
`sh "$root/scripts/build-picolibc.sh"`, `sh "$root/scripts/build-c-kit.sh"`
and `sh "$root/scripts/build-userland.sh"`, in that order (or make the kit a
core input). The command matrix also stays red until
`scripts/operator_image.py` PORTS names the nine
(`docs/base-userland-20261012/RECORD.md`, "Held for the owner").

The last line is `USERLAND BUILD OK ports=9 reproducible=2 gate=9
unresolved=0 host_cases=99 guest=unverified`. The kit has no host-run route,
so the ABSD ELFs are not run by this check. A pass of the host cases shows
that the reference build produces the pinned outputs; it says nothing about
the ABSD binaries.

The reference is not upstream sbase everywhere. Some hunks apply to both
builds on purpose, so that the host pins exercise ABSD's code path on
glibc rather than show upstream parity: in `ed`, the scratch file in the
working directory when `TMPDIR` is unset (every `ed-*` case runs that way;
upstream would use `/tmp`) and the refusal of `!cmd` and `w !cmd`
(`ed-shell`, `ed-wshell`; upstream would run the command); in `find`, the
`spawn()` stub and the parse-time refusal of `-exec` and `-ok`
(`find-exec`, `find-ok`; upstream would run `cat`); in `test`, `access()`
for `faccessat` and the `fflush(stdout)`. The ABSD-only hunks
(`ABSD_NO_MTIME`, `ABSD_NO_SIGNALS`, `ABSD_NO_UMASK`) are left out of the
reference, and the cases where they change the result are the rows of
`divergences.tsv`. The pins in `expected/` are the
guest's expected outputs, except for the cases `divergences.tsv` names.
A pin ends with a `--- files` section when its case created, changed or
removed a file in its directory (each named with its new content), so a
file `ed` writes, or a scratch file it leaves behind, is part of the pin.
The archiver for the ABSD side is `$ABSD_AR` (default `llvm-ar-18`), in
the Makefile and the probe.

## Guest run (T5)

The specification is `docs/base-userland-20261012/RECORD.md`, "Owed: guest
run (T5, via the steward)". The runner is `scripts/userland-matrix.py`,
started by `scripts/run-userland-matrix.sh` (niceness 10 or more, 1-minute
load at most 10, a clean tree for a full run) with `ABSD_KERNEL_RUN` (a
disposable kernel clone) and `ABSD_USERLAND_PLATFORM` (the built platform
tree whose `ports/` holds the nine at their `PORTS.tsv` digests, with
`commands/absd-sh`, the boot ELFs and the rendered manual). It is the
cports harness on a new table: `CportsMatrix` and `KitMatrix` over
`ssh_absd.py` supply the sessions, the census and its rules; nothing of
them is copied.

Inputs: `cases.tsv`, `expected/` and `divergences.tsv`, and the fixtures,
imported from `check-userland.py` (`FIXTURES`, `MTIMES`). The 99 pins in
`expected/` were produced by the Linux REFERENCE build (gcc, glibc) of the
sbase 0.1 pin in `PIN`, run with argv[0] = `/bin/<name>`; the runner prints
that as its `USERLAND PINS PROVENANCE` line. That argv[0] is the
equalization of controller ruling D-21: absd-sh starts a bare name as
`/bin/<name>` (sshd's argv route uses the same form), so a message
prefixed with argv[0] reads `/bin/sed: ...` on ABSD. The reference is run
the same way, as the Stage 2 and 3 harnesses (`cports-matrix.py`,
`compat-matrix.py`) run their Linux twins, and ABSD's output is never
normalized. 23 of the 99 pins carry the prefix. The `ABSD_STDERR` texts of
`divergences.tsv` still start with the bare `NAME:` and are the lane's to
restate. The fixtures go onto the image once, by the fixture
importer, and are read back byte for byte by the host's reader (`bin.dat`
included). Each case then gets a fresh directory (`cp -r` of them, checked
byte for byte again), runs by bare name in one SSH exec session with its
STDIN fixture on the session's input, and is formatted by
`check-userland.py`'s `format_result`, the function that wrote the pins:
status, stdout, stderr and the `--- files` section. No time is set: ABSD
has none, and the three cases that use times are `divergences.tsv` rows
refused before any time is read.

Judging is byte-exact. A case agrees when its result equals its pin. A
`divergences.tsv` row must give its `ABSD_STATUS`, empty stdout, its
`ABSD_STDERR` line and no changed file. Anything else, and any repeat that
differs from the first run, is a DEFECT: the result goes to `<pins>/<ID>`,
`<pins>/DEFECTS` says what differed, and the matrix exits 1. `<pins>` is the
run's work directory, `$ABSD_USERLAND_WORK/matrix/pins` (default
`<campaign>/userland-guest/matrix/pins`), cleared with it by the next run;
`ABSD_USERLAND_PINS` puts them elsewhere. Nothing is written into the tree. A defect is
never made a divergence by the runner. An `ed` defect that shows the
scratch file, or a `find -exec`/`-ok` defect that shows the parse-time
refusal, is marked "candidate disposition D-04" so the steward can
re-class it with the lane's record.

Stage 2 discipline: a census before each case's directory is made and
after it is removed (`compare_census`: settle, the frames-only step
allowance, a high-water reading allowed only for that directory: every
first run may take one, and nothing bounds their total across cases); every
case runs twice, and the second census must equal the first with no allowed
path, under the boot's frames-only STEP allowance (STEP_BOUND, 5 frames in
all per boot);
^C in a PTY shell for `sed`, `grep`, `sort`, `od`, `cmp` and `ed` reading
the terminal (prompt back, status 130, the session ends 0; `ed`'s
left-behind scratch file is counted). Not run, with reasons printed:
^C for `printf`, `test` and `find` (they read no input) and exhaustion (the
cports harness has no such scenario). The demo rehearsal follows the
record's T5 list: `ed` writes `hello.c` with no scratch file left, `od -t
x1`, `cmp`, `grep`, an empty `find . -name 'ed.*'`, `tcc` only if
`/bin/tcc` exists (else `USERLAND DEMO TCC NOT_RUN reason=no /bin/tcc`),
`rm`, `man sbase` with the licence, and `/bin` naming the nine, with the
census equal around it.

Not established by this runner: the record's T5 bullets 1-2 (`/bin` holds
exactly NATIVE + 17 ports + `absd-sh`; `COMMAND SBASE PRESENT`) and the
extra cases of the T2/T3 reports. They are owed to `scripts/cmds-matrix.py`
in the same chain, and the summary lists them in `notrun=`
(`bin-exact`, `command-sbase-present`, `t2-t3-report-cases`).

A failed check (a census that does not settle, a session that hangs past
its timeout or is not as expected, a ^C screen that differs) aborts the run
with `USERLAND MATRIX FAILED` and no summary line; only judging differences
are counted as DEFECTs.

The last line is `ABSD USERLAND GUEST OK cases=<n> agree=<a> diverge=<d>
defects=0 demo=ok|not_run notrun=<list|none>`; with defects it reads
`ABSD USERLAND GUEST DEFECTS ...` and the status is 1.
`scripts/userland-matrix-selftest.py --work <dir>` checks the judging on
a fake guest without a boot and prints `USERLAND SELFTEST OK checks=<n>`;
the wrapper runs it first.

## Demand (T1)

`scripts/userland-demand.py` compiles every sbase utility (97) with
`absd-cc`, trial-links it with sbase's libraries and the adapter as the
ports link, runs the ELF gate, and classifies every name the utility needs
as PICOLIBC, KIT, ADAPTER, REFUSED or MISSING, following
`docs/c-ecosystem-20261010/posix/DEMAND.md` and
`cports/demand/classify.tsv` (its KIT-FIVE is KIT here; a name refused by
`docs/C-INTERFACE.md` section 10 that no archive defines is REFUSED and
blocks the link). `DEMAND.tsv` has one row per (utility, name);
`DEMAND-SUMMARY.tsv` one row per utility with its outcome and blocker. On
sbase 0.1: 97 utilities, 50 portable (compile, link and pass the gate with
no adapter change), 11 do not compile against the kit headers, 27 do not
link (unresolved names), 9 link but fail the gate (below). Of the T2 set, six were
portable unmodified; `test` needed `faccessat` (MISSING).

Findings for later tasks, from the probe:

- **Weak `stdout`.** Picolibc's buffered-I/O member references `stdout`
  weakly; the gate admits only a weak `stdin`. A program that writes only to
  stderr never links `stdout` and is refused (`cat dd pathchk rmdir sleep
  sponge tee unlink xinstall` in the probe, `test` before its patch). This is the
  kit's to decide (admit a weak `stdout` as it admits `stdin`), not the
  ports'.
- **The `*at` family** (`fstatat openat fdopendir unlinkat fchownat
  fchmodat linkat symlinkat faccessat utimensat`) is undefined: sbase's
  `libutil/recurse.c` uses `fstatat`/`openat`/`fdopendir`, so every
  recursive tool (`du chgrp chmod chown rm cp mv`) is blocked, and `find`
  is blocked by `fork execve waitpid` (`-exec`) plus `clock_gettime`
  and `umask`.
- `ed` needs only `sigaction` (REFUSED, link-time): a per-port patch or
  refusal glue (owner D4) is T3's.
- `tar` does not compile (`makedev` undeclared; `sys/sysmacros.h` absent).

## Build adaptations

Not changes to sbase sources; applied to every compile on both sides.

- `include/regex.h`, first on the include path: Picolibc 1.8.12's `regex.h`
  declares `regex_t` with a `size_t` member but includes `<stddef.h>` under
  `__need_ptrdiff_t` only (`regex.h:41-49`), so `grep.c` and `sed.c`, which
  include `<regex.h>` before anything that defines `size_t`, do not compile.
  The wrapper includes `<stddef.h>`, then the kit's header unchanged.
  (`absd-cc` refuses `-include`, so a wrapper is the only route.)
- sbase's own CPPFLAGS (`-D_DEFAULT_SOURCE -D_NETBSD_SOURCE -D_BSD_SOURCE
  -D_XOPEN_SOURCE=700 -D_FILE_OFFSET_BITS=64`), `-O2`, and a file-prefix map
  (the sources to `/sbase`, the tree to `/absd`).
- ABSD side only: `-DABSD_NO_MTIME`, read by `test-access-mtime.patch`,
  while `C-INTERFACE.md` 11 says no modification time reaches a program.
  Remove it when R3 lands.
- ABSD side only: `-DABSD_NO_SIGNALS`, read by `ed-absd.patch`: no signal
  is delivered on ABSD (CPA-004) and `sigaction` is refused at link time.
- ABSD side only: `-DABSD_NO_UMASK`, read by `find-absd.patch`: a
  link-only `umask` stub (no creation mask exists; no archive defines
  `umask`). `ABSD_NO_MTIME` also drives `find`'s time refusals.

## Patches

Each is a file in `patches/` whose header states the failure, the change
and the ABSD behaviour it preserves. Applied in name order.

| patch | failure | change | preserved |
|---|---|---|---|
| `test-access-mtime.patch` | `faccessat` undefined (link); `-nt`/`-ot` would answer false (mtime 0) | `access()` for `-e -r -w -x`; ENOSYS/EINVAL from `access` and, under `ABSD_NO_MTIME`, `-nt`/`-ot` end with status 2 and a message | fixed identity, so `access` == `faccessat(AT_EACCESS)`; on Linux the program behaves as upstream |
| `test-stdout-gate.patch` | gate: `undefined symbol stdout (weak)` | `fflush(stdout)` once in `main` (both builds) | `test` writes nothing to stdout; status and stderr unchanged |
| `find-absd.patch` | `fork`/`execvp`/`waitpid` (`-exec`, `-ok`) refused at link time; `clock_gettime`, `umask` undefined; file times all 0 | port-local ENOSYS stub for `spawn()` (D4) and `-exec`/`-ok` refused at parse time (both builds); under `ABSD_NO_MTIME` `-atime -ctime -mtime -newer` refused at parse time and no `clock_gettime`; under `ABSD_NO_UMASK` a link-only `umask` | traversal (stat/lstat, opendir, readdir, path concatenation; no `*at`), loop detection, every other primary and operator |
| `ed-absd.patch` | `sigaction` refused (link); scratch file in `$TMPDIR` or `/tmp` (not writable, empty environment); `!cmd`/`w !cmd` reach the adapter's refused `system`/`popen` | no handlers under `ABSD_NO_SIGNALS`; scratch file in `$TMPDIR` if set, else the working directory, fatal and named at start-up when it cannot be created; `!cmd` and `w !cmd` refused before anything runs (both builds) | every editing command, undo, reads and writes, the `?` convention and exit status; scratch file removed on `q`, `Q` and end of input |

In T2 no port needed a temporary file (sbase 0.1 `sed` has no `-i`) or a
spawn. In T3 `ed` needs a scratch file (owner D2: a per-port patch puts it
in the working directory, never `/tmp`) and offers `!` (refused), and
`find` spawns for `-exec`/`-ok` (refused through a port-local ENOSYS stub,
the controller's D4 ruling).

## The line editor: `ed` on ABSD

`ed` is the editor of the base userland because the SSH terminal is a line
discipline in sshd with no raw mode, `TERM` or window size
(`ssh/src/tty.rs`), so no screen editor can work (owner D3, deferred).
What a person must know, all predicted from the contract and the patch
until the guest run:

- **Start it in a writable directory.** Its scratch file (the buffer's
  backing store) is `./ed.XXXXXX` in the working directory; sessions start
  in read-only `/`, so `cd /home/operator` or `cd /tmp/session-N` first.
  Otherwise `ed` exits at once with status 1:
  `ed: cannot create scratch file ./ed.XXXXXX (start ed in a writable
  directory): <reason>`. The file is removed on `q`, `Q` or end of input.
- **Leave with `w` then `q`.** ^D on an empty line closes the session's
  input for the whole session (`ssh/src/tty.rs`), and `ed` treats end of
  input as `q` without the modified-buffer warning: unsaved text is lost
  (case `ed-eof`).
- **^C loses the buffer.** No signal is delivered on ABSD; ^C ends the
  pipeline and `ed` with it, unsaved text is lost, and the scratch file
  `./ed.XXXXXX` stays behind in the directory (remove it with `rm`; in
  `/tmp/session-N` it goes with the session).
- **No shell escapes.** `!cmd` and `w !cmd` answer `?`; `h` shows
  `shell commands are not supported on this system` (no spawn right).
  `r !cmd` was never special in sbase 0.1: it reads a file named `!cmd`.
  `!!` with no earlier command answers `no previous command` first, as upstream.
- Errors are `?`, with the reason after `h` (or every time after `H`); the
  exit status is 1 after any error, as upstream.

## `find` on ABSD

sbase 0.1 `find` walks with `lstat`/`stat`, `opendir`, `readdir` and path
concatenation; it uses no `*at` call and not `libutil/recurse.c`, so its
traversal needed no patch. The adapter's `opendir` takes a snapshot of
the listing and holds no handle (`c/posix/dirent.c`), so each level of
depth costs memory, not one of the 64 open files. Output order is the
file server's listing order (CPA-032), not the host's: the cases use a
tree with one entry per directory so their pins hold on both.

The port's patch (`find-absd.patch`) refuses what ABSD cannot do while
the expression is parsed, before any path is visited, so nothing is
printed first:

- `-exec` and `-ok`: status 1, `find: -exec: cannot run commands on this
  system: Function not implemented` (`-ok` likewise). A port-local stub
  replaces `spawn()` (fork, execvp, waitpid) and fails with ENOSYS, under
  the controller's D4 ruling: the stub lives in this port's patch only,
  never in the kit or the adapter, and is disclosed here and in CPA-065.
  Both builds carry it, so the reference pins the refusal.
- `-atime`, `-ctime`, `-mtime`, `-newer`: status 1, `find:
  -atime/-ctime/-mtime/-newer: file times are not available on this
  system`, under `ABSD_NO_MTIME` (the ABSD build only; temporary until R3).
  `clock_gettime`, which only these primaries need, is not called. The
  reference build keeps them (cases `find-mtime`, `find-newer` are
  `divergences.tsv` rows; a host build of the patched source with the ABSD
  defines printed exactly the predicted line and status).
- `umask`: never called by `find` (`-perm` calls `parsemode(str, 0, 0)`),
  but `libutil/mode.o` names it; under `ABSD_NO_UMASK` the patch defines a
  link-only `umask` that returns 0 and changes nothing.

## Unsupported features and their behaviour on ABSD

Predicted from the contract and the patches; to be confirmed in the guest.

| tool | feature | behaviour |
|---|---|---|
| `test` | `-w DIR` | status 2, `test: -w DIR: check not supported on this system: Function not implemented` (SPEC A11) |
| `test` | `-x FILE` | status 2, `... check not supported on this system: Invalid argument` (no execute permission exists); `-x DIR` is true |
| `test` | `-nt`, `-ot` | status 2, `test: -nt/-ot: file modification times are not available on this system` |
| `test` | `-h`, `-L`, `-p`, `-S`, `-b`, `-c` | false: only files and directories exist (A13) |
| `test` | `-u`, `-g`, `-k` | false: modes are 0644/0444 only |
| `test` | `-t FD` | false: no descriptor is a terminal (`isatty` 0) |
| `test` | `[` form | the binary honours `argv[0]` `[`, but no `[` is installed |
| `ed` | `!cmd`, `w !cmd` | `?`; `h`: `shell commands are not supported on this system`; nothing runs; status 1 at exit |
| `ed` | scratch file | `./ed.XXXXXX` (or `$TMPDIR`, never set on ABSD); not creatable at start-up: status 1, `ed: cannot create scratch file ./ed.XXXXXX (start ed in a writable directory): <strerror>` |
| `ed` | ^C, hang-up | no handler (no signals): the process ends, the buffer is lost, `./ed.XXXXXX` remains; `ed.hup` is never written |
| `ed` | ^D on an empty line | closes the session's input; `ed` quits as on `q` without the modified warning: unsaved text is lost |
| `ed` | interactive prompt | only with `-p STRING`; no line editing beyond sshd's erase |
| `find` | `-exec`, `-ok` | status 1, `find: -exec: cannot run commands on this system: Function not implemented`, before any output |
| `find` | `-atime`, `-ctime`, `-mtime`, `-newer` | status 1, `find: -atime/-ctime/-mtime/-newer: file times are not available on this system`, before any output |
| `find` | `-type l`, `-type p/s/b/c` | never true: only files and directories exist (A13) |
| `find` | `-perm` | predicted: compares the reported modes, 0644 or 0444 (directories too, no search bits): `-perm -200` selects writable objects |
| `find` | `-nouser`, `-nogroup`, `-user NAME`, `-group NAME` | predicted: no user database on ABSD (CPA-050): `-nouser`/`-nogroup` are true for every object, a name is `unknown user`, status 1; `-user 1000` matches everything (SPEC A8) |
| `find` | `-xdev` | compares `st_dev`, the filesystem id; mount boundaries in a session are unverified |
| `find` | `-H`, `-L` | accepted; no symbolic links exist, so they change nothing |
| `find` | an unreadable path | `find: failed to stat PATH: <strerror>` and status 0, as upstream (`weprintf` does not set the status) |
| `sed` | `-i` | not in sbase 0.1: usage error, status 1 |
| `sed` | `w FILE` | writes only where the session may write (`/home/operator`, `/tmp/session-N`); elsewhere the open fails with sbase's message |
| `od` | `-c` | not in sbase 0.1: usage error, status 1; `-t c` works |
| `grep`, `sed` | regular expressions | Picolibc's `regcomp`/`regexec`; C locale only (R14), so `-i` and classes are ASCII |
| `sort` | input size | in memory, bounded by the 32 MiB heap (`C-INTERFACE.md`); exhaustion is T5's to qualify (after R16) |
| all | messages | prefixed with `argv[0]`, which is `/bin/NAME` when absd-sh starts a bare name; `strerror` texts are Picolibc's (equal to glibc's for the errors in `cases.tsv`) |

## Not ported, deliberately

`scripts/cmds-matrix.py` asserts that `kill chmod chown touch ln top mount`
are absent from `/bin` (README "Not provided"). sbase offers `kill chmod
chown touch ln`; they are not ported, and must not be. sbase has no `top`
or `mount`. A `do-not-port` disposition in `DEMAND-SUMMARY.tsv` overrides
`portable`: `kill` links and passes the gate, and is still not ported.
Tools whose purpose
is to spawn (`xargs env nohup time setsid chroot flock nice renice`) are
structurally impossible (no spawn right) and are not candidates. Tools the
platform already has natively or as uutils ports (`cat ls cp mv rm mkdir
head tail wc echo pwd printenv date sync sha256sum uname`, `basename cut
fold nl seq uniq`) are not duplicated.

## Licence and provenance

sbase is MIT (`sbase.LICENSE`, its `LICENSE` verbatim, which
`stage-userland.sh` checks against the staged tree). Its notice must
accompany every copy, so any image carrying these binaries carries it:
sbase(7) (`man/sbase.7`) reproduces it, and the host check compares the
rendered page with this file. The sources are downloaded and verified at build time
and never vendored; the pin is trust-on-first-use (suckless publishes no
digest beside the tarball; recorded 2026-10-12 before extraction). The
patches are adapted material under sbase's terms (`provenance.toml`). The
glue, cases, pins and records here are first-party, Apache-2.0.

## Diff host adaptation (not installed)

`diff/README.md` records the isolated Toybox 0.8.15 bounded two-file adaptation,
source-specific staging/build path and host controls. Target kit/link/demand,
two-build pins and steward guest qualification remain open. This does not add
a qualified port to PORTS.tsv or change installed userland.

## Toybox diff and hexdump pipeline additions (2026-10-13)

The installed set now also names bounded Toybox 0.8.15 adaptations `diff`
and `hexdump`; their individual README files and manpages define the actual
contracts, refusals and source/license identities. No Toybox multicall program
is linked. `userland/PIN` pins the archive; source-specific stagers verify the
selected member, license, declared patch and resulting bytes. The build stages
those adapted sources afresh into its own output tree, compiles standalone
objects, and links no sbase helper archives into these two tools.

The existing build route still rebuilds the adapter and all utility products
in two rounds, checks every ELF/map and computed object demand, and compares
host cases with checked-in expected outputs. `DEMAND.tsv` remains the earlier
unpatched sbase discovery survey; it is not fabricated or relabeled as a
Toybox probe. Actual standalone demands are computed by `check-userland.py`.
The new cases flow through the same guest matrix and are **unqualified on the
guest until that matrix executes**. Host cases never establish guest results.

Toybox PORTS rows use independently reviewed target outputs made against a
copied SDK whose BUILT-FROM names Candidate 5 `d0a73257`; its source attribution
is corroborated historical evidence, not a fresh SDK rebuild witness. Source
commits: diff `eaaf4cb2`, hexdump `abf51e90`. Exact full/stripped digests came
from retained target receipts, not guessed replacements. The combined twelve-port pipeline has passed its complete two-round
adapter/utility rebuild and host gate against that copied SDK. Guest qualification
and integration acceptance remain with the steward. In particular runtime A3 or
adapter changes require steward recomposition and deliberate digest re-pin;
the installer must refuse differing bytes. No main or integration acceptance
follows from this source integration.

Toybox's 0BSD license appears in toybox(7). The command matrix's historic
`SBASE` variable/result label continues to identify the entire C userland group
for compatibility with its existing gate; each port's actual origin is read
from PORTS.tsv for its manual reference. It does not label Toybox as sbase.

Formalization consideration: pipeline source-to-output claims use exact
source/SDK hashes, existing ELF predicates, measured demand and deterministic
negative controls for staging/digest refusal. These tests and scoped prose
suffice for this integration; no broader provenance or runtime proof is claimed.
## Tar — substantial native ustar adaptation (host qualification)

`tar-absd.patch` substantially adapts the pinned MIT sbase0.1 source. It
replaces checked record I/O, numeric/header validation, extraction effect
ordering and directory-fd traversal. It preserves the command/member flow
and standard uncompressed ustar format; it does not claim that the original
parser/extractor is preserved unchanged. Source and MIT notice remain
under the existing PIN/staging route. `userland/Makefile` builds the utility;
the pipeline successor adds operator-image inclusion and measured PORTS.tsv pins
after the complete copied-SDK target build. This does not establish guest behavior.

Supported: `-c/-t/-x`, `-f archive` (exact `-` means standard input/output),
`-C directory`, `-v` (stderr, never mixed with archive bytes), optional named
members and their descendants, recursive regular files/directories, and
`-m` as an explicit reminder that native extraction ignores Unix times.
Unsupported options, compression, links, devices, FIFOs and GNU/PAX/sparse
extensions fail with nonzero status. This is not full POSIX pax behavior.

Creation records native stat metadata, including the existing synthetic
owner/time/permission values. Extraction restores contents/hierarchy; Unix
owners/timestamps/execute/set-ID bits are not restored. Regular file
readonly state maps to0444 when owner-write is absent and0644 otherwise,
after content completes. Directories use native creation; no directory
chmod is attempted. Preservation flags are refused. Host tests use the
same native mapping, even though the host could preserve more metadata.

Benign `./`, repeated separators and directory trailing separators normalize;
absolute names and parent components refuse. Existing same-kind directories
are reusable, writable regular files are replaced, and later duplicate
members replace earlier writable files. Readonly files, symlinks and
file/directory conflicts refuse. Ancestors are checked before current-member
mutation. Source/destination pathname bindings must remain stable: checks
do not prevent concurrent pathname replacement. Earlier members and a
partial current file may remain after failure; there is no rollback claim.
Creating an archive excludes its own output identity and detects source
size changes, but does not provide a concurrent-content snapshot.

Format bounds derive from ustar:512byte records, name100/prefix155 with
slash split (up to256bytes), terminated octal fields, and two zero endrecords.
Paths that cannot be represented refuse, rather than switching format.
Traversal depth is bounded by representable relative paths; open directory
snapshots consume the runtime's bounded heap and fail on exhaustion.
File data is streamed through512bytes, no input-size allocation. Selected
member tracking is proportional to admitted process arguments. Host error
controls establish nonzero output on read/write/format failures; broken
pipe may terminate by SIGPIPE on hosts, while ABSD delivers no POSIX signals.
Actual ABSD error/resource/cleanup behavior remains a guest qualification
obligation, not implied by host tests.

Run `python3 userland/test_tar.py /absolute/path/to/tar-host`. The retained
independent Python-ustar vector is in `userland/tar-vectors`; tests cross-read
port output using GNUtar and Python, and cross-write input using Python.
Malformed records, path conflicts, native metadata and stdio controls are
part of the focused host suite. No archive files outside isolated fixtures
are modified by it. Independent implementation review and SDK symbol/ELF closure are recorded
separately; target linking does not establish guest execution.

## Tar pipeline successor (copied-SDK build complete; guest pending)

The successor adds the accepted native ustar adaptation to the existing sbase
source/patch/Makefile route and eight shared host/guest matrix cases. List and
extract use the independently generated `tar-vectors/basic.ustar`: the literal
listing is `file\n`, and extraction creates `file` with exactly `abc`. Creation
includes a regular file and nested directory tree, not merely an archive listing.

For the **named `tar-create` case only**, comparison projects the created archive
into ordered member names, regular/directory types and exact file content. The
fixture requires ordinary ustar headers, contiguous records and zero end blocks;
it refuses hidden extension headers. Unix uid/gid/time/mode equality is explicitly
excluded from this comparison because the native contract does not preserve those
host metadata values. Other cases retain the ordinary exact-byte result format.
This small fixture projection is not a general archive verifier.

The guest harness obtains raw `made.ustar` bytes through its existing filesystem
reader, before any text rendering. It retains first and repeat occurrences as
`<work>/tar-create-raw/{first,repeat}.ustar`, prints their hashes, then projects
for comparison and removes the guest case directory. Case identity is preserved
across the repeat. These files belong to that qualification occurrence, with
review/replay custody until its existing terminal disposition; they are not
indefinite retention. The host keeps its raw archive in the case directory and
this source lane's `created-raw.ustar` evidence. Python controls exercise actual
first/repeat lifecycle code and missing/extra/duplicate/type/content, malformed,
checksum, truncated and extension cases. This does not execute a guest.

The admitted full pipeline at source `91b526f8` rebuilt the adapter and all
12 utilities in two rounds, checked 12 ELF/maps with zero unresolved symbols,
and passed 125 host cases. The tar pin is measured from that actual top-level
link, not copied from the earlier minimal-helper experiment. Run identity:
`62239cc8-de0d-4408-b4c8-6a49328b230b` under the shared r11-pipeline registry.
The copied SDK's BUILT-FROM names Candidate 5 `d0a73257`; this is corroborated
historical source attribution, not proof of a fresh SDK build. The final source
successor adds only measured manifests, image/command lists and documentation.
Candidate runtime or kit changes still require steward recomposition, a full
pipeline gate and deliberate `install-userland-ports.sh --print` re-pinning.
Guest cases (including the existing D-21 command convention), integration
acceptance and main promotion are not established by this host build.
