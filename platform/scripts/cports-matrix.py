#!/usr/bin/env python3
"""Stage-2 ports on the shell route (docs/c-ecosystem-20261010/posix/CPORTS-HARNESS.md).

One `net fsd` boot (scripts/ssh_absd.py) on a 128 MiB image, a harness
fixture (CPORTS-HARNESS.md 6; ssh_absd.IMAGE_BYTES and DEVICE_SECTORS are set
before setup; the filesystem is the device's second half). The two stopping
scenarios end the boot and start the next on the same image. The image
carries, beside ssh_absd's deployment, /bin/{mkdir,cat,df,sysinfo,ls}, every
product of --absd at /bin/<product>, and for every case directory CWD of the
case table the files of cports/data/<CWD>/ at /home/operator/cports/<CWD>/;
the CWD `lua-tests` gets the upstream test tree
(upstream/lua-tests/absd/lua-5.4.9-tests/, recursively) and the CWD `zlib`
the generated one.bin (CPORTS-HARNESS.md 5.2: `line %07d <24 hex digits>`
of a SHA-256 chain seeded with b"absd-cports-zlib", truncated to 1 MiB; its
digest must equal ONE_BIN_SHA256). A case directory with no file is made by a
session `"/bin/mkdir"` before its first case and checked on the image.

A case (route `shell`) is one SSH exec session through absd-sh:
`cd /home/operator/cports/<CWD>; "<PROGRAM>" "<ARG>"...` with the STDIN
file's bytes on the session's stdin, and the case's `# timeout` (default
600 s). The program must be the shell's only child. Its Linux twin is the
reference build of the same name, started with argv[0] = /bin/<name>, in
<work>/linux/<CWD> (the same files), env {TZ: UTC} only (the session's
environment is empty, SPEC A20, and is never manufactured), umask 022,
SIGPIPE ignored. Case directories chain: a case sees what the earlier cases
of its CWD left, on both sides. `eight.bin` is made before `zlib.gzip-8m`
by `"/bin/cat"` of one.bin eight times in the guest, and on the host.

Normalizers (cports/normalize.tsv, CPORTS-HARNESS.md 4.3): every match of a
case's regexes (multiline) in stdout and stderr becomes `<n>` on both sides
before comparison. A case with a normalizer runs its Linux twin twice: the
normalized outputs must be equal, the raw outputs must differ as a whole,
and every pattern must match in both runs (else CPORTS NORMALIZER UNUSED
<name> [<regex>] and the run fails). That a pattern covers only variable
text is not tested per pattern (a random 0/1 span is often equal by chance):
it rests on the upstream line each row of normalize.tsv cites. The second, comparison-only run uses a copy
of the case directory taken before the first. A case's stdin bytes must
equal the same file on the image before the run.

Judging: a case listed in cports/divergences.txt must equal its pin
cports/absd-expected/<name>.txt (stdout, `--`, stderr, `--`, status) and
differ from the Linux twin; a case in cports/absd-expected/DEFECTS must
equal its pin and counts as a defect, and before the defect it must still
equal the twin (DEFECT_PREFIX: normalized stdout through the program's last
progress line, stderr up to its error line; CPORTS DEFECT PREFIX OK); any
other case must equal the twin.
`--pin NAME` writes the pin (review it). A pin naming no case fails the run.
Every `# outputs` file is read from the running image with the host's own
reader and must equal the Linux twin's file byte for byte; minigzip's ABSD
`.gz` outputs are also decompressed on the host and compared with the
input. A `# removed` path must be gone after the case.

Resources (SPEC A5): a stable census (KitMatrix.census: live images,
sysinfo's memory and kernel lines, the image's objects) before and after
every shell case and scenario; everything equal except the case's
outputs/retained/removed paths (under its CWD) and anything under /var/log.
One exception, for a case that changes files: the frame count may move
when nothing else does (the file server's heap follows the image it holds
and its pooled pages stay mapped, C-INTERFACE.md 3): printed as CPORTS
RESOURCES HIGHWATER (with the fsd heap step and its ruling (a) class,
below). Only a case in REPEATABLE (a gzip/gunzip pair), in a
CHAIN (cases of one CWD that rebuild their files once the chain's files are
removed: the four SQLite scripts, temp-nomem, each speedtest1) or in
REPEAT_SCENARIOS (a scenario whose run leaves the files it started from:
posix.lock-contention, whose lock file `l` is retained and nothing produced)
may take it; any other fails the run (CPORTS RESOURCES HIGHWATER
UNREPEATABLE). The run then ends with a repeat round: every high-water case
with its inverse, plus the zlib pairs that ran, every chain holding a
high-water case (its files removed by /bin/rm, its cases run in order, each
printing what it printed the first time; each zlib pair's produced file equal
to the first run's), and every high-water scenario of REPEAT_SCENARIOS (its
same scenario method run again, Linux twin included, each run printing what
its CPORTS SCENARIO OK line printed the first time: CPORTS SCENARIO REPEAT
<name> round=<k>), once to warm (round 0), then twice more. The warm
round permits only fsd +0/+4 pages and at most +4 frames, with unchanged
images, kernel objects and names; it prints CPORTS REPEAT WARM. Each judged
round's census, the file server's heap peak included, settled and at rest (ruling (b) below), must equal the one before
the judged rounds (taken after warm, itself settled and at rest) exactly (CPORTS RESOURCES
REPEAT OK repeated=... outputs_checked=...), so a
per-operation leak still fails. A scenario that stops QEMU retakes the
census on the next boot (CPORTS RESOURCES REBASE, printed with the reading
before the cut) and is compared against it; its frame growth there is an
informational high-water reading. Such a scenario runs twice (RESTART_ROUNDS,
controller ruling 1): round 2 removes its files with /bin/rm and repeats the
whole stop/restart scenario, and the census after each round must be equal
(CPORTS RESOURCES RESTART ROUND <name> round=<k>): that shows determinism
across boots, not reclamation. Reclamation on the restarted boot is measured
by the same-boot repeat (final review I3): after B's recovery query, B's
read-only query runs twice more and the census after each must equal the
census after the recovery query exactly, with no allowance (CPORTS
RESOURCES RESTART REPEAT <name> :: round=<k> repeat=<j> <census>). The repeat rounds measure
the warm boot that ran the cases: they run immediately before the first
stopping scenario (or at the end when none runs), and each stopping
scenario's leak check is its round-against-round census equality.
Census ruling (b) (steward, as clarified and ratified by the rule's owner on
2026-10-13). It applies to every CportsMatrix harness: cports, and tcc,
clang and userland, whose censuses are CportsMatrix.census and carry the
file server's keys (draining, opens, heap peak from its last FSD CAPACITY
line, printed at READY and at each channel settle; draining=0 means 0 at the
last settle). Every judged census (before and after a case or scenario,
the frames warmup's two, the census before the repeat rounds and each
round's, the restart rounds' and the restart repeats' with their base) is
taken by sampling once per second through the settle window: a 20 s
agreement wait plus 60 s (AGREE_SECONDS + SETTLE_SECONDS, about 80 s plus
the time each census takes).
- REST (ruling "Ruling (b), rest counts"): the boot's rest counts (opens,
  handles) are its first reading with draining 0 and THREE consecutive equal
  samples, taken after its own first sessions, by the base class for every
  CportsMatrix harness (stable() takes it before the boot's first judged
  census, and again after each restart; cports also takes it explicitly
  after its session probes and in cut()): CPORTS RESOURCES REST boot=<n> ::
  draining=0 opens=<o> handles=<h>. Rest may later be LOWERED, never
  raised: a judged census that settles (draining 0, two equal samples) with
  handles or opens below the rest count lowers it to that value (CPORTS
  RESOURCES REST LOWERED boot=<n> :: <field> <old> -> <new> (earlier
  censuses of this boot were judged against <old>)), and the run's summary
  carries a CPORTS RESOURCES RECORDED line naming every lowering (not a
  failure). A reading above rest never raises it.
- AT REST: a sample whose draining is 0, whose opens and handles equal the
  rest counts, and which equals its predecessor on every judged field
  (images, frames, kernel line, objects, heap peak, opens, draining). The
  FIRST such sample is judged: a transient that returns to rest within the
  window is not a change. The N5 shape of bisect run A (66 -> 67 -> 67 ->
  ... -> 66) is judged at 66, and an fsd heap peak of 20, 24, 20, 20 is
  judged at 20: a heap reading that lasts one sample between settles is a
  transient, not charged (it is recorded, below). The heap peak is not a
  rest field: a heap-peak reading that holds for two consecutive samples at
  a settle (with the rest fields at rest) is judged and charged, whatever
  follows (20, 24, 24, 20 is judged at 24).
- SETTLED CHANGE: no sample at rest within the window, but some consecutive
  pair agreed with draining 0 (after any lowering above): the LAST such reading is judged, and the
  existing checks fail it: a persistent +1 handle fails the kernel-objects
  check (resources before/after <case> ... kernel objects ... unchanged,
  the repeat round's, or "kernel objects unchanged (handles at the boot's
  rest count)"), opens above rest fail "the file server's opens unchanged
  (at the boot's rest count)", an oscillation that never returns to rest
  fails on whatever its last settled reading shows.
- UNSETTLED: draining never 0, or no consecutive pair ever agreed: the run
  fails with its own check text naming the fields (CPORTS RESOURCES
  UNSETTLED <case> :: <fields>; "UNSETTLED <fields> never settled").
- TRANSIENT: every judged census that needed re-sampling prints one CPORTS
  RESOURCES TRANSIENT <case> [when] :: <field v, field v, ...> line naming
  every off-rest or off-judged value seen (draining, opens, handles, kernel,
  fsd heap, frames, images, objects), e.g. `fsd heap 24`.
- compare_census does not sample again for these censuses (the Task 13
  re-sample of a refused reading is withdrawn for them): the judged reading
  is judged as is. Two equal samples 1 s apart can still sit inside a
  longer oscillation; the fsd fields are last-settle snapshots.
No tolerance, no allowance, no skip. A census without the fsd keys (none
of the harnesses takes one; the self-test's synthetic readings) keeps the
earlier rule: two readings agreeing within 20 s, else the last
(CPORTS RESOURCES TRANSIENT per differing pair), and the Task 13 re-sample
of a refused reading for up to 60 s (CPORTS RESOURCES SETTLED <case> after
<n> s :: <what differed>), else the check fails as before.
Census ruling (a), what a heap-peak step means: the exact equality of the
file server's heap_pages_peak proves an unchanged mapped total at the
sampled settle and nothing finer. A rise is pooled growth (MIN_GROW_PAGES =
4 pages per minimum growth; an over-aligned or >64-page request grows the
pool by other amounts, runtime/src/allocator.rs), a dedicated >= 4 KiB block
alive at the reading, or both, and an R16 pooled unmap can offset one.
Every fsd heap step the harness reports (the HIGHWATER line, the
UNREPEATABLE and repeat-round failures, the frames-only STEP check, the
restart rounds and the census deltas) prints `fsd heap peak <a> -> <b>
(<n> pages, <class>)`: "pool-sized" for a rise that is a multiple of 4,
"not pool-sized (a dedicated block, or over-aligned or >64-page pool
growth)" for any other rise, "released" for a fall, and `<b> (equal)` for
none. The classification is information only: the verdict on any
post-baseline step is unchanged (it fails, no tolerance).
Frames-only moves (controller ruling 2; SPEC A15, sshd's bounded
connection-table growth): when images, kernel objects, the file server's
heap peak (FSD CAPACITY heap_pages_peak) and every file are equal, a growth
of the frame count is a step against one allowance per boot of at most
STEP_BOUND (5) frames in all (CPORTS RESOURCES STEP <case> +<n>
cumulative=<m>/5); the first-concurrent-session warmup is one such step.
The counter resets with the baseline retaken after a restart.
The first time two sessions are open at once the kernel keeps one frame
(the kit's warmup observation): provoked once before the first scenario
(CPORTS FRAMES WARMUP) and counted as a step of the allowance above. absd-sh reports a non-zero status on its
own stderr (`absd-sh: <program>: exit status <n>`): that last line is
required and removed before comparison (CPORTS SHELL STATUS LINE).

lua.all (SPEC A20): predicted, with the empty environment both sides stop
at files.lua:8; streams equal after normalization, status equal and
non-zero, `testing files` absent, the last file marker
`***** FILE 'files.lua'*****`. Observed in Stage 2: Linux stops there, ABSD
stops earlier at literals.lua:298 on the kit defect R14, so lua.all is a
DEFECT pin (absd-expected/DEFECTS) and is judged by its prefix rule
(DEFECT_PREFIX: ABSD's output before the stop equals Linux's).

Scenarios (route `scenario`) run `scenario_<PROGRAM>`.
`lock-contention`: A holds the probe's whole-file lock in a held session,
B tries twice around A's session being killed; the Linux twin uses host
processes (A killed with SIGKILL). SQLite (SQLITE-VFS.md 8-10, SPEC A7, A10,
A17): `excl-contention deny` (B refused in under 5 s while A is in a
transaction, still refused after A's COMMIT, granted after A's .quit),
`kill-holder` (B granted after A's session is killed; directory listing
compared with Linux, a difference a CPORTS SCENARIO NOTE), `crash-recover`
(QEMU stopped at SPILLED, the image copied, next boot B recovers the hot
journal), `power-cut` (form a: committed rows survive, uncommitted absent),
`excl-concurrency-loss` (Linux unix reader succeeds, unix-excl readers on
both systems refused). A stopped boot is followed by
AbsdTarget.start(expect_sweep=True). Databases copied out of an image (the
copy before recovery: database and journal; the live image after it) go to
<work>/host-reader/<label>/ and are read by Python's sqlite3 module
(`python3 -I`). A deny that does not deny, a kill that does not release, or
a recovery outside the expected one prints CPORTS SQLITE LOCK FAILED (power
cut: CPORTS SQLITE POWER-CUT FAILED) and fails the run; the A17 line
CPORTS SQLITE LOCK :: denied= released_on_death= hot_journal_recovered=
sums the three. speedtest1 cases are followed by an extra session's
PRAGMA integrity_check on both sides (CPORTS SQLITE INTEGRITY OK);
sqlite.speedtest1-20 past its timeout is CPORTS LIMIT with the measured
time, not a failure.
Timeouts: any other shell case's timed-out session leaves what sshd
delivered before the client was killed in <case>.absd.out/.absd.err and
`timeout <seconds>` in <case>.absd.status (CPORTS TIMEOUT OUTPUT). A case
annotated in cases.tsv `# defect-on-timeout NAME: ID` (the colon may be
omitted: `# defect-on-timeout NAME ID`; ID one word, e.g. R15; after the
case's row) is then a known defect, not a failure: it must be a shell case
listed in DEFECTS whose text names ID, never in LIMIT_ON_TIMEOUT. Its
session must be reclaimed, its Linux twin runs (<case>.linux.*), the
DEFECT_PREFIX rule is applied to the partial output (normalized stdout
through ABSD's last progress line equal to Linux's, ABSD's partial stderr
a prefix of Linux's), and it prints CPORTS DEFECT PREFIX OK <case>
lines=<n> ... (timeout ...), CPORTS DEFECT TIMEOUT <case> id=<ID>
seconds=<timeout> lines=<n> and CPORTS DEFECT <case> :: <DEFECTS text>;
the census before and after is judged as for any case. Its pin
(<case>.txt) is neither compared nor written on this path: the partial
output depends on how far the timeout let it run. Without the annotation a
timeout still fails the run (CPORTS MATRIX FAILED: session timed out ...).
Prefix-judged limits: a case annotated in cases.tsv
`# limit-prefix NAME: ID FILE "MESSAGE"` (colon optional; ID and FILE one
word each, e.g. `# limit-prefix lua.all: CPA-060 locals.lua "not enough
memory"`) is a NATIVE LIMIT divergence whose stop point varies (GC timing),
so its pin is not byte-exact. It must be a shell case listed in
divergences.txt and not in DEFECTS (else the load fails). It is judged by
the DEFECT_PREFIX machinery instead of its pin: ABSD's normalized stdout
through its last progress line equal to Linux's prefix, ABSD's stderr
before the program's error line equal to Linux's, and in addition the last
`***** FILE '<f>'*****` marker before the stop names FILE, ABSD's stderr
(absd-sh's status line already removed) ends with MESSAGE (trailing
newlines ignored), and the status is non-zero. It prints CPORTS DIVERGES
PREFIX OK <case> :: NATIVE LIMIT <ID> stop_file=<f> lines=<n> status=<s>
then CPORTS DIVERGES <case> :: <divergences.txt reason>. A stop in another
file, a missing message, status 0 or a prefix that differs prints CPORTS
LIMIT PREFIX MISMATCH <case> :: <what> and fails the run. The <case>.txt
pin is neither compared nor written on this path (--pin of such a case
writes nothing). A divergence without the annotation keeps the pin rule. A scenario with no method fails the run
unless --skip-scenarios (then CPORTS SCENARIO SKIPPED, counted as a limit).
Route `probe` runs on ABSD only and is recorded (probe.env: the session's
environment, which must be empty).

Markers: CPORTS ARGS <argv> (first line); CPORTS IMPORT files= bytes= boots=; CPORTS ONE.BIN sha256=;
CPORTS IMAGE capacity=; CPORTS LIMIT ...; CPORTS SESSION ENV count=;
CPORTS CASE OK <name>; CPORTS DIVERGES <name> :: <reason>; CPORTS DEFECT
<name> :: <reason>; CPORTS PIN WRITTEN <path>; CPORTS OUTPUT OK <name>
<path> sha256=; CPORTS OUTPUT OK <name> <path> decompresses; CPORTS
RESOURCES <name> :: ...; CPORTS RESOURCES HIGHWATER/REPEAT OK; CPORTS FRAMES
WARMUP; CPORTS LUA testing_lines=<n> stop=<file:line>;
CPORTS SCENARIO OK <name>; CPORTS SCENARIO REPEAT <name> round=<k>; CPORTS SCENARIO NOTE <name>; CPORTS SCENARIO SKIPPED <name>;
CPORTS CUT <name>; CPORTS RESOURCES REBASE <name>; CPORTS RESOURCES RESTART ROUND/REPEAT <name>; CPORTS RESOURCES SETTLED <name>; CPORTS RESOURCES REST boot=<n>; CPORTS RESOURCES REST LOWERED boot=<n>; CPORTS RESOURCES RECORDED; CPORTS RESOURCES UNSETTLED <name>; CPORTS RESOURCES TRANSIENT <name>; CPORTS HOST READER <label>;
CPORTS SQLITE INTEGRITY OK <name>; CPORTS SQLITE VERIFY <name> :: <hash line>; CPORTS SQLITE LOCK [FAILED] ...; CPORTS SHELL OK
cases= agree= diverge= defects= scenarios= probes= limits=; CPORTS
RESOURCES OK cases= highwater= repeat=; CPORTS DEFECT PREFIX OK <name>
lines=; CPORTS DEFECT TIMEOUT <name> id= seconds= lines=; CPORTS DIVERGES
PREFIX OK <name> :: NATIVE LIMIT <id> stop_file= lines= status=; CPORTS LIMIT
PREFIX MISMATCH <name> :: ...; CPORTS TIMEOUT
OUTPUT <name> ...; CPORTS MATRIX OK seconds=."""
import argparse, hashlib, os, pathlib, re, select, shutil, signal, subprocess, sys, threading, time
here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import ssh_absd  # noqa: E402
import cports_warm as cw  # noqa: E402
import types
import absd_fs  # noqa: E402
import importlib.util  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), here / f"{name}.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


sm = load("ssh-matrix")
ck = load("c-kit-matrix")

# A harness fixture, not a platform limit (controller ruling, Task 11): the
# filesystem region is the second half of the device (absd_image.parse_layout),
# so 128 MiB gives about 64 MiB of filesystem, room for speedtest1 --size 20.
IMAGE_BYTES = 128 * 1024 * 1024
# Census ruling (b): the judged census samples through AGREE_SECONDS +
# SETTLE_SECONDS; a census without the fsd keys keeps the Task 13 re-sample of
# a refused reading for SETTLE_SECONDS (CPORTS RESOURCES SETTLED).
SETTLE_SECONDS = 60
# The judged census's agreement wait; with SETTLE_SECONDS, its whole settle window (ruling (b)).
AGREE_SECONDS = 20
# The file server's pool grows by at least MIN_GROW_PAGES pages
# (runtime/src/allocator.rs). Census ruling (a) labels a heap_pages_peak rise
# that is a multiple of it "pool-sized", any other rise "not pool-sized (a
# dedicated block, or over-aligned or >64-page pool growth)", a fall
# "released"; information only, never a verdict.
MIN_GROW_PAGES = 4
HANDLES = re.compile(r"(\d+) handles")
FSD_CAPACITY = re.compile(r"FSD CAPACITY [^\n]*\bopens=(\d+) draining=(\d+) heap_pages_peak=(\d+)")


def heap_step(a, b):
    """Census ruling (a): an fsd heap_pages_peak step with its size in pages
    and its class. Equality proves an unchanged mapped total at the sampled
    settle and nothing finer. A rise that is a multiple of MIN_GROW_PAGES is
    "pool-sized" (one or more minimum pool growths, or a dedicated block of
    that size); any other rise is "not pool-sized" (a dedicated block, or an
    over-aligned or >64-page pool growth, runtime/src/allocator.rs); a fall
    is "released". Printed, never judged (any post-baseline step fails)."""
    if a == b:
        return f"{b} (equal)"
    if a is None or b is None:
        return f"{a} -> {b}"
    n = b - a
    if n < 0:
        kind = "released"
    elif n % MIN_GROW_PAGES == 0:
        kind = "pool-sized"
    else:
        kind = "not pool-sized (a dedicated block, or over-aligned or >64-page pool growth)"
    return f"{a} -> {b} ({n:+d} pages, {kind})"


def handles(kernel):
    m = HANDLES.search(kernel or "")
    return int(m.group(1)) if m else None
CPORTS = "/home/operator/cports"
TREES = {"lua-tests": ("lua-tests", "absd", "lua-5.4.9-tests")}   # CWD -> upstream/<name>/<side>/<dir>
DEFAULT_TIMEOUT = 600
EXTRA = ["mkdir", "cat", "df", "sysinfo", "ls"]
# The full digest of one.bin, recorded by the first run of this harness
# (2026-10-11); the research phase's `6ee9c255...` (CPORTS-HARNESS.md 5.2) is
# not the digest of the file the specified generator makes (see the receipt).
ONE_BIN_SHA256 = "7eaa7b66e998295ce12e21cec95e4263c6a0b69417b6629953533c2daf72531d"
# Cases whose effect the next listed case undoes (gzip, then gunzip of the same
# file): the only cases the repeat round can run again on the same image state.
REPEATABLE = {"zlib.gzip-1m": "zlib.gunzip-1m", "zlib.gunzip-1m": "zlib.gzip-1m",
              "zlib.gzip-8m": "zlib.gunzip-8m", "zlib.gunzip-8m": "zlib.gzip-8m"}
# Scenarios whose run leaves the file set it started from (posix.lock-contention:
# the probe's lock file `l` is retained, nothing produced), so the repeat round
# can run them again with the same scenario method: they may take the
# high-water allowance, proven like a pair's (each round's census, the file
# server's heap peak included, equal to the census before the rounds).
REPEAT_SCENARIOS = {"posix.lock-contention"}
# A DEFECT pin is also checked against the Linux twin up to the defect: ABSD's
# normalized stdout through its last progress line, and its stderr up to the
# program's own error line, must be prefixes of Linux's (per program).
DEFECT_PREFIX = {"/bin/lua": (rb"^(\*\*\*\*\* FILE |testing ).*\n", b"/bin/lua: ")}
# A DEFECT that follows a declared divergence in the same case has its own
# check of the part before the defect (CPORTS DEFECT PREFIX OK), by case name.
TEMP_NOMEM_DECLARED = b"Error near line 10 of temp-nomem.sql: out of memory\n"
GUNZIP = "import gzip,sys; sys.stdout.buffer.write(gzip.open(sys.argv[1]).read())"
# Chains: cases of one CWD that rebuild their files from nothing once `reset`
# is removed (speedtest1 deletes its own database first, speedtest1.c:3241-3253).
# The repeat round removes `reset` with /bin/rm and runs the chain again in
# order; each run must print what it printed the first time. A case in a chain
# may take the high-water allowance.
CHAINS = [
    {"cwd": "sqlite", "reset": ["t.db", "t.db-journal"],
     "cases": ["sqlite.create-insert", "sqlite.index", "sqlite.rollback", "sqlite.vacuum"]},
    {"cwd": "sqlite-nomem", "reset": ["n.db", "n.db-journal"], "cases": ["sqlite.temp-nomem"]},
    {"cwd": "speedtest", "reset": [], "cases": ["sqlite.speedtest1-5"]},
    {"cwd": "speedtest", "reset": [], "cases": ["sqlite.speedtest1-20"]},
]
CHAIN_OF = {name: chain for chain in CHAINS for name in chain["cases"]}
# An extra session after the case, on the database it left (both sides): database, SQL, expected stdout.
INTEGRITY = {"sqlite.speedtest1-5": ("s5.db", "PRAGMA integrity_check;", b"ok\n"),
             "sqlite.speedtest1-20": ("st.db", "PRAGMA integrity_check;", b"ok\n"),
             "sqlite.temp-nomem": ("n.db", "PRAGMA integrity_check; SELECT count(*) FROM t;", b"ok\n1\n")}
# Controller ruling 2 (Task 12 fix round 0): a census move of the frame count
# alone (images, kernel objects, the file server's heap peak and every file
# equal) is sshd's bounded growth (SPEC A15: its connection-table Vec, at most
# +4 pages, closed as not a leak). One allowance per boot, merging the former
# one-time frames warmup: cumulative growth of at most STEP_BOUND frames, each
# step printed (CPORTS RESOURCES STEP); the counter resets with the baseline
# taken after a restart. Repeat rounds stay exact.
STEP_BOUND = 5
# Controller ruling 1 (Task 12 fix round 0): a scenario that stops QEMU runs
# twice; round 2 first removes these files with /bin/rm (as chains do), then
# repeats the whole stop/restart scenario; the census after each round must be
# equal (CPORTS RESOURCES RESTART ROUND). excl-crash removes nothing: its
# scenario needs the table the earlier excl cases left (3 rows), and round 1
# ends with exactly that state (the hot journal rolled back and deleted).
RESTART_ROUNDS = {"sqlite.excl-crash": [], "sqlite.power-cut": ["cut.db", "cut.db-journal"]}
# A case whose timeout is a named limit with the measured partial time, not a failure.
LIMIT_ON_TIMEOUT = {"sqlite.speedtest1-20"}
# The scenarios' sqlite3 sessions name the case directory's empty init file last
# (argument positions unchanged), as the cases do: the ~/.sqliterc lookup differs
# (getpwuid NULL and no HOME on ABSD) and is its own case, sqlite.home.
SQLITE_INIT = ["-init", "empty.sqliterc"]
# Cases whose Linux twin gets HOME=<work>/linux-home (empty), see linux_home.
LINUX_EMPTY_HOME = {"sqlite.home"}
B_TIMEOUT = 60      # a B session's timeout (the brief: 60 s; the native lock never waits)
SQLITE_LOCKED = b"Parse error in 5th command line argument: database is locked (5)\n"
# The independent reader of databases copied out of an image (Python's sqlite3
# module, the host's own library): one line per row, columns joined by "|".
HOST_READER = ("import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); "
               "print(sqlite3.sqlite_version, file=sys.stderr); "
               "[print('|'.join(str(v) for v in r)) for q in sys.argv[2:] for r in c.execute(q).fetchall()]; c.close()")


class SessionTimeout(sm.Failed):
    """A session that outlived its timeout, with what it printed so far."""
    def __init__(self, message, out, err, seconds):
        super().__init__(message)
        self.out, self.err, self.seconds = out, err, seconds


class Case:
    def __init__(self, fields):
        self.name, self.route, self.cwd, self.stdin, self.env, self.program, *self.args = fields
        self.outputs, self.retained, self.removed, self.expect, self.timeout = [], [], [], "", DEFAULT_TIMEOUT
        self.defect_on_timeout = None       # the DEFECTS id of a timeout that is a known defect
        self.limit_prefix = None            # (id, file, message) of a prefix-judged NATIVE LIMIT divergence


# "# defect-on-timeout NAME: ID" (colon optional): a timeout of NAME is the
# known defect ID (CPORTS DEFECT TIMEOUT), not a failure.
DEFECT_ON_TIMEOUT = re.compile(r"# defect-on-timeout (\S+?):? (\S+)")
# "# limit-prefix NAME: ID FILE \"MESSAGE\"" (colon optional): NAME is a
# NATIVE LIMIT divergence judged by its prefix, its stop in FILE, its stderr
# ending with MESSAGE and a non-zero status (CPORTS DIVERGES PREFIX OK).
LIMIT_PREFIX = re.compile(r'# limit-prefix (\S+?):? (\S+) (\S+) "([^"]+)"')
FILE_MARK = re.compile(rb"^\*\*\*\*\* FILE '([^']+)'\*\*\*\*\*$", re.M)


def load_cases(path):
    cases, by_name = [], {}
    for line in path.read_text().splitlines():
        if line.startswith("# defect-on-timeout"):
            m = DEFECT_ON_TIMEOUT.fullmatch(line.rstrip())
            sm.require(m is not None, f"malformed annotation (want '# defect-on-timeout NAME: ID'): {line!r}")
            name, ident = m.groups()
            sm.require(name in by_name, f"# defect-on-timeout names no earlier case: {name}")
            sm.require(by_name[name].defect_on_timeout is None, f"two # defect-on-timeout lines for {name}")
            by_name[name].defect_on_timeout = ident
            continue
        if line.startswith("# limit-prefix"):
            m = LIMIT_PREFIX.fullmatch(line.rstrip())
            sm.require(m is not None, f"malformed annotation (want '# limit-prefix NAME: ID FILE \"MESSAGE\"'): {line!r}")
            name, ident, stop_file, message = m.groups()
            sm.require(name in by_name, f"# limit-prefix names no earlier case: {name}")
            sm.require(by_name[name].limit_prefix is None, f"two # limit-prefix lines for {name}")
            by_name[name].limit_prefix = (ident, stop_file, message)
            continue
        m = re.match(r"# (outputs|retained|removed|expect|timeout) (\S+): (.*)$", line)
        if m:
            kind, name, rest = m.groups()
            case = by_name[name]                     # a directive must follow its case row
            if kind == "expect": case.expect = rest
            elif kind == "timeout": case.timeout = int(rest)
            else: getattr(case, kind).extend(rest.split())
            continue
        if not line.strip() or line.startswith("#"): continue
        case = Case(line.split("\t")); cases.append(case); by_name[case.name] = case
    return cases


def one_bin():
    out, h, i = bytearray(), hashlib.sha256(b"absd-cports-zlib"), 0
    while len(out) < 1048576:
        h = hashlib.sha256(h.digest()); out += f"line {i:07d} {h.hexdigest()[:24]}\n".encode(); i += 1
    return bytes(out[:1048576])


def normalize(data, patterns):
    for p in patterns: data = p.sub(b"<n>", data)
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


class CportsTarget(ssh_absd.AbsdTarget):
    def files(self, authorized):
        files = super().files(authorized)
        have = {path for path, _ in files}
        files += [(f"/bin/{name}", (self.root / "commands" / name).read_bytes()) for name in EXTRA
                  if f"/bin/{name}" not in have]
        files += [(f"/bin/{p.name}", p.read_bytes()) for p in self.products]
        files += self.case_files
        return files

    def tree(self):
        for attempt in range(20):
            try:
                return super().tree()
            except ssh_absd.absd_fs.Refused:
                time.sleep(0.5)
        raise ssh_absd.Failed("the host reader never found a committed image")


class CportsMatrix(ck.KitMatrix):
    # Count held sessions too, and reset the count at each guest restart.
    # An ordinary census starts only after all sessions of this boot have
    # been reclaimed; the deliberate held-session probe still uses ssh().
    QUIESCENT_READINGS = True

    def __init__(self, target, work, args):
        self.repo = here.parent
        self.absd = pathlib.Path(args.absd).resolve()
        self.linux = pathlib.Path(args.linux).resolve()
        self.upstream = pathlib.Path(args.upstream).resolve()
        table_path = pathlib.Path(args.cases).resolve()
        self.cports = table_path.parent
        self.expected = self.cports / "absd-expected"
        self.pin = set(args.pin or [])
        self.skip_scenarios = args.skip_scenarios
        every = load_cases(table_path)
        names = [c.name for c in every]
        sm.require(len(names) == len(set(names)), f"duplicate case names in {table_path}")
        self.cases = [c for c in every if not args.only or any(c.name.startswith(p) for p in args.only)]
        sm.require(self.cases, f"no case matches --only {args.only}")
        sm.require(self.pin <= set(names), f"--pin names no case: {sorted(self.pin - set(names))}")
        for c in every:
            sm.require(c.env == "-", f"{c.name}: ENV must be - on the shell route")
        self.divergences = ck.table(self.cports / "divergences.txt")
        self.defects = ck.table(self.expected / "DEFECTS")
        sm.require(set(self.defects) <= set(names), f"DEFECTS names no case: {sorted(set(self.defects) - set(names))}")
        sm.require(not set(self.defects) & set(self.divergences),
                   f"a case is both a DEFECT and a divergence: {sorted(set(self.defects) & set(self.divergences))}")
        stray = sorted(p.name for p in self.expected.glob("*.txt") if p.stem not in names) if self.expected.exists() else []
        sm.require(not stray, f"absd-expected pins for no case of cases.tsv: {stray}")
        sm.require(set(self.divergences) <= set(names), f"divergences.txt names no case: {sorted(set(self.divergences) - set(names))}")
        for c in every:
            if c.defect_on_timeout is not None:
                self.require_defect_on_timeout(c)
            if c.limit_prefix is not None:
                self.require_limit_prefix(c)
        self.normalizers = {}
        for line in (self.cports / "normalize.tsv").read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            name, regex = line.split("\t", 1)
            sm.require(name in names, f"normalize.tsv names no case: {name}")
            self.normalizers.setdefault(name, []).append(re.compile(regex.encode(), re.M))
        # Products: the executables of --absd (no suffix), each with its Linux twin.
        products = sorted(p for p in self.absd.iterdir() if p.is_file() and "." not in p.name)
        for p in products:
            sm.require((self.linux / p.name).is_file(), f"no Linux reference build {self.linux / p.name}")
        target.products = products
        # The case directories' files, for the image and for the Linux twin.
        self.one = one_bin()
        self.dirs = {}
        for cwd in dict.fromkeys(c.cwd for c in every):
            entries = []
            data = self.cports / "data" / cwd
            if data.is_dir():
                entries += [(p.relative_to(data).as_posix(), p.read_bytes()) for p in sorted(data.rglob("*")) if p.is_file()]
            if cwd in TREES:
                name, side, sub = TREES[cwd]
                tree = self.upstream / name / side / sub
                sm.require(tree.is_dir(), f"no upstream tree {tree}")
                entries += [(p.relative_to(tree).as_posix(), p.read_bytes()) for p in sorted(tree.rglob("*")) if p.is_file()]
            if cwd == "zlib":
                entries.append(("one.bin", self.one))
            self.dirs[cwd] = entries
        target.case_files = [(f"{CPORTS}/{cwd}/{rel}", data) for cwd, entries in self.dirs.items() for rel, data in entries]
        sm.Matrix.__init__(self, target, work)

    # -- sessions ------------------------------------------------------------------

    def shell_ssh(self, text, stdin=b"", timeout=DEFAULT_TIMEOUT, baseline=0):
        """KitMatrix.shell_ssh with a timeout, and with `baseline` image
        processes that stay alive (a held session's) after this one ends."""
        sessions = len(re.findall(r"SSH SESSION CHILD ", self.t.output()))
        done = self.reclaimed()
        try:
            rc, out, err = self.ssh(text, stdin=stdin, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise SessionTimeout(f"session timed out after {timeout} s: {text[:120]!r}", e.stdout or b"",
                                 e.stderr or b"", timeout)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and (self.reclaimed() <= done or self.t.all_images() != baseline):
            time.sleep(0.2)
        self.check(f"session reclaimed after {text[:60]!r}", self.reclaimed() > done and self.t.all_images() == baseline,
                   self.t.census_detail())
        child = re.findall(r"SSH SESSION CHILD pid=(\d+) spawn_right=(\w+) argv0=(\S+) [^\n]*control=(\w+)",
                           self.t.output())[sessions:]
        self.check(f"the session ran absd-sh with the spawn right: {text[:60]!r}",
                   len(child) == 1 and child[0][1:] == ("true", "/bin/absd-sh", "true"), str(child))
        shell = child[0][0]
        programs = re.findall(rf"SPAWN OK pid=(\d+) parent={shell} program=image", self.t.serial())
        return rc, out, err, shell, programs

    def hold(self, text):
        """A session kept open: returns the Popen; stdout is read incrementally by await_line."""
        self.connections += 1
        p = subprocess.Popen(self.client.base(self.op) + [text], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        p.seen = b""
        return p

    def await_line(self, p, line, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if line in p.seen.splitlines(): return True
            r, _, _ = select.select([p.stdout], [], [], 0.5)
            if r:
                chunk = os.read(p.stdout.fileno(), 4096)
                if not chunk: break
                p.seen += chunk
        sm.require(False, f"{line!r} did not arrive: seen={p.seen!r}")

    def finish_session(self, p, timeout=120):
        """Closes A's stdin and waits for its session to end by itself and be reclaimed: (rc, out, err)."""
        done = self.reclaimed()
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill(); p.communicate()
            raise sm.Failed(f"the held session did not end within {timeout} s after its input ended: {p.seen!r}")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and (self.reclaimed() <= done or self.t.all_images() != 0): time.sleep(0.2)
        self.check("the held session ended normally and was reclaimed", self.reclaimed() > done and self.t.all_images() == 0,
                   self.t.census_detail())
        return p.returncode, p.seen + out, err

    def feed(self, p, data):
        """Writes `data` to a held session's stdin from a thread (a large
        input must not block the reader of its output)."""
        def write():
            try:
                p.stdin.write(data); p.stdin.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass
        th = threading.Thread(target=write, daemon=True); th.start()
        return th

    def end_session(self, p):
        """Kills the client (the session ends without the program unlocking anything) and waits for sshd's reclaim."""
        done = self.reclaimed(); p.kill(); p.wait()
        for pipe in (p.stdin, p.stdout, p.stderr):
            pipe.close()
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline and (self.reclaimed() <= done or self.t.all_images() != 0): time.sleep(0.2)
        self.check("the held session was reclaimed and its program ended", self.reclaimed() > done and self.t.all_images() == 0,
                   self.t.census_detail())

    def text(self, case, program=None, args=None):
        words = [program or case.program, *(case.args if args is None else args)]
        return f"cd {CPORTS}/{case.cwd}; " + " ".join(ck.quote(w) for w in words)

    def objects(self):
        return {o[0]: o for o in self.t.system_objects()}

    def fsd_peak(self):
        """The file server's own heap peak, its last `FSD CAPACITY ... heap_pages_peak=` line this boot."""
        peaks = re.findall(r"FSD CAPACITY [^\n]*heap_pages_peak=(\d+)", self.t.serial())
        return int(peaks[-1]) if peaks else None

    def fsd_capacity(self):
        """The file server's last `FSD CAPACITY` line this boot: (opens,
        draining, heap_pages_peak), or Nones when there is none."""
        lines = FSD_CAPACITY.findall(self.t.serial())
        return tuple(int(x) for x in lines[-1]) if lines else (None, None, None)

    def census(self):
        census = super().census()
        opens, draining, _ = self.fsd_capacity()
        census["fsd"] = self.fsd_peak()
        census["fsd_opens"], census["fsd_draining"] = opens, draining
        if os.environ.get("ABSD_CPORTS_DIAG_REPEAT_ROUNDS") is not None:
            lines = re.findall(r"FSD CAPACITY [^\n]*", self.t.serial())
            fields = dict(re.findall(r"(\w+)=(\d+)", lines[-1])) if lines else {}
            census["fsd_free"] = int(fields["heap_free_pages"]) if "heap_free_pages" in fields else None
            census["settled"] = int(fields["settled_releases"]) if "settled_releases" in fields else None
        return census

    JUDGED = ("images", "memory", "kernel", "objects", "fsd", "fsd_opens", "fsd_draining")

    @staticmethod
    def differs(before, after):
        """Two samples differ on a judged field (the kit's fields plus the
        file server's heap peak, opens and draining)."""
        return any(before.get(k) != after.get(k) for k in CportsMatrix.JUDGED)

    @staticmethod
    def fsd_keyed(census):
        """A census CportsMatrix.census took (every CportsMatrix harness's:
        cports, tcc, clang, userland), as opposed to a census without the
        file server's keys, which keeps the earlier rule."""
        return "fsd_draining" in census

    @staticmethod
    def drained(census):
        return census["fsd_draining"] == 0

    def rest_handles(self, census):
        """Whether the kernel's handles equal the boot's rest count (true
        when no rest count is taken: a harness that takes none, or the
        reading that takes it)."""
        rest = getattr(self, "rest", None)
        return rest is None or handles(census["kernel"]) == rest["handles"]

    def rest_fields_ok(self, census):
        """At rest: draining 0, opens and handles at the boot's rest counts."""
        rest = getattr(self, "rest", None)
        return self.drained(census) and (rest is None or (census["fsd_opens"] == rest["opens"]
                                                          and handles(census["kernel"]) == rest["handles"]))

    def rest_opens(self, where, census):
        """A judged reading whose opens differ from the boot's rest count is
        a settled change: the opens check fails."""
        rest = getattr(self, "rest", None)
        if rest is None or "fsd_opens" not in census:
            return
        self.check(f"{where}: the file server's opens unchanged (at the boot's rest count {rest['opens']})",
                   census["fsd_opens"] == rest["opens"], f"opens {rest['opens']} -> {census['fsd_opens']}")

    def rest_kernel(self, where, census):
        """A judged reading whose handles differ from the boot's rest count is
        a kernel-object change (where no before/after comparison holds it)."""
        rest = getattr(self, "rest", None)
        if rest is None:
            return
        self.check(f"{where}: kernel objects unchanged (handles at the boot's rest count {rest['handles']})",
                   self.rest_handles(census), f"handles {rest['handles']} -> {handles(census['kernel'])}")

    def offs(self, seen, judged):
        """The TRANSIENT record: every value seen in `seen` that was off rest
        (draining not 0, opens or handles not at the rest counts) or off the
        judged reading, by field, in the order first seen."""
        rest = getattr(self, "rest", None)
        got = {}

        def add(field, value):
            got.setdefault(field, [])
            if value not in got[field]:
                got[field].append(value)
        for c in seen:
            if c["fsd_draining"] != 0 or c["fsd_draining"] != judged["fsd_draining"]:
                add("draining", c["fsd_draining"])
            if c["fsd_opens"] != judged["fsd_opens"] or (rest is not None and c["fsd_opens"] != rest["opens"]):
                add("opens", c["fsd_opens"])
            h = handles(c["kernel"])
            if h != handles(judged["kernel"]) or (rest is not None and h != rest["handles"]):
                add("handles", h)
            if HANDLES.sub("", c["kernel"]) != HANDLES.sub("", judged["kernel"]):
                add("kernel", c["kernel"])
            if c["fsd"] != judged["fsd"]:
                add("fsd heap", c["fsd"])
            if c["memory"] != judged["memory"]:
                add("frames", self.allocated(c["memory"]))
            if c["images"] != judged["images"]:
                add("images", c["images"])
            if c["objects"] != judged["objects"]:
                add("objects", f"{len(c['objects'])} (contents differ)" if len(c["objects"]) == len(judged["objects"])
                    else len(c["objects"]))
        return ", ".join(f"{field} {v}" for field, values in got.items() for v in values) or "nothing off"

    @staticmethod
    def changed_fields(a, b):
        """The judged fields two consecutive samples differ in (handles
        named on their own), for an UNSETTLED line."""
        names = {"memory": "frames", "fsd": "fsd heap peak", "fsd_opens": "opens", "fsd_draining": "draining"}
        what = []
        for k in CportsMatrix.JUDGED:
            if a.get(k) == b.get(k):
                continue
            if k == "kernel" and handles(a["kernel"]) != handles(b["kernel"]):
                what.append(f"handles {handles(a['kernel'])} -> {handles(b['kernel'])}")
                if HANDLES.sub("", a["kernel"]) == HANDLES.sub("", b["kernel"]):
                    continue
            what.append(f"{names.get(k, k)} {len(a[k]) if k == 'objects' else a.get(k)} -> "
                        f"{len(b[k]) if k == 'objects' else b.get(k)}")
        return what

    def take_rest(self, label):
        """Census ruling (b), rest counts: the boot's rest counts are its
        first reading with draining 0 and THREE consecutive equal samples,
        taken after the boot's own first sessions (every CportsMatrix
        harness: stable() takes it before the boot's first judged census,
        and cports also takes it after its session probes and in cut()),
        printed once per boot. A later judged census may LOWER it, never
        raise it (stable)."""
        self.rest, self.taking_rest = None, True
        try:
            r = self.stable("rest", label)
        finally:
            self.taking_rest = False
        self.rest = {"opens": r["fsd_opens"], "handles": handles(r["kernel"]), "boot": self.t.boots}
        self.rest_boot = self.t.boots
        print(f"CPORTS RESOURCES REST boot={self.t.boots} :: draining=0 opens={self.rest['opens']} "
              f"handles={self.rest['handles']} ({label}) | {r['memory']} | {r['kernel']} | images={r['images']} "
              f"objects={len(r['objects'])} fsd_heap_peak={r['fsd']}", flush=True)
        return self.stamp_rest(r)

    def lower_rest(self, where, now):
        """Census ruling (b): a settled reading (draining 0, two equal
        samples) below a rest count lowers it (never raises it): CPORTS
        RESOURCES REST LOWERED, recorded for the run's summary."""
        for field, value in (("handles", handles(now["kernel"])), ("opens", now["fsd_opens"])):
            old = self.rest[field]
            if value is not None and old is not None and value < old:
                self.rest[field] = value
                line = (f"boot={self.t.boots} :: {field} {old} -> {value} (earlier censuses of this boot were "
                        f"judged against {old}; lowered at {where})")
                print(f"CPORTS RESOURCES REST LOWERED {line}", flush=True)
                self.rest_lowered = getattr(self, "rest_lowered", []) + [line]

    def rest_recorded(self):
        """The run summary's RECORDED line naming every lowered rest count
        (not a failure); printed by every CportsMatrix harness's run."""
        lowered = getattr(self, "rest_lowered", [])
        if lowered:
            print(f"CPORTS RESOURCES RECORDED rest lowered {len(lowered)} time(s) (not a failure) :: "
                  + " | ".join(lowered), flush=True)

    def stamp_rest(self, census):
        """Keep the floor at this AT REST judgment, independent of later lowers."""
        rest = getattr(self, "rest", None)
        if rest is not None:
            census = dict(census)
            census["rest_at_judgment"] = dict(rest)
        return census

    def permitted_rest_lowering(self, before, after):
        """Ruling (b)'s downward handle floor, only for two stamped rest readings.

        Raw lines stay unchanged. This is count admission, not object identity
        or an attribution of the decrease to any particular session.
        """
        stamps = [c.get("rest_at_judgment") for c in (before, after)]
        for census, floor in zip((before, after), stamps):
            if not isinstance(floor, dict) or set(floor) != {"boot", "handles", "opens"}:
                return False
            if any(type(floor[k]) is not int or floor[k] < 0 for k in floor):
                return False
            if (floor["boot"] != getattr(self.t, "boots", None)
                    or census.get("images") != 0 or census.get("fsd_draining") != 0
                    or not isinstance(census.get("kernel"), str)
                    or census.get("fsd_opens") != floor["opens"]
                    or handles(census["kernel"]) != floor["handles"]):
                return False
        old, new = stamps
        return (old["boot"] == new["boot"] and old["handles"] > new["handles"]
                and old["opens"] == new["opens"] and new == getattr(self, "rest", None)
                and HANDLES.sub("", before["kernel"]) == HANDLES.sub("", after["kernel"]))

    def comparison_kernels(self, before, after, lowered):
        if lowered and self.permitted_rest_lowering(before, after):
            return tuple(HANDLES.sub("REST handles", c["kernel"]) for c in (before, after))
        return before["kernel"], after["kernel"]

    def frames_step(self, name, before, after, rest_lowering=False):
        """Ruling 2: a frames-only move (images, kernel objects, the file
        server's heap peak and every file equal) counts against the boot's
        cumulative bound of STEP_BOUND frames."""
        n = self.allocated(after["memory"]) - self.allocated(before["memory"])
        bk, ak = self.comparison_kernels(before, after, rest_lowering)
        equal = ((before["images"], bk, before["objects"], before["fsd"])
                 == (after["images"], ak, after["objects"], after["fsd"]))
        self.check(f"{name}: a frames-only move has images, kernel objects, the file server's heap peak and every "
                   f"file equal, and grows", equal and n > 0,
                   f"frames {n:+d} fsd heap peak {heap_step(before['fsd'], after['fsd'])} {before['kernel']} -> "
                   f"{after['kernel']}")
        self.steps += n
        print(f"CPORTS RESOURCES STEP {name} +{n} cumulative={self.steps}/{STEP_BOUND} :: fsd heap peak equal "
              f"({after['fsd']}), objects equal, files equal", flush=True)
        self.check(f"{name}: cumulative frames-only growth this boot within {STEP_BOUND} frames (SPEC A15)",
                   self.steps <= STEP_BOUND, f"cumulative {self.steps}")

    def is_dir(self, path):
        o = self.objects().get(path)
        return o is not None and o[1]

    def ensure_dir(self, cwd):
        for path in (CPORTS, f"{CPORTS}/{cwd}"):
            if self.is_dir(path):
                continue
            rc, out, err, _, _ = self.shell_ssh(f'"/bin/mkdir" {ck.quote(path)}')
            self.check(f"mkdir {path}", rc == 0 and out == b"" and err == b"" and self.is_dir(path),
                       f"rc={rc} {out!r} {err!r}")
            print(f"CPORTS DIR MADE {path}", flush=True)

    # -- resources -----------------------------------------------------------------

    def stable(self, key, when):
        """The judged census (census ruling (b) as ratified by the rule's
        owner, 2026-10-13). Samples are taken once per second through the
        settle window, AGREE_SECONDS (20 s) + SETTLE_SECONDS (60 s), plus the
        time each census takes.
        - JUDGED AT REST: the first sample at rest (the file server's
          draining 0, its opens and the kernel's handles equal to the boot's
          rest counts) and equal to its predecessor on every judged field
          (the rest reading itself, take_rest: draining 0 and three equal
          samples). A transient that returns to rest within the window is
          not a change (bisect run A's 66 -> 67 -> 67 -> ... -> 66 is judged
          at 66). The boot's rest counts are taken first when this boot has
          none (every CportsMatrix harness), and a settled pair below them
          lowers them (lower_rest; never raised).
        - SETTLED CHANGE: no sample at rest, but some consecutive pair agreed
          with draining 0: the last such reading is judged, and the existing
          checks fail it (a persistent +1 handle, opens above rest, an
          oscillation that never returns to rest).
        - UNSETTLED: draining never 0, or no consecutive pair ever agreed:
          the run fails with its own check naming the fields.
        Every judged census that needed re-sampling prints one CPORTS
        RESOURCES TRANSIENT line naming every off-rest or off-judged value
        seen (an fsd heap peak of 20, 24, 20, 20 is judged at 20 and prints
        `fsd heap 24`). A census without the fsd keys keeps the earlier
        rule exactly (old_stable)."""
        first = self.census()
        if not self.fsd_keyed(first):
            return self.old_stable(key, when, first)
        taking = getattr(self, "taking_rest", False)
        if not taking and getattr(self, "rest_boot", None) != getattr(self.t, "boots", None):
            # Every CportsMatrix harness (ruling R1): the boot's rest counts
            # are taken before its first judged census, after its own first
            # sessions (and again after each restart).
            self.take_rest(f"boot {getattr(self.t, 'boots', None)} before its first judged census")
            first = self.census()
        needed = 3 if taking else 2        # the rest reading needs three equal samples
        where = f"{key} {when}" if when else key
        seen, prev, settled, last_pair, run = [first], first, None, None, 1
        start = time.monotonic()
        while time.monotonic() - start < AGREE_SECONDS + SETTLE_SECONDS:
            time.sleep(1)
            now = self.census()
            seen.append(now)
            agree = not self.differs(prev, now)
            run = run + 1 if agree else 1
            if agree and self.drained(now) and not taking and getattr(self, "rest", None) is not None:
                self.lower_rest(where, now)
            if run >= needed and self.rest_fields_ok(now):
                if len(seen) > needed:
                    print(f"CPORTS RESOURCES TRANSIENT {where} :: {self.offs(seen[:-needed], now)} "
                          f"(judged at rest after {len(seen) - 1} samples)", flush=True)
                return now if taking else self.stamp_rest(now)
            if run >= needed and self.drained(now):
                settled = now
            last_pair, prev = (prev, now), now
        if settled is not None:
            print(f"CPORTS RESOURCES TRANSIENT {where} :: {self.offs(seen, settled)} (no sample at rest within "
                  f"{AGREE_SECONDS + SETTLE_SECONDS} s; the last settled reading is judged as a SETTLED CHANGE)",
                  flush=True)
            return settled
        fields = [] if self.drained(prev) else [f"draining {prev['fsd_draining']} (never 0)"]
        if not any(self.drained(c) for c in seen):
            fields = [f"draining {', '.join(str(v) for v in dict.fromkeys(c['fsd_draining'] for c in seen))} (never 0)"]
        elif last_pair is not None:
            fields = [f for f in self.changed_fields(*last_pair) if not f.startswith("draining ")] or fields
        names = ", ".join(dict.fromkeys("fsd heap peak" if f.startswith("fsd heap") else f.split(" ", 1)[0]
                                        for f in fields)) or "nothing"
        print(f"CPORTS RESOURCES TRANSIENT {where} :: {self.offs(seen, prev)} (no settled pair)", flush=True)
        print(f"CPORTS RESOURCES UNSETTLED {where} :: {'; '.join(fields)} after {AGREE_SECONDS + SETTLE_SECONDS} s | "
              f"{prev['memory']} | {prev['kernel']} | images={prev['images']} fsd_heap_peak={prev.get('fsd')}",
              flush=True)
        self.check(f"{where}: the census settled within {AGREE_SECONDS + SETTLE_SECONDS} s (fsd draining 0, "
                   f"{'three' if needed == 3 else 'two'} consecutive samples equal)", False, f"UNSETTLED {names} never settled: {'; '.join(fields)}")
        return prev

    def old_stable(self, key, when, last):
        """The earlier rule, for a census without the fsd keys: two
        consecutive readings agreeing on the kit's fields within
        AGREE_SECONDS, else the last reading."""
        deadline = time.monotonic() + AGREE_SECONDS
        while time.monotonic() < deadline:
            time.sleep(1)
            now = self.census()
            if not ck.KitMatrix.differs(last, now):
                return now
            print(f"CPORTS RESOURCES TRANSIENT {key} {when} :: {last['kernel']} images={last['images']} "
                  f"objects={len(last['objects'])} -> {now['kernel']} images={now['images']} "
                  f"objects={len(now['objects'])}", flush=True)
            last = now
        return last

    @staticmethod
    def repeatable(name):
        return name in REPEATABLE or name in CHAIN_OF or name in REPEAT_SCENARIOS

    def allowed(self, case):
        return {f"{CPORTS}/{case.cwd}/{p}" for p in case.outputs + case.retained + case.removed}

    def census_accepts(self, case, before, after):
        """Whether compare_census would pass `after` (no side effects): equal,
        a frames-only step, or a file-changing high-water reading."""
        allowed = self.allowed(case)

        def kept(census):
            return [o for o in census["objects"] if o[0] not in allowed and not o[0].startswith("/var/log/")]

        if kept(before) != kept(after):
            return False
        if (before["images"], before["memory"], before["kernel"]) == (after["images"], after["memory"], after["kernel"]):
            return True
        if ((before["images"], before["kernel"], before["objects"], before["fsd"])
                == (after["images"], after["kernel"], after["objects"], after["fsd"])):
            return True
        return bool(allowed) and (before["images"], before["kernel"]) == (after["images"], after["kernel"])

    @staticmethod
    def census_delta(a, b):
        what = [f"{k} {a[k]} -> {b[k]}" for k in ("images", "memory", "kernel") if a[k] != b[k]]
        if a["fsd"] != b["fsd"]:
            what.append(f"fsd heap peak {heap_step(a['fsd'], b['fsd'])}")
        what += [f"{k} {a.get(k)} -> {b.get(k)}" for k in ("fsd_opens", "fsd_draining") if a.get(k) != b.get(k)]
        names = sorted({o[0] for o in a["objects"]} ^ {o[0] for o in b["objects"]})
        if names:
            what.append(f"names {names}")
        elif a["objects"] != b["objects"]:
            what.append("object contents")
        return "; ".join(what) or "nothing"

    def settle(self, name, after, accepts=None):
        """A census CportsMatrix.census took is judged once, by stable()
        (ruling (b)): returned as is. A census without the fsd keys keeps the
        Task 13 rule: a reading the check would refuse is sampled again for
        up to SETTLE_SECONDS and the first accepted one is used (CPORTS
        RESOURCES SETTLED), else the original, and the check fails as before."""
        if self.fsd_keyed(after) or accepts is None or accepts(after):
            return after
        start = time.monotonic()
        while time.monotonic() - start < SETTLE_SECONDS:
            time.sleep(1)
            now = self.census()
            if accepts(now):
                print(f"CPORTS RESOURCES SETTLED {name} after {time.monotonic() - start:.0f} s :: "
                      f"{self.census_delta(after, now)}", flush=True)
                return now
        return after

    def compare_census(self, case, before, after, restart=False, allow_rest_lowering=True):
        """`restart`: the case stopped QEMU and `before` is the baseline
        retaken after the restart, in the same boot as `after`. Its stamped
        downward rest-floor rule still applies; exact restart-round and
        post-recovery repeat comparisons remain separate. File-changing frame growth is printed
        as an informational high-water reading (ruling 1: the restart rounds
        judge it). The census actually judged is left in self.judged."""
        after = self.settle(case.name, after, lambda now: self.census_accepts(case, before, now))
        self.judged = after
        allowed = self.allowed(case)
        lowered = (allow_rest_lowering
                   and self.permitted_rest_lowering(before, after))
        bk, ak = self.comparison_kernels(before, after, lowered)

        def kept(census):
            return [o for o in census["objects"] if o[0] not in allowed and not o[0].startswith("/var/log/")]

        b, a = kept(before), kept(after)
        same = ((before["images"], before["memory"], bk, before["fsd"])
                == (after["images"], after["memory"], ak, after["fsd"]))
        if (not same and (before["images"], bk, before["objects"], before["fsd"])
                == (after["images"], ak, after["objects"], after["fsd"])):
            self.frames_step(case.name, before, after, rest_lowering=lowered)
            same = True
        if (not same and allowed and a == b and (before["images"], bk) == (after["images"], ak)):
            # The file server's own heap follows the image it holds (records
            # and block lists of the files the case changed) and its pooled
            # pages stay mapped (C-INTERFACE.md 3): frames may move when a case
            # changes files. Taken as a high-water mark here, and proven not
            # to grow per operation by the repeat round at the end of the run.
            grew = self.allocated(after["memory"]) - self.allocated(before["memory"])
            print(f"CPORTS RESOURCES HIGHWATER {case.name} :: frames {self.allocated(before['memory'])} -> "
                  f"{self.allocated(after['memory'])} ({grew:+d}); fsd heap peak {heap_step(before['fsd'], after['fsd'])}; "
                  f"images, kernel objects and other files equal"
                  f"{' (after the restart; informational, the restart rounds judge it)' if restart else ''}"
                  f"{' (a LIMIT case: not repeated)' if case.name in self.limited else ''}", flush=True)
            if restart or case.name in self.limited:
                pass
            elif not self.repeatable(case.name):
                print(f"CPORTS RESOURCES HIGHWATER UNREPEATABLE {case.name}", flush=True)
                self.check(f"{case.name}: a high-water case must be repeatable (a gzip/gunzip pair, a chain or a REPEAT_SCENARIOS scenario)", False,
                           f"frames {self.allocated(before['memory'])} -> {self.allocated(after['memory'])} "
                           f"fsd heap peak {heap_step(before['fsd'], after['fsd'])}")
            if not restart and case.name not in self.limited:
                self.highwater.append(case.name)
            same = True
        self.check(f"resources after {case.name}: images, frames, kernel objects and image files unchanged "
                   f"(except {sorted(allowed) or 'nothing'})",
                   same and a == b and (self.rest_handles(before) or lowered) and self.rest_handles(after),
                   f"before={ {k: v for k, v in before.items() if k != 'objects'} } "
                   f"after={ {k: v for k, v in after.items() if k != 'objects'} } "
                   f"fsd heap peak {heap_step(before['fsd'], after['fsd'])} "
                   f"added={sorted({o[0] for o in a} - {o[0] for o in b})} "
                   f"removed={sorted({o[0] for o in b} - {o[0] for o in a})} "
                   f"changed={sorted(x[0] for x in a if x not in b and x[0] in {o[0] for o in b})}")
        if lowered:
            print(f"CPORTS RESOURCES RECORDED {case.name}: same-boot rest handle floor "
                  f"{handles(before['kernel'])} -> {handles(after['kernel'])}; each census judged at its own floor; "
                  "raw counts retained", flush=True)
        self.rest_opens(f"resources before {case.name}", before)
        self.rest_opens(f"resources after {case.name}", after)
        present = {o[0] for o in after["objects"]}
        for p in case.removed:
            self.check(f"{case.name}: {p} removed", f"{CPORTS}/{case.cwd}/{p}" not in present)
        return before["memory"], before["kernel"]

    # -- the Linux twin ------------------------------------------------------------

    def linux_home(self):
        """sqlite.home's Linux twin (the reference, not the guest; A20 is about
        the guest): HOME is an empty directory under the work directory. The
        Linux shell asks getpwuid first (shell.c find_home_dir), so HOME is
        only its fallback; the passwd home of the running user must therefore
        hold no ~/.sqliterc and no ~/.config/sqlite3/sqliterc, checked here."""
        import pwd
        home = self.work / "linux-home"
        home.mkdir(exist_ok=True)
        self.check("the Linux twin's HOME is an empty directory", not any(home.iterdir()), str(home))
        passwd_home = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir)
        found = [str(f) for f in (passwd_home / ".sqliterc", passwd_home / ".config" / "sqlite3" / "sqliterc") if f.exists()]
        self.check("the Linux reference reads no host sqlite3 init file (passwd home)", not found, str(found))
        return home

    def linux_dir(self, cwd):
        return self.work / "linux" / cwd

    def linux_run(self, case, cwd, twice=False, program=None, args=None):
        stdin = b"" if case.stdin == "-" else (cwd / case.stdin).read_bytes()
        program = program or case.program
        name = program.rsplit("/", 1)[1]

        env = {"TZ": "UTC"}
        if case.name in LINUX_EMPTY_HOME:
            env["HOME"] = str(self.linux_home())

        def once():
            r = subprocess.run([program, *(case.args if args is None else args)], executable=str(self.linux / name),
                               cwd=cwd, env=env, input=stdin, capture_output=True,
                               preexec_fn=ck.ignore_sigpipe, timeout=case.timeout)
            return r.returncode, r.stdout, r.stderr

        if not twice:
            return once(), None
        # The comparison-only second run gets a copy of the case directory
        # as it was before the first run, so the first run's side effects
        # (a database left behind) cannot change it; the chain continues
        # from the first run's directory.
        fresh = self.work / "linux-second" / case.cwd
        if fresh.exists():
            shutil.rmtree(fresh)
        shutil.copytree(cwd, fresh)
        first = once()
        cwd = fresh
        return first, once()

    # -- a case --------------------------------------------------------------------

    def normalized(self, case, got):
        patterns = self.normalizers.get(case.name, [])
        return got[0], normalize(got[1], patterns), normalize(got[2], patterns)

    def absd_case(self, case, quiet=False):
        """The case's one session on ABSD: (rc, out, err), absd-sh's status line removed."""
        stdin = b"" if case.stdin == "-" else (self.linux_dir(case.cwd) / case.stdin).read_bytes()
        if case.stdin != "-":
            image = self.t.tree().get(f"{CPORTS}/{case.cwd}/{case.stdin}")
            self.check(f"{case.name}: the stdin bytes equal {case.stdin} on the image", image == stdin,
                       f"image={None if image is None else (len(image), sha(image))} linux={(len(stdin), sha(stdin))}")
        rc, out, err, shell, pids = self.shell_ssh(self.text(case), stdin=stdin, timeout=case.timeout)
        self.check(f"{case.name}: the program ran as the shell's only child", len(pids) == 1, f"shell={shell} children={pids}")
        if rc != 0:
            # absd-sh's own report of a non-zero status (sh/src/lib.rs), not
            # the program's output: required, then removed before comparison.
            line = f"absd-sh: {case.program}: exit status {rc}\n".encode()
            self.check(f"{case.name}: absd-sh reported the status {rc} as the last stderr line", err.endswith(line), repr(err[-200:]))
            if not quiet:
                (self.work / f"{case.name}.absd.err.raw").write_bytes(err)
                print(f"CPORTS SHELL STATUS LINE {case.name} removed: {line.decode().strip()}", flush=True)
            err = err[:-len(line)]
        return rc, out, err

    # -- a timed-out session ---------------------------------------------------------

    def require_defect_on_timeout(self, case):
        sm.require(case.route == "shell", f"{case.name}: # defect-on-timeout on a {case.route} case")
        sm.require(case.name not in LIMIT_ON_TIMEOUT, f"{case.name}: both LIMIT_ON_TIMEOUT and # defect-on-timeout")
        sm.require(case.name in self.defects and re.search(rf"(?<![\w.-]){re.escape(case.defect_on_timeout)}(?![\w.-])",
                                                           self.defects[case.name]),
                   f"{case.name}: # defect-on-timeout {case.defect_on_timeout} needs a DEFECTS entry naming "
                   f"{case.defect_on_timeout}: {self.defects.get(case.name, '(none)')[:200]!r}")

    def require_limit_prefix(self, case):
        sm.require(case.route == "shell", f"{case.name}: # limit-prefix on a {case.route} case")
        sm.require(case.name in self.divergences, f"{case.name}: # limit-prefix needs a divergences.txt entry")
        sm.require(case.name not in self.defects, f"{case.name}: # limit-prefix on a case listed in DEFECTS")
        sm.require(case.program in DEFECT_PREFIX, f"{case.name}: # limit-prefix needs a DEFECT_PREFIX rule for "
                                                  f"{case.program}")

    def judge_limit_prefix(self, case, got, ref):
        """A # limit-prefix divergence (normalized got/ref): the DEFECT_PREFIX
        rule plus the declared stop file, message and a non-zero status."""
        self.require_limit_prefix(case)
        ident, want_file, message = case.limit_prefix
        rc, out, err = got
        progress, error = DEFECT_PREFIX[case.program]
        marks = list(re.finditer(progress, out, re.M))
        end = marks[-1].end() if marks else 0
        files = FILE_MARK.findall(out[:end])
        stop_file = files[-1].decode(errors="replace") if files else "none"
        stop = err.find(error)
        lines = out[:end].count(b"\n")
        wrong = []
        if not marks or out[:end] != ref[1][:end]:
            wrong.append(f"stdout through the last progress line (bytes {end}) differs from Linux's")
        if stop < 0 or err[:stop] != ref[2][:stop]:
            wrong.append(f"stderr before the error line ({stop}) differs from Linux's or has no {error!r}")
        if stop_file != want_file:
            wrong.append(f"stop_file={stop_file}, declared {want_file}")
        # Lua's test suite keeps printing tracegc dots on stderr during
        # lua_close, so for a Lua case one or more "." may follow the message;
        # they are not part of it. Every other case must end exactly there.
        tail = err.rstrip(b".\n") if case.name.startswith("lua.") else err.rstrip(b"\n")
        if not tail.endswith(message.encode()):
            wrong.append(f"stderr does not end with {message!r}"
                         + (" (trailing tracegc dots ignored)" if case.name.startswith("lua.") else "")
                         + f": {err[-200:]!r}")
        if rc == 0:
            wrong.append("status 0")
        if wrong:
            print(f"CPORTS LIMIT PREFIX MISMATCH {case.name} :: NATIVE LIMIT {ident}: {'; '.join(wrong)} "
                  f"(stop_file={stop_file} lines={lines} status={rc})", flush=True)
        self.check(f"{case.name}: NATIVE LIMIT {ident} by prefix (equal to Linux before the stop, stop in "
                   f"{want_file}, stderr ending {message!r}, status non-zero)", not wrong, "; ".join(wrong))
        print(f"CPORTS DIVERGES PREFIX OK {case.name} :: NATIVE LIMIT {ident} stop_file={stop_file} lines={lines} "
              f"status={rc}", flush=True)
        print(f"CPORTS DIVERGES {case.name} :: {self.divergences[case.name]}", flush=True)
        return "diverge"

    def keep_timeout(self, case, e):
        """What sshd delivered before the client was killed: <case>.absd.*."""
        for part, value in (("status", f"timeout {e.seconds}\n".encode()), ("out", e.out), ("err", e.err)):
            (self.work / f"{case.name}.absd.{part}").write_bytes(value)
        last = [l for l in e.out.decode(errors="replace").splitlines() if l.strip()][-1:]
        print(f"CPORTS TIMEOUT OUTPUT {case.name} seconds={e.seconds} stdout_bytes={len(e.out)} "
              f"stderr_bytes={len(e.err)} lines={e.out.count(b'\n')} last={last}", flush=True)

    def timed_out(self, case, e, start, before):
        """A shell case (not LIMIT_ON_TIMEOUT) past its timeout: its partial
        output is kept; unannotated, the timeout is re-raised (the run
        fails); under # defect-on-timeout it is judged as that DEFECT on
        the partial output. Returns (memory, kernel, judged census)."""
        self.keep_timeout(case, e)
        if case.defect_on_timeout is None:
            raise e
        self.require_defect_on_timeout(case)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline and self.t.all_images() != 0:
            time.sleep(0.5)
        self.check(f"{case.name}: the timed-out session was reclaimed", self.t.all_images() == 0, self.t.census_detail())
        ref, _ = self.linux_run(case, self.linux_dir(case.cwd))
        for part, value in (("status", f"{ref[0]}\n".encode()), ("out", ref[1]), ("err", ref[2])):
            (self.work / f"{case.name}.linux.{part}").write_bytes(value)
        _, out, err = self.normalized(case, (None, e.out, e.err))
        _, lout, lerr = self.normalized(case, ref)
        self.check(f"{case.name}: a prefix rule for {case.program} exists", case.program in DEFECT_PREFIX)
        progress, _ = DEFECT_PREFIX[case.program]
        marks = list(re.finditer(progress, out, re.M))
        end = marks[-1].end() if marks else 0
        self.check(f"{case.name}: before the timeout ABSD equals Linux (normalized stdout through the last progress "
                   f"line; the partial stderr a prefix of Linux's)",
                   bool(marks) and out[:end] == lout[:end] and lerr.startswith(err),
                   f"stdout_end={end} stderr_bytes={len(err)} linux_status={ref[0]}")
        lines = out[:end].count(b"\n")
        linux_marks = list(re.finditer(progress, lout, re.M))
        linux_lines = lout[:linux_marks[-1].end()].count(b"\n") if linux_marks else 0
        print(f"CPORTS DEFECT PREFIX OK {case.name} lines={lines} stdout_bytes={end} stderr_bytes={len(err)} "
              f"(timeout; Linux lines={linux_lines} status {ref[0]})", flush=True)
        print(f"CPORTS DEFECT TIMEOUT {case.name} id={case.defect_on_timeout} seconds={e.seconds} lines={lines}",
              flush=True)
        print(f"CPORTS DEFECT {case.name} :: {self.defects[case.name]}", flush=True)
        after = self.stable(case.name, "after")
        memory, kernel = self.compare_census(case, before, after)
        return memory, kernel, self.judged

    def run_shell_case(self, case):
        cwd = self.linux_dir(case.cwd)
        rc, out, err = self.absd_case(case)
        self.first[case.name] = self.normalized(case, (rc, out, err))
        twice = case.name in self.normalizers
        ref, second = self.linux_run(case, cwd, twice=twice)
        if twice:
            a, b = self.normalized(case, ref), self.normalized(case, second)
            for run in (ref, second):
                lout, lerr = run[1], run[2]
                for p in self.normalizers[case.name]:
                    if not (p.search(lout) or p.search(lerr)):
                        print(f"CPORTS NORMALIZER UNUSED {case.name} {p.pattern.decode()}", flush=True)
                        self.check(f"{case.name}: normalizer {p.pattern.decode()!r} matches in both Linux runs", False)
                    lout, lerr = p.sub(b"<n>", lout), p.sub(b"<n>", lerr)
            if ref == second:
                print(f"CPORTS NORMALIZER UNUSED {case.name}", flush=True)
            self.check(f"{case.name}: two Linux runs differ only inside normalized spans", a == b,
                       f"first={ref!r}\nsecond={second!r}")
            self.check(f"{case.name}: the normalizer covers text that varies (raw Linux runs differ)", ref != second)
            print(f"CPORTS NORMALIZER OK {case.name} patterns={len(self.normalizers[case.name])}", flush=True)
        for kind, data in (("absd", (rc, out, err)), ("linux", ref)):
            for part, value in (("status", f"{data[0]}\n".encode()), ("out", data[1]), ("err", data[2])):
                (self.work / f"{case.name}.{kind}.{part}").write_bytes(value)
        return (rc, out, err), ref

    def verify_line(self, case, got):
        """speedtest1 (after the case was judged equal to Linux): the ABSD
        output's verification hash, printed so the receipt carries it."""
        found = re.findall(rb"^Verification Hash: [^\n]*$", got[1], re.M)
        self.check(f"{case.name}: one Verification Hash line in the ABSD output", len(found) == 1, repr(found))
        line = found[0].decode()
        print(f"CPORTS SQLITE VERIFY {case.name} :: {line}", flush=True)
        return line

    def judge(self, case, got, ref):
        got, ref = self.normalized(case, got), self.normalized(case, ref)
        pin = self.expected / f"{case.name}.txt"
        if case.limit_prefix is not None:
            if case.name in self.pin:
                print(f"CPORTS PIN NOT WRITTEN {case.name}: a # limit-prefix case has no byte-exact pin", flush=True)
            return self.judge_limit_prefix(case, got, ref)
        if case.name in self.pin:
            self.expected.mkdir(exist_ok=True)
            pin.write_bytes(ck.pin_bytes(*got))
            print(f"CPORTS PIN WRITTEN {pin}: review it before committing", flush=True)
        if case.name in self.defects:
            self.check(f"{case.name}: defect output unchanged (pinned)", pin.exists() and pin.read_bytes() == ck.pin_bytes(*got),
                       f"ABSD {got!r}")
            if case.name == "sqlite.temp-nomem":
                # Before the defect: the declared SQLITE_NOMEM of the sort
                # (SPEC A18: a defined failure, first on stderr), and the
                # process alive printing what Linux prints after its sort.
                self.check(f"{case.name}: before the defect, the sort is the declared SQLITE_NOMEM and the shell "
                           f"continues as Linux does after its sort",
                           got[0] == 1 and ref[0] == 0 and got[2].startswith(TEMP_NOMEM_DECLARED)
                           and ref[1].split(b"\n")[1:2] == got[1].split(b"\n")[:1] == [b"still running|1"],
                           f"ABSD {got!r} Linux {ref!r}")
                print(f"CPORTS DEFECT PREFIX OK {case.name} :: {TEMP_NOMEM_DECLARED.decode().strip()!r} then "
                      f"'still running|1' (Linux: 40000 then 'still running|1')", flush=True)
                print(f"CPORTS DEFECT {case.name} :: {self.defects[case.name]}", flush=True)
                return "defect"
            self.check(f"{case.name}: a prefix rule for {case.program} exists", case.program in DEFECT_PREFIX)
            progress, error = DEFECT_PREFIX[case.program]
            marks = list(re.finditer(progress, got[1], re.M))
            end = marks[-1].end() if marks else 0
            stop = got[2].find(error)
            self.check(f"{case.name}: before the defect ABSD equals Linux (normalized stdout through the last progress "
                       f"line, stderr up to the program's error line)",
                       marks and got[1][:end] == ref[1][:end] and stop >= 0 and got[2][:stop] == ref[2][:stop],
                       f"stdout_end={end} stderr_stop={stop}")
            print(f"CPORTS DEFECT PREFIX OK {case.name} lines={got[1][:end].count(b'\n')} stdout_bytes={end} "
                  f"stderr_bytes={stop}", flush=True)
            print(f"CPORTS DEFECT {case.name} :: {self.defects[case.name]}", flush=True)
            return "defect"
        if case.name in self.divergences:
            self.check(f"{case.name}: pinned ABSD output matches and differs from Linux",
                       pin.exists() and pin.read_bytes() == ck.pin_bytes(*got) and got != ref,
                       f"ABSD {got!r}\nLinux {ref!r}")
            print(f"CPORTS DIVERGES {case.name} :: {self.divergences[case.name]}", flush=True)
            return "diverge"
        self.check(f"{case.name}: no pin for a case that must agree", not pin.exists(), str(pin))
        self.check(f"case {case.name}", got == ref, f"ABSD {got!r}\nLinux {ref!r}")
        print(f"CPORTS CASE OK {case.name}", flush=True)
        return "agree"

    def check_outputs(self, case):
        tree = self.t.tree()
        keep = self.work / "absd-out" / case.cwd
        keep.mkdir(parents=True, exist_ok=True)
        for path in case.outputs:
            got = tree.get(f"{CPORTS}/{case.cwd}/{path}")
            want = (self.linux_dir(case.cwd) / path).read_bytes()
            self.check(f"{case.name}: {path} on the image equals the Linux twin's", got == want,
                       f"absd={None if got is None else (len(got), sha(got))} linux={(len(want), sha(want))}")
            (keep / path).write_bytes(got)
            print(f"CPORTS OUTPUT OK {case.name} {path} sha256={sha(got)} bytes={len(got)}", flush=True)
            source = {"one.bin.gz": self.one, "eight.bin.gz": self.one * 8}.get(path)
            if source is not None:
                r = subprocess.run([sys.executable, "-I", "-c", GUNZIP, str(keep / path)], capture_output=True, timeout=120)
                self.check(f"{case.name}: the ABSD {path} decompresses on the host to its input",
                           r.returncode == 0 and r.stdout == source, f"rc={r.returncode} {r.stderr[-300:]!r}")
                print(f"CPORTS OUTPUT OK {case.name} {path} decompresses", flush=True)

    def check_lua(self, case, got, ref):
        """A20: both sides stop at files.lua:8. A case pinned as a DEFECT
        records where ABSD stopped instead (a finding, not an exclusion; in
        Stage 2, literals.lua:298 on R14). testing_lines counts the
        `testing ...` lines printed, not files completed."""
        rc, out, err = got
        files = re.findall(rb"^\*\*\*\*\* FILE '([^']+)'\*\*\*\*\*$", out, re.M)
        stop = re.search(rb"/bin/lua: ([^:\s]+:\d+): ", err)
        stop = stop.group(1).decode() if stop else "none"
        completed = len(re.findall(rb"^testing ", out, re.M))
        if case.limit_prefix is not None:
            print(f"CPORTS LUA testing_lines={completed} stop={stop} (NATIVE LIMIT {case.limit_prefix[0]}; Linux "
                  f"stop=files.lua:8; last file marker {files[-1].decode() if files else None}; status {rc})", flush=True)
            return
        if case.name in self.defects:
            self.check(f"{case.name}: ABSD stopped (non-zero status) where Linux did not", rc != 0 and stop != "files.lua:8"
                       and b"files.lua:8: assertion failed!" in ref[2], f"stop={stop} rc={rc}")
            print(f"CPORTS LUA testing_lines={completed} stop={stop} (DEFECT; Linux stop=files.lua:8; last file marker "
                  f"{files[-1].decode() if files else None}; status {rc})", flush=True)
            return
        self.check(f"{case.name}: `testing files` is absent (files.lua stopped before its tests)", b"testing files" not in out)
        self.check(f"{case.name}: the last file marker is files.lua", files and files[-1] == b"files.lua", str(files[-3:]))
        self.check(f"{case.name}: the stop is files.lua:8 on both sides, status equal and non-zero",
                   stop == "files.lua:8" and b"files.lua:8: assertion failed!" in ref[2]
                   and rc == ref[0] and rc != 0, f"rc={rc} linux={ref[0]} err={err[-400:]!r}")
        print(f"CPORTS LUA testing_lines={completed} stop=files.lua:8 (case {case.name}; file markers before "
              f"files.lua: {len(files) - 1}; status {rc})", flush=True)

    def make_eight(self, case):
        path = f"{CPORTS}/{case.cwd}/eight.bin"
        if path in self.objects():
            return
        text = f"cd {CPORTS}/{case.cwd}; " + " ".join(ck.quote(w) for w in ["/bin/cat", *["one.bin"] * 8]) + " > eight.bin"
        start = time.monotonic()
        rc, out, err, _, _ = self.shell_ssh(text, timeout=DEFAULT_TIMEOUT)
        got = self.t.tree().get(path)
        self.check("eight.bin made in the guest by cat of one.bin eight times",
                   rc == 0 and out == b"" and err == b"" and got == self.one * 8,
                   f"rc={rc} {out!r} {err!r} size={None if got is None else len(got)}")
        (self.linux_dir(case.cwd) / "eight.bin").write_bytes(self.one * 8)
        print(f"CPORTS EIGHT.BIN made sha256={sha(got)} seconds={time.monotonic() - start:.1f}", flush=True)

    def frames_warmup(self, rehearsal=False):
        """The kit's observation (c-kit-matrix.py live_frames): the first
        time two sessions are open at once, one frame stays allocated
        afterwards, every other count equal. Provoked once, before the first
        scenario that holds a session; its step counts against the boot's
        frames-only allowance (ruling 2)."""
        rest = self.stable("frames warmup", "rest")
        self.rest_kernel("frames warmup rest", rest)
        self.rest_opens("frames warmup rest", rest)
        spawned = self.t.spawn_count()
        held = self.hold(f"cd {CPORTS}; " + ck.quote("/bin/cat"))
        try:
            self.t.await_spawns(spawned, 2)
            rc, out, err = self.ssh("/bin/sysinfo")
            self.check("sysinfo answers while a second session is held", rc == 0, f"{rc} {out!r} {err!r}")
        finally:
            try:
                out, err = held.communicate(b"", timeout=120)
            except subprocess.TimeoutExpired:
                held.kill(); held.wait(); self.close_pipes(held)
                raise sm.Failed("the held warmup session did not end at EOF within 120 s")
        self.check("the held cat ended at EOF", held.returncode == 0 and out == b"" and err == b"",
                   f"rc={held.returncode} {out!r} {err!r}")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and self.t.all_images() != 0:
            time.sleep(0.2)
        after = self.stable("frames warmup", "after")
        grew = self.allocated(after["memory"]) - self.allocated(rest["memory"])
        self.rest_kernel("frames warmup", after)
        self.rest_opens("frames warmup", after)
        print(f"CPORTS FRAMES WARMUP :: rest {rest['memory']} | after {after['memory']} | frames {grew:+d} | "
              f"{after['kernel']} images={after['images']} objects={len(after['objects'])}", flush=True)
        if rehearsal:
            # Cold mapped capacity may grow without the measured five-page cap.
            # Whole-group fingerprints bound establishment; retain non-capacity
            # correctness here, including exact kernel/file/image correspondence.
            self.check("rehearsal held-session leaves images, kernel objects and files unchanged",
                       (rest["images"], rest["kernel"], rest["objects"])
                       == (after["images"], after["kernel"], after["objects"]))
        elif grew != 0:
            # Ruling 2: the warmup's step is one occurrence of the boot's frames-only allowance.
            self.frames_step("frames-warmup", rest, after)
        self.warmed = True

    def repeat_round(self):
        """After a high-water reading: every zlib file-changing pair of the
        run (gzip then gunzip of one.bin, then of eight.bin), every chain
        holding a high-water case (its files removed, then its cases in
        order) and every high-water scenario of REPEAT_SCENARIOS (its own
        scenario method, which must print what it printed the first time) is
        run once to warm, then twice judged. Warm permits fsd +0/+4 pages
        and at most +4 frames, with unchanged images, kernel objects and names.
        The image returns to the same files, so the census after each judged
        round must equal the settled baseline taken after warm
        in images, frames, kernel objects and the file server's heap peak (a
        per-operation leak would grow it every round). Each repeated case
        must print what it printed the first time (normalized), and each
        zlib pair's produced file must equal the first run's bytes.

        ABSD_CPORTS_DIAG_REPEAT_ROUNDS=N (N >= 2) extends the judged loop.
        The cports entry point scales --boot-seconds by N + 1 (warm included;
        default N=2), reserving an original whole-boot budget per repeat.
        Census mismatches still print FAIL; the first is re-raised after N
        rounds. Unsettled readings and workload failures still abort.
        Diagnostic steps are positive frame OR heap deltas from the previous
        judged round (round 1 uses the post-warm start); later_steps counts
        such rounds after the first. Free-pool and release counters are observations, not verdicts.
        """
        diag = os.environ.get("ABSD_CPORTS_DIAG_REPEAT_ROUNDS")
        rounds = 2 if diag is None else int(diag)
        if rounds < 2:
            raise ValueError("ABSD_CPORTS_DIAG_REPEAT_ROUNDS must be at least 2 (preserve both ordinary rounds)")
        failure, first_step, later_steps = None, None, 0
        unrepeatable, pairs, chains = self.repeat_plan()
        for n in unrepeatable:
            print(f"CPORTS RESOURCES HIGHWATER UNREPEATABLE {n}", flush=True)
        self.check("every high-water case can be repeated (with its inverse, with its whole chain, or as a REPEAT_SCENARIOS scenario)", not unrepeatable,
                   str(unrepeatable))
        self.check("the repeat set restores the image (each gzip followed by its gunzip)",
                   all(pairs.index(n) < pairs.index(REPEATABLE[n]) for n in pairs if "gunzip" not in n), str(pairs))
        scenarios = [n for n in self.highwater if n in REPEAT_SCENARIOS and n in self.ran]
        repeated = pairs + [n for c in chains for n in c["cases"]] + scenarios
        start = self.stable("repeat", "before")
        self.rest_opens("repeat before", start)
        outputs_checked = 0
        prev = start
        for round_no in range(0, rounds + 1):
            for name in pairs:
                case = self.ran[name]
                rc, out, err, _, pids = self.shell_ssh(self.text(case), timeout=case.timeout)
                self.check(f"repeat {round_no} {name}", rc == 0 and out == b"" and err == b"" and len(pids) == 1,
                           f"{rc} {out!r} {err!r}")
                # Final review M3: the file the pair produced, not only its streams.
                tree = self.t.tree()
                for path in case.outputs:
                    got = tree.get(f"{CPORTS}/{case.cwd}/{path}")
                    first = (self.work / "absd-out" / case.cwd / path).read_bytes()
                    self.check(f"repeat {round_no} {name}: {path} equals the first run's", got == first,
                               f"now={None if got is None else (len(got), sha(got))} first={(len(first), sha(first))}")
                    outputs_checked += 1
                for path in case.removed:
                    self.check(f"repeat {round_no} {name}: {path} removed", f"{CPORTS}/{case.cwd}/{path}" not in tree)
            for chain in chains:
                present = self.objects()
                gone = [p for p in chain["reset"] if f"{CPORTS}/{chain['cwd']}/{p}" in present]
                if gone:
                    rc, out, err, _, _ = self.shell_ssh(f"cd {CPORTS}/{chain['cwd']}; " +
                                                        " ".join(ck.quote(w) for w in ["/bin/rm", *gone]))
                    left = self.objects()
                    self.check(f"repeat {round_no}: removed {gone} in {chain['cwd']}",
                               rc == 0 and out == b"" and err == b"" and
                               not any(f"{CPORTS}/{chain['cwd']}/{p}" in left for p in gone), f"{rc} {out!r} {err!r}")
                for name in chain["cases"]:
                    case = self.ran[name]
                    got = self.normalized(case, self.absd_case(case, quiet=True))
                    self.check(f"repeat {round_no} {name}: the same output as its first run", got == self.first[name],
                               f"now {got!r}\nfirst {self.first[name]!r}")
                    if name in INTEGRITY:
                        self.integrity(case, linux=False)
            for name in scenarios:
                case = self.ran[name]
                got = getattr(self, "scenario_" + case.program.replace("-", "_"))(case, repeat=round_no)
                self.check(f"repeat {round_no} {name}: the scenario printed what it printed the first time",
                           got == self.first[name], f"now {got!r}\nfirst {self.first[name]!r}")
            now = self.stable("repeat", f"after {round_no}")
            if round_no == 0:
                df = self.allocated(now["memory"]) - self.allocated(start["memory"])
                dh = now["fsd"] - start["fsd"]
                kernel_equal = (now["kernel"] == start["kernel"]
                                and {o[0] for o in now["objects"]} == {o[0] for o in start["objects"]})
                print(f"CPORTS REPEAT WARM frames={df:+d} fsd_heap={dh:+d} "
                      f"multiple4={'yes' if dh % 4 == 0 else 'no'} "
                      f"kernel_equal={'yes' if kernel_equal else 'no'}", flush=True)
                self.check("repeat warm: bounded first-use step, images, kernel objects and names unchanged",
                           dh in (0, 4) and df <= 4 and kernel_equal
                           and now["images"] == start["images"]
                           and self.rest_handles(start) and self.rest_handles(now),
                           f"frames {df:+d}; fsd heap peak {heap_step(start['fsd'], now['fsd'])}; "
                           f"before={start} after={now}")
                self.rest_opens("repeat warm", now)
                start = self.stable("repeat", "judged baseline after warm")
                self.rest_opens("repeat judged baseline", start)
                prev = start
                continue
            if diag is not None:
                df = self.allocated(now["memory"]) - self.allocated(prev["memory"])
                dh = now["fsd"] - prev["fsd"]
                if df > 0 or dh > 0:
                    if first_step is None:
                        first_step = round_no
                    else:
                        later_steps += 1
                counts = dict((kind, int(n)) for n, kind in
                              re.findall(r"(\d+) (handles|pipes|cells)", now["kernel"]))
                print(f"CPORTS DIAG ROUND {round_no} frames={self.allocated(now['memory'])} "
                      f"handles={counts['handles']} pipes={counts['pipes']} cells={counts['cells']} "
                      f"fsd_heap={now['fsd']} fsd_free={now.get('fsd_free')} settled={now.get('settled')} "
                      f"step_vs_prev=frames:{df:+d},fsd_heap:{dh:+d}", flush=True)
                prev = now
            try:
                self.check(f"repeat round {round_no}: images, frames, kernel objects and the file server's heap peak equal "
                           f"the census before the rounds",
                           (now["images"], now["memory"], now["kernel"], now["fsd"])
                           == (start["images"], start["memory"], start["kernel"], start["fsd"])
                           and {o[0] for o in now["objects"]} == {o[0] for o in start["objects"]}
                           and self.rest_handles(start) and self.rest_handles(now),
                           f"before={start['memory']} {start['kernel']} after={now['memory']} {now['kernel']} "
                           f"fsd heap peak {heap_step(start['fsd'], now['fsd'])} "
                           f"names added={sorted({o[0] for o in now['objects']} - {o[0] for o in start['objects']})} "
                           f"removed={sorted({o[0] for o in start['objects']} - {o[0] for o in now['objects']})}")
                self.rest_opens(f"repeat round {round_no}", now)
            except (sm.Failed, ck.sm.Failed) as exc:
                if diag is None:
                    raise
                if failure is None:
                    failure = exc
        if diag is not None:
            print(f"CPORTS DIAG PLATEAU rounds={rounds} first_step_round={first_step if first_step is not None else 'none'} "
                  f"later_steps={later_steps}", flush=True)
        if failure is not None:
            raise failure
        print(f"CPORTS RESOURCES REPEAT OK rounds={rounds} repeated={' '.join(repeated)} outputs_checked={outputs_checked} :: "
              f"{start['memory']} | {start['kernel']} | fsd_heap_peak={start['fsd']} "
              f"(high-water cases: {' '.join(self.highwater)})", flush=True)

    # -- scenarios -----------------------------------------------------------------

    def scenario_lock_contention(self, case, repeat=None):
        """Returns what its CPORTS SCENARIO OK line states (B's held-try and
        after-kill texts, the Linux twin equal), which the repeat round
        (REPEAT_SCENARIOS) requires again; `repeat`: the repeat round's number
        (the line is then CPORTS SCENARIO REPEAT <name> round=<k>)."""
        path = case.args[0]
        a = self.hold(self.text(case, "/bin/posixprobe", ["hold", path]))
        try:
            self.await_line(a, b"HELD")
            alive = self.t.all_images()
            self.check("A's shell and probe are alive holding the lock", alive == 2, self.t.census_detail())
            start = time.monotonic()
            rc1, out1, err1, _, pids = self.shell_ssh(self.text(case, "/bin/posixprobe", ["try", path]), baseline=alive)
            took = time.monotonic() - start
            self.check("B ran as its shell's only child", len(pids) == 1, str(pids))
        finally:
            self.end_session(a)
        rc2, out2, err2, _, _ = self.shell_ssh(self.text(case, "/bin/posixprobe", ["try", path]))
        got = (rc1, out1, err1, rc2, out2, err2)
        # The Linux twin: A and B as host processes.
        cwd = self.linux_dir(case.cwd)
        la = subprocess.Popen(["/bin/posixprobe", "hold", path], executable=str(self.linux / "posixprobe"), cwd=cwd,
                              env={"TZ": "UTC"}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              preexec_fn=ck.ignore_sigpipe)
        la.seen = b""
        try:
            self.await_line(la, b"HELD")
            r1, _ = self.linux_run(case, cwd, program="/bin/posixprobe", args=["try", path])
        finally:
            la.send_signal(signal.SIGKILL); la.wait()
            for pipe in (la.stdin, la.stdout, la.stderr):
                pipe.close()
        r2, _ = self.linux_run(case, cwd, program="/bin/posixprobe", args=["try", path])
        ref = (*r1, *r2)
        want = (0, b"try shared: -1 EAGAIN\ntry exclusive: -1 EAGAIN\n", b"",
                0, b"try shared: 0 0\ntry exclusive: 0 0\n", b"")
        self.check(f"{case.name}: B is refused at once while A holds, succeeds after A's session is killed; "
                   "the Linux twin prints the same (B's refused session took under 5 s)", got == want and ref == want and took < 5,
                   f"ABSD {got!r}\nLinux {ref!r} seconds={took:.1f}")
        stated = (out1.decode().strip(), out2.decode().strip(), "Linux equal")
        head = f"CPORTS SCENARIO OK {case.name}" if repeat is None else f"CPORTS SCENARIO REPEAT {case.name} round={repeat}"
        print(f"{head} :: held-try {stated[0]!r} in {took:.1f} s; after-kill {stated[1]!r}; {stated[2]}", flush=True)
        return stated

    # -- SQLite ----------------------------------------------------------------------

    def sqlite_text(self, case, db, sql, vfs="unix-excl"):
        return self.text(case, "/bin/sqlite3", ["-batch", "-vfs", vfs, db, sql, *SQLITE_INIT])

    def sqlite_linux(self, case, db, sql, vfs="unix-excl"):
        r, _ = self.linux_run(case, self.linux_dir(case.cwd), program="/bin/sqlite3",
                              args=["-batch", "-vfs", vfs, db, sql, *SQLITE_INIT])
        return r

    def sqlite_absd(self, case, db, sql, vfs="unix-excl", baseline=0):
        """One B session (rc, out, err, seconds); absd-sh's status line, required for a non-zero status, removed."""
        start = time.monotonic()
        rc, out, err, _, pids = self.shell_ssh(self.sqlite_text(case, db, sql, vfs), baseline=baseline, timeout=B_TIMEOUT)
        took = time.monotonic() - start
        self.check("B ran as its shell's only child", len(pids) == 1, str(pids))
        if rc != 0:
            line = f"absd-sh: /bin/sqlite3: exit status {rc}\n".encode()
            self.check(f"B: absd-sh reported the status {rc} as the last stderr line", err.endswith(line), repr(err[-200:]))
            err = err[:-len(line)]
        return rc, out, err, took

    def integrity(self, case, linux=True):
        """An extra session on the database the case left (ABSD, and the Linux twin)."""
        db, sql, want = INTEGRITY[case.name]
        got = self.sqlite_absd(case, db, sql)[:3]
        ref = self.sqlite_linux(case, db, sql) if linux else (0, want, b"")
        self.check(f"{case.name}: {sql!r} on {db} in a fresh session prints {want!r} (ABSD and Linux)",
                   got == (0, want, b"") and ref == (0, want, b""), f"ABSD {got!r} Linux {ref!r}")
        if linux:
            print(f"CPORTS SQLITE INTEGRITY OK {case.name} {db} :: {sql} -> {want.decode().strip()!r} on ABSD and Linux",
                  flush=True)

    def hold_sqlite(self, case, db, vfs="unix-excl"):
        return self.hold(self.text(case, "/bin/sqlite3", ["-vfs", vfs, db, *SQLITE_INIT]))

    def hold_linux_sqlite(self, case, db, vfs="unix-excl"):
        p = subprocess.Popen(["/bin/sqlite3", "-vfs", vfs, db, *SQLITE_INIT], executable=str(self.linux / "sqlite3"),
                             cwd=self.linux_dir(case.cwd), env={"TZ": "UTC"}, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=ck.ignore_sigpipe)
        p.seen = b""
        return p

    @staticmethod
    def close_pipes(p):
        for pipe in (p.stdin, p.stdout, p.stderr):
            try:
                pipe.close()
            except OSError:
                pass

    def kill_linux(self, p):
        p.send_signal(signal.SIGKILL); p.wait(); self.close_pipes(p)

    def quit_linux(self, p):
        p.stdin.write(b".quit\n"); p.stdin.flush()
        out, err = p.communicate(timeout=120)
        return p.returncode, p.seen + out, err

    def names(self, cwd, tree=None):
        tree = self.t.tree() if tree is None else tree
        prefix = f"{CPORTS}/{cwd}/"
        return sorted(p[len(prefix):] for p in tree if p.startswith(prefix) and "/" not in p[len(prefix):])

    @staticmethod
    def image_tree(image):
        """The files of a saved image, read by the host's own filesystem reader."""
        region = absd_fs.fs_region(image, ssh_absd.DEVICE_SECTORS)
        selected = absd_fs.select(region)
        return {path: absd_fs.content(region, selected, record)
                for path, record in absd_fs.tree(region, selected).items()
                if not path.endswith("/") and ssh_absd.record_is_file(region, selected, record)}

    def host_reader(self, label, tree, cwd, names, sql):
        """Copies `names` (each must exist) out of an image's tree into their
        own directory (untrusted data) and runs Python's sqlite3 module on the
        first: its lines, joined. A hot journal copied with the database is
        rolled back by the host library on the first read."""
        dest = self.work / "host-reader" / label
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        sizes = {}
        for n in names:
            data = tree.get(f"{CPORTS}/{cwd}/{n}")
            if data is None:
                print(f"CPORTS HOST READER {label} :: {n} is not on the image", flush=True)
                return f"<{n} not on the image>".encode()
            (dest / n).write_bytes(data)
            sizes[n] = len(data)
        r = subprocess.run(["python3", "-I", "-c", HOST_READER, str(dest / names[0]), *sql], capture_output=True,
                           timeout=120)
        if r.returncode != 0:
            print(f"CPORTS HOST READER {label} :: failed: {r.stderr[-400:]!r}", flush=True)
            return b"<host reader failed: " + r.stderr[-400:] + b">"
        print(f"CPORTS HOST READER {label} :: {' '.join(f'{n}={b}' for n, b in sizes.items())} -> "
              f"{r.stdout.decode().strip().replace(chr(10), ' / ')} (python sqlite3 {r.stderr.decode().strip()})",
              flush=True)
        return r.stdout

    @staticmethod
    def pending_stderr(p):
        """What a held session has written to stderr so far, read without blocking."""
        data = b""
        while select.select([p.stderr], [], [], 0)[0]:
            chunk = os.read(p.stderr.fileno(), 65536)
            if not chunk:
                break
            data += chunk
        return data

    def cut(self, case, p, label):
        """Section 8 form (a): QEMU stops while A holds the database; the
        image is copied as the stop left it; the next boot recovers
        (expect_sweep: the boot ended with a session bound); the census
        baseline is retaken on the new boot and printed."""
        stopped_at = time.monotonic()
        self.t.stop()
        p.kill(); p.wait(); self.close_pipes(p)
        label = label + ("" if self.restart_round == 1 else f"-round{self.restart_round}")
        pre = self.work / f"{label}-pre.img"
        shutil.copy(self.t.image, pre)
        print(f"CPORTS CUT {case.name} :: QEMU stopped at {label}; image copied to {pre.name} "
              f"({pre.stat().st_size} bytes); serial {self.t.log.name}", flush=True)
        info = self.t.start(expect_sweep=True)
        self.connections = 0  # The restarted server has a new session counter.
        self.check(f"{case.name}: the restart loaded the same host key", not info["generated"] and info["public"] == self.host_key,
                   str(info))
        rebased = self.take_rest(f"{case.name} after restart")
        self.steps = 0          # ruling 2: the per-boot allowance restarts with the new baseline
        old = self.case_before
        print(f"CPORTS RESOURCES REBASE {case.name} :: boot {self.t.boots} ({self.t.log.name}, restart "
              f"{time.monotonic() - stopped_at:.1f} s, image_changed={info['image_changed']}) | before the cut "
              f"{old['memory']} | {old['kernel']} images={old['images']} -> after restart {rebased['memory']} | "
              f"{rebased['kernel']} images={rebased['images']} (frames {self.allocated(old['memory'])} -> "
              f"{self.allocated(rebased['memory'])}); the case is compared against the new baseline", flush=True)
        self.check(f"{case.name}: no image process alive after the restart", rebased["images"] == 0, self.t.census_detail())
        self.rebased = rebased
        return pre

    def limit_case(self, case, e, start, before):
        """A LIMIT_ON_TIMEOUT case past its timeout: a named limit with the
        measured time, not a failure. The case joins self.limited: it is never
        a high-water case, never in self.ran, and its chain is not repeated
        (the files it left are partial; its census allowance still applies)."""
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline and self.t.all_images() != 0:
            time.sleep(0.5)
        self.check(f"{case.name}: the timed-out session was reclaimed", self.t.all_images() == 0, self.t.census_detail())
        last = [l for l in e.out.decode(errors="replace").splitlines() if l.strip()][-1:]
        self.limited.add(case.name)
        print(f"CPORTS LIMIT {case.name} :: exceeded its {e.seconds} s timeout under TCG "
              f"(measured {time.monotonic() - start:.0f} s); last line printed: {last}; the smaller rung "
              f"stands as the verified one; excluded from the high-water list and the repeat chains", flush=True)
        after = self.stable(case.name, "after")
        self.compare_census(case, before, after)

    def repeat_plan(self):
        """What the repeat round runs: (unrepeatable high-water cases, zlib
        pairs in run order, chains). A chain holding a LIMIT case is never
        repeated."""
        unrepeatable = [n for n in self.highwater
                        if not ((n in REPEATABLE and REPEATABLE[n] in self.ran)
                                or (n in CHAIN_OF and all(c in self.ran for c in CHAIN_OF[n]["cases"]))
                                or (n in REPEAT_SCENARIOS and n in self.ran))]
        wanted = {n for n in self.highwater if n in REPEATABLE} | {REPEATABLE[n] for n in self.highwater if n in REPEATABLE}
        wanted |= {n for n in REPEATABLE if n in self.ran and REPEATABLE[n] in self.ran}
        pairs = [n for n in self.ran if n in wanted]          # run order: each gzip before its gunzip
        chains = [c for c in CHAINS if any(n in self.highwater for n in c["cases"])
                  and not any(n in self.limited for n in c["cases"])]
        return unrepeatable, pairs, chains

    def a17_line(self):
        """SPEC A17's summary: printed once all three proofs have run (before
        the case's own census), or at the end of a run that ran only some."""
        print("CPORTS SQLITE LOCK :: " + " ".join(f"{k}={v or 'not-run'}" for k, v in self.a17.items()), flush=True)
        self.a17_printed = True

    def round_line(self, case, k, census):
        print(f"CPORTS RESOURCES RESTART ROUND {case.name} round={k} :: {census['memory']} | {census['kernel']} | "
              f"images={census['images']} objects={len(census['objects'])} fsd_heap_peak={census['fsd']}", flush=True)

    def restart_rounds(self, case, method, first):
        """Ruling 1: round 2 removes RESTART_ROUNDS[case] with /bin/rm, then
        repeats the whole stop/restart scenario; the census after each round
        (after the restart and the case's own run) must be equal: images,
        frames, kernel objects and the image's object names. Returns round 2's
        seconds."""
        self.round_line(case, 1, first)
        start = time.monotonic()
        present = self.objects()
        gone = [p for p in RESTART_ROUNDS[case.name] if f"{CPORTS}/{case.cwd}/{p}" in present]
        if gone:
            rc, out, err, _, _ = self.shell_ssh(f"cd {CPORTS}/{case.cwd}; " + " ".join(ck.quote(w) for w in ["/bin/rm", *gone]))
            left = self.objects()
            self.check(f"{case.name} round 2: removed {gone}", rc == 0 and out == b"" and err == b"" and
                       not any(f"{CPORTS}/{case.cwd}/{p}" in left for p in gone), f"{rc} {out!r} {err!r}")
        self.restart_round = 2
        try:
            before = self.stable(case.name, "round 2 before")
            self.rest_kernel(f"{case.name} round 2 before", before)
            self.rest_opens(f"{case.name} round 2 before", before)
            self.case_before = before
            method(case)
            after = self.stable(case.name, "round 2 after")
            self.check(f"{case.name} round 2 restarted QEMU", self.rebased is not None)
            rebased, self.rebased = self.rebased, None
            self.compare_census(case, rebased, after, restart=True)
            after = self.judged

            def same_round(now):
                return ((first["images"], first["memory"], first["kernel"], first["fsd"])
                        == (now["images"], now["memory"], now["kernel"], now["fsd"])
                        and {o[0] for o in first["objects"]} == {o[0] for o in now["objects"]})
            after = self.settle(f"{case.name} round 2", after, same_round)
        finally:
            self.restart_round = 1
        self.round_line(case, 2, after)
        self.check(f"{case.name}: the census after round 2 equals the census after round 1 (images, frames, kernel "
                   f"objects, the file server's heap peak, object names)",
                   (first["images"], first["memory"], first["kernel"], first["fsd"])
                   == (after["images"], after["memory"], after["kernel"], after["fsd"])
                   and {o[0] for o in first["objects"]} == {o[0] for o in after["objects"]},
                   f"round 1 {first['memory']} {first['kernel']} round 2 {after['memory']} {after['kernel']} "
                   f"fsd heap peak {heap_step(first['fsd'], after['fsd'])} names "
                   f"{sorted({o[0] for o in first['objects']} ^ {o[0] for o in after['objects']})}")
        return time.monotonic() - start

    def restart_repeat(self, case, db, sql, first):
        """Final review I3: on the restarted boot, B's read-only query runs
        twice more after the recovery query `first`; the census after each
        must equal the census after `first` exactly (images, frames, kernel
        objects, the file server's heap peak, every object and its contents).
        This measures reclamation on the restarted boot; the rounds' equality
        shows only determinism across boots. No allowance: each census is
        the judged census of ruling (b) (stable), the base included, and a
        mismatch fails (opens and handles off rest fail their checks)."""
        base = self.stable(case.name, "restart repeat base")
        self.rest_kernel(f"{case.name} restart repeat base", base)
        self.rest_opens(f"{case.name} restart repeat base", base)

        def exact(now):
            return ((base["images"], base["memory"], base["kernel"], base["fsd"], base["objects"])
                    == (now["images"], now["memory"], now["kernel"], now["fsd"], now["objects"]))
        for k in (1, 2):
            r = self.sqlite_absd(case, db, sql)
            self.check(f"{case.name}: repeat {k} of B's read-only query prints what the recovery query printed",
                       r[:3] == first[:3], f"{r!r} first {first!r}")
            now = self.stable(case.name, f"restart repeat {k}")
            now = self.settle(f"{case.name} restart repeat {k}", now, exact)
            self.rest_kernel(f"{case.name} restart repeat {k}", now)
            self.rest_opens(f"{case.name} restart repeat {k}", now)
            print(f"CPORTS RESOURCES RESTART REPEAT {case.name} :: round={self.restart_round} repeat={k} "
                  f"{now['memory']} | {now['kernel']} | images={now['images']} objects={len(now['objects'])} "
                  f"fsd_heap_peak={now['fsd']}", flush=True)
            self.check(f"{case.name}: the census after repeat {k} of B's query equals the census after the recovery "
                       f"query (round {self.restart_round})", exact(now), self.census_delta(base, now))

    def lock_failed(self, case, what, detail):
        print(f"CPORTS SQLITE LOCK FAILED {case.name} :: {what}: {detail}", flush=True)
        self.check(f"{case.name}: {what}", False, detail)

    def scenario_excl_contention(self, case):
        mode, db = case.args
        getattr(self, "excl_" + mode.replace("-", "_"))(case, db)

    def excl_deny(self, case, db):
        query = "SELECT count(*) FROM t;"
        denied = (1, b"", SQLITE_LOCKED)

        def steps(hold, ask, write, wait, finish):
            a = hold()
            write(a, b"BEGIN; INSERT INTO t VALUES(3,'three');\n.print HELD\n"); wait(a, b"HELD")
            r1 = ask()
            write(a, b"COMMIT;\n.print COMMITTED\n"); wait(a, b"COMMITTED")
            r2 = ask()
            write(a, b".quit\n")
            ra = finish(a)
            r3 = ask()
            return r1, r2, ra, r3

        def write(p, data):
            p.stdin.write(data); p.stdin.flush()

        alive = []

        def absd_hold():
            a = self.hold_sqlite(case, db); alive.append(a); return a

        def absd_ask():
            return self.sqlite_absd(case, db, query, baseline=self.t.all_images())

        try:
            r1, r2, ra, r3 = steps(absd_hold, absd_ask, write, self.await_line, self.finish_session)
        except BaseException:
            for a in alive:
                if a.poll() is None:
                    self.end_session(a)
            raise
        if r1[:3] != denied:
            self.lock_failed(case, "B was not denied while A held the database in a transaction", repr(r1))
        if r1[3] >= 5:
            self.lock_failed(case, "B's refusal waited (the native lock never waits)", f"{r1[3]:.1f} s")
        if r2[:3] != denied:
            self.lock_failed(case, "B was not denied after A's COMMIT (unix-excl keeps the lock for the connection's life)",
                             repr(r2))
        self.check(f"{case.name}: A's session ended normally after .quit", ra == (0, b"HELD\nCOMMITTED\n", b""), repr(ra))
        if r3[:3] != (0, b"3\n", b""):
            self.lock_failed(case, "B was not granted after A quit", repr(r3))
        la = []

        def linux_hold():
            p = self.hold_linux_sqlite(case, db); la.append(p); return p

        try:
            l1, l2, lra, l3 = steps(linux_hold, lambda: self.sqlite_linux(case, db, query), write, self.await_line,
                                    lambda p: self.quit_after_input(p))
        finally:
            for p in la:
                if p.poll() is None:
                    self.kill_linux(p)
        self.check(f"{case.name}: the Linux twin prints the same (denied, denied after commit, A ends 0, granted with 3)",
                   (l1, l2, l3) == (denied, denied, (0, b"3\n", b"")) and lra == ra, f"{l1!r} {l2!r} {lra!r} {l3!r}")
        self.a17["denied"] = "yes"
        print(f"CPORTS SCENARIO OK {case.name} denied_in_transaction=yes denied_after_commit=yes granted_after_quit=yes :: "
              f"B refused in {r1[3]:.1f} s and {r2[3]:.1f} s, granted 3 after A's .quit; Linux equal; native truth: "
              f"A's descriptor holds the file server's exclusive whole-file lock (absd_fd_lock mode 2, fs try_lock) "
              f"until its last descriptor closes", flush=True)

    def quit_after_input(self, p):
        """The Linux A after `.quit` was written: its exit status and streams."""
        out, err = p.communicate(timeout=120)
        return p.returncode, p.seen + out, err

    def excl_kill_holder(self, case, db):
        query = "SELECT count(*) FROM t;"
        denied = (1, b"", SQLITE_LOCKED)
        a = self.hold_sqlite(case, db)
        try:
            a.stdin.write(b"BEGIN; INSERT INTO t VALUES(4,'four');\n.print HELD\n"); a.stdin.flush()
            self.await_line(a, b"HELD")
            r1 = self.sqlite_absd(case, db, query, baseline=self.t.all_images())
        finally:
            self.end_session(a)
        r2 = self.sqlite_absd(case, db, query)
        absd_names = self.names(case.cwd)
        if r1[:3] != denied:
            self.lock_failed(case, "B was not denied while A held the database", repr(r1))
        if r2[:3] != (0, b"3\n", b""):
            self.lock_failed(case, "the lock was not released when A's session was killed", repr(r2))
        la = self.hold_linux_sqlite(case, db)
        try:
            la.stdin.write(b"BEGIN; INSERT INTO t VALUES(4,'four');\n.print HELD\n"); la.stdin.flush()
            self.await_line(la, b"HELD")
            l1 = self.sqlite_linux(case, db, query)
        finally:
            self.kill_linux(la)
        l2 = self.sqlite_linux(case, db, query)
        linux_names = sorted(os.listdir(self.linux_dir(case.cwd)))
        self.check(f"{case.name}: the Linux twin prints the same", (l1, l2) == (denied, (0, b"3\n", b"")), f"{l1!r} {l2!r}")
        if absd_names != linux_names:
            print(f"CPORTS SCENARIO NOTE {case.name} :: directory after the kill differs: ABSD {absd_names} Linux "
                  f"{linux_names}", flush=True)
        self.a17["released_on_death"] = "yes"
        print(f"CPORTS SCENARIO OK {case.name} released_on_death=yes :: B refused in {r1[3]:.1f} s; after A's session "
              f"was killed B printed 3 (A's row absent); directory ABSD {absd_names} Linux {linux_names}; native truth: "
              f"the file server dropped the channel's open files and their locks (drop_opens) when sshd released the "
              f"session", flush=True)

    @staticmethod
    def spill_input():
        return (b"PRAGMA cache_size=10;\nBEGIN;\n" + b"".join(b"INSERT INTO t(v) VALUES('" + b"x" * 200 + b"');\n"
                                                             for _ in range(2000)) + b".print SPILLED\n")

    def excl_crash_recover(self, case, db):
        sql = "PRAGMA integrity_check; SELECT count(*) FROM t;"
        want = (0, b"ok\n3\n", b"")
        a = self.hold_sqlite(case, db)
        writer = self.feed(a, self.spill_input())
        try:
            self.await_line(a, b"SPILLED", timeout=900)
        except BaseException:
            self.end_session(a)
            raise
        writer.join(timeout=5)
        err = self.pending_stderr(a)
        if err:
            self.end_session(a)
            self.lock_failed(case, "A wrote to stderr before the cut", repr(err[-400:]))
        spilled = self.names(case.cwd)
        pre = self.cut(case, a, "excl-crash")
        pre_tree = self.image_tree(pre)
        pre_names = self.names(case.cwd, pre_tree)
        if f"{db}-journal" not in pre_names:
            print(f"CPORTS SQLITE LOCK FAILED {case.name} :: no {db}-journal on the image at the cut: {pre_names}", flush=True)
            self.check(f"{case.name}: a hot journal is on the image at the cut", False, str(pre_names))
        r = self.sqlite_absd(case, db, sql)
        after = self.names(case.cwd)
        pre_read = self.host_reader(pre.stem, pre_tree, case.cwd, [db, f"{db}-journal"],
                                    ["PRAGMA integrity_check", "SELECT count(*) FROM t"])
        live_read = self.host_reader(pre.stem.replace("-pre", "-after"), self.t.tree(), case.cwd, [db],
                                     ["PRAGMA integrity_check", "SELECT count(*) FROM t"])
        if r[:3] != want or f"{db}-journal" in after:
            self.lock_failed(case, "the hot journal was not recovered on the next boot",
                             f"{r!r} directory {after}; image {pre}; serials {self.t.log.name} and the one before it")
        if pre_read != b"ok\n3\n" or live_read != b"ok\n3\n":
            self.lock_failed(case, "the host reader disagrees (pre-recovery database + journal, or the recovered "
                             "database)", f"pre {pre_read!r} after {live_read!r}; image {pre}; serials "
                             f"{self.t.log.name} and the one before it")
        self.restart_repeat(case, db, sql, r)
        # The Linux twin: A killed with SIGKILL instead of a machine stop.
        la = self.hold_linux_sqlite(case, db)
        lw = self.feed(la, self.spill_input())
        try:
            self.await_line(la, b"SPILLED", timeout=300)
            linux_spilled = sorted(os.listdir(self.linux_dir(case.cwd)))
        finally:
            self.kill_linux(la)
            lw.join(timeout=5)
        l1 = self.sqlite_linux(case, db, sql)
        linux_after = sorted(os.listdir(self.linux_dir(case.cwd)))
        self.check(f"{case.name}: the Linux twin (A killed) prints the same and removes the journal",
                   l1 == want and f"{db}-journal" in linux_spilled and f"{db}-journal" not in linux_after,
                   f"{l1!r} at the kill {linux_spilled} after {linux_after}")
        self.a17["hot_journal_recovered"] = "yes"
        if all(self.a17.values()) and not self.a17_printed:
            self.a17_line()
        print(f"CPORTS SCENARIO OK {case.name} hot_journal_recovered=yes host_reader_agrees=yes :: at SPILLED the guest "
              f"directory was {spilled}, the image at the cut held {pre_names}; next boot B printed ok and 3 and "
              f"{db}-journal is gone ({after}); Linux equal; native truth: the journal's synced bytes survive the stop "
              f"(fsync returns after the file server's commit) and the next connection's exclusive lock (no other "
              f"holder after a boot) lets it roll the journal back", flush=True)

    def scenario_power_cut(self, case):
        db, n, m = case.args[0], int(case.args[1]), int(case.args[2])
        total = n * (n + 1) // 2
        sql = "PRAGMA integrity_check; SELECT count(*), sum(k) FROM t;"
        want = f"ok\n{n}|{total}\n".encode()
        rows = lambda lo, hi: b"".join(f"INSERT INTO t VALUES({k}, substr(hex(zeroblob(100)),1,200) || {k});\n".encode()
                                       for k in range(lo, hi + 1))
        a = self.hold_sqlite(case, db)
        try:
            w1 = self.feed(a, b"CREATE TABLE t(k INTEGER PRIMARY KEY, v BLOB);\nBEGIN;\n" + rows(1, n) +
                           f"COMMIT;\n.print COMMITTED n={n} sum={total}\n".encode())
            self.await_line(a, f"COMMITTED n={n} sum={total}".encode(), timeout=900)
            w1.join(timeout=5)
            w2 = self.feed(a, b"PRAGMA cache_size=10;\nBEGIN;\n" + rows(n + 1, n + m) + b".print UNCOMMITTED-WRITTEN\n")
            self.await_line(a, b"UNCOMMITTED-WRITTEN", timeout=900)
            w2.join(timeout=5)
        except BaseException:
            self.end_session(a)
            raise
        err = self.pending_stderr(a)
        if err:
            self.end_session(a)
            print(f"CPORTS SQLITE POWER-CUT FAILED {case.name} :: A wrote to stderr before the cut: {err[-400:]!r}",
                  flush=True)
            self.check(f"{case.name}: A's stderr is empty before the cut", False, repr(err[-400:]))
        written = self.names(case.cwd)
        pre = self.cut(case, a, "power-cut")
        pre_tree = self.image_tree(pre)
        pre_names = self.names(case.cwd, pre_tree)
        r = self.sqlite_absd(case, db, sql)
        after = self.names(case.cwd)
        pre_read = self.host_reader(pre.stem, pre_tree, case.cwd, [db, f"{db}-journal"],
                                    ["PRAGMA integrity_check", "SELECT count(*), sum(k) FROM t"])
        live_read = self.host_reader(pre.stem.replace("-pre", "-after"), self.t.tree(), case.cwd, [db],
                                     ["PRAGMA integrity_check", "SELECT count(*), sum(k) FROM t"])
        ok = (r[:3] == (0, want, b"") and f"{db}-journal" not in after and f"{db}-journal" in pre_names
              and pre_read == want and live_read == want)
        if not ok:
            print(f"CPORTS SQLITE POWER-CUT FAILED {case.name} :: B {r!r}; directory at the cut {pre_names}, after {after}; "
                  f"host reader pre {pre_read!r} after {live_read!r}; image {pre}; serial {self.t.log.name} and the one "
                  f"before it", flush=True)
        self.check(f"{case.name}: after the cut the committed rows survive, the uncommitted are absent, the journal is "
                   f"gone (and it was on the image at the cut), and the host reader agrees", ok,
                   f"{r!r} {pre_names} {after} pre {pre_read!r} after {live_read!r}")
        self.restart_repeat(case, db, sql, r)
        print(f"CPORTS SCENARIO OK {case.name} committed_survives=yes uncommitted_absent=yes host_reader_agrees=yes :: "
              f"at UNCOMMITTED-WRITTEN the guest directory was {written}, the image at the cut held {pre_names}; next "
              f"boot B printed ok and {n}|{total}; {db}-journal gone; native truth: COMMIT's journal deletion and "
              f"fsyncs return after the file server's commit, and the synced hot journal restores the spilled pages",
              flush=True)

    def scenario_excl_concurrency_loss(self, case):
        db = case.args[0]
        query = "SELECT count(*) FROM t;"
        hold_text = b"BEGIN; INSERT INTO t VALUES(9,'nine');\n.print HELD\n"
        results = {}
        for vfs in ("unix", "unix-excl"):
            la = self.hold_linux_sqlite(case, db, vfs)
            try:
                la.stdin.write(hold_text); la.stdin.flush()
                self.await_line(la, b"HELD")
                results[f"linux-{vfs}"] = self.sqlite_linux(case, db, query, vfs)
                results[f"linux-{vfs}-quit"] = self.quit_linux(la)
            finally:
                if la.poll() is None:
                    self.kill_linux(la)
            results[f"linux-{vfs}-after"] = self.sqlite_linux(case, db, query)
        a = self.hold_sqlite(case, db)
        try:
            a.stdin.write(hold_text); a.stdin.flush()
            self.await_line(a, b"HELD")
            results["absd-unix-excl"] = self.sqlite_absd(case, db, query, baseline=self.t.all_images())[:3]
            a.stdin.write(b".quit\n"); a.stdin.flush()
            results["absd-unix-excl-quit"] = self.finish_session(a)
        except BaseException:
            if a.poll() is None:
                self.end_session(a)
            raise
        results["absd-unix-excl-after"] = self.sqlite_absd(case, db, query)[:3]
        denied = (1, b"", SQLITE_LOCKED)
        three = (0, b"3\n", b"")
        quit_ok = (0, b"HELD\n", b"")
        self.check(f"{case.name}: Linux unix reader succeeds, Linux unix-excl and ABSD unix-excl readers are denied, "
                   f"each A quits and the count stays 3",
                   results["linux-unix"] == three and results["linux-unix-excl"] == denied
                   and results["absd-unix-excl"] == results["linux-unix-excl"]
                   and all(results[k] == quit_ok for k in ("linux-unix-quit", "linux-unix-excl-quit", "absd-unix-excl-quit"))
                   and all(results[k] == three for k in ("linux-unix-after", "linux-unix-excl-after", "absd-unix-excl-after")),
                   repr(results))
        print(f"CPORTS SCENARIO OK {case.name} linux_unix_reader=ok linux_excl_reader=denied absd_excl_reader=denied :: "
              f"the declared loss: while one process has the database open read-write no other process can read it, "
              f"where the default unix VFS on Linux lets readers proceed until the writer's commit; native truth: "
              f"unix-excl's single range maps to the file server's exclusive whole-file lock (c/posix/fcntl.c, "
              f"absd_fd_lock mode 2), which never coexists with a reader, and A's .quit released it through the "
              f"file server's channel release (the count stayed 3 on ABSD)", flush=True)

    # -- the run -------------------------------------------------------------------

    def session_probes(self):
        rc, out, err, _, _ = self.shell_ssh('"/bin/df"')
        self.check("df in a session", rc == 0 and err == b"", f"{rc} {out!r} {err!r}")
        m = re.search(r"^absd:[0-9a-f]+ +(\d+) +(\d+) +(\d+) ", out.decode(), re.M)
        self.check("df reports the filesystem's space", m is not None, out.decode())
        total, used, free = (int(x) * 1024 for x in m.groups())
        print(f"CPORTS IMAGE capacity={total} used={used} available={free} image={ssh_absd.IMAGE_BYTES}", flush=True)
        limits = 0
        if total <= 48 * 1024 * 1024:
            print(f"CPORTS LIMIT image :: capacity {total} used {used} available {free} (image {ssh_absd.IMAGE_BYTES}), "
                  f"speedtest1 --size 20 not run", flush=True)
            self.speedtest_limit = True
            limits += 1
        return limits

    def run(self):
        t = self.t
        self.connections = 0
        self.cports_warm = None
        self.warm_finished = False
        started = time.monotonic()
        os.umask(0o022)
        sm.require(sha(self.one) == ONE_BIN_SHA256, f"one.bin sha256 {sha(self.one)} != recorded {ONE_BIN_SHA256}")
        print(f"CPORTS ONE.BIN sha256={sha(self.one)} bytes={len(self.one)} (research-phase prefix 6ee9c255 "
              f"not reproduced; recorded digest matched)", flush=True)
        linux = self.work / "linux"
        if linux.exists():
            shutil.rmtree(linux)
        for cwd, entries in self.dirs.items():
            base = self.linux_dir(cwd)
            base.mkdir(parents=True)
            for rel, data in entries:
                (base / rel).parent.mkdir(parents=True, exist_ok=True)
                (base / rel).write_bytes(data)
        ssh_absd.IMAGE_BYTES = IMAGE_BYTES
        ssh_absd.DEVICE_SECTORS = ssh_absd.IMAGE_BYTES // 512
        authorized = (self.op.with_suffix(".pub")).read_text()
        imported = t.files(authorized)
        t.setup(self.work, authorized)
        link = self.work / "cports.img"
        if not link.exists():
            link.symlink_to("ssh.img")
        setup_done = time.monotonic()
        print(f"CPORTS IMPORT files={len(imported)} bytes={sum(len(d) for _, d in imported)} boots={t.boots} "
              f"seconds={setup_done - started:.1f}", flush=True)
        first = t.start(fresh=True)
        print(f"CPORTS BOOT SECONDS sshd={time.monotonic() - setup_done:.1f}", flush=True)
        self.client = sm.Client(self.work, t.port)
        self.client.trust(first["public"])
        self.host_key = first["public"]
        self.first, self.rebased, self.case_before = {}, None, None
        self.a17 = {"denied": None, "released_on_death": None, "hot_journal_recovered": None}
        self.a17_printed = False
        self.steps, self.restart_round, self.repeated = 0, 1, False
        self.rest = None
        self.limited = set()
        self.speedtest_limit = False
        counts = {"agree": 0, "diverge": 0, "defect": 0, "scenario": 0, "probe": 0}
        limits = self.session_probes()
        self.take_rest("boot 1 after its first sessions")
        resources = 0
        timings = []
        self.highwater, self.ran = [], {}
        if self.pin:
            print('CPORTS WARM NOT_ESTABLISHED reason=pin-authoring', flush=True)
        else:
            # Prerequisite directories/large input are prepared before cold sampling.
            chosen = cw.selected(self, types.SimpleNamespace(**globals()))
            for case in chosen:
                self.ensure_dir(case.cwd)
                if case.name == 'zlib.gzip-8m':
                    self.make_eight(case)
            if chosen:
                self.cports_warm = cw.Rehearsal(self, types.SimpleNamespace(**globals()))
                self.cports_warm.establish()
                self.steps = 0
            else:
                print('CPORTS WARM NOT_ESTABLISHED reason=no-nonstopping-workload R23=PARTIAL', flush=True)
        for case in self.cases:
            self.ensure_dir(case.cwd)
            if case.route == "probe":
                rc, out, err, _, pids = self.shell_ssh(self.text(case), timeout=case.timeout)
                self.check(f"{case.name}: the probe ran", rc == 0 and err == b"" and len(pids) == 1, f"{rc} {out!r} {err!r}")
                (self.work / f"{case.name}.absd.out").write_bytes(out)
                if case.name == "probe.env":
                    env = [l for l in out.decode().splitlines() if "=" in l]
                    print(f"CPORTS SESSION ENV count={len(env)} {' '.join(sorted(env))}", flush=True)
                    self.check("the session's environment is empty (SPEC A20; never manufactured)", not env, str(env))
                counts["probe"] += 1
                continue
            if case.route == "scenario":
                method = getattr(self, "scenario_" + case.program.replace("-", "_"), None)
                if method is None:
                    self.check(f"{case.name}: scenario {case.program} has a method (or --skip-scenarios)", self.skip_scenarios)
                    print(f"CPORTS SCENARIO SKIPPED {case.name}", flush=True)
                    limits += 1
                    continue
            if case.name == "zlib.gzip-8m":
                self.make_eight(case)
            if case.name == "sqlite.speedtest1-20" and self.speedtest_limit:
                print(f"CPORTS LIMIT {case.name} :: not run (image capacity, CPORTS IMAGE above)", flush=True)
                continue
            # Close the rehearsed measured group before the separate D-24
            # repeat warmup can take its permitted first-use heap step.
            if case.name in RESTART_ROUNDS and self.cports_warm and not self.warm_finished:
                self.cports_warm.finish()
                self.warm_finished = True
                print('CPORTS WARM stopping-cases=NOT_ESTABLISHED R23=PARTIAL', flush=True)
            if case.name in RESTART_ROUNDS and self.highwater and not self.repeated:
                # Ruling (a): the repeat rounds measure the warm boot that ran
                # the cases, so they run before the first stopping scenario.
                self.repeat_round()
                self.repeated = True
            if case.route == "scenario" and not getattr(self, "warmed", False):
                self.frames_warmup()
            before = self.stable(case.name, "before")
            self.case_before = before
            start = time.monotonic()
            if case.route == "scenario":
                stated = method(case)
                if case.name in REPEAT_SCENARIOS:
                    self.first[case.name] = stated
                verdict = "scenario"
            else:
                sm.require(case.route == "shell", f"{case.name}: unknown route {case.route}")
                try:
                    got, ref = self.run_shell_case(case)
                except SessionTimeout as e:
                    if case.name in LIMIT_ON_TIMEOUT:
                        self.limit_case(case, e, start, before)
                        limits += 1
                        timings.append((case.name, time.monotonic() - start))
                        continue
                    memory, kernel, after = self.timed_out(case, e, start, before)   # re-raises unless annotated
                    counts["defect"] += 1
                    resources += 1
                    took = time.monotonic() - start
                    timings.append((case.name, took))
                    print(f"CPORTS RESOURCES {case.name} :: {memory} | {kernel} | images={after['images']} "
                          f"objects={len(after['objects'])} seconds={took:.1f}", flush=True)
                    continue
                if case.name in INTEGRITY:
                    self.integrity(case)
                verdict = None
            took = time.monotonic() - start
            after = self.stable(case.name, "after")
            restart = self.rebased is not None
            if restart:
                before, self.rebased = self.rebased, None
            memory, kernel = self.compare_census(case, before, after, restart=restart)
            after = self.judged
            if case.name in RESTART_ROUNDS:
                took += self.restart_rounds(case, method, after)
            resources += 1
            if verdict is None:
                verdict = self.judge(case, got, ref)
                if case.outputs:
                    self.check_outputs(case)
                if case.program == "/bin/speedtest1" and verdict == "agree":
                    self.verify_line(case, got)
                # The all.lua stop rule (A20, files.lua:8) is about the test suite, not
                # about every program that happens to be /bin/lua (lua.recursion runs a
                # one-line -e program and must simply agree with Linux).
                if case.program == "/bin/lua" and "all.lua" in case.args:
                    self.check_lua(case, self.normalized(case, got), self.normalized(case, ref))
            counts[verdict] += 1
            self.ran[case.name] = case
            timings.append((case.name, took))
            print(f"CPORTS RESOURCES {case.name} :: {memory} | {kernel} | images={after['images']} "
                  f"objects={len(after['objects'])} seconds={took:.1f}", flush=True)
        if any(v is not None for v in self.a17.values()) and not self.a17_printed:
            self.a17_line()
        self.alive("the cports cases")
        if self.cports_warm and not self.warm_finished:
            self.cports_warm.finish()
            self.warm_finished = True
        if self.highwater and not self.repeated:
            self.repeat_round()
            self.alive("the repeat rounds")
        t.stop()
        print("CPORTS TIMINGS " + " ".join(f"{n}={s:.1f}" for n, s in timings), flush=True)
        print(f"CPORTS SHELL OK cases={len(self.cases)} agree={counts['agree']} diverge={counts['diverge']} "
              f"defects={counts['defect']} scenarios={counts['scenario']} probes={counts['probe']} limits={limits}",
              flush=True)
        self.rest_recorded()
        print(f"CPORTS RESOURCES OK cases={resources} highwater={len(self.highwater)} "
              f"repeat={'ok' if self.highwater else 'none'}", flush=True)
        print(f"CPORTS MATRIX OK seconds={time.monotonic() - started:.0f}", flush=True)


def repeat_boot_budget(seconds):
    """Scale the base two-round budget for judged rounds plus one warm round.

    Default two judged rounds reserve base * 3/2; diagnostic N uses (N+1)/2.
    Apply only at the cports entry point, before any boot, not to importers.
    """
    diag = os.environ.get("ABSD_CPORTS_DIAG_REPEAT_ROUNDS")
    rounds = 2 if diag is None else int(diag)
    if rounds < 2 or seconds <= 0:
        raise ValueError("repeat rounds must be at least 2 and --boot-seconds must be positive")
    return seconds * (rounds + 1) / 2


def main():
    ap = argparse.ArgumentParser()
    for name in ("work", "absd", "linux", "cases", "upstream"):
        ap.add_argument(f"--{name}", required=True)
    ap.add_argument("--only", action="append", help="run only cases whose name starts with this prefix")
    ap.add_argument("--pin", action="append", help="write cports/absd-expected/<case>.txt from this run (review it)")
    ap.add_argument("--skip-scenarios", action="store_true", help="skip scenarios with no method (counted as limits)")
    argv = sys.argv[1:]
    print("CPORTS ARGS " + " ".join(sys.argv), flush=True)
    rest = []
    if "--" in argv:
        i = argv.index("--")
        argv, rest = argv[:i], argv[i + 1:]
    args = ap.parse_args(argv)
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    base = ssh_absd.target(rest)
    original_budget = base.boot_seconds
    base.boot_seconds = repeat_boot_budget(original_budget)
    rounds = os.environ.get("ABSD_CPORTS_DIAG_REPEAT_ROUNDS", "2")
    print(f"CPORTS BOOT BUDGET seconds={base.boot_seconds:g} base={original_budget} "
          f"formula=base*({rounds}+1)/2 includes_warm=yes", flush=True)
    target = CportsTarget.__new__(CportsTarget)
    target.__dict__.update(base.__dict__)
    matrix = CportsMatrix(target, work, args)
    try:
        matrix.run()
    except (sm.Failed, ck.sm.Failed, ssh_absd.Failed, cw.wb.BaselineError) as e:   # c-kit-matrix loads its own ssh-matrix
        print(f"CPORTS MATRIX FAILED: {e}", file=sys.stderr, flush=True)
        target.stop()
        sys.exit(1)
    except BaseException:
        target.stop()
        raise


if __name__ == "__main__":
    main()
