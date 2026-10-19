#!/usr/bin/env python3
"""Stage 3 on the shell route: /bin/tcc compiles in the guest, the shell
spawns what it wrote (docs/c-ecosystem-20261010/tcc/STAGE3-DESIGN.md;
plan Task 5 with the controller's rulings in task-5-context.md).

One `net fsd` boot (scripts/ssh_absd.py) on the Stage 2 harness fixture, a
128 MiB image (cports-matrix.IMAGE_BYTES). The image carries, beside
ssh_absd's deployment and cports-matrix's extra commands, /bin/cp,
/bin/sha256sum, /bin/tcc (tcc-build/absd/tcc), the share tree
tcc-build/share/absd-c/** at /share/absd-c/** (checked against
tcc-build/share.sha256 on the image by the host's own reader), each case's
source with the files it includes by `#include "..."` and its stdin file at
/home/operator/tcc-cases/<basename>, and the negative control
/home/operator/hello-relro.elf. /home/operator/tcc-out is made by a session
`"/bin/mkdir"` and checked on the image.

A compile-run case is ONE held absd-sh session (no exec text: sshd starts
the shell reading its stdin; ruling 1). Each command is fed as its own
line, followed by three builtin lines: `status` (the command's status, on
stdout), `exit <mark>` (not a number: the shell prints
`absd-sh: exit: <mark>: not a number` on stderr and goes on) and
`echo <mark>`; the step ends when both marks arrived, and the command's
stdout, status and stderr are cut out exactly between the marks
(split_step: prompts and builtin lines are the shell's own, nothing of the
program's output is changed). The commands, in order:
  "/bin/ls" /tmp            -> exactly `session-<n>/`: this session's
                               scratch directory (truth source: the
                               session's own mount listing; fsd shows a
                               session only its own directory)
  cd /tmp/session-<n>
  "/bin/tcc" /home/operator/tcc-cases/<src> -o a.out      status 0
  "/bin/sha256sum" a.out    -> the digest of what tcc wrote, in the session
  "/bin/cp" a.out /home/operator/tcc-out/<case>.elf
  ./a.out ARGS... [< /home/operator/tcc-cases/<stdin>]
The scratch directory is removed when the session ends (fsd release), so
the copy is what the host reads back from the image after the session; its
bytes must have the digest sha256sum printed in the session (the copy is
exact) and equal tcc-build/hostcfg/tcc's output for the same source
(expected/<case>.elf; hostcfg bakes the host share path, the guest's tcc
/share/absd-c; tcc embeds no path in a static non-`-g` link: shown by the
comparison itself) as a whole file; a difference prints the first differing
offset and the section holding it. Each spawn is the kernel's own line:
`SPAWN OK pid=<p> parent=<shell> program=image` and `USER EXIT pid=<p>
status=<s>`, which must equal the status the shell reported.

The program's stdout, stderr (absd-sh's `exit status` line required when
the status is not 0, then removed and kept raw) and status are compared
with the Linux reference: tcc-build/host/tcc's (glibc, dynamic) build of
the same source, run twice (equal) with argv[0] the program path the shell
spawned (`/tmp/session-<n>/a.out`: absd-sh resolves `./a.out` against its
cwd, sh/src/lib.rs program_path, and passes it to Command::new,
src/sh_host.rs), the same arguments and stdin bytes, the session's
environment as `"/bin/printenv"` printed it in a held session (empty, SPEC
A20; never manufactured), umask 022, SIGPIPE ignored, in a fresh empty
directory. No normalizers. Stdin is not the same kind of object on both
sides (final review, Task 5 #9): a `# stdin` row reads a file by `<` in the
guest and a pipe carrying the same bytes on Linux; a row without stdin
inherits the shell's command stream in the guest and gets an empty pipe on
Linux. No current source depends on the difference (short reads to EOF;
errno's lseek gives ESPIPE on both sides), and a guest child that read
stdin would consume the session's builtin lines and time its step out, so
the asymmetry fails safe.

A spawn-refused case (the negative control, ruling 2) is a held session:
cd /home/operator; "/bin/ls" -l <file>; "/bin/sha256sum" <file>;
./<file>. The kernel prints nothing on an image refusal; the evidence is
all four of: the shell's exact `cannot run: not a static ELF64 image the
ABSD loader accepts` with status 126; the file present with the host
file's size, at most 32 MiB (so the runtime's missing/oversize/directory
refusals are excluded) and the host file's digest; no `SPAWN OK` of a child
of the shell during that command, empty stdout, and over the whole session
no child of the shell but the `ls` and `sha256sum` children; the host
gate's reason for the same bytes naming type 0x6474e552.

Judging: tcc/absd-expected/CLASSES (CASE, DIVERGES|DEFECT, CLASS, REASON;
CLASS one of CLASSES_ALLOWED) with the ABSD outputs pinned in
tcc/absd-expected/<case>.txt (stdout, `--`, stderr, `--`, status): such a
case must equal its pin and differ from Linux; any other case must equal
Linux. A `kit divergence` row's pin must also be the kit's own Stage 1 pin
(c/tests/kit/shell-expected/<test>.txt: stdout, status, and stderr with
absd-sh's status line stripped; final review M11). A case that cannot be
judged (compile failure, a refused a.out, an a.out not identical to the
host build) is printed as TCC FINDING with its evidence and fails the run
until it is classified; nothing is masked. An a.out difference prints the
offset, its section and 16 bytes either side, guest and host, and no CASE
line follows it.

Resources: the inherited Stage 2 rules (cports-matrix compare_census,
settle, frames_step, the HIGHWATER rule), the only allowed file change of a
case being its /home/operator/tcc-out/<case>.elf; each compile-run case is
repeatable (re-running it rewrites the same file with the same bytes); the
run ends with the repeat round (repeat()): `hello` and every case that took
the high-water allowance, each `cwd` case with its whole chain, compile-run
twice more, each round's census (images, frames, kernel objects, the file
server's heap peak, object names) equal to the census before the rounds,
each case's a.out and outputs equal to its first run's (short.writer's
timing figure judged by its range).

Markers: TCC ARGS; TCC IMPORT files= bytes= boots=; TCC IMPORT SHARE OK;
TCC IMPORT TCC sha256=<absd/tcc> hostcfg_sha256=<hostcfg/tcc>; TCC IMAGE; TCC SESSION ENV; TCC DIR MADE; TCC HOST <case>; TCC COMPILE OK
<case> bytes= sha256= identical_to_host=yes|no seconds=; TCC COPY OK; TCC
SPAWN OK <case> status= seconds=; TCC SPAWN REFUSED hello-relro :: shell=126
"<message>" present=<bytes> serial=no-spawn-ok gate=<reason>; TCC TRUTH
<case> :: ...; TCC CASE OK|DIVERGES|DEFECT <case> :: <class>; TCC FINDING
<case> :: ...; TCC DIVERGES <case> :: output differs at offset N (section);
TCC RESOURCES <case> :: ...; TCC RESOURCES REPEAT OK; TCC TIMINGS; ABSD TCC
STAGE3 OK cases= agree= diverge= defects= compile_seconds= for a run of
every case with no --pin, ABSD TCC STAGE3 PARTIAL ... :: only=... pin=...
otherwise (final review M4), or ABSD TCC STAGE3 FAILED ...."""
if __name__ == "__main__":
    print("TCC STAGE NOT_RUN: not included in the public source", flush=True)
    raise SystemExit(78)

import argparse, hashlib, os, pathlib, re, select, shutil, struct, subprocess, sys, time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import ssh_absd  # noqa: E402
import tcc_warm  # noqa: E402
import importlib.util  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), here / f"{name}.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


cm = load("cports-matrix")
ck = cm.ck
gate = load("check-abi-elf")

PROMPT = b"absd$ "                   # sh/src/lib.rs PROMPT, written before every line read
REFUSAL = "not a static ELF64 image the ABSD loader accepts"   # std's text for ERROR_NOT_EXECUTABLE (-8)
MAX_IMAGE = 32 * 1024 * 1024         # runtime/src/process.rs MAX_IMAGE: larger files are refused before the kernel
CASES_DIR = "/home/operator/tcc-cases"
OUT_DIR = "/home/operator/tcc-out"
NEGATIVE = "/home/operator"          # where the negative control's file is imported and spawned
# Named limits (measured values are printed per step): a compile under TCG
# links the kit's archives in the guest; these bound a step, they are not
# expectations.
COMPILE_TIMEOUT = 1800
RUN_TIMEOUT = 600
STEP_TIMEOUT = 300
REPEAT_CASE = "hello"
REPEAT_ROUNDS = 2
EXTRA = ["cp", "sha256sum", "head", "rm"]  # beside cports-matrix.EXTRA (mkdir cat df sysinfo ls)
# The one row whose stderr carries a timing-dependent figure by construction
# (where a pipe write fails after head exits; controller ruling, fix round 0b):
# stdout, status and the a.out bytes are compared exactly, the figure is
# printed and judged by Stage 1's range (c-kit-matrix.py `short writer`). Not
# a general mechanism: no other row may use it.
TIMING_CASE = "short.writer"
TIMING_ERR = re.compile(rb"write failed after (\d+) bytes\n")
TIMING_RANGE = (1000, 30000)
CLASSES_ALLOWED = ("compiler limitation", "linker limitation", "ABSD ABI defect", "kit divergence")
CONTEXT_BYTES = 16                   # bytes printed either side of a differing a.out offset (M12)
SESSION_START_TIMEOUT = 120          # sshd's SSH SESSION CHILD line for a held session
SESSION_CLOSE_TIMEOUT = 120          # a held session's end of output and reclaim after end of input
CLIENT_WAIT_TIMEOUT = 60             # the ssh client's exit after the session's streams closed
USER_LINE_TIMEOUT = 10               # a child's USER EXIT/KILLED/FAULT line after its step ended
HOST_COMPILE_TIMEOUT = 300           # one host compile (hostcfg tcc, host tcc, gcc)
HOST_QUERY_TIMEOUT = 60              # host tcc's predefined-macro dump


class Refused(Exception):
    """A stream or table the harness will not interpret."""


# -- judging helpers (host-only; scripts/tcc-matrix-selftest.py) -------------

def exit_mark(mark):
    return f"absd-sh: exit: {mark}: not a number\n".encode()


def split_step(out, opos, err, epos, mark):
    """One fed command's (stdout, status, stderr, next stdout position, next
    stderr position), or None while its marks have not both arrived. The
    stdout segment from `opos` is PROMPT command-output PROMPT status\\n
    PROMPT PROMPT mark\\n; the stderr segment from `epos` is the command's
    stderr followed by the `exit <mark>` line."""
    seg, tail = out[opos:], PROMPT + PROMPT + mark.encode() + b"\n"
    at = seg.find(tail)
    if at < 0:
        return None
    eseg, line = err[epos:], exit_mark(mark)
    eat = eseg.find(line)
    if eat < 0:
        return None
    m = re.fullmatch(re.escape(PROMPT) + rb"(.*)" + re.escape(PROMPT) + rb"(-?\d+)\n", seg[:at], re.S)
    if m is None:
        raise Refused(f"step {mark}: stdout is not prompt, output, prompt, status: {seg[:at][-300:]!r}")
    return m.group(1), int(m.group(2)), eseg[:eat], opos + at + len(tail), epos + eat + len(line)


def strip_status(err, name, status, abnormal=False):
    """absd-sh's own report of a non-zero end (sh/src/lib.rs:746, 752),
    required as the last stderr line and removed: (stderr, removed). An
    `abnormal` end (the kernel's USER FAULT line for the child) is reported
    as `ended abnormally` with status 128; an exit code as `exit status n`."""
    if status == 0 and not abnormal:
        return err, False
    line = (f"absd-sh: {name}: ended abnormally\n" if abnormal else f"absd-sh: {name}: exit status {status}\n").encode()
    if (abnormal and status != 128) or not err.endswith(line):
        raise Refused(f"no `{line.decode().strip()}` at the end of stderr (status {status}): {err[-300:]!r}")
    return err[:-len(line)], True


def first_difference(a, b):
    if a == b:
        return None
    n = min(len(a), len(b))
    lo = 0
    step = 4096
    while lo < n and a[lo:lo + step] == b[lo:lo + step]:
        lo += step
    for i in range(lo, min(lo + step, n)):
        if a[i] != b[i]:
            return i
    return n


def section_list(data):
    """[(name, offset, size)] of an ELF64's sections that occupy file bytes
    (names may repeat: tcc keeps input sections it does not merge)."""
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    heads = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    strtab = heads[shstrndx][4]
    out = []
    for name, kind, _, _, offset, size, *_ in heads:
        if kind in (0, 8):                       # SHT_NULL, SHT_NOBITS
            continue
        end = data.index(b"\0", strtab + name)
        out.append((data[strtab + name:end].decode(), offset, size))
    return out


def sections(data):
    """{name: (offset, size)}, the first section of each name."""
    out = {}
    for name, offset, size in section_list(data):
        out.setdefault(name, (offset, size))
    return out


def section_at(data, offset):
    phoff, shoff = struct.unpack_from("<QQ", data, 0x20)
    phentsize, phnum, shentsize, shnum = struct.unpack_from("<HHHH", data, 0x36)
    if offset < 64:
        return "ELF header"
    if phoff <= offset < phoff + phentsize * phnum:
        return "program headers"
    if shoff <= offset < shoff + shentsize * shnum:
        return "section headers"
    for name, start, size in section_list(data):
        if start <= offset < start + size:
            return name
    return "between sections"


def compare_elf(got, want):
    """None when identical, else (first differing offset, the section of the
    host build holding it)."""
    off = first_difference(got, want)
    if off is None:
        return None
    return off, section_at(want if off < len(want) else got, off)


def byte_context(got, want, off, n=CONTEXT_BYTES):
    """Final review M12 (plan Review Focus 4, "both contexts"): `n` bytes
    either side of a differing offset, guest and host, in hex."""
    lo = max(0, off - n)
    return f"context [{lo},{off + n}) guest={got[lo:off + n].hex()} host={want[lo:off + n].hex()}"


def refusal_evidence(status, out, err, listing, host_bytes, serial, shell, gate, children, helpers):
    """Ruling 2's four pieces: (ok, the marker's text, or why not). `out` is
    the refused command's stdout (must be empty); `children` every child
    the kernel spawned for the session's shell, which must be exactly
    `helpers`, the `ls` and `sha256sum` children (final review, Task 5 #5:
    the step's serial window alone could pass vacuously)."""
    want = f"absd-sh: ./hello-relro.elf: cannot run: {REFUSAL}\n".encode()
    if status != 126 or err != want or out != b"":
        return False, f"shell: status {status} stdout {out!r} stderr {err!r}, want 126, empty stdout, {want!r}"
    m = re.fullmatch(rb"- (?:ro|--) \d+ +(\d+) (?:-|[0-9]{4,12}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}) hello-relro\.elf\n", listing)
    if m is None:
        return False, f"no `ls -l` line for the file: {listing!r}"
    size = int(m.group(1))
    if size != host_bytes or size > MAX_IMAGE:
        return False, f"present with {size} bytes; host file {host_bytes}; limit {MAX_IMAGE}"
    spawned = re.findall(rf"SPAWN OK pid=(\d+) parent={shell} program=image", serial)
    if spawned:
        return False, f"the kernel spawned a child of the shell: {spawned}"
    if len(helpers) != 2 or list(children) != list(helpers):
        return False, f"the shell's children in the session {list(children)} are not exactly ls and sha256sum's {list(helpers)}"
    if "type 0x6474e552" not in gate:
        return False, f"the gate's reason does not name PT_GNU_RELRO: {gate!r}"
    return True, (f'shell={status} "{err.decode().strip()}" present={size} serial=no-spawn-ok '
                  f'children={",".join(children)}(ls,sha256sum) gate={gate}')


def parse_pin(data):
    """(status, stdout, stderr) of a pin (c-kit-matrix pin_bytes: stdout,
    `--`, stderr, `--`, `status=<n>`), or None. The first `--` line ends
    stdout; the line before the status line is the second."""
    lines = data.splitlines(keepends=True)
    m = re.fullmatch(rb"status=(-?\d+)\n", lines[-1]) if lines else None
    if m is None or len(lines) < 3 or lines[-2] != b"--\n" or b"--\n" not in lines[:-2]:
        return None
    i = lines.index(b"--\n")
    return int(m.group(1)), b"".join(lines[:i]), b"".join(lines[i + 1:-2])


KIT_STATUS_LINE = re.compile(rb"absd-sh: [^\n]*: (?:exit status -?\d+|ended abnormally)\n\Z")


def kit_pin_agrees(pin, kit_pin):
    """Final review M11: a `kit divergence` row's Stage 3 pin must be the
    kit's own Stage 1 pin (c/tests/kit/shell-expected/<test>.txt): the
    same stdout and status, and the same stderr once absd-sh's status line,
    which the Stage 1 pin keeps and Stage 3 removes, is stripped. (ok, why)."""
    ours, theirs = parse_pin(pin), parse_pin(kit_pin)
    if ours is None or theirs is None:
        return False, f"a pin is not stdout, --, stderr, --, status: ours={ours is not None} kit={theirs is not None}"
    kit_err = KIT_STATUS_LINE.sub(b"", theirs[2])
    if (ours[0], ours[1], ours[2]) != (theirs[0], theirs[1], kit_err):
        return False, f"Stage 3 {ours!r} kit {(theirs[0], theirs[1], kit_err)!r}"
    return True, ""


def kit_pin_path(kit, name):
    """The kit's Stage 1 pin for a Stage 3 row: the kit keys `exit abort` as exit_abort."""
    return kit / "c" / "tests" / "kit" / "shell-expected" / f"{name.replace('.', '_')}.txt"


class Case:
    def __init__(self, fields):
        self.name, self.source, self.kind, *self.args = fields
        self.stdin, self.expect, self.reference, self.cwd, self.pipe = None, "", "tcc", None, None
        self.keeps, self.drops = [], []                              # files of `cwd` the case leaves / removes
        self.outputs, self.retained, self.removed = [], [], []      # compare_census's fields (unused here)


DIRECTIVES = ("stdin", "expect", "reference", "cwd", "pipe", "retained", "removed")


def load_cases(path):
    """Rows NAME SOURCE KIND ARGS...; directives `# <kind> <case>: <value>`
    after their case: stdin FILE; expect TEXT; reference gcc (the Linux
    reference is gcc's build, not host tcc's); cwd DIR (./a.out is run by
    its absolute path from DIR, a directory kept across sessions); pipe
    WORDS (the run's stdout goes through `| WORDS`); retained/removed FILE
    (a file of cwd the case leaves / removes)."""
    cases, by_name = [], {}
    for line in path.read_text().splitlines():
        m = re.match(r"# (\w+) (\S+): (.*)$", line)
        if m and m.group(1) in DIRECTIVES:
            kind, name, rest = m.groups()
            if name not in by_name:
                raise Refused(f"{path}: `# {kind} {name}` names no case above it")
            case = by_name[name]
            if kind == "retained":
                case.keeps.append(rest)
            elif kind == "removed":
                case.drops.append(rest)
            elif kind == "reference":
                if rest != "gcc":
                    raise Refused(f"{path}: reference {rest!r}: only gcc")
                case.reference = rest
            else:
                setattr(case, kind, rest)
            continue
        if not line.strip() or line.startswith("#"):
            continue
        case = Case(line.split("\t"))
        if case.kind not in ("compile-run", "spawn-refused") or case.name in by_name:
            raise Refused(f"{path}: bad or duplicate row {line!r}")
        cases.append(case); by_name[case.name] = case
    return cases


def sha(data):
    return hashlib.sha256(data).hexdigest()


# -- the guest -----------------------------------------------------------------

class Step:
    def __init__(self, command, out, status, err, seconds, children, serial):
        self.command, self.out, self.status, self.err = command, out, status, err
        self.seconds, self.children, self.serial = seconds, children, serial


class Held:
    """One interactive absd-sh session (ruling 1), fed a line at a time."""

    def __init__(self, m):
        self.m, t = m, m.t
        before = len(re.findall(r"SSH SESSION CHILD ", t.output()))
        self.done = m.reclaimed()
        m.connections += 1
        self.p = subprocess.Popen(m.client.base(m.op, ("-T",)), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        self.out, self.err, self.opos, self.epos, self.k = b"", b"", 0, 0, 0
        try:
            deadline = time.monotonic() + SESSION_START_TIMEOUT
            child = []
            while time.monotonic() < deadline:
                # Whole lines only: the log may be read while sshd is still writing one.
                child = re.findall(r"SSH SESSION CHILD pid=(\d+) spawn_right=(\w+) argv0=(\S+) [^\n]*control=(\w+)\r?\n",
                                   t.output())[before:]
                if child:
                    break
                time.sleep(0.2)
            m.check("the held session runs absd-sh with the spawn right and session control",
                    len(child) == 1 and child[0][1:] == ("true", "/bin/absd-sh", "true"), str(child))
        except BaseException:
            # The callers never get the object to kill (final review, Task 5 #3).
            self.kill()
            raise
        self.shell = child[0][0]

    def children(self):
        return re.findall(rf"SPAWN OK pid=(\d+) parent={self.shell} program=image", self.m.t.serial())

    def pump(self, timeout):
        live = [f for f in (self.p.stdout, self.p.stderr) if not f.closed]
        r, _, _ = select.select(live, [], [], timeout)
        got = False
        for f in r:
            chunk = os.read(f.fileno(), 65536)
            if not chunk:
                f.close(); continue
            got = True
            if f is self.p.stdout:
                self.out += chunk
            else:
                self.err += chunk
        return got or bool(r)

    def step(self, command, timeout=STEP_TIMEOUT):
        self.k += 1
        mark = f"tcc-mark-{self.k}"
        before = len(self.children())
        serial_at = len(self.m.t.serial())
        start = time.monotonic()
        self.p.stdin.write(f"{command}\nstatus\nexit {mark}\necho {mark}\n".encode()); self.p.stdin.flush()
        while True:
            done = split_step(self.out, self.opos, self.err, self.epos, mark)
            if done is not None:
                break
            if time.monotonic() - start > timeout:
                raise ck.sm.Failed(f"step {command!r} did not end within {timeout} s (named limit): "
                                   f"stdout tail {self.out[-400:]!r} stderr tail {self.err[-400:]!r}")
            if self.p.stdout.closed and self.p.stderr.closed:
                raise ck.sm.Failed(f"the session ended during {command!r}: {self.out[-400:]!r} {self.err[-400:]!r}")
            self.pump(1.0)
        seconds = time.monotonic() - start
        out, status, err, self.opos, self.epos = done
        children = self.children()[before:]
        return Step(command, out, status, err, seconds, children, self.m.t.serial()[serial_at:])

    def close(self):
        """End of input: the shell exits with the last status (echo: 0); sshd reclaims the session."""
        m = self.m
        self.p.stdin.close()
        deadline = time.monotonic() + SESSION_CLOSE_TIMEOUT
        while not (self.p.stdout.closed and self.p.stderr.closed) and time.monotonic() < deadline:
            self.pump(1.0)
        rc = self.p.wait(timeout=CLIENT_WAIT_TIMEOUT)
        while time.monotonic() < deadline and (m.reclaimed() <= self.done or m.t.all_images() != 0):
            time.sleep(0.2)
        m.check("the held session ended at end of input with status 0 and was reclaimed",
                rc == 0 and m.reclaimed() > self.done and m.t.all_images() == 0,
                f"rc={rc} trailing={self.out[self.opos:]!r} {self.err[self.epos:]!r} {m.t.census_detail()}")

    def kill(self):
        if self.p.poll() is None:
            self.p.kill(); self.p.wait()


class TccTarget(cm.CportsTarget):
    pass


class TccMatrix(cm.CportsMatrix):
    # Every SSH and held session is counted, and no held session remains at
    # a census. Unlike the general C-port scenarios, this sequence can wait
    # for the existing all-sessions-reclaimed gate before starting sysinfo.
    QUIESCENT_READINGS = True
    warm_quote = staticmethod(ck.quote)

    def __init__(self, target, work, args):
        self.repo = here.parent
        self.tcc_build = pathlib.Path(args.tcc_build).resolve()
        self.kit = pathlib.Path(args.kit).resolve()
        table_path = pathlib.Path(args.cases).resolve()
        self.expected_dir = table_path.parent / "absd-expected"
        every = load_cases(table_path)
        names = [c.name for c in every]
        self.cases = [c for c in every if not args.only or c.name in args.only]
        self.only = bool(args.only)
        cm.sm.require(self.cases, f"no case matches --only {args.only}")
        self.pin = set(args.pin or [])
        cm.sm.require(self.pin <= set(names), f"--pin names no case: {sorted(self.pin - set(names))}")
        self.classes = {}
        classes = self.expected_dir / "CLASSES"
        if classes.exists():
            for line in classes.read_text().splitlines():
                if not line.strip() or line.startswith("#"):
                    continue
                name, verdict, klass, reason = line.split("\t")
                cm.sm.require(name in names and verdict in ("DIVERGES", "DEFECT") and klass in CLASSES_ALLOWED,
                              f"CLASSES row not understood: {line!r}")
                self.classes[name] = (verdict, klass, reason)
        stray = sorted(p.name for p in self.expected_dir.glob("*.txt") if p.stem not in self.classes) \
            if self.expected_dir.exists() else []
        cm.sm.require(not stray or self.pin, f"pins for no classified case: {stray}")
        for c in every:
            c.path = self.source_path(c.source)
            cm.sm.require(c.path.is_file(), f"{c.name}: no source {c.path}")
            if c.stdin:
                c.stdin_path = self.source_path(c.stdin)
                cm.sm.require(c.stdin_path.is_file(), f"{c.name}: no stdin file {c.stdin_path}")
        # The case files on the image: sources, the files they include by "...", stdin files.
        cases_files = {}
        for c in every:
            if c.kind != "compile-run":
                continue
            wanted = [c.path] + [c.path.parent / inc for inc in
                                 re.findall(r'^#include "([^"/]+)"', c.path.read_text(), re.M)]
            if c.stdin:
                wanted.append(c.stdin_path)
            for p in wanted:
                cm.sm.require(cases_files.get(p.name, p) == p, f"two case files named {p.name}")
                cases_files[p.name] = p
        self.case_files = cases_files
        self.share = self.tcc_build / "share" / "absd-c"
        share = [(f"/share/absd-c/{p.relative_to(self.share).as_posix()}", p.read_bytes())
                 for p in sorted(self.share.rglob("*")) if p.is_file()]
        self.share_files = share
        self.negative = {c.name: c for c in every if c.kind == "spawn-refused"}
        target.products = []
        self.tcc_bytes = (self.tcc_build / "absd" / "tcc").read_bytes()
        self.tcc_sha = sha(self.tcc_bytes)
        self.hostcfg_sha = sha((self.tcc_build / "hostcfg" / "tcc").read_bytes())
        target.case_files = []
        have = {path for path, _ in target.files("")}
        target.case_files = ([(f"/bin/{n}", (target.root / "commands" / n).read_bytes()) for n in EXTRA
                             if f"/bin/{n}" not in have]
                             + [("/bin/tcc", self.tcc_bytes)]
                             + share
                             + [(f"{CASES_DIR}/{n}", p.read_bytes()) for n, p in sorted(cases_files.items())]
                             + [(f"{NEGATIVE}/{c.path.name}", c.path.read_bytes()) for c in self.negative.values()])
        ck.sm.Matrix.__init__(self, target, work)

    def source_path(self, source):
        if source.startswith("c/"):
            return self.kit / source
        if source.startswith("tcc-build/"):
            return self.tcc_build.parent / source
        return self.repo / source

    # -- inherited resource rules, this stage's files -----------------------------

    def allowed(self, case):
        if case.kind != "compile-run":
            return set()
        return {f"{OUT_DIR}/{case.name}.elf"} | {f"{case.cwd}/{f}" for f in case.keeps + case.drops}

    def repeatable(self, name):
        # Each compile-run case can be run again by itself (it rewrites its
        # own output with the same bytes; a `cwd` case with its whole chain,
        # so the directory returns to its state); the repeat round re-runs
        # every case that took the high-water allowance itself (ruling 2).
        return any(c.name == name and c.kind == "compile-run" for c in self.cases)

    def chain(self, case):
        """The cases sharing `case`'s kept directory, in table order (stdio write, then verify)."""
        return [c for c in self.cases if case.cwd and c.cwd == case.cwd] or [case]

    # -- host side -----------------------------------------------------------------

    def host_side(self):
        """expected/<case>.elf by hostcfg tcc, the Linux reference build by
        host tcc, both from a copy of the image's case files; the gate's
        verdict on each expected ELF and on the negative control."""
        src = self.work / "tcc-cases"
        for d in (src, self.work / "expected", self.work / "linux", self.work / "linux-tcc", self.work / "linux-cwd"):
            if d.exists():
                shutil.rmtree(d)
            d.mkdir(parents=True)
        for n, p in self.case_files.items():
            (src / n).write_bytes(p.read_bytes())
        tb = self.tcc_build
        for c in self.cases:
            if c.kind == "spawn-refused":
                ok, reason, _ = gate.check(c.path.read_bytes())
                self.check(f"{c.name}: the host gate refuses the negative control", not ok, reason)
                c.gate = reason
                print(f"TCC HOST {c.name} gate=REFUSES :: {reason} bytes={c.path.stat().st_size} "
                      f"sha256={sha(c.path.read_bytes())}", flush=True)
                continue
            elf = self.work / "expected" / f"{c.name}.elf"
            r = subprocess.run([str(tb / "hostcfg" / "tcc"), "-B", str(tb / "share" / "absd-c" / "tcc"), c.path.name,
                                "-o", str(elf)], cwd=src, capture_output=True, timeout=HOST_COMPILE_TIMEOUT)
            self.check(f"{c.name}: hostcfg tcc compiles", r.returncode == 0, f"{r.returncode} {r.stdout!r} {r.stderr!r}")
            c.host_compile = (r.stdout, r.stderr)
            data = elf.read_bytes()
            ok, reason, loads = gate.check(data)
            self.check(f"{c.name}: the host gate accepts the expected ELF", ok, reason)
            lin = self.work / "linux" / c.name
            # glibc keeps libm apart (the kit's libc carries the math functions, its
            # libm.a is empty): the reference names it; nothing changes on the guest side.
            host_tcc = lin if c.reference == "tcc" else self.work / "linux-tcc" / c.name
            r = subprocess.run([str(tb / "host" / "tcc"), "-B", str(tb / "host"), c.path.name, "-o", str(host_tcc), "-lm"],
                               cwd=src, capture_output=True, timeout=HOST_COMPILE_TIMEOUT)
            self.check(f"{c.name}: host tcc builds the Linux reference", r.returncode == 0,
                       f"{r.returncode} {r.stdout!r} {r.stderr!r}")
            if c.reference == "gcc":
                # Ruling (fix round 0): for `# reference gcc` the Linux reference is gcc's build.
                r = subprocess.run(["gcc", "-O0", "-o", str(lin), c.path.name, "-lm"], cwd=src, capture_output=True,
                                   timeout=HOST_COMPILE_TIMEOUT)
                self.check(f"{c.name}: gcc builds the Linux reference", r.returncode == 0,
                           f"{r.returncode} {r.stdout!r} {r.stderr!r}")
            print(f"TCC HOST {c.name} expected bytes={len(data)} sha256={sha(data)} gate=ACCEPTS loads={loads} "
                  f"warnings={len(c.host_compile[1])}", flush=True)

    def linux_dir(self, cwd):
        return self.work / "linux-cwd" / cwd.strip("/").replace("/", "_")

    def linux_ref(self, case, argv0, binary=None):
        """The Linux reference, run twice (equal): argv0, the case's args and
        stdin bytes, the session's environment, umask 022, SIGPIPE ignored.
        A `cwd` case runs in that directory's Linux twin (kept across the
        chain's cases), its second, comparison-only run in a copy of the
        directory as it was before the first; any other case in a fresh
        empty directory. A `pipe` case's stdout goes through the host's
        program of the same name and arguments; the status is the last
        stage's, the stderr both stages' (as the shell's)."""
        binary = binary or self.work / "linux" / case.name
        stdin = case.stdin_path.read_bytes() if case.stdin else b""
        env = dict(self.session_env)

        def once(cwd):
            if not case.pipe:
                r = subprocess.run([argv0, *case.args], executable=str(binary), cwd=cwd, env=env, input=stdin,
                                   capture_output=True, preexec_fn=ck.ignore_sigpipe, timeout=RUN_TIMEOUT)
                return r.returncode, r.stdout, r.stderr
            words = [w.strip('"') for w in case.pipe.split()]
            tail = [shutil.which(words[0].rsplit("/", 1)[-1]), *words[1:]]
            p1 = subprocess.Popen([argv0, *case.args], executable=str(binary), cwd=cwd, env=env, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=ck.ignore_sigpipe)
            p2 = subprocess.Popen(tail, cwd=cwd, env=env, stdin=p1.stdout, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, preexec_fn=ck.ignore_sigpipe)
            p1.stdout.close()
            p1.stdin.write(stdin); p1.stdin.close()
            out, err2 = p2.communicate(timeout=RUN_TIMEOUT)
            err1 = p1.stderr.read(); p1.stderr.close(); p1.wait(timeout=RUN_TIMEOUT)
            return p2.returncode, out, err1 + err2

        if case.cwd:
            base = self.linux_dir(case.cwd)
            base.mkdir(parents=True, exist_ok=True)
            fresh = self.work / "linux-second" / base.name
            if fresh.exists():
                shutil.rmtree(fresh)
            shutil.copytree(base, fresh)
            first, second = once(base), once(fresh)
        else:
            runs = []
            for _ in range(2):
                cwd = self.work / "linux-run" / case.name
                if cwd.exists():
                    shutil.rmtree(cwd)
                cwd.mkdir(parents=True)
                runs.append(once(cwd))
            first, second = runs
        self.check(f"{case.name}: two Linux reference runs are equal", first == second, f"{first!r}\n{second!r}")
        return first

    # -- a case ----------------------------------------------------------------------

    def need(self, step, what, ok):
        self.check(f"{what}: {step.command!r}", ok,
                   f"status={step.status} out={step.out[-300:]!r} err={step.err[-300:]!r} children={step.children}")

    def exits(self, step):
        """The kernel's USER EXIT status of each child of the step."""
        text = self.t.serial()
        out = []
        for pid in step.children:
            deadline = time.monotonic() + USER_LINE_TIMEOUT
            m = None
            while time.monotonic() < deadline:
                m = re.search(rf"USER (EXIT|KILLED|FAULT) pid={pid}\b([^\n]*)", text)
                if m:
                    break
                time.sleep(0.2); text = self.t.serial()
            out.append((pid, m.group(1) + m.group(2) if m else "none"))
        return out

    def compile_run(self, case, quiet=False):
        """The held session; returns a dict of what it saw."""
        h = Held(self)
        seen = {"shell": h.shell}
        try:
            s = h.step('"/bin/ls" /tmp')
            m = re.fullmatch(rb"session-(\d+)/?\n", s.out)
            self.need(s, "the session lists exactly its own scratch directory", s.status == 0 and s.err == b"" and m)
            n = int(m.group(1))
            seen["session"] = n
            s = h.step(f"cd /tmp/session-{n}")
            self.need(s, "cd to the session's scratch directory", (s.status, s.out, s.err, s.children) == (0, b"", b"", []))
            s = h.step(f'"/bin/tcc" {CASES_DIR}/{case.path.name} -o a.out', COMPILE_TIMEOUT)
            seen["compile"] = s
            seen["compile_exit"] = self.exits(s)
            if s.status != 0:
                h.close()
                return seen
            s = h.step('"/bin/sha256sum" a.out')
            m = re.fullmatch(rb"([0-9a-f]{64})  a\.out\n", s.out)
            self.need(s, "sha256sum of a.out in the session", s.status == 0 and s.err == b"" and m)
            seen["digest"] = m.group(1).decode()
            s = h.step(f'"/bin/cp" a.out {OUT_DIR}/{case.name}.elf')
            self.need(s, "cp a.out to the image", (s.status, s.out, s.err) == (0, b"", b"") and len(s.children) == 1)
            prog = "./a.out"
            if case.cwd:
                s = h.step(f"cd {case.cwd}")
                self.need(s, "cd to the case's kept directory", (s.status, s.out, s.err, s.children) == (0, b"", b"", []))
                prog = f"/tmp/session-{n}/a.out"
            seen["prog"] = prog
            words = [prog, *[ck.quote(a) for a in case.args]]
            if case.stdin:
                words += ["<", f"{CASES_DIR}/{case.stdin_path.name}"]
            if case.pipe:
                words += ["|", case.pipe]
            s = h.step(" ".join(words), RUN_TIMEOUT)
            seen["run"] = s
            seen["run_exit"] = self.exits(s)
            h.close()
        except BaseException:
            h.kill()
            raise
        return seen

    def run_negative(self, case):
        h = Held(self)
        name = case.path.name
        try:
            s = h.step(f"cd {NEGATIVE}")
            self.need(s, "cd", (s.status, s.out, s.err) == (0, b"", b""))
            listing = h.step(f'"/bin/ls" -l {name}')
            self.need(listing, "ls -l the negative control", listing.status == 0 and listing.err == b"")
            digest = h.step(f'"/bin/sha256sum" {name}')
            data = case.path.read_bytes()
            self.need(digest, "the file in the session holds the host file's bytes",
                      digest.status == 0 and digest.out == f"{sha(data)}  {name}\n".encode())
            s = h.step(f"./{name}")
            h.close()
        except BaseException:
            h.kill()
            raise
        ok, text = refusal_evidence(s.status, s.out, s.err, listing.out, len(data), s.serial, h.shell, case.gate,
                                    h.children(), listing.children + digest.children)
        (self.work / f"{case.name}.absd.err.raw").write_bytes(s.err)
        if not ok:
            print(f"TCC FINDING {case.name} :: the refusal evidence is incomplete: {text}", flush=True)
            return "failed", s.seconds
        print(f"TCC SPAWN REFUSED {case.name} :: {text}", flush=True)
        print(f"TCC TRUTH {case.name} :: shell status and stderr (sh/src/lib.rs:772 `cannot run: {{e}}`, 126); "
              f"ls -l and sha256sum in the session (present, {len(data)} bytes, sha256 {sha(data)}); kernel serial "
              f"during the command: no SPAWN OK parent={h.shell}, and over the whole session only the ls and "
              f"sha256sum children; scripts/check-abi-elf.py on the same bytes",
              flush=True)
        print(f"TCC CASE OK {case.name} :: refused as expected (the loader's refusal, reported by the shell)", flush=True)
        return "agree", s.seconds

    def judge_run(self, case, got, ref, elf_same=True):
        """The case's verdict from its output `got` and the Linux reference
        `ref` (status, stdout, stderr); `elf_same` False when the guest
        a.out differed from the host build, which fails the case with no
        CASE line (final review, Task 5 #1)."""
        pin = self.expected_dir / f"{case.name}.txt"
        if case.name in self.pin:
            self.expected_dir.mkdir(exist_ok=True)
            pin.write_bytes(ck.pin_bytes(*got))
            print(f"TCC PIN WRITTEN {pin}: review it before committing", flush=True)
        if not elf_same:
            print(f"TCC FINDING {case.name} :: the a.out differs from the host build (TCC DIVERGES above); output "
                  f"equal_to_linux={got == ref}; not judged further", flush=True)
            return "failed"
        if case.name in self.classes:
            verdict, klass, reason = self.classes[case.name]
            pinned = pin.exists() and pin.read_bytes() == ck.pin_bytes(*got)
            if not (pinned and got != ref):
                print(f"TCC FINDING {case.name} :: classified {verdict} but pinned={pinned} differs_from_linux="
                      f"{got != ref}: ABSD {got!r} Linux {ref!r}", flush=True)
                return "failed"
            kit_note = ""
            if klass == "kit divergence":
                kit = kit_pin_path(self.kit, case.name)
                ok, why = kit_pin_agrees(pin.read_bytes(), kit.read_bytes()) if kit.is_file() else (False, "no kit pin")
                if not ok:
                    print(f"TCC FINDING {case.name} :: classified kit divergence but the pin is not the kit's Stage 1 "
                          f"pin {kit.relative_to(self.kit)}: {why}", flush=True)
                    return "failed"
                kit_note = f" :: pin equals the kit's Stage 1 pin {kit.relative_to(self.kit)} (absd-sh status line stripped)"
            print(f"TCC CASE {verdict} {case.name} :: {klass} :: {reason}{kit_note}", flush=True)
            return "diverge" if verdict == "DIVERGES" else "defect"
        if case.name == TIMING_CASE:
            m = TIMING_ERR.fullmatch(got[2])
            n = int(m.group(1)) if m else None
            if not (got[:2] == ref[:2] and m and TIMING_RANGE[0] <= n < TIMING_RANGE[1] and got[2] != ref[2]):
                print(f"TCC FINDING {case.name} :: stdout/status equal={got[:2] == ref[:2]} stderr {got[2]!r} "
                      f"(Linux {ref[2]!r})", flush=True)
                return "failed"
            print(f"TCC CASE OK {case.name} :: timing-dependent stderr N={n} in [{TIMING_RANGE[0]},{TIMING_RANGE[1]}) "
                  f"(Stage 1 rule); stdout and status equal Linux exactly (Linux stderr {ref[2].decode().strip()!r})",
                  flush=True)
            return "agree"
        if pin.exists() and case.name not in self.pin:
            print(f"TCC FINDING {case.name} :: a pin exists for a case that is not classified", flush=True)
            return "failed"
        if got != ref:
            print(f"TCC FINDING {case.name} :: differs from the Linux reference (unclassified): ABSD {got!r}\n"
                  f"Linux {ref!r}", flush=True)
            return "failed"
        if case.reference == "gcc":
            print(f"TCC CASE OK {case.name} :: reference=gcc", flush=True)
        else:
            print(f"TCC CASE OK {case.name} :: equal to the Linux reference (stdout, stderr, status; no normalizers), "
                  f"a.out identical to the host build", flush=True)
        return "agree"

    def run_compile_case(self, case):
        seen = self.compile_run(case)
        c = seen["compile"]
        (self.work / f"{case.name}.compile.out").write_bytes(c.out)
        (self.work / f"{case.name}.compile.err").write_bytes(c.err)
        self.compile_seconds += c.seconds
        if c.status != 0:
            print(f"TCC FINDING {case.name} :: the guest's tcc failed: status {c.status} children={c.children} "
                  f"kernel={seen['compile_exit']} seconds={c.seconds:.1f} stdout={c.out[-500:]!r} "
                  f"stderr={c.err[-1500:]!r}", flush=True)
            return "failed", c.seconds
        self.check(f"{case.name}: tcc ran as the shell's only child, its kernel exit status 0",
                   len(c.children) == 1 and seen["compile_exit"][0][1] == "EXIT status=0", str(seen["compile_exit"]))
        if c.out or c.err:
            print(f"TCC COMPILE NOTE {case.name} :: guest stdout={c.out!r} stderr={c.err!r} host stderr="
                  f"{case.host_compile[1]!r}", flush=True)
        got_elf = self.t.tree().get(f"{OUT_DIR}/{case.name}.elf")
        want = (self.work / "expected" / f"{case.name}.elf").read_bytes()
        self.check(f"{case.name}: the copy on the image is what tcc wrote (host reader digest == sha256sum in the "
                   f"session)", got_elf is not None and sha(got_elf) == seen["digest"],
                   f"image={None if got_elf is None else sha(got_elf)} session={seen['digest']}")
        (self.work / "absd-out").mkdir(exist_ok=True)
        (self.work / "absd-out" / f"{case.name}.elf").write_bytes(got_elf)
        diff = compare_elf(got_elf, want)
        print(f"TCC COPY OK {case.name} :: /tmp/session-{seen['session']}/a.out -> {OUT_DIR}/{case.name}.elf by "
              f"/bin/cp; sha256sum in the session == the host reader's digest of the copy", flush=True)
        print(f"TCC COMPILE OK {case.name} bytes={len(got_elf)} sha256={sha(got_elf)} "
              f"identical_to_host={'yes' if diff is None else 'no'} seconds={c.seconds:.1f}", flush=True)
        verdict = None
        if diff is not None:
            print(f"TCC DIVERGES {case.name} :: output differs at offset {diff[0]} (section {diff[1]}; "
                  f"guest {len(got_elf)} bytes, host {len(want)} bytes) {byte_context(got_elf, want, diff[0])}",
                  flush=True)
            verdict = "failed"
        r = seen["run"]
        if not r.children:
            ok, reason, _ = gate.check(got_elf)
            print(f"TCC FINDING {case.name} :: a.out was not spawned: status {r.status} stderr {r.err!r}; host gate "
                  f"on the same bytes: {'ACCEPTS' if ok else 'REFUSES ' + reason}"
                  f"{' (ABSD ABI DEFECT candidate: the loader refuses what the kernel-exact gate accepts)' if ok else ''}",
                  flush=True)
            return "failed", c.seconds
        try:
            got, kernel, line = self.result(case, seen)
        except Refused as e:
            print(f"TCC FINDING {case.name} :: {e}", flush=True)
            return "failed", c.seconds
        kept = (f" spawned_from={case.cwd} (kept directory; /tmp/session-{seen['session']}/a.out by absolute path)"
                if case.cwd else "")
        print(f"TCC SPAWN OK {case.name} status={r.status} seconds={r.seconds:.1f}{kept}", flush=True)
        if line:
            (self.work / f"{case.name}.absd.err.raw").write_bytes(r.err)
            print(f"TCC SHELL STATUS LINE {case.name} removed: {line}", flush=True)
        argv0 = f"/tmp/session-{seen['session']}/a.out"
        ref = self.linux_ref(case, argv0)
        if case.reference == "gcc":
            self.reference_limitation(case, argv0, ref)
        for kind, data in (("absd", got), ("linux", ref)):
            for part, value in (("status", f"{data[0]}\n".encode()), ("out", data[1]), ("err", data[2])):
                (self.work / f"{case.name}.{kind}.{part}").write_bytes(value)
        print(f"TCC TRUTH {case.name} :: session=/tmp/session-{seen['session']} (`ls /tmp` in the session); compile="
              f"kernel SPAWN OK pid={c.children[0]} parent={seen['shell']} {seen['compile_exit'][0][1]}; copy=sha256sum "
              f"in the session == host reader; run=kernel {kernel}; Linux argv0={argv0} reference={case.reference}",
              flush=True)
        self.first[case.name] = (got, got_elf)
        self.check_files(case)
        v = self.judge_run(case, got, ref, elf_same=diff is None)
        return (verdict or v), c.seconds + r.seconds

    def result(self, case, seen):
        """(status, stdout, stderr) of the run step with absd-sh's own status
        line removed, the kernel's account of the children, and the removed
        line. The kernel must agree with the shell: a.out (and a pipe's last
        stage) a SPAWN OK child of the session's shell; an exit's USER EXIT
        status equal to the shell's; a fault (USER FAULT) reported by the
        shell as `ended abnormally`, 128."""
        r, exits = seen["run"], seen["run_exit"]
        want = 2 if case.pipe else 1
        if len(r.children) != want:
            raise Refused(f"{len(r.children)} children of the shell for the run, want {want}: {exits}")
        first = exits[0][1]
        abnormal = first.startswith("FAULT")
        last = exits[-1][1]
        if case.pipe:
            ok = first.startswith("EXIT ") and last == f"EXIT status={r.status}"
            name = case.pipe.split()[0].strip('"')
        elif abnormal:
            ok = r.status == 128
            name = seen["prog"]
        else:
            ok = first == f"EXIT status={r.status}"
            name = seen["prog"]
        if not ok:
            raise Refused(f"the kernel's account {exits} does not match the shell's status {r.status}")
        err, removed = strip_status(r.err, name, r.status, abnormal and not case.pipe)
        line = r.err[len(err):].decode().strip() if removed else ""
        kernel = "; ".join(f"SPAWN OK pid={pid} parent={seen['shell']} {e}" for pid, e in exits)
        return (r.status, r.out, err), kernel, line

    def reference_limitation(self, case, argv0, ref):
        """`# reference gcc`: the host tcc build still runs; when it differs
        from gcc's and host tcc defines no __GNUC__, the reference's
        limitation is printed (a finding about the reference, not ABSD)."""
        tcc_ref = self.linux_ref(case, argv0, self.work / "linux-tcc" / case.name)
        tb = self.tcc_build
        macros = subprocess.run([str(tb / "host" / "tcc"), "-B", str(tb / "host"), "-dM", "-E", "-"], input=b"",
                                capture_output=True, timeout=HOST_QUERY_TIMEOUT).stdout
        cdefs = pathlib.Path("/usr/include/x86_64-linux-gnu/sys/cdefs.h").read_text().splitlines()
        erased = cdefs[289:291] == ["#if !(defined __GNUC__ || defined __clang__)",
                                    "# define __attribute__(xyz)\t/* Ignore */"]
        if tcc_ref == ref:
            print(f"TCC REFERENCE {case.name} :: host tcc's build equals gcc's", flush=True)
            return
        self.check(f"{case.name}: the host tcc reference differs from gcc's for the stated cause (no __GNUC__; "
                   f"glibc cdefs.h:290-291)", b"__GNUC__" not in macros and erased, f"cdefs {cdefs[289:291]}")
        (self.work / f"{case.name}.linux-tcc.out").write_bytes(tcc_ref[1])
        self.limited_refs.append(case.name)
        print(f"TCC REFERENCE {case.name} :: host tcc: status {tcc_ref[0]} stdout {len(tcc_ref[1])} bytes; gcc: status "
              f"{ref[0]} stdout {len(ref[1])} bytes (judged against gcc)", flush=True)

    def check_files(self, case):
        """A `cwd` case's kept files equal the Linux twin's; its removed files are gone on both sides."""
        if not case.cwd:
            return
        tree = self.t.tree()
        base = self.linux_dir(case.cwd)
        for f in case.keeps:
            got, want = tree.get(f"{case.cwd}/{f}"), (base / f).read_bytes() if (base / f).exists() else None
            self.check(f"{case.name}: {case.cwd}/{f} on the image equals the Linux twin's", got is not None and got == want,
                       f"absd={None if got is None else (len(got), sha(got))} linux={None if want is None else len(want)}")
            print(f"TCC FILE OK {case.name} {case.cwd}/{f} bytes={len(got)} sha256={sha(got)} (host reader == Linux twin)",
                  flush=True)
        for f in case.drops:
            self.check(f"{case.name}: {case.cwd}/{f} removed on the image and in the Linux twin",
                       f"{case.cwd}/{f}" not in tree and not (base / f).exists())
            print(f"TCC FILE GONE {case.name} {case.cwd}/{f}", flush=True)

    # -- the run -------------------------------------------------------------------

    def repeat(self):
        """Ruling 2: every case that took the high-water allowance is itself
        repeated (a `cwd` case with its chain), plus REPEAT_CASE, twice;
        each round's census equals the census before the rounds, each case's
        a.out bytes and output equal its first run's."""
        names = []
        for name in [REPEAT_CASE, *self.highwater]:
            case = next(c for c in self.cases if c.name == name)
            names += [c.name for c in self.chain(case) if c.name not in names]
        start = self.stable("repeat", "before")
        for round_no in range(1, REPEAT_ROUNDS + 1):
            for name in names:
                case = next(c for c in self.cases if c.name == name)
                seen = self.compile_run(case)
                c = seen["compile"]
                self.check(f"repeat {round_no} {name}: compile status 0", c.status == 0, f"{c.status} {c.err!r}")
                got_elf = self.t.tree().get(f"{OUT_DIR}/{name}.elf")
                first, first_elf = self.first[name]
                got = self.result(case, seen)[0]
                same = got == first
                if name == TIMING_CASE:
                    # Everything but the declared timing-dependent figure (ruling, fix round 0b).
                    m = TIMING_ERR.fullmatch(got[2])
                    same = (got[:2] == first[:2] and m is not None
                            and TIMING_RANGE[0] <= int(m.group(1)) < TIMING_RANGE[1])
                    print(f"TCC REPEAT {round_no} {name} timing-dependent stderr N={m.group(1).decode() if m else None}",
                          flush=True)
                self.check(f"repeat {round_no} {name}: the same a.out bytes and output as the first run",
                           got_elf == first_elf and seen["digest"] == sha(first_elf) and same,
                           f"{got!r} {first!r}")
                print(f"TCC REPEAT {round_no} {name} compile_seconds={c.seconds:.1f} "
                      f"run_seconds={seen['run'].seconds:.1f}", flush=True)
            now = self.stable("repeat", f"after {round_no}")
            self.check(f"repeat round {round_no}: images, frames, kernel objects, the file server's heap peak and "
                       f"object names equal the census before the rounds",
                       (now["images"], now["memory"], now["kernel"], now["fsd"])
                       == (start["images"], start["memory"], start["kernel"], start["fsd"])
                       and {o[0] for o in now["objects"]} == {o[0] for o in start["objects"]},
                       f"before={start['memory']} {start['kernel']} fsd {start['fsd']} after={now['memory']} "
                       f"{now['kernel']} fsd {now['fsd']}")
        print(f"TCC RESOURCES REPEAT OK rounds={REPEAT_ROUNDS} repeated={' '.join(names)} :: {start['memory']} | "
              f"{start['kernel']} | fsd_heap_peak={start['fsd']} (high-water cases: {' '.join(self.highwater) or 'none'})",
              flush=True)

    def run(self):
        t = self.t
        started = time.monotonic()
        os.umask(0o022)
        self.host_side()
        cm.ssh_absd.IMAGE_BYTES = cm.IMAGE_BYTES
        cm.ssh_absd.DEVICE_SECTORS = cm.IMAGE_BYTES // 512
        authorized = (self.op.with_suffix(".pub")).read_text()
        imported = t.files(authorized)
        t.setup(self.work, authorized)
        print(f"TCC IMPORT files={len(imported)} bytes={sum(len(d) for _, d in imported)} boots={t.boots} "
              f"seconds={time.monotonic() - started:.1f}", flush=True)
        tree = t.tree()
        listed = [line.split("  ", 1) for line in (self.tcc_build / "share.sha256").read_text().splitlines()]
        bad = [p for h, p in listed if sha(tree.get(t.physical(f"/share/{p}"), b"")) != h]
        self.check("the share tree on the image matches tcc-build/share.sha256 (host reader)",
                   not bad and len(listed) == len(self.share_files), f"{len(listed)} listed, {len(self.share_files)} "
                   f"imported, mismatched {bad[:5]}")
        print(f"TCC IMPORT SHARE OK files={len(listed)} bytes={sum(len(d) for _, d in self.share_files)} :: every "
              f"share.sha256 line equals the image's bytes at /share/<path> (host reader)", flush=True)
        # Final review M3: the guest compiler and the host compiler of expected/
        # named by digest; run-tcc.sh requires the first to equal round2.sha256.
        on_image = tree.get(t.physical("/bin/tcc"))
        self.check("/bin/tcc on the image is tcc-build/absd/tcc (host reader)",
                   on_image is not None and sha(on_image) == self.tcc_sha,
                   f"image={None if on_image is None else sha(on_image)} imported={self.tcc_sha}")
        print(f"TCC IMPORT TCC sha256={self.tcc_sha} hostcfg_sha256={self.hostcfg_sha} :: /bin/tcc as imported and "
              f"read back from the image (host reader); hostcfg_sha256 is the tcc that wrote expected/", flush=True)
        boot = time.monotonic()
        first = t.start(fresh=True)
        print(f"TCC BOOT SECONDS sshd={time.monotonic() - boot:.1f}", flush=True)
        self.client = ck.sm.Client(self.work, t.port)
        self.client.trust(first["public"])
        self.first, self.steps, self.limited, self.highwater = {}, 0, set(), []
        self.compile_seconds = 0.0
        self.limited_refs = []
        rc, out, err, _, _ = self.shell_ssh('"/bin/df"')
        self.check("df in a session", rc == 0 and err == b"", f"{rc} {out!r} {err!r}")
        m = re.search(r"^absd:[0-9a-f]+ +(\d+) +(\d+) +(\d+) ", out.decode(), re.M)
        self.check("df reports the filesystem's space", m is not None, out.decode())
        print(f"TCC IMAGE capacity={int(m.group(1)) * 1024} used={int(m.group(2)) * 1024} "
              f"available={int(m.group(3)) * 1024} image={cm.IMAGE_BYTES}", flush=True)
        h = Held(self)
        try:
            s = h.step('"/bin/printenv"')
            h.close()
        except BaseException:
            h.kill()
            raise
        self.need(s, "printenv in a held session", s.status == 0 and s.err == b"")
        self.session_env = [tuple(line.split("=", 1)) for line in s.out.decode().splitlines() if "=" in line]
        print(f"TCC SESSION ENV count={len(self.session_env)} {' '.join(k for k, _ in self.session_env)} :: the Linux "
              f"reference gets exactly this environment", flush=True)
        for d in [OUT_DIR, *dict.fromkeys(c.cwd for c in self.cases if c.cwd)]:
            if self.is_dir(d):
                continue
            rc, out, err, _, _ = self.shell_ssh(f'"/bin/mkdir" {ck.quote(d)}')
            self.check(f"mkdir {d}", rc == 0 and out == b"" and err == b"" and self.is_dir(d), f"rc={rc} {out!r} {err!r}")
            print(f"TCC DIR MADE {d}", flush=True)
        warm = None
        if self.pin:
            print("TCC WARM NOT_ESTABLISHED reason=pin-authoring", flush=True)
        else:
            try:
                warm = tcc_warm.Rehearsal(self, OUT_DIR)
            except tcc_warm.wb.BaselineError as error:
                # Unsupported reset scope does not alter the original case
                # oracles. A failure after warming starts is never swallowed.
                print(f"TCC WARM NOT_ESTABLISHED reason={error}", flush=True)
        if warm is not None:
            warm.establish()
            # Real connection counters remain cumulative. Preserve rehearsal
            # evidence in logs; measured case reports start fresh.
            self.first, self.highwater, self.limited_refs = {}, [], []
            self.compile_seconds = 0.0
            warm.reset()
            print("TCC WARM SCOPE tcc-main-sequence=established R23=PARTIAL", flush=True)
        counts = {"agree": 0, "diverge": 0, "defect": 0, "failed": 0}
        failed, timings = [], []
        for case in self.cases:
            before = self.stable(case.name, "before")
            start = time.monotonic()
            if case.kind == "spawn-refused":
                verdict, _ = self.run_negative(case)
            else:
                verdict, _ = self.run_compile_case(case)
            took = time.monotonic() - start
            after = self.stable(case.name, "after")
            memory, kernel = self.compare_census(case, before, after)
            after = self.judged
            counts[verdict] += 1
            if verdict == "failed":
                failed.append(case.name)
            timings.append((case.name, took))
            print(f"TCC RESOURCES {case.name} :: {memory} | {kernel} | images={after['images']} "
                  f"objects={len(after['objects'])} seconds={took:.1f}", flush=True)
        if warm is not None:
            warm.measured()
        if self.limited_refs:
            print(f"TCC REFERENCE LIMITATION {','.join(self.limited_refs)} :: host tcc with glibc headers drops "
                  f"constructor/destructor attributes (tcc defines no __GNUC__; glibc sys/cdefs.h:290-291)", flush=True)
        if any(c.name == REPEAT_CASE for c in self.cases) and REPEAT_CASE in self.first:
            self.repeat()
        self.alive("the tcc cases")
        t.stop()
        print("TCC TIMINGS " + " ".join(f"{n}={s:.1f}" for n, s in timings), flush=True)
        self.rest_recorded()          # census ruling (b): any lowered rest count (not a failure)
        if failed:
            print(f"ABSD TCC STAGE3 FAILED cases={len(self.cases)} agree={counts['agree']} diverge={counts['diverge']} "
                  f"defects={counts['defect']} unclassified={','.join(failed)} compile_seconds={self.compile_seconds:.0f}",
                  flush=True)
            return False
        # Final review M4: OK only for a run of every case that wrote no pin;
        # an --only run is partial, and a --pin run certifies its own pins.
        partial = [f"only={','.join(c.name for c in self.cases)}"] if self.only else []
        partial += [f"pin={','.join(sorted(self.pin))}"] if self.pin else []
        print(f"ABSD TCC STAGE3 {'PARTIAL' if partial else 'OK'} cases={len(self.cases)} agree={counts['agree']} "
              f"diverge={counts['diverge']} defects={counts['defect']} compile_seconds={self.compile_seconds:.0f}"
              f"{' :: ' + ' '.join(partial) + ' (not a full run)' if partial else ''}", flush=True)
        print(f"TCC MATRIX OK seconds={time.monotonic() - started:.0f}", flush=True)
        return True


def main():
    ap = argparse.ArgumentParser()
    for name in ("work", "tcc-build", "kit", "cases"):
        ap.add_argument(f"--{name}", required=True)
    ap.add_argument("--only", action="append", help="run only this case (repeatable; not a final run)")
    ap.add_argument("--pin", action="append", help="write tcc/absd-expected/<case>.txt from this run (review it)")
    argv = sys.argv[1:]
    print("TCC ARGS " + " ".join(sys.argv), flush=True)
    rest = []
    if "--" in argv:
        i = argv.index("--")
        argv, rest = argv[:i], argv[i + 1:]
    args = ap.parse_args(argv)
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    base = ssh_absd.target(rest)
    target = TccTarget.__new__(TccTarget)
    target.__dict__.update(base.__dict__)
    matrix = TccMatrix(target, work, args)
    try:
        ok = matrix.run()
    except (cm.sm.Failed, ck.sm.Failed, ssh_absd.Failed, Refused) as e:
        print(f"ABSD TCC STAGE3 FAILED: {e}", file=sys.stderr, flush=True)
        target.stop()
        sys.exit(1)
    except BaseException:
        target.stop()
        raise
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
