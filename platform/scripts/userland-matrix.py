#!/usr/bin/env python3
"""The base userland on the shell route: guest run T5
(docs/base-userland-20261012/RECORD.md, "Owed: guest run (T5, via the
steward)"; userland/README.md, "Guest run (T5)").

One `net fsd` boot (scripts/ssh_absd.py) on the cports harness's 128 MiB
image (cports-matrix.py IMAGE_BYTES). The image carries ssh_absd's
deployment, /bin/{mkdir,cp,rm,cat,ls,df,sysinfo}, the nine sbase ports at
/bin/<name> from <platform>/ports/<name> (each refused unless its digest is
userland/PORTS.tsv's SHA256), and the fixtures of scripts/check-userland.py
(FIXTURES, imported from it, never copied) at /home/operator/userland/
fixtures/, written by the fixture importer and read back byte for byte by
the host's own reader (bin.dat included). Its empty `dir/` is made by one
`mkdir` session after the boot.

A case (a row of userland/cases.tsv: ID UTILITY STDIN ARGS) runs in a fresh
directory: one session `cp -r fixtures run` in /home/operator/userland, then
the host reader must find exactly FIXTURES' bytes below `run/` and `run/dir`
a directory; then one SSH exec session through absd-sh,
`cd /home/operator/userland/run; "UTILITY" "ARG"...` (bare name: absd-sh
runs it from /bin; ARGS split with shlex, every word double-quoted as the
cports harness quotes, so `$`, `;`, `{}` and `\\` reach the utility as
cases.tsv gives them), the STDIN fixture's bytes on the session's stdin
(empty for `-`). The utility must be the shell's only child; for a non-zero
status absd-sh's own last stderr line `absd-sh: UTILITY: exit status N` is
required and removed (the cports rule). The files below `run/` are then
read with the host reader and the result is formatted by check-userland's
format_result, the function the host pins were made with: status, stdout,
stderr and the "--- files" section. Finally `rm -r run`.

MTIMES: ABSD has no modification times (st_mtime is 0, C-INTERFACE.md 11),
so none is set in the guest. The cases that need MTIMES (test-newer,
find-newer) and find-mtime are rows of userland/divergences.tsv: the ABSD
build refuses -nt/-ot and the time primaries before any file is compared,
so the times cannot change their outcome. If a row leaves divergences.tsv
(R3 lands), this runner must set the times first; it refuses to start when
a case naming older.txt with -nt/-ot/-newer is not a divergence.

Judging (no normalizer; byte-exact):
  agree    the case is not in divergences.tsv and its result equals
           userland/expected/<ID> (the Linux REFERENCE build's pin);
  diverge  the case is in divergences.tsv: its result must be exactly
           `status ABSD_STATUS`, empty stdout, stderr ABSD_STDERR plus a
           newline, and no "--- files" section (nothing in its directory
           changed); the prediction must differ from the host pin;
  DEFECT   anything else, including a repeat (the second run of the case,
           in a new fresh directory) that differs from the first. The
           result is written to <pins>/<ID> (and <pins>/<ID>.repeat), and
           <pins>/DEFECTS names it with what differed; the run goes on, and
           the matrix exits 1. A defect is never turned into a divergence
           here: divergences.tsv is the lane's. A defect of an ed case whose
           result shows ed's scratch file, or of a find -exec/-ok case
           showing the parse-time refusal, is marked "candidate disposition
           D-04" (the per-port dispositions of the base-userland record) for
           the steward to re-class with that record.
A pin file in <pins> naming no case fails the load.

Resources (Stage 2, SPEC A5; CportsMatrix's census and rules): a stable
census (live images, sysinfo's memory and kernel lines, the image's objects,
the file server's heap peak) before the case's fresh directory is made and
after it was removed; CportsMatrix.compare_census judges it (settle, the
per-boot frames-only STEP allowance, and the high-water reading for a
lifecycle that changed files: the case's own directory is its allowed
set, so every first lifecycle may take a high-water reading and nothing
bounds their total across cases). Every case runs twice (repeat): the
second lifecycle's census is judged against the first's after-reading with
no allowed path, so no high-water reading; only the boot's frames-only STEP
allowance (cumulative STEP_BOUND = 5 frames per boot) still applies. Any
failed check (a refused census, a hang past a session's timeout, a session
that is not as expected) aborts the run with USERLAND MATRIX FAILED and no
summary line; only judging differences are counted as DEFECTs.

^C: one PTY shell (AbsdTarget.open_shell; stock ssh on a host terminal) in
a fresh directory runs each utility that reads its input in a form that
never ends (sed -n p, grep x, sort, od, cmp - words.txt, ed), types ^C
once it has started (the kernel's spawn line), and requires the prompt, the
program reaped and `status` 130; the shell then exits 0. ed's scratch file
left by ^C (userland/README.md predicts one) is counted, printed and then
removed with the directory; the census is equal around the whole block.
printf, test and find read no input: NOT_RUN. Exhaustion: NOT_RUN (the
cports harness offers no exhaustion scenario; sort's heap bound is T5's
after R16, userland/README.md).

Demo rehearsal (RECORD.md, T5 list): in /home/operator, ed -p '* ' writes
hello.c from a script (its byte count printed, the file's bytes on the image,
no ed.* left), od -t x1 (its dump read back to the bytes), cmp, grep -n,
find . -name 'ed.*' (empty), tcc only if /bin/tcc is on the image (else
USERLAND DEMO TCC NOT_RUN reason=no /bin/tcc), rm, then man sbase (every
line of userland/sbase.LICENSE, as cmds-matrix.py's licence_lines renders
it) and ls /bin naming the nine (USERLAND DEMO SBASE PRESENT; the command
matrix's own COMMAND SBASE PRESENT is that matrix's guest route, not this
one). The census is equal before and after.

Not established here, and listed in notrun= so the summary cannot be read
as all of T5: RECORD.md's T5 bullets 1-2 (/bin holds exactly NATIVE + 17
ports + absd-sh; the command matrix's COMMAND SBASE PRESENT) and the extra
cases of the T2/T3 reports. They are owed to scripts/cmds-matrix.py in the
same chain (NOT_RUN bin-exact, command-sbase-present, t2-t3-report-cases).

Defect pins go to --pins, default <work>/pins (the wrapper's
ABSD_USERLAND_PINS overrides), never into the tree by default.

Markers: USERLAND CASE OK <ID>; USERLAND DIVERGES <ID> :: <reason>;
USERLAND DEFECT <ID> :: <what>; USERLAND PIN WRITTEN <path>; USERLAND
RESOURCES <ID> :: ...; USERLAND INTERRUPT OK <util> ms=; USERLAND DEMO ...;
USERLAND NOT_RUN <item> reason=...; USERLAND PINS PROVENANCE ...; last line
ABSD USERLAND GUEST OK cases= agree= diverge= defects=0 demo=ok|not_run
notrun=<list|none> (with defects: ABSD USERLAND GUEST DEFECTS ..., exit 1)."""
import argparse, hashlib, pathlib, re, shlex, sys, time
here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import ssh_absd  # noqa: E402
import importlib.util  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), here / f"{name}.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


cm = load("cports-matrix")
ck, sm = cm.ck, cm.sm
cu = load("check-userland")
cmds = load("cmds-matrix")
FIXTURES, MTIMES = cu.FIXTURES, cu.MTIMES
FAILED = (cm.sm.Failed, ck.sm.Failed, cmds.sm.Failed, ssh_absd.Failed)

REPO = here.parent
HOME = "/home/operator"
BASE = f"{HOME}/userland"
TEMPLATE = f"{BASE}/fixtures"
RUN = f"{BASE}/run"
# Directories a case's working directory holds besides FIXTURES' files.
FIXTURE_DIRS = ["dir"]
EXTRA = ["mkdir", "cp", "rm", "cat", "ls", "df", "sysinfo"]
CASE_TIMEOUT = 300
# ^C: each utility that reads its input in a form that never ends on a terminal.
INTERRUPT = [("sed", ["-n", "p"]), ("grep", ["x"]), ("sort", []), ("od", []), ("cmp", ["-", "words.txt"]), ("ed", [])]
NO_INTERRUPT = {"printf": "reads no input", "test": "reads no input", "find": "reads no input"}
SCRATCH = re.compile(r"ed\.[A-Za-z0-9]{6}")
DEMO_LINE = b"int main(void) { return 0; }\n"
DEMO_ED = b"a\n" + DEMO_LINE + b".\nw hello.c\nq\n"
# T5 items this runner does not establish (RECORD.md T5 list; review N3).
OWED = [("bin-exact", "/bin holding exactly NATIVE + 17 ports + absd-sh is owed to scripts/cmds-matrix.py in the same chain"),
        ("command-sbase-present", "COMMAND SBASE PRESENT is owed to scripts/cmds-matrix.py in the same chain"),
        ("t2-t3-report-cases", "the extra cases of the T2/T3 reports are owed to scripts/cmds-matrix.py in the same chain")]
EXHAUSTION_REASON = "the cports harness offers no exhaustion scenario (sort's heap bound is T5's after R16)"


class Case:
    def __init__(self, name, util, stdin, args):
        self.name, self.util, self.stdin, self.args = name, util, stdin, args
        self.result_id = name
        # CportsMatrix.compare_census's interface: the paths below RUN this
        # lifecycle made (allowed), nothing kept or removed.
        self.allowed, self.removed, self.outputs, self.retained = set(), [], [], []


def table_rows(path):
    return [line.split("\t") for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]


def utils():
    return cu.utils()


def load_cases(path):
    cases, names = [], set()
    for f in table_rows(path):
        sm.require(len(f) == 4, f"bad case row {f!r}")
        name, util, stdin, args = f
        sm.require(name not in names, f"duplicate case {name}")
        sm.require(stdin == "-" or stdin in FIXTURES, f"{name}: STDIN {stdin} is not a fixture")
        names.add(name)
        cases.append(Case(name, util, stdin, shlex.split(args)))
    return cases


def load_divergences(path):
    out = {}
    for f in table_rows(path):
        sm.require(len(f) == 4, f"bad divergence row {f!r}")
        name, status, stderr, reason = f
        out[name] = (int(status), stderr, reason)
    return out


def predicted(status, stderr):
    """A divergences.tsv row as result bytes: its status, empty stdout, its
    stderr line, and (FIXTURES unchanged) no files section."""
    return cu.format_result(status, b"", stderr.encode() + b"\n", dict(FIXTURES))


def parse_pin(data):
    """(status, stdout, stderr, {name: bytes or None for removed}): the
    inverse of check-userland's format_result for the pins in expected/."""
    m = re.match(rb"status (-?\d+)\n--- stdout\n", data)
    sm.require(m is not None, f"not a pin: {data[:40]!r}")
    rest = data[m.end():]
    i = rest.index(b"--- stderr\n")
    out, rest = rest[:i], rest[i + len(b"--- stderr\n"):]
    j = rest.find(b"--- files\n")
    if j < 0:
        return int(m.group(1)), out, rest, {}
    err, rest = rest[:j], rest[j + len(b"--- files\n"):]
    files = {}
    while rest:
        line, rest = rest.split(b"\n", 1)
        word = line.split(b" ")
        if word[0] == b"removed":
            files[line[len(b"removed "):].decode()] = None
            continue
        sm.require(word[0] == b"file", f"bad files line {line!r}")
        size = int(word[-1])
        name = line[len(b"file "):-(len(word[-1]) + 1)].decode()
        files[name], rest = rest[:size], rest[size:]
    return int(m.group(1)), out, err, files


def d04(case, got):
    """The candidate disposition D-04 a defect may fall under, or None."""
    _, _, err, files = parse_pin(got)
    if case.util == "ed" and (any(SCRATCH.fullmatch(n) for n in files) or b"scratch file" in err):
        return "ed's scratch file (TMPDIR else the working directory)"
    if case.util == "find" and {"-exec", "-ok"} & set(case.args) and b"cannot run commands" in err:
        return "find's -exec/-ok refused with ENOSYS at parse time"
    return None


def od_bytes(text):
    """The bytes an `od -t x1` dump shows (address lines without data skipped)."""
    data = bytearray()
    for line in text.decode().splitlines():
        words = line.split()
        data += bytes(int(w, 16) for w in words[1:])
    return bytes(data)


def summary(n, counts, demo, notrun):
    word = "OK" if counts["defect"] == 0 else "DEFECTS"
    line = (f"ABSD USERLAND GUEST {word} cases={n} agree={counts['agree']} diverge={counts['diverge']} "
            f"defects={counts['defect']} demo={demo} notrun={','.join(notrun) or 'none'}")
    return line, 0 if counts["defect"] == 0 else 1


class UserlandTarget(cm.CportsTarget):
    def files(self, authorized):
        files = super().files(authorized)
        have = {path for path, _ in files}
        files += [(f"/bin/{name}", (self.root / "commands" / name).read_bytes()) for name in EXTRA
                  if f"/bin/{name}" not in have]
        return files


class UserlandMatrix(cm.CportsMatrix):
    # Each exec and PTY connection is counted. No PTY remains at a census,
    # so require the existing all-sessions-reclaimed line before sysinfo.
    QUIESCENT_READINGS = True

    def __init__(self, target, work, args):
        self.repo = REPO
        self.pins = pathlib.Path(args.pins).resolve()
        self.load_tables(args.only)
        root = pathlib.Path(target.root)
        rows = {f[0]: f for f in table_rows(REPO / "userland" / "PORTS.tsv")}
        sm.require(sorted(rows) == sorted(utils()), f"userland/PORTS.tsv names {sorted(rows)}, not {utils()}")
        products = []
        for name in utils():
            path = root / "ports" / name
            sm.require(path.is_file(), f"no {path}: ABSD_USERLAND_PLATFORM must be a built platform tree")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            sm.require(digest == rows[name][5], f"{path} sha256 {digest} is not userland/PORTS.tsv's {rows[name][5]}")
            products.append(path)
        target.products = products
        target.case_files = [(f"{TEMPLATE}/{n}", d) for n, d in FIXTURES.items()]
        sm.Matrix.__init__(self, target, work)

    def load_tables(self, only=None):
        every = load_cases(REPO / "userland" / "cases.tsv")
        names = {c.name for c in every}
        for c in every:
            sm.require(c.util in utils(), f"{c.name}: {c.util} is not a port")
        self.cases = [c for c in every if not only or any(c.name.startswith(p) for p in only)]
        sm.require(self.cases, f"no case matches --only {only}")
        self.divergences = load_divergences(REPO / "userland" / "divergences.tsv")
        sm.require(set(self.divergences) <= names, f"divergences.tsv names no case: {set(self.divergences) - names}")
        self.expected = REPO / "userland" / "expected"
        for c in every:
            pin = self.expected / c.name
            sm.require(pin.is_file(), f"no pin {pin}")
            if c.name in self.divergences:
                sm.require(predicted(*self.divergences[c.name][:2]) != pin.read_bytes(),
                           f"{c.name}: the divergence predicts the host pin itself")
            elif {"-nt", "-ot", "-newer", "-mtime", "-atime", "-ctime"} & set(c.args):
                sm.require(False, f"{c.name} uses file times and is not a divergence: this runner sets no times")
        if self.pins.exists():
            stray = sorted(p.name for p in self.pins.iterdir()
                           if p.name != "DEFECTS" and p.name.removesuffix(".repeat") not in names)
            sm.require(not stray, f"pins naming no case in {self.pins}: {stray}")
        self.defect_lines = {}

    # -- census interface (CportsMatrix) ------------------------------------------

    def allowed(self, case):
        return case.allowed

    @staticmethod
    def repeatable(name):
        # Every case runs twice; the repeat is judged with no allowed path
        # (only the boot's frames-only STEP allowance applies).
        return True

    # -- the case directory ---------------------------------------------------------

    def run_text(self, cwd, words):
        return f"cd {cwd}; " + " ".join(ck.quote(w) for w in words)

    def plain(self, cwd, words, what):
        rc, out, err, _, pids = self.shell_ssh(self.run_text(cwd, words), timeout=CASE_TIMEOUT)
        self.check(what, rc == 0 and out == b"" and err == b"" and len(pids) == 1, f"rc={rc} {out!r} {err!r} {pids}")

    def below(self, prefix, tree=None):
        tree = self.t.tree() if tree is None else tree
        return {p[len(prefix) + 1:]: d for p, d in tree.items() if p.startswith(prefix + "/")}

    def names_below(self, prefix):
        return {o for o in self.objects() if o.startswith(prefix + "/") or o == prefix}

    def make_template(self):
        self.plain(BASE, ["mkdir", *[f"fixtures/{d}" for d in FIXTURE_DIRS]], "the fixtures' empty directories made")
        self.check("the imported fixtures are FIXTURES byte for byte (bin.dat included)",
                   self.below(TEMPLATE) == FIXTURES, str(sorted(self.below(TEMPLATE))))

    def fresh_dir(self, case):
        self.check(f"{case.name}: no {RUN} left from before", RUN not in self.objects())
        self.plain(BASE, ["cp", "-r", "fixtures", "run"], f"{case.name}: fresh directory copied from the fixtures")
        objects = self.objects()
        got = self.below(RUN)
        self.check(f"{case.name}: the fresh directory holds FIXTURES byte for byte (bin.dat included) and its "
                   f"empty directories", got == FIXTURES and all(objects.get(f"{RUN}/{d}", (0, False))[1]
                                                                for d in FIXTURE_DIRS),
                   f"differ={sorted(n for n in set(got) | set(FIXTURES) if got.get(n) != FIXTURES.get(n))}")
        case.allowed |= self.names_below(RUN)

    def remove_dir(self, case):
        case.allowed |= self.names_below(RUN)
        self.plain(BASE, ["rm", "-r", "run"], f"{case.name}: the case directory removed")
        self.check(f"{case.name}: nothing of {RUN} is left", not self.names_below(RUN))

    def strip_status(self, case_name, util, rc, err):
        if rc != 0:
            line = f"absd-sh: {util}: exit status {rc}\n".encode()
            self.check(f"{case_name}: absd-sh reported the status {rc} as the last stderr line", err.endswith(line),
                       repr(err[-200:]))
            err = err[:-len(line)]
        return err

    def lifecycle(self, case):
        """Fresh directory, the case's session, its files, removal: the result bytes."""
        self.fresh_dir(case)
        stdin = b"" if case.stdin == "-" else FIXTURES[case.stdin]
        rc, out, err, shell, pids = self.shell_ssh(self.run_text(RUN, [case.util, *case.args]), stdin=stdin,
                                                   timeout=CASE_TIMEOUT)
        self.check(f"{case.name}: {case.util} ran as the shell's only child", len(pids) == 1,
                   f"shell={shell} children={pids}")
        err = self.strip_status(case.name, case.util, rc, err)
        after = self.below(RUN)  # raw file bytes through the existing fs reader
        if case.result_id == "tar-create" and "made.ustar" in after:
            # Preserve both actual occurrences before projection and guest cleanup.
            rawdir = pathlib.Path(self.work) / "tar-create-raw"
            rawdir.mkdir(exist_ok=True)
            occurrence = "repeat" if case.name.endswith(" repeat") else "first"
            rawpath = rawdir / (occurrence + ".ustar")
            data = after["made.ustar"]
            if rawpath.exists():
                sm.require(rawpath.read_bytes() == data, "conflicting retained tar-create occurrence")
            else:
                with rawpath.open("xb") as stream:
                    stream.write(data)
            print(f"USERLAND TAR RAW {occurrence} bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()} path={rawpath}", flush=True)
        got = cu.format_result(rc, out, err, after, case_id=case.result_id)
        self.remove_dir(case)
        return got

    # -- judging ---------------------------------------------------------------------

    def want(self, case):
        if case.name in self.divergences:
            status, stderr, _ = self.divergences[case.name]
            return predicted(status, stderr), "its divergences.tsv row"
        return (self.expected / case.name).read_bytes(), f"userland/expected/{case.name}"

    def judge(self, case, got, again):
        want, source = self.want(case)
        wrong = []
        if got != want:
            wrong.append(f"differs from {source}")
        if again != got:
            wrong.append("the repeat differs from the first run")
        if not wrong:
            if case.name in self.divergences:
                print(f"USERLAND DIVERGES {case.name} :: {self.divergences[case.name][2]}", flush=True)
                return "diverge"
            print(f"USERLAND CASE OK {case.name}", flush=True)
            return "agree"
        self.pins.mkdir(parents=True, exist_ok=True)
        (self.pins / case.name).write_bytes(got)
        print(f"USERLAND PIN WRITTEN {self.pins / case.name}: review it", flush=True)
        if again != got:
            (self.pins / f"{case.name}.repeat").write_bytes(again)
            print(f"USERLAND PIN WRITTEN {self.pins / case.name}.repeat: review it", flush=True)
        what = "; ".join(wrong)
        disposition = d04(case, got)
        if disposition and case.name not in self.divergences:
            what += f"; candidate disposition D-04: {disposition}"
        self.defect_lines[case.name] = what
        (self.pins / "DEFECTS").write_text(
            "# Defects of the last guest run (scripts/userland-matrix.py): ID, what differed.\n"
            + "".join(f"{n}\t{w}\n" for n, w in sorted(self.defect_lines.items())))
        print(f"USERLAND DEFECT {case.name} :: {what}\n--- want ({source})\n"
              f"{want.decode(errors='replace')}--- got\n{got.decode(errors='replace')}--- end", flush=True)
        return "defect"

    def run_cases(self):
        counts = {"agree": 0, "diverge": 0, "defect": 0}
        for case in self.cases:
            start = time.monotonic()
            before = self.stable(case.name, "before")
            got = self.lifecycle(case)
            after = self.stable(case.name, "after")
            memory, kernel = self.compare_census(case, before, after)
            first = self.judged
            repeat = Case(f"{case.name} repeat", case.util, case.stdin, case.args)
            repeat.result_id = case.result_id
            again = self.lifecycle(repeat)
            repeat.allowed = set()           # the repeat: no allowed path, no high-water reading
            self.compare_census(repeat, first, self.stable(case.name, "repeat"), allow_rest_lowering=False)
            counts[self.judge(case, got, again)] += 1
            print(f"USERLAND RESOURCES {case.name} :: {memory} | {kernel} | images={first['images']} "
                  f"objects={len(first['objects'])} repeat=equal seconds={time.monotonic() - start:.1f}", flush=True)
        return counts

    # -- ^C ----------------------------------------------------------------------------

    def interrupts(self):
        t, block = self.t, Case("interrupt", "-", "-", [])
        before = self.stable("interrupt", "before")
        self.fresh_dir(block)
        baseline = t.all_images()
        self.connections += 1
        term, _ = t.open_shell(self)
        done = []
        try:
            t.step(self, term, f"cd {RUN}\r".encode(), f"cd {RUN}\r\n".encode() + t.pty_prompt, "cd to the fresh directory")
            for util, args in INTERRUPT:
                line = " ".join([util, *args]).encode()
                spawned = t.spawn_count()
                t.step(self, term, line + b"\r", line + b"\r\n", f"{util} runs, reading the terminal")
                t.await_spawns(spawned, 1)
                ms = t.interrupt(self, term, f"^C ends {util}; the shell prompts")
                t.await_live(self, baseline + 1, f"{util} was killed and reaped")
                t.step(self, term, b"status\r", b"status\r\n130\r\n" + t.pty_prompt, f"{util}: the line's status is 130")
                print(f"USERLAND INTERRUPT OK {util} ms={ms:.0f}", flush=True)
                done.append(util)
            t.step(self, term, b"exit\r", b"exit\r\n", "the shell exits when asked")
            rc = term.wait(timeout=60)
        finally:
            term.close()
        self.check("the PTY session ends with status 0", rc == 0, f"rc={rc}")
        t.await_live(self, baseline, "nothing of the session is left")
        files = self.below(RUN)
        scratch = sorted(n for n in files if SCRATCH.fullmatch(n))
        rest = {n: d for n, d in files.items() if n not in scratch}
        self.check("after ^C the directory holds FIXTURES and at most ed's one scratch file",
                   rest == FIXTURES and len(scratch) <= 1, f"scratch={scratch} differ={sorted(set(rest) ^ set(FIXTURES))}")
        print(f"USERLAND INTERRUPT ED scratch_left={len(scratch)} {' '.join(scratch)} (userland/README.md predicts 1: "
              f"no signal handler, the buffer is lost)", flush=True)
        self.remove_dir(block)
        self.compare_census(block, before, self.stable("interrupt", "after"))
        return done

    # -- the demo --------------------------------------------------------------------

    def demo(self):
        demo = Case("demo", "-", "-", [])
        demo.allowed = {f"{HOME}/hello.c", f"{HOME}/a.out"}
        before = self.stable("demo", "before")

        def run(words, stdin=b""):
            rc, out, err, _, pids = self.shell_ssh(self.run_text(HOME, words), stdin=stdin, timeout=CASE_TIMEOUT)
            self.check(f"demo: {' '.join(words)} ran as the shell's only child", len(pids) == 1, str(pids))
            return rc, out, self.strip_status("demo", words[0], rc, err)

        rc, out, err = run(["ed", "-p", "* "], DEMO_ED)
        self.check("demo: ed -p '* ' wrote hello.c (its byte count printed)",
                   rc == 0 and err == b"" and f"{len(DEMO_LINE)}\n".encode() in out, f"rc={rc} {out!r} {err!r}")
        tree = self.t.tree()
        home = self.below(HOME, tree)
        self.check("demo: hello.c holds the line on the image", home.get("hello.c") == DEMO_LINE, repr(home.get("hello.c")))
        left = sorted(n for n in home if SCRATCH.fullmatch(n.rsplit("/", 1)[-1]))
        self.check("demo: no ./ed.XXXXXX left behind", not left, str(left))
        print(f"USERLAND DEMO ED hello.c bytes={len(DEMO_LINE)} stdout={out!r}", flush=True)
        rc, out, err = run(["od", "-t", "x1", "hello.c"])
        self.check("demo: od -t x1 dumps hello.c's bytes", rc == 0 and err == b"" and od_bytes(out) == DEMO_LINE,
                   f"rc={rc} {out!r} {err!r}")
        rc, out, err = run(["cmp", "hello.c", "hello.c"])
        self.check("demo: cmp of hello.c with itself is silent, status 0", (rc, out, err) == (0, b"", b""), f"{rc} {out!r} {err!r}")
        rc, out, err = run(["grep", "-n", "main", "hello.c"])
        self.check("demo: grep -n main hello.c", (rc, out, err) == (0, b"1:" + DEMO_LINE, b""), f"{rc} {out!r} {err!r}")
        rc, out, err = run(["find", ".", "-name", "ed.*"])
        self.check("demo: find . -name 'ed.*' finds nothing", (rc, out, err) == (0, b"", b""), f"{rc} {out!r} {err!r}")
        notrun = []
        if self.t.physical("/bin/tcc") in tree:
            rc, out, err = run(["tcc", "-o", "a.out", "hello.c"])
            self.check("demo: tcc compiles hello.c", rc == 0 and err == b"", f"{rc} {out!r} {err!r}")
            rc, out, err = run(["./a.out"])
            self.check("demo: ./a.out returns 0", (rc, out, err) == (0, b"", b""), f"{rc} {out!r} {err!r}")
            self.plain(HOME, ["rm", "a.out"], "demo: rm a.out")
            print("USERLAND DEMO TCC OK", flush=True)
        else:
            print("USERLAND DEMO TCC NOT_RUN reason=no /bin/tcc", flush=True)
            notrun.append("demo-tcc")
        self.plain(HOME, ["rm", "hello.c"], "demo: rm hello.c")
        rc, out, err = run(["man", "sbase"])
        shown = " ".join(out.decode(errors="replace").split())
        missing = [l for l in cmds.licence_lines((REPO / "userland" / "sbase.LICENSE").read_text()) if l not in shown]
        self.check("demo: man sbase prints sbase's licence", rc == 0 and not missing, f"rc={rc} missing={missing[:3]}")
        rc, out, err = run(["ls", "/bin"])
        names = set(out.decode().split())
        self.check("demo: /bin holds the nine sbase ports", rc == 0 and set(utils()) <= names, str(sorted(names)))
        print(f"USERLAND DEMO SBASE PRESENT names={','.join(utils())} (COMMAND SBASE PRESENT is the command "
              f"matrix's, scripts/run-cmds-matrix.sh)", flush=True)
        self.compare_census(demo, before, self.stable("demo", "after"))
        print("USERLAND DEMO OK", flush=True)
        return notrun

    # -- the run ----------------------------------------------------------------------

    def provenance_line(self):
        pin = [f for f in table_rows(REPO / "userland" / "PIN") if f[0] == "sbase"][0]
        return (f"USERLAND PINS PROVENANCE expected=userland/expected pins={len(list(self.expected.iterdir()))} "
                f"from the Linux REFERENCE build (gcc, glibc) of {pin[0]} {pin[1]} sha256={pin[3]} (userland/PIN) "
                f"with argv[0]=/bin/<name> (D-21); "
                f"divergences=userland/divergences.tsv rows={len(self.divergences)} (ABSD predictions)")

    def run(self):
        t = self.t
        started = time.monotonic()
        ssh_absd.IMAGE_BYTES = cm.IMAGE_BYTES
        ssh_absd.DEVICE_SECTORS = ssh_absd.IMAGE_BYTES // 512
        authorized = (self.op.with_suffix(".pub")).read_text()
        imported = t.files(authorized)
        t.setup(self.work, authorized)
        print(f"USERLAND IMPORT files={len(imported)} bytes={sum(len(d) for _, d in imported)} boots={t.boots}", flush=True)
        first = t.start(fresh=True)
        self.client = sm.Client(self.work, t.port)
        self.client.trust(first["public"])
        self.host_key = first["public"]
        self.steps, self.limited, self.highwater, self.restart_round = 0, set(), [], 1
        rc, out, err, _, _ = self.shell_ssh('"printenv"')
        self.check("the session's environment is empty, as the host cases' (SPEC A20)", (rc, out, err) == (0, b"", b""),
                   f"{rc} {out!r} {err!r}")
        self.make_template()
        counts = self.run_cases()
        notrun = []
        done = self.interrupts()
        for util in utils():
            if util not in done:
                print(f"USERLAND NOT_RUN interrupt-{util} reason={NO_INTERRUPT.get(util, 'no case')}", flush=True)
                notrun.append(f"interrupt-{util}")
        print(f"USERLAND NOT_RUN exhaustion reason={EXHAUSTION_REASON}", flush=True)
        notrun.append("exhaustion")
        notrun += self.demo()
        for item, reason in OWED:
            print(f"USERLAND NOT_RUN {item} reason={reason}", flush=True)
            notrun.append(item)
        self.alive("the userland cases")
        t.stop()
        self.rest_recorded()          # census ruling (b): any lowered rest count (not a failure)
        print(f"USERLAND RESOURCES OK cases={len(self.cases)} highwater={len(self.highwater)} steps={self.steps} "
              f"seconds={time.monotonic() - started:.0f}", flush=True)
        print(self.provenance_line(), flush=True)
        line, status = summary(len(self.cases), counts, "ok", notrun)
        print(line, flush=True)
        return status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--pins", help="where a DEFECT's result is written (default <work>/pins)")
    ap.add_argument("--only", action="append", help="run only cases whose ID starts with this prefix")
    argv = sys.argv[1:]
    print("USERLAND ARGS " + " ".join(sys.argv), flush=True)
    rest = []
    if "--" in argv:
        i = argv.index("--")
        argv, rest = argv[:i], argv[i + 1:]
    args = ap.parse_args(argv)
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    args.pins = args.pins or str(work / "pins")
    base = ssh_absd.target(rest)
    target = UserlandTarget.__new__(UserlandTarget)
    target.__dict__.update(base.__dict__)
    matrix = UserlandMatrix(target, work, args)
    try:
        status = matrix.run()
    except FAILED as e:
        print(f"USERLAND MATRIX FAILED: {e}", file=sys.stderr, flush=True)
        target.stop()
        sys.exit(1)
    except BaseException:
        target.stop()
        raise
    sys.exit(status)


if __name__ == "__main__":
    main()
