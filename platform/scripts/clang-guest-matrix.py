#!/usr/bin/env python3
"""Native Clang T4-T6 in the guest on the shell route: CL1 (lld and the
split front end start on ABSD) and CL2/CL3 (the split pipeline cc1-fe-o0 ->
llc -> lld compiles, links and runs hello.c inside one absd-sh session).
docs/native-clang-20261012/GUEST-RUN.md is the steward's page.

Modelled on the Stage 3 harness (the tcc lane's scripts/tcc-matrix.py at
e4a2cca0: held absd-sh sessions fed a line at a time, cut by marks; the
import route; the session environment; the kernel-exact gate on the host
reader's copy; the inherited census rules of scripts/cports-matrix.py).

One `net fsd` boot (scripts/ssh_absd.py) on a fixture of IMAGE_BYTES (the
filesystem is the device's second half, absd_image.parse_layout v3). The
image carries, beside ssh_absd's deployment and cports-matrix's extra
commands, /bin/cp and /bin/sha256sum; the three LLVM images
(<llvm-build>/kit/bin/<name>.stripped, each bound by digest to
kit/BUILT-FROM's `image <name> <sha256> bytes=<n>` line, each at most the
32 MiB spawn cap) at /bin/lld, /bin/cc1-fe-o0, /bin/llc; the share tree
SHARE: the kit's include/ tree, its crt0.o, libabs.a, libc.a, libm.a,
libabs_builtins.a and absd-c.ld (digests bound to kit/BUILT-FROM's
`kit-lib/` and `kit-absd-c.ld` lines where it records them), the clang-18
builtins archive the kit's absd-cc links (`clang-18 -print-resource-dir`,
lib/linux/), and the C freestanding headers of the pinned clang's resource
directory (RESOURCE_HEADERS, from <llvm-build>/kit/lib/clang/18/include) at
RESOURCE/include; and the case inputs at CASES_DIR (hello.c and
hello.cc1.rsp from cxx/tests/llvm/).

Cases (cxx/tests/llvm/guest-cases.tsv; pins in guest-expected/<case>.txt,
c-kit-matrix pin_bytes form: stdout, `--`, stderr, `--`, `status=<n>`):
  start  ARGV...      one held session whose FIRST command is ARGV (the
                      program by absolute path). Its stdout, stderr and
                      status must equal the pin; exactly one SPAWN OK child
                      of the shell, its USER EXIT status the shell's.
  split  SRC RSP      one held session; the first spawn is the front end
                      (the shell reads a spawned image into one buffer kept
                      at the largest capacity so far, runtime/src/process.rs
                      92-100, 276; growing it later would ask for
                      max(2 x capacity, image) while the old block is held,
                      so the 32.86 MB image is read first, into an empty
                      buffer). In order:
    cd /tmp/session-<n>   builtin; <n> predicted from sshd's session count,
                          other numbers tried by cd if it is wrong (fsd
                          shows a session only its own scratch directory)
    cd CASES_DIR
    "/bin/cc1-fe-o0" "@<RSP>" "-o" "/tmp/session-<n>/hello.bc"
                          (MAX_ARGC is 32, broker/src/lib.rs:34: the cc1
                          arguments travel in the response file, which
                          cc1-main.cpp expands as the driver would)
    cd /tmp/session-<n>
    "/bin/ls" /tmp        exactly `session-<n>/` (the truth source of <n>)
    "/bin/llc" LLC_OPTIONS hello.bc -o hello.o   (T2's exact options)
    "/bin/lld" -flavor ld.lld LINK... -Map=a.out.map -o a.out   (absd-cc's
                          link line over the imported share tree)
    "/bin/sha256sum" hello.bc hello.o a.out a.out.map
    "/bin/cp" <each> OUT_DIR/<case>.{bc,o,elf,map}
    ./a.out               stdout, stderr, status equal to the pin
  The host then reads the copies from the image (each digest equal to the
  session's sha256sum line), runs scripts/check-abi-elf.py (kernel-exact)
  on the ELF and scripts/check-c-elf.py --map on it with the map's share
  paths rewritten to the host mirror (the kit gate), and compares each
  artifact with the Linux twin's run of the same pipeline over a host
  mirror of the same files (identical_to_twin, reported, not judged: the
  twin's front end is cc1-fe, not the O0-only cc1-fe-o0).

Expected outputs come from the Linux twin (<llvm-build>/twin/bin), checked
again on every run (host_side): `start` pins by running the twin program of
the same name (cc1-fe for cc1-fe-o0; -version does not depend on the pass
registry) with argv[0] the guest path, an empty environment and a fresh
empty directory; the `split` pin by the twin front end compiling SRC for
x86_64-linux-gnu (-O0 -c) and the host's cc linking it, run twice (equal)
with an empty environment. The response file must equal the cc1 arguments
the twin driver prints (-###) for absd-cc's flags over SHARE with
-ffile-compilation-dir=CASES_DIR, less `-o <out>`. A stale pin refuses the
run; --write-pins (with --host-only) writes them.

Resources: each case runs between two stable censuses judged by
cports-matrix compare_census (the case's OUT_DIR files the only allowed
change; the frames-only step rule; a high-water case is repeated twice at
the end, each round's census equal to the census before the rounds). sshd's
quiescent `SERVED CAPACITY ... frames= heap_pages_peak=` line before and
after each case is printed (CLANG GUEST CAPACITY): frames is the kernel's
census at rest, heap_pages_peak sshd's own heap; neither is the compiler's
peak, which no line reports.

Host rules: run-clang-guest.sh runs this at niceness 10 or more; before
every QEMU launch (each import boot and the sshd boot, AbsdTarget.iso is
called right before each) the 1-minute load must be at most LOAD_LIMIT
(waited for up to LOAD_WAIT seconds) and no QEMU of this work directory may
be running.

Markers: CLANG HOST ...; CLANG GUEST FIXTURE; CLANG GUEST IMPORT; CLANG
GUEST IMAGE; CLANG GUEST SESSION ENV count=; CLANG GUEST CAPACITY <case>;
CLANG GUEST STEP <case> <step>; CLANG GUEST OK <case> ...; CLANG GUEST
FAILED <case> <first divergent line>; CLANG GUEST RESOURCES <case>; ABSD
CLANG GUEST OK cases=N ... (every case, no --only) | PARTIAL | FAILED."""
import argparse, hashlib, os, pathlib, re, select, shutil, subprocess, sys, time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import ssh_absd  # noqa: E402
import absd_fs  # noqa: E402
import importlib.util  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), here / f"{name}.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


cm = load("cports-matrix")
ck = cm.ck
gate = load("check-abi-elf")
em = ssh_absd.em

PROMPT = b"absd$ "                   # sh/src/lib.rs PROMPT, written before every line read
MAX_IMAGE = 32 * 1024 * 1024         # runtime/src/process.rs:40 MAX_IMAGE (= abi MAX_SPAWN_IMAGE_BYTES)
SHARE = "/share/absd-clang"
RESOURCE = f"{SHARE}/lib/clang/18"
CASES_DIR = "/home/operator/clang-cases"
OUT_DIR = "/home/operator/clang-out"
IMAGES = ("lld", "cc1-fe-o0", "llc")  # <llvm-build>/kit/bin/<name>.stripped -> /bin/<name>
TWIN = {"/bin/lld": "lld", "/bin/cc1-fe-o0": "cc1-fe", "/bin/llc": "llc"}
KIT_LIBS = ("crt0.o", "libabs.a", "libc.a", "libm.a", "libabs_builtins.a")
BUILTINS = "libclang_rt.builtins-x86_64.a"
# The C freestanding headers clang supplies (C17 4p6, C23's stdckdint.h)
# and the pieces stddef.h/stdarg.h include; no target intrinsics, no
# offload or wrapper trees. The kit's include/ is searched first.
RESOURCE_HEADERS = ("float.h", "iso646.h", "limits.h", "stdalign.h", "stdarg.h", "stdatomic.h", "stdbool.h",
                    "stdckdint.h", "stddef.h", "stdint.h", "stdnoreturn.h")
RESOURCE_PREFIXES = ("__stddef_", "__stdarg_")
EXTRA = ["cp", "sha256sum"]          # beside cports-matrix.EXTRA (mkdir cat df sysinfo ls)
# absd-cc's cflags (kit bin/absd-cc:23) over SHARE: what the response file must equal.
KIT_CFLAGS = ["--target=x86_64-unknown-none-elf", "-U_FORTIFY_SOURCE", "-ffreestanding", "-nostdinc", "-nostdlib",
              "-mcmodel=large", "-fno-pic", "-fno-pie", "-fno-stack-protector", "-mno-avx", "-march=x86-64",
              "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-fdata-sections", "-Xclang",
              "-fstack-clash-protection", "-isystem", f"{SHARE}/include", "-isystem", f"{RESOURCE}/include"]
# T2's split pipeline (scripts/build-llvm-kit.sh measure_twin): llc's options, verbatim.
LLC_OPTIONS = ["-O0", "-filetype=obj", "-mtriple=x86_64-unknown-none-elf", "-code-model=large",
               "-relocation-model=static", "-mcpu=x86-64", "-mattr=-avx", "-function-sections", "-data-sections"]
# absd-cc's link (kit bin/absd-cc:61-63) over SHARE, plus a map for the kit gate.
LINK = (["-flavor", "ld.lld", "-static", "-no-pie", "--gc-sections", "-T", f"{SHARE}/absd-c.ld",
         "-Map=a.out.map", "-o", "a.out", f"{SHARE}/lib/crt0.o", "hello.o", "--start-group"]
        + [f"{SHARE}/lib/{n}" for n in ("libabs.a", "libc.a", "libm.a", "libabs_builtins.a", BUILTINS)]
        + ["--end-group"])
ARTIFACTS = (("hello.bc", "bc"), ("hello.o", "o"), ("a.out", "elf"), ("a.out.map", "map"))
# The fixture: the smallest multiple of 64 MiB whose filesystem (the second
# half) holds the payload plus FS_HEADROOM (logs, state, outputs), computed
# from the file list (--list) for the reference platform tree; a run whose
# payload does not fit refuses before the first import boot.
IMAGE_BYTES = 256 * 1024 * 1024
FIXTURE_STEP = 64 * 1024 * 1024
FS_HEADROOM = 16 * 1024 * 1024
LOAD_LIMIT = 10.0
LOAD_WAIT = 1800
# Named limits (measured values are printed per step), not expectations.
SPAWN_TIMEOUT = 3600                 # one LLVM program under TCG, its image read through the file server
STEP_TIMEOUT = 300
RUN_TIMEOUT = 600
SESSION_START_TIMEOUT = 120
SESSION_CLOSE_TIMEOUT = 120
CLIENT_WAIT_TIMEOUT = 60
USER_LINE_TIMEOUT = 10
CAPACITY_TIMEOUT = 60
HOST_TIMEOUT = 300
REPEAT_ROUNDS = 2
SERVED = re.compile(r"SERVED CAPACITY boot=\S+ accepted_reclaimed=(\d+) [^\n]*?processes=(\d+) handles=(\d+) "
                    r"pipes=(\d+) cells=(\d+) frames=(\d+) heap_pages_peak=(\d+)")


class Refused(Exception):
    """A stream, table or input the harness will not interpret."""


class CaseFailed(Exception):
    """A case's first divergence; the message is the FAILED line's tail."""


# -- pure helpers (scripts/clang-guest-selftest.py) ------------------------------

def sha(data):
    return hashlib.sha256(data).hexdigest()


def exit_mark(mark):
    return f"absd-sh: exit: {mark}: not a number\n".encode()


def split_step(out, opos, err, epos, mark):
    """tcc-matrix.split_step: one fed command's (stdout, status, stderr,
    next stdout position, next stderr position), or None while its marks
    have not both arrived."""
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


def first_divergent_line(want, got):
    """None when equal, else `line <k>: got <...> want <...>` for the
    first differing line (keepends: a missing final newline differs)."""
    if want == got:
        return None
    w, g = want.splitlines(keepends=True), got.splitlines(keepends=True)
    for i in range(max(len(w), len(g))):
        a = w[i] if i < len(w) else None
        b = g[i] if i < len(g) else None
        if a != b:
            return f"line {i + 1}: got {b!r} want {a!r}"
    return "equal lines, different bytes"


def parse_pin(data):
    """(status, stdout, stderr) of a pin_bytes text, or None."""
    lines = data.splitlines(keepends=True)
    m = re.fullmatch(rb"status=(-?\d+)\n", lines[-1]) if lines else None
    if m is None or len(lines) < 3 or lines[-2] != b"--\n" or b"--\n" not in lines[:-2]:
        return None
    i = lines.index(b"--\n")
    return int(m.group(1)), b"".join(lines[:i]), b"".join(lines[i + 1:-2])


def parse_digests(out, names):
    """{name: hex} from sha256sum's stdout for exactly `names`, in order."""
    lines = out.decode(errors="replace").splitlines()
    got = [re.fullmatch(r"([0-9a-f]{64})  (\S+)", line) for line in lines]
    if len(got) != len(names) or any(m is None for m in got) or [m.group(2) for m in got] != list(names):
        raise Refused(f"sha256sum printed {out!r}, want one line for each of {list(names)}")
    return {m.group(2): m.group(1) for m in got}


def rewrite_map(text, mirror_share):
    """The guest's link map with SHARE replaced by the host mirror's copy
    (the same bytes), so check-c-elf.py can read the archives it names."""
    return text.replace(SHARE + "/", str(mirror_share) + "/")


def resource_header(name):
    return name in RESOURCE_HEADERS or name.startswith(RESOURCE_PREFIXES)


def fs_capacity(image_bytes):
    sectors = image_bytes // 512
    return absd_fs.geometry(sectors - sectors // 2)["data_blocks"] * absd_fs.BLOCK


def payload_bytes(files):
    return sum(-(-len(data) // absd_fs.BLOCK) * absd_fs.BLOCK for _, data in files)


def smallest_fixture(files):
    need = payload_bytes(files) + FS_HEADROOM
    size = FIXTURE_STEP
    while fs_capacity(size) < need:
        size += FIXTURE_STEP
    return size


def predicted_session(output):
    """sshd's next session id is its attempted count (ssh/src/absd.rs
    785-786); the SSH SESSION CHILD lines through the held session's own
    count the attempts that started a child."""
    return len(re.findall(r"SSH SESSION CHILD ", output))


def quote(word):
    return ck.quote(word)


def command(argv):
    """A shell line: the program by absolute path, every word quoted."""
    return " ".join(quote(w) for w in argv)


class Case:
    def __init__(self, fields):
        self.name, self.kind, *self.argv = fields
        self.cwd, self.removed = "", []          # cports-matrix compare_census's fields


def load_cases(path):
    """Rows NAME KIND WORDS... (tab-separated): `start ARGV...` (ARGV[0] a
    /bin path of the image) or `split SRC RSP` (files in the table's
    directory)."""
    cases, names = [], set()
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        case = Case(line.split("\t"))
        ok = case.name not in names and (
            (case.kind == "start" and case.argv and case.argv[0] in TWIN)
            or (case.kind == "split" and len(case.argv) == 2))
        if not ok:
            raise Refused(f"{path}: bad or duplicate row {line!r}")
        cases.append(case); names.add(case.name)
    return cases


def built_from(path):
    """kit/BUILT-FROM: {'image <name>': (sha, bytes)} and {'kit-lib/<f>' or 'kit-absd-c.ld': sha}."""
    images, kit = {}, {}
    for line in path.read_text().splitlines():
        m = re.fullmatch(r"image (\S+) ([0-9a-f]{64}) bytes=(\d+)", line)
        if m:
            images[m.group(1)] = (m.group(2), int(m.group(3)))
            continue
        m = re.fullmatch(r"(kit-lib/\S+|kit-absd-c\.ld) ([0-9a-f]{64})", line)
        if m:
            kit[m.group(1)] = m.group(2)
    return images, kit


def load_average():
    return float(pathlib.Path("/proc/loadavg").read_text().split()[0])


def lane_qemus(work):
    """PIDs of qemu-system-* processes whose command line names `work`."""
    found = []
    for proc in pathlib.Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            args = (proc / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if args and b"qemu-system" in pathlib.Path(args[0].decode(errors="replace")).name.encode() \
                and any(str(work).encode() in a for a in args):
            found.append(int(proc.name))
    return found


def guard_launch(work, what):
    """U1 host rules before a QEMU launch: none of this lane's running, and
    the 1-minute load at most LOAD_LIMIT (waited for, LOAD_WAIT at most)."""
    running = lane_qemus(work)
    if running:
        raise ssh_absd.Failed(f"before {what}: QEMU of this work directory still running: {running}")
    start = time.monotonic()
    while True:
        load = load_average()
        if load <= LOAD_LIMIT:
            return load
        if time.monotonic() - start > LOAD_WAIT:
            raise ssh_absd.Failed(f"before {what}: the 1-minute load stayed above {LOAD_LIMIT} for {LOAD_WAIT} s")
        print(f"CLANG GUEST LOAD WAIT {what} load={load} limit={LOAD_LIMIT}", flush=True)
        time.sleep(30)


# -- the guest -----------------------------------------------------------------

class Step:
    def __init__(self, command, out, status, err, seconds, children, serial):
        self.command, self.out, self.status, self.err = command, out, status, err
        self.seconds, self.children, self.serial = seconds, children, serial


class Held:
    """One interactive absd-sh session fed a line at a time (tcc-matrix.Held)."""

    def __init__(self, m):
        self.m, t = m, m.t
        before = len(re.findall(r"SSH SESSION CHILD ", t.output()))
        self.done = m.reclaimed()
        self.p = subprocess.Popen(m.client.base(m.op, ("-T",)), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        self.out, self.err, self.opos, self.epos, self.k = b"", b"", 0, 0, 0
        try:
            deadline = time.monotonic() + SESSION_START_TIMEOUT
            child = []
            while time.monotonic() < deadline:
                child = re.findall(r"SSH SESSION CHILD pid=(\d+) spawn_right=(\w+) argv0=(\S+) [^\n]*control=(\w+)\r?\n",
                                   t.output())[before:]
                if child:
                    break
                time.sleep(0.2)
            m.check("the held session runs absd-sh with the spawn right and session control",
                    len(child) == 1 and child[0][1:] == ("true", "/bin/absd-sh", "true"), str(child))
        except BaseException:
            self.kill()
            raise
        self.shell = child[0][0]
        self.session = predicted_session(t.output())

    def children(self):
        return re.findall(rf"SPAWN OK pid=(\d+) parent={self.shell} program=image", self.m.t.serial())

    def pump(self, timeout):
        live = [f for f in (self.p.stdout, self.p.stderr) if not f.closed]
        r, _, _ = select.select(live, [], [], timeout)
        for f in r:
            chunk = os.read(f.fileno(), 65536)
            if not chunk:
                f.close(); continue
            if f is self.p.stdout:
                self.out += chunk
            else:
                self.err += chunk

    def step(self, line, timeout=STEP_TIMEOUT):
        self.k += 1
        mark = f"clang-mark-{self.k}"
        before = len(self.children())
        serial_at = len(self.m.t.serial())
        start = time.monotonic()
        self.p.stdin.write(f"{line}\nstatus\nexit {mark}\necho {mark}\n".encode()); self.p.stdin.flush()
        while True:
            done = split_step(self.out, self.opos, self.err, self.epos, mark)
            if done is not None:
                break
            if time.monotonic() - start > timeout:
                raise CaseFailed(f"step {line[:80]!r} did not end within {timeout} s (named limit): "
                                 f"stdout tail {self.out[-200:]!r} stderr tail {self.err[-200:]!r}")
            if self.p.stdout.closed and self.p.stderr.closed:
                raise CaseFailed(f"the session ended during {line[:80]!r}: {self.err[-200:]!r}")
            self.pump(1.0)
        seconds = time.monotonic() - start
        out, status, err, self.opos, self.epos = done
        return Step(line, out, status, err, seconds, self.children()[before:], self.m.t.serial()[serial_at:])

    def close(self):
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


class ClangTarget(cm.CportsTarget):
    def iso(self, step, worker, input_bytes=b"", options="", server=""):
        # Called right before every QEMU launch: each import boot and the sshd boot.
        load = guard_launch(self.work, f"boot {self.boots + 1}")
        self.launch_loads.append(load)
        return super().iso(step, worker, input_bytes, options, server)


class ClangMatrix(cm.CportsMatrix):
    # This runner has separate interactive sessions and no complete count.
    # Preserve its existing sampling behavior when Cports enables its gate.
    QUIESCENT_READINGS = False

    def __init__(self, target, work, args):
        self.repo = here.parent
        self.llvm = pathlib.Path(args.llvm_build).resolve()
        self.kit = pathlib.Path(args.kit).resolve()
        table = pathlib.Path(args.cases).resolve()
        self.inputs = table.parent
        self.expected_dir = table.parent / "guest-expected"
        every = load_cases(table)
        self.cases = [c for c in every if not args.only or c.name in args.only]
        self.only = bool(args.only)
        cm.sm.require(self.cases, f"no case matches --only {args.only}")
        self.every = every
        self.images = {}
        record_images, record_kit = built_from(self.llvm / "kit" / "BUILT-FROM")
        for name in IMAGES:
            data = (self.llvm / "kit" / "bin" / f"{name}.stripped").read_bytes()
            want = record_images.get(name)
            cm.sm.require(want == (sha(data), len(data)),
                          f"{name}.stripped {sha(data)} {len(data)} B is not kit/BUILT-FROM's {want}")
            cm.sm.require(len(data) <= MAX_IMAGE, f"{name}: {len(data)} B over the spawn cap {MAX_IMAGE}")
            self.images[name] = data
        share = []
        for f in KIT_LIBS:
            data = (self.kit / "lib" / f).read_bytes()
            want = record_kit.get(f"kit-lib/{f}")
            cm.sm.require(want in (None, sha(data)), f"kit lib/{f} {sha(data)} is not kit/BUILT-FROM's {want}")
            share.append((f"{SHARE}/lib/{f}", data))
        data = (self.kit / "absd-c.ld").read_bytes()
        cm.sm.require(record_kit.get("kit-absd-c.ld") == sha(data), "kit absd-c.ld is not kit/BUILT-FROM's")
        share.append((f"{SHARE}/absd-c.ld", data))
        self.builtins_path = self.host_builtins()
        share.append((f"{SHARE}/lib/{BUILTINS}", self.builtins_path.read_bytes()))
        include = self.kit / "include"
        share += [(f"{SHARE}/include/{p.relative_to(include).as_posix()}", p.read_bytes())
                  for p in sorted(include.rglob("*")) if p.is_file()]
        resource = self.llvm / "kit" / "lib" / "clang" / "18" / "include"
        headers = [p for p in sorted(resource.iterdir()) if p.is_file() and resource_header(p.name)]
        cm.sm.require(len([p for p in headers if p.name in RESOURCE_HEADERS]) == len(RESOURCE_HEADERS),
                      f"resource headers missing from {resource}")
        share += [(f"{RESOURCE}/include/{p.name}", p.read_bytes()) for p in headers]
        self.share = share
        self.case_inputs = []
        for c in every:
            if c.kind == "split":
                for n in c.argv:
                    p = self.inputs / n
                    cm.sm.require(p.is_file(), f"{c.name}: no input {p}")
                    self.case_inputs.append((f"{CASES_DIR}/{n}", p.read_bytes()))
        target.products = []
        target.launch_loads = []
        root = getattr(target, "root", None)
        extra = [(f"/bin/{n}", (root / "commands" / n).read_bytes()) for n in EXTRA] if root else []
        target.case_files = (extra + [(f"/bin/{n}", self.images[n]) for n in IMAGES] + share + self.case_inputs)
        work.mkdir(parents=True, exist_ok=True)
        for stale in ("id_operator", "id_operator.pub", "id_other", "id_other.pub"):
            (work / stale).unlink(missing_ok=True)       # throwaway keys; ssh-keygen will not overwrite
        ck.sm.Matrix.__init__(self, target, work)
        self.limited, self.highwater, self.steps, self.first = set(), [], 0, {}

    # -- host side ---------------------------------------------------------------

    @staticmethod
    def host_builtins():
        res = subprocess.run(["clang-18", "-print-resource-dir"], capture_output=True, text=True, check=True,
                             timeout=HOST_TIMEOUT).stdout.strip()
        path = pathlib.Path(res) / "lib" / "linux" / BUILTINS
        cm.sm.require(path.is_file(), f"no {path} (absd-cc's builtins archive)")
        return path

    def twin(self, name):
        return self.llvm / "twin" / "bin" / name

    def pin_path(self, case):
        return self.expected_dir / f"{case.name}.txt"

    def run_twin_start(self, case):
        """(status, stdout, stderr) of the twin program for a start row,
        argv[0] the guest path, an empty environment, a fresh empty cwd."""
        cwd = self.work / "twin-run" / case.name
        if cwd.exists():
            shutil.rmtree(cwd)
        cwd.mkdir(parents=True)
        r = subprocess.run(case.argv, executable=str(self.twin(TWIN[case.argv[0]])), cwd=cwd, env={},
                           capture_output=True, timeout=HOST_TIMEOUT)
        return r.returncode, r.stdout, r.stderr

    def linux_hello(self, case):
        """The split row's Linux reference: the twin front end compiles SRC
        for x86_64-linux-gnu at -O0, the host's cc links it; run twice."""
        d = self.work / "linux"
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        src = case.argv[0]
        shutil.copy(self.inputs / src, d / src)
        r = subprocess.run([str(self.twin("clang-18")), "--target=x86_64-linux-gnu", "-O0", "-c", src, "-o", "hello.o"],
                           cwd=d, capture_output=True, timeout=HOST_TIMEOUT)
        self.check("the twin front end compiles the Linux reference", r.returncode == 0, f"{r.returncode} {r.stderr!r}")
        r = subprocess.run(["cc", "hello.o", "-o", "hello"], cwd=d, capture_output=True, timeout=HOST_TIMEOUT)
        self.check("the host cc links the Linux reference", r.returncode == 0, f"{r.returncode} {r.stderr!r}")
        runs = []
        for _ in range(2):
            run = d / "run"
            if run.exists():
                shutil.rmtree(run)
            run.mkdir()
            r = subprocess.run(["./a.out"], executable=str(d / "hello"), cwd=run, env={}, capture_output=True,
                               preexec_fn=ck.ignore_sigpipe, timeout=HOST_TIMEOUT)
            runs.append((r.returncode, r.stdout, r.stderr))
        self.check("two Linux reference runs are equal", runs[0] == runs[1], repr(runs))
        return runs[0], sha((d / "hello.o").read_bytes())

    def rsp_from_driver(self, case):
        """The cc1 arguments the twin driver prints for absd-cc's flags over
        SHARE, one per line, less `-o <out>`."""
        d = self.work / "driver"
        d.mkdir(parents=True, exist_ok=True)
        src = case.argv[0]
        shutil.copy(self.inputs / src, d / src)          # the driver checks that the input exists
        r = subprocess.run([str(self.twin("clang-18")), "-resource-dir", RESOURCE, *KIT_CFLAGS,
                            f"-ffile-compilation-dir={CASES_DIR}", "-O0", "-c", src, "-o", "hello.bc", "-emit-llvm",
                            "-###"], cwd=d, capture_output=True, text=True, timeout=HOST_TIMEOUT)
        import shlex
        lines = [shlex.split(l) for l in r.stderr.splitlines() if " \"-cc1\" " in l]
        self.check("the twin driver prints one cc1 command", len(lines) == 1, r.stderr[-500:])
        args = lines[0][2:]
        i = args.index("-o")
        cm.sm.require(args[i + 1] == "hello.bc", f"driver -o {args[i + 1]!r}")
        return args[:i] + args[i + 2:]

    def mirror(self):
        """The image's share tree and case inputs at <work>/mirror/<path>."""
        root = self.work / "mirror"
        if root.exists():
            shutil.rmtree(root)
        for path, data in self.share + self.case_inputs:
            p = root / path.lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        return root

    def twin_split(self, case):
        """The split pipeline on the host with the twin's programs over the
        mirror: the same arguments, SHARE replaced by the mirror's path."""
        root = self.mirror()
        share = root / SHARE.lstrip("/")
        cases = root / CASES_DIR.lstrip("/")
        src, rsp = case.argv
        text = (cases / rsp).read_text().replace(SHARE, str(share))
        (cases / f"{rsp}.mirror").write_text(text)
        out = root / "tmp" / "session-twin"
        out.mkdir(parents=True)
        steps = [(cases, [str(self.twin("cc1-fe")), f"@{rsp}.mirror", "-o", str(out / "hello.bc")]),
                 (out, [str(self.twin("llc")), *LLC_OPTIONS, "hello.bc", "-o", "hello.o"]),
                 (out, [str(self.twin("lld")), *[w.replace(SHARE, str(share)) for w in LINK]])]
        for cwd, argv in steps:
            r = subprocess.run(argv, cwd=cwd, env={}, capture_output=True, timeout=HOST_TIMEOUT)
            self.check(f"twin {pathlib.Path(argv[0]).name} over the mirror", r.returncode == 0,
                       f"{r.returncode} {r.stdout[-300:]!r} {r.stderr[-500:]!r}")
        got = {kind: (out / n).read_bytes() for n, kind in ARTIFACTS}
        ok, reason, loads = gate.check(got["elf"])
        self.check("the kernel-exact gate accepts the twin's ELF", ok, reason)
        r = subprocess.run([sys.executable, "-I", str(here / "check-c-elf.py"), str(out / "a.out"), "--map",
                            str(out / "a.out.map")], capture_output=True, text=True, timeout=HOST_TIMEOUT)
        self.check("the kit gate accepts the twin's ELF", r.returncode == 0, r.stdout + r.stderr)
        return {k: sha(v) for k, v in got.items() if k != "map"}, share

    def host_side(self, write_pins=False):
        for name in IMAGES:
            data = self.images[name]
            print(f"CLANG HOST IMAGE {name} bytes={len(data)} sha256={sha(data)} under_cap_by={MAX_IMAGE - len(data)} "
                  f":: kit/bin/{name}.stripped, bound to kit/BUILT-FROM", flush=True)
        print(f"CLANG HOST SHARE files={len(self.share)} bytes={sum(len(d) for _, d in self.share)} builtins="
              f"{self.builtins_path} sha256={sha(self.builtins_path.read_bytes())}", flush=True)
        stale = []
        for case in self.every:
            if case.kind == "start":
                got = self.run_twin_start(case)
                twin = self.twin(TWIN[case.argv[0]])
                note = f"twin {twin.name} sha256={sha(twin.read_bytes())}"
            else:
                got, obj = self.linux_hello(case)
                note = f"twin clang-18 -c (x86_64-linux-gnu) object sha256={obj} + host cc"
                rsp = (self.inputs / case.argv[1]).read_text().splitlines()
                derived = self.rsp_from_driver(case)
                self.check(f"{case.argv[1]} equals the twin driver's cc1 arguments (less -o)", rsp == derived,
                           first_divergent_line("\n".join(derived).encode(), "\n".join(rsp).encode()) or "")
                print(f"CLANG HOST RSP {case.argv[1]} args={len(rsp)} :: equal to the twin driver's -### for absd-cc's "
                      f"flags over {SHARE}, -ffile-compilation-dir={CASES_DIR}", flush=True)
                self.twin_digests, self.mirror_share = self.twin_split(case)
                print(f"CLANG HOST TWIN SPLIT bc={self.twin_digests['bc']} o={self.twin_digests['o']} "
                      f"elf={self.twin_digests['elf']} :: twin cc1-fe -> llc -> lld over the mirror; check-abi-elf "
                      f"and check-c-elf --map accept the ELF", flush=True)
            pin = self.pin_path(case)
            text = ck.pin_bytes(*got)
            if write_pins:
                self.expected_dir.mkdir(exist_ok=True)
                pin.write_bytes(text)
                print(f"CLANG HOST PIN WRITTEN {pin} :: review it before committing", flush=True)
            elif not pin.is_file() or pin.read_bytes() != text:
                stale.append(case.name)
                print(f"CLANG HOST PIN STALE {case.name} :: "
                      f"{first_divergent_line(pin.read_bytes() if pin.is_file() else b'', text)}", flush=True)
                continue
            print(f"CLANG HOST PIN {case.name} status={got[0]} stdout_bytes={len(got[1])} stderr_bytes={len(got[2])} "
                  f"pin_sha256={sha(text)} :: {note}", flush=True)
        cm.sm.require(not stale, f"pins differ from the twin: {stale} (--host-only --write-pins, then review)")

    # -- the import ----------------------------------------------------------------

    def installed(self):
        return self.t.installed((self.op.with_suffix(".pub")).read_text())

    def fixture_line(self):
        files = self.installed()
        payload = payload_bytes(files)
        capacity = fs_capacity(IMAGE_BYTES)
        boots = len(em.import_plan(files))
        smallest = smallest_fixture(files)
        line = (f"CLANG GUEST FIXTURE image_bytes={IMAGE_BYTES} fs_capacity={capacity} payload={payload} "
                f"headroom={FS_HEADROOM} files={len(files)} import_boots={boots} smallest={smallest}")
        return line, payload + FS_HEADROOM <= capacity

    # -- the census rules ------------------------------------------------------------

    def allowed(self, case):
        return {f"{OUT_DIR}/{case.name}.{kind}" for _, kind in ARTIFACTS} if case.kind == "split" else set()

    def repeatable(self, name):
        # Each case can run again by itself: a split case rewrites its own
        # OUT_DIR files with the same bytes; a start case writes nothing.
        return any(c.name == name for c in self.cases)

    def capacity(self):
        return SERVED.findall(self.t.output())

    def capacity_after(self, n):
        deadline = time.monotonic() + CAPACITY_TIMEOUT
        while time.monotonic() < deadline:
            lines = self.capacity()
            if len(lines) > n:
                return lines[n]
            time.sleep(0.5)
        return None

    @staticmethod
    def capacity_text(line):
        if line is None:
            return "absent"
        reclaimed, processes, handles, pipes, cells, frames, heap = line
        return (f"frames={frames} heap_pages_peak={heap} processes={processes} handles={handles} pipes={pipes} "
                f"cells={cells} accepted_reclaimed={reclaimed}")

    # -- a case ----------------------------------------------------------------------

    def exits(self, step):
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

    def open_held(self):
        return Held(self)

    def tool(self, h, case, name, argv, timeout=SPAWN_TIMEOUT):
        """One program step: the shell's only child for the step, its USER
        EXIT status the shell's; a non-zero status ends the case."""
        s = h.step(command(argv), timeout)
        exits = self.exits(s)
        print(f"CLANG GUEST STEP {case.name} {name} status={s.status} seconds={s.seconds:.1f} "
              f"children={','.join(s.children) or 'none'} kernel={';'.join(e for _, e in exits) or 'none'} "
              f"stdout_bytes={len(s.out)} stderr_bytes={len(s.err)}", flush=True)
        if len(s.children) != 1:
            first = (s.err.decode(errors="replace").splitlines() or [""])[0]
            raise CaseFailed(f"step={name} not spawned (children={s.children}) status={s.status} stderr: {first!r}")
        if exits[0][1] not in (f"EXIT status={s.status}",) and not (exits[0][1].startswith("FAULT") and s.status == 128):
            raise CaseFailed(f"step={name} the kernel's account {exits} does not match the shell's status {s.status}")
        return s

    def builtin(self, h, line):
        s = h.step(line)
        return s.status == 0 and s.out == b"" and s.err == b"" and not s.children

    def find_session(self, h):
        """cd to the session's scratch directory without spawning anything:
        the predicted number first, then the others up to it plus 8."""
        tried = []
        for n in [h.session] + [k for k in range(1, h.session + 9) if k != h.session]:
            tried.append(n)
            if self.builtin(h, f"cd /tmp/session-{n}"):
                return n, tried
        raise CaseFailed(f"no /tmp/session-<n> reachable by cd (tried {tried})")

    def run_start(self, case):
        """(status, stdout, stderr, seconds, kernel) of the start row's command, the session's first."""
        h = self.open_held()
        try:
            s = self.tool(h, case, pathlib.Path(case.argv[0]).name, case.argv)
            exits = self.exits(s)
        except CaseFailed:
            self.finish(h)
            raise
        except BaseException:
            h.kill()
            raise
        h.close()
        return (s.status, s.out, s.err), s.seconds, exits

    def run_split(self, case):
        """The split pipeline in one held session; returns what it saw."""
        src, rsp = case.argv
        h = self.open_held()
        seen = {"steps": {}}
        try:
            n, tried = self.find_session(h)
            seen["session"], seen["tried"] = n, tried
            if not self.builtin(h, f"cd {CASES_DIR}"):
                raise CaseFailed(f"cd {CASES_DIR} failed")
            scratch = f"/tmp/session-{n}"
            seen["steps"]["cc1-fe-o0"] = self.tool(h, case, "cc1-fe-o0",
                                                   ["/bin/cc1-fe-o0", f"@{rsp}", "-o", f"{scratch}/hello.bc"])
            if seen["steps"]["cc1-fe-o0"].status != 0:
                raise CaseFailed(self.step_failure("cc1-fe-o0", seen["steps"]["cc1-fe-o0"]))
            if not self.builtin(h, f"cd {scratch}"):
                raise CaseFailed(f"cd {scratch} failed after the front end")
            s = h.step('"/bin/ls" /tmp')
            if not (s.status == 0 and s.err == b"" and re.fullmatch(rb"session-(\d+)/?\n", s.out)
                    and int(re.fullmatch(rb"session-(\d+)/?\n", s.out).group(1)) == n):
                raise CaseFailed(f"`ls /tmp` printed {s.out!r} (status {s.status}), want exactly session-{n}/")
            for name, argv in (("llc", ["/bin/llc", *LLC_OPTIONS, "hello.bc", "-o", "hello.o"]),
                               ("lld", ["/bin/lld", *LINK])):
                s = seen["steps"][name] = self.tool(h, case, name, argv)
                if s.status != 0:
                    raise CaseFailed(self.step_failure(name, s))
            names = [a for a, _ in ARTIFACTS]
            s = self.tool(h, case, "sha256sum", ["/bin/sha256sum", *names], STEP_TIMEOUT)
            if s.status != 0:
                raise CaseFailed(self.step_failure("sha256sum", s))
            seen["digests"] = parse_digests(s.out, names)
            for a, kind in ARTIFACTS:
                s = self.tool(h, case, f"cp-{kind}", ["/bin/cp", a, f"{OUT_DIR}/{case.name}.{kind}"], STEP_TIMEOUT)
                if (s.status, s.out, s.err) != (0, b"", b""):
                    raise CaseFailed(self.step_failure(f"cp-{kind}", s))
            s = h.step("./a.out", RUN_TIMEOUT)
            seen["run"], seen["run_exit"] = s, self.exits(s)
            print(f"CLANG GUEST STEP {case.name} a.out status={s.status} seconds={s.seconds:.1f} "
                  f"children={','.join(s.children) or 'none'} kernel={';'.join(e for _, e in seen['run_exit']) or 'none'}",
                  flush=True)
        except CaseFailed:
            self.finish(h)
            raise
        except BaseException:
            h.kill()
            raise
        h.close()
        return seen

    @staticmethod
    def finish(h):
        """After a case's divergence: end the session at end of input as
        usual (the shell is idle between steps); a session that will not
        end (a step timed out) is killed."""
        try:
            h.close()
        except BaseException:
            h.kill()

    @staticmethod
    def step_failure(name, s):
        lines = (s.err or s.out).decode(errors="replace").splitlines()
        return f"step={name} status={s.status} {lines[0] if lines else '(no output)'!r}"

    def judge_start(self, case, got, seconds, exits):
        pin = self.pin_path(case).read_bytes()
        div = first_divergent_line(pin, ck.pin_bytes(*got))
        if div:
            raise CaseFailed(div)
        image = self.images[pathlib.Path(case.argv[0]).name]
        print(f"CLANG GUEST OK {case.name} status={got[0]} spawn_seconds={seconds:.1f} stdout_bytes={len(got[1])} "
              f"kernel={exits[0][1]} :: {case.argv[0]} ({len(image)} B, sha256 {sha(image)}) started as the shell's "
              f"first child and printed the twin's text exactly", flush=True)
        return got, seconds

    def judge_split(self, case, seen):
        r = seen["run"]
        tree = self.t.tree()
        copies = {}
        for a, kind in ARTIFACTS:
            data = tree.get(self.t.physical(f"{OUT_DIR}/{case.name}.{kind}"))
            if data is None or sha(data) != seen["digests"][a]:
                raise CaseFailed(f"copy {OUT_DIR}/{case.name}.{kind}: host reader "
                                 f"{None if data is None else sha(data)} session {seen['digests'][a]}")
            copies[kind] = data
        out = self.work / "absd-out"
        out.mkdir(exist_ok=True)
        for kind, data in copies.items():
            (out / f"{case.name}.{kind}").write_bytes(data)
        ok, reason, loads = gate.check(copies["elf"])
        print(f"CLANG GUEST GATE {case.name} {'ACCEPTS loads=' + str(loads) if ok else 'REFUSES ' + reason} :: "
              f"scripts/check-abi-elf.py on the host reader's copy", flush=True)
        if not ok:
            raise CaseFailed(f"check-abi-elf refuses the guest-made ELF: {reason}")
        mapped = out / f"{case.name}.map.host"
        mapped.write_text(rewrite_map(copies["map"].decode(errors="replace"), self.mirror_share))
        c = subprocess.run([sys.executable, "-I", str(here / "check-c-elf.py"), str(out / f"{case.name}.elf"), "--map",
                            str(mapped)], capture_output=True, text=True, timeout=HOST_TIMEOUT)
        print(f"CLANG GUEST KIT GATE {case.name} {(c.stdout + c.stderr).strip()}", flush=True)
        if c.returncode != 0:
            raise CaseFailed(f"check-c-elf refuses the guest-made ELF: {(c.stdout + c.stderr).strip()}")
        if len(r.children) != 1:
            raise CaseFailed(f"a.out not spawned: status {r.status} stderr {r.err[:200]!r}")
        if seen["run_exit"][0][1] != f"EXIT status={r.status}":
            raise CaseFailed(f"a.out: the kernel's account {seen['run_exit']} does not match the shell's status {r.status}")
        got = (r.status, r.out, r.err)
        div = first_divergent_line(self.pin_path(case).read_bytes(), ck.pin_bytes(*got))
        if div:
            raise CaseFailed(f"a.out output {div}")
        same = ",".join(f"{k}:{'yes' if sha(copies[k]) == self.twin_digests[k] else 'no'}" for k in ("bc", "o", "elf"))
        st = seen["steps"]
        print(f"CLANG GUEST OK {case.name} run=equal fe_seconds={st['cc1-fe-o0'].seconds:.1f} "
              f"llc_seconds={st['llc'].seconds:.1f} lld_seconds={st['lld'].seconds:.1f} run_seconds={r.seconds:.1f} "
              f"bc_sha256={sha(copies['bc'])} o_sha256={sha(copies['o'])} elf_sha256={sha(copies['elf'])} "
              f"elf_bytes={len(copies['elf'])} gate=ACCEPTS loads={loads} kit_gate=OK identical_to_twin={same} :: "
              f"/tmp/session-{seen['session']} (cd tried {seen['tried']}; ls /tmp); the a.out the guest's lld wrote, "
              f"spawned by the shell, printed the Linux twin's output exactly", flush=True)
        return (got, {k: sha(v) for k, v in copies.items()}), st["cc1-fe-o0"].seconds

    def run_case(self, case):
        """(verdict, signature for the repeat round)."""
        try:
            if case.kind == "start":
                got, seconds, exits = self.run_start(case)
                return "ok", self.judge_start(case, got, seconds, exits)[0]
            seen = self.run_split(case)
            return "ok", self.judge_split(case, seen)[0]
        except (CaseFailed, Refused) as e:
            print(f"CLANG GUEST FAILED {case.name} {e}", flush=True)
            return "failed", None

    # -- the run ---------------------------------------------------------------------

    def repeat(self):
        names = list(dict.fromkeys(self.highwater))
        start = self.stable("repeat", "before")
        for round_no in range(1, REPEAT_ROUNDS + 1):
            for name in names:
                case = next(c for c in self.cases if c.name == name)
                verdict, signature = self.run_case(case)
                self.check(f"repeat {round_no} {name}: the same outputs as the first run",
                           verdict == "ok" and signature == self.first[name], f"{signature!r} {self.first[name]!r}")
            now = self.stable("repeat", f"after {round_no}")
            self.check(f"repeat round {round_no}: images, frames, kernel objects, the file server's heap peak and object "
                       f"names equal the census before the rounds",
                       (now["images"], now["memory"], now["kernel"], now["fsd"])
                       == (start["images"], start["memory"], start["kernel"], start["fsd"])
                       and {o[0] for o in now["objects"]} == {o[0] for o in start["objects"]},
                       f"before={start['memory']} {start['kernel']} fsd {start['fsd']} after={now['memory']} "
                       f"{now['kernel']} fsd {now['fsd']}")
        print(f"CLANG GUEST RESOURCES REPEAT OK rounds={REPEAT_ROUNDS} repeated={' '.join(names)} :: {start['memory']} "
              f"| {start['kernel']} | fsd_heap_peak={start['fsd']}", flush=True)

    def run(self):
        t = self.t
        started = time.monotonic()
        os.umask(0o022)
        self.host_side()
        cm.ssh_absd.IMAGE_BYTES = IMAGE_BYTES
        cm.ssh_absd.DEVICE_SECTORS = IMAGE_BYTES // 512
        line, fits = self.fixture_line()
        print(line, flush=True)
        self.check("the fixture's filesystem holds the payload and the headroom", fits, line)
        authorized = (self.op.with_suffix(".pub")).read_text()
        t.setup(self.work, authorized)
        print(f"CLANG GUEST IMPORT files={len(self.installed())} boots={t.boots} seconds={time.monotonic() - started:.1f} "
              f"load_max={max(t.launch_loads):.2f} :: every file read back equal by the host reader", flush=True)
        tree = t.tree()
        for name in IMAGES:
            on = tree.get(t.physical(f"/bin/{name}"))
            self.check(f"/bin/{name} on the image is kit/bin/{name}.stripped (host reader)",
                       on is not None and sha(on) == sha(self.images[name]))
        bad = [p for p, d in self.share if tree.get(t.physical(p)) != d]
        self.check("the share tree on the image equals the import list (host reader)", not bad, str(bad[:5]))
        print(f"CLANG GUEST IMPORT OK " + " ".join(f"{n}={sha(self.images[n])}" for n in IMAGES)
              + f" share_files={len(self.share)} share_bytes={sum(len(d) for _, d in self.share)} :: host reader",
              flush=True)
        boot = time.monotonic()
        first = t.start(fresh=True)
        print(f"CLANG GUEST BOOT SECONDS sshd={time.monotonic() - boot:.1f}", flush=True)
        self.client = ck.sm.Client(self.work, t.port)
        self.client.trust(first["public"])
        rc, out, err, _, _ = self.shell_ssh('"/bin/df"')
        m = re.search(r"^absd:[0-9a-f]+ +(\d+) +(\d+) +(\d+) ", out.decode(), re.M)
        self.check("df reports the filesystem's space", rc == 0 and m is not None, f"{rc} {out!r} {err!r}")
        print(f"CLANG GUEST IMAGE capacity={int(m.group(1)) * 1024} used={int(m.group(2)) * 1024} "
              f"available={int(m.group(3)) * 1024} image={IMAGE_BYTES}", flush=True)
        h = Held(self)
        try:
            s = h.step('"/bin/printenv"')
            h.close()
        except BaseException:
            h.kill()
            raise
        self.check("printenv in a held session", s.status == 0 and s.err == b"", f"{s.status} {s.err!r}")
        env = [line.split("=", 1)[0] for line in s.out.decode().splitlines() if "=" in line]
        print(f"CLANG GUEST SESSION ENV count={len(env)} {' '.join(env)} :: getMainExecutable has no PATH; every LLVM "
              f"program is started by absolute path, cc1 with -resource-dir {RESOURCE}", flush=True)
        if not self.is_dir(OUT_DIR):
            rc, out, err, _, _ = self.shell_ssh(f'"/bin/mkdir" {quote(OUT_DIR)}')
            self.check(f"mkdir {OUT_DIR}", rc == 0 and out == b"" and err == b"" and self.is_dir(OUT_DIR),
                       f"rc={rc} {out!r} {err!r}")
            print(f"CLANG GUEST DIR MADE {OUT_DIR}", flush=True)
        failed, ok, spawn = [], 0, []
        for case in self.cases:
            before = self.stable(case.name, "before")
            n = len(self.capacity())
            cap_before = self.capacity()[-1] if n else None
            took = time.monotonic()
            verdict, signature = self.run_case(case)
            took = time.monotonic() - took
            cap_after = self.capacity_after(n)
            print(f"CLANG GUEST CAPACITY {case.name} before {self.capacity_text(cap_before)} after "
                  f"{self.capacity_text(cap_after)} :: sshd's quiescent SERVED CAPACITY lines around the case's session",
                  flush=True)
            after = self.stable(case.name, "after")
            memory, kernel = self.compare_census(case, before, after)
            print(f"CLANG GUEST RESOURCES {case.name} :: {memory} | {kernel} | images={self.judged['images']} "
                  f"objects={len(self.judged['objects'])} seconds={took:.1f}", flush=True)
            if verdict == "ok":
                ok += 1
                self.first[case.name] = signature
            else:
                failed.append(case.name)
            if cap_before is None or cap_after is None:
                self.capacity_absent = True
        if self.highwater and not failed:
            self.repeat()
        self.alive("the clang cases")
        t.stop()
        partial = [f"only={','.join(c.name for c in self.cases)}"] if self.only else []
        partial += ["capacity=absent"] if getattr(self, "capacity_absent", False) else []
        summary = f"cases={len(self.cases)} ok={ok} failed={len(failed)} import_boots={t.boots - 1}"
        self.rest_recorded()          # census ruling (b): any lowered rest count (not a failure)
        if failed:
            print(f"ABSD CLANG GUEST FAILED {summary} :: {','.join(failed)}", flush=True)
            return False
        print(f"ABSD CLANG GUEST {'PARTIAL' if partial else 'OK'} {summary}"
              f"{' :: ' + ' '.join(partial) + ' (not a full run)' if partial else ''}", flush=True)
        print(f"CLANG GUEST MATRIX OK seconds={time.monotonic() - started:.0f}", flush=True)
        return True


def list_mode(matrix):
    """The cases, the import list with digests, the fixture: no QEMU."""
    for c in matrix.cases:
        print(f"CLANG LIST CASE {c.name} {c.kind} {' '.join(c.argv)}")
    for path, data in matrix.t.case_files:
        print(f"CLANG LIST FILE {path} bytes={len(data)} sha256={sha(data)}")
    line, fits = matrix.fixture_line()
    base = [f for f in matrix.installed() if f[0] not in {matrix.t.physical(p) for p, _ in matrix.t.case_files}]
    print(f"CLANG LIST BASE files={len(base)} bytes={sum(len(d) for _, d in base)} :: ssh_absd's deployment, "
          f"cports-matrix.EXTRA, the release record, from {matrix.t.root}")
    print(line + f" fits={'yes' if fits else 'NO'}")
    return fits


def main():
    ap = argparse.ArgumentParser()
    for name in ("work", "llvm-build", "kit", "cases"):
        ap.add_argument(f"--{name}", required=True)
    ap.add_argument("--only", action="append", help="run only this case (repeatable; not a full run)")
    ap.add_argument("--list", action="store_true", help="print cases, import list and fixture; no QEMU")
    ap.add_argument("--host-only", action="store_true", help="the host side only (twin pins, mirror pipeline)")
    ap.add_argument("--write-pins", action="store_true", help="with --host-only: write guest-expected/ from the twin")
    argv = sys.argv[1:]
    print("CLANG GUEST ARGS " + " ".join(sys.argv), flush=True)
    rest = []
    if "--" in argv:
        i = argv.index("--")
        argv, rest = argv[:i], argv[i + 1:]
    args = ap.parse_args(argv)
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    if args.list or args.host_only:
        # No boot: a target that holds only the platform tree and the shell.
        lp = argparse.ArgumentParser()
        lp.add_argument("--platform", required=True)
        lp.add_argument("--shell", required=True)
        known, _ = lp.parse_known_args(rest)
        target = ClangTarget.__new__(ClangTarget)
        target.root = pathlib.Path(known.platform).resolve()
        target.shell = pathlib.Path(known.shell).resolve()
    else:
        base = ssh_absd.target(rest)
        target = ClangTarget.__new__(ClangTarget)
        target.__dict__.update(base.__dict__)
    matrix = ClangMatrix(target, work, args)
    if args.list:
        sys.exit(0 if list_mode(matrix) else 1)
    if args.host_only:
        try:
            matrix.host_side(write_pins=args.write_pins)
        except (cm.sm.Failed, ck.sm.Failed, Refused) as e:
            print(f"CLANG HOST FAILED: {e}", flush=True)
            sys.exit(1)
        print("CLANG HOST OK :: twin pins, response file and the mirror pipeline", flush=True)
        sys.exit(0)
    try:
        ok = matrix.run()
    except (cm.sm.Failed, ck.sm.Failed, ssh_absd.Failed, Refused, CaseFailed) as e:
        print(f"ABSD CLANG GUEST FAILED: {e}", flush=True)
        target.stop()
        sys.exit(1)
    except BaseException:
        target.stop()
        raise
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
