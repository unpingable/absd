#!/usr/bin/env python3
"""Host-only checks of scripts/clang-guest-matrix.py (no QEMU), after the
tcc lane's scripts/tcc-matrix-selftest.py.

1. Steps of a held absd-sh session: split_step cuts a command's stdout,
   status and stderr out of the streams by the step's marks and refuses a
   stream without the status line; first_divergent_line names the first
   differing line (a missing final newline included); parse_pin,
   parse_digests and rewrite_map; command() quotes every word.
2. The case table: the committed rows load; a start row whose program is
   not one of the three images, a split row without its two files and a
   duplicate are refused.
3. The fixture: fs_capacity grows with the image, smallest_fixture is the
   first 64 MiB multiple that holds payload + headroom, and IMAGE_BYTES
   holds the committed import list (the platform tree given).
4. The host side for real: the twin pins equal the committed pins, the
   response file equals the twin driver's, the twin's split pipeline over
   the host mirror passes both gates.
5. A dry run of every case through a fake transport (FakeHeld: an absd-sh
   that answers builtins, spawns from a scripted table, writes the twin's
   artifacts into a fake image, and prints the kernel's SPAWN OK / USER
   EXIT lines): run_case prints `CLANG GUEST OK` for each committed case;
   and `CLANG GUEST FAILED <case> <first divergent line>` for a version
   text that differs, a front end that fails, a wrong session number
   (recovered by cd's search) and a wrong `ls /tmp`, a copy whose bytes
   differ from the session's digest, an a.out the kernel-exact gate
   refuses, and an a.out whose output differs. The front end must be the
   session's first spawn.

Usage: clang-guest-selftest.py --work <empty dir> --llvm-build <dir> --kit <dir>
       --platform <built platform tree>
Prints CLANG SELFTEST OK checks=<n> on success."""
import argparse, contextlib, importlib.util, io, pathlib, re, shlex, sys

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
spec = importlib.util.spec_from_file_location("clang_guest_matrix", here / "clang-guest-matrix.py")
gm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gm)

checks = 0
TABLE = here.parent / "cxx" / "tests" / "llvm" / "guest-cases.tsv"


def check(name, ok, detail=""):
    global checks
    checks += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{(': ' + detail) if detail and not ok else ''}", flush=True)
    if not ok:
        print(f"CLANG SELFTEST FAILED: {name}", flush=True)
        sys.exit(1)


def raises(fn, kind=gm.Refused):
    try:
        fn()
    except kind:
        return True
    return False


def helpers():
    P = gm.PROMPT
    before_out = P + P + b"0\n" + P + P + b"clang-mark-1\n"
    before_err = gm.exit_mark("clang-mark-1")
    out = before_out + P + b"LLD 18.1.8 (compatible with GNU linkers)\n" + P + b"0\n" + P + P + b"clang-mark-2\n" + P
    err = before_err + gm.exit_mark("clang-mark-2")
    got = gm.split_step(out, len(before_out), err, len(before_err), "clang-mark-2")
    check("split_step: the command's stdout, status and stderr",
          got is not None and got[:3] == (b"LLD 18.1.8 (compatible with GNU linkers)\n", 0, b""), repr(got))
    check("split_step: positions after the step", got[3] == len(out) - len(P) and got[4] == len(err), repr(got[3:]))
    check("split_step: incomplete while the mark is missing",
          gm.split_step(out[:-25], len(before_out), err, len(before_err), "clang-mark-2") is None)
    check("split_step: the stderr mark is required too",
          gm.split_step(out, len(before_out), err[:-5], len(before_err), "clang-mark-2") is None)
    check("split_step: a stream without the status line is refused",
          raises(lambda: gm.split_step(P + b"x" + P + P + b"clang-mark-1\n", 0, gm.exit_mark("clang-mark-1"), 0,
                                       "clang-mark-1")))
    check("first_divergent_line: equal is None", gm.first_divergent_line(b"a\nb\n", b"a\nb\n") is None)
    check("first_divergent_line: the first differing line",
          gm.first_divergent_line(b"a\nb\nc\n", b"a\nX\nc\n") == "line 2: got b'X\\n' want b'b\\n'",
          gm.first_divergent_line(b"a\nb\nc\n", b"a\nX\nc\n"))
    check("first_divergent_line: a missing final newline differs",
          gm.first_divergent_line(b"hello\n", b"hello") == "line 1: got b'hello' want b'hello\\n'")
    check("first_divergent_line: a missing line is None on one side",
          gm.first_divergent_line(b"a\n", b"a\nb\n") == "line 2: got b'b\\n' want None")
    check("parse_pin: the pin form", gm.parse_pin(b"hello\n--\n--\nstatus=0\n") == (0, b"hello\n", b""))
    check("parse_pin: not a pin", gm.parse_pin(b"hello\nstatus=0\n") is None)
    d = "a" * 64
    check("parse_digests: one line per name in order",
          gm.parse_digests(f"{d}  x\n{d}  y\n".encode(), ["x", "y"]) == {"x": d, "y": d})
    check("parse_digests: a missing or reordered name is refused",
          raises(lambda: gm.parse_digests(f"{d}  y\n{d}  x\n".encode(), ["x", "y"]))
          and raises(lambda: gm.parse_digests(f"{d}  x\n".encode(), ["x", "y"])))
    check("rewrite_map: the share root becomes the mirror's",
          gm.rewrite_map(f"  {gm.SHARE}/lib/libc.a(x.o):(.text)\n", "/m/share") == "  /m/share/lib/libc.a(x.o):(.text)\n")
    check("command: every word quoted", gm.command(["/bin/llc", "-O0", "a b"]) == '"/bin/llc" "-O0" "a b"')
    check("resource headers: freestanding only",
          gm.resource_header("stddef.h") and gm.resource_header("__stddef_size_t.h")
          and not gm.resource_header("immintrin.h") and not gm.resource_header("arm_neon.h"))
    check("the link has at most 32 words (broker MAX_ARGC)", len(gm.LINK) + 1 <= 32, str(len(gm.LINK)))
    check("llc's words fit too", len(gm.LLC_OPTIONS) + 4 <= 32)


def table(work):
    cases = gm.load_cases(TABLE)
    check("the committed table: cl1-lld, cl1-cc1fe, cl2-split",
          [(c.name, c.kind) for c in cases] == [("cl1-lld", "start"), ("cl1-cc1fe", "start"), ("cl2-split", "split")])
    for text, why in (("x\tstart\t/bin/clang\t--version\n", "a start row for no imported image"),
                      ("x\tsplit\thello.c\n", "a split row without its response file"),
                      ("x\tstart\t/bin/lld\t-v\nx\tstart\t/bin/lld\t-v\n", "a duplicate row")):
        p = work / "bad.tsv"
        p.write_text(text)
        check(f"load_cases refuses {why}", raises(lambda: gm.load_cases(p)))


def fixture(m):
    check("fs_capacity grows with the image", gm.fs_capacity(128 << 20) < gm.fs_capacity(192 << 20) < gm.fs_capacity(256 << 20))
    files = [("/x", b"\0" * (100 << 20))]
    small = gm.smallest_fixture(files)
    check("smallest_fixture: the first 64 MiB multiple holding payload + headroom",
          small % gm.FIXTURE_STEP == 0 and gm.fs_capacity(small) >= (100 << 20) + gm.FS_HEADROOM
          and gm.fs_capacity(small - gm.FIXTURE_STEP) < (100 << 20) + gm.FS_HEADROOM, str(small))
    line, fits = m.fixture_line()
    print(line, flush=True)
    check("IMAGE_BYTES holds the committed import list", fits, line)


# -- the fake transport -----------------------------------------------------------

class FakeTarget:
    def __init__(self):
        self.out_text, self.serial_text, self.image = "", "", {}
        self.pid = 100

    def output(self):
        return self.out_text

    def serial(self):
        return self.serial_text

    def tree(self):
        return dict(self.image)

    @staticmethod
    def physical(path):
        return path


class FakeHeld:
    """absd-sh as far as the matrix sees it: builtins, scripted spawns."""

    def __init__(self, m, fault=None, session=7, predicted=7):
        self.m, self.t, self.fault = m, m.t, fault
        self.t.pid += 1
        self.shell = str(self.t.pid)
        self.t.out_text += f"SSH SESSION CHILD pid={self.shell} spawn_right=true argv0=/bin/absd-sh x control=true\n"
        self.session, self.real = predicted, session
        self.cwd, self.files, self.spawns = "/", {}, []
        tw = m.twin_bytes
        self.made = {"hello.bc": tw["bc"], "hello.o": tw["o"], "a.out": tw["elf"], "a.out.map": tw["map"]}

    def spawn(self, prog, status):
        self.t.pid += 1
        self.spawns.append(prog)
        self.t.serial_text += (f"SPAWN OK pid={self.t.pid} parent={self.shell} program=image\n"
                               f"USER EXIT pid={self.t.pid} status={status}\n")
        return [str(self.t.pid)]

    def step(self, line, timeout=0):
        words = shlex.split(line)
        prog, args = words[0], words[1:]
        out, err, status, children = b"", b"", 0, []
        if prog == "cd":
            ok = args[0] in ("/", gm.CASES_DIR, f"/tmp/session-{self.real}")
            status, err = (0, b"") if ok else (1, f"absd-sh: cd: {args[0]}: not found\n".encode())
            if ok:
                self.cwd = args[0]
        elif prog == "/bin/lld" and "--version" in args:
            text = b"LLD 18.1.8 (compatible with GNU linkers)\n"
            out = text.replace(b"18.1.8", b"18.1.9") if self.fault == "version" else text
            children = self.spawn(prog, 0)
        elif prog == "/bin/cc1-fe-o0" and "-version" in args:
            out = b"LLVM (http://llvm.org/):\n  LLVM version 18.1.8\n  Optimized build.\n"
            children = self.spawn(prog, 0)
        elif prog == "/bin/cc1-fe-o0":
            if self.fault == "fe":
                status, err = 1, b"error: unable to open output file\n"
            else:
                self.files["hello.bc"] = self.made["hello.bc"]
            children = self.spawn(prog, status)
        elif prog == "/bin/ls":
            n = self.real + 1 if self.fault == "ls" else self.real
            out, children = f"session-{n}/\n".encode(), self.spawn(prog, 0)
        elif prog in ("/bin/llc", "/bin/lld"):
            for name in (("hello.o",) if prog == "/bin/llc" else ("a.out", "a.out.map")):
                self.files[name] = self.made[name]
            if self.fault == "gate" and prog == "/bin/lld":
                elf = bytearray(self.files["a.out"]); elf[0] = 0; self.files["a.out"] = bytes(elf)
            children = self.spawn(prog, 0)
        elif prog == "/bin/sha256sum":
            out = b"".join(f"{gm.sha(self.files[a])}  {a}\n".encode() for a in args)
            children = self.spawn(prog, 0)
        elif prog == "/bin/cp":
            data = self.files[args[0]]
            if self.fault == "copy" and args[0] == "hello.o":
                data = data + b"\0"
            self.t.image[args[1]] = data
            children = self.spawn(prog, 0)
        elif prog == "./a.out":
            out = b"hullo\n" if self.fault == "run" else b"hello\n"
            children = self.spawn(prog, 0)
        else:
            raise AssertionError(f"FakeHeld: unexpected line {line!r}")
        return gm.Step(line, out, status, err, 0.1, children, "")

    def close(self):
        pass

    def kill(self):
        pass


class DryMatrix(gm.ClangMatrix):
    fault, session, predicted, held = None, 7, 7, None

    def open_held(self):
        self.held = FakeHeld(self, self.fault, self.session, self.predicted)
        return self.held


def run(m, case, **kw):
    for k, v in kw.items():
        setattr(m, k, v)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        verdict, _ = m.run_case(case)
    for k in kw:
        delattr(m, k)
    return verdict, buf.getvalue()


def dry(work, args):
    target = gm.ClangTarget.__new__(gm.ClangTarget)
    target.root = pathlib.Path(args.platform).resolve()
    target.shell = target.root / "commands" / "absd-sh"
    margs = argparse.Namespace(llvm_build=args.llvm_build, kit=args.kit, cases=str(TABLE), only=None)
    m = DryMatrix(target, work / "dry", margs)
    fixture(m)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        m.host_side()
    text = buf.getvalue()
    print("\n".join(l for l in text.splitlines() if l.startswith("CLANG HOST")), flush=True)
    check("host side: twin pins current, response file equal, twin split gated",
          "CLANG HOST TWIN SPLIT" in text and "CLANG HOST RSP" in text and text.count("CLANG HOST PIN ") == 3, text[-500:])
    out = work / "dry" / "mirror" / "tmp" / "session-twin"
    m.twin_bytes = {k: (out / n).read_bytes() for n, k in gm.ARTIFACTS}
    # The guest's map names the guest share tree (the mirror's text, reversed).
    m.twin_bytes["map"] = m.twin_bytes["map"].replace(str(m.mirror_share).encode(), gm.SHARE.encode())
    m.t = FakeTarget()
    cases = {c.name: c for c in m.cases}
    for name in ("cl1-lld", "cl1-cc1fe", "cl2-split"):
        verdict, text = run(m, cases[name])
        print(text.rstrip(), flush=True)
        check(f"dry run {name}: CLANG GUEST OK", verdict == "ok" and f"CLANG GUEST OK {name} " in text, text[-800:])
    check("dry run cl2-split: the front end is the session's first spawn and the twin's bytes match",
          m.held.spawns[0] == "/bin/cc1-fe-o0" and "identical_to_twin=bc:yes,o:yes,elf:yes" in text, str(m.held.spawns))
    verdict, text = run(m, cases["cl2-split"], predicted=5)
    check("dry run: a wrong predicted session is found by cd", verdict == "ok" and "cd tried [5, 1, 2, 3, 4, 6, 7]" in text,
          text[-600:])
    for fault, case, want in (
            ("version", "cl1-lld", "CLANG GUEST FAILED cl1-lld line 1: got b'LLD 18.1.9"),
            ("fe", "cl2-split", "CLANG GUEST FAILED cl2-split step=cc1-fe-o0 status=1 'error: unable to open output file'"),
            ("ls", "cl2-split", "CLANG GUEST FAILED cl2-split `ls /tmp` printed b'session-8/\\n'"),
            ("copy", "cl2-split", "CLANG GUEST FAILED cl2-split copy /home/operator/clang-out/cl2-split.o: host reader"),
            ("gate", "cl2-split", "CLANG GUEST FAILED cl2-split check-abi-elf refuses the guest-made ELF"),
            ("run", "cl2-split", "CLANG GUEST FAILED cl2-split a.out output line 1: got b'hullo\\n' want b'hello\\n'")):
        verdict, text = run(m, cases[case], fault=fault)
        check(f"dry run fault {fault}: {want[:60]}", verdict == "failed" and want in text, text[-600:])
    # The copies the dry run wrote are the twin's bytes again (the last good run's outputs were replaced).
    print(f"CLANG SELFTEST DRY cases={len(m.cases)} faults=6", flush=True)


def main():
    ap = argparse.ArgumentParser()
    for name in ("work", "llvm-build", "kit", "platform"):
        ap.add_argument(f"--{name}", required=True)
    args = ap.parse_args()
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    helpers()
    table(work)
    dry(work, args)
    print(f"CLANG SELFTEST OK checks={checks}", flush=True)


if __name__ == "__main__":
    main()
