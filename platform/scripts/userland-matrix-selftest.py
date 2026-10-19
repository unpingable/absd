#!/usr/bin/env python3
"""Host-only checks of scripts/userland-matrix.py's judging (no QEMU).

A fake guest stands in for the boot, as cports-matrix-selftest.py's fake
target does: an in-memory image (path -> bytes, and directories) that
answers the matrix's sessions (`cp -r`, `rm -r`, `mkdir`, `printenv`, and
each case's utility, which it answers from that case's expected result,
writing the "--- files" section into the case directory and appending
absd-sh's status line for a non-zero status). The matrix's own code runs
unchanged: fresh directory, host-reader formatting, judging, pins, census.

1. FORMAT: every pin in userland/expected/ parses (parse_pin) and
   check-userland's format_result rebuilds it byte for byte from the parsed
   result over FIXTURES: the guest's formatting is the host pins'.
2. AGREE: the honest fake guest over all of cases.tsv: every case run twice,
   agree = cases - divergences, diverge = divergences.tsv rows, no defect,
   no pin written; the summary line is the OK grammar.
3. DIVERGENCE: a divergence row is judged by status, empty stdout and
   stderr: the host pin, a non-empty stdout, another stderr line, another
   status, or a changed file is each a DEFECT.
4. DEFECT: a files-section mismatch (ed-edit writing other bytes), a stdout
   mismatch and a repeat that differs from the first run are DEFECTs; the
   result is written to <pins>/<ID> (and .repeat), DEFECTS names it, the
   summary says DEFECTS and the status is 1. An ed case leaving its scratch
   file, and a find -exec case with another refusal text, are marked
   "candidate disposition D-04"; another defect is not.
5. BINARY: FIXTURES through the importer's stream encoding (exec-matrix.py
   stream) decode to the same bytes (bin.dat included); a fake cp that flips
   one byte of bin.dat fails the fresh-directory check; a files section
   carrying all 256 byte values round-trips.
6. STATUS LINE: a non-zero status without absd-sh's status line fails.
7. GRAMMAR: summary() and od_bytes().
8. DEMO: the demo rehearsal's sessions answered as the guest should; tcc
   NOT_RUN without /bin/tcc, hello.c gone afterwards.

Usage: userland-matrix-selftest.py --work <empty dir>
Prints USERLAND SELFTEST OK checks=<n>."""
import argparse, contextlib, hashlib, importlib.util, io, pathlib, re, struct, sys, tarfile

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
spec = importlib.util.spec_from_file_location("userland_matrix", here / "userland-matrix.py")
um = importlib.util.module_from_spec(spec)
spec.loader.exec_module(um)
spec = importlib.util.spec_from_file_location("exec_matrix", here / "exec-matrix.py")
em = importlib.util.module_from_spec(spec)
spec.loader.exec_module(em)

CHECKS = 0
CENSUS = {"images": 0, "memory": "memory: 1 KiB free, 1 KiB allocated (30000 + 700 frames of 4096 bytes)",
          "kernel": "kernel: 4 process slots, 66 handles, 27 pipes, 1 cells", "objects": [], "fsd": 26}
OK_LINE = re.compile(r"ABSD USERLAND GUEST OK cases=\d+ agree=\d+ diverge=\d+ defects=0 demo=(ok|not_run) "
                     r"notrun=(none|[a-z0-9-]+(,[a-z0-9-]+)*)")


def ok(cond, what):
    global CHECKS
    CHECKS += 1
    if not cond:
        raise SystemExit(f"USERLAND SELFTEST FAILED: {what}")


def unquote(text):
    return [w.replace('\\"', '"').replace("\\\\", "\\") for w in re.findall(r'"((?:[^"\\]|\\.)*)"', text)]


class FakeTarget:
    """The image: files (path -> bytes) and directories."""
    def __init__(self):
        self.files, self.dirs = {}, {um.HOME, um.BASE}
        for name, data in um.FIXTURES.items():
            self.put(f"{um.TEMPLATE}/{name}", data)

    def put(self, path, data):
        self.files[path] = data
        parts = path.split("/")
        for i in range(2, len(parts)):
            self.dirs.add("/".join(parts[:i]))

    def tree(self):
        return dict(self.files)

    def system_objects(self):
        objs = [(p, False, False, 0, hashlib.sha256(d).hexdigest()) for p, d in self.files.items()]
        objs += [(p, True, False, 0, "") for p in self.dirs]
        return sorted(objs)

    def all_images(self):
        return 0

    def census_detail(self):
        return "fake"

    def physical(self, path):
        return "/releases/dev" + path


class FakeGuest:
    """Answers the matrix's sessions; `answers` overrides a case's result
    (bytes, or a function of the run number), `corrupt` flips a byte of
    bin.dat in cp, `no_status_line` drops absd-sh's line."""
    def __init__(self, m, answers=None, corrupt=False, no_status_line=False):
        self.m, self.answers, self.corrupt, self.no_status_line = m, answers or {}, corrupt, no_status_line
        self.runs = {}

    def __call__(self, text, stdin=b"", timeout=None, baseline=0):
        t = self.m.t
        cwd, rest = re.fullmatch(r"cd (\S+); (.*)", text, re.S).groups()
        words = unquote(rest)
        if words == ["printenv"]:
            return 0, b"", b"", "1", ["2"]
        if words[0] == "mkdir":
            for d in words[1:]:
                t.dirs.add(f"{cwd}/{d}")
            return 0, b"", b"", "1", ["2"]
        if words[:2] == ["cp", "-r"]:
            src, dst = f"{cwd}/{words[2]}", f"{cwd}/{words[3]}"
            for p, d in list(t.files.items()):
                if p.startswith(src + "/"):
                    if self.corrupt and p.endswith("/bin.dat"):
                        d = bytes([d[0] ^ 1]) + d[1:]
                    t.put(dst + p[len(src):], d)
            t.dirs |= {dst + p[len(src):] for p in list(t.dirs) if p == src or p.startswith(src + "/")}
            return 0, b"", b"", "1", ["2"]
        if words[:2] == ["rm", "-r"]:
            gone = f"{cwd}/{words[2]}"
            t.files = {p: d for p, d in t.files.items() if not p.startswith(gone + "/")}
            t.dirs = {p for p in t.dirs if p != gone and not p.startswith(gone + "/")}
            return 0, b"", b"", "1", ["2"]
        if cwd == um.HOME:
            return self.demo(words, stdin) + ("1", ["2"])
        match = [c for c in self.m.all_cases if c.util == words[0] and c.args == words[1:]
                 and (b"" if c.stdin == "-" else um.FIXTURES[c.stdin]) == stdin]
        assert len(match) == 1, (words, stdin, [c.name for c in match])
        case = match[0]
        self.runs[case.name] = self.runs.get(case.name, 0) + 1
        answer = self.answers.get(case.name, self.m.want(case)[0])
        if callable(answer):
            answer = answer(self.runs[case.name])
        rc, out, err, files = um.parse_pin(answer)
        if case.result_id == "tar-create" and case.name not in self.answers:
            # The pin contains the contents projection; the guest produces ustar.
            # Use the independent standard writer for this fixed case's inputs.
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name in ("words-short.txt", "tree", "tree/sub", "tree/sub/leaf.txt"):
                    info = tarfile.TarInfo(name)
                    data = t.files.get(f"{cwd}/{name}")
                    info.mode = 0o755 if data is None else 0o644
                    if data is None:
                        info.type = tarfile.DIRTYPE
                    else:
                        info.size = len(data)
                    archive.addfile(info, io.BytesIO(data) if data is not None else None)
            files["made.ustar"] = buf.getvalue()
        for name, data in files.items():
            if data is None:
                t.files.pop(f"{cwd}/{name}", None)
            else:
                t.put(f"{cwd}/{name}", data)
        if rc != 0 and not self.no_status_line:
            err += f"absd-sh: {case.util}: exit status {rc}\n".encode()
        return rc, out, err, "1", ["2"]


    def demo(self, words, stdin):
        """The demo's sessions in /home/operator, as the guest should answer them."""
        t, hello = self.m.t, f"{um.HOME}/hello.c"
        if words == ["ed", "-p", "* "] and stdin == um.DEMO_ED:
            t.put(hello, um.DEMO_LINE)
            return 0, f"* * {len(um.DEMO_LINE)}\n* ".encode(), b""
        if words == ["od", "-t", "x1", "hello.c"]:
            data = t.files[hello]
            return 0, b"0000000 " + " ".join(f"{b:02x}" for b in data).encode() + b"\n%07o\n" % len(data), b""
        if words == ["cmp", "hello.c", "hello.c"]:
            return 0, b"", b""
        if words == ["grep", "-n", "main", "hello.c"]:
            return 0, b"1:" + t.files[hello], b""
        if words == ["find", ".", "-name", "ed.*"]:
            return 0, b"", b""
        if words == ["rm", "hello.c"]:
            del t.files[hello]
            return 0, b"", b""
        if words == ["man", "sbase"]:
            return 0, (um.REPO / "userland" / "sbase.LICENSE").read_text().replace("\u00a9", "(C)").translate(
                str.maketrans({"\u0144": "n", "\u00e9": "e"})).encode(), b""
        if words == ["ls", "/bin"]:
            return 0, "\n".join(["cat", "ls", *um.utils()]).encode() + b"\n", b""
        raise AssertionError(f"the fake guest has no answer for {words}")


def matrix(work, label, only=None, **guest):
    m = um.UserlandMatrix.__new__(um.UserlandMatrix)
    m.pins = work / label / "pins"
    m.load_tables(only)
    m.all_cases = um.load_cases(um.REPO / "userland" / "cases.tsv")
    m.t = FakeTarget()
    m.work = work / label
    m.work.mkdir(parents=True, exist_ok=True)
    m.checks, m.passed = 0, []
    m.steps, m.limited, m.highwater, m.restart_round = 0, set(), [], 1
    m.stable = lambda key, when: CENSUS
    m.census = lambda: CENSUS
    m.shell_ssh = FakeGuest(m, **guest)
    return m


def quiet(fn, *args):
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            return fn(*args), buf.getvalue()
    except BaseException:
        sys.stdout.write(buf.getvalue()[-4000:])
        raise


def run_cases(m):
    quiet(m.make_template)
    return quiet(m.run_cases)


def fails(fn, *args):
    """Whether fn fails as the matrix fails (its output, expected to end in
    a FAIL line, is kept out of the log)."""
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            fn(*args)
    except um.FAILED:
        return True
    return False


def with_files(pin, files):
    rc, out, err, _ = um.parse_pin(pin)
    after = dict(um.FIXTURES)
    for name, data in files.items():
        if data is None:
            after.pop(name, None)
        else:
            after[name] = data
    return um.cu.format_result(rc, out, err, after)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    work = pathlib.Path(ap.parse_args().work).resolve()
    work.mkdir(parents=True, exist_ok=True)

    # 1. FORMAT
    pins = sorted((um.REPO / "userland" / "expected").iterdir())
    with_section = 0
    for pin in pins:
        data = pin.read_bytes()
        rc, out, err, files = um.parse_pin(data)
        ok(with_files(data, files) == data, f"format_result does not rebuild {pin.name}")
        with_section += bool(files)
    ok(with_section >= 2, f"only {with_section} pins carry a files section")
    print(f"USERLAND SELFTEST FORMAT OK pins={len(pins)} with_files={with_section}", flush=True)

    # 2. AGREE
    m = matrix(work, "agree")
    counts, text = run_cases(m)
    n, d = len(m.cases), len(m.divergences)
    ok(counts == {"agree": n - d, "diverge": d, "defect": 0}, f"honest run counted {counts}")
    ok(not m.pins.exists(), "the honest run wrote pins")
    ok(text.count("USERLAND CASE OK ") == n - d and text.count("USERLAND DIVERGES ") == d, "markers")
    ok(all(text.count(f"USERLAND RESOURCES {c.name} ::") == 1 for c in m.cases), "a resources line per case")
    ok(m.shell_ssh.runs == {c.name: 2 for c in m.cases}, "every case runs twice")
    raw = [m.work / "tar-create-raw" / f"{name}.ustar" for name in ("first", "repeat")]
    ok(raw[0].read_bytes() == raw[1].read_bytes(), "both raw tar-create fixtures retained")
    projected = um.parse_pin((um.REPO / "userland/expected/tar-create").read_bytes())[3]["made.ustar"]
    ok(um.cu.tar_create_contents(raw[0].read_bytes()) == projected,
       "independent ustar fixture matches the existing contents pin")
    try:
        um.cu.tar_create_contents(projected)
    except (tarfile.ReadError, ValueError):
        rejected_projection = True
    else:
        rejected_projection = False
    ok(rejected_projection, "projected contents cannot substitute for a raw archive")
    line, status = um.summary(n, counts, "ok", ["interrupt-printf", "exhaustion", "demo-tcc"])
    ok(OK_LINE.fullmatch(line) is not None and status == 0, line)
    ok(not any(p for p in m.t.files if p.startswith(um.RUN + "/")), "the case directory was left")
    print(f"USERLAND SELFTEST AGREE OK :: {line}", flush=True)

    # 3. DIVERGENCE
    name = "test-newer"
    status, stderr, _ = m.divergences[name]
    host = (um.REPO / "userland" / "expected" / name).read_bytes()
    pred = um.predicted(status, stderr)
    ok(pred != host, "the prediction equals the host pin")
    bad = {
        "the host pin": host,
        "a non-empty stdout": um.cu.format_result(status, b"x\n", stderr.encode() + b"\n", dict(um.FIXTURES)),
        "another stderr": um.cu.format_result(status, b"", b"test: something else\n", dict(um.FIXTURES)),
        "another status": um.cu.format_result(status + 1, b"", stderr.encode() + b"\n", dict(um.FIXTURES)),
        "a changed file": with_files(pred, {"words.txt": b"changed\n"}),
    }
    for label, answer in bad.items():
        md = matrix(work, f"div-{len(label)}-{label.replace(' ', '-')}", only=[name], answers={name: answer})
        counts, _ = run_cases(md)
        ok(counts["defect"] == 1 and (md.pins / name).read_bytes() == answer, f"divergence with {label} not a DEFECT")
    print(f"USERLAND SELFTEST DIVERGENCE OK :: {name} judged by status {status}, empty stdout and its stderr; "
          f"{len(bad)} wrong answers each a DEFECT", flush=True)

    # 4. DEFECT
    edit = (um.REPO / "userland" / "expected" / "ed-edit").read_bytes()
    _, _, _, files = um.parse_pin(edit)
    wrong = with_files(edit, {"lines.txt": files["lines.txt"].replace(b"added", b"addeD")})
    mx = matrix(work, "defect-files", only=["ed-edit"], answers={"ed-edit": wrong})
    counts, text = run_cases(mx)
    ok(counts["defect"] == 1 and (mx.pins / "ed-edit").read_bytes() == wrong, "files-section mismatch")
    defects = (mx.pins / "DEFECTS").read_text()
    ok("ed-edit\tdiffers from userland/expected/ed-edit\n" in defects and "D-04" not in defects, defects)
    line, status = um.summary(len(mx.cases), counts, "ok", [])
    ok(line.startswith("ABSD USERLAND GUEST DEFECTS ") and "defects=1" in line and status == 1, line)
    grep = (um.REPO / "userland" / "expected" / "grep-n").read_bytes()
    my = matrix(work, "defect-stdout", only=["grep-n"], answers={"grep-n": grep.replace(b"1:b", b"1:c")})
    ok(run_cases(my)[0]["defect"] == 1, "stdout mismatch")
    first = (um.REPO / "userland" / "expected" / "sort-plain").read_bytes()
    second = first.replace(b"status 0", b"status 1")
    mr = matrix(work, "defect-repeat", only=["sort-plain"], answers={"sort-plain": lambda k: first if k == 1 else second})
    counts, _ = run_cases(mr)
    ok(counts["defect"] == 1 and (mr.pins / "sort-plain.repeat").read_bytes() == second
       and "repeat differs" in (mr.pins / "DEFECTS").read_text(), "repeat mismatch")
    new = (um.REPO / "userland" / "expected" / "ed-new").read_bytes()
    md4 = matrix(work, "defect-d04-ed", only=["ed-new"], answers={"ed-new": with_files(new, {"ed.AbC123": b""})})
    ok(run_cases(md4)[0]["defect"] == 1 and "candidate disposition D-04: ed's scratch file"
       in (md4.pins / "DEFECTS").read_text(), "ed scratch D-04 marker")
    fexec = (um.REPO / "userland" / "expected" / "find-exec").read_bytes()
    other = fexec.replace(b"Function not implemented", b"Operation not permitted")
    ok(other != fexec, "find-exec pin has no ENOSYS text")
    mf = matrix(work, "defect-d04-find", only=["find-exec"], answers={"find-exec": other})
    ok(run_cases(mf)[0]["defect"] == 1 and "candidate disposition D-04: find's -exec/-ok"
       in (mf.pins / "DEFECTS").read_text(), "find -exec D-04 marker")
    print("USERLAND SELFTEST DEFECT OK :: files section, stdout and repeat mismatches pinned under <pins>/<ID> with "
          "DEFECTS; D-04 candidates marked (ed scratch, find -exec); summary DEFECTS, status 1", flush=True)

    # 5. BINARY
    stream = em.stream([(f"{um.TEMPLATE}/{n}", d) for n, d in um.FIXTURES.items()])
    ok(stream[:8] == b"ABSDFIX1", "stream magic")
    i, decoded = 8, {}
    while True:
        (length,) = struct.unpack_from("<H", stream, i); i += 2
        if not length:
            break
        path = stream[i:i + length].decode(); i += length
        (size,) = struct.unpack_from("<Q", stream, i); i += 8
        digest, data = stream[i:i + 32], stream[i + 32:i + 32 + size]; i += 32 + size
        ok(hashlib.sha256(data).digest() == digest, f"digest of {path}")
        decoded[path[len(um.TEMPLATE) + 1:]] = data
    ok(i == len(stream) and decoded == um.FIXTURES and decoded["bin.dat"] == bytes(range(40)), "importer stream")
    mc = matrix(work, "binary-corrupt", only=["od-x1"], corrupt=True)
    quiet(mc.make_template)
    ok(fails(mc.run_cases), "a flipped byte of bin.dat passed the fresh-directory check")
    allbytes = with_files((um.REPO / "userland" / "expected" / "od-x1").read_bytes(), {"bin.dat": bytes(range(256))})
    ok(um.parse_pin(allbytes)[3] == {"bin.dat": bytes(range(256))} and with_files(allbytes, {"bin.dat": bytes(range(256))})
       == allbytes, "256-byte files section round trip")
    mo = matrix(work, "binary-od", only=["od-x1", "od-default", "od-skip"])
    ok(run_cases(mo)[0] == {"agree": 3, "diverge": 0, "defect": 0}, "od over bin.dat")
    print("USERLAND SELFTEST BINARY OK :: FIXTURES through the importer stream byte-exact; a flipped bin.dat byte "
          "fails the fresh directory; 256 byte values round-trip in a files section", flush=True)

    # 6. STATUS LINE
    ms = matrix(work, "status-line", only=["grep-missing"], no_status_line=True)
    quiet(ms.make_template)
    ok(fails(ms.run_cases), "a non-zero status without absd-sh's line passed")
    print("USERLAND SELFTEST STATUS LINE OK :: absd-sh's status line is required for a non-zero status", flush=True)

    # 8. DEMO: the scripted rehearsal on the fake guest (tcc absent).
    mdemo = matrix(work, "demo")
    notrun, text = quiet(mdemo.demo)
    ok(notrun == ["demo-tcc"] and "USERLAND DEMO TCC NOT_RUN reason=no /bin/tcc\n" in text
       and "USERLAND DEMO OK\n" in text and f"{um.HOME}/hello.c" not in mdemo.t.files, text[-600:])
    print("USERLAND SELFTEST DEMO OK :: ed writes hello.c, od/cmp/grep/find/rm, man sbase licence, /bin names; "
          "tcc NOT_RUN without /bin/tcc", flush=True)

    # 7. GRAMMAR
    ok(um.od_bytes(b"0000000 69 6e 74\n0000003\n") == b"int", "od_bytes")
    line, status = um.summary(99, {"agree": 94, "diverge": 5, "defect": 0}, "not_run", [])
    ok(line == "ABSD USERLAND GUEST OK cases=99 agree=94 diverge=5 defects=0 demo=not_run notrun=none"
       and OK_LINE.fullmatch(line) and status == 0, line)
    print("USERLAND SELFTEST GRAMMAR OK", flush=True)
    print(f"USERLAND SELFTEST OK checks={CHECKS}", flush=True)


if __name__ == "__main__":
    main()
