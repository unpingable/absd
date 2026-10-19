#!/usr/bin/env python3
"""Host-only checks of scripts/tcc-matrix.py's judging helpers (no QEMU).

1. Steps of a held absd-sh session: split_step cuts one fed command's
   stdout, status and stderr out of the session's streams by the step's
   marks (prompts, the `status` builtin's line, the `exit <mark>` builtin's
   stderr line, the `echo <mark>` line), refuses a stream without them, and
   strip_status removes absd-sh's own `exit status` line only when it is
   there and matches.
2. Byte comparison: first_difference reports equal files as None, the first
   differing offset otherwise (a strict prefix differs at the shorter
   length), and compare_elf names the section holding that offset in a real
   tcc ELF (hostcfg tcc's hello) with one byte flipped in .text, and in the
   ELF header for a flipped e_entry.
3. The negative control's evidence (task-5-context ruling 2): refusal_evidence
   accepts the shell's exact refusal with status 126, the file's `ls -l`
   line with the host file's size under 32 MiB, no `SPAWN OK` of a child of
   the session's shell in the step's serial text, and the gate's PT_GNU_RELRO
   reason; and rejects each of: status 127 `not found`, the runtime's
   oversize refusal, a size other than the host file's, a size over 32 MiB,
   a `SPAWN OK` of a child of the shell, a gate reason without
   `type 0x6474e552`.
   It also requires empty stdout for the refused command and, over the
   whole session, exactly the `ls` and `sha256sum` children of the shell.
4. The case table: load_cases reads the brief's rows with `# stdin` and
   `# expect` directives, and refuses a directive for no case.
5. The verdict paths (final review, Task 5 #2), driven with a stub matrix:
   judge_run for an agreeing, a differing and a gcc-referenced row; a
   classified row pinned and differing, unpinned, or equal to Linux; a
   `kit divergence` row whose pin is or is not the kit's Stage 1 pin
   (parse_pin, kit_pin_agrees); a stray pin; short.writer's figure at 999,
   1000, 29999 and 30000; an a.out that differs from the host build (failed,
   no CASE line). result for a kernel exit equal to or different from the
   shell's status, a fault reported as 128, a pipe, and a wrong child count.
   byte_context prints 16 bytes either side, guest and host.

Usage: tcc-matrix-selftest.py --tcc-build <tcc-build> --work <empty dir>
Prints TCC SELFTEST OK on success."""
if __name__ == "__main__":
    print("TCC STAGE NOT_RUN: not included in the public source", flush=True)
    raise SystemExit(78)

import argparse, contextlib, importlib.util, io, pathlib, subprocess, sys, types
from unittest.mock import patch

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
spec = importlib.util.spec_from_file_location("tcc_matrix", here / "tcc-matrix.py")
tm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tm)

checks = 0


def check(name, ok, detail=""):
    global checks
    checks += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{(': ' + detail) if detail and not ok else ''}", flush=True)
    if not ok:
        print(f"TCC SELFTEST FAILED: {name}", flush=True)
        sys.exit(1)


def raises(fn):
    try:
        fn()
    except tm.Refused:
        return True
    return False


def steps():
    P = tm.PROMPT
    # Step 3 of a session whose step 2 ended with the mark line: the run of
    # ./a.out printed two lines and exited 2.
    before_out = P + b"session-4/\n" + P + b"0\n" + P + P + b"tcc-mark-2\n"
    before_err = b"absd-sh: exit: tcc-mark-2: not a number\n"
    out = before_out + P + b"usage line\nmore\n" + P + b"2\n" + P + P + b"tcc-mark-3\n" + P
    err = before_err + b"oops\nabsd-sh: ./a.out: exit status 2\n" + b"absd-sh: exit: tcc-mark-3: not a number\n"
    got = tm.split_step(out, len(before_out), err, len(before_err), "tcc-mark-3")
    check("split_step: the command's stdout, status and stderr", got is not None and got[:3] ==
          (b"usage line\nmore\n", 2, b"oops\nabsd-sh: ./a.out: exit status 2\n"), repr(got))
    check("split_step: the stream positions after the step", got[3] == len(out) - len(P) and got[4] == len(err),
          repr(got[3:]))
    # Output without a final newline stays exact (no normalizer).
    out2 = P + b"no newline" + P + b"0\n" + P + P + b"tcc-mark-1\n"
    got = tm.split_step(out2, 0, tm.exit_mark("tcc-mark-1"), 0, "tcc-mark-1")
    check("split_step: output without a final newline is kept as it is", got is not None and got[:3] == (b"no newline", 0, b""),
          repr(got))
    check("split_step: a step whose mark has not arrived is not complete",
          tm.split_step(out[:-20], len(before_out), err, len(before_err), "tcc-mark-3") is None)
    check("split_step: the stderr mark is required too",
          tm.split_step(out, len(before_out), err[:-10], len(before_err), "tcc-mark-3") is None)
    check("split_step: a stream without the status line is refused",
          raises(lambda: tm.split_step(P + b"x" + P + P + b"tcc-mark-1\n", 0, tm.exit_mark("tcc-mark-1"), 0, "tcc-mark-1")))
    e = b"oops\nabsd-sh: ./a.out: exit status 2\n"
    check("strip_status: removes absd-sh's matching status line", tm.strip_status(e, "./a.out", 2) == (b"oops\n", True))
    check("strip_status: status 0 removes nothing", tm.strip_status(b"x\n", "./a.out", 0) == (b"x\n", False))
    a = b"x\nabsd-sh: ./a.out: ended abnormally\n"
    check("strip_status: a fault's `ended abnormally` (128) is removed", tm.strip_status(a, "./a.out", 128, True) == (b"x\n", True))
    check("strip_status: an exit code 128 is not a fault's line", raises(lambda: tm.strip_status(a, "./a.out", 128)))
    check("strip_status: a fault with a status other than 128 is refused", raises(lambda: tm.strip_status(a, "./a.out", 1, True)))
    check("strip_status: a non-matching status line is refused",
          raises(lambda: tm.strip_status(e, "./a.out", 3)) and raises(lambda: tm.strip_status(b"x\n", "./a.out", 2)))


def compare(tcc_build, work):
    check("first_difference: equal", tm.first_difference(b"abc", b"abc") is None)
    check("first_difference: first differing byte", tm.first_difference(b"abcd", b"abXd") == 2)
    check("first_difference: a strict prefix differs at the shorter length", tm.first_difference(b"ab", b"abc") == 2)
    src = work / "hello.c"
    src.write_text('#include <stdio.h>\nint main(void) { printf("hello, world\\n"); return 0; }\n')
    elf = work / "hello.elf"
    subprocess.run([str(tcc_build / "hostcfg" / "tcc"), "-B", str(tcc_build / "share" / "absd-c" / "tcc"), str(src),
                    "-o", str(elf)], check=True)
    data = elf.read_bytes()
    text = tm.sections(data)[".text"]
    flipped = bytearray(data)
    flipped[text[0] + 5] ^= 0xFF
    report = tm.compare_elf(bytes(flipped), data)
    check("compare_elf: a flipped .text byte is reported with its offset and section",
          report == (text[0] + 5, ".text"), repr(report))
    flipped = bytearray(data)
    flipped[0x18] ^= 1                              # e_entry
    check("compare_elf: a flipped e_entry is in the ELF header", tm.compare_elf(bytes(flipped), data) == (0x18, "ELF header"),
          repr(tm.compare_elf(bytes(flipped), data)))
    check("compare_elf: identical files", tm.compare_elf(data, data) is None)
    check("compare_elf: a truncated file differs at its end",
          tm.compare_elf(data[:-1], data) == (len(data) - 1, tm.section_at(data, len(data) - 1)))
    flipped = bytearray(data)
    flipped[text[0] + 40] ^= 0xFF
    off = text[0] + 40
    ctx = tm.byte_context(bytes(flipped), data, off)
    check("byte_context: 16 bytes either side, guest and host",
          ctx == f"context [{off - 16},{off + 16}) guest={bytes(flipped)[off - 16:off + 16].hex()} "
                 f"host={data[off - 16:off + 16].hex()}" and bytes(flipped)[off - 16:off + 16] != data[off - 16:off + 16],
          ctx)
    print(f"TCC SELFTEST ELF {elf.name} bytes={len(data)} .text={text}", flush=True)


def refusal():
    good = dict(
        status=126, out=b"",
        err=b"absd-sh: ./hello-relro.elf: cannot run: not a static ELF64 image the ABSD loader accepts\n",
        listing=b"- -- 1 12345 2026-10-17 06:00 hello-relro.elf\n", host_bytes=12345,
        serial="SPAWN OK pid=40 parent=33 program=image\nUSER EXIT pid=40 status=0\n", shell="31",
        gate="program header type other than PT_NULL/PT_LOAD (header 4 type 0x6474e552) (elf.rs:167-169)",
        children=["32", "33"], helpers=["32", "33"])
    ok, marker = tm.refusal_evidence(**good)
    check("refusal_evidence: all four pieces", ok and marker.startswith('shell=126 "absd-sh: ./hello-relro.elf: cannot run: '
                                                                       'not a static ELF64 image the ABSD loader accepts" '
                                                                       'present=12345 serial=no-spawn-ok '
                                                                       'children=32,33(ls,sha256sum) gate='), marker)
    check("refusal_evidence accepts explicit unknown time",
          tm.refusal_evidence(**{**good, "listing": b"- -- 1 12345 - hello-relro.elf\n"})[0])
    bad = {
        "old listing omits timestamp column": dict(listing=b"- -- 1 12345 hello-relro.elf\n"),
        "listing contains an invalid timestamp": dict(listing=b"- -- 1 12345 now hello-relro.elf\n"),
        "status 127 not found": dict(status=127, err=b"absd-sh: ./hello-relro.elf: not found\n"),
        "the runtime's oversize refusal": dict(err=b"absd-sh: ./hello-relro.elf: cannot run: the program image exceeds 32 MiB\n"),
        "a size other than the host file's": dict(listing=b"- -- 1 12344 2026-10-17 06:00 hello-relro.elf\n"),
        "a size over 32 MiB": dict(listing=b"- -- 1 40000000 2026-10-17 06:00 hello-relro.elf\n", host_bytes=40000000),
        "no listing line": dict(listing=b""),
        "a SPAWN OK of a child of the shell": dict(serial="SPAWN OK pid=41 parent=31 program=image\n"),
        "a gate reason without type 0x6474e552": dict(gate="program header type other than PT_NULL/PT_LOAD (header 4 type 0x6474e551)"),
        "an accepting gate": dict(gate=""),
        "stdout from the refused command": dict(out=b"x\n"),
        "a third child of the shell in the session": dict(children=["32", "33", "34"]),
        "helpers other than ls and sha256sum's two": dict(children=["32"], helpers=["32"]),
    }
    for name, change in bad.items():
        ok, why = tm.refusal_evidence(**{**good, **change})
        check(f"refusal_evidence rejects {name}", not ok, why)


def table(work):
    path = work / "cases.tsv"
    path.write_text("# a comment\nhello\tc/tests/kit/hello.c\tcompile-run\n"
                    "args\tc/tests/kit/args.c\tcompile-run\tone\ttwo three\n"
                    "short\tc/tests/kit/short.c\tcompile-run\n# stdin short: c/tests/kit/inputs/lines.txt\n"
                    "# expect short: equal\nhello-relro\ttcc-build/hostcfg-unpatched/hello-relro.elf\tspawn-refused\n"
                    "stdio.write\tc/tests/kit/stdio.c\tcompile-run\twrite\n# cwd stdio.write: /home/operator/w\n"
                    "# retained stdio.write: c-stdio.dat\n# reference stdio.write: gcc\n"
                    "w\tc/tests/kit/short.c\tcompile-run\twriter\n# pipe w: \"/bin/head\" -c 1000\n# removed w: f\n")
    cases = tm.load_cases(path)
    check("load_cases: rows, args with a space, stdin and expect",
          [(c.name, c.kind, c.args, c.stdin, c.expect) for c in cases] ==
          [("hello", "compile-run", [], None, ""), ("args", "compile-run", ["one", "two three"], None, ""),
           ("short", "compile-run", [], "c/tests/kit/inputs/lines.txt", "equal"),
           ("hello-relro", "spawn-refused", [], None, ""), ("stdio.write", "compile-run", ["write"], None, ""),
           ("w", "compile-run", ["writer"], None, "")], repr([(c.name, c.args, c.stdin) for c in cases]))
    check("load_cases: cwd, retained, removed, reference, pipe",
          [(c.cwd, c.keeps, c.drops, c.reference, c.pipe) for c in cases[4:]] ==
          [("/home/operator/w", ["c-stdio.dat"], [], "gcc", None), (None, [], ["f"], "tcc", '"/bin/head" -c 1000')],
          repr([(c.cwd, c.keeps, c.drops, c.reference, c.pipe) for c in cases[4:]]))
    path.write_text("hello\tc/tests/kit/hello.c\tcompile-run\n# reference hello: clang\n")
    check("load_cases: a reference other than gcc is refused", raises(lambda: tm.load_cases(path)))
    path.write_text("hello\tc/tests/kit/hello.c\tcompile-run\n# stdin nosuch: x\n")
    try:
        tm.load_cases(path)
        refused = False
    except (KeyError, tm.Refused):
        refused = True
    check("load_cases: a directive for no case is refused", refused)


def quiet(fn):
    """fn()'s value and what it printed."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        value = fn()
    return value, buf.getvalue()


def verdicts(work):
    pins, kit = work / "absd-expected", work / "kit"
    kit_pins = kit / "c" / "tests" / "kit" / "shell-expected"
    for d in (pins, kit_pins):
        d.mkdir(parents=True, exist_ok=True)
    pin = tm.ck.pin_bytes
    linux = (0, b"hello\n", b"")
    stub = types.SimpleNamespace(expected_dir=pins, pin=set(), kit=kit, classes={
        "lim": ("DIVERGES", "compiler limitation", "why"),
        "exit.abort": ("DIVERGES", "kit divergence", "why"),
        "kitless": ("DIVERGES", "kit divergence", "why")})

    def judge(name, got, ref=linux, elf_same=True, reference="tcc"):
        case = tm.Case([name, "c/x.c", "compile-run"])
        case.reference = reference
        return quiet(lambda: tm.TccMatrix.judge_run(stub, case, got, ref, elf_same))

    v, text = judge("plain", linux)
    check("judge_run: equal to Linux agrees", v == "agree" and "TCC CASE OK plain" in text, text)
    v, text = judge("plain", (0, b"hellO\n", b""))
    check("judge_run: an unclassified difference fails", v == "failed" and "TCC FINDING plain" in text, text)
    v, text = judge("plain", linux, reference="gcc")
    check("judge_run: a gcc-referenced row agrees as reference=gcc", v == "agree" and "reference=gcc" in text, text)
    v, text = judge("plain", linux, elf_same=False)
    check("judge_run: an a.out differing from the host build fails with no CASE line",
          v == "failed" and "TCC CASE" not in text and "TCC FINDING plain" in text, text)
    got = (128, b"", b"")
    (pins / "lim.txt").write_bytes(pin(*got))
    v, text = judge("lim", got)
    check("judge_run: a classified row equal to its pin and differing from Linux diverges",
          v == "diverge" and "TCC CASE DIVERGES lim :: compiler limitation" in text, text)
    v, text = judge("lim", (127, b"", b""))
    check("judge_run: a classified row not equal to its pin fails", v == "failed", text)
    (pins / "lim.txt").write_bytes(pin(*linux))
    v, text = judge("lim", linux)
    check("judge_run: a classified row equal to Linux fails", v == "failed", text)
    abort = (134, b"ctor\nmain\nabort\n", b"")
    (pins / "exit.abort.txt").write_bytes(pin(*abort))
    kit_abort = kit_pins / "exit_abort.txt"
    kit_abort.write_bytes(b"ctor\nmain\nabort\n--\nabsd-sh: /bin/exit: exit status 134\n--\nstatus=134\n")
    v, text = judge("exit.abort", abort)
    check("judge_run: a kit divergence equal to the kit's Stage 1 pin (status line stripped) diverges",
          v == "diverge" and "kit's Stage 1 pin c/tests/kit/shell-expected/exit_abort.txt" in text, text)
    kit_abort.write_bytes(b"ctor\nmain\n--\nabsd-sh: /bin/exit: exit status 134\n--\nstatus=134\n")
    v, text = judge("exit.abort", abort)
    check("judge_run: a kit divergence whose stdout differs from the kit's pin fails", v == "failed", text)
    kit_abort.write_bytes(b"ctor\nmain\nabort\n--\nabsd-sh: /bin/exit: exit status 6\n--\nstatus=6\n")
    v, text = judge("exit.abort", abort)
    check("judge_run: a kit divergence whose status differs from the kit's pin fails", v == "failed", text)
    (pins / "kitless.txt").write_bytes(pin(*abort))
    v, text = judge("kitless", abort)
    check("judge_run: a kit divergence with no kit pin fails", v == "failed" and "no kit pin" in text, text)
    check("parse_pin: refuses a stream without the separators", tm.parse_pin(b"x\nstatus=0\n") is None)
    (pins / "stray.txt").write_bytes(pin(*linux))
    v, text = judge("stray", linux)
    check("judge_run: a pin for an unclassified row fails", v == "failed", text)
    writer_ref = (0, b"x" * 1000, b"wrote 30000 bytes\n")
    for n, want in ((999, "failed"), (1000, "agree"), (29999, "agree"), (30000, "failed")):
        v, text = judge(tm.TIMING_CASE, (0, b"x" * 1000, f"write failed after {n} bytes\n".encode()), writer_ref)
        check(f"judge_run: short.writer's figure {n} is judged {want} by [1000,30000)", v == want, text)
    v, text = judge(tm.TIMING_CASE, (1, b"x" * 1000, b"write failed after 2048 bytes\n"), writer_ref)
    check("judge_run: short.writer with a different status fails", v == "failed", text)

    def result(status, exits, err=b"", pipe=None):
        case = tm.Case(["c", "c/x.c", "compile-run"])
        case.pipe = pipe
        step = tm.Step("./a.out", b"out\n", status, err, 0.1, [p for p, _ in exits], "")
        seen = {"run": step, "run_exit": exits, "shell": "14", "prog": "./a.out"}
        try:
            return tm.TccMatrix.result(None, case, seen)
        except tm.Refused as e:
            return e

    r = result(0, [("19", "EXIT status=0")])
    check("result: the kernel's exit equals the shell's status", not isinstance(r, Exception) and r[0] == (0, b"out\n", b"")
          and "SPAWN OK pid=19 parent=14 EXIT status=0" in r[1], repr(r))
    check("result: a kernel exit other than the shell's status is refused",
          isinstance(result(0, [("19", "EXIT status=3")]), tm.Refused))
    r = result(128, [("19", "FAULT vector=14 address=0x1")], b"absd-sh: ./a.out: ended abnormally\n")
    check("result: a fault reported by the shell as 128 is accepted, its line removed",
          not isinstance(r, Exception) and r[0] == (128, b"out\n", b"") and r[2] == "absd-sh: ./a.out: ended abnormally",
          repr(r))
    check("result: a fault the shell reports with another status is refused",
          isinstance(result(1, [("19", "FAULT vector=14 address=0x1")], b"absd-sh: ./a.out: exit status 1\n"), tm.Refused))
    check("result: two children for a run without a pipe are refused",
          isinstance(result(0, [("19", "EXIT status=0"), ("20", "EXIT status=0")]), tm.Refused))
    r = result(0, [("19", "EXIT status=0"), ("20", "EXIT status=0")], pipe='"/bin/head" -c 1000')
    check("result: a pipe's last stage gives the status", not isinstance(r, Exception) and r[0][0] == 0, repr(r))


def deployment(tcc_build, platform, work):
    args = types.SimpleNamespace(kernel=tcc_build.parent / "kernel", platform=platform,
                                 qemu="qemu-system-x86_64", shell=platform / "commands/absd-sh",
                                 boot_seconds=600)
    target = tm.TccTarget(args)
    matrix_args = types.SimpleNamespace(tcc_build=tcc_build, kit=platform,
                                       cases=tm.here.parent / "tcc/cases.tsv", only=None, pin=[])
    with patch.object(tm.ck.sm, "keygen", side_effect=lambda path: path):
        tm.TccMatrix(target, work / "deployment", matrix_args)
    files = target.files("fixture-public-key")
    paths = [path for path, _ in files]
    check("real deployment has unique logical paths", len(paths) == len(set(paths)))
    check("rm is installed once with the candidate command bytes",
          paths.count("/bin/rm") == 1 and dict(files)["/bin/rm"] == (platform / "commands/rm").read_bytes())
    check("all TinyCC extra commands remain installed", all(f"/bin/{n}" in paths for n in tm.EXTRA))
    installed = target.installed("fixture-public-key")
    check("release layout accepts the complete TinyCC deployment", bool(installed))
    target.case_files.append(("/bin/rm", b"conflicting fixture"))
    try:
        target.installed("fixture-public-key")
    except ValueError:
        refused = True
    else:
        refused = False
    check("release layout still refuses conflicting duplicate paths", refused)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tcc-build", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--platform", help="built platform for the deployment regression")
    args = ap.parse_args()
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    steps()
    compare(pathlib.Path(args.tcc_build).resolve(), work)
    refusal()
    table(work)
    verdicts(work)
    if args.platform:
        deployment(pathlib.Path(args.tcc_build).resolve(), pathlib.Path(args.platform).resolve(), work)
    print(f"TCC SELFTEST OK checks={checks}", flush=True)


if __name__ == "__main__":
    main()
