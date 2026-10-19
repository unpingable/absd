#!/usr/bin/env python3
"""Host-only checks of scripts/cports-matrix.py's judging paths (no QEMU).

1. The LIMIT path (LIMIT_ON_TIMEOUT): a synthetic SessionTimeout for
   sqlite.speedtest1-20, whose census then shows a frames-only move with its
   retained st.db changed, must print CPORTS LIMIT, leave the case out of the
   high-water list, self.ran and the repeat chains, and fail nothing. A
   negative control: the same move on a case that is neither repeatable nor a
   LIMIT must still fail as UNREPEATABLE.
2. The Linux twins that run on the host: sqlite.home with HOME at an empty
   directory under the work directory (stdout 1, empty stderr, status 0), and
   sqlite.speedtest1-5 run twice with its normalizer (normalized runs equal,
   the verification hash of the case table).
3. VERIFY: verify_line prints speedtest1's Verification Hash line and fails
   when the output has none.
4. SETTLED (the earlier rule, kept for a census without the fsd keys): a
   census the check refuses is re-sampled (Task 13); a reading that returns
   to the expected one passes, one that never returns fails; stable() on
   such censuses returns the first agreeing pair, or the last reading
   without failing when none agrees within 20 s.
5. RESTART REPEAT: the same-boot repeat of B's read-only query passes on
   equal censuses and fails on one frame more (no allowance, no re-sample)
   or on another query result.
6. TIMEOUT: the `# defect-on-timeout` grammar (with and without the colon;
   a malformed line or an unknown case fails the load). A synthetic
   timed-out lua.all session with partial output: annotated, it prints
   CPORTS DEFECT TIMEOUT with id, seconds and the prefix line count and
   keeps .absd.out/.err/.status ("timeout 600"); unannotated, the timeout
   still fails the run with the same files kept; annotated but diverging
   from Linux before the stop, or with a DEFECTS entry that does not name
   the id, it fails.
7. LIMIT PREFIX: the `# limit-prefix NAME: ID FILE "MESSAGE"` grammar; the
   load refuses an annotated case missing from divergences.txt or listed in
   DEFECTS. A synthetic lua.all ending in locals.lua with "not enough
   memory" passes (CPORTS DIVERGES PREFIX OK), and neither compares nor
   writes its pin; a stop in another file, no message, status 0 or a prefix
   that differs fails with CPORTS LIMIT PREFIX MISMATCH; an unannotated
   divergence keeps the pin rule.
8. REPEAT SCENARIO: posix.lock-contention (REPEAT_SCENARIOS) is repeatable()
   and its high-water (frames +4, the file server's heap peak 20 -> 24) is
   taken without UNREPEATABLE; a fake repeat round that runs the scenario
   again with equal censuses prints CPORTS RESOURCES REPEAT OK naming it;
   the same with the heap peak moving again (24 -> 28), or with the scenario
   printing something else, fails.
9. HEAP STEP (census ruling (a)): a synthetic HIGHWATER of +4 heap pages
   prints "pool-sized" and one of +3 "not pool-sized (...)"; both are
   recorded for lock-contention and both fail UNREPEATABLE on a case that is
   not repeatable, exactly as before; a repeat round (stable() not stubbed:
   its censuses are judged by ruling (b)) whose heap peak steps +4 or +3
   fails naming the class; a frames-only step with the heap peak moved fails
   naming it; a fall prints "released", none "(equal)".
10. JUDGED CENSUS (census ruling (b) as ratified 2026-10-13): REST is taken
   from the boot's first reading with draining 0 and two equal samples, and
   again on the restart path (cut -> REBASE); a rest reading stuck at
   draining 1 fails UNSETTLED. The first sample at rest is judged: bisect
   run A's 66 -> 67 -> 67 -> 67 -> 66 -> 66 at 66, an fsd heap peak of 20,
   24, 20, 20 at 20, an opens transient at rest; each prints one TRANSIENT
   line naming what it absorbed (handles 67, fsd heap 24, opens 4). No sample
   at rest: the last settled reading is a SETTLED CHANGE failing the
   existing checks (a persistent +1 handle, through stable() and
   compare_census; opens above rest; an oscillation 67, 67, 68, 68 that
   never returns; a pipes +1; a case-before reading off rest on handles or
   opens). No settled pair: UNSETTLED handles; draining stuck: UNSETTLED
   draining. The repeat rounds: a pre-round +1 transient is absorbed; a
   round stuck at draining 1 fails UNSETTLED; a round settled at +1 handle
   fails the round's check; opens off rest fail before the rounds and in a
   round. rest_kernel and rest_opens fail the frames warmup and the restart
   repeat (base and repeats) off rest. Rest counts: the rest reading needs
   three equal samples (a two-sample 67 is not taken); a settled pair below
   rest lowers it (REST LOWERED, and the RECORDED summary line), and a
   reading above the lowered rest still fails as a settled change. The tcc,
   clang and userland matrices inherit CportsMatrix.census and stable(): the
   base class takes each boot's rest before its first judged census, run
   A's shape is judged at 66 in each, and a draining stuck at 1 fails
   UNSETTLED there.

11. WARM REPEAT: warm +0/+4 proceeds, +8/non-pool/negative heap, +5 frames,
    kernel/name/image changes fail; judged steps still fail exactly. Diagnostic
    continuation follows warm and the settled baseline, with a scaled boot budget.

Usage: cports-matrix-selftest.py --linux <cports-build/linux> --work <empty dir>
Prints CPORTS SELFTEST OK on success."""
import argparse, contextlib, copy, importlib.util, io, os, pathlib, re, sys, time
from unittest.mock import patch

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
spec = importlib.util.spec_from_file_location("cports_matrix", here / "cports-matrix.py")
cm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cm)


class FakeTarget:
    boots = 1

    def all_images(self):
        return 0

    def census_detail(self):
        return "fake"


def census(frames, st_digest):
    memory = f"memory: 1 KiB free, 1 KiB allocated (30000 + {frames} frames of 4096 bytes)"
    objects = [(f"{cm.CPORTS}/speedtest/st.db", False, False, 7, st_digest),
               (f"{cm.CPORTS}/speedtest/empty.sqliterc", False, False, 6, "e3b0")]
    return {"images": 0, "memory": memory, "kernel": "kernel: 4 process slots, 66 handles, 27 pipes, 1 cells",
            "objects": objects, "fsd": 26, "fsd_opens": 3, "fsd_draining": 0}


def keyless(c):
    """A census without the file server's opens/draining keys (a subclass's)."""
    return {k: v for k, v in c.items() if k not in ("fsd_opens", "fsd_draining")}


def matrix(work, linux):
    m = cm.CportsMatrix.__new__(cm.CportsMatrix)
    m.checks, m.passed = 0, []
    m.t = FakeTarget()
    m.work, m.linux = work, linux
    m.highwater, m.ran, m.limited, m.steps = [], {}, set(), 0
    m.normalizers = {}
    m.rest_boot = m.t.boots          # this boot's rest is handled by each test (take_rest is tested on its own)
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--linux", required=True)
    ap.add_argument("--work", required=True)
    args = ap.parse_args()
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    linux = pathlib.Path(args.linux).resolve()
    cases = {c.name: c for c in cm.load_cases(here.parent / "cports" / "cases.tsv")}

    # 1. LIMIT path.
    m = matrix(work, linux)
    case = cases["sqlite.speedtest1-20"]
    before, after = census(721, "aaaa"), census(725, "bbbb")
    m.stable = lambda key, when: after
    e = cm.SessionTimeout("timed out", b"-- Speedtest1\n 100 - 2500 INSERTs ....   12.000s\n", b"", case.timeout)
    m.limit_case(case, e, time.monotonic(), before)
    assert case.name in m.limited and case.name not in m.highwater and case.name not in m.ran, (m.limited, m.highwater)
    # A high-water case of another chain still repeats; the LIMIT case's chain does not.
    m.highwater.append("sqlite.speedtest1-5")
    m.ran["sqlite.speedtest1-5"] = cases["sqlite.speedtest1-5"]
    unrepeatable, pairs, chains = m.repeat_plan()
    assert unrepeatable == [] and pairs == [], (unrepeatable, pairs)
    assert [c["cases"] for c in chains] == [["sqlite.speedtest1-5"]], chains
    print("CPORTS SELFTEST LIMIT OK :: speedtest1-20 limited, not high-water, not ran, its chain not repeated", flush=True)

    # Negative control: the same move on a non-repeatable, non-LIMIT case fails.
    m2 = matrix(work, linux)
    other = cm.Case(["sqlite.excl-setup", "shell", "speedtest", "-", "-", "/bin/sqlite3"])
    other.retained = ["st.db"]
    try:
        m2.compare_census(other, before, after)
    except (cm.sm.Failed, cm.ck.sm.Failed):
        print("CPORTS SELFTEST UNREPEATABLE OK :: a non-LIMIT case outside REPEATABLE/CHAINS still fails", flush=True)
    else:
        raise SystemExit("negative control did not fail")

    # 1b. SETTLED (coordinator ruling, Task 13), for a census without the fsd
    # keys (a subclass's own; census ruling (b) leaves it exactly as before):
    # a +1 handle after a case that returns to the expected reading on a later
    # sample passes; one that never returns fails exactly as before.
    # SETTLE_SECONDS is shortened for the test.
    cm.SETTLE_SECONDS = 3
    real_sleep, cm.time.sleep = cm.time.sleep, (lambda s: None)
    base = keyless(census(721, "aaaa"))
    plus = dict(base, kernel=base["kernel"].replace("66 handles", "67 handles"))
    m4 = matrix(work, linux)
    seq = iter([plus, base])
    m4.census = lambda: next(seq)
    m4.compare_census(other, base, plus)
    assert m4.judged is base, m4.judged
    m5 = matrix(work, linux)
    m5.census = lambda: plus
    real = cm.time.monotonic
    clock = iter(range(0, 1000))
    cm.time.monotonic = lambda: next(clock)
    try:
        m5.compare_census(other, base, plus)
    except (cm.sm.Failed, cm.ck.sm.Failed):
        print("CPORTS SELFTEST SETTLED OK :: a census that returns passes as SETTLED; one that never returns fails",
              flush=True)
        # stable() on a census without the fsd keys: the earlier rule exactly.
        m6 = matrix(work, linux)
        seq = [plus, base, base]
        m6.census = lambda: seq.pop(0) if len(seq) > 1 else seq[0]
        assert m6.stable("x", "after") is base
        flip = iter([plus, base] * 100)
        m6.census = lambda: next(flip)
        got = m6.stable("x", "after")              # no agreement within 20 s: the last reading, no failure
        assert got in (plus, base), got
        print("CPORTS SELFTEST KEYLESS STABLE OK :: a census without the fsd keys: first agreeing pair, else the "
              "last reading (no UNSETTLED)", flush=True)
    else:
        raise SystemExit("a census that never settled passed")
    finally:
        cm.time.monotonic, cm.time.sleep = real, real_sleep

    # 1c. RESTART REPEAT (final review I3): B's read-only query twice more on
    # the restarted boot; equal censuses pass, one frame more that never
    # returns fails (no allowance), and so does a different query result.
    cm.SETTLE_SECONDS = 3
    real_sleep, cm.time.sleep = cm.time.sleep, (lambda s: None)
    real = cm.time.monotonic
    clock = iter(range(0, 1000))
    cm.time.monotonic = lambda: next(clock)
    crash = cases["sqlite.excl-crash"]
    first = (0, b"ok\n3\n", b"", 1.0)
    try:
        m6 = matrix(work, linux)
        m6.restart_round = 1
        m6.sqlite_absd = lambda case, db, sql: first
        m6.stable = lambda key, when: base
        m6.census = lambda: base
        m6.restart_repeat(crash, "x.db", "SELECT 1;", first)
        grown = census(722, "aaaa")
        for label, result, later in (("a frame more", first, grown), ("another result", (0, b"ok\n2\n", b"", 1.0), base)):
            m7 = matrix(work, linux)
            m7.restart_round = 2
            m7.sqlite_absd = lambda case, db, sql, result=result: result
            readings = iter([base] + [later] * 1000)
            m7.stable = lambda key, when: next(readings)
            m7.census = lambda: later
            try:
                m7.restart_repeat(crash, "x.db", "SELECT 1;", first)
            except (cm.sm.Failed, cm.ck.sm.Failed):
                pass
            else:
                raise SystemExit(f"restart_repeat passed with {label}")
    finally:
        cm.time.monotonic, cm.time.sleep = real, real_sleep
    print("CPORTS SELFTEST RESTART REPEAT OK :: equal censuses pass; a frame more or another result fails", flush=True)

    # 6. TIMEOUT: partial capture and # defect-on-timeout.
    timeout_section(work, linux, cases)
    # 7. LIMIT PREFIX: a prefix-judged NATIVE LIMIT divergence.
    limit_prefix_section(work, linux, cases)
    # 8. REPEAT SCENARIO: a scenario's high-water proven by the repeat round.
    repeat_scenario_section(work, linux, cases)
    # 9. HEAP STEP: census ruling (a).
    heap_step_section(work, linux, cases)
    # 10. AT REST: census ruling (b).
    at_rest_section(work, linux, cases)

    diag_repeat_section(work, linux, cases)

    # 2. Linux twins on the host.
    for name in ("sqlite.home", "sqlite.speedtest1-5"):
        case = cases[name]
        d = work / "linux" / case.cwd
        d.mkdir(parents=True, exist_ok=True)
        data = here.parent / "cports" / "data" / case.cwd
        for f in data.iterdir():
            (d / f.name).write_bytes(f.read_bytes())
    m3 = matrix(work, linux)
    ref, _ = m3.linux_run(cases["sqlite.home"], m3.linux_dir("sqlite"))
    assert ref == (0, b"1\n", b""), ref
    home = work / "linux-home"
    assert home.is_dir() and not any(home.iterdir())
    print(f"CPORTS SELFTEST LINUX OK sqlite.home :: {ref!r} with HOME={home}", flush=True)
    case = cases["sqlite.speedtest1-5"]
    m3.normalizers = {case.name: [re.compile(rb" +[0-9]+\.[0-9]+s$", re.M)]}
    first, second = m3.linux_run(case, m3.linux_dir("speedtest"), twice=True)
    a, b = m3.normalized(case, first), m3.normalized(case, second)
    assert first[0] == 0 and a == b, (first[0], a == b)
    assert b"Verification Hash: 1235255 446bc256109febab75a5efc5558b33506464d18cabd8d34d\n" in first[1]
    line = m3.verify_line(case, first)
    assert line == "Verification Hash: 1235255 446bc256109febab75a5efc5558b33506464d18cabd8d34d", line
    try:
        m3.verify_line(case, (0, b"no hash here\n", b""))
    except (cm.sm.Failed, cm.ck.sm.Failed):
        pass
    else:
        raise SystemExit("verify_line accepted an output without a Verification Hash line")
    print("CPORTS SELFTEST VERIFY OK :: the speedtest1 hash line is printed; a missing one fails", flush=True)
    print("CPORTS SELFTEST LINUX OK sqlite.speedtest1-5 :: two runs equal after normalization, hash as the case table",
          flush=True)
    print("CPORTS SELFTEST OK", flush=True)


LUA_PARTIAL = (b"***** FILE 'main.lua'*****\ntesting stand-alone interpreter\n"
               b"***** FILE 'gc.lua'*****\ntesting incremental garbage collection\nOK\n"
               b"***** FILE 'db.lua'*****\ntesting debug lib")             # cut mid-line by the kill
LUA_LINUX = (1, b"***** FILE 'main.lua'*****\ntesting stand-alone interpreter\n"
                b"***** FILE 'gc.lua'*****\ntesting incremental garbage collection\nOK\n"
                b"***** FILE 'db.lua'*****\ntesting debug library and debug information\n"
                b"***** FILE 'files.lua'*****\n",
             b"/bin/lua: files.lua:8: assertion failed!\nstack traceback:\n")


def timeout_section(work, linux, cases):
    failed = (cm.sm.Failed, cm.ck.sm.Failed)
    # The grammar.
    rows = "lua.all\tshell\tlua-tests\t-\t-\t/bin/lua\tall.lua\nzlib.x\tshell\tzlib\t-\t-\t/bin/minigzip\n"
    for annotation, name, ident in (("# defect-on-timeout lua.all: R15", "lua.all", "R15"),
                                    ("# defect-on-timeout lua.all R15", "lua.all", "R15")):
        t = work / "cases-annotated.tsv"
        t.write_text(rows + annotation + "\n")
        got = {c.name: c.defect_on_timeout for c in cm.load_cases(t)}
        assert got == {name: ident, "zlib.x": None}, (annotation, got)
    for bad in ("# defect-on-timeout lua.all:R15", "# defect-on-timeout lua.all", "# defect-on-timeout nosuch: R15",
                "# defect-on-timeout lua.all: R15 extra"):
        t.write_text(rows + bad + "\n")
        try:
            cm.load_cases(t)
        except failed:
            continue
        raise SystemExit(f"load_cases accepted {bad!r}")
    print("CPORTS SELFTEST TIMEOUT GRAMMAR OK :: '# defect-on-timeout NAME: ID' and '# defect-on-timeout NAME ID'; "
          "malformed and unknown-case lines fail", flush=True)

    base = census(721, "aaaa")
    lua = cases["lua.all"]
    defect_text = "KIT (allocator): R15 realloc-doubling growth; the suite makes no progress under TCG"

    def timeout_matrix(sub, defects=defect_text, ref=LUA_LINUX):
        d = work / sub
        d.mkdir(parents=True, exist_ok=True)
        m = matrix(d, linux)
        m.defects = {"lua.all": defects}
        m.stable = lambda key, when: base
        m.linux_run = lambda case, cwd, twice=False: (ref, None)
        return m, d

    def run(m, case, out=LUA_PARTIAL, err=b""):
        e = cm.SessionTimeout(f"session timed out after {case.timeout} s: 'lua'", out, err, case.timeout)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                result = m.timed_out(case, e, time.monotonic(), base)
        except BaseException as x:
            sys.stdout.write(buf.getvalue())
            raise x
        sys.stdout.write(buf.getvalue())
        return result, buf.getvalue()

    # Annotated: DEFECT TIMEOUT with the prefix count.
    annotated = copy.copy(lua)
    annotated.defect_on_timeout = "R15"
    m, d = timeout_matrix("timeout-annotated")
    (memory, kernel, judged), text = run(m, annotated)
    want = f"CPORTS DEFECT TIMEOUT lua.all id=R15 seconds={lua.timeout} lines=6\n"
    assert want in text, text
    assert "CPORTS DEFECT PREFIX OK lua.all lines=6 " in text and "CPORTS DEFECT lua.all :: " + defect_text in text, text
    assert (d / "lua.all.absd.status").read_bytes() == f"timeout {lua.timeout}\n".encode()
    assert (d / "lua.all.absd.out").read_bytes() == LUA_PARTIAL and (d / "lua.all.absd.err").read_bytes() == b""
    assert (d / "lua.all.linux.out").read_bytes() == LUA_LINUX[1]
    assert judged is base and memory == base["memory"], (memory, judged)
    print(f"CPORTS SELFTEST TIMEOUT ANNOTATED OK :: {want.strip()}; partial output kept, status 'timeout "
          f"{lua.timeout}'", flush=True)

    # Unannotated: still a failure, with the same files kept.
    plain = copy.copy(lua)
    plain.defect_on_timeout = None
    m, d = timeout_matrix("timeout-plain")
    try:
        run(m, plain)
    except cm.SessionTimeout as e:
        assert str(e).startswith("session timed out after"), str(e)
    else:
        raise SystemExit("an unannotated timeout did not fail")
    assert (d / "lua.all.absd.status").read_bytes() == f"timeout {lua.timeout}\n".encode()
    assert (d / "lua.all.absd.out").read_bytes() == LUA_PARTIAL
    assert not (d / "lua.all.linux.out").exists()
    print("CPORTS SELFTEST TIMEOUT UNANNOTATED OK :: the timeout fails the run; partial output kept", flush=True)

    # Annotated, but ABSD's partial output differs from Linux before the stop.
    m, _ = timeout_matrix("timeout-diverged")
    try:
        run(m, annotated, out=LUA_PARTIAL.replace(b"OK\n", b"KO\n"))
    except failed:
        pass
    else:
        raise SystemExit("a partial output that differs from Linux passed as DEFECT TIMEOUT")
    # Annotated, but the partial stderr is not Linux's.
    m, _ = timeout_matrix("timeout-stderr")
    try:
        run(m, annotated, err=b"lua: not enough memory\n")
    except failed:
        pass
    else:
        raise SystemExit("a partial stderr Linux did not print passed as DEFECT TIMEOUT")
    # Annotated, but DEFECTS does not name the id (R150 is not R15).
    for text_ in (defect_text.replace("R15", "R150"), None):
        m, _ = timeout_matrix("timeout-noid", defects=text_)
        if text_ is None:
            m.defects = {}
        try:
            run(m, annotated)
        except failed:
            continue
        raise SystemExit(f"DEFECT TIMEOUT passed with DEFECTS {text_!r}")
    print("CPORTS SELFTEST TIMEOUT NEGATIVE OK :: a prefix that differs from Linux, a foreign stderr, or a DEFECTS "
          "entry without the id fails", flush=True)


LUA_HEAD = (b"***** FILE 'main.lua'*****\ntesting stand-alone interpreter\n"
            b"***** FILE 'gc.lua'*****\ntesting incremental garbage collection\nOK\n")
LIMIT_OUT = LUA_HEAD + b"***** FILE 'locals.lua'*****\ntesting local variables and environments\n"
LIMIT_ERR = b"/bin/lua: not enough memory\n"
LIMIT_LINUX = (1, LIMIT_OUT + b"OK\n***** FILE 'files.lua'*****\n",
               b"/bin/lua: files.lua:8: assertion failed!\nstack traceback:\n")


def limit_prefix_section(work, linux, cases):
    failed = (cm.sm.Failed, cm.ck.sm.Failed)
    rows = "lua.all\tshell\tlua-tests\t-\t-\t/bin/lua\tall.lua\n"
    t = work / "cases-limit.tsv"
    for annotation in ('# limit-prefix lua.all: CPA-060 locals.lua "not enough memory"',
                       '# limit-prefix lua.all CPA-060 locals.lua "not enough memory"'):
        t.write_text(rows + annotation + "\n")
        got = cm.load_cases(t)[0].limit_prefix
        assert got == ("CPA-060", "locals.lua", "not enough memory"), (annotation, got)
    for bad in ('# limit-prefix lua.all: CPA-060 locals.lua not enough memory',
                '# limit-prefix lua.all: CPA-060 "not enough memory"',
                '# limit-prefix nosuch: CPA-060 locals.lua "not enough memory"'):
        t.write_text(rows + bad + "\n")
        try:
            cm.load_cases(t)
        except failed:
            continue
        raise SystemExit(f"load_cases accepted {bad!r}")
    lua = copy.copy(cases["lua.all"])
    lua.limit_prefix = ("CPA-060", "locals.lua", "not enough memory")
    reason = "NATIVE LIMIT: the 32 MiB heap window (CPA-060) ends locals.lua's stack-overflow test"

    def limit_matrix(sub, divergences=True, defects=False):
        d = work / sub
        d.mkdir(parents=True, exist_ok=True)
        m = matrix(d, linux)
        m.expected = d / "absd-expected"
        m.expected.mkdir(exist_ok=True)
        m.divergences = {"lua.all": reason} if divergences else {}
        m.defects = {"lua.all": "x"} if defects else {}
        m.pin = set()
        return m

    for label, kw in (("not in divergences.txt", {"divergences": False}), ("in DEFECTS", {"defects": True})):
        try:
            limit_matrix("limit-load").require_limit_prefix(lua)
        except failed:
            raise SystemExit("a valid # limit-prefix case was refused")
        try:
            limit_matrix("limit-load", **kw).require_limit_prefix(lua)
        except failed:
            continue
        raise SystemExit(f"# limit-prefix accepted a case {label}")
    print("CPORTS SELFTEST LIMIT PREFIX GRAMMAR OK :: '# limit-prefix NAME: ID FILE \"MESSAGE\"' (colon optional); "
          "malformed lines, a case not in divergences.txt or in DEFECTS refused", flush=True)

    def judge(m, case, got, ref=LIMIT_LINUX):
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                verdict = m.judge(case, got, ref)
        finally:
            sys.stdout.write(buf.getvalue())
        return verdict, buf.getvalue()

    # Passes: stop in locals.lua with the message, non-zero status; no pin compared or written.
    m = limit_matrix("limit-pass")
    m.pin = {"lua.all"}
    (m.expected / "lua.all.txt").write_bytes(b"a stale pin that would not match\n")
    verdict, text = judge(m, lua, (1, LIMIT_OUT, LIMIT_ERR))
    want = "CPORTS DIVERGES PREFIX OK lua.all :: NATIVE LIMIT CPA-060 stop_file=locals.lua lines=7 status=1\n"
    assert verdict == "diverge" and want in text and f"CPORTS DIVERGES lua.all :: {reason}\n" in text, text
    assert (m.expected / "lua.all.txt").read_bytes() == b"a stale pin that would not match\n"
    print(f"CPORTS SELFTEST LIMIT PREFIX OK :: {want.strip()}; the pin neither compared nor written", flush=True)

    # Fails: another file, no message, status 0, a prefix that differs.
    other = LUA_HEAD + b"***** FILE 'constructs.lua'*****\ntesting tables\n"
    for label, got, ref in (
            ("stop in another file", (1, other, LIMIT_ERR), (1, other + b"OK\n", LIMIT_LINUX[2])),
            ("message absent", (1, LIMIT_OUT, b"/bin/lua: locals.lua:3: assertion failed!\n"), LIMIT_LINUX),
            ("status 0", (0, LIMIT_OUT, LIMIT_ERR), LIMIT_LINUX),
            ("prefix differs", (1, LIMIT_OUT.replace(b"OK\n", b"KO\n"), LIMIT_ERR), LIMIT_LINUX)):
        m = limit_matrix("limit-fail")
        try:
            _, text = judge(m, lua, got, ref)
        except failed:
            continue
        raise SystemExit(f"# limit-prefix passed with {label}")
    print("CPORTS SELFTEST LIMIT PREFIX MISMATCH OK :: a stop in another file, no message, status 0 or a differing "
          "prefix fails (CPORTS LIMIT PREFIX MISMATCH)", flush=True)

    # An unannotated divergence keeps the pin rule.
    plain = copy.copy(cases["lua.all"])
    plain.limit_prefix = None
    got = (1, LIMIT_OUT, LIMIT_ERR)
    m = limit_matrix("limit-plain")
    (m.expected / "lua.all.txt").write_bytes(cm.ck.pin_bytes(*got))
    verdict, _ = judge(m, plain, got)
    assert verdict == "diverge"
    m = limit_matrix("limit-plain-stale")
    (m.expected / "lua.all.txt").write_bytes(cm.ck.pin_bytes(1, LIMIT_OUT, b"/bin/lua: other\n"))
    try:
        judge(m, plain, got)
    except failed:
        pass
    else:
        raise SystemExit("an unannotated divergence passed against a pin it does not match")
    print("CPORTS SELFTEST LIMIT PREFIX UNANNOTATED OK :: a divergence without # limit-prefix is judged by its pin",
          flush=True)


def diag_repeat_section(work, linux, cases):
    """Diagnostic continuation retains the ordinary failure and strict baseline."""
    # Extra observations come from the last capacity record and do not
    # affect the default census or its judged fields.
    m = matrix(work, linux)
    m.t.serial = lambda: ("FSD CAPACITY settled_releases=1 heap_free_pages=3\n"
                          "FSD CAPACITY settled_releases=742 heap_free_pages=7\n")
    m.fsd_capacity = lambda: (3, 0, 31)
    m.fsd_peak = lambda: 31
    with patch.object(cm.ck.KitMatrix, "census", side_effect=lambda: census(724, "aaaa")):
        with patch.dict(os.environ):
            os.environ.pop("ABSD_CPORTS_DIAG_REPEAT_ROUNDS", None)
            plain = m.census()
            assert plain == dict(census(724, "aaaa"), fsd=31)
            os.environ["ABSD_CPORTS_DIAG_REPEAT_ROUNDS"] = "10"
            assert m.census() == dict(plain, fsd_free=7, settled=742)
    assert "fsd_free" not in m.JUDGED and "settled" not in m.JUDGED
    name = "posix.lock-contention"
    base = dict(census(720, "aaaa"), fsd=27, fsd_free=3, settled=700)

    def run(values, diag=None, method=cm.CportsMatrix.repeat_round):
        m = matrix(work, linux)
        m.highwater, m.ran, m.first = [name], {name: cases[name]}, {name: "same"}
        calls = []
        m.scenario_lock_contention = lambda c, repeat=None: calls.append(repeat) or "same"
        readings = iter([base] + [dict(base, memory=census(720 + n, "aaaa")["memory"],
                                     fsd=27 + n, fsd_free=3 + n, settled=700 + 42 * k)
                                  for k, n in enumerate(values, 1)])
        m.stable = lambda *args: next(readings)
        buf, error = io.StringIO(), None
        with patch.dict(os.environ):
            os.environ.pop("ABSD_CPORTS_DIAG_REPEAT_ROUNDS", None)
            if diag is not None:
                os.environ["ABSD_CPORTS_DIAG_REPEAT_ROUNDS"] = str(diag)
            with contextlib.redirect_stdout(buf):
                try:
                    method(m)
                except (cm.sm.Failed, cm.ck.sm.Failed) as exc:
                    error = str(exc)
        return buf.getvalue(), error, calls

    ordinary, error, calls = run([0, 0, 0, 0])
    assert error is None and calls == [0, 1, 2] and "DIAG" not in ordinary
    assert "CPORTS RESOURCES REPEAT OK rounds=2 " in ordinary
    assert "CPORTS REPEAT WARM frames=+0 fsd_heap=+0 multiple4=yes kernel_equal=yes" in ordinary
    warm, error, calls = run([4, 4, 4, 4])
    assert error is None and calls == [0, 1, 2]
    assert "CPORTS REPEAT WARM frames=+4 fsd_heap=+4 multiple4=yes kernel_equal=yes" in warm
    # Readings are warm, fresh post-warm stable baseline, then judged rounds.
    # Distinct warm/baseline readings catch judging against the warm snapshot.
    for diag in (None, 2):
        text, error, calls = run([4, 0, 0, 0], diag)
        assert error is None and calls == [0, 1, 2], text
        assert "CPORTS RESOURCES REPEAT OK rounds=2 " in text, text
        text, error, calls = run([4, 0, 4, 4], diag)
        assert error and "repeat round 1" in error and "REPEAT OK" not in text, text
        assert calls == ([0, 1] if diag is None else [0, 1, 2]), calls
    print("CPORTS SELFTEST POST-WARM BASELINE OK :: warm differs; judged matches baseline passes, warm fails")
    for values in ([4, 4, 8], [4, 4, 4, 8]):
        text, error, calls = run(values)
        assert error and "repeat round" in error and "REPEAT OK" not in text, text
    for step in (8, 3, -4):
        text, error, calls = run([step])
        assert error and calls == [0] and "repeat warm:" in error, text
    for values, first, later in (([4] * 10, "none", 0), ([4, 8, 8, 12], 2, 1),
                                 ([0, 4, 8, 12], 2, 2), ([0] * 3, "none", 0),
                                 ([4, 0, 0], "none", 0)):
        # Warm and a separately settled baseline precede diagnostic round 1.
        text, error, calls = run([4, 4] + values, len(values))
        assert calls == list(range(0, len(values) + 1)), calls
        assert bool(error) == any(n != 4 for n in values), text
        previous = 4
        for k, n in enumerate(values, 1):
            delta = n - previous
            expected = (f"CPORTS DIAG ROUND {k} frames={720+n} handles=66 pipes=27 cells=1 "
                        f"fsd_heap={27+n} fsd_free={3+n} settled={700+42*(k+2)} "
                        f"step_vs_prev=frames:{delta:+d},fsd_heap:{delta:+d}")
            assert expected in text.splitlines(), text
            previous = n
        assert (f"CPORTS DIAG PLATEAU rounds={len(values)} first_step_round={first} "
                f"later_steps={later}") in text.splitlines(), text
        assert ("CPORTS RESOURCES REPEAT OK" in text) == (error is None)
    with patch.dict(os.environ):
        os.environ.pop("ABSD_CPORTS_DIAG_REPEAT_ROUNDS", None)
        assert cm.repeat_boot_budget(3600) == 5400
        assert cm.repeat_boot_budget(1) == 1.5
        for invalid in (0, -1):
            try:
                cm.repeat_boot_budget(invalid)
            except ValueError:
                pass
            else:
                raise AssertionError(f"invalid base budget accepted: {invalid}")
        os.environ["ABSD_CPORTS_DIAG_REPEAT_ROUNDS"] = "10"
        assert cm.repeat_boot_budget(3600) == 19800
        for invalid in ("1", "0", "-1", "bad"):
            os.environ["ABSD_CPORTS_DIAG_REPEAT_ROUNDS"] = invalid
            try:
                cm.repeat_boot_budget(3600)
            except ValueError:
                pass
            else:
                raise AssertionError(f"invalid diagnostic rounds accepted: {invalid}")
    print("CPORTS SELFTEST DIAG REPEAT OK :: warm then exact baseline; FAIL retained; plateau, slope, fall; boot budget")


def repeat_scenario_section(work, linux, cases):
    failed = (cm.sm.Failed, cm.ck.sm.Failed)
    name = "posix.lock-contention"
    case = cases[name]
    assert case.route == "scenario" and case.retained == ["l"], (case.route, case.retained)
    assert cm.CportsMatrix.repeatable(name), "posix.lock-contention is not repeatable()"
    assert name not in cm.REPEATABLE and name not in cm.CHAIN_OF

    def posix_census(frames, fsd):
        c = census(frames, "aaaa")
        c["objects"] = c["objects"] + [(f"{cm.CPORTS}/posix/l", False, False, 0, "e3b0")]
        return dict(c, fsd=fsd)

    # The first run's reading (sshd-013.serial.log): frames 716 -> 720, heap peak 20 -> 24.
    m = matrix(work, linux)
    m.first = {}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        m.compare_census(case, posix_census(716, 20), posix_census(720, 24))
    sys.stdout.write(buf.getvalue())
    assert m.highwater == [name] and "HIGHWATER UNREPEATABLE" not in buf.getvalue(), buf.getvalue()
    assert f"CPORTS RESOURCES HIGHWATER {name} :: frames 716 -> 720 (+4)" in buf.getvalue(), buf.getvalue()
    print("CPORTS SELFTEST REPEAT SCENARIO REPEATABLE OK :: posix.lock-contention takes its high-water "
          "(no UNREPEATABLE)", flush=True)

    stated = ("try shared: -1 EAGAIN\ntry exclusive: -1 EAGAIN", "try shared: 0 0\ntry exclusive: 0 0", "Linux equal")

    def repeat_matrix(after_rounds, says=stated):
        m = matrix(work, linux)
        m.highwater, m.ran, m.first = [name], {name: case}, {name: stated}
        calls = []
        m.scenario_lock_contention = lambda c, repeat=None: calls.append((c.name, repeat)) or says
        readings = iter([posix_census(720, 24)] * 3 + after_rounds)
        m.stable = lambda key, when: next(readings)
        return m, calls

    for label, changed in (
            ("frames +5", posix_census(725, 24)),
            ("kernel objects", dict(posix_census(720, 24), kernel="kernel: changed")),
            ("object names", dict(posix_census(720, 24), objects=[])),
            ("images", dict(posix_census(720, 24), images=1))):
        m, calls = repeat_matrix([])
        readings = iter([posix_census(720, 24), changed])
        m.stable = lambda *args: next(readings)
        result, text = captured(m.repeat_round)
        assert isinstance(result, failed) and "repeat warm:" in str(result), (label, text)
        assert calls == [(name, 0)], calls
    print("CPORTS SELFTEST WARM REFUSAL OK :: frames +5, kernel objects, names and images")

    # Equal censuses after both rounds: REPEAT OK, the scenario run once per round.
    m, calls = repeat_matrix([posix_census(720, 24), posix_census(720, 24)])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        m.repeat_round()
    sys.stdout.write(buf.getvalue())
    assert calls == [(name, 0), (name, 1), (name, 2)], calls
    line = [l for l in buf.getvalue().splitlines() if l.startswith("CPORTS RESOURCES REPEAT OK ")]
    assert len(line) == 1 and f"repeated={name} " in line[0] and f"(high-water cases: {name})" in line[0], line
    print(f"CPORTS SELFTEST REPEAT SCENARIO OK :: equal censuses after both rounds -> {line[0]}", flush=True)

    # The heap peak moves again on repeat (and frames with it): the run fails, as a growing pair does.
    for label, rounds, says in (("the heap peak 24 -> 28", [posix_census(724, 28), posix_census(724, 28)], stated),
                                ("the heap peak 24 -> 28 in round 2", [posix_census(720, 24), posix_census(724, 28)],
                                 stated),
                                ("the peak alone 24 -> 28", [posix_census(720, 28), posix_census(720, 28)], stated),
                                ("another after-kill text", [posix_census(720, 24), posix_census(720, 24)],
                                 (stated[0], "try shared: -1 EAGAIN\ntry exclusive: -1 EAGAIN", stated[2]))):
        m, _ = repeat_matrix(rounds, says)
        try:
            m.repeat_round()
        except failed:
            continue
        raise SystemExit(f"the repeat round passed posix.lock-contention with {label}")
    print("CPORTS SELFTEST REPEAT SCENARIO GROWS OK :: a heap peak that moves again on repeat (24 -> 28), or "
          "another scenario text, fails the repeat round", flush=True)


def captured(fn, *a):
    """Runs fn(*a) with stdout captured (and echoed); returns (result or the
    Failed raised, the text printed)."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            result = fn(*a)
    except (cm.sm.Failed, cm.ck.sm.Failed) as e:
        result = e
    finally:
        sys.stdout.write(buf.getvalue())
    return result, buf.getvalue()


def posix_census(frames, fsd, **kw):
    c = census(frames, "aaaa")
    c["objects"] = c["objects"] + [(f"{cm.CPORTS}/posix/l", False, False, 0, "e3b0")]
    return dict(c, fsd=fsd, **kw)


def heap_step_section(work, linux, cases):
    failed = (cm.sm.Failed, cm.ck.sm.Failed)
    name = "posix.lock-contention"
    case = cases[name]
    classes = {4: "pool-sized", 3: "not pool-sized (a dedicated block, or over-aligned or >64-page pool growth)"}
    for n, kind in classes.items():
        want = f"fsd heap peak 20 -> {20 + n} (+{n} pages, {kind})"
        # Recorded for a REPEAT_SCENARIOS scenario, exactly as before.
        m = matrix(work, linux)
        result, text = captured(m.compare_census, case, posix_census(716, 20), posix_census(716 + n, 20 + n))
        assert not isinstance(result, failed), result
        line = [l for l in text.splitlines() if l.startswith(f"CPORTS RESOURCES HIGHWATER {name} :: ")]
        assert len(line) == 1 and want in line[0] and m.highwater == [name], (line, m.highwater)
        assert "UNREPEATABLE" not in text, text
        # Fails UNREPEATABLE on a case that is not repeatable, exactly as before.
        m = matrix(work, linux)
        other = cm.Case(["sqlite.excl-setup", "shell", "speedtest", "-", "-", "/bin/sqlite3"])
        other.retained = ["st.db"]
        before = dict(census(721, "aaaa"), fsd=20)
        after = dict(census(721 + n, "bbbb"), fsd=20 + n)
        result, text = captured(m.compare_census, other, before, after)
        assert isinstance(result, failed) and "HIGHWATER UNREPEATABLE sqlite.excl-setup" in text, text
        assert want in text and want in str(result), (text, result)
        print(f"CPORTS SELFTEST HEAP STEP HIGHWATER OK :: +{n} prints '{kind}' ({line[0]}); recorded for {name}, "
              f"UNREPEATABLE elsewhere", flush=True)

    # A repeat round whose heap peak steps fails as before, naming the class.
    stated = ("held", "after kill", "Linux equal")
    for n, kind in classes.items():
        m = matrix(work, linux)
        m.highwater, m.ran, m.first = [name], {name: case}, {name: stated}
        m.scenario_lock_contention = lambda c, repeat=None: stated
        seq = [posix_census(720, 24)] * 6 + [posix_census(720, 24 + n)]
        m.census = lambda: seq.pop(0) if len(seq) > 1 else seq[0]     # stable() judges these (ruling (b))
        result, text = captured(m.repeat_round)
        want = f"fsd heap peak 24 -> {24 + n} (+{n} pages, {kind})"
        assert isinstance(result, failed) and want in str(result) and "REPEAT OK" not in text, (result, text)
    print("CPORTS SELFTEST HEAP STEP REPEAT OK :: a repeat round stepping +4 or +3 (judged by stable(), not "
          "stubbed) fails, naming 'pool-sized' / 'not pool-sized'", flush=True)

    # frames_step: a frames move with the heap peak moved is refused, naming the class.
    m = matrix(work, linux)
    result, _ = captured(m.frames_step, "x", posix_census(716, 20), posix_census(717, 23))
    assert isinstance(result, failed) and "fsd heap peak 20 -> 23 (+3 pages, not pool-sized" in str(result), result
    assert cm.heap_step(24, 20) == "24 -> 20 (-4 pages, released)" and cm.heap_step(24, 21) == "24 -> 21 (-3 pages, released)"
    assert cm.heap_step(31, 31) == "31 (equal)" and cm.heap_step(20, 28) == "20 -> 28 (+8 pages, pool-sized)"
    print("CPORTS SELFTEST HEAP STEP FRAMES OK :: a frames-only step with the heap peak moved fails, naming the class",
          flush=True)


class Held:
    """A held session for frames_warmup: ends at EOF with nothing printed."""
    returncode = 0
    stdin = stdout = stderr = io.BytesIO()

    def communicate(self, data, timeout=None):
        return b"", b""

    def kill(self):
        pass

    def wait(self):
        return 0


class RestartTarget(FakeTarget):
    """A target whose stop/start a cut() can drive: the next boot is boots+1."""
    def __init__(self, image):
        self.image, self.boots, self.log = image, 1, pathlib.Path("sshd-001.serial.log")

    def stop(self):
        pass

    def start(self, expect_sweep=False):
        self.boots += 1
        self.log = pathlib.Path(f"sshd-{self.boots:03d}.serial.log")
        return {"generated": False, "public": "key", "image_changed": True}

    def spawn_count(self):
        return 0

    def await_spawns(self, n, k):
        pass


def at_rest_section(work, linux, cases):
    failed = (cm.sm.Failed, cm.ck.sm.Failed)
    saved = (cm.time.sleep, cm.time.monotonic, cm.SETTLE_SECONDS, cm.AGREE_SECONDS)
    cm.SETTLE_SECONDS, cm.AGREE_SECONDS = 3, 5
    cm.time.sleep = lambda s: None
    clock = iter(range(0, 1 << 30))
    cm.time.monotonic = lambda: next(clock)
    UNCHANGED = "kernel objects and image files unchanged"
    try:
        base = census(721, "aaaa")
        d1 = dict(base, fsd_draining=1)
        o4 = dict(base, fsd_opens=4)
        h67 = dict(base, kernel=base["kernel"].replace("66 handles", "67 handles"))
        h68 = dict(base, kernel=base["kernel"].replace("66 handles", "68 handles"))
        pipes = dict(base, kernel=base["kernel"].replace("27 pipes", "28 pipes"))
        rest = {"opens": 3, "handles": 66, "boot": 1}

        def sampled(readings, cycle=False, m=None):
            """A matrix whose census() returns `readings` in turn, then the last
            forever (or, `cycle`, cycles through them forever)."""
            m = m or matrix(work, linux)
            seq, i = list(readings), [0]

            def census_():
                if cycle:
                    i[0] += 1
                    return seq[(i[0] - 1) % len(seq)]
                return seq.pop(0) if len(seq) > 1 else seq[0]
            m.census = census_
            m.rest = dict(rest)
            return m

        def fails(result, *texts, absent=()):
            assert isinstance(result, failed), result
            assert all(t in str(result) for t in texts) and not any(t in str(result) for t in absent), result

        def transient(text):
            lines = [l for l in text.splitlines() if l.startswith("CPORTS RESOURCES TRANSIENT ")]
            assert len(lines) == 1, text
            return lines[0]

        # REST: the boot's first reading with draining 0 and two equal samples, printed once.
        m = sampled([d1, d1, base])
        m.rest = None
        result, text = captured(m.take_rest, "boot 1 after its first sessions")
        assert result == dict(base, rest_at_judgment=dict(rest)) and m.rest == rest, (result, m.rest)
        rest_line = [l for l in text.splitlines() if l.startswith("CPORTS RESOURCES REST ")]
        assert len(rest_line) == 1 and "boot=1 :: draining=0 opens=3 handles=66" in rest_line[0], text
        m = sampled([d1])
        m.rest = None
        result, _ = captured(m.take_rest, "boot 1 after its first sessions")
        fails(result, "UNSETTLED draining never settled")
        # REST on the restart path: cut() takes the new boot's rest counts (REBASE).
        image = work / "restart.img"
        image.write_bytes(b"img")
        new = dict(base, fsd_opens=5, kernel=base["kernel"].replace("66 handles", "70 handles"))
        m = sampled([d1, new, new])
        m.t = RestartTarget(image)
        m.host_key, m.case_before, m.restart_round = "key", base, 1
        result, text = captured(m.cut, cases["sqlite.excl-crash"], Held(), "spilled")
        assert not isinstance(result, failed) and m.rest == {"opens": 5, "handles": 70, "boot": 2}, (result, m.rest)
        assert "CPORTS RESOURCES REST boot=2 :: draining=0 opens=5 handles=70" in text, text
        assert "CPORTS RESOURCES REBASE" in text and m.rebased == dict(new, rest_at_judgment={"boot": 2, "handles": 70, "opens": 5}), text
        # Three samples: a two-sample N5 (67, 67) is never taken as the rest reading.
        m = sampled([h67, h67, base, base, base])
        m.rest = None
        result, text = captured(m.take_rest, "boot 1 after its first sessions")
        assert result == dict(base, rest_at_judgment=dict(m.rest)) and m.rest["handles"] == 66, (result, m.rest)
        assert "TRANSIENT rest boot 1 after its first sessions :: handles 67" in text, text
        # Lowered, never raised: a settled pair below rest lowers it (LOWERED; the summary RECORDED line) ...
        h65 = dict(base, kernel=base["kernel"].replace("66 handles", "65 handles"), fsd_opens=2)
        m = sampled([h65, h65])
        after, text = captured(m.stable, "sqlite.x", "after")
        assert after == dict(h65, rest_at_judgment={"boot": 1, "handles": 65, "opens": 2}) and m.rest["handles"] == 65 and m.rest["opens"] == 2, (after, m.rest)
        assert ("CPORTS RESOURCES REST LOWERED boot=1 :: handles 66 -> 65 (earlier censuses of this boot were "
                "judged against 66") in text and "REST LOWERED boot=1 :: opens 3 -> 2" in text, text
        _, text = captured(m.rest_recorded)
        assert text.startswith("CPORTS RESOURCES RECORDED rest lowered 2 time(s) (not a failure) :: ") and \
            "handles 66 -> 65" in text, text
        recorded = text.strip()
        # ... and a reading above the lowered rest (66 again) is a settled change, never a raise.
        m.census = lambda: base
        after, text = captured(m.stable, "sqlite.x", "after")
        assert after is base and m.rest["handles"] == 65 and "SETTLED CHANGE" in text, (m.rest, text)
        other_ = cm.Case(["sqlite.excl-setup", "shell", "speedtest", "-", "-", "/bin/sqlite3"])
        other_.retained = ["st.db"]
        result, _ = captured(m.compare_census, other_, h65, after)
        fails(result, "kernel objects and image files unchanged", absent=("UNSETTLED",))
        print(f"CPORTS SELFTEST JUDGED REST THREE/LOWERED OK :: a two-sample 67 is not taken as rest (66 is); "
              f"lowered 66 -> 65 with {recorded[:60]}...; 66 afterwards fails as a settled change", flush=True)
        print(f"CPORTS SELFTEST JUDGED REST OK :: {rest_line[0].split(' (')[0]}; boot 2's rest taken on the "
              f"restart path (opens=5 handles=70); a rest reading stuck at draining 1 fails UNSETTLED", flush=True)

        other = cm.Case(["sqlite.excl-setup", "shell", "speedtest", "-", "-", "/bin/sqlite3"])
        other.retained = ["st.db"]
        changed = census(721, "cccc")       # st.db changed: an allowed path
        # The first sample at rest is judged; the TRANSIENT line records what the window absorbed.
        f20, f24 = dict(changed, fsd=20), dict(changed, fsd=24)
        for label, readings, judged, want in (
                ("bisect run A's N5 shape", [changed, dict(changed, kernel=h67["kernel"]),
                                             dict(changed, kernel=h67["kernel"]), dict(changed, kernel=h67["kernel"]),
                                             changed, changed], changed, "handles 67"),
                ("a reverting heap step", [f20, f24, f20, f20], f20, "fsd heap 24"),
                ("an opens transient", [dict(changed, fsd_opens=4), dict(changed, fsd_opens=4), changed, changed],
                 changed, "opens 4")):
            m = sampled(readings)
            after, text = captured(m.stable, other.name, "after")
            assert after == dict(judged, rest_at_judgment=dict(rest)), (label, after)
            line = transient(text)
            assert want in line and "judged at rest" in line, (label, line)
            result, _ = captured(m.compare_census, other, dict(base, fsd=judged["fsd"]), after)
            assert not isinstance(result, failed) and m.judged is after, (label, result)
            print(f"CPORTS SELFTEST JUDGED AT REST OK :: {label} judged at rest :: {line}", flush=True)

        # The heap peak is not a rest field: 24 held for two samples at a settle is judged (and charged).
        m = sampled([f20, f24, f24, f20])
        after, _ = captured(m.stable, other.name, "after")
        assert after == dict(f24, rest_at_judgment=dict(rest)), after
        print("CPORTS SELFTEST JUDGED HEAP HELD OK :: 20, 24, 24, 20 is judged at 24 (two samples at a settle)",
              flush=True)

        # SETTLED CHANGE: no sample at rest; the last settled reading is judged and the existing checks fail it.
        m = sampled([h67])
        after, text = captured(m.stable, other.name, "after")
        assert after is h67 and "UNSETTLED" not in text and "SETTLED CHANGE" in transient(text), text
        result, _ = captured(m.compare_census, other, base, after)
        fails(result, f"resources after {other.name}", UNCHANGED, absent=("UNSETTLED",))
        m = sampled([h67])
        result, _ = captured(m.compare_census, other, base, h67)
        fails(result, UNCHANGED, absent=("UNSETTLED",))
        m = sampled([o4])
        after, _ = captured(m.stable, other.name, "after")
        assert after is o4, after
        result, text = captured(m.compare_census, other, base, after)
        fails(result, "the file server's opens unchanged (at the boot's rest count 3)", "opens 3 -> 4",
              absent=("UNSETTLED",))
        assert f"ok   resources after {other.name}: images, frames, {UNCHANGED}" in text, text
        m = sampled([h67, h67, h68, h68], cycle=True)
        after, text = captured(m.stable, other.name, "after")
        assert after in (h67, h68) and "SETTLED CHANGE" in transient(text), text
        result, _ = captured(m.compare_census, other, base, after)
        fails(result, UNCHANGED, absent=("UNSETTLED",))
        m = sampled([pipes])
        result, _ = captured(m.compare_census, other, base, m.stable(other.name, "after"))
        fails(result, UNCHANGED, absent=("UNSETTLED",))
        # A case-before reading off rest (handles; opens).
        m = sampled([h67])
        result, _ = captured(m.compare_census, other, h67, h67)
        fails(result, UNCHANGED)
        m = sampled([base])
        result, _ = captured(m.compare_census, other, o4, base)
        fails(result, f"resources before {other.name}: the file server's opens unchanged")
        print("CPORTS SELFTEST JUDGED SETTLED CHANGE OK :: a persistent +1 handle (stable() and compare_census), opens "
              "above rest, an oscillation 67/68, a pipes +1 and a case-before off rest each fail their existing check",
              flush=True)

        # UNSETTLED: no consecutive pair agrees; draining never 0.
        m = sampled([h67, base], cycle=True)
        result, text = captured(m.stable, other.name, "after")
        fails(result, "UNSETTLED handles never settled", "the census settled within 8 s", absent=(UNCHANGED,))
        assert f"CPORTS RESOURCES UNSETTLED {other.name} after :: handles " in text, text
        m = sampled([d1])
        result, text = captured(m.stable, other.name, "after")
        fails(result, "UNSETTLED draining never settled", absent=(UNCHANGED,))
        print(f"CPORTS SELFTEST JUDGED UNSETTLED OK :: handles never agreeing -> UNSETTLED handles; draining stuck -> "
              f"{str(result).split(': ', 1)[1]}", flush=True)

        # The repeat rounds.
        name = "posix.lock-contention"
        case = cases[name]
        stated = ("held", "after kill", "Linux equal")
        at = posix_census(720, 24)
        at67 = dict(at, kernel=at["kernel"].replace("66 handles", "67 handles"))
        for label, readings, want in (
                ("pre-round +1 handle absorbed", [at67, at67, at, at], None),
                ("round 1 draining stuck", [at, at, dict(at, fsd_draining=1)], "UNSETTLED draining never settled"),
                ("round 1 settled at +1 handle", [at] * 6 + [at67], "repeat round 1: images, frames, kernel objects"),
                ("round 1 opens off rest", [at] * 6 + [dict(at, fsd_opens=4)],
                 "repeat round 1: the file server's opens unchanged"),
                ("pre-round opens off rest", [dict(at, fsd_opens=4)], "repeat before: the file server's opens unchanged")):
            m = sampled(readings)
            m.highwater, m.ran, m.first = [name], {name: case}, {name: stated}
            m.scenario_lock_contention = lambda c, repeat=None: stated
            result, text = captured(m.repeat_round)
            if want is None:
                assert not isinstance(result, failed) and "CPORTS RESOURCES REPEAT OK " in text, (result, text)
                assert "handles 67" in transient(text), text
            else:
                fails(result, want)
        print("CPORTS SELFTEST JUDGED REPEAT OK :: a pre-round +1 transient absorbed (TRANSIENT handles 67); a round "
              "stuck at draining 1 UNSETTLED; a round at +1 handle, opens off rest before or in a round fail", flush=True)

        # rest_kernel / rest_opens: the frames warmup and the restart repeat.
        for label, readings, want in (("warmup after +1 handle", [base, base, h67], "frames warmup: kernel objects unchanged"),
                                      ("warmup rest opens", [o4], "frames warmup rest: the file server's opens")):
            m = sampled(readings)
            m.t = RestartTarget(image)
            m.hold = lambda text: Held()
            m.ssh = lambda cmd: (0, b"", b"")
            m.steps = 0
            result, _ = captured(m.frames_warmup)
            fails(result, want)
        crash = cases["sqlite.excl-crash"]
        r = (0, b"ok\n3\n", b"", 1.0)
        for label, readings, want in (("repeat +1 handle", [base, base, h67], "restart repeat 1: kernel objects unchanged"),
                                      ("base opens", [o4], "restart repeat base: the file server's opens"),
                                      ("base handles", [h67], "restart repeat base: kernel objects unchanged")):
            m = sampled(readings)
            m.restart_round = 1
            m.sqlite_absd = lambda case, db, sql: r
            result, _ = captured(m.restart_repeat, crash, "x.db", "SELECT 1;", r)
            fails(result, want)
        print("CPORTS SELFTEST JUDGED REST CHECKS OK :: handles or opens off rest fail the frames warmup and the "
              "restart repeat (base and repeat)", flush=True)

        # The inheriting harnesses: their censuses are CportsMatrix.census and carry the fsd keys.
        sysinfo = (base["memory"], base["kernel"])
        for script, cls in (("tcc-matrix", "TccMatrix"), ("clang-guest-matrix", "ClangMatrix"),
                            ("userland-matrix", "UserlandMatrix")):
            spec_ = importlib.util.spec_from_file_location(script.replace("-", "_") + "_st", here / f"{script}.py")
            mod = importlib.util.module_from_spec(spec_)
            spec_.loader.exec_module(mod)
            klass = getattr(mod, cls)
            sub_cm = mod.cm
            assert klass.census is sub_cm.CportsMatrix.census and klass.stable is sub_cm.CportsMatrix.stable, cls
            sub_cm.SETTLE_SECONDS, sub_cm.AGREE_SECONDS = 3, 5
            for draining, ok in ((0, True), (1, False)):
                m = klass.__new__(klass)
                m.checks, m.passed = 0, []
                t = FakeTarget()
                t.serial = lambda d=draining: (f"FSD CAPACITY boot=0 settled_releases=0 fs_objects=1 rotated_logs=0 "
                                               f"bound=1 opens=3 draining={d} heap_pages_peak=26\n")
                t.system_objects = lambda: []
                t.output = lambda: ('SERVED CAPACITY boot=' + 'a' * 32 +
                                    ' accepted_reclaimed=0 slots=0 pool=0 processes=3 handles=57 '
                                    'pipes=24 cells=1 frames=619 heap_pages_peak=222\n')
                m.connections = 0
                m.t, m.sysinfo = t, (lambda: sysinfo)
                c = m.census()
                assert (c["fsd_opens"], c["fsd_draining"], c["fsd"]) == (3, draining, 26), c
                sub_failed = (sub_cm.sm.Failed, sub_cm.ck.sm.Failed)
                try:
                    result = m.stable("x", "after")
                except sub_failed as e:
                    result = e
                if ok:
                    assert not isinstance(result, (sub_cm.sm.Failed, sub_cm.ck.sm.Failed)), result
                else:
                    assert isinstance(result, (sub_cm.sm.Failed, sub_cm.ck.sm.Failed)), result
                    assert "UNSETTLED draining never settled" in str(result), result
            # R1: the base class takes this boot's rest before the first judged census; run A's shape is judged at 66.
            m = klass.__new__(klass)
            m.checks, m.passed, m.t = 0, [], FakeTarget()
            shape = [base] * 5 + [h67, h67, h67, base, base]
            m.census = lambda: shape.pop(0) if len(shape) > 1 else shape[0]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                result = m.stable("x", "after")
            sys.stdout.write(buf.getvalue())
            assert result == dict(base, rest_at_judgment=dict(m.rest)) and m.rest["handles"] == 66 and m.rest_boot == 1, (cls, result, m.rest)
            assert "CPORTS RESOURCES REST boot=1 :: draining=0 opens=3 handles=66" in buf.getvalue(), buf.getvalue()
            assert "TRANSIENT x after :: handles 67 (judged at rest" in buf.getvalue(), buf.getvalue()
        print("CPORTS SELFTEST JUDGED SUBCLASSES OK :: TccMatrix, ClangMatrix and UserlandMatrix inherit "
              "CportsMatrix.census (fsd keys) and stable(): the base class takes each boot's rest (REST boot=1 "
              "handles=66) and run A's shape is judged at 66 (TRANSIENT handles 67); draining stuck at 1 fails "
              "UNSETTLED", flush=True)
    finally:
        cm.time.sleep, cm.time.monotonic, cm.SETTLE_SECONDS, cm.AGREE_SECONDS = saved


if __name__ == "__main__":
    main()
