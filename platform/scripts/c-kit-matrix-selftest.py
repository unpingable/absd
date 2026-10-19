#!/usr/bin/env python3
"""Host-only checks of scripts/c-kit-matrix.py's resource readings (no QEMU).

A fake boot models the N5 transient seen on 2026-10-12 (c-kit attempt 1,
`exit _Exit`): a sysinfo session opened before sshd's quiescent SERVED
CAPACITY line for the previous connection reads the kernel's handles one
above rest (67 for 66); sshd prints that line a few polls after the
session ended.

1. CONTROL: the fake reproduces the artefact: a sysinfo opened without
   waiting for quiescence reads 67 handles.
2. TRANSIENT BEFORE: with the previous session not yet quiescent, the
   before-reading (stable(confirm=True)) is 66, and a case that leaves
   nothing behind passes compare_census.
3. REAL +1 AFTER: a case that keeps one handle fails compare_census.
4. QUIESCENCE COUNT: a SERVED CAPACITY line for fewer connections than the
   matrix opened is not quiescence; none at all fails within the bound.
5. UNSETTLED: a before-reading that never agrees fails as
   C KIT RESOURCES UNSETTLED instead of returning an unconfirmed reading.

6. SUBCLASSES: CportsMatrix and TccMatrix built by their own __init__
   (which skips KitMatrix.__init__) over a fake transport: ssh() counts
   connections from 0, and CportsMatrix.shell_ssh (the path of the
   2026-10-12 AttributeError) runs; both keep QUIESCENT_READINGS False.
   Reads (never writes) the campaign's cports-build, upstream and tcc-build.

Usage: c-kit-matrix-selftest.py [--campaign <dir with cports-build, upstream,
tcc-build>; default the worktree's parent] [--work <empty dir>; default a
temporary directory]. Prints C KIT SELFTEST OK checks=<n>."""
import argparse, importlib.util, pathlib, sys, tempfile, types

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
spec = importlib.util.spec_from_file_location("c_kit_matrix", here / "c-kit-matrix.py")
ck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ck)
sm = ck.sm

REST = 66
OBJECTS = [("/home/operator/x", False, False, 1, "00")]


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, s):
        self.now += s


class FakeBoot:
    """sshd's stream and the kernel's handle count. `delay` output() polls
    pass between a session's end and its quiescent line."""

    def __init__(self, delay=3):
        self.lines, self.pending = ["SSH LISTENING"], []
        self.delay, self.leaked, self.reclaimed, self.flap = delay, 0, 0, None

    def output(self):
        if self.pending:
            line = self.pending.pop(0)
            if line is not None:
                self.lines.append(line)
        return "\n".join(self.lines) + "\n"

    def all_images(self):
        return 0

    def system_objects(self):
        return list(OBJECTS)

    def census_detail(self):
        return "fake"

    def handles(self):
        if self.flap is not None:
            self.flap ^= 1
            return REST + self.flap
        return REST + self.leaked + (1 if self.pending else 0)

    def session_ended(self, quiescent=True):
        self.reclaimed += 1
        self.lines.append(f"SSH SESSION RECLAIMED children_started={self.reclaimed}")
        if quiescent:
            self.pending += [None] * self.delay + [
                f"SERVED CAPACITY boot={'0' * 32} accepted_reclaimed={self.reclaimed} slots=0 pool=0 net_sockets=1 "
                f"net_closing=0 processes=4 handles={REST + self.leaked} pipes=27 cells=1 frames=707 "
                f"heap_pages_peak=9"]


def matrix(boot):
    m = ck.KitMatrix.__new__(ck.KitMatrix)
    m.checks, m.passed, m.t, m.connections = 0, [], boot, 0

    def ssh(command=None, **kw):
        m.connections += 1
        if command == "/bin/sysinfo":
            out = (f"memory: 122624 KiB free, 2828 KiB allocated (30656 + 707 frames of 4096 bytes)\n"
                   f"kernel: 4 process slots, {boot.handles()} handles, 27 pipes, 1 cells\n").encode()
        else:
            out = b""
        boot.session_ended()
        return 0, out, b""
    m.ssh = ssh
    return m


def handles(reading):
    return int(reading["kernel"].split(", ")[1].split()[0])


def fails(fn, needle):
    try:
        fn()
    except sm.Failed as e:
        return needle in str(e)
    return False


class FakeTransport:
    """A boot and an SSH client in one: each session ends reclaimed, with
    sshd's CHILD line for absd-sh, the program spawned under it, and the
    quiescent line for the connections so far."""

    def __init__(self, root):
        self.root, self.lines, self.serial_lines, self.n = root, ["SSH LISTENING"], [], 0

    def output(self):
        return "\n".join(self.lines) + "\n"

    def serial(self):
        return "\n".join(self.serial_lines) + "\n"

    def all_images(self):
        return 0

    def census_detail(self):
        return "fake"

    def run(self, key, command=None, stdin=b"", extra=(), timeout=120):
        self.n += 1
        shell = 100 + 2 * self.n
        self.lines.append(f"SSH SESSION CHILD pid={shell} spawn_right=true argv0=/bin/absd-sh fs_slot=1 control=true")
        self.serial_lines.append(f"SPAWN OK pid={shell + 1} parent={shell} program=image")
        self.lines.append(f"SSH SESSION RECLAIMED children_started={self.n}")
        self.lines.append(f"SERVED CAPACITY boot={'0' * 32} accepted_reclaimed={self.n} slots=0 pool=0 "
                          f"net_sockets=1 net_closing=0 processes=4 handles={REST} pipes=27 cells=1 frames=707 "
                          f"heap_pages_peak=9")
        return 0, b"out\n", b""


def subclasses(want, campaign, work):
    """CportsMatrix and TccMatrix through their real constructors."""
    repo = here.parent
    platform = work / "platform"
    (platform / "commands").mkdir(parents=True, exist_ok=True)
    for name in ("cp", "sha256sum", "head", "mkdir", "cat", "df", "sysinfo", "ls"):
        (platform / "commands" / name).write_bytes(b"\x7fELF fake")
    tm = None
    for label, build in (("cports", None), ("tcc", None)):
        if label == "cports":
            spec_ = importlib.util.spec_from_file_location("cports_matrix_st", here / "cports-matrix.py")
            cm = importlib.util.module_from_spec(spec_)
            spec_.loader.exec_module(cm)
            args = types.SimpleNamespace(absd=campaign / "cports-build" / "absd", linux=campaign / "cports-build" / "linux",
                                         upstream=campaign / "upstream", cases=repo / "cports" / "cases.tsv",
                                         only=None, pin=None, skip_scenarios=False)
            target = FakeTransport(platform)
            d = work / "cports"
            d.mkdir(exist_ok=True)
            m = cm.CportsMatrix(target, d, args)
            klass = cm.CportsMatrix
        else:
            spec_ = importlib.util.spec_from_file_location("tcc_matrix_st", here / "tcc-matrix.py")
            tm = importlib.util.module_from_spec(spec_)
            spec_.loader.exec_module(tm)
            args = types.SimpleNamespace(tcc_build=campaign / "tcc-build", kit=repo, cases=repo / "tcc" / "cases.tsv",
                                         only=None, pin=None)
            target = FakeTransport(platform)
            d = work / "tcc"
            d.mkdir(exist_ok=True)
            m = tm.TccMatrix(target, d, args)
            klass = tm.TccMatrix
        want(f"{label}: the constructor skips KitMatrix.__init__ and the counter still starts at 0",
             "connections" not in vars(m) and m.connections == 0, vars(m).get("connections"))
        want(f"{label}: QUIESCENT_READINGS is off", klass.QUIESCENT_READINGS is False)
        m.client = types.SimpleNamespace(run=target.run)
        m.ssh("/bin/sysinfo")
        m.ssh("/bin/sysinfo")
        want(f"{label}: ssh() counts two connections", m.connections == 2, m.connections)
        if label == "cports":
            rc, out, err, shell, programs = m.shell_ssh('"/bin/printenv"')
            want("cports: shell_ssh (session_probes' path) runs and counts", (rc, out, m.connections, len(programs))
                 == (0, b"out\n", 3, 1), (rc, out, m.connections, programs))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign", default=str(here.parent.parent))
    ap.add_argument("--work")
    args = ap.parse_args()
    ck.time = Clock()
    checks = 0

    def want(name, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"  {'ok  ' if ok else 'FAIL'} {name}{(': ' + str(detail)) if not ok else ''}", flush=True)
        if not ok:
            sys.exit(1)

    # 1. The fake reproduces the 2026-10-12 artefact without the gate.
    boot = FakeBoot()
    m = matrix(boot)
    m.ssh("previous case")
    memory, kernel = ck.KitMatrix.sysinfo(m)
    want("control: sysinfo opened before quiescence reads +1 handle (the N5 transient)", f"{REST + 1} handles" in kernel,
         kernel)

    # 2. A transient before the case does not fail it.
    boot = FakeBoot()
    m = matrix(boot)
    m.ssh("previous case")
    before = m.stable("exit _Exit", "before", confirm=True)
    want("transient before: the before-reading is taken at quiescence (66)", handles(before) == REST, before["kernel"])
    want("transient before: the reading carries the quiescent line it waited for",
         before["quiescent"]["accepted_reclaimed"] == m.connections - 1 and before["quiescent"]["handles"] == REST,
         before["quiescent"])
    m.ssh("/bin/exit _Exit")
    after = m.stable("exit _Exit", "after")
    try:
        m.compare_census("exit _Exit", before, after)
        ok = True
    except sm.Failed as e:
        ok = str(e)
    want("transient before: a case that leaves nothing passes compare_census", ok is True, ok)

    # 3. A real +1 after the case fails.
    boot = FakeBoot()
    m = matrix(boot)
    m.ssh("previous case")
    before = m.stable("leaky", "before", confirm=True)
    boot.leaked = 1
    m.ssh("/bin/leaky")
    after = m.stable("leaky", "after")
    want("real +1 after: the after-reading keeps the handle (67)", handles(after) == REST + 1, after["kernel"])
    want("real +1 after: compare_census fails",
         fails(lambda: m.compare_census("leaky", before, after), "resources after leaky"))

    # 4. Quiescence is for every connection the matrix opened.
    boot = FakeBoot(delay=0)
    m = matrix(boot)
    m.ssh("one")
    boot.session_ended(quiescent=False)   # a second session sshd has not declared quiescent
    m.connections += 1
    boot.output()
    want("quiescence count: a SERVED line for fewer connections is not quiescence",
         fails(m.quiescent, f"for {m.connections} connections"))
    want("quiescence count: the wait is bounded (60 s)", ck.time.now >= ck.QUIESCE_SECONDS)
    boot = FakeBoot(delay=0)
    m = matrix(boot)
    m.ssh("one")
    boot.output()
    want("quiescence count: the line for every connection is quiescence", m.quiescent()["accepted_reclaimed"] == 1)

    # 5. A before-reading that never agrees is UNSETTLED, never unconfirmed.
    boot = FakeBoot(delay=0)
    m = matrix(boot)
    m.ssh("previous case")
    boot.flap = 0
    want("unsettled: no agreement within 60 s fails as C KIT RESOURCES UNSETTLED",
         fails(lambda: m.stable("flappy", "before", confirm=True), "C KIT RESOURCES UNSETTLED flappy before"))
    boot = FakeBoot(delay=0)
    m = matrix(boot)
    m.ssh("previous case")
    boot.flap = 0
    last = m.stable("flappy", "after")
    want("unsettled: the after-reading's rule is unchanged (the last reading after 20 s)", "handles" in last["kernel"])

    # 6. Subclasses through their own constructors (real clock: keygen runs).
    import time as real_time
    ck.time = real_time
    work = pathlib.Path(args.work) if args.work else pathlib.Path(tempfile.mkdtemp(prefix="c-kit-selftest-"))
    work.mkdir(parents=True, exist_ok=True)
    subclasses(want, pathlib.Path(args.campaign).resolve(), work.resolve())

    print(f"C KIT SELFTEST OK checks={checks}", flush=True)


if __name__ == "__main__":
    main()
