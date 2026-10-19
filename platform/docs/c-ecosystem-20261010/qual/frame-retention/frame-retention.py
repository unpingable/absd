#!/usr/bin/env python3
"""Qualification case A15: the one-frame step after the first concurrent
SSH session. One `net fsd` boot (scripts/ssh_absd.py) and a fixed session
sequence: singles, then 2, 3 and 4 sessions open at once, each followed by
singles. After every step the boot is read at rest, from three sources:

  served  sshd's own quiescent line `SERVED CAPACITY ... frames=F
          heap_pages_peak=H` (F: the kernel's allocated frames from
          resource_census; H: sshd's runtime heap_mapped_pages(), its
          currently mapped heap pages including retained pool pages),
          printed once per reclaimed count with no session open;
  fsd     the file server's latest `FSD CAPACITY ... heap_pages_peak=H`;
  sysinfo the matrix's reading: sysinfo's allocated frames, taken by its
          own session (so it includes that session's frames).

--mode native: singles are `echo` and `printenv` under absd-sh, and
sysinfo; the held program of a concurrent group is `/bin/head -c 1` under
absd-sh. --mode native-exec: the same, but `echo` and `printenv` are
exec'd by sshd without a shell, so no absd-sh session precedes the first
concurrent group.
--mode c: singles are the C kit's `/bin/hello` under absd-sh and sysinfo;
the held program is `/bin/short` (the matrix's warm-up program).
Prints one `A15 STEP` line per step and `A15 RUN OK` at the end."""

import argparse
import pathlib
import re
import subprocess
import sys
import time

scripts = pathlib.Path(__file__).resolve().parents[4] / "scripts"
sys.path.insert(0, str(scripts))
import ssh_absd  # noqa: E402
import importlib.util  # noqa: E402

spec = importlib.util.spec_from_file_location("ssh_matrix", scripts / "ssh-matrix.py")
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)

SCRATCH = "cd /home/operator; "
FRAMES = re.compile(r"\((\d+) \+ (\d+) frames of 4096 bytes\)")
SERVED = re.compile(r"SERVED CAPACITY boot=\S+ accepted_reclaimed=(\d+) .*?handles=(\d+) pipes=(\d+) cells=(\d+) "
                    r"frames=(\d+) heap_pages_peak=(\d+)")
FSD = re.compile(r"FSD CAPACITY .*heap_pages_peak=(\d+)")
HEAP = re.compile(r"HEAP MAP size=(\d+) pages=(\d+) mapped=(\d+)")


class Target(ssh_absd.AbsdTarget):
    extra = ["head", "df", "sysinfo"]
    programs = []

    def files(self, authorized):
        files = super().files(authorized)
        files += [(f"/bin/{n}", (self.root / "commands" / n).read_bytes()) for n in self.extra]
        files += [(f"/bin/{p.name}", p.read_bytes()) for p in self.programs]
        return files


class Run(sm.Matrix):
    def __init__(self, target, work, mode):
        self.mode = mode
        # native: through absd-sh (as the matrix's cases); native-exec:
        # sshd execs the command itself, no shell.
        self.prefix = "" if mode == "native-exec" else SCRATCH
        super().__init__(target, work)
        self.connections = 0
        self.heap_seen = 0
        self.rows = []

    def ssh_count(self, command, **kw):
        self.connections += 1
        return self.ssh(command, **kw)

    def served(self):
        """sshd's quiescent line for the current connection count."""
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            lines = SERVED.findall(self.t.output())
            if lines and int(lines[-1][0]) == self.connections and self.t.all_images() == 0:
                r, handles, pipes, cells, frames, heap = map(int, lines[-1])
                return {"reclaimed": r, "frames": frames, "sshd_heap": heap, "handles": handles,
                        "pipes": pipes, "cells": cells}
            time.sleep(0.2)
        raise sm.Failed(f"no SERVED CAPACITY for {self.connections} connections: {self.t.census_detail()}")

    def fsd_heap(self):
        found = FSD.findall(self.t.serial())
        return int(found[-1]) if found else None

    def sysinfo(self):
        rc, out, err = self.ssh_count("/bin/sysinfo")
        self.check("sysinfo answers", rc == 0, f"{rc} {out!r} {err!r}")
        m = FRAMES.search(out.decode())
        self.check("sysinfo has frame counts", m is not None, out.decode())
        return int(m.group(2))

    def single(self, i):
        if self.mode == "c":
            command = SCRATCH + "/bin/hello" if i % 2 == 0 else None
            if command:
                rc, out, err = self.ssh_count(command)
                self.check("hello", rc == 0 and out == b"hello, world\n", f"{rc} {out!r} {err!r}")
                return "hello"
        else:
            if i % 3 == 0:
                rc, out, err = self.ssh_count(self.prefix + f"echo a15-{i}")
                self.check("echo", rc == 0 and out == f"a15-{i}\n".encode(), f"{rc} {out!r} {err!r}")
                return "echo"
            if i % 3 == 1:
                rc, out, err = self.ssh_count(self.prefix + "/bin/printenv")
                self.check("printenv", rc == 0, f"{rc} {out!r} {err!r}")
                return "printenv"
        self.sysinfo()
        return "sysinfo"

    def group(self, n):
        """n sessions open at once: n-1 held programs blocked on stdin,
        then one sysinfo session, then every held stdin closed."""
        held_words = "/bin/short" if self.mode == "c" else "/bin/head -c 1"
        held = []
        for _ in range(n - 1):
            spawned = self.t.spawn_count()
            self.connections += 1
            held.append(subprocess.Popen(self.client.base(self.op) + [SCRATCH + held_words],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            self.t.await_spawns(spawned, 2)
        alive = len(self.t.live_images())
        frames_held = self.sysinfo()
        for p in held:
            out, err = p.communicate(b"", timeout=120)
            self.check("held session ended at EOF", p.returncode == 0, f"rc={p.returncode} {out!r} {err!r}")
        return f"group{n} live_images={alive} sysinfo_held={frames_held}"

    def record(self, step, what):
        s = self.served()
        row = dict(step=step, what=what, fsd_heap=self.fsd_heap(), **s)
        heap = HEAP.findall(self.t.output())
        row["heap_maps"] = len(heap)
        # A diagnostic sshd (runtime built with ABSD_HEAP_DIAG) prints one
        # line per heap map; the ones since the previous step are this
        # step's growth.
        for size, pages, mapped in heap[self.heap_seen:]:
            print(f"A15 HEAP step={step} size={size} pages={pages} mapped_before={mapped}", flush=True)
        self.heap_seen = len(heap)
        self.rows.append(row)
        print(f"A15 STEP {step} {what} :: conns={self.connections} frames={s['frames']} sshd_heap={s['sshd_heap']} "
              f"fsd_heap={row['fsd_heap']} handles={s['handles']} pipes={s['pipes']} cells={s['cells']} "
              f"heap_map_lines={len(heap)}", flush=True)

    def run(self, singles_after_first):
        t = self.t
        t.setup(self.work, (self.op.with_suffix(".pub")).read_text())
        first = t.start(fresh=True)
        self.client = sm.Client(self.work, t.port)
        self.client.trust(first["public"])
        step = 0
        for i in range(5):
            step += 1
            self.record(step, "single " + self.single(i))
        plan = [2] + [None] * singles_after_first + [2] + [None] * 5 + [3] + [None] * 5 + [3] + [None] * 3 + \
               [4] + [None] * 5 + [4] + [None] * 3
        for i, n in enumerate(plan):
            step += 1
            self.record(step, self.group(n) if n else "single " + self.single(i))
        t.stop()
        print(f"A15 RUN OK mode={self.mode} steps={step} connections={self.connections}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--mode", choices=["native", "native-exec", "c"], required=True)
    ap.add_argument("--program", action="append", default=[])
    ap.add_argument("--singles", type=int, default=25)
    args, rest = ap.parse_known_args()
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    base = ssh_absd.target(rest)
    target = Target.__new__(Target)
    target.__dict__.update(base.__dict__)
    target.programs = [pathlib.Path(p).resolve() for p in args.program]
    run = Run(target, work, args.mode)
    try:
        run.run(args.singles)
    except BaseException:
        target.stop()
        raise


if __name__ == "__main__":
    main()
