#!/usr/bin/env python3
"""Program start and file-server transfer times on a `net fsd` boot.

One SSH session (scripts/cmds-matrix.py's image: the platform's commands,
the uutils ports, fixtures) types commands and times them host-side from
Enter to the next prompt; /bin/fsd-probe times file-server work in the
guest. Every figure is a median of --rounds runs.

  start.native    `cat /etc/motd` (a native std command, ~170 KB image)
  start.port      `basename`, `nl` (uutils ports, 0.6-1.5 MB images)
  read.kbps       fsd-probe read of a 1 MiB file (std::fs::read)
  image.ms        fsd-probe read of /bin/nl (the bytes a start moves)
  stat.ms         one std::fs::metadata round trip (stat-loop 50)
  pipe.kbps       a shell pipeline between two commands,
                  `sshtest zeros 1048576 | nofs fsd-probe drain`: KB/s
                  from the reader's first byte to its end of file
  pipe.read       bytes per read on that pipe (how often the two
                  processes hand over)

(`fsd-probe pingpong`, one byte through /bin/cat and back, is not timed:
a command a session's shell starts has no spawn right, so it cannot start
/bin/cat, and a shell pipeline only runs one way, so no command line gives
a round trip between two commands. stat.ms is the cross-process round
trip; pipe.kbps is the one-way figure.)

With --baseline (a JSON file of an earlier run) it prints
  FSD THROUGHPUT OK before=<KB/s> after=<KB/s>
  COMMAND START OK native=<s> port=<s>
only when this run is at least --min-factor times the baseline on the
1 MiB read and the image read and no slower on command start. --record
writes this run's figures as JSON.
"""

import argparse
import json
import pathlib
import re
import statistics
import sys

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import importlib.util  # noqa: E402
import ssh_absd  # noqa: E402

spec = importlib.util.spec_from_file_location("cmds_matrix", here / "cmds-matrix.py")
cm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cm)
sm = cm.sm

MIB = bytes((i * 7 + i // 4096) % 251 for i in range(1024 * 1024))


class PerfTarget(cm.CmdsTarget):
    def files(self, authorized):
        return super().files(authorized) + [("/etc/big1m", MIB)]


class PerfMatrix(cm.CmdsMatrix):
    def __init__(self, target, work, rounds):
        super().__init__(target, work)
        self.rounds = rounds
        self.figures = {}

    def timed(self, sh, name, line, want):
        runs = []
        for _ in range(self.rounds):
            got = sh.run(line)
            self.check(f"{name}: {line}", got == want, f"got {got!r} want {want!r}")
            runs.append(sh.times[line])
        self.figures[name] = round(statistics.median(runs), 3)
        print(f"PERF {name}={self.figures[name]} runs={','.join(f'{r:.2f}' for r in runs)}", flush=True)

    def probe(self, sh, name, line, pattern, convert):
        values = []
        for _ in range(self.rounds):
            got = sh.run(line).decode(errors="replace")
            m = re.fullmatch(pattern, got, re.S)
            self.check(f"{name}: {line}", m is not None, f"got {got!r} want /{pattern}/")
            values.append(convert(m))
        self.figures[name] = round(statistics.median(values), 3)
        print(f"PERF {name}={self.figures[name]} runs={','.join(f'{v:.3f}' for v in values)}", flush=True)

    def run(self):
        t = self.t
        t.setup(self.work, (self.op.with_suffix(".pub")).read_text())
        first = t.start(fresh=True)
        self.client = sm.Client(self.work, t.port)
        self.client.trust(first["public"])
        nl = self.device()[self.t.physical("/bin/nl")]
        sh = cm.Shell(self)
        motd = ssh_absd.MOTD
        self.timed(sh, "start.native", "cat /etc/motd", motd)
        self.timed(sh, "start.basename", "basename /home/operator/notes.txt .txt", b"notes\n")
        self.timed(sh, "start.nl", "nl /etc/words.txt",
                   b"".join(f"{i + 1:6d}\t{w}\n".encode() for i, w in enumerate(cm.WORDS.decode().split())))
        self.probe(sh, "read.kbps", "/bin/fsd-probe read /etc/big1m", rf"read: {len(MIB)} bytes (\d+) ms\n",
                   lambda m: len(MIB) / max(int(m.group(1)), 1))
        self.probe(sh, "image.ms", "/bin/fsd-probe read /bin/nl", rf"read: {len(nl)} bytes (\d+) ms\n",
                   lambda m: int(m.group(1)))
        self.probe(sh, "stat.ms", "/bin/fsd-probe stat-loop /etc/motd 50", r"stat-loop: 50 stats (\d+) ms\n",
                   lambda m: int(m.group(1)) / 50)
        pipeline = "/bin/sshtest zeros 1048576 | nofs /bin/fsd-probe drain"
        self.probe(sh, "pipe.kbps", pipeline, r"drain: 1048576 bytes (\d+) reads (\d+) ms\n",
                   lambda m: 1024 * 1024 / max(int(m.group(2)), 1))
        self.probe(sh, "pipe.read", pipeline, r"drain: 1048576 bytes (\d+) reads (\d+) ms\n",
                   lambda m: 1024 * 1024 / int(m.group(1)))
        self.check("the session exits", sh.close() == 0)
        self.alive("the perf matrix")
        t.stop()
        self.figures["start.port"] = round(max(self.figures["start.basename"], self.figures["start.nl"]), 3)
        self.figures["image.bytes"] = len(nl)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--baseline")
    ap.add_argument("--record")
    ap.add_argument("--min-factor", type=float, default=1.0)
    args, rest = ap.parse_known_args()
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    ssh_absd.IMAGE_BYTES = 32 * 1024 * 1024
    ssh_absd.DEVICE_SECTORS = ssh_absd.IMAGE_BYTES // 512
    base = ssh_absd.target(rest)
    target = PerfTarget.__new__(PerfTarget)
    target.__dict__.update(base.__dict__)
    matrix = PerfMatrix(target, work, args.rounds)
    try:
        matrix.run()
    except (sm.Failed, ssh_absd.Failed) as e:
        print(f"PERF MATRIX FAILED: {e}", file=sys.stderr)
        target.stop()
        sys.exit(1)
    except BaseException:
        target.stop()
        raise
    f = matrix.figures
    print("PERF FIGURES " + json.dumps(f, sort_keys=True), flush=True)
    if args.record:
        pathlib.Path(args.record).write_text(json.dumps(f, indent=1, sort_keys=True) + "\n")
    if args.baseline:
        b = json.loads(pathlib.Path(args.baseline).read_text())
        read_factor = f["read.kbps"] / b["read.kbps"]
        image_factor = b["image.ms"] / max(f["image.ms"], 1)
        print(f"PERF FACTORS read={read_factor:.1f} image={image_factor:.1f} "
              f"native={b['start.native'] / f['start.native']:.1f} port={b['start.port'] / f['start.port']:.1f} "
              f"stat={b['stat.ms'] / max(f['stat.ms'], 0.01):.1f}", flush=True)
        if read_factor < args.min_factor or image_factor < args.min_factor:
            print(f"PERF MATRIX FAILED: factor below {args.min_factor}", file=sys.stderr)
            sys.exit(1)
        print(f"FSD THROUGHPUT OK before={b['read.kbps']:.0f} after={f['read.kbps']:.0f}")
        if f["start.native"] > b["start.native"] or f["start.port"] > b["start.port"]:
            print("PERF MATRIX FAILED: a command starts slower than the baseline", file=sys.stderr)
            sys.exit(1)
        print(f"COMMAND START OK native={f['start.native']:.2f} port={f['start.port']:.2f}")
    print(f"PERF MATRIX OK checks={matrix.checks}")


if __name__ == "__main__":
    main()
