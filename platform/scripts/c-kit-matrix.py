#!/usr/bin/env python3
"""The C kit on the shell route (docs/C-INTERFACE.md section 6).

One `net fsd` boot (scripts/ssh_absd.py) whose image carries the kit's
test programs under /bin and its inputs under /etc. Each case of
c/tests/kit/cases.tsv routed `shell` or `both` runs in its own SSH exec
session as absd-sh's child, after `cd /home/operator` (sshd's working
directory `/` is read-only; the kit's scratch files are cwd-relative,
contract 6): every word of the exec text is double-quoted,
so sshd hands the text to the shell (`absd-sh -c`, ssh/src/main.rs
shell_syntax) rather than starting the program itself, and the program is
named by path (`/bin/exit`, never the `exit` builtin). The session's shell
and the program's spawn are checked from sshd's and the kernel's own lines.
Its (status, stdout, stderr) is compared with the Linux reference build
run with the same argv (argv[0] = /bin/<program>), stdin, the session's
environment (printenv) and SIGPIPE ignored (ABSD has no signals). A
`native` case runs the platform's /bin/<program> instead and is compared
with the host's <program>; cases run in file order, and the Linux
references share one scratch directory, so `stdio write`, `cat
c-stdio.dat` and `stdio verify` are three processes over one file in
both worlds.

A case whose ABSD output differs from Linux is one of:
  DIVERGES  listed in divergences.txt (by case key, else by program) with
            the contract's reason; its ABSD output is pinned in
            shell-expected/<key>.txt and must match exactly and differ
            from Linux (`short writer` is matched by pattern, see below);
  PINNED    an ABSD-only observation pinned in shell-expected/<key>.txt,
            matched exactly. A pin that is not a fault (FAULTS) differs
            from Linux only by the shell's own stderr line: its stdout and
            status must equal Linux's. A fault pin (a status Linux reports
            as a signal) is checked against the kernel's serial line
            instead;
  DEFECT    listed in shell-expected/DEFECTS: a difference the contract
            does not explain, pinned so that any change shows, and counted
            in the markers as a defect, never as agreement.
Anything else must equal Linux. A pin file whose name is not a case of
cases.tsv fails the run.

A pin is stdout, `--\\n`, stderr, `--\\n`, `status=<n>\\n`.

Resources (A5): before each case and after its session was reclaimed
(sshd's `SSH SESSION RECLAIMED`), as confirmed readings (samples a
second apart, each taken at quiescence, below), the kernel's
live image processes, the
memory and kernel lines of sysinfo(1) (frames, process slots, handles,
pipes, cells) and the image's objects other than logs and recovery state
(the host's own reader) must be equal; a file a case keeps on purpose
would be named in RETAINED. The file `stdio write` keeps must hold the
Linux reference file's bytes (by digest) after that case and be gone
after `stdio verify`.

Quiescence (the adversarial A2 rule): every sample's sysinfo session is
opened only after sshd's quiescent line `SERVED CAPACITY ...
accepted_reclaimed=<n>` for every connection this matrix has opened
(n = connections, sshd prints it only when no session, pool session or
closing socket is left) and with no live image process, waited for up to
60 s. The before-reading of a case must be CONFIRMED: two consecutive
quiescent samples must match the previous case's successfully judged
after-reading in images, memory line, kernel line and objects (tolerance
zero). The first case has no such anchor and requires three consecutive
equal samples instead. Its initial baseline remains a sampling observation,
not proof that a longer transient cannot exist. A sample that differs is
printed as TRANSIENT and sampling goes on. No matching confirmation within
60 s fails as `C KIT RESOURCES UNSETTLED`, rather than judging a case against
an unconfirmed reading. An anchor mismatch can be a real resource change
between cases, as well as sampling noise; either fails the run. The
after-reading keeps its rule (two agreeing samples within 20 s, else the
last; a pair that differs from the case's before-reading does not end
the sampling early, so a transient that settles back within those 20 s is
read settled, and one that persists is still the last sample and fails).
The N4/N5 allowances are unchanged: a +1 handle that settles before
quiescence is never sampled, one that persists still fails.

Frames (A4): after the cases, the kernel's allocated frames (sysinfo's
memory line) are read at rest and while one session holds a program
alive, blocked reading its stdin: the C kit's `short` (crt0, pre-touch,
the counting loop) and the native `head -c 1`; each reading is the
sysinfo session's own plus the held session's (sshd's state, absd-sh,
the program). `C KIT FRAMES LIVE` prints both differences.

Vectors (c/vectors/startup): args is run with each vector's arguments;
its echo of argc and argv must be exact, and its environment echo must be
the session's (printenv), which is sshd's policy, not the vector's.

Markers: C KIT SHELL OK cases= agree= diverge= pinned= defects=;
C KIT RESOURCES OK cases=; C KIT FRAMES LIVE c= native= rest=; C KIT VECTOR OK <name>; C KIT MATRIX OK."""

import argparse
import contextlib
import io
import hashlib
import json
import pathlib
import re
import signal
import subprocess
import sys
import time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import ssh_absd  # noqa: E402
import warm_baseline as wb  # noqa: E402
import importlib.util  # noqa: E402

spec = importlib.util.spec_from_file_location("ssh_matrix", here / "ssh-matrix.py")
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)

# Platform commands the matrix itself uses beside ssh_absd's base set.
EXTRA = ["head", "df", "sysinfo"]
# Files a case leaves on the image (or removes) on purpose: `stdio write`
# keeps its file for the next two cases, `stdio verify` removes it.
STDIO_FILE = "/home/operator/c-stdio.dat"
RETAINED = {"stdio write": (STDIO_FILE,), "stdio verify": (STDIO_FILE,)}
# sshd starts a session in `/`, a read-only ancestor (contract 6); a case
# starts in a writable directory and names its scratch relative to it.
SCRATCH = "cd /home/operator; "
PRETOUCH_PAGES = 256 * 1024 // 4096    # c/include/absd/kit.h ABSD_STACK_PRETOUCH_BYTES
WRITER = re.compile(rb"write failed after (\d+) bytes\n")
FRAMES = re.compile(r"\((\d+) \+ (\d+) frames of 4096 bytes\)")
# sshd's quiescent capacity line (ssh/src/absd.rs report_quiescent_capacity).
SERVED = re.compile(r"^SERVED CAPACITY boot=\S+ accepted_reclaimed=(\d+) .*?processes=(\d+) handles=(\d+) "
                    r"pipes=(\d+) cells=(\d+) frames=(\d+) ", re.M)
QUIESCE_SECONDS = 60
CONFIRM_SECONDS = 60
# Pinned cases whose ABSD end is a fault Linux reports as a signal: each is
# judged by the kernel's serial line for the program's pid, not by Linux's
# status. stack overflow: a page fault (vector 14), which absd-sh reports
# as 128; exit abort: abort()'s raise(SIGABRT) ends the process with 134.
FAULTS = {
    "stack overflow": ("the kernel reports the program's fault with vector 14",
                       r"USER FAULT pid={pid} vector=(\d+)", ["14"]),
    "exit abort": ("the kernel reports the program's exit with status 134 (128 + SIGABRT)",
                   r"USER EXIT pid={pid} status=(-?\d+)", ["134"]),
}


def cases(text):
    return [line.split("\t") for line in text.splitlines() if line.strip() and not line.startswith("#")]


def table(path):
    if not path.exists():
        return {}
    return dict(line.split("\t", 1) for line in path.read_text().splitlines() if line.strip() and not line.startswith("#"))


def case_key(program, stdin_name, args):
    return " ".join([program, *args]) if args else (program if stdin_name == "-" else f"{program} <{stdin_name}")


def pin_name(key):
    return key.replace(" ", "_").replace("<", "") + ".txt"


def quote(word):
    return '"' + word.replace("\\", "\\\\").replace('"', '\\"') + '"'


def pin_bytes(rc, out, err):
    return out + b"--\n" + err + b"--\n" + f"status={rc}\n".encode()


def ignore_sigpipe():
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)


class KitTarget(ssh_absd.AbsdTarget):
    def files(self, authorized):
        files = super().files(authorized)
        files += [(f"/bin/{name}", (self.root / "commands" / name).read_bytes()) for name in EXTRA]
        files += [(f"/bin/{p.name}", p.read_bytes()) for p in self.programs]
        files += [(f"/etc/{p.name}", p.read_bytes()) for p in self.inputs]
        return files


class KitMatrix(sm.Matrix):
    # Every reading opens at sshd's quiescent line (see Quiescence above).
    QUIESCENT_READINGS = True
    # Connections this matrix has opened. A class attribute, so a subclass
    # whose __init__ skips KitMatrix.__init__ (CportsMatrix, TccMatrix call
    # sm.Matrix.__init__ directly) still counts from 0 in ssh().
    connections = 0

    def __init__(self, target, work, args):
        self.kit = pathlib.Path(args.kit).resolve()
        self.absd = pathlib.Path(args.absd).resolve()
        self.linux = pathlib.Path(args.linux).resolve()
        self.vectors = pathlib.Path(args.vectors).resolve()
        self.expected = self.kit / "shell-expected"
        self.pin = set(args.pin or [])
        self.cases = [c for c in cases((self.kit / "cases.tsv").read_text()) if c[0] in ("shell", "both", "native")]
        self.divergences = table(self.kit / "divergences.txt")
        self.defects = table(self.expected / "DEFECTS")
        known = {pin_name(case_key(c[1], c[2], c[3:])) for c in self.cases}
        stray = sorted(p.name for p in self.expected.glob("*.txt") if p.name not in known)
        sm.require(not stray, f"shell-expected pins for no case of cases.tsv: {stray}")
        sm.require(set(FAULTS) <= {case_key(c[1], c[2], c[3:]) for c in self.cases},
                   f"FAULTS names a case not in cases.tsv: {sorted(FAULTS)}")
        names = sorted({c[1] for c in self.cases if c[0] != "native"})
        target.programs = [self.absd / n for n in names]
        target.inputs = sorted((self.kit / "inputs").iterdir())
        for n in names:
            sm.require((self.linux / n).is_file(), f"no Linux reference build {self.linux / n}")
        super().__init__(target, work)
        self.connections = 0

    # -- the session's facts ----------------------------------------------------

    def reclaimed(self):
        return len(re.findall(r"SSH SESSION RECLAIMED ", self.t.output()))

    def ssh(self, command=None, **kw):
        # Every connection is counted: quiescent() waits for sshd's line
        # that has reclaimed all of them.
        self.connections += 1
        return super().ssh(command, **kw)

    def quiescent(self):
        """sshd's quiescent SERVED CAPACITY line for every connection the
        matrix has opened, with no live image process; up to 60 s."""
        deadline = time.monotonic() + QUIESCE_SECONDS
        while True:
            lines = SERVED.findall(self.t.output())
            if lines and int(lines[-1][0]) == self.connections and self.t.all_images() == 0:
                n, processes, handles, pipes, cells, frames = map(int, lines[-1])
                return {"accepted_reclaimed": n, "processes": processes, "handles": handles, "pipes": pipes,
                        "cells": cells, "frames": frames}
            if time.monotonic() >= deadline:
                raise sm.Failed(f"no quiescent SERVED CAPACITY line for {self.connections} connections within "
                                f"{QUIESCE_SECONDS} s (last {lines[-1][0] if lines else 'none'}): "
                                f"{self.t.census_detail()}")
            time.sleep(0.2)

    def shell_ssh(self, text, stdin=b""):
        """One exec session through absd-sh; returns (rc, out, err, shell
        pid, [program pids]) once sshd has reclaimed the session."""
        sessions = len(re.findall(r"SSH SESSION CHILD ", self.t.output()))
        done = self.reclaimed()
        rc, out, err = self.ssh(text, stdin=stdin, timeout=300)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and (self.reclaimed() <= done or self.t.all_images() != 0):
            time.sleep(0.2)
        self.check(f"session reclaimed after {text[:60]!r}", self.reclaimed() > done and self.t.all_images() == 0,
                   self.t.census_detail())
        child = re.findall(r"SSH SESSION CHILD pid=(\d+) spawn_right=(\w+) argv0=(\S+) [^\n]*control=(\w+)",
                           self.t.output())[sessions:]
        self.check(f"the session ran absd-sh with the spawn right: {text[:60]!r}",
                   len(child) == 1 and child[0][1:] == ("true", "/bin/absd-sh", "true"), str(child))
        shell = child[0][0]
        programs = re.findall(rf"SPAWN OK pid=(\d+) parent={shell} program=image", self.t.serial())
        return rc, out, err, shell, programs

    def sysinfo(self):
        rc, out, err = self.ssh("/bin/sysinfo")
        self.check("sysinfo answers", rc == 0, f"{rc} {out!r} {err!r}")
        lines = out.decode().splitlines()
        memory = [l for l in lines if l.startswith("memory: ")]
        kernel = [l for l in lines if l.startswith("kernel: ")]
        self.check("sysinfo has memory and kernel lines", len(memory) == 1 and len(kernel) == 1, out.decode())
        # The measuring session itself must be gone before anything is read.
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and self.t.all_images() != 0:
            time.sleep(0.2)
        return memory[0], kernel[0]

    def census(self):
        """One reading whose sysinfo session opens at quiescence. The
        quiescent line's own counts are kept beside it (shown, not
        judged). A subclass that opens sessions this matrix does not
        count, or restarts the boot, turns it off (QUIESCENT_READINGS)."""
        served = self.quiescent() if self.QUIESCENT_READINGS else None
        memory, kernel = self.sysinfo()
        census = {"images": self.t.all_images(), "memory": memory, "kernel": kernel,
                  "objects": self.t.system_objects()}
        if served is not None:
            census["quiescent"] = served
        return census

    def stable(self, key, when, confirm=False, settle_to=None):
        """Two agreeing after samples within 20 s, else the last, unchanged.
        A confirmed before sample must also match the preceding judged after
        census; a transient pair (N5: 66 -> 67 -> 67) cannot move that anchor.
        With no prior case, require three agreeing initial samples. Failure
        to confirm within 60 s is UNSETTLED, never a new accepted baseline.
        Each census still opens a fresh session only after quiescence.
        `settle_to` (an after-reading's before census): an agreeing pair that
        compare_census would reject does not end the 20 s early; at the end
        the last sample stands, as before."""
        anchor = getattr(self, "_settled_census", None) if confirm else None
        required = 3 if confirm and anchor is None else 2
        agreeing = 1
        last = self.census()
        deadline = time.monotonic() + (CONFIRM_SECONDS if confirm else 20)
        while time.monotonic() < deadline:
            time.sleep(1)
            now = self.census()
            if self.differs(last, now):
                agreeing = 1
                print(f"C KIT RESOURCES TRANSIENT {key} {when} :: {last['kernel']} images={last['images']} "
                      f"objects={len(last['objects'])} -> {now['kernel']} images={now['images']} "
                      f"objects={len(now['objects'])}", flush=True)
            else:
                agreeing += 1
            if agreeing >= required:
                if settle_to is not None and not confirm:
                    if self.unchanged(key, settle_to, now):
                        return now
                elif anchor is None or not self.differs(anchor, now):
                    return now
                if agreeing == required:
                    print(f"C KIT RESOURCES TRANSIENT {key} {when} :: repeated reading does not match "
                          f"previous judged after census: {now['memory']} | {now['kernel']}", flush=True)
            last = now
        if confirm:
            raise sm.Failed(f"C KIT RESOURCES UNSETTLED {key} {when} :: no {required} consecutive quiescent "
                            f"readings {'matched the previous judged after census' if anchor is not None else 'agreed'} "
                            f"within {CONFIRM_SECONDS} s; last {last['memory']} | {last['kernel']} "
                            f"images={last['images']} objects={len(last['objects'])} quiescent={last.get('quiescent')}")
        return last

    @staticmethod
    def differs(before, after):
        return any(before[k] != after[k] for k in ("images", "memory", "kernel", "objects"))

    @staticmethod
    def unchanged(key, before, after):
        """compare_census's predicate: exact equality, RETAINED aside."""
        added = {o[0] for o in after["objects"]} - {o[0] for o in before["objects"]}
        unexpected = sorted(added - set(RETAINED.get(key, ())))
        same = (before["images"], before["memory"], before["kernel"]) == (after["images"], after["memory"], after["kernel"])
        objects = [o for o in after["objects"] if o[0] not in RETAINED.get(key, ())] == \
                  [o for o in before["objects"] if o[0] not in RETAINED.get(key, ())]
        return same and objects and not unexpected

    def compare_census(self, key, before, after):
        added = {o[0] for o in after["objects"]} - {o[0] for o in before["objects"]}
        unexpected = sorted(added - set(RETAINED.get(key, ())))
        self.check(f"resources after {key}: images, frames, kernel objects and image files unchanged",
                   self.unchanged(key, before, after),
                   f"before={ {k: v for k, v in before.items() if k != 'objects'} } "
                   f"after={ {k: v for k, v in after.items() if k != 'objects'} } added={unexpected} "
                   f"changed={sorted({o[0] for o in after['objects']} ^ {o[0] for o in before['objects']})}")
        return before["memory"], before["kernel"]

    def check_stdio_file(self, key, after, cwd):
        image = {o[0]: o for o in after["objects"]}
        if key == "stdio write":
            want = hashlib.sha256((cwd / "c-stdio.dat").read_bytes()).hexdigest()
            self.check("stdio write: the kept file holds the Linux reference file's bytes",
                       STDIO_FILE in image and image[STDIO_FILE][4] == want, f"{image.get(STDIO_FILE)} want={want}")
        else:
            self.check("stdio verify: the file is gone from the image", STDIO_FILE not in image, str(image.get(STDIO_FILE)))

    @staticmethod
    def allocated(memory):
        m = FRAMES.search(memory)
        sm.require(m is not None, f"no frame counts in {memory!r}")
        return int(m.group(2))

    def live_frames(self, label, words, warmup=False, rehearsal=False):
        """Allocated frames while one session holds `words` alive, blocked
        reading its stdin, minus the rest reading. Both readings are taken
        by a sysinfo session, so its own frames cancel. The first time two
        sessions are open at once, one frame stays allocated afterwards
        (seen 705 -> 706, every count else equal, no file changed): a
        `warmup` round takes that step unjudged and prints it; the
        measured rounds must then return to their rest reading exactly."""
        rest = self.stable(f"frames {label}", "rest")
        spawned = self.t.spawn_count()
        self.connections += 1
        held = subprocess.Popen(self.client.base(self.op) + [SCRATCH + " ".join(quote(w) for w in words)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.t.await_spawns(spawned, 2)
            rc, out, err = self.ssh("/bin/sysinfo")
            self.check(f"sysinfo answers while {words[0]} is held", rc == 0, f"{rc} {out!r} {err!r}")
            memory = [l for l in out.decode().splitlines() if l.startswith("memory: ")]
            self.check("sysinfo has a memory line", len(memory) == 1, out.decode())
            alive = self.t.live_images()
        finally:
            out, err = held.communicate(b"", timeout=120)
        self.check(f"{words[0]} was alive during the reading and ended at EOF",
                   held.returncode == 0 and len(alive) >= 2, f"rc={held.returncode} out={out!r} err={err!r} {alive}")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and self.t.all_images() != 0:
            time.sleep(0.2)
        after = self.stable(f"frames {label}", "after", settle_to=None if rehearsal or warmup else rest)
        if rehearsal:
            # Whole-group plateau judges cold growth; semantic checks above still run.
            pass
        elif warmup:
            print(f"C KIT FRAMES WARMUP {' '.join(words)} :: rest {rest['memory']} | after {after['memory']} | "
                  f"{after['kernel']} images={after['images']} objects={len(after['objects'])}", flush=True)
            self.check("warmup: only the frame count may differ after the first concurrent session",
                       (rest["images"], rest["kernel"], rest["objects"]) == (after["images"], after["kernel"], after["objects"])
                       and 0 <= self.allocated(after["memory"]) - self.allocated(rest["memory"]) <= 4,
                       f"rest={rest['memory']} {rest['kernel']} after={after['memory']} {after['kernel']}")
        else:
            self.compare_census(f"frames {label}", rest, after)
        live = self.allocated(memory[0]) - self.allocated(rest["memory"])
        print(f"C KIT FRAMES {label} {' '.join(words)} :: rest {rest['memory']} | held {memory[0]} | "
              f"held-session frames={live}", flush=True)
        return live, self.allocated(rest["memory"])

    # -- the Linux reference ------------------------------------------------------------------

    def linux_run(self, program, args, stdin, env, cwd):
        r = subprocess.run([f"/bin/{program}", *args], executable=str(self.linux / program), cwd=cwd, env=env,
                           input=stdin, capture_output=True, preexec_fn=ignore_sigpipe, timeout=120)
        return r.returncode, r.stdout, r.stderr

    def linux_writer(self, env, cwd):
        r = subprocess.run(["/bin/bash", "-c", f"exec -a /bin/short {self.linux / 'short'} writer | head -c 1000"],
                           cwd=cwd, env=env, input=b"", capture_output=True, preexec_fn=ignore_sigpipe, timeout=120)
        return r.returncode, r.stdout, r.stderr

    # -- the run -----------------------------------------------------------------

    def probe_shell(self):
        """What the shell route offers C programs: mounts, environment, quoting."""
        rc, out, err, _, _ = self.shell_ssh('"/bin/df"')
        self.check("df in a shell session", rc == 0 and err == b"", f"{rc} {out!r} {err!r}")
        mounts = re.findall(r"^(/\S*) +(ro|rw)$", out.decode(), re.M)
        print("C KIT SESSION MOUNTS " + " ".join(f"{p}:{a}" for p, a in mounts), flush=True)
        want = [("/bin", "ro"), ("/etc", "ro"), ("/home/operator", "rw"), ("/share", "ro"), ("/var/log", "ro")]
        tmp = [m for m in mounts if m[0].startswith("/tmp/session-")]
        self.check("the session's mounts: /bin /etc /share /var/log read-only, /home/operator and its own "
                   "/tmp/session-<n> writable", [m for m in mounts if m not in tmp] == want
                   and len(tmp) == 1 and tmp[0][1] == "rw", str(mounts))
        rc, out, err, _, _ = self.shell_ssh('"/bin/printenv"')
        self.check("printenv in a shell session", rc == 0 and err == b"", f"{rc} {out!r} {err!r}")
        env = dict(line.split("=", 1) for line in out.decode().splitlines() if "=" in line)
        print(f"C KIT SESSION ENV count={len(env)} {' '.join(sorted(env))}", flush=True)
        # Quoting (ruling R4): single quotes are literal; double quotes
        # group, and an empty pair is an empty word.
        rc, out, err, _, _ = self.shell_ssh("echo 'a b';")
        self.check("absd-sh: single quotes are literal characters", (rc, out, err) == (0, b"'a b'\n", b""),
                   f"{rc} {out!r} {err!r}")
        rc, out, err, _, _ = self.shell_ssh('echo "a b" "" x')
        self.check('absd-sh: double quotes group words, "" is an empty word', (rc, out, err) == (0, b"a b  x\n", b""),
                   f"{rc} {out!r} {err!r}")
        print("C KIT SESSION QUOTING double=yes single=literal", flush=True)
        return env

    def run_case(self, route, program, stdin_name, args, env, cwd):
        data = b"" if stdin_name == "-" else (self.kit / "inputs" / stdin_name).read_bytes()
        key = case_key(program, stdin_name, args)
        writer = program == "short" and args == ["writer"]
        if route == "native":
            text = SCRATCH + " ".join(quote(w) for w in [f"/bin/{program}", *args])
            r = subprocess.run([f"/bin/{program}", *args], cwd=cwd, env=env, input=data, capture_output=True, timeout=120)
            ref = (r.returncode, r.stdout, r.stderr)
        elif writer:
            text = f'{SCRATCH}{quote("/bin/short")} {quote("writer")} | head -c 1000'
            ref = self.linux_writer(env, cwd)
        else:
            text = SCRATCH + " ".join(quote(w) for w in [f"/bin/{program}", *args])
            ref = self.linux_run(program, args, data, env, cwd)
        rc, out, err, shell, pids = self.shell_ssh(text, stdin=data)
        self.check(f"{key}: the program ran as the shell's child", len(pids) == (2 if writer else 1),
                   f"shell={shell} children={pids}")
        return key, (rc, out, err), ref, pids

    def judge(self, key, program, got, ref, pids):
        rc, out, err = got
        pin = self.expected / pin_name(key)
        if key in self.pin:
            pin.write_bytes(pin_bytes(*got))
            print(f"C KIT PIN WRITTEN {pin}: review it before committing", flush=True)
        reason = self.divergences.get(key) or self.divergences.get(program)
        if key in self.defects:
            self.check(f"{key}: defect output unchanged (pinned)", pin.exists() and pin.read_bytes() == pin_bytes(*got),
                       f"ABSD {got!r}")
            print(f"C KIT DEFECT {key} :: {self.defects[key]}", flush=True)
            return "defect"
        if reason and key == "short writer":
            # The bytes moved and the status are Linux's; the writer's own
            # report is ABSD's pipe (1024 bytes, EPIPE without a signal).
            m = WRITER.fullmatch(err)
            self.check(f"{key}: stdout and status equal Linux; the writer saw EPIPE (no signal) after head ended",
                       (rc, out) == ref[:2] and m is not None and 1000 <= int(m.group(1)) < 30000 and err != ref[2],
                       f"ABSD {got!r}\nLinux {ref!r}")
            print(f"C KIT DIVERGES {key} :: {reason} (ABSD: {err.decode().strip()}; Linux: {ref[2].decode().strip()})",
                  flush=True)
            return "diverge"
        if reason:
            self.check(f"{key}: pinned ABSD output matches and differs from Linux",
                       pin.exists() and pin.read_bytes() == pin_bytes(*got) and got != ref,
                       f"ABSD {got!r}\nLinux {ref!r}")
            print(f"C KIT DIVERGES {key} :: {reason}", flush=True)
            return "diverge"
        if pin.exists():
            self.check(f"{key}: pinned ABSD-only observation", pin.read_bytes() == pin_bytes(*got), f"ABSD {got!r}")
            if key in FAULTS:
                what, pattern, want = FAULTS[key]
                seen = re.findall(pattern.format(pid=pids[0]), self.t.serial())
                self.check(f"{key}: {what}", seen == want, f"pid={pids[0]} {seen}")
            else:
                self.check(f"{key}: stdout and status equal Linux (only the shell's stderr line differs)",
                           (rc, out) == ref[:2], f"ABSD {got!r}\nLinux {ref!r}")
            print(f"C KIT PINNED {key} (stdout{' =' if out == ref[1] else ' !='} Linux, status {rc} vs Linux "
                  f"{ref[0]})", flush=True)
            return "pinned"
        self.check(f"case {key}", got == ref, f"ABSD {got!r}\nLinux {ref!r}")
        print(f"C KIT CASE OK shell {key}", flush=True)
        return "agree"

    def run_vectors(self, env):
        executed = []
        for vector in sorted(self.vectors.glob("*.json")):
            want = json.loads(vector.read_text())
            if want.get("refused"):
                print(f"C KIT VECTOR SKIPPED {vector.stem} :: the encoder refuses it ({want.get('error')}); "
                      "no record exists to start a program with", flush=True)
                continue
            words = want["argv"][1:]
            rc, out, err, _, pids = self.shell_ssh(" ".join(quote(w) for w in ["/bin/args", *words]))
            argv = ["/bin/args", *words]
            expected = f"argc={len(argv)}\n".encode()
            expected += b"".join(f"argv[{i}]=[{a}] len={len(a.encode())}\n".encode() for i, a in enumerate(argv))
            session_env = [f"{k}={v}" for k, v in env.items()]
            expected += b"".join(f"env[{i}]=[{e}]\n".encode() for i, e in enumerate(session_env))
            expected += f"envc={len(session_env)}\n".encode()
            self.check(f"vector {vector.stem}: argc and argv exact (argv[0] is the shell's path, not "
                       f"{want['argv'][0]!r}); environment is the session's",
                       (rc, out, err) == (0, expected, b"") and len(pids) == 1 and want["argc"] == len(argv),
                       f"rc={rc} out={out[:400]!r} err={err!r}")
            executed.append("vector:" + vector.stem)
            print(f"C KIT VECTOR OK {vector.stem} argc={len(argv)} vector_env={len(want['env'])} "
                  f"session_env={len(session_env)}", flush=True)

        return executed


    def warm_capacity(self):
        """No SSH sampling traffic and no older-line or last-reading fallback."""
        deadline = time.monotonic() + 60
        reason = "capacity unavailable"
        while time.monotonic() < deadline:
            pair = (wb.latest_capacity(self.t.output(), "SERVED CAPACITY"),
                    wb.latest_capacity(self.t.serial(), "FSD CAPACITY"))
            try:
                wb.validate(pair)
                if hasattr(self, "warm"):
                    self.warm.same_boot(pair)
                if pair[0]['accepted_reclaimed'] == self.connections and self.t.all_images() == 0:
                    return pair
                reason = "capacity not current for all opened sessions"
            except wb.BaselineError as error:
                reason = str(error)
            time.sleep(0.2)
        raise wb.BaselineError("C KIT WARM CAPACITY UNSETTLED: " + reason)

    def warm_shapes(self):
        return (["shell-probe"] +
                ["case:" + case_key(p, stdin, args) for _, p, stdin, *args in self.cases] +
                ["held:c", "held:native"] +
                ["vector:" + p.stem for p in sorted(self.vectors.glob("*.json"))
                 if not json.loads(p.read_text()).get("refused")] + ["alive"])

    def rehearse(self, attempt, cwd):
        # Ordered stdio write/cat/verify is one repeatable chain, never a
        # blind repetition of individual stateful operations.
        self.check("rehearsal starts without stdio file",
                   not (cwd / "c-stdio.dat").exists() and
                   STDIO_FILE not in {o[0] for o in self.t.system_objects()})
        shapes = []
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                self.rehearsed_env = self.probe_shell()
                shapes.append("shell-probe")
                for route, program, stdin, *args in self.cases:
                    key, got, ref, pids = self.run_case(route, program, stdin, args, self.rehearsed_env, cwd)
                    self.quiescent()
                    if key in RETAINED:
                        self.check_stdio_file(key, {"objects": self.t.system_objects()}, cwd)
                    self.judge(key, program, got, ref, pids)
                    shapes.append("case:" + key)
                self.live_frames("rehearsal c", ["/bin/short"], rehearsal=True)
                shapes.append("held:c")
                self.live_frames("rehearsal native", ["/bin/head", "-c", "1"], rehearsal=True)
                shapes.append("held:native")
                shapes.extend(self.run_vectors(self.rehearsed_env))
                self.alive("C kit rehearsal")
                shapes.append("alive")
        finally:
            for line in output.getvalue().splitlines():
                print(f"C KIT REHEARSAL {attempt} {line}", flush=True)
        self.check("rehearsal finishes without stdio file",
                   not (cwd / "c-stdio.dat").exists() and
                   STDIO_FILE not in {o[0] for o in self.t.system_objects()})
        return shapes

    def run(self):
        t = self.t
        started = time.monotonic()
        t.setup(self.work, (self.op.with_suffix(".pub")).read_text())
        imported = time.monotonic()
        first = t.start(fresh=True)
        listening = time.monotonic()
        print(f"C KIT BOOT SECONDS import={imported - started:.1f} sshd={listening - imported:.1f}", flush=True)
        self.client = sm.Client(self.work, t.port)
        self.client.trust(first["public"])
        cwd = self.work / "linux-cwd"
        cwd.mkdir(exist_ok=True)
        if self.pin:
            # Preserve the existing authoring route, explicitly outside warm
            # qualification. Its original single concurrency warmup is below.
            print("C KIT WARM NOT_ESTABLISHED reason=pin-authoring", flush=True)
            env = self.probe_shell()
        else:
            cold = self.warm_capacity()
            self.warm = wb.WarmBaseline(cold, self.warm_shapes(),
                lambda record: print("C KIT WARM " + json.dumps(record, sort_keys=True), flush=True))
            self.warm.establish(lambda n: self.rehearse(n, cwd), self.warm_capacity)
            env = self.rehearsed_env
            print("C KIT WARM SCOPE c-kit=established R23=PARTIAL stopping-cases=NOT_ESTABLISHED", flush=True)
        counts = {"agree": 0, "diverge": 0, "pinned": 0, "defect": 0}
        resources = 0
        self._settled_census = None
        for route, program, stdin_name, *args in self.cases:
            before = self.stable(" ".join([program, *args]) or program, "before", confirm=True)
            case_start = time.monotonic()
            key, got, ref, pids = self.run_case(route, program, stdin_name, args, env, cwd)
            took = time.monotonic() - case_start
            after = self.stable(key, "after", settle_to=before)
            memory, kernel = self.compare_census(key, before, after)
            if key in RETAINED:
                self.check_stdio_file(key, after, cwd)
            resources += 1
            counts[self.judge(key, program, got, ref, pids)] += 1
            self._settled_census = after
            print(f"C KIT RESOURCES {key} :: {memory} | {kernel} | images={after['images']} "
                  f"objects={len(after['objects'])} seconds={took:.1f}", flush=True)
        if self.pin:
            self.live_frames("warmup", ["/bin/short"], warmup=True)
        c_frames, rest = self.live_frames("c", ["/bin/short"])
        native_frames, _ = self.live_frames("native", ["/bin/head", "-c", "1"])
        print(f"C KIT FRAMES LIVE c={c_frames} native={native_frames} rest={rest} :: frames allocated while one "
              f"session holds the program blocked on stdin, above the rest reading (pre-touch "
              f"{PRETOUCH_PAGES} pages per C process by construction)", flush=True)
        self.run_vectors(env)
        self.alive("the C kit cases")
        if not self.pin:
            self.warm.measured_group(self.warm_capacity())
        t.stop()
        print(f"C KIT SHELL OK cases={len(self.cases)} agree={counts['agree']} diverge={counts['diverge']} "
              f"pinned={counts['pinned']} defects={counts['defect']}", flush=True)
        print(f"C KIT RESOURCES OK cases={resources}", flush=True)
        print(f"C KIT MATRIX OK seconds={time.monotonic() - started:.0f}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    for name in ("work", "kit", "absd", "linux", "vectors"):
        ap.add_argument(f"--{name}", required=True)
    ap.add_argument("--pin", action="append", help="write shell-expected/<case>.txt from this run (review it)")
    args, rest = ap.parse_known_args()
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    base = ssh_absd.target(rest)
    target = KitTarget.__new__(KitTarget)
    target.__dict__.update(base.__dict__)
    matrix = KitMatrix(target, work, args)
    try:
        matrix.run()
    except (sm.Failed, ssh_absd.Failed, wb.BaselineError) as e:
        print(f"C KIT MATRIX FAILED: {e}", file=sys.stderr)
        target.stop()
        sys.exit(1)
    except BaseException:
        target.stop()
        raise


if __name__ == "__main__":
    main()
