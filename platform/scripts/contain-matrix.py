#!/usr/bin/env python3
"""Session containment matrix (experiment E2 of tranche A): does ending a
session end everything it started, and does `reboot` still restart the
machine when a session left something running?

Every boot is a `net fsd served` boot (scripts/served-matrix.py) of a copy
of one base image per configuration; every client is the host's
/usr/bin/ssh. Each case starts a session, lets its commands start (the
kernel's own SPAWN lines, not a delay), and ends it one of three ways:

  disconnect  the client is killed (SIGKILL): sshd sees the channel or the
              connection close
  timeout     the client stays connected and silent; sshd's idle timeout
              (/etc/sshd.conf `idle-timeout`, short in this configuration)
              ends the session
  shutdown    another session asks for `shutdown` or `reboot` while the
              case runs; one boot per case

Oracle, per case (disconnect, timeout: several cases share a boot and each
is checked before the next starts; shutdown: the boot's end):

  * the session's processes are gone: every image process started since the
    case began has a USER EXIT/KILLED/FAULT line, and killed ones were
    killed by their parent (the shell) or, for a command sshd started
    directly, by sshd
  * INIT ORPHAN REAPED does not grow (nothing was left to init)
  * no `FSD BIND REFUSED` or `FSD DERIVE REFUSED` with status -16 (BUSY):
    no leftover holds a file server channel (`FSD BIND DEFERRED`, a bind
    that waited for a released slot's last request to be refused, is a
    retry, not a leak, and is not counted)
  * sshd's `SSH SESSION END` line for the session says forced=false (the
    shell acted on End within END_GRACE)
  * at the boot's end: `SERVED SHUTDOWN ... orphans_reaped=0 drained=true`,
    `DURABLE status=0 frames=0 processes=0 cells=0 pipes=0`, and for a
    `reboot` the restart (QEMU status 0 under ABSD_QEMU_REBOOT=exit, or the
    machine booting again under =allow)

Controls (each expected to leave residue, labelled, never counted as a
pass of the claim):

  negative    a qualification-only absd-sh that keeps the spawn right:
              `absd-sh -c "sshtest sleep 600000"` then disconnect leaves the
              grandchild, and the boot ends drained=false (status 71). With
              the installed shell the nested start is refused and the boot
              drains
  shell-killed  a qualification-only sshd kills every session shell
              without End: its command is orphaned (status 71)
  sshd-died   the same sshd exits at once with a session running: tranche
              B's case, status 71
  lent-broken the third stage of an unredirected pipeline is lent the
              shell's own channel (both spares busy; with a redirection the
              shell copies and refuses the stage instead); `fsd-probe
              garbage` writes bytes that are no frame there. Since the
              2026-10-02 audit repair the file server drops them and the
              channel goes on: the shell's next request (`cd`) is answered,
              End is read, the end is not forced, and the boot drains. The
              same holds for a lent writer killed between the transfers of
              one frame (host tests in fsd/tests/audit_probe.rs)

The orphan-reaped check uses the same sshd for the other half of that
story: a command left by a killed shell that ends on its own is reaped by
init, its file server channel is served again, and the boot then drains
and halts. It is a check that must pass, run with the controls.

The scratch part: one session fills its /tmp/session-N with many files
and ends together with another session whose shell is copying a command's
output into a file through the file server. Removing the scratch tree at
release is one commit, so both ends are unforced and a new session is
served within 20 s of the disconnects (with one commit per file, as
before, 1200 files held sshd and the file server for about a minute), and
the release reports every file removed.

A case that fails is reported with its evidence and the matrix goes on to
the next boot; the exit status is 1 if any case other than a control
failed, or if a control did not show its residue.
"""

import argparse
import json
import pathlib
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import importlib.util

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import ssh_absd  # noqa: E402

spec = importlib.util.spec_from_file_location("served_matrix", here / "served-matrix.py")
srv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(srv)
sm = srv.sm

PROMPT = b"absd$ "
SHUTDOWN_SECONDS = 240
IDLE_SECONDS = 10
LONG = "600000"

SSH_CAPACITY = re.compile(
    r"^SERVED CAPACITY boot=(?P<boot>[0-9a-f]{32}) accepted_reclaimed=(?P<accepted_reclaimed>\d+) "
    r"slots=(?P<slots>\d+) pool=(?P<pool>\d+) net_sockets=(?P<net_sockets>\d+) "
    r"net_closing=(?P<net_closing>\d+) processes=(?P<processes>\d+) handles=(?P<handles>\d+) "
    r"pipes=(?P<pipes>\d+) cells=(?P<cells>\d+) frames=(?P<frames>\d+) "
    r"heap_pages_peak=(?P<heap_pages_peak>\d+)(?=\r?\n|$)", re.MULTILINE)
FSD_CAPACITY = re.compile(
    r"^FSD CAPACITY boot=(?P<boot>[0-9a-f]{32}) settled_releases=(?P<settled_releases>\d+) "
    r"fs_objects=(?P<fs_objects>\d+) rotated_logs=(?P<rotated_logs>\d+) "
    r"bound=(?P<bound>\d+) opens=(?P<opens>\d+) draining=(?P<draining>\d+) "
    r"heap_pages_peak=(?P<heap_pages_peak>\d+)(?=\r?\n|$)", re.MULTILINE)


def capacity_record(pattern, text):
    matches = list(pattern.finditer(text))
    if not matches:
        return None
    record = matches[-1].groupdict()
    return {key: value if key == "boot" else int(value) for key, value in record.items()}


class CaseFailed(Exception):
    pass


def need(ok, what, detail=""):
    if not ok:
        raise CaseFailed(f"{what}: {detail}" if detail else what)


def fsd_group_settlements(serial, expected_binds, what):
    """Count successful session bindings and their settled primary/spares."""
    bound_records = list(re.finditer(
        r"^FSD BIND slot=(\d+) spares=\[([0-9, ]*)\] mounts=[^\r\n]*(?=\r?\n|$)",
        serial, re.MULTILINE))
    release_records = list(re.finditer(
        r"^FSD RELEASE slot=(\d+) closed=\d+ scratch_removed=\d+ fs_objects=\d+ "
        r"bound=\d+ opens=\d+ draining=\d+(?=\r?\n|$)", serial, re.MULTILINE))
    bound = [(record.group(1), record.group(2)) for record in bound_records]
    released = [record.group(1) for record in release_records]
    need(len(bound) == expected_binds and len(released) == expected_binds,
         f"{what}: exact successful FSD BIND/RELEASE count",
         f"expected={expected_binds} bound={bound} released={released}")
    need(sorted(slot for slot, _ in bound) == sorted(released),
         f"{what}: every successful FSD binding was released",
         f"bound={bound} released={released}")
    live = set()
    events = sorted(((record.start(), "bind", record.group(1)) for record in bound_records),
                    key=lambda event: event[0])
    events += [(record.start(), "release", record.group(1)) for record in release_records]
    for _, kind, slot in sorted(events):
        if kind == "bind":
            need(slot not in live, f"{what}: slot not rebound before release", f"slot={slot} events={events}")
            live.add(slot)
        else:
            need(slot in live, f"{what}: RELEASE follows its BIND", f"slot={slot} events={events}")
            live.remove(slot)
    need(not live, f"{what}: all FSD bindings released", f"live={live}")
    settled = 0
    for slot, spare_text in bound:
        spares = [] if not spare_text.strip() else [part.strip() for part in spare_text.split(",")]
        need(all(spare.isdigit() for spare in spares), f"{what}: well-formed FSD spare list",
             f"slot={slot} spares={spare_text!r}")
        settled += 1 + len(spares)
    return settled


def check_fsd_group_settlements():
    """Small parser qualification: direct, shell, and refused/mismatched records."""
    release = "FSD RELEASE slot={} closed=0 scratch_removed=1 fs_objects=20 bound=0 opens=1 draining=0\n"
    direct = "FSD BIND slot=1 spares=[] mounts=/tmp:rw\n" + release.format(1)
    shell = "FSD BIND slot=1 spares=[2, 3] mounts=/tmp:rw\n" + release.format(1)
    need(fsd_group_settlements(direct, 1, "direct parser") == 1, "direct binding settles one channel")
    need(fsd_group_settlements(shell, 1, "shell parser") == 3, "shell binding settles three channels")
    for bad in ("FSD BIND REFUSED slot=1 status=-16\n" + release.format(1),
                "FSD BIND slot=1 spares=[] mounts=/tmp:rw\n" + release.format(2),
                release.format(1) + "FSD BIND slot=1 spares=[] mounts=/tmp:rw\n"):
        try:
            fsd_group_settlements(bad, 1, "negative parser")
        except CaseFailed:
            continue
        raise CaseFailed("FSD parser accepted a refused, mismatched, or reversed binding")


class Config:
    """One image: which sshd and shell, and /etc/sshd.conf."""

    def __init__(self, name, sshd, shell, conf=None):
        self.name, self.sshd, self.shell, self.conf = name, sshd, shell, conf


class ContainTarget(srv.ServedTarget):
    def files(self, authorized):
        files = super().files(authorized)
        # The pipeline cases' silent last stage.
        files.append(("/bin/wc", (self.root / "commands" / "wc").read_bytes()))
        if self.conf is not None:
            files.append(("/etc/sshd.conf", self.conf))
        return files

    def sshd_iso(self, regenerate=False):
        server = self.fsd_elf
        return self.iso(0, self.sshd_elf, options="net fsd served", server=server)


class Session:
    """A client: `proc` (stdin pipe, no terminal) or `term` (PTY)."""

    def __init__(self, boot, pid, proc=None, term=None, what=""):
        self.boot, self.pid, self.proc, self.term, self.what = boot, pid, proc, term, what

    def disconnect(self):
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.kill()
            self.proc.communicate()
        if self.term is not None:
            self.term.close()
            self.term = None

    def close_quietly(self):
        try:
            self.disconnect()
        except Exception:
            pass


class Boot:
    def __init__(self, lab, config, reboot=None):
        self.lab, self.config = lab, config
        t = lab.target(config)
        shutil.copyfile(lab.base[config.name], t.image)
        t.served = True
        if reboot:
            import os
            os.environ["ABSD_QEMU_REBOOT"] = reboot
        try:
            info = t.start()
        finally:
            import os
            os.environ.pop("ABSD_QEMU_REBOOT", None)
        self.t = t
        self.client = sm.Client(t.work, t.port)
        self.client.trust(info["public"])
        self.op = lab.op
        self.sessions = []
        self.baseline = dict(t.live_images())

    # -- what the serial log says -------------------------------------------

    def serial(self):
        return self.t.serial()

    def worker(self):
        return self.t.output()

    def children(self):
        """(pid, argv0, control) of every session child sshd started."""
        return re.findall(r"SSH SESSION CHILD pid=(\d+) spawn_right=\w+ argv0=(\S+) [^\n]*control=(\w+)", self.worker())

    def ends(self):
        return {int(m.group(1)): m.groupdict() for m in re.finditer(
            r"SSH SESSION END pid=(\d+) sent=(?P<sent>\d) exited=(?P<exited>\w+) forced=(?P<forced>\w+) "
            r"ms=(?P<ms>\d+)(?: read=(?P<read>-?\d+))?", self.worker())}

    def orphans(self):
        return len(self.t.reaped_orphans())

    def busy(self):
        text = self.serial() + self.worker()
        return len(re.findall(r"FSD (?:BIND|DERIVE) REFUSED \S+ status=-16", text))

    def quiescent_capacity(self, min_accepted, min_settled, timeout=60):
        """Latest complete SSH and settled-FSD samples from this served boot."""
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            ssh = capacity_record(SSH_CAPACITY, self.worker())
            fsd = capacity_record(FSD_CAPACITY, self.serial())
            last = (ssh, fsd)
            if ssh is not None and fsd is not None and \
                    ssh["accepted_reclaimed"] >= min_accepted and fsd["settled_releases"] >= min_settled:
                need(ssh["boot"] == fsd["boot"], "SSH and FSD capacity samples name the same boot", f"{last}")
                need(all(ssh[key] == 0 for key in ("slots", "pool", "net_closing")),
                     "SSH capacity sample is quiescent", f"{ssh}")
                # sshd keeps its control-channel log open after first use.
                # Its exact open count is compared at warmed baseline/final.
                need(all(fsd[key] == 0 for key in ("bound", "draining")),
                     "FSD capacity sample is settled", f"{fsd}")
                need(fsd["rotated_logs"] <= 2 and fsd["fs_objects"] >= fsd["rotated_logs"],
                     "FSD named rotated-log count is valid", f"{fsd}")
                return ssh, fsd
            time.sleep(0.1)
        raise CaseFailed(f"quiescent capacity missing accepted>={min_accepted} settled>={min_settled}: {last}")

    def await_worker(self, pattern, start=0, timeout=30):
        """Wait for one complete worker line emitted after `start`."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            match = re.search(pattern, self.worker()[start:], re.MULTILINE)
            if match is not None:
                return match
            time.sleep(0.1)
        raise CaseFailed(f"worker marker missing: {pattern!r}; tail={self.worker()[start:][-600:]!r}")

    def spawned_since(self, mark):
        """Image processes the kernel started after serial offset `mark`."""
        return re.findall(r"SPAWN OK pid=(\d+) parent=(\d+) program=image", self.serial()[mark:])

    def fates(self):
        text = self.serial()
        fate = {}
        for m in re.finditer(r"USER (EXIT|FAULT) pid=(\d+)", text):
            fate[m.group(2)] = (m.group(1), None)
        for m in re.finditer(r"USER KILLED pid=(\d+) by=(\d+)", text):
            fate[m.group(1)] = ("KILLED", m.group(2))
        return fate

    # -- sessions -----------------------------------------------------------

    def _await_child(self, before, what, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            kids = self.children()
            if len(kids) > before:
                return int(kids[before][0])
            time.sleep(0.1)
        raise CaseFailed(f"{what}: no session child started ({self.t.census_detail()})")

    def _await_spawns(self, mark, count, what, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self.spawned_since(mark)) >= count:
                return
            time.sleep(0.05)
        raise CaseFailed(f"{what}: expected {count} image starts, saw {self.spawned_since(mark)}")

    def shell(self, line, spawns, pty=False, what=""):
        """A shell session running `line` (bytes, no newline); waits until
        `spawns` image processes (the shell included) have started."""
        mark = len(self.serial())
        before = len(self.children())
        if pty:
            term = self.client.terminal(self.op, extra=("-t",))
            need(term.wait_raw() and term.expect(PROMPT, timeout=60), f"{what}: PTY prompt", repr(term.shown[-200:]))
            pid = self._await_child(before, what)
            if line:
                term.type(line + b"\r")
            session = Session(self, pid, term=term, what=what)
        else:
            proc = subprocess.Popen(self.client.base(self.op), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            if line:
                proc.stdin.write(line + b"\n")
                proc.stdin.flush()
            pid = self._await_child(before, what)
            session = Session(self, pid, proc=proc, what=what)
        self.sessions.append(session)
        if spawns:
            self._await_spawns(mark, spawns, what)
        return session, mark

    def exec(self, command, spawns, stdin=b"", what=""):
        mark = len(self.serial())
        before = len(self.children())
        proc = subprocess.Popen(self.client.base(self.op) + [command], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if stdin:
            proc.stdin.write(stdin)
            proc.stdin.flush()
        pid = self._await_child(before, what)
        session = Session(self, pid, proc=proc, what=what)
        self.sessions.append(session)
        if spawns:
            self._await_spawns(mark, spawns, what)
        return session, mark

    def ssh(self, command=None, stdin=b"", timeout=120):
        return self.client.run(self.op, command, stdin=stdin, timeout=timeout)

    # -- the per-case oracle -------------------------------------------------

    def settle(self, session, mark, orphans, busy, control=True, timeout=45):
        """Everything the case started since `mark` has ended; nothing went
        to init; no channel is busy; sshd's End was not forced."""
        started = self.spawned_since(mark)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            fates = self.fates()
            left = [pid for pid, _ in started if pid not in fates]
            ended = session.pid in self.ends() or not control
            if not left and ended:
                break
            time.sleep(0.2)
        fates = self.fates()
        left = [pid for pid, _ in started if pid not in fates]
        need(not left, "every process the session started has ended",
             f"left={left} started={started} {self.t.census_detail()}")
        # Killed ones were killed by their own parent.
        wrong = [(pid, parent, fates[pid][1]) for pid, parent in started
                 if fates[pid][0] == "KILLED" and fates[pid][1] != parent]
        need(not wrong, "each kill came from the process's parent", f"{wrong}")
        need(self.orphans() == orphans, "nothing was left to init (INIT ORPHAN REAPED unchanged)",
             f"{orphans} -> {self.orphans()}")
        need(self.busy() == busy, "no file server channel refused BUSY", f"{busy} -> {self.busy()}")
        end = self.ends().get(session.pid)
        if control and self.lab.args.expect_end:
            need(end is not None, "sshd logged the session's End", self.worker()[-800:])
            need(end["forced"] == "false", "the shell acted on End (not forced)", f"{end}")
        return end

    # -- the boot's end ------------------------------------------------------

    def finish(self, action="halt", expect_drained=True, via="exec"):
        """Ends the boot with `shutdown` or `reboot` and checks the
        accounting. Returns QEMU's status."""
        t = self.t
        word = "shutdown" if action == "halt" else "reboot"
        rc, out, err = self.ssh(word)
        need(rc == 0 and f"going down for {action}".encode() in out, f"`{word}` is answered", f"{rc} {out!r} {err!r}")
        status = t.status(SHUTDOWN_SECONDS)
        for s in self.sessions:
            s.close_quietly()
        serial = t.serial()
        first = serial.split("ABSD KERNEL BOOT\n")[1] if serial.count("ABSD KERNEL BOOT\n") > 1 else serial
        seen = srv.seen(first)
        self.last = seen
        drained = re.search(r"SERVED SHUTDOWN action=(\w+) worker_status=(\d+) file_server_status=(\d+) "
                            r"orphans_reaped=(\d+) drained=(\w+)", seen)
        need(drained is not None, "init reports the served shutdown", seen[-1500:])
        if not expect_drained:
            return status, drained, seen
        need(drained.group(5) == "true", "drained=true", drained.group(0))
        need(drained.group(4) == "0", "orphans_reaped=0 (nothing was left to init)", drained.group(0))
        need(re.search(r"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ", seen) is not None,
             "final accounting: processes=0 pipes=0", seen[-1200:])
        need(self.orphans() == 0, "INIT ORPHAN REAPED = 0 in this boot", f"{self.orphans()}")
        forced = [e for e in self.ends().values() if e["forced"] != "false"]
        need(not forced, "no End was forced", f"{forced}")
        need(self.busy() == 0, "no BUSY refusal in this boot", f"{self.busy()}")
        if action == "halt":
            need(status == "3", "the machine halts (QEMU status 3)", f"status={status}")
        else:
            need("MACHINE RESTART" in seen or "MACHINE RESTART" in serial, "the machine restarts", seen[-600:])
            need(status in ("0", None), "restart ends QEMU with 0 under ABSD_QEMU_REBOOT=exit", f"status={status}")
        return status, drained, seen

    def abandon(self):
        for s in self.sessions:
            s.close_quietly()
        self.t.stop()


# -- the cases ---------------------------------------------------------------

def c(line):
    return line.encode()


# name: (kind, what, spawns incl. the session child, control, columns)
# kind: shell (no PTY), pty, exec
CASES = [
    ("prompt", "shell", b"", 1, True, "dts", "a shell idle at its prompt"),
    ("sleeper", "shell", c(f"sshtest sleep {LONG}"), 2, True, "dts", "foreground sleeper"),
    ("pty-sleeper", "pty", c(f"sshtest sleep {LONG}"), 2, True, "dts", "sleeper on a PTY"),
    ("pipeline", "shell", c("sshtest zeros 1000000000 | cat | nofs wc -c"), 4, True, "dts", "3-stage pipeline moving bytes"),
    ("blocked-writer", "shell", c(f"sshtest zeros 1000000 | sshtest sleep {LONG}"), 3, True, "dts",
     "writer blocked on a full pipe"),
    ("blocked-reader", "shell", c(f"sshtest sleep {LONG} | cat"), 3, True, "dts", "reader blocked on a pipe"),
    ("stdin-reader", "shell", c("cat"), 2, True, "dts", "cat blocked on the session's input"),
    ("copier", "shell", c("sshtest drip > /home/operator/drip"), 2, True, "dts", "in-shell copier into a file"),
    ("exec-upload", "exec", "cat > /home/operator/upload", 2, True, "dts", "exec shell: cat > FILE, input open"),
    ("exec-pipeline", "exec", f"sshtest sleep {LONG} | cat", 3, True, "dts", "exec shell: ssh host 'cmd | cmd'"),
    ("exec-direct", "exec", f"sshtest sleep {LONG}", 1, False, "dts", "exec without the spawn right (sshd's child)"),
    ("ro", "shell", c(f"ro sshtest sleep {LONG}"), 2, True, "dts", "ro child (read-only spare)"),
    ("nofs", "shell", c(f"nofs sshtest sleep {LONG}"), 2, True, "dts", "nofs child (no channel)"),
    ("mid-fsd", "shell", c("fsd-probe stat-loop /etc/motd 100000000"), 2, True, "dts", "command mid-fsd request"),
    ("fsd-writer", "shell", c(f"fsd-probe hold /home/operator/held {LONG}"), 2, True, "dts",
     "command writing and syncing"),
    ("exit-then-close", "shell", c("sshtest exit 3"), 2, True, "d", "disconnect before the shell saw completion"),
]


class Lab:
    def __init__(self, args):
        self.args = args
        self.work = pathlib.Path(args.work).resolve()
        self.root = pathlib.Path(args.platform).resolve()
        self.kernel = pathlib.Path(args.kernel).resolve()
        self.qemu = args.qemu
        if args.operator_key:
            key = pathlib.Path(args.operator_key).resolve()
            if key == self.work or self.work in key.parents:
                raise SystemExit("--operator-key must be outside the matrix work directory")
            if not key.is_file() or not key.with_suffix(".pub").is_file():
                raise SystemExit("--operator-key requires an existing private key and matching .pub file")
            self.op = key
        else:
            key = self.work / "id_operator"
            self.op = key if key.exists() else sm.keygen(key)
        self.base = {}
        self.targets = {}
        self.results = []
        self.rng = random.Random(args.seed)

    def target(self, config):
        if config.name in self.targets:
            return self.targets[config.name]
        work = self.work / config.name
        work.mkdir(parents=True, exist_ok=True)
        t = ContainTarget.__new__(ContainTarget)
        t.kernel, t.root, t.qemu = self.kernel, self.root, self.qemu
        t.shell = pathlib.Path(config.shell).resolve()
        t.boot_seconds = 7200
        t.proc, t.boots, t.port = None, 0, None
        t.sshd_elf = pathlib.Path(config.sshd).resolve()
        t.fsd_elf = pathlib.Path(self.args.fsd).resolve() if self.args.fsd else self.root / "absd-fsd.elf"
        t.conf = config.conf
        t.served = True
        self.targets[config.name] = t
        return t

    def prepare(self, config):
        """Imports the deployment, generates the host key with one boot,
        halts, and keeps the image as this configuration's base."""
        if config.name in self.base:
            return
        t = self.target(config)
        # A fresh directory: an earlier run's image and logs are not reused.
        shutil.rmtree(self.work / config.name, ignore_errors=True)
        (self.work / config.name).mkdir(parents=True)
        t.setup(self.work / config.name, self.op.with_suffix(".pub").read_text())
        info = t.start()
        client = sm.Client(t.work, t.port)
        client.trust(info["public"])
        rc, out, err = client.run(self.op, "shutdown")
        status = t.status(SHUTDOWN_SECONDS)
        if rc != 0 or status != "3":
            raise SystemExit(f"{config.name}: base boot did not halt: rc={rc} status={status} {t.serial()[-800:]}")
        base = t.work / "base.img"
        shutil.copyfile(t.image, base)
        self.base[config.name] = base
        print(f"BASE IMAGE {config.name} ready", flush=True)

    def record(self, column, case, ok, detail="", control=False, expected=True):
        verdict = "PASS" if ok == expected else "FAIL"
        self.results.append({"column": column, "case": case, "verdict": verdict, "control": control,
                             "detail": detail})
        print(f"E2 {verdict} {column:<10} {case:<18} {detail}", flush=True)

    def returned_capacity(self, first, last, what):
        first_ssh, first_fsd = first
        last_ssh, last_fsd = last
        need(first_ssh["boot"] == first_fsd["boot"] == last_ssh["boot"] == last_fsd["boot"],
             f"{what}: one boot for all capacity samples")
        for field in ("slots", "pool", "net_sockets", "net_closing", "processes", "handles",
                      "pipes", "cells", "frames", "heap_pages_peak"):
            need(first_ssh[field] == last_ssh[field], f"{what}: SSH {field} returned",
                 f"{first_ssh[field]} -> {last_ssh[field]}")
        for field in ("bound", "opens", "draining", "heap_pages_peak"):
            need(first_fsd[field] == last_fsd[field], f"{what}: FSD {field} returned",
                 f"{first_fsd[field]} -> {last_fsd[field]}")
        first_objects = first_fsd["fs_objects"] - first_fsd["rotated_logs"]
        last_objects = last_fsd["fs_objects"] - last_fsd["rotated_logs"]
        need(first_objects == last_objects, f"{what}: FSD objects returned apart from two named log rotations",
             f"{first_objects} -> {last_objects}")

    @staticmethod
    def capacity_fingerprint(sample):
        """Reusable occupancy only; cumulative counters are checked apart."""
        ssh, fsd = sample
        return (
            *(ssh[field] for field in ("slots", "pool", "net_sockets", "net_closing", "processes",
                                      "handles", "pipes", "cells", "frames", "heap_pages_peak")),
            *(fsd[field] for field in ("bound", "opens", "draining", "heap_pages_peak")),
            fsd["fs_objects"] - fsd["rotated_logs"],
        )

    @staticmethod
    def capacity_trace(name, phase, sample):
        ssh, fsd = sample
        print(f"E2 CAPACITY TRAJECTORY case={name} phase={phase} boot={ssh['boot']} "
              f"accepted_reclaimed={ssh['accepted_reclaimed']} settled_releases={fsd['settled_releases']} "
              f"slots={ssh['slots']} pool={ssh['pool']} net_sockets={ssh['net_sockets']} "
              f"net_closing={ssh['net_closing']} processes={ssh['processes']} handles={ssh['handles']} "
              f"pipes={ssh['pipes']} cells={ssh['cells']} frames={ssh['frames']} "
              f"ssh_heap_pages_peak={ssh['heap_pages_peak']} fsd_heap_pages_peak={fsd['heap_pages_peak']} "
              f"fs_objects={fsd['fs_objects']} rotated_logs={fsd['rotated_logs']} "
              f"bound={fsd['bound']} opens={fsd['opens']} draining={fsd['draining']}", flush=True)

    def capacity_after_group(self, boot, name, previous, accepted, binds, phase, serial_start):
        sample = boot.quiescent_capacity(previous[0]["accepted_reclaimed"] + accepted,
                                         previous[1]["settled_releases"] + binds)
        serial = boot.serial()[serial_start:]
        settled = fsd_group_settlements(serial, binds, f"{name}: {phase}")
        need(sample[0]["boot"] == previous[0]["boot"] == previous[1]["boot"] == sample[1]["boot"],
             f"{name}: {phase} stayed in one boot")
        need(sample[0]["accepted_reclaimed"] == previous[0]["accepted_reclaimed"] + accepted,
             f"{name}: {phase} exact accepted/reclaimed delta", f"expected={accepted} {previous} -> {sample}")
        need(sample[1]["settled_releases"] == previous[1]["settled_releases"] + settled,
             f"{name}: {phase} exact channel-settlement delta from BIND spares",
             f"expected={settled} {previous} -> {sample}")
        need(sample[1]["opens"] == 1, f"{name}: {phase} one persistent FSD control-log open",
             f"opens={sample[1]['opens']}")
        self.capacity_trace(name, phase, sample)
        return sample

    def rehearse_capacity(self, boot, name, group, accepted, binds):
        """At most three complete groups to establish a measured plateau."""
        previous = boot.quiescent_capacity(0, 0)
        self.capacity_trace(name, "raw", previous)
        for attempt in range(1, 4):
            serial_start = len(boot.serial())
            group(f"rehearsal-{attempt}")
            sample = self.capacity_after_group(boot, name, previous, accepted, binds,
                                               f"rehearsal-{attempt}", serial_start)
            if attempt >= 2 and self.capacity_fingerprint(sample) == self.capacity_fingerprint(previous):
                self.capacity_trace(name, "baseline", sample)
                return sample
            previous = sample
        raise CaseFailed(f"{name}: reusable capacity did not plateau within three representative groups")

    # -- running one case in a boot -------------------------------------------

    def start_case(self, boot, name):
        _, kind, line, spawns, control, _, what = next(x for x in CASES if x[0] == name)
        if kind == "exec":
            stdin = b"partial upload\n" if name == "exec-upload" else b""
            session, mark = boot.exec(line, spawns, stdin=stdin, what=name)
        else:
            session, mark = boot.shell(line, spawns, pty=(kind == "pty"), what=name)
        return session, mark, control

    def shared_column(self, config, how, names):
        """Cases one after another in one boot, each ended by `how`."""
        boot = Boot(self, config)
        try:
            for name in names:
                orphans, busy = boot.orphans(), boot.busy()
                idle_before = len(re.findall(r"end: idle timeout", boot.worker()))
                try:
                    session, mark, control = self.start_case(boot, name)
                    if name in ("mid-fsd", "fsd-writer"):
                        # A command keeping the file server busy must not
                        # keep sshd from serving (its log and binds go
                        # through the same server).
                        t0 = time.monotonic()
                        rc, out, err = boot.ssh("echo alive", timeout=60)
                        need(rc == 0 and out == b"alive\n", "a new session is served while it runs",
                             f"rc={rc} {err!r} after {time.monotonic() - t0:.1f}s")
                    if how == "disconnect":
                        if name != "exit-then-close":
                            time.sleep(0.5)
                        session.disconnect()
                    else:
                        deadline = time.monotonic() + IDLE_SECONDS + 60
                        while time.monotonic() < deadline and \
                                len(re.findall(r"end: idle timeout", boot.worker())) == idle_before:
                            time.sleep(0.3)
                        need(len(re.findall(r"end: idle timeout", boot.worker())) > idle_before,
                             "sshd ended the session at its idle timeout")
                    end = boot.settle(session, mark, orphans, busy, control=control)
                    session.close_quietly()
                    self.record(how, name, True, f"end={end['ms'] + 'ms' if end else 'killed-by-sshd'}")
                except CaseFailed as e:
                    self.record(how, name, False, str(e))
            try:
                boot.finish("halt")
                self.record(how, "boot-end", True, "drained=true processes=0 pipes=0")
            except CaseFailed as e:
                self.record(how, "boot-end", False, str(e))
        finally:
            boot.abandon()

    def shutdown_case(self, config, name, action):
        """One boot: the case runs, then `shutdown`/`reboot` from another
        session ends everything."""
        boot = Boot(self, config, reboot="exit" if action == "restart" else None)
        try:
            session, mark, control = self.start_case(boot, name)
            time.sleep(0.5)
            status, drained, seen = boot.finish(action)
            end = boot.ends().get(session.pid)
            how = f"end_ms={end['ms']}" if end else "ended without End (input closed)" if control else "killed by sshd"
            self.record("shutdown", name, True, f"{action}: drained=true orphans_reaped=0 status={status} {how}")
        except CaseFailed as e:
            self.record("shutdown", name, False, f"{action}: {e}")
        finally:
            boot.abandon()

    # -- races, churn, pressure -------------------------------------------------

    def race(self, config, kind, rounds):
        """End racing child exit (`sshtest sleep 50`, disconnect around 50
        ms after it starts) or End racing spawn (disconnect while a 3-stage
        pipeline starts). Random delays from --seed."""
        boot = Boot(self, config)
        delays = []
        failures = []
        try:
            for i in range(rounds):
                orphans, busy = boot.orphans(), boot.busy()
                mark = len(boot.serial())
                before = len(boot.children())
                proc = subprocess.Popen(boot.client.base(boot.op), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                try:
                    pid = boot._await_child(before, kind)
                    if kind == "race-exit":
                        # The shell is at its prompt: send the line, wait
                        # for the command's start, then a delay around its
                        # 50 ms life.
                        proc.stdin.write(b"sshtest sleep 50\n")
                        proc.stdin.flush()
                        boot._await_spawns(mark, 2, kind)
                        delay = self.rng.uniform(0.0, 0.12)
                    else:
                        proc.stdin.write(f"sshtest sleep {LONG} | cat | cat\n".encode())
                        proc.stdin.flush()
                        delay = self.rng.uniform(0.0, 0.25)
                    delays.append(delay)
                    time.sleep(delay)
                    proc.kill()
                    proc.communicate()
                    session = Session(boot, pid, what=kind)
                    boot.settle(session, mark, orphans, busy, control=True)
                except CaseFailed as e:
                    failures.append(f"round {i}: {e}")
                    proc.kill()
                    proc.communicate()
                    if len(failures) > 3:
                        break
            if failures:
                self.record("disconnect", f"{kind}x{rounds}", False, "; ".join(failures)[:2000])
            else:
                self.record("disconnect", f"{kind}x{rounds}", True,
                            f"delays {min(delays) * 1000:.0f}-{max(delays) * 1000:.0f} ms")
            try:
                boot.finish("halt")
                self.record("disconnect", f"{kind}-boot-end", True, "drained=true processes=0 pipes=0")
            except CaseFailed as e:
                self.record("disconnect", f"{kind}-boot-end", False, str(e))
        finally:
            boot.abandon()

    def churn(self, config, rounds):
        """connect / command / ^C / disconnect, over cases 1-3."""
        lines = [c(f"sshtest sleep {LONG}"), c("sshtest zeros 1000000000 | cat | nofs wc -c"),
                 c("sshtest drip > /home/operator/churn")]
        boot = Boot(self, config)
        failures = []
        successes = 0
        started = time.monotonic()
        try:
            def cycle(line, what):
                orphans, busy = boot.orphans(), boot.busy()
                spawns = 4 if b"|" in line else 2
                session, mark = boot.shell(line, spawns, pty=True, what=what)
                session.term.type(b"\x03")
                # (The pipeline's last stage may print its count between:
                # its input ended when the others were killed.)
                need(session.term.expect(b"^C\r\n", timeout=30) and session.term.expect(PROMPT, timeout=30)
                     and re.fullmatch(rb"(\d+\r\n)?", session.term.between) is not None,
                     f"{what}: ^C prompt", repr(session.term.shown[-200:]))
                session.disconnect()
                boot.settle(session, mark, orphans, busy, control=True)
                boot.sessions = []

            baseline = None
            try:
                # Every rehearsal covers all three later workloads. The
                # redirected case creates /home/operator/churn before the
                # baseline; no rehearsal counts toward the >=300 claim.
                def group(phase):
                    for j, line in enumerate(lines):
                        cycle(line, f"{phase} workload {j}")

                baseline = self.rehearse_capacity(boot, "churn", group, 3, 3)
            except CaseFailed as e:
                failures.append(f"warmup: {e}")

            if baseline is not None:
                measured_serial_start = len(boot.serial())
                for i in range(rounds):
                    try:
                        cycle(lines[i % len(lines)], f"churn {i}")
                        successes += 1
                        if successes % 25 == 0:
                            print(f"E2 CHURN PROGRESS boot={baseline[0]['boot']} "
                                  f"authenticated_cycles_completed={successes}/{rounds}", flush=True)
                    except CaseFailed as e:
                        failures.append(f"round {i}: {e}")
                        if len(failures) > 3:
                            break
                try:
                    first_ssh, first_fsd = baseline
                    need(successes == rounds, "requested authenticated cycles completed", f"{successes}/{rounds}")
                    last_ssh, last_fsd = self.capacity_after_group(
                        boot, "churn", baseline, successes, successes, "measured-final",
                        measured_serial_start)
                    self.returned_capacity(baseline, (last_ssh, last_fsd), "churn")
                    first_objects = first_fsd["fs_objects"] - first_fsd["rotated_logs"]
                    last_objects = last_fsd["fs_objects"] - last_fsd["rotated_logs"]
                    need(successes >= 300, ">=300 authenticated command/reply/close cycles completed",
                         f"{successes}/{rounds}")
                    self.record("capacity", f"churn x{rounds}", True,
                                f"boot={first_ssh['boot']} authenticated={successes} "
                                f"accepted_reclaimed={first_ssh['accepted_reclaimed']}->{last_ssh['accepted_reclaimed']} "
                                f"settled_releases={first_fsd['settled_releases']}->{last_fsd['settled_releases']} "
                                f"fs_objects_normalized={first_objects}->{last_objects}")
                except CaseFailed as e:
                    self.record("capacity", f"churn x{rounds}", False, str(e))
            else:
                self.record("capacity", f"churn x{rounds}", False, "; ".join(failures)[:2000])
            self.record("disconnect", f"churn x{rounds}", not failures,
                        "; ".join(failures)[:2000] if failures else f"{time.monotonic() - started:.0f}s")
            try:
                boot.finish("halt")
                self.record("disconnect", "churn-boot-end", True, "drained=true processes=0 pipes=0")
            except CaseFailed as e:
                self.record("disconnect", "churn-boot-end", False, str(e))
        finally:
            boot.abandon()

    def pressure(self, config, sessions, how):
        """`sessions` shells, each running the 3-stage pipeline, until the
        tables refuse; then all end by `how`."""
        boot = Boot(self, config, reboot="exit" if how == "restart" else None)
        opened, refused = [], []
        try:
            orphans, busy = boot.orphans(), boot.busy()
            mark = len(boot.serial())
            for i in range(sessions):
                before = len(boot.children())
                proc = subprocess.Popen(boot.client.base(boot.op), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                proc.stdin.write(b"sshtest zeros 1000000000 | cat | nofs wc -c\n")
                proc.stdin.flush()
                try:
                    pid = boot._await_child(before, f"pressure {i}", timeout=40)
                    boot.sessions.append(Session(boot, pid, proc=proc, what=f"pressure {i}"))
                    opened.append(pid)
                except CaseFailed:
                    refused.append(i)
                    proc.kill()
                    proc.communicate()
            time.sleep(3)
            started = boot.spawned_since(mark)
            shells = len(opened)
            commands = len(started) - shells
            note = f"sessions={shells}/{sessions} commands_started={commands}"
            if how in ("halt", "restart"):
                status, drained, seen = boot.finish(how)
                self.record("shutdown", f"pressure-{sessions}", True, f"{how}: {note} drained=true")
            else:
                for s in boot.sessions:
                    s.disconnect()
                for s in boot.sessions:
                    boot.settle(s, mark, orphans, busy, control=True, timeout=90)
                self.record("disconnect", f"pressure-{sessions}", True, note)
                boot.finish("halt")
                self.record("disconnect", f"pressure-{sessions}-boot-end", True, "drained=true processes=0 pipes=0")
        except CaseFailed as e:
            self.record(how if how == "disconnect" else "shutdown", f"pressure-{sessions}", False, str(e))
        finally:
            boot.abandon()

    def capacity(self, config, sessions):
        """Fill the global SSH table, refuse one more connection without
        making a session, then release one and serve an authenticated command."""
        boot = Boot(self, config)
        rows = []
        try:
            need(1 <= sessions <= 4, "configured max-connections is in the supported range", str(sessions))

            def group(phase):
                held = []
                group_rows = []
                for i in range(sessions):
                    orphans, busy = boot.orphans(), boot.busy()
                    # One directly executed sleeper per authenticated SSH
                    # session. Four simultaneous shell pipelines exceed the
                    # file-server spare-channel bound before the SSH limit.
                    session, mark = boot.exec(f"sshtest sleep {LONG}", 1, what=f"{phase} capacity {i}")
                    held.append((session, mark, orphans, busy))
                    group_rows.append((i + 1, "authenticated direct exec", session.pid))

                child_count = len(boot.children())
                refusal_start = len(boot.worker())
                try:
                    rc, out, err = boot.ssh("echo over-cap", timeout=15)
                except subprocess.TimeoutExpired as e:
                    raise CaseFailed(f"{phase}: full-table connection was not refused within 15 s: {e}") from e
                need(rc != 0, f"{phase}: full-table SSH connection refused",
                     f"rc={rc} out={out!r} err={err!r}")
                refusals = re.findall(
                    rf"^SSH GLOBAL REFUSED source=.* limit={sessions} slots={sessions} pool={sessions}(?=\r?\n|$)",
                    boot.worker()[refusal_start:], re.MULTILINE)
                need(refusals, f"{phase}: global limit refusal at full measured occupancy",
                     boot.worker()[refusal_start:][-600:])
                need(len(boot.children()) == child_count, f"{phase}: refused connection created no child",
                     f"{child_count} -> {len(boot.children())}")

                # Release the most recent session so its mark contains no
                # other still-running child, then prove authenticated reuse.
                session, mark, orphans, busy = held.pop()
                reclaimed = len(re.findall(r"SSH SESSION RECLAIMED children_started=", boot.worker()))
                session.disconnect()
                boot.settle(session, mark, orphans, busy, control=False)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline and \
                        len(re.findall(r"SSH SESSION RECLAIMED children_started=", boot.worker())) == reclaimed:
                    time.sleep(0.1)
                need(len(re.findall(r"SSH SESSION RECLAIMED children_started=", boot.worker())) > reclaimed,
                     f"{phase}: closed session slot reclaimed")
                rc, out, err = boot.ssh("echo capacity-reused", timeout=30)
                need(rc == 0 and out == b"capacity-reused\n", f"{phase}: authenticated command after refusal",
                     f"rc={rc} out={out!r} err={err!r}")
                group_rows.append(("reuse", "authenticated command", rc))

                for session, mark, orphans, busy in reversed(held):
                    session.disconnect()
                    boot.settle(session, mark, orphans, busy, control=False)
                boot.sessions = []
                return group_rows, len(refusals)

            baseline = self.rehearse_capacity(boot, "max-connections", group, sessions + 1, sessions + 1)
            measured_serial_start = len(boot.serial())
            rows, refusal_count = group("measured")
            final = self.capacity_after_group(boot, "max-connections", baseline, sessions + 1,
                                              sessions + 1, "measured-final", measured_serial_start)
            self.returned_capacity(baseline, final, "max-connections refusal/reuse")
            self.record("capacity", f"max-connections-{sessions}", True,
                        f"boot={baseline[0]['boot']} rows={rows} refusals={refusal_count} "
                        f"accepted_reclaimed={baseline[0]['accepted_reclaimed']}->{final[0]['accepted_reclaimed']}")
            boot.finish("halt")
        except CaseFailed as e:
            self.record("capacity", f"max-connections-{sessions}", False, f"rows={rows} {e}")
        finally:
            boot.abandon()

    def preauth_source(self, config):
        """Accepted same-source preauth slots are capped at two. Authentication
        stops consuming that allowance; closing a slot permits reuse."""
        boot = Boot(self, config)
        raw = []
        try:
            def connect():
                try:
                    conn = socket.create_connection(("127.0.0.1", boot.t.port), timeout=10)
                except OSError as e:
                    raise CaseFailed(f"raw preauth TCP connection failed: {e}") from e
                conn.settimeout(10)
                raw.append(conn)
                return conn

            def accepted():
                start = len(boot.worker())
                conn = connect()
                match = boot.await_worker(r"^sshd: conn (\d+): from (.+):(\d+)(?=\r?\n|$)", start)
                return conn, match.group(1), match.group(2)

            def refused(source):
                start = len(boot.worker())
                conn = connect()
                match = boot.await_worker(
                    r"^SSH PREAUTH REFUSED source=(.+?) reason=source-limit limit=2(?=\r?\n|$)", start)
                need(match.group(1) == source, "same source reached the accepted preauth limit",
                     f"accepted={source} refused={match.group(1)}")
                need(re.search(r"(?m)^sshd: conn \d+: from ", boot.worker()[start:]) is None,
                     "source-cap refusal created no SSH Slot")
                try:
                    data = conn.recv(1)
                except ConnectionResetError:
                    data = b""
                except socket.timeout as e:
                    raise CaseFailed("source-cap refusal did not close its TCP socket within 10 s") from e
                need(data == b"", "source-cap refusal closed its TCP socket", repr(data))
                conn.close()

            def group(phase):
                a, _, source = accepted()
                b, b_id, other_source = accepted()
                need(other_source == source, f"{phase}: two preauth sockets share one source",
                     f"{source} != {other_source}")
                refused(source)

                before = len(boot.worker())
                a.close()
                boot.await_worker(r"^SSH SESSION RECLAIMED children_started=\d+(?=\r?\n|$)", before)
                # B remains unauthenticated. Authentication frees its
                # per-source allowance while D stays in the global table.
                orphans, busy = boot.orphans(), boot.busy()
                session, mark = boot.shell(b"", 1, pty=True, what=f"{phase} source-cap authenticated")
                need(f"sshd: conn {b_id}: end:" not in boot.worker(),
                     f"{phase}: original preauth socket still live")
                e, _, e_source = accepted()
                need(e_source == source, f"{phase}: authentication freed preauth allowance")

                before = len(boot.worker())
                b.close()
                boot.await_worker(r"^SSH SESSION RECLAIMED children_started=\d+(?=\r?\n|$)", before)
                before = len(boot.worker())
                e.close()
                boot.await_worker(r"^SSH SESSION RECLAIMED children_started=\d+(?=\r?\n|$)", before)
                session.disconnect()
                boot.settle(session, mark, orphans, busy)
                rc, out, err = boot.ssh("echo source-reused", timeout=30)
                need(rc == 0 and out == b"source-reused\n", f"{phase}: authenticated service after close",
                     f"rc={rc} out={out!r} err={err!r}")
                boot.sessions = []
                raw.clear()
                return source

            baseline = self.rehearse_capacity(boot, "preauth-source", group, 5, 2)
            measured_serial_start = len(boot.serial())
            source = group("measured")
            final = self.capacity_after_group(boot, "preauth-source", baseline, 5, 2, "measured-final",
                                              measured_serial_start)
            self.returned_capacity(baseline, final, "preauth source close/auth reuse")
            self.record("capacity", "preauth-source", True,
                        f"boot={baseline[0]['boot']} source={source} accepted_reclaimed="
                        f"{baseline[0]['accepted_reclaimed']}->{final[0]['accepted_reclaimed']}")
            boot.finish("halt")
        except CaseFailed as e:
            self.record("capacity", "preauth-source", False, str(e))
        finally:
            for conn in raw:
                conn.close()
            boot.abandon()

    def preauth_timeout(self, config):
        """Unauthenticated login grace reclaims two Slots and permits a
        later accepted socket and authenticated command from the same source."""
        boot = Boot(self, config)
        raw = []
        try:
            def group(phase):
                ids = []
                prior_reclaimed = len(re.findall(r"(?m)^SSH SESSION RECLAIMED children_started=", boot.worker()))
                for _ in range(2):
                    start = len(boot.worker())
                    try:
                        conn = socket.create_connection(("127.0.0.1", boot.t.port), timeout=10)
                    except OSError as e:
                        raise CaseFailed(f"{phase}: raw preauth TCP connection failed: {e}") from e
                    raw.append(conn)
                    match = boot.await_worker(r"^sshd: conn (\d+): from .+(?=\r?\n|$)", start)
                    ids.append(match.group(1))
                for ident in ids:
                    boot.await_worker(rf"^sshd: conn {ident}: end: authentication timeout(?=\r?\n|$)",
                                      timeout=45)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline and \
                        len(re.findall(r"(?m)^SSH SESSION RECLAIMED children_started=", boot.worker())) < \
                        prior_reclaimed + 2:
                    time.sleep(0.1)
                need(len(re.findall(r"(?m)^SSH SESSION RECLAIMED children_started=", boot.worker())) >=
                     prior_reclaimed + 2, f"{phase}: both login-grace timeouts reclaimed")
                for conn in raw:
                    conn.close()

                start = len(boot.worker())
                try:
                    later = socket.create_connection(("127.0.0.1", boot.t.port), timeout=10)
                except OSError as e:
                    raise CaseFailed(f"{phase}: post-timeout TCP connection failed: {e}") from e
                raw.append(later)
                boot.await_worker(r"^sshd: conn \d+: from .+(?=\r?\n|$)", start)
                before = len(boot.worker())
                later.close()
                boot.await_worker(r"^SSH SESSION RECLAIMED children_started=\d+(?=\r?\n|$)", before)
                rc, out, err = boot.ssh("echo timeout-reused", timeout=30)
                need(rc == 0 and out == b"timeout-reused\n", f"{phase}: authenticated service after timeouts",
                     f"rc={rc} out={out!r} err={err!r}")
                raw.clear()
                return len(ids)

            baseline = self.rehearse_capacity(boot, "preauth-timeout", group, 4, 1)
            measured_serial_start = len(boot.serial())
            timed_out = group("measured")
            final = self.capacity_after_group(boot, "preauth-timeout", baseline, 4, 1, "measured-final",
                                              measured_serial_start)
            self.returned_capacity(baseline, final, "preauth timeout reuse")
            self.record("capacity", "preauth-timeout", True,
                        f"boot={baseline[0]['boot']} timed_out={timed_out} accepted_reclaimed="
                        f"{baseline[0]['accepted_reclaimed']}->{final[0]['accepted_reclaimed']}")
            boot.finish("halt")
        except CaseFailed as e:
            self.record("capacity", "preauth-timeout", False, str(e))
        finally:
            for conn in raw:
                conn.close()
            boot.abandon()

    def active_then_idle(self, config):
        """One authenticated SSH connection makes real command progress
        beyond 60 seconds, then its configured idle deadline reclaims it."""
        boot = Boot(self, config)
        try:
            def group(phase):
                orphans, busy = boot.orphans(), boot.busy()
                session, mark = boot.shell(b"", 1, pty=True, what=f"{phase} active beyond 60 seconds")
                started = time.monotonic()
                replies = 0
                try:
                    while time.monotonic() - started < 65:
                        session.term.type(b"echo active\r")
                        need(session.term.expect(PROMPT, timeout=8) and b"active\r\n" in session.term.between,
                             f"{phase}: authenticated SSH command replied during active interval",
                             repr(session.term.shown[-200:]))
                        replies += 1
                        need(session.pid not in boot.ends(), f"{phase}: authenticated session stayed open",
                             f"elapsed={time.monotonic() - started:.1f}s")
                        time.sleep(min(3, max(0, started + 65 - time.monotonic())))
                finally:
                    print(f"E2 ACTIVE PROGRESS phase={phase} elapsed={time.monotonic() - started:.1f} "
                          f"replies={replies}", flush=True)
                elapsed = time.monotonic() - started
                need(elapsed >= 65 and replies >= 10, f"{phase}: authenticated activity crossed 60 s",
                     f"elapsed={elapsed:.1f}s replies={replies}")
                # Stop SSH traffic without closing the client. Only sshd's
                # configured idle policy may end this accepted session now.
                idle_start = len(boot.worker())
                boot.await_worker(r"^sshd: conn \d+: end: idle timeout(?=\r?\n|$)", idle_start, timeout=35)
                boot.await_worker(r"^SSH SESSION RECLAIMED children_started=\d+(?=\r?\n|$)",
                                  idle_start, timeout=35)
                boot.settle(session, mark, orphans, busy)
                session.close_quietly()
                rc, out, err = boot.ssh("echo idle-reused", timeout=30)
                need(rc == 0 and out == b"idle-reused\n", f"{phase}: authenticated service after idle",
                     f"rc={rc} out={out!r} err={err!r}")
                boot.sessions = []
                return elapsed, replies

            baseline = self.rehearse_capacity(boot, "active-then-idle", group, 2, 2)
            measured_serial_start = len(boot.serial())
            elapsed, replies = group("measured")
            final = self.capacity_after_group(boot, "active-then-idle", baseline, 2, 2,
                                              "measured-final", measured_serial_start)
            self.returned_capacity(baseline, final, "active then idle SSH reuse")
            self.record("capacity", "active-then-idle", True,
                        f"boot={baseline[0]['boot']} active_seconds={elapsed:.1f} replies={replies} "
                        f"accepted_reclaimed={baseline[0]['accepted_reclaimed']}->{final[0]['accepted_reclaimed']}")
            boot.finish("halt")
        except CaseFailed as e:
            self.record("capacity", "active-then-idle", False, str(e))
        finally:
            boot.abandon()

    # -- a large scratch tree ending beside another session ---------------------------

    def scratch(self, config, files):
        """Session A fills its scratch with `files` files and sits at its
        prompt; session B's shell copies `sshtest drip` into a file (so the
        shell itself waits on the file server). B is disconnected, then A:
        A's release removes its tree while B's shell is being ended."""
        boot = Boot(self, config)
        try:
            orphans, busy = boot.orphans(), boot.busy()
            a, mark_a = boot.shell(c(f"fsd-probe fill-scratch {files} > /home/operator/fill"), 2,
                                   what="scratch-filler")
            filler = boot.spawned_since(mark_a)[-1][0]
            started = time.monotonic()
            deadline = started + 1200
            while time.monotonic() < deadline and filler not in boot.fates():
                # Keep the shell session active; sshd's configured idle
                # deadline is based on SSH activity, not a transport timer.
                a.proc.stdin.write(b"\n")
                a.proc.stdin.flush()
                time.sleep(5)
            filled = time.monotonic() - started
            need(boot.fates().get(filler, ("",))[0] == "EXIT", "the filler finished",
                 f"after {filled:.0f}s {boot.fates().get(filler)} {boot.worker()[-600:]}")
            rc, report, err = boot.ssh("cat /home/operator/fill", timeout=60)
            need(rc == 0 and report.startswith(f"fill-scratch: {files} files".encode()), "the filler's report",
                 f"{rc} {report!r} {err!r}")
            b, mark_b = boot.shell(c("sshtest drip > /home/operator/drip"), 2, what="scratch-neighbour")
            time.sleep(1)
            # Both clients go at once (neighbour first), so that both ends
            # are under way together.
            t0 = time.monotonic()
            b.proc.kill()
            a.proc.kill()
            b.disconnect()
            a.disconnect()
            end_b = boot.settle(b, mark_b, orphans, busy, control=True, timeout=300)
            end_a = boot.settle(a, mark_a, orphans, busy, control=True, timeout=300)
            rc, out, err = boot.ssh("echo alive", timeout=300)
            served = time.monotonic() - t0
            need(rc == 0 and out == b"alive\n", "a new session is served after", f"{rc} {err!r}")
            # Removing the tree is one commit: the ends and the next
            # session are not held up by it (one file per commit took about
            # as long as filling the tree did).
            need(served < 20, "both sessions ended and a new one was served within 20 s",
                 f"{served:.1f}s (filling took {filled:.0f}s)")
            released = re.findall(r"FSD RELEASE slot=\d+ closed=\d+ scratch_removed=(\d+)", boot.serial() + boot.worker())
            need(str(files + 1) in released, f"a release removed all {files} files and the directory", f"{released}")
            self.record("disconnect", f"scratch-{files}", True,
                        f"neighbour end={end_b['ms']}ms read={end_b.get('read')} filler end={end_a['ms']}ms "
                        f"served_after={served:.1f}s scratch_removed={files + 1} ({report.decode().strip()})")
            boot.finish("halt")
            self.record("disconnect", "scratch-boot-end", True, "drained=true processes=0 pipes=0")
        except CaseFailed as e:
            self.record("disconnect", f"scratch-{files}", False, str(e))
        finally:
            boot.abandon()

    # -- controls ------------------------------------------------------------------

    def orphan_reaped(self, config):
        """A shell killed without End leaves a command that ends on its own
        (5 s): init reaps it, its file server channel is bindable again,
        and the boot drains and halts. Must pass."""
        boot = Boot(self, config)
        try:
            session, mark = boot.shell(c("sshtest sleep 5000"), 2, what="orphan-reaped")
            command = boot.spawned_since(mark)[-1][0]
            rc, out, err = boot.ssh("qualification-kill-shells")
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and command not in boot.t.reaped_orphans():
                time.sleep(0.5)
            need(command in boot.t.reaped_orphans(), f"init reaped the orphaned command {command} once it ended",
                 boot.t.census_detail())
            need(boot.fates().get(command, ("",))[0] == "EXIT", "the orphan ran to its own end", f"{boot.fates().get(command)}")
            session.disconnect()
            busy = boot.busy()
            # Sessions until every slot has been bound once more: none is
            # refused BUSY now that the orphan is gone.
            for _ in range(3):
                rc2, out2, err2 = boot.ssh(None, stdin=b"ps\n")
                need(rc2 == 0 and b"other holders: input 0, file server channels 0" in out2,
                     "a later session is served and counts no leftover", f"{rc2} {out2!r} {err2!r}")
            need(boot.busy() == busy, "no BUSY refusal after the orphan ended", f"{busy} -> {boot.busy()}")
            status, drained, seen = boot.finish("halt", expect_drained=False)
            ok = drained.group(5) == "true" and status == "3"
            self.record("control", "orphan-reaped", ok,
                        f"orphan {command} reaped; {drained.group(0)} status={status}", control=True)
        except CaseFailed as e:
            self.record("control", "orphan-reaped", False, str(e), control=True)
        finally:
            boot.abandon()


    def negative(self, keep_config, deny_config):
        line = b'absd-sh -c "sshtest sleep 600000"'
        # Without the deny: the grandchild survives the End.
        boot = Boot(self, keep_config)
        try:
            session, mark = boot.shell(line, 3, what="negative")
            time.sleep(0.5)
            session.disconnect()
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and session.pid not in boot.ends():
                time.sleep(0.2)
            time.sleep(2)
            left = [pid for pid, _ in boot.spawned_since(mark) if pid not in boot.fates()]
            status, drained, seen = boot.finish("halt", expect_drained=False)
            ok = drained.group(5) == "false" and status == "71" and len(left) == 1
            self.record("control", "negative-keep-spawn", ok,
                        f"left={left} {drained.group(0)} status={status}", control=True)
        except CaseFailed as e:
            self.record("control", "negative-keep-spawn", False, str(e), control=True)
        finally:
            boot.abandon()
        # With the deny: the nested start is refused; the boot drains.
        boot = Boot(self, deny_config)
        try:
            orphans, busy = boot.orphans(), boot.busy()
            session, mark = boot.shell(line + b"\nstatus", 2, what="negative-deny")
            time.sleep(3)
            session.proc.stdin.close()
            session.proc.stdin = None
            out, err = session.proc.communicate(timeout=60)
            text = (out + err).decode(errors="replace")
            refused = re.search(r"absd-sh: sshtest: cannot run: [^\n]*", text)
            need(refused is not None and refused.group(0) == "absd-sh: sshtest: cannot run: permission denied",
                 "the nested shell's start is refused PermissionDenied", repr(text))
            need(re.search(r"(^|\$ )126\n", out.decode(errors="replace")) is not None, "the nested shell's status 126",
                 repr(text))
            boot.settle(session, mark, orphans, busy, control=False)
            status, drained, seen = boot.finish("halt")
            self.record("control", "negative-deny", True, f"{refused.group(0)!r}; drained=true", control=True)
        except CaseFailed as e:
            self.record("control", "negative-deny", False, str(e), control=True)
        finally:
            boot.abandon()

    def shell_killed(self, config):
        boot = Boot(self, config)
        try:
            session, mark = boot.shell(c(f"sshtest sleep {LONG}"), 2, what="shell-killed")
            rc, out, err = boot.ssh("qualification-kill-shells")
            time.sleep(3)
            left = [pid for pid, _ in boot.spawned_since(mark) if pid not in boot.fates()]
            session.disconnect()
            rc2, out2, err2 = boot.ssh(None, stdin=b"ps\n")
            busy = boot.busy()
            status, drained, seen = boot.finish("halt", expect_drained=False)
            ok = drained.group(5) == "false" and status == "71" and len(left) == 1
            self.record("control", "shell-killed", ok,
                        f"left={left} busy_refusals={busy} ps={out2.decode(errors='replace').strip()[-120:]!r} "
                        f"{drained.group(0)} status={status}", control=True)
        except CaseFailed as e:
            self.record("control", "shell-killed", False, str(e), control=True)
        finally:
            boot.abandon()

    def shell_killed_reboot(self, config):
        """A `reboot` asked while a session orphan survives (audit D2):
        init records the escalation, then takes the recovery reset with
        the orphan in the kernel census (kernel docs/PROCESS-STARTUP.md,
        "Served boot and orderly shutdown", outcome table)."""
        boot = Boot(self, config, reboot="exit")
        try:
            session, mark = boot.shell(c(f"sshtest sleep {LONG}"), 2, what="shell-killed-reboot")
            rc, out, err = boot.ssh("qualification-kill-shells")
            time.sleep(3)
            left = [pid for pid, _ in boot.spawned_since(mark) if pid not in boot.fates()]
            session.disconnect()
            status, drained, seen = boot.finish("restart", expect_drained=False)
            serial = boot.serial()
            recover = "MACHINE RECOVER RESET pid=1" in serial
            accounted = "MACHINE RESTART\n" in serial
            stop17 = "MACHINE STOP code=17" in serial
            unreaped = "SERVED SHUTDOWN UNREAPED adopted_child_residue=true" in serial
            escalated = ("SERVED SHUTDOWN ESCALATED requested=restart reason=unreaped "
                         "outcome=recovery_reset code=17") in serial
            # Repaired (kernel a619b3c): the escalation is recorded before
            # the recovery reset, and the orphan is in the kernel census.
            ok = (drained.group(5) == "false" and len(left) == 1 and unreaped and escalated
                  and recover and not accounted and not stop17 and status == "0"
                  and serial.index("SERVED SHUTDOWN ESCALATED") < serial.index("MACHINE RECOVER RESET"))
            self.record("control", "shell-killed-reboot", ok,
                        f"left={left} {drained.group(0)} status={status} unreaped_marker={unreaped} "
                        f"escalated={escalated} machine_recover={recover} accounted_restart={accounted} "
                        f"stop17={stop17}", control=True)
        except CaseFailed as e:
            self.record("control", "shell-killed-reboot", False, str(e), control=True)
        finally:
            boot.abandon()

    def lent_channel_broken(self, config):
        """D5 of the lifecycle review, repaired by the 2026-10-02 audit
        repair: a command lent the shell's own channel (the third stage of
        a pipeline with no redirection; a redirected pipeline's stages are
        SpareOnly and the third is refused) writes bytes that are no frame.
        The file server drops them; the shell's next request on the same
        channel (`cd`) is answered, so the shell reads End when the client
        goes, nothing is forced, and the boot drains and halts."""
        boot = Boot(self, config)
        try:
            line = c("sshtest zeros 1000000000 | cat | fsd-probe garbage\ncd /home/operator\npwd")
            session, mark = boot.shell(line, 4, what="lent-broken")
            time.sleep(3)
            session.proc.kill()
            _, err = session.proc.communicate()
            session.proc = None
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and session.pid not in boot.ends():
                time.sleep(0.5)
            end = boot.ends().get(session.pid)
            broken = "FSD CHANNEL BROKEN" in boot.serial()[mark:]
            status, drained, seen = boot.finish("halt")
            ok = not broken and end is not None and end["forced"] == "false" and status == "3"
            self.record("control", "lent-broken", ok,
                        f"broken={broken} end={end} {drained.group(0)} status={status} "
                        f"stderr={err.decode(errors='replace').strip()[-160:]!r}", control=True)
        except CaseFailed as e:
            self.record("control", "lent-broken", False, str(e), control=True)
        finally:
            boot.abandon()

    def sshd_died(self, config):
        boot = Boot(self, config)
        try:
            session, mark = boot.shell(c(f"sshtest sleep {LONG}"), 2, what="sshd-died")
            proc = subprocess.Popen(boot.client.base(boot.op) + ["qualification-sshd-exit"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            status = boot.t.status(SHUTDOWN_SECONDS)
            proc.kill()
            proc.communicate()
            session.close_quietly()
            seen = srv.seen(boot.serial())
            drained = re.search(r"SERVED SHUTDOWN [^\n]*drained=(\w+)", seen)
            ok = status == "71" and drained is not None and drained.group(1) == "false"
            self.record("control", "sshd-died", ok,
                        f"{drained.group(0) if drained else 'no SERVED SHUTDOWN line'} status={status}", control=True)
        except CaseFailed as e:
            self.record("control", "sshd-died", False, str(e), control=True)
        finally:
            boot.abandon()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--platform", default=str(here.parent))
    ap.add_argument("--qemu", default="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand")
    ap.add_argument("--shell", required=True, help="the installed absd-sh")
    ap.add_argument("--keep-spawn-shell", help="qualification-only absd-sh that keeps the spawn right")
    ap.add_argument("--sshd", required=True)
    ap.add_argument("--operator-key", help="existing campaign private key outside this matrix's work directory")
    ap.add_argument("--fsd", help="absd-fsd to boot (default: the platform's absd-fsd.elf)")
    ap.add_argument("--scratch-files", type=int, default=1200)
    ap.add_argument("--controls-sshd", help="qualification-only sshd with --qualification-controls")
    ap.add_argument("--max-connections", type=int, default=4)
    ap.add_argument("--race-rounds", type=int, default=100)
    ap.add_argument("--churn-rounds", type=int, default=300)
    ap.add_argument("--seed", type=int, default=20260927)
    ap.add_argument("--only", default="", help="comma-separated parts: columns,shutdown,races,churn,pressure,"
                                                "scratch,capacity,preauth,active-idle,controls")
    ap.add_argument("--cases", default="", help="comma-separated case names (default: all)")
    ap.add_argument("--capacity-sessions", type=int, default=0)
    ap.add_argument("--results", help="write the results as JSON here")
    ap.add_argument("--before", dest="expect_end", action="store_false",
                    help="a platform from before the End protocol: residue is measured, End is not expected")
    args = ap.parse_args()
    check_fsd_group_settlements()
    print("E2 FSD ACCOUNTING PARSER OK direct=1 shell=3 negatives=3", flush=True)
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    lab = Lab(args)
    parts = set(filter(None, args.only.split(","))) or {"columns", "shutdown", "races", "churn", "pressure",
                                                         "scratch", "controls"}
    wanted = set(filter(None, args.cases.split(","))) or {x[0] for x in CASES}
    conf = f"max-connections {args.max_connections}\n".encode()
    std = Config("std", args.sshd, args.shell, conf)
    idle = Config("idle", args.sshd, args.shell, conf + f"idle-timeout {IDLE_SECONDS}\n".encode())
    try:
        if parts & {"columns", "shutdown", "races", "churn", "pressure", "scratch"}:
            lab.prepare(std)
        if "columns" in parts:
            names = [x[0] for x in CASES if x[0] in wanted]
            lab.shared_column(std, "disconnect", [n for n in names if "d" in next(x for x in CASES if x[0] == n)[5]])
            lab.prepare(idle)
            lab.shared_column(idle, "timeout", [n for n in names if "t" in next(x for x in CASES if x[0] == n)[5]])
        if "shutdown" in parts:
            for i, name in enumerate(n for n in (x[0] for x in CASES) if n in wanted
                                     and "s" in next(x for x in CASES if x[0] == n)[5]):
                lab.shutdown_case(std, name, "restart" if i % 2 else "halt")
        if "races" in parts:
            lab.race(std, "race-exit", args.race_rounds)
            lab.race(std, "race-spawn", args.race_rounds)
        if "churn" in parts:
            lab.churn(std, args.churn_rounds)
        if "pressure" in parts:
            lab.pressure(std, args.max_connections, "disconnect")
            lab.pressure(std, args.max_connections, "restart")
        if "scratch" in parts:
            lab.scratch(std, args.scratch_files)
        if "capacity" in parts and args.capacity_sessions:
            cap = Config(f"cap{args.capacity_sessions}", args.sshd, args.shell,
                         f"max-connections {args.capacity_sessions}\n".encode())
            lab.prepare(cap)
            lab.capacity(cap, args.capacity_sessions)
        if "preauth" in parts:
            source = Config("preauth-source", args.sshd, args.shell,
                            b"max-connections 4\nlogin-grace-time 180\nidle-timeout 120\n")
            timeout = Config("preauth-timeout", args.sshd, args.shell,
                             b"max-connections 4\nlogin-grace-time 15\nidle-timeout 120\n")
            lab.prepare(source)
            lab.preauth_source(source)
            lab.prepare(timeout)
            lab.preauth_timeout(timeout)
        if "active-idle" in parts:
            active = Config("active-idle", args.sshd, args.shell,
                            b"max-connections 4\nlogin-grace-time 30\nidle-timeout 10\n")
            lab.prepare(active)
            lab.active_then_idle(active)
        if "audit-reboot" in parts and args.controls_sshd:
            ctl = Config("controls", args.controls_sshd, args.shell, conf)
            lab.prepare(ctl)
            lab.shell_killed_reboot(ctl)
        if "controls" in parts:
            lab.prepare(std)
            lab.lent_channel_broken(std)
            if args.keep_spawn_shell:
                keep = Config("keep", args.sshd, args.keep_spawn_shell, conf)
                lab.prepare(keep)
                lab.prepare(std)
                lab.negative(keep, std)
            if args.controls_sshd:
                ctl = Config("controls", args.controls_sshd, args.shell, conf)
                lab.prepare(ctl)
                lab.shell_killed(ctl)
                lab.orphan_reaped(ctl)
                lab.sshd_died(ctl)
    finally:
        for t in lab.targets.values():
            t.stop()
    if args.results:
        pathlib.Path(args.results).write_text(json.dumps(lab.results, indent=1))
    failed = [r for r in lab.results if r["verdict"] != "PASS"]
    passed = [r for r in lab.results if r["verdict"] == "PASS"]
    print(f"E2 SUMMARY pass={len(passed)} fail={len(failed)}")
    for r in failed:
        print(f"E2 FAILED {r['column']} {r['case']}: {r['detail'][:600]}")
    if failed:
        sys.exit(1)
    print("CONTAINMENT MATRIX OK")


if __name__ == "__main__":
    main()
