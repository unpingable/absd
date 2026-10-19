#!/usr/bin/env python3
"""The served-boot matrix: a boot that serves until told to stop, the
operator's orderly shutdown and reboot, and the machine-ending right.

Boots are `net fsd` durable boots (scripts/ssh_absd.py) built with a short
qualification deadline for the NIC worker (`NET_WAIT_TICKS`, kernel
Makefile) so the deadline can be watched acting; `served` boots add the
kernel option `served`. Every client is the host's /usr/bin/ssh with strict
host key checking. The host reads the image back with its own filesystem
reader (scripts/absd_fs.py) after each halt.

Markers (each printed only when every check behind it held):

  QUALIFICATION DEADLINE KEPT OK  a qualification boot's sshd is still
                                  ended by init at its deadline
  SERVED BOOT OK                  a served boot runs well past that same
                                  deadline (guest ticks) and still serves
  STOP RIGHT OK                   an exec command and a shell's child
                                  cannot stop the machine: the kernel
                                  refuses every attempt (-9, retired -38)
                                  and logs it; the machine keeps serving
  ORDERLY SHUTDOWN OK             `ssh host shutdown`: a shell mid-write
                                  (cat > file, input still open), an idle
                                  PTY shell, and a command that never ends
                                  are told and closed; the writer's bytes
                                  are committed; sshd, the file server and
                                  init end cleanly; every process reaped;
                                  QEMU status 3; the host reads the file
  LEFTOVER REBOOT OK               `reboot` while a shell's command runs
                                  and never ends: sshd tells the shell
                                  (End) after the grace, the shell kills
                                  and reaps it, init finds nothing left
                                  (drained=true, orphans_reaped=0) and
                                  restarts the machine. (What init does
                                  when something is left, status 71, is
                                  now reachable only if sshd itself dies:
                                  scripts/contain-matrix.py, sshd-died.)
  REBOOT OK                       `ssh host reboot`: a restart armed by
                                  init, the machine resets, boots the same
                                  image again, serves what was written,
                                  and halts on `shutdown`; under
                                  -no-reboot (without -no-shutdown) the
                                  restart ends QEMU with status 0
  SHELL SHUTDOWN OK               an interactive shell's `shutdown` (PTY)
                                  and `reboot` (no terminal) go to sshd on
                                  the session control channel: refused
                                  forms change nothing, the accepted one
                                  ends the boot in the same order as an
                                  `exec` request
  LINK DOWN BOOT OK               a served boot whose NIC link is down from
                                  power-on (QEMU started stopped, QMP
                                  `set_link` off, `cont`): the kernel grants
                                  the NIC (`NIC LINK DOWN AT PROBE`), sshd
                                  reaches `SSH LISTENING` (readiness is not
                                  reachability), the host's SSH handshake
                                  times out, then the link is raised and an
                                  authenticated command succeeds on the
                                  same boot with nothing restarted, and
                                  `shutdown` halts the machine (status 3)

`--only link-down` runs the last boot alone.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
import time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
from served_kernel import kernel_make
from served_ram import served_qemu
import ssh_absd  # noqa: E402

spec = importlib.util.spec_from_file_location("ssh_matrix", here / "ssh-matrix.py")
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)

PROMPT = b"absd$ "
# The qualification deadline under test, in kernel ticks (about 1 kHz).
DEADLINE_TICKS = 30_000
SHUTDOWN_SECONDS = 180


def seen(part):
    """A boot's serial text plus its captured worker stream, where sshd's
    own lines are."""
    raw = part.encode() if isinstance(part, str) else part
    return raw.decode(errors="replace") + "\n" + ssh_absd.captured(raw)


def captured_all(serial):
    """Every boot's captured worker stream in one serial log (a reboot
    restarts the offsets at zero)."""
    streams = []
    for part in serial.split(b"ABSD KERNEL BOOT\n")[1:]:
        streams.append(ssh_absd.captured(part))
    return streams


class ServedTarget(ssh_absd.AbsdTarget):
    """AbsdTarget whose sshd boot is `net fsd` with a short qualification
    deadline, or `net fsd served`."""

    served = True

    def iso(self, step, worker, input_bytes=b"", options="", server=""):
        input_path = self.work / f"input-{hashlib.sha256(input_bytes).hexdigest()}.bin"
        input_path.write_bytes(input_bytes)
        subprocess.run([*kernel_make(), "--no-print-directory", "-C", str(self.kernel), "durable-iso",
                        f"DURABLE_STEP={step}", f"EXTERNAL_USER_ELF={worker}", f"EXTERNAL_INPUT={input_path}",
                        "EXTERNAL_READER_ELF=", "EXTERNAL_READER_INPUT=", f"DURABLE_OPTIONS={options}",
                        f"FILE_SERVER_ELF={server}", f"NET_WAIT_TICKS={DEADLINE_TICKS}"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        return self.kernel / "build" / "durable" / f"absd-durable-{step}.iso"

    def sshd_iso(self, regenerate=False):
        server = self.root / ("absd-fsd-regenerate.elf" if regenerate else "absd-fsd.elf")
        options = "net fsd served" if self.served else "net fsd"
        return self.iso(0, self.root / "sshd.elf", options=options, server=server)

    def files(self, authorized):
        return super().files(authorized)

    def status(self, timeout):
        """QEMU's exit status as durable-boot.sh reports it, or None if the
        boot is still running after `timeout` seconds."""
        try:
            out, _ = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        self.proc = None
        return out.decode().strip()


class Qmp:
    """One QMP connection to a QEMU started with `-S -qmp unix:PATH,server,
    nowait`, enough for `set_link` and `cont`. Connecting retries until the
    socket appears or `deadline` passes."""

    def __init__(self, path, deadline):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        while True:
            try:
                self.sock.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() > deadline:
                    raise sm.Failed("QEMU offered no QMP socket")
                time.sleep(0.05)
        self.sock.settimeout(30.0)
        self.lines = self.sock.makefile("rwb", buffering=0)
        if not self.lines.readline():
            raise sm.Failed("QMP closed before its greeting")
        self.execute("qmp_capabilities")

    def execute(self, command, **arguments):
        request = {"execute": command}
        if arguments:
            request["arguments"] = arguments
        self.lines.write((json.dumps(request) + "\n").encode())
        while True:
            line = self.lines.readline()
            if not line:
                raise sm.Failed(f"QMP connection closed during {command}")
            answer = json.loads(line)
            if "error" in answer:
                raise sm.Failed(f"QMP {command}: {answer['error']}")
            if "return" in answer:
                return

    def set_link(self, up):
        self.execute("set_link", name="n0", up=up)

    def close(self):
        self.sock.close()


class ServedMatrix(sm.Matrix):
    def ticks(self):
        rc, out, err = self.ssh("/bin/sshtest ticks")
        m = re.fullmatch(rb"ticks (\d+)\n", out)
        self.check("the guest reports its tick count", rc == 0 and m is not None, f"rc={rc} {out!r} {err!r}")
        return int(m.group(1))

    def start(self, served=True, reboot=None):
        """`reboot`: None (the harness default, -no-reboot -no-shutdown),
        "exit" (a guest reset ends QEMU), "allow" (it reboots)."""
        t = self.t
        t.served = served
        if reboot:
            os.environ["ABSD_QEMU_REBOOT"] = reboot
        try:
            info = t.start()
        finally:
            os.environ.pop("ABSD_QEMU_REBOOT", None)
        return info

    def shell_popen(self, first_line):
        p = subprocess.Popen(self.client.base(self.op), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        p.stdin.write(first_line)
        p.stdin.flush()
        return p

    def run(self):
        t = self.t
        t.setup(self.work, (self.op.with_suffix(".pub")).read_text())
        self.ram_below_minimum_boot()

        # -- SERVED BOOT ---------------------------------------------------
        first = self.start(served=True)
        self.client = sm.Client(self.work, t.port)
        self.client.trust(first["public"])
        serial = t.serial()
        self.check("the served boot starts the file server and sshd as in an fsd boot",
                   "FILE SERVER START pid=2 channels=11" in serial and "SSH LISTENING" in t.output(), serial[-600:])
        started = self.ticks()
        waited = 0
        now = started
        while now - started <= DEADLINE_TICKS * 3 // 2:
            time.sleep(10)
            waited += 10
            self.check("the served boot is still running", t.proc.poll() is None, t.serial()[-600:])
            now = self.ticks()
            self.check("guest time advances", waited < 900, f"{now - started} ticks in {waited}s")
        rc, out, err = self.ssh("/bin/cat /etc/motd")
        serial = t.serial()
        self.check(f"{now - started} ticks after the first session (deadline {DEADLINE_TICKS}) sshd still serves",
                   rc == 0 and out == ssh_absd.MOTD and "external workload deadline" not in serial
                   and t.proc.poll() is None, f"rc={rc} {out!r} {err!r}")
        self.mark(f"SERVED BOOT OK past_deadline_ticks={now - started - DEADLINE_TICKS}")

        # -- STOP RIGHT ----------------------------------------------------
        refusal = re.compile(rb"stop refused runtime=-9 retired=-38 guessed=256/256\n")
        refused_before = len(re.findall(r"MACHINE REQUEST REFUSED pid=\d+ error=-9", t.serial()))
        rc, out, err = self.ssh("/bin/sshtest stop")
        self.check("an exec command cannot stop the machine (no machine handle: -9; retired stop: -38)",
                   rc == 0 and refusal.fullmatch(out) is not None, f"rc={rc} {out!r} {err!r}")
        rc, out, err = self.ssh(None, stdin=b"sshtest stop\nstatus\n")
        shown = out.replace(PROMPT, b"")
        self.check("a shell's child cannot stop the machine", rc == 0 and refusal.match(shown) is not None
                   and shown.endswith(b"0\n"), f"rc={rc} {out!r} {err!r}")
        serial = t.serial()
        refused = len(re.findall(r"MACHINE REQUEST REFUSED pid=\d+ error=-9", serial)) - refused_before
        self.check("the kernel logged every refused attempt, by PID", refused == 2 * (1 + 256), f"{refused}")
        self.check("no machine stop happened and the boot still serves",
                   "MACHINE STOP" not in serial and t.proc.poll() is None and self.ssh("/bin/pwd")[0] == 0,
                   serial[-400:])
        self.mark("STOP RIGHT OK")

        # -- ORDERLY SHUTDOWN ----------------------------------------------
        # A shell writing a file from its input, the input still open.
        spawned = t.spawn_count()
        writer = self.shell_popen(b"cat > /home/operator/inflight.txt\n")
        t.await_spawns(spawned, 2)
        payload = b"".join(b"inflight line %03d %s\n" % (i, b"x" * (i % 37)) for i in range(120))
        writer.stdin.write(payload)
        writer.stdin.flush()
        # An idle interactive shell on a PTY.
        term = self.client.terminal(self.op)
        self.check("PTY session starts", term.wait_raw() and term.expect(PROMPT), term.shown[-200:].decode(errors="replace"))
        # A command that never reads its input and never ends.
        spawned = t.spawn_count()
        forever = subprocess.Popen(self.client.base(self.op) + ["/bin/sshtest sleep 600000"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        t.await_spawns(spawned, 1)
        time.sleep(3)  # the writer's bytes reach cat and the file server
        rc, out, err = self.ssh("shutdown")
        self.check("`shutdown` is answered and ends with status 0",
                   rc == 0 and b"going down for halt" in out, f"rc={rc} {out!r} {err!r}")
        status = t.status(SHUTDOWN_SECONDS)
        self.check("the machine halts on its own (QEMU status 3)", status == "3", f"status={status}")
        w_out, w_err = writer.communicate(timeout=60)
        self.check("the writing session was told and ended cleanly (its shell's status)",
                   writer.returncode == 0 and b"going down for halt" in w_err,
                   f"rc={writer.returncode} {w_out!r} {w_err!r}")
        pty_status = term.wait(60)
        self.check("the idle PTY session was told and closed with its shell's status",
                   pty_status == 0 and b"going down for halt" in term.shown, f"{pty_status} {term.shown[-300:]!r}")
        term.close()
        f_out, f_err = forever.communicate(timeout=60)
        self.check("the command that never ends was ended after the grace; its session closed",
                   forever.returncode is not None and b"slept" not in f_out, f"rc={forever.returncode}")
        serial = seen(t.log.read_bytes())
        for line in [r"SSH SHUTDOWN REQUESTED action=halt connections=4",
                     r"SSH SHUTDOWN GRACE OVER sessions_still_running=1",
                     r"SSH SHUTDOWN COMPLETE action=halt connections=4 ",
                     r"FSD STOPPED served=\d+ commits=\d+",
                     r"FILE SERVER OUTCOME pid=2 status=0",
                     r"DURABLE WORKER OUTCOME generation=1 pid=\d+ status=0",
                     r"SERVED SHUTDOWN action=halt worker_status=0 file_server_status=0 orphans_reaped=0 drained=true",
                     r"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ",
                     r"DURABLE WORKLOAD OK", r"ABSD BOOT OK"]:
            self.check(f"serial: {line}", re.search(line, serial) is not None, serial[-1500:])
        self.check("no restart, no machine stop, no refusal from the file server",
                   "MACHINE RESTART" not in serial and "MACHINE STOP" not in serial and "FSD FAILED" not in serial,
                   serial[-800:])
        tree = t.tree()
        self.check("the host reads every byte the writer sent before the shutdown",
                   tree.get("/home/operator/inflight.txt") == payload,
                   f"{len(tree.get('/home/operator/inflight.txt') or b'')} of {len(payload)} bytes")
        self.mark("ORDERLY SHUTDOWN OK")

        # -- LEFTOVER REBOOT ------------------------------------------------
        self.start(served=True, reboot="exit")
        spawned = t.spawn_count()
        leaver = self.shell_popen(b"sshtest sleep 600000\n")
        t.await_spawns(spawned, 2)
        rc, out, err = self.ssh("reboot")
        self.check("`reboot` with a shell's command still running", rc == 0, f"rc={rc} {err!r}")
        status = t.status(SHUTDOWN_SECONDS)
        leaver.communicate(timeout=60)
        serial = t.serial()
        worker = seen(serial)
        self.check("the shell ended its command on End; init found nothing left and restarted the machine",
                   status == "0" and "ABSD BOOT OK\nMACHINE RESTART\n" in serial
                   and re.search(r"SSH SESSION END pid=\d+ sent=1 exited=true forced=false", worker) is not None
                   and re.search(r"SERVED SHUTDOWN action=restart worker_status=98 file_server_status=0 "
                                 r"orphans_reaped=0 drained=true", serial) is not None
                   and "INIT ORPHAN REAPED" not in serial and "SERVED SHUTDOWN UNREAPED" not in serial
                   and re.search(r"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ", serial) is not None,
                   f"status={status} {serial[-1500:]}")
        self.check("the image still mounts and holds the earlier file",
                   t.tree().get("/home/operator/inflight.txt") == payload)
        self.mark("LEFTOVER REBOOT OK")

        # -- REBOOT --------------------------------------------------------
        self.start(served=True, reboot="allow")
        rc, out, err = self.ssh(None, stdin=b"echo written before the restart > /home/operator/restart.txt\n")
        self.check("a session writes before the restart", rc == 0, f"{rc} {err!r}")
        rc, out, err = self.ssh("reboot")
        self.check("`reboot` is answered", rc == 0 and b"going down for restart" in out, f"rc={rc} {out!r} {err!r}")
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            streams = captured_all(t.log.read_bytes())
            if len(streams) >= 2 and "SSH LISTENING" in streams[1]:
                break
            self.check("QEMU keeps running across the restart", t.proc.poll() is None, t.serial()[-800:])
            time.sleep(1)
        serial = t.serial()
        boots = [seen(part) for part in serial.split("ABSD KERNEL BOOT\n")[1:]]
        self.check("the machine reset and booted again", len(boots) == 2, f"{len(boots)} boots")
        for line in [r"SSH SHUTDOWN COMPLETE action=restart ", r"DURABLE WORKER OUTCOME generation=1 pid=\d+ status=98",
                     r"FILE SERVER OUTCOME pid=2 status=0",
                     r"SERVED SHUTDOWN action=restart worker_status=98 file_server_status=0 orphans_reaped=\d+ drained=true",
                     r"MACHINE RESTART ARMED pid=1", r"DURABLE WORKLOAD OK", r"ABSD BOOT OK\nMACHINE RESTART\n"]:
            self.check(f"first boot: {line}", re.search(line, boots[0]) is not None, boots[0][-1500:])
        self.check("the second boot serves again", "SSH LISTENING" in captured_all(t.log.read_bytes())[1])
        rc, out, err = self.ssh("/bin/cat /home/operator/restart.txt")
        self.check("the file written before the restart is there after it",
                   rc == 0 and out == b"written before the restart\n", f"{rc} {out!r} {err!r}")
        # The second boot is halted from an interactive shell on a PTY: the
        # shell's `shutdown` goes to sshd on the session control channel.
        term = self.client.terminal(self.op, extra=("-t",))
        try:
            ready = term.wait_raw() and term.expect(PROMPT, timeout=60)
            steps = []
            for keys, screen in [
                (b"shutdown +5\r", b"shutdown +5\r\nusage: shutdown [-h|-p|-r now] | reboot (this sshd takes no other form)\r\n" + PROMPT),
                (b"shutdown | cat\r", b"shutdown | cat\r\nabsd-sh: shutdown: cannot run in a pipeline\r\n" + PROMPT),
                (b"status\r", b"status\r\n2\r\n" + PROMPT),
            ]:
                term.type(keys)
                steps.append(term.expect(screen, timeout=60) and term.between == b"")
            self.check("the shell's refused forms change nothing and the session continues",
                       ready and all(steps) and t.proc.poll() is None, f"{steps} {term.shown[-600:]!r}")
            term.type(b"shutdown\r")
            told = term.expect(b"going down for halt", timeout=60)
            pty_status = term.wait(timeout=120)
        finally:
            term.close()
        status = t.status(SHUTDOWN_SECONDS)
        second = seen(t.serial().split("ABSD KERNEL BOOT\n")[-1].encode())
        self.check("the interactive shell's `shutdown` is answered and its session ends with status 0",
                   told and pty_status == 0, f"{pty_status} {term.shown[-400:]!r}")
        self.check("sshd took it from the session's shell, not an exec",
                   'machine request "halt" from the session\'s shell' in second
                   and "SSH SHUTDOWN REQUESTED action=halt" in second, second[-1500:])
        self.check("the second boot halts in order (QEMU status 3)",
                   status == "3" and "SERVED SHUTDOWN action=halt" in second
                   and re.search(r"SERVED SHUTDOWN action=halt worker_status=0 file_server_status=0 "
                                 r"orphans_reaped=\d+ drained=true", second) is not None
                   and "MACHINE RESTART" not in second and "ABSD BOOT OK" in second, f"status={status} {second[-800:]}")
        # Under -no-reboot without -no-shutdown the restart ends QEMU with 0;
        # asked by a shell without a terminal this time.
        self.start(served=True, reboot="exit")
        rc, out, err = self.ssh(None, stdin=b"reboot\n")
        status = t.status(SHUTDOWN_SECONDS)
        serial = t.serial()
        self.check("a shell without a terminal asks for `reboot`, prints the answer, and ends with status 0",
                   rc == 0 and b"going down for restart" in out
                   and 'machine request "restart" from the session\'s shell' in seen(serial.encode()),
                   f"rc={rc} {out!r} {err!r}")
        self.check("under -no-reboot (ABSD_QEMU_REBOOT=exit) a restart ends QEMU with status 0 after the accounting",
                   status == "0" and "ABSD BOOT OK\nMACHINE RESTART\n" in serial
                   and serial.count("ABSD KERNEL BOOT") == 1, f"status={status} {serial[-600:]}")
        self.mark("REBOOT OK")
        self.mark("SHELL SHUTDOWN OK")

        # -- QUALIFICATION DEADLINE ----------------------------------------
        self.start(served=False)
        begun = self.ticks()
        status = t.status(900)
        serial = t.serial()
        self.check("a qualification boot's sshd is ended at its deadline and the boot fails (status 7)",
                   status == "7" and "init: FAILED at external workload deadline" in serial
                   and "DURABLE WORKLOAD FAILED" in serial, f"status={status} {serial[-800:]}")
        self.mark(f"QUALIFICATION DEADLINE KEPT OK deadline_ticks={DEADLINE_TICKS} first_session_tick={begun}")

        # -- LINK DOWN BOOT ------------------------------------------------
        self.link_down_boot()

    def ram_below_minimum_boot(self):
        """Deliberate gate-only bypass: prove the kernel refuses 128M.

        Normal launchers cannot request this size through served_qemu.
        Keep the bypass local to this negative case, never a runner option.
        """
        t = self.t
        t.served = True
        iso = t.sshd_iso()
        log = t.work / "ram-below-minimum.serial.log"
        # served_qemu normalizes -m to the final two words. Replace it only
        # here so an inherited larger -m/env cannot mask the refusal probe.
        qemu = [*served_qemu(t.qemu)[:-2], "-m", "128M"]
        result = subprocess.run(
            [str(t.kernel / "scripts/durable-boot.sh"), str(iso), str(t.image), str(log),
             "120", *qemu, "-nic", "none"],
            check=True, capture_output=True, text=True, timeout=180,
            env=dict(os.environ, ABSD_QEMU_REBOOT="allow"))
        serial = log.read_text(errors="replace")
        matches = re.findall(r"(?m)^SERVED FRAME BOOT REFUSED reason=ram_below_minimum "
                             r"usable_bytes=(\d+) minimum_bytes=(\d+)$", serial)
        self.check("128M served boot is refused for insufficient RAM with measured bytes",
                   result.stdout.strip() == "7" and len(matches) == 1
                   and 0 < int(matches[0][0]) < int(matches[0][1]),
                   f"status={result.stdout!r} {serial[-2000:]}")
        self.check("128M refusal has one boot, no readiness, service launch or reset",
                   serial.count("ABSD KERNEL BOOT\n") == 1
                   and all(marker not in serial for marker in
                           ("FILE SERVER START", "SERVED READY", "MACHINE RECOVER RESET"))
                   and "SSH LISTENING" not in ssh_absd.captured(log.read_bytes()), serial[-2000:])
        self.mark("SERVED RAM 128M REFUSED reason=ram_below_minimum")

    def link_down_boot(self):
        """A served boot with the NIC's link down from power-on. The kernel
        grants the NIC anyway, sshd listens, nothing is reachable until the
        link comes up, and then an authenticated command succeeds on the
        same boot with nothing restarted."""
        t = self.t
        t.served = True
        # A short path: AF_UNIX names are limited to 107 bytes and the work
        # directory may sit deep in a lane checkout.
        qmp_dir = tempfile.mkdtemp(prefix="absd-qmp-")
        qmp_path = os.path.join(qmp_dir, "qmp.sock")
        armed = {}

        def arm():
            # QEMU is started stopped by t.start(); the link goes down over
            # QMP before `cont`, so the kernel's probe never sees carrier.
            # start() builds the ISO first, so the wait is as long as its own.
            try:
                qmp = Qmp(qmp_path, time.monotonic() + 300)
                qmp.set_link(False)
                qmp.execute("cont")
                armed["qmp"] = qmp
            except Exception as e:  # reported by the check below
                armed["error"] = e

        thread = threading.Thread(target=arm, daemon=True)
        thread.start()
        try:
            info = t.start(qemu_extra=f"{t.qemu} -S -qmp unix:{qmp_path},server,nowait")
        finally:
            shutil.rmtree(qmp_dir, ignore_errors=True)
        thread.join(60)
        qmp = armed.get("qmp")
        self.check("the link was set down over QMP before the guest ran", qmp is not None, repr(armed.get("error")))
        serial = t.serial()
        self.check("the kernel grants the NIC with the link down",
                   "NIC LINK DOWN AT PROBE rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048" in serial
                   and "NETWORK LINK OK" not in serial and "NIC UNAVAILABLE" not in serial, serial[-800:])
        self.check("sshd and the file server reach readiness with the link down (readiness is not reachability)",
                   "SSH LISTENING" in t.output() and "FSD READY" in serial, t.output()[-600:])
        self.client = sm.Client(self.work, t.port)
        self.client.trust(info["public"])
        # slirp completes the host's TCP connect itself; the SSH handshake
        # then times out (the client's ConnectTimeout, 20 s, covers it).
        rc, out, err = self.ssh("/bin/cat /etc/motd", timeout=60)
        self.check("the machine is unreachable while the link is down (the handshake times out)",
                   rc != 0 and out == b"" and b"timed out" in err, f"rc={rc} {out!r} {err!r}")
        qmp.set_link(True)
        rc, out, err = self.ssh("/bin/cat /etc/motd")
        serial = t.serial()
        self.check("once the link is up an authenticated command succeeds on the same boot, nothing restarted",
                   rc == 0 and out == ssh_absd.MOTD and serial.count("ABSD KERNEL BOOT") == 1
                   and "SERVED RECOVERY" not in serial and t.output().count("SSH LISTENING") == 1,
                   f"rc={rc} {out!r} {err!r} {serial[-600:]}")
        rc, out, err = self.ssh("shutdown")
        self.check("`shutdown` is answered and ends with status 0",
                   rc == 0 and b"going down for halt" in out, f"rc={rc} {out!r} {err!r}")
        status = t.status(SHUTDOWN_SECONDS)
        self.check("the machine halts on its own (QEMU status 3)", status == "3", f"status={status}")
        qmp.close()
        self.mark("LINK DOWN BOOT OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--only", choices=["link-down", "ram-below-minimum"])
    args, rest = ap.parse_known_args()
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    base = ssh_absd.target(rest)
    target = ServedTarget.__new__(ServedTarget)
    target.__dict__.update(base.__dict__)
    matrix = ServedMatrix(target, work)
    try:
        if args.only:
            target.setup(work, (matrix.op.with_suffix(".pub")).read_text())
            if args.only == "link-down":
                matrix.link_down_boot()
            else:
                matrix.ram_below_minimum_boot()
        else:
            matrix.run()
    except (sm.Failed, ssh_absd.Failed) as e:
        print(f"SERVED MATRIX FAILED: {e}", file=sys.stderr)
        target.stop()
        sys.exit(1)
    except BaseException:
        target.stop()
        raise
    print(f"SERVED MATRIX OK checks={matrix.checks}")


if __name__ == "__main__":
    main()
