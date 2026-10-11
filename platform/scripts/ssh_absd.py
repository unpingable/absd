"""The ABSD target of scripts/ssh-matrix.py.

One filesystem image carries the deployment: /ssh/authorized_keys (the
matrix's throwaway operator key), the platform's /bin commands, the shell
(/bin/absd-sh), the matrix's session helper (/bin/sshtest), /etc/motd, and
the manual: /bin/man and the pages scripts/render-man.sh rendered, as
/share/man/catS/NAME.0 and /share/man/whatis. Those are the paths a
session sees; on the disk `/bin` and `/share` are the release tree
`/releases/<id>/bin` and `/releases/<id>/share`, next to the release record
`/releases/<id>/release` and the selection `/absd/selected`
(docs/RELEASE.md; scripts/release_record.py), with `<id>` from
ABSD_RELEASE_ID, default `dev`: the id the services were compiled with.
The file server refuses to serve a disk without them. The importer writes
it in importer boots and the host reads every file back
(scripts/absd_fs.py), at its physical path, before sshd first runs.

sshd then runs as the durable worker of a `net fsd` durable boot: the
kernel hands it the e1000 NIC, init starts the file server (absd-fsd) with
the only read-write block handle and gives sshd channels to it, and QEMU
forwards 127.0.0.1:<port> to the guest's port 22 (`-netdev user,hostfwd=...`). QEMU runs in the background while the
matrix's client connects; `stop` ends it. Every boot's serial log is kept in
the work directory. The host key is checked against the seed the host reads
from the image with its own filesystem reader and its own ed25519.
"""

import base64
import hashlib
import importlib.util
import os
import pathlib
import re
import signal
import socket
import struct
import subprocess
import time

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("exec_matrix", here / "exec-matrix.py")
em = importlib.util.module_from_spec(spec)
spec.loader.exec_module(em)
import absd_fs  # noqa: E402
import absd_inputs  # noqa: E402
import release_record  # noqa: E402

IMAGE_BYTES = 16 * 1024 * 1024
DEVICE_SECTORS = IMAGE_BYTES // 512
COMMANDS = ["echo", "pwd", "ls", "cat", "printenv", "uname"]
# Commands that change the filesystem, installed when built.
EXTRA_COMMANDS = ["mkdir", "rm", "mv"]
# The manual's reader; its pages come from manual() below.
MAN_COMMAND = "man"
MAN_ROOT = "/share/man"

# What sessions may not change, as the host reader reports it: the release
# trees (/bin and /share), the selection, /etc, and /ssh.
SYSTEM_PREFIXES = (release_record.RELEASES + "/", "/absd/", "/etc/", "/ssh/")

MOTD = b"Welcome to ABSD over SSH.\n"
SEED_PATH = "/ssh/host_ed25519_seed"


class Failed(Exception):
    pass


def captured(serial):
    data = bytearray()
    for m in re.finditer(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]+) data=([0-9a-f]*)\n", serial):
        if int(m.group(1), 16) != len(data):
            break
        data.extend(bytes.fromhex(m.group(2).decode()))
    return data.decode(errors="replace")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class AbsdTarget:
    entropy_checked = True
    settle = 3.0
    # sshd.elf's default (the image carries no timeout arguments).
    auth_timeout = 30
    large_output_bytes = 1_000_000
    backpressure_bytes = 4_000_000
    missing_command = "/bin/nonexistent"
    cat_stdin = "/bin/cat"
    stdin_then_output = "/bin/sshtest after 500"
    stdin_then_output_expect = b"first\nafter\n"
    stderr_command = "/bin/sshtest stderr"
    fault_command = "/bin/sshtest fault"
    shell_script = b"cd /etc\npwd\necho in-shell\nexit 3\n"
    shell_status = 3
    shell_orphan_note = "killed and reaped by its shell on sshd's End"
    pty_prompt = b"absd$ "
    # (typed, then the screen up to the next prompt: echo, output, prompt).
    # On a PTY the shell's stderr reaches the same screen.
    pty_shell_steps = [
        (b"cd /etc\r", b"cd /etc\r\nabsd$ "),
        (b"pwx\x7fd\r", b"pwx\x08 \x08d\r\n/etc\r\nabsd$ "),
        (b"ls\r", b"ls\r\nmotd\r\nabsd$ "),
        (b"cat motd\r", b"cat motd\r\n" + MOTD.replace(b"\n", b"\r\n") + b"absd$ "),
        (b"sshtest exit 5\r", b"sshtest exit 5\r\nabsd-sh: sshtest: exit status 5\r\nabsd$ "),
        (b"status\r", b"status\r\n5\r\nabsd$ "),
        # ^C discards the line being typed; the shell is still reading
        # (it prints no new prompt), and the next line runs.
        (b"ech\x03", b"ech^C\r\n"),
        (b"cd /\r", b"cd /\r\nabsd$ "),
        (b"exit 3\r", b"exit 3\r\n"),
    ]

    def shell_sleep_line(self, seconds):
        return f"sshtest sleep {seconds * 1000}".encode()

    def __init__(self, args):
        self.kernel = pathlib.Path(args.kernel).resolve()
        if absd_inputs.is_kernel_source(self.kernel):
            raise Failed("refusing the canonical kernel checkout")
        self.root = pathlib.Path(args.platform).resolve()
        self.qemu = args.qemu
        self.shell = pathlib.Path(args.shell).resolve()
        self.boot_seconds = args.boot_seconds
        self.proc = None
        self.boots = 0
        self.port = None

    # -- deployment ---------------------------------------------------------

    _release_id = None

    @property
    def release_id(self):
        """ABSD_RELEASE_ID, default `dev`: the id the services were compiled
        with, so the file server's record check passes. Read on first use
        (some matrices build targets without __init__)."""
        if self._release_id is None:
            self._release_id = release_record.release_id_from_env()
        return self._release_id

    def physical(self, path):
        """Where a session's path is on the disk (what tree() reports)."""
        return release_record.physical(path, self.release_id)

    def files(self, authorized):
        """The deployment at the paths a session sees; setup() writes it
        in the release layout (installed())."""
        files = [("/ssh/authorized_keys", authorized.encode()), ("/etc/motd", MOTD)]
        files += [(f"/bin/{name}", (self.root / "commands" / name).read_bytes()) for name in COMMANDS]
        files += [("/bin/absd-sh", self.shell.read_bytes()), ("/bin/sshtest", (self.root / "sshtest.elf").read_bytes())]
        files += [(f"/bin/{name}", (self.root / "commands" / name).read_bytes())
                  for name in EXTRA_COMMANDS if (self.root / "commands" / name).exists()]
        files += [("/bin/fsd-probe", (self.root / "fsd-probe.elf").read_bytes())]
        files += [(f"/bin/{MAN_COMMAND}", (self.root / "commands" / MAN_COMMAND).read_bytes())]
        files += manual(self.root)
        return files

    def installed(self, authorized):
        """files() in the release layout: what setup() writes, at the
        paths the host reader reports, plus the record and selection."""
        return release_record.release_layout(self.files(authorized), self.release_id)

    def iso(self, step, worker, input_bytes=b"", options="", server=""):
        input_path = self.work / f"input-{hashlib.sha256(input_bytes).hexdigest()}.bin"
        input_path.write_bytes(input_bytes)
        subprocess.run(["make", "--no-print-directory", "-C", str(self.kernel), "durable-iso",
                        f"DURABLE_STEP={step}", f"EXTERNAL_USER_ELF={worker}", f"EXTERNAL_INPUT={input_path}",
                        "EXTERNAL_READER_ELF=", "EXTERNAL_READER_INPUT=", f"DURABLE_OPTIONS={options}",
                        f"FILE_SERVER_ELF={server}"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        return self.kernel / "build" / "durable" / f"absd-durable-{step}.iso"

    def setup(self, work, authorized):
        self.work = work
        self.image = work / "ssh.img"
        with open(self.image, "wb") as handle:
            handle.truncate(IMAGE_BYTES)
        files = self.installed(authorized)
        for step, entries in em.import_plan(files):
            iso = self.iso(step, self.root / "fixture-import.elf", em.stream(entries))
            self.boots += 1
            log = work / f"import-{self.boots:03d}.serial.log"
            status = subprocess.run([str(self.kernel / "scripts" / "durable-boot.sh"), str(iso), str(self.image),
                                     str(log), "600", *self.qemu.split()], check=True, capture_output=True,
                                    text=True).stdout.strip()
            text = captured(log.read_bytes())
            if status != "3" or f"FIXTURE IMPORT OK files={len(entries)}" not in text:
                raise Failed(f"import step {step}: status {status}\n{text[-1000:]}")
        tree = self.tree()
        for path, data in files:
            if tree.get(path) != data:
                raise Failed(f"host reader sees different bytes at {path}")
        self.motd_path = "/etc/motd"
        self.port = free_port()

    def tree(self):
        region = absd_fs.fs_region(self.image, DEVICE_SECTORS)
        selected = absd_fs.select(region)
        return {path: absd_fs.content(region, selected, record)
                for path, record in absd_fs.tree(region, selected).items()
                if not path.endswith("/") and record_is_file(region, selected, record)}

    # The only files a boot writes that a session did not ask for: the
    # file server's and sshd's logs and their rotated copies (README "Logs").
    LOGS = ("/var/log/fsd", "/var/log/fsd.0", "/var/log/sshd", "/var/log/sshd.0")
    # The recovery ledger and facts (absd_fsd::recovery): charged by the
    # file server on every boot and left by sshd, so they change on a boot
    # that only loaded the host key.
    STATE = ("/var/state", "/var/state/recovery", "/var/state/recovery.init", "/var/state/facts",
             "/var/state/facts/served-ready", "/var/state/facts/served-end", "/var/state/facts/served-stopped",
             "/var/state/facts/served-completed", "/var/state.new")

    def system_digest(self):
        return hashlib.sha256(repr(self.system_objects()).encode()).hexdigest()

    def system_objects(self):
        """Every object on the image but the four log files and the recovery
        state, read by the host: path, kind, read-only flag, serial, and
        bytes, so a changed flag, a new directory, a rewritten file, or
        anything else under /var/log still counts. The guest may be
        committing a log line while this reads, so a read that finds the
        image mid-commit is retried."""
        for attempt in range(20):
            try:
                region = absd_fs.fs_region(self.image, DEVICE_SECTORS)
                selected = absd_fs.select(region)
                objects = sorted(
                    (path, record["dir"], record["readonly"], record["serial"],
                     hashlib.sha256(absd_fs.content(region, selected, record)).hexdigest())
                    for path, record in absd_fs.tree(region, selected).items()
                    if path not in self.LOGS and path not in self.STATE)
                return objects
            except absd_fs.Refused:
                time.sleep(0.5)
        raise Failed("the host reader never found a committed image")

    def host_public_from_image(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        seed = self.tree().get(SEED_PATH)
        if seed is None or len(seed) != 32:
            raise Failed(f"image holds no 32-byte host key seed at {SEED_PATH}")
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()

    # -- running sshd ----------------------------------------------------------

    def sshd_iso(self, regenerate=False):
        server = self.root / ("absd-fsd-regenerate.elf" if regenerate else "absd-fsd.elf")
        return self.iso(0, self.root / "sshd.elf", options="net fsd", server=server)

    def start(self, fresh=False, regenerate=False, qemu_extra=None, expect_sweep=False):
        """`expect_sweep`: the previous generation ended by a fault or a
        stop with a session bound, so the file server removes its scratch
        before serving (`FSD SWEEP`); that removal, and nothing else, may
        change the image on this boot."""
        iso = self.sshd_iso(regenerate)
        self.boots += 1
        self.log = self.work / f"sshd-{self.boots:03d}.serial.log"
        before = self.system_objects()
        qemu = qemu_extra if qemu_extra is not None else self.qemu
        netdev = f"-netdev user,id=n0,net=10.0.2.0/24,hostfwd=tcp:127.0.0.1:{self.port}-:22 -device e1000,netdev=n0"
        self.proc = subprocess.Popen(
            [str(self.kernel / "scripts" / "durable-boot.sh"), str(iso), str(self.image), str(self.log),
             str(self.boot_seconds), *qemu.split(), *netdev.split()],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            text = self.output()
            if "SSH LISTENING" in text:
                break
            if self.proc.poll() is not None:
                raise Failed(f"sshd boot ended: status {self.proc.stdout.read()!r}\n{text[-2000:]}")
            time.sleep(0.5)
        else:
            raise Failed(f"sshd did not listen:\n{self.output()[-2000:]}")
        text = self.output()
        m = re.search(r"SSH HOST KEY (GENERATED|LOADED) (ssh-ed25519 \S+) (SHA256:\S+)", text)
        if not m:
            raise Failed(f"no host key line:\n{text[-2000:]}")
        public = m.group(2)
        # sshd holds no block handle; the file server made or found the key.
        if not re.search(r"SSH STORAGE VIA FILE SERVER OK block=none control=/ssh:ro,/bin:ro,/etc:ro,/var/log:rw,/var/state:ro,/var/state/facts:rw slots=\d+",
                         text):
            raise Failed(f"sshd storage is not the file server's:\n{text[-2000:]}")
        server = re.search(r"FSD HOST KEY (GENERATED|PRESENT) ", self.serial())
        if not server or "FSD READY" not in self.serial():
            raise Failed(f"no file server host key line:\n{self.serial()[-2000:]}")
        after = self.system_objects()
        generated = server.group(1) == "GENERATED"
        # The host's own reader and ed25519: the image holds this key.
        from_image = self.host_public_from_image()
        if from_image != public:
            raise Failed(f"image seed gives {from_image}, sshd reports {public}")
        if not generated and before != after:
            removed = [o for o in before if o not in after]
            added = [o for o in after if o not in before]
            swept = removed and not added and all(o[0].startswith("/tmp/") for o in removed)
            if not (expect_sweep and swept):
                raise Failed("the image's files (other than /var/log and /var/state) changed on a boot that "
                             f"only loaded the host key: removed={[o[0] for o in removed]} added={[o[0] for o in added]}")
        return {"generated": generated, "public": public, "fingerprint": m.group(3),
                "entropy": "ok" if "SSH ENTROPY OK source=rdrand" in text else "missing",
                "image_changed": before != after}

    def output(self):
        try:
            return captured(self.log.read_bytes())
        except FileNotFoundError:
            return ""

    def serial(self):
        return self.log.read_bytes().decode(errors="replace")

    def stop(self):
        """Ends this boot's QEMU. durable-boot.sh runs QEMU under
        `timeout`, which makes its own process group, so every descendant
        of the boot script is signalled by PID (only our own processes)."""
        if self.proc and self.proc.poll() is None:
            pids = descendants(self.proc.pid)
            for pid in reversed(pids):
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                for pid in [self.proc.pid, *descendants(self.proc.pid)]:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.proc.wait()
        self.proc = None

    def restart(self, regenerate=False):
        self.stop()
        return self.start(regenerate=regenerate)

    def negative_controls(self, matrix):
        """Without an accepted entropy source sshd must not start: QEMU's
        default CPU model (no RDRAND; an old-family AMD identity the
        backend rejects) ends the boot before any key is used, and the
        device is untouched."""
        before = self.system_digest()
        iso = self.sshd_iso()
        self.boots += 1
        log = self.work / f"sshd-{self.boots:03d}-no-rdrand.serial.log"
        qemu = self.qemu.split()[0]
        status = subprocess.run([str(self.kernel / "scripts" / "durable-boot.sh"), str(iso), str(self.image), str(log),
                                 "300", qemu, "-netdev", "user,id=n0", "-device", "e1000,netdev=n0"],
                                check=True, capture_output=True, text=True).stdout.strip()
        serial = log.read_bytes().decode(errors="replace")
        text = captured(log.read_bytes())
        after = self.system_digest()
        # Without RDRAND the kernel refuses the boot identity, so the file
        # server fails before it serves (`FSD FAILED boot identity: -38`)
        # and sshd's runtime refuses the process for want of a server
        # (`FSD PROTOCOL REFUSED reason=no_server`, status 104) before
        # sshd's own entropy check could run; either refusal is sshd not
        # starting for the same cause.
        refused = "sshd: entropy:" in text or (
            "FSD FAILED boot identity: -38" in serial and "FSD PROTOCOL REFUSED reason=no_server" in text)
        matrix.check("no RDRAND: sshd refuses to start, files untouched (the file server logs its start)",
                     status == "7" and refused and "SSH HOST KEY" not in text
                     and "SSH LISTENING" not in text and before == after,
                     f"status={status} changed={before != after} {text[-400:]!r}")
        matrix.mark("ENTROPY NEGATIVE CONTROL OK")

    # -- expectations ----------------------------------------------------------

    def commands(self):
        # /bin/ls marks directories with a trailing slash. A session sees
        # its mounts and the directories leading to them, never /ssh.
        names = sorted(["bin/", "etc/", "home/", "share/", "tmp/", "var/"])
        motd = MOTD

        def ls(rc, out, err):
            return rc == 0 and sorted(out.decode().split()) == names, None

        return [
            ("pwd", lambda rc, out, err: (rc == 0 and out == b"/\n", None)),
            ("ls /", ls),
            ("cat /etc/motd", lambda rc, out, err: (rc == 0 and out == motd, None)),
            ("uname", lambda rc, out, err: (rc == 0 and out.startswith(b"ABSD"), None)),
        ]

    def exit_command(self, status):
        return f"/bin/sshtest exit {status}"

    def sleep_command(self, seconds):
        return f"/bin/sshtest sleep {seconds * 1000}"

    def large_output(self, size):
        return f"/bin/sshtest zeros {size}"

    def large_output_expect(self, size):
        return b"\0" * size

    def shell_expect(self, rc, out, err):
        # absd-sh prompts before every line it reads.
        return rc == 3 and out.replace(b"absd$ ", b"") == b"/etc\nin-shell\n" and out.count(b"absd$ ") == 4, None

    def spawn_count(self):
        """Processes started from filesystem images so far this boot."""
        return len(re.findall(r"SPAWN OK pid=\d+ parent=\d+ program=image", self.serial()))

    def await_spawns(self, before, count, timeout=60):
        """Waits until `count` more image processes have started (the
        kernel's own spawn lines), instead of guessing with a delay."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.spawn_count() >= before + count:
                return True
            time.sleep(0.2)
        raise Failed(f"expected {count} more image spawns within {timeout}s: {self.census_detail()}")

    def live_images(self):
        """Live processes started from filesystem images, from the kernel's
        own spawn and exit lines: {pid: parent}."""
        text = self.serial()
        spawned = dict(re.findall(r"SPAWN OK pid=(\d+) parent=(\d+) program=image", text))
        ended = set(re.findall(r"USER (?:EXIT|KILLED|FAULT) pid=(\d+)", text))
        return {pid: parent for pid, parent in spawned.items() if pid not in ended}

    def sshd_pid(self):
        pids = re.findall(r"DURABLE WORKER GENERATION generation=\d+ pid=(\d+)", self.serial())
        return pids[-1] if pids else None

    def session_census(self):
        """Session children: live image processes whose parent is sshd."""
        sshd = self.sshd_pid()
        return sum(1 for parent in self.live_images().values() if parent == sshd)

    def all_images(self):
        """Every live image process, session children and theirs."""
        return len(self.live_images())

    def census_detail(self):
        return f"sshd={self.sshd_pid()} live image processes (pid: parent)={self.live_images()}"

    def reaped_orphans(self):
        # init writes this line to the serial console, not the worker stream.
        return re.findall(r"INIT ORPHAN REAPED pid=(\d+)", self.serial())

    def check_orphans_reaped(self, matrix, rounds=16):
        """A disconnect while an interactive shell runs a command: sshd
        tells the shell (End), the shell kills and reaps its command and
        exits, and nothing is left to init. More rounds than the process
        table has entries, each checked for no adoption."""
        matrix.check("nothing was left to init by the disconnect", not self.reaped_orphans(), self.census_detail())
        baseline = self.all_images()
        for i in range(rounds):
            before = len(self.reaped_orphans())
            spawned = self.spawn_count()
            victim = subprocess.Popen(matrix.client.base(matrix.op), stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            victim.stdin.write(self.shell_sleep_line(5) + b"\n")
            victim.stdin.flush()
            # Kill the client only once the shell's command has started:
            # a fixed delay raced the start under host load.
            self.await_spawns(spawned, 2)
            victim.kill()
            victim.wait()
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and self.all_images() != baseline:
                time.sleep(0.5)
            matrix.check(f"shell disconnect {i}: the shell ended its command, nothing went to init",
                         self.all_images() == baseline and len(self.reaped_orphans()) == before
                         and not re.search(r"SSH SESSION END [^\n]*forced=true", self.output()),
                         self.census_detail())
        matrix.alive(f"{rounds} shell disconnects during a command")

    # -- session control (ABSD only: the Linux reference has none) ----------

    def shell_pids(self):
        """Session shells sshd started, in order: [pid]."""
        return [int(pid) for pid in re.findall(r"SSH SESSION CHILD pid=(\d+) [^\n]*argv0=/bin/absd-sh [^\n]*control=true",
                                               self.output())]

    def open_shell(self, matrix):
        """A PTY shell from stock ssh (plain -t), at its first prompt, and
        its shell's PID."""
        before = len(self.shell_pids())
        term = matrix.client.terminal(matrix.op, extra=("-t",))
        ok = term.wait_raw() and term.expect(self.pty_prompt, timeout=60)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and len(self.shell_pids()) <= before:
            time.sleep(0.2)
        pids = self.shell_pids()
        matrix.check("a PTY shell with a session control channel starts", ok and len(pids) == before + 1,
                     f"{term.shown!r} {pids}")
        return term, pids[-1]

    def step(self, matrix, term, keys, screen, what, timeout=60):
        term.type(keys)
        ok = term.expect(screen, timeout=timeout) and term.between == b""
        matrix.check(what, ok, f"want {screen!r} shown {term.shown[-400:]!r}")

    def interrupt(self, matrix, term, what):
        """Types ^C and waits for the prompt; returns the milliseconds from
        the keystroke leaving the host to the prompt arriving."""
        start = time.monotonic()
        term.type(b"\x03")
        ok = term.expect(b"^C\r\n" + self.pty_prompt, timeout=30) and term.between == b""
        took = (time.monotonic() - start) * 1000
        matrix.check(what, ok, f"shown {term.shown[-400:]!r}")
        return took

    def listing(self, matrix, term, check=True):
        """Runs `ps` in a PTY shell: (session line, [pids], holders line)."""
        term.type(b"ps\r")
        ok = term.expect(b"ps\r\n", timeout=30) and term.expect(self.pty_prompt, timeout=60)
        text = term.between.decode(errors="replace")
        m = re.fullmatch(r"(session \d+ \(this session\), terminal, connected \d+ s)\r\n"
                         r"  PID PROGRAM\r\n((?: *\d+ \S+\r\n)*)"
                         r"(other holders: input \d+, file server channels \d+)\r\n", text)
        if check or m is None:
            matrix.check("`ps` answers in its format", ok and m is not None, repr(text))
        pids = [int(line.split()[0]) for line in m.group(2).splitlines()]
        return m.group(1), pids, m.group(3), text

    def await_live(self, matrix, count, what, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self.all_images() != count:
            time.sleep(0.3)
        matrix.check(what, self.all_images() == count, self.census_detail())

    def check_session_control(self, matrix):
        """^C in an interactive shell (SSH INTERRUPT OK) and the session's
        own listing (SESSION LIST OK), with stock ssh on a host terminal."""
        baseline = self.all_images()
        term, shell = self.open_shell(matrix)
        latencies = []
        try:
            # A command sleeping: ^C ends it; the shell prompts again.
            spawned = self.spawn_count()
            self.step(matrix, term, b"sshtest sleep 600000\r", b"sshtest sleep 600000\r\n", "a sleeping command runs")
            self.await_spawns(spawned, 1)
            latencies.append(self.interrupt(matrix, term, "^C ends a sleeping command; the shell prompts"))
            self.await_live(matrix, baseline + 1, "the interrupted command was killed and reaped")
            self.step(matrix, term, b"status\r", b"status\r\n130\r\n" + self.pty_prompt,
                      "the interrupted line's status is 130")
            # A command blocked reading the session's input.
            spawned = self.spawn_count()
            self.step(matrix, term, b"cat\r", b"cat\r\n", "cat reads the session's input")
            self.await_spawns(spawned, 1)
            self.step(matrix, term, b"typed\r", b"typed\r\ntyped\r\n", "cat copies a typed line")
            latencies.append(self.interrupt(matrix, term, "^C ends cat blocked on the input; ^C is not its input"))
            self.await_live(matrix, baseline + 1, "cat was killed and reaped")
            # A pipeline blocked on a pipe: both commands end.
            spawned = self.spawn_count()
            self.step(matrix, term, b"sshtest sleep 600000 | cat\r", b"sshtest sleep 600000 | cat\r\n",
                      "a pipeline whose reader is blocked on the pipe runs")
            self.await_spawns(spawned, 2)
            latencies.append(self.interrupt(matrix, term, "^C ends both commands of the pipeline"))
            self.await_live(matrix, baseline + 1, "both pipeline commands were killed and reaped")
            # ^C at the prompt discards the line and does not interrupt the
            # next command (it is tagged before that line).
            self.step(matrix, term, b"ech\x03", b"ech^C\r\n", "^C at the prompt discards the line")
            self.step(matrix, term, b"\x03", b"^C\r\n", "^C at an empty prompt")
            self.step(matrix, term, b"sshtest sleep 1500\r", b"sshtest sleep 1500\r\nslept\r\n" + self.pty_prompt,
                      "a ^C typed at the prompt does not interrupt the next command", timeout=120)
            self.step(matrix, term, b"echo still here\r", b"echo still here\r\nstill here\r\n" + self.pty_prompt,
                      "the session continues")
            serial = self.output()
            matrix.check("sshd passed each ^C to the shell on its control channel",
                         len(re.findall(r"interrupt: told the shell", serial)) >= 5, serial[-600:])
            self.step(matrix, term, b"exit 4\r", b"exit 4\r\n", "the shell exits when asked")
            rc = term.wait(timeout=60)
        finally:
            term.close()
        matrix.check("and the session ends with the shell's own status", rc == 4, f"rc={rc}")
        self.await_live(matrix, baseline, "nothing of the session is left")
        worst = max(latencies)
        matrix.mark(f"SSH INTERRUPT OK latency_ms={','.join(f'{ms:.0f}' for ms in latencies)} max_ms={worst:.0f}")

        # SESSION LIST OK: two shells, each sees only itself.
        first, first_pid = self.open_shell(matrix)
        second, second_pid = self.open_shell(matrix)
        try:
            spawned = self.spawn_count()
            self.step(matrix, second, b"sshtest sleep 600000\r", b"sshtest sleep 600000\r\n",
                      "the second session runs a command")
            self.await_spawns(spawned, 1)
            sleeper = [int(pid) for pid, parent in self.live_images().items() if int(parent) == second_pid]
            matrix.check("the second session's command is its shell's child", len(sleeper) == 1, self.census_detail())
            header, pids, holders, text = self.listing(matrix, first)
            matrix.check("the first session lists exactly its own shell", pids == [first_pid],
                         f"{pids} want [{first_pid}] ({text!r})")
            matrix.check("nothing of the other session is visible (its shell, its command, its holders)",
                         second_pid not in pids and sleeper[0] not in pids
                         and holders == "other holders: input 0, file server channels 0", repr(text))
            self.interrupt(matrix, second, "the second session's command interrupted")
            header2, pids2, holders2, text2 = self.listing(matrix, second)
            matrix.check("the second session lists exactly its own shell, as another session",
                         pids2 == [second_pid] and header2.split(" (")[0] != header.split(" (")[0],
                         f"{text2!r} vs {text!r}")
            # A command cannot start programs: a nested shell runs (the
            # shell started it) but its own start is refused, so nothing
            # of the session is out of its shell's reach.
            spawned = self.spawn_count()
            line = b'absd-sh -c "sshtest sleep 15000"'
            self.step(matrix, first, line + b"\r", line + b"\r\n", "a nested shell tries to start a command")
            refused = first.expect(b"absd-sh: sshtest: cannot run: permission denied\r\n", timeout=60)
            ended = first.expect(b"absd-sh: absd-sh: exit status 126\r\n" + self.pty_prompt, timeout=60)
            matrix.check("the nested start is refused (no spawn right) and the nested shell ends with 126",
                         refused and ended and self.spawn_count() == spawned + 1, f"{first.shown[-400:]!r}")
            _, pids, holders, text = self.listing(matrix, first)
            matrix.check("nothing is left to count",
                         pids == [first_pid] and holders == "other holders: input 0, file server channels 0",
                         repr(text))
            rc, out, err = matrix.ssh(None, stdin=b"ps\n")
            m = re.search(rb"session \d+ \(this session\), no terminal, connected \d+ s\n  PID PROGRAM\n *(\d+) /bin/absd-sh\n"
                          rb"other holders: input 0, file server channels 0\n", out)
            matrix.check("a shell without a terminal lists itself too", rc == 0 and m is not None
                         and int(m.group(1)) not in (first_pid, second_pid), f"rc={rc} {out!r} {err!r}")
            for term in (first, second):
                term.type(b"exit\r")
            codes = [first.wait(timeout=60), second.wait(timeout=60)]
        finally:
            first.close()
            second.close()
        matrix.check("both sessions end normally", codes == [0, 0], f"{codes}")
        self.await_live(matrix, baseline, "nothing of either session is left")
        matrix.mark("SESSION LIST OK")

    def check_host_key_custody(self, matrix):
        """The host key seed lives on the file server's image under /ssh,
        which no session binding includes: a session cannot open it by any
        path, and sshd signs with the copy it read once at start
        (README "Host key custody")."""
        seed = self.tree().get(SEED_PATH)
        for path in [SEED_PATH, "/home/operator/../../ssh/host_ed25519_seed", "/tmp/../ssh/host_ed25519_seed"]:
            rc, out, err = matrix.ssh("/bin/cat " + path)
            matrix.check(f"a session cannot read the host key seed ({path})",
                         rc != 0 and seed not in out and seed not in err and b"not found" in err.lower(),
                         f"rc={rc} out={out[:80]!r} err={err[:200]!r}")
        rc, out, err = matrix.ssh("/bin/ls /ssh")
        matrix.check("a session cannot list /ssh", rc != 0 and b"host_ed25519_seed" not in out, f"rc={rc} out={out!r}")

    def check_memory_bound(self, matrix):
        text = self.output()
        matrix.check("sshd still running after backpressure", "sshd: out of memory" not in text
                     and self.proc.poll() is None, text[-500:])


def manual(root):
    """The rendered manual (scripts/render-man.sh's manpages/), as image
    files under /share/man: every page and the whatis index."""
    base = pathlib.Path(root) / "manpages"
    if not (base / "whatis").is_file():
        raise Failed(f"no rendered manual in {base}: run scripts/render-man.sh")
    return [(f"{MAN_ROOT}/{path.relative_to(base)}", path.read_bytes())
            for path in sorted(base.rglob("*")) if path.is_file()]


def descendants(pid):
    """Every live descendant of `pid`, parents before children."""
    out, frontier = [], [pid]
    while frontier:
        parent = frontier.pop(0)
        try:
            children = pathlib.Path(f"/proc/{parent}/task/{parent}/children").read_text().split()
        except OSError:
            continue
        for child in map(int, children):
            out.append(child)
            frontier.append(child)
    return out


def record_is_file(region, selected, record):
    """A file record (not a directory), readable: an empty directory also
    has no blocks and would otherwise read back as an empty file, which
    the release tool's migration then imported as one."""
    if record.get("dir"):
        return False
    try:
        absd_fs.content(region, selected, record)
        return True
    except Exception:
        return False


def target(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--platform", default=str(here.parent))
    ap.add_argument("--shell", required=True)
    ap.add_argument("--qemu", default="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand")
    ap.add_argument("--boot-seconds", type=int, default=3000)
    return AbsdTarget(ap.parse_args(argv))
