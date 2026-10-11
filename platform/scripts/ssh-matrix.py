#!/usr/bin/env python3
"""SSH interoperability matrix for the ABSD SSH server (ssh/).

The client is always the host's /usr/bin/ssh with throwaway keys, strict
host key checking against a private known_hosts file built from the key the
server reports, and no configuration file. The same checks run against a
target:

  linux   the sshd binary built for Linux (development reference);
  absd    sshd on ABSD under QEMU (`-netdev user,hostfwd=...`), driven by
          scripts/ssh_absd.py.

Every check prints one line; the matrix ends with the gate markers that hold.
Any failure stops the matrix with the evidence.
"""

import argparse
import hashlib
import os
import pathlib
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

here = pathlib.Path(__file__).resolve().parent

SSH = "/usr/bin/ssh"
KEYGEN = "/usr/bin/ssh-keygen"


class Failed(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failed(message)


def keygen(path):
    subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", path.name, "-f", str(path)], check=True)
    return path


class Client:
    def __init__(self, work, port):
        self.work = work
        self.port = port
        self.known_hosts = work / "known_hosts"

    def base(self, key, extra=()):
        return [
            SSH, "-F", "/dev/null", "-p", str(self.port), "-i", str(key),
            "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=20",
            "-o", "ServerAliveInterval=0", "-o", "LogLevel=ERROR", *extra, "127.0.0.1",
        ]

    def run(self, key, command=None, stdin=b"", extra=(), timeout=120):
        argv = self.base(key, extra) + ([command] if command is not None else [])
        p = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr

    def terminal(self, key, command=None, extra=()):
        """/usr/bin/ssh on a host pseudo-terminal (so the client really
        allocates one), `-tt` unless `extra` says otherwise."""
        return Terminal(self.base(key, ("-tt", *extra)) + ([command] if command is not None else []))

    def trust(self, public):
        self.known_hosts.write_text(f"[127.0.0.1]:{self.port} {public}\n")


class Terminal:
    """A client on a host pseudo-terminal, driven like a person typing:
    wait for the client to put its terminal in raw mode, type, expect."""

    def __init__(self, argv):
        import pty
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execv(argv[0], argv)
        self.shown = b""
        self.mark = 0
        self.status = None

    def _read(self, timeout):
        import select
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return True
        try:
            data = os.read(self.fd, 4096)
        except OSError:
            data = b""
        if not data:
            return False
        self.shown += data
        return True

    def wait_raw(self, timeout=60):
        """The client switches its terminal to raw mode once the session
        is set up; typing earlier would be edited by the host's terminal."""
        import termios
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not termios.tcgetattr(self.fd)[3] & termios.ICANON:
                return True
            if not self._read(0.1):
                return False
        return False

    def type(self, data):
        os.write(self.fd, data)

    def expect(self, want, timeout=60):
        """Waits until `want` appears after the previous match; returns
        whether it did (the text between is kept in `between`)."""
        deadline = time.monotonic() + timeout
        while True:
            i = self.shown.find(want, self.mark)
            if i >= 0:
                self.between = self.shown[self.mark:i]
                self.mark = i + len(want)
                return True
            if time.monotonic() >= deadline or not self._read(min(0.2, deadline - time.monotonic())):
                self.between = self.shown[self.mark:]
                return False

    def rest(self):
        return self.shown[self.mark:]

    def resize(self, rows, cols):
        import fcntl
        import termios
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def wait(self, timeout=60):
        """The client's exit status, or None if it is still running."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                while self._read(0.05) and len(self.shown) < 1 << 20:
                    pass
                self.status = os.waitstatus_to_exitcode(status)
                return self.status
            self._read(0.1)
        return None

    def close(self):
        if self.status is None:
            try:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
            except ProcessLookupError:
                pass
        os.close(self.fd)


class Matrix:
    def __init__(self, target, work):
        self.t = target
        self.work = work
        self.op = keygen(work / "id_operator")
        self.other = keygen(work / "id_other")
        self.passed = []
        self.checks = 0

    def check(self, name, ok, detail=""):
        self.checks += 1
        print(f"  {'ok  ' if ok else 'FAIL'} {name}{(': ' + detail) if detail and not ok else ''}", flush=True)
        require(ok, f"{name}: {detail}")

    def mark(self, marker):
        self.passed.append(marker)
        print(marker, flush=True)

    def ssh(self, command=None, **kw):
        return self.client.run(self.op, command, **kw)

    def pty(self):
        """PTY sessions: sshd's line discipline (ssh/src/tty.rs)."""
        t = self.t
        # A forced PTY without a terminal on the client side: accepted, and
        # the command's output comes back through the terminal (LF -> CR LF).
        rc, out, err = self.ssh("echo pty", extra=("-tt",))
        self.check("forced pty request accepted, output LF -> CR LF", rc == 0 and out == b"pty\r\n",
                   f"rc={rc} out={out!r} err={err!r}")
        rc, out, err = self.ssh(t.stderr_command, extra=("-tt",))
        self.check("on a PTY stderr is the same screen: one stream, in order",
                   rc == 0 and out == b"out\r\nerr\r\n" and err == b"", f"rc={rc} out={out!r} err={err!r}")
        rc, out, err = self.ssh("echo nopty", extra=("-T",))
        self.check("a session without a PTY is untouched", rc == 0 and out == b"nopty\n", f"rc={rc} out={out!r}")
        self.mark("PTY ALLOC OK")

        # Line editing, echo, CR -> LF, LF -> CR LF, ^D, on a real client
        # terminal. The expected screen is exact: echo of each keystroke,
        # then the command's own output of the finished line.
        term = self.client.terminal(self.op, t.cat_stdin)
        try:
            raw = term.wait_raw()
            steps = [
                (b"hellp\x7fo\r", b"hellp\x08 \x08o\r\nhello\r\n"),
                (b"ab\x15xy\x08z\r", b"ab\x08 \x08\x08 \x08xy\x08 \x08z\r\nxz\r\n"),
                ("\u00e9t\u00e9\x7f\x7fa\r".encode(), "\u00e9t\u00e9\x08 \x08\x08 \x08a\r\n\u00e9a\r\n".encode()),
                (b"tab\x01\x7f!\r", b"tab^A\x08 \x08\x08 \x08!\r\ntab!\r\n"),
            ]
            shown = []
            for keys, screen in steps:
                term.type(keys)
                ok = term.expect(screen, timeout=30) and term.between == b""
                shown.append(ok)
                if not ok:
                    break
            term.type(b"\x04")
            rc = term.wait(timeout=30)
        finally:
            term.close()
        self.check("client terminal in raw mode", raw, f"{term.shown!r}")
        self.check("echo, backspace (DEL and BS), erase line, UTF-8 erase, CR -> LF, LF -> CR LF",
                   all(shown) and len(shown) == len(steps), f"{term.shown!r}")
        self.check("^D at line start ends the command's input", rc == 0 and term.rest() == b"",
                   f"rc={rc} rest={term.rest()!r}")
        self.mark("PTY IO OK")

        # ^C ends an exec command (sshd's own child): no exit status.
        baseline = t.session_census()
        spawned = t.spawn_count()
        term = self.client.terminal(self.op, t.sleep_command(120))
        try:
            raw = term.wait_raw()
            t.await_spawns(spawned, 1)
            running = t.session_census() == baseline + 1
            start = time.monotonic()
            term.type(b"\x03")
            rc = term.wait(timeout=30)
            took = time.monotonic() - start
        finally:
            term.close()
        self.check("^C ends a PTY exec command at once, no exit status",
                   raw and running and rc == 255 and term.shown.endswith(b"^C\r\n") and took < 15,
                   f"rc={rc} running={running} took={took:.1f}s shown={term.shown!r}")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and t.session_census() != baseline:
            time.sleep(0.5)
        self.check("and it was reclaimed", t.session_census() == baseline, t.census_detail())
        self.alive("^C on a PTY")
        self.mark("SSH PTY OK")

        # The interactive shell from a real client terminal (no command:
        # OpenSSH asks for a PTY by itself, no -tt).
        term = self.client.terminal(self.op, extra=("-t",))
        resized = None
        try:
            raw = term.wait_raw()
            prompt = t.pty_prompt
            ok = [term.expect(prompt, timeout=60) if prompt else True]
            for i, (line, want) in enumerate(t.pty_shell_steps):
                if i == 2:
                    # A window change mid-session: the client sends
                    # `window-change`; sunset declines it (no reply is
                    # wanted) and nothing in the session uses the size.
                    term.resize(50, 132)
                    resized = True
                term.type(line)
                good = term.expect(want, timeout=60) and term.between == b""
                ok.append(good)
                if not good:
                    break
            rc = term.wait(timeout=60) if all(ok) else None
        finally:
            term.close()
        self.check("client terminal in raw mode for the shell", raw, f"{term.shown!r}")
        self.check("prompt, cd, pwd, ls, cat, status, ^C at the prompt, backspace",
                   all(ok) and len(ok) == len(t.pty_shell_steps) + 1, f"steps={ok} shown={term.shown!r}")
        self.check(f"exit status {t.shell_status} of the PTY shell", rc == t.shell_status, f"rc={rc}")
        self.check("session kept serving after a window change", resized and all(ok), f"{term.shown!r}")
        # ^D at the prompt ends the shell with its last status.
        term = self.client.terminal(self.op, extra=("-t",))
        try:
            raw = term.wait_raw()
            ready = term.expect(t.pty_prompt, timeout=60) if t.pty_prompt else True
            term.type(b"\x04")
            rc = term.wait(timeout=30)
        finally:
            term.close()
        self.check("^D at the shell prompt ends the session, status 0", raw and ready and rc == 0,
                   f"rc={rc} shown={term.shown!r}")
        self.mark("SSH INTERACTIVE SHELL OK")

    def alive(self, why):
        rc, out, err = self.ssh("echo alive")
        self.check(f"listener serves after {why}", rc == 0 and out == b"alive\n", f"rc={rc} out={out!r} err={err!r}")

    def run(self):
        t = self.t
        t.setup(self.work, (self.op.with_suffix(".pub")).read_text())
        first = t.start(fresh=True)
        self.client = Client(self.work, t.port)
        if t.entropy_checked:
            self.check("entropy source accepted by getrandom's self-test", first.get("entropy") == "ok",
                       str(first))
            self.mark("ENTROPY OK")
        self.check("host key generated on first start", first["generated"], str(first))
        host_key = first["public"]
        self.client.trust(host_key)

        # Handshake and authentication.
        rc, out, err = self.ssh("echo hi", extra=("-v",))
        text = err.decode(errors="replace")
        self.check("handshake with strict host key checking", rc == 0 and out == b"hi\n", f"rc={rc} {text[-400:]}")
        kex = re.search(r"kex: algorithm: (\S+)", text)
        hk = re.search(r"kex: host key algorithm: (\S+)", text)
        cipher = re.search(r"kex: server->client cipher: (\S+)", text)
        self.check("negotiated algorithms", kex and hk and hk.group(1) == "ssh-ed25519",
                   text[-400:])
        print(f"       kex={kex.group(1)} hostkey={hk.group(1)} cipher={cipher.group(1) if cipher else '?'}")
        self.mark("SSH HANDSHAKE OK")

        rc, out, err = self.client.run(self.other, "echo no")
        self.check("unauthorized key refused", rc == 255 and b"Permission denied (publickey)" in err and out == b"",
                   f"rc={rc} err={err!r}")
        rc, out, err = self.client.run(self.op, "echo no", extra=("-o", "PreferredAuthentications=password,keyboard-interactive"))
        self.check("password and keyboard-interactive not offered", rc == 255 and out == b"", f"rc={rc} err={err!r}")
        rc, out, err = self.client.run(self.other, "echo no", extra=("-o", "IdentitiesOnly=yes", "-i", str(self.op)))
        self.check("second key after a refused one accepted", rc == 0 and out == b"no\n", f"rc={rc} err={err!r}")
        self.mark("SSH AUTH OK")

        # Commands.
        for command, expect in t.commands():
            rc, out, err = self.ssh(command)
            ok, detail = expect(rc, out, err)
            self.check(f"command {command!r}", ok, detail or f"rc={rc} out={out[:300]!r} err={err[:300]!r}")
        for status in (0, 1, 7, 255):
            rc, out, err = self.ssh(t.exit_command(status))
            self.check(f"exit status {status} propagated", rc == status, f"rc={rc} err={err!r}")
        rc, out, err = self.ssh(t.missing_command)
        self.check("missing program: nonzero status and a message", rc not in (0, 255) and err, f"rc={rc} err={err!r}")
        self.mark("SSH COMMAND OK")

        # Session data paths.
        payload = os.urandom(200_000)
        rc, out, err = self.ssh(t.cat_stdin, stdin=payload)
        self.check("200 kB stdin round trip, EOF delivered after the data", rc == 0 and out == payload,
                   f"rc={rc} len={len(out)} err={err[:200]!r}")
        rc, out, err = self.ssh(t.stdin_then_output, stdin=b"first\n")
        self.check("output after client EOF still delivered", rc == 0 and out == t.stdin_then_output_expect,
                   f"rc={rc} out={out!r} err={err!r}")
        rc, out, err = self.ssh(t.stderr_command)
        self.check("stderr carried separately", rc == 0 and out == b"out\n" and err == b"err\n",
                   f"rc={rc} out={out!r} err={err!r}")
        size = t.large_output_bytes
        rc, out, err = self.ssh(t.large_output(size))
        self.check(f"{size} byte output", rc == 0 and len(out) == size and out == t.large_output_expect(size),
                   f"rc={rc} len={len(out)} err={err[:200]!r}")
        # Two sessions at once: the loop multiplexes them.
        slow = subprocess.Popen(self.client.base(self.op) + [t.sleep_command(3)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(t.settle)
        start = time.monotonic()
        rc, out, err = self.ssh("echo quick")
        quick = time.monotonic() - start
        slow_rc = slow.wait(timeout=120)
        self.check("concurrent session served while another runs",
                   rc == 0 and out == b"quick\n" and slow_rc == 0, f"rc={rc} slow={slow_rc} {quick:.1f}s")
        self.mark("SSH SESSION OK")

        # Non-PTY interactive shell.
        rc, out, err = self.ssh(None, stdin=t.shell_script)
        ok, detail = t.shell_expect(rc, out, err)
        self.check("non-PTY interactive shell", ok, detail or f"rc={rc} out={out!r} err={err!r}")
        self.mark("SSH SHELL OK")

        self.pty()
        if hasattr(t, "check_session_control"):
            t.check_session_control(self)

        # Reconnect.
        for i in range(5):
            rc, out, err = self.ssh(f"echo round{i}")
            self.check(f"reconnect {i}", rc == 0 and out == f"round{i}\n".encode(), f"rc={rc} err={err!r}")
        self.mark("SSH RECONNECT OK")

        # Reclaim and the listener surviving each fault.
        baseline = t.session_census()
        baseline_all = t.all_images()
        spawned = t.spawn_count()
        victim = subprocess.Popen(self.client.base(self.op) + [t.sleep_command(60)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        t.await_spawns(spawned, 1)
        self.check("session child running", t.session_census() == baseline + 1, t.census_detail())
        victim.kill()
        victim.wait()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and t.session_census() != baseline:
            time.sleep(0.5)
        self.check("client killed mid-command: session child reclaimed", t.session_census() == baseline,
                   t.census_detail())
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and t.all_images() != baseline_all:
            time.sleep(0.5)
        self.check("and every process it started", t.all_images() == baseline_all, t.census_detail())
        self.alive("a client disconnect mid-command")
        # The same from an interactive shell running a command: the command
        # is the shell's child, not sshd's; on ABSD sshd tells the shell to
        # end it (End) before the shell is reclaimed.
        spawned = t.spawn_count()
        victim = subprocess.Popen(self.client.base(self.op), stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        victim.stdin.write(t.shell_sleep_line(8) + b"\n")
        victim.stdin.flush()
        # The shell and its command both started (evidence, not a delay).
        t.await_spawns(spawned, 2)
        self.check("shell session running a command", t.all_images() >= baseline_all + 2, t.census_detail())
        victim.kill()
        victim.wait()
        start = time.monotonic()
        while time.monotonic() < start + 30 and t.session_census() != baseline:
            time.sleep(0.5)
        self.check("client killed during a shell command: shell reclaimed", t.session_census() == baseline,
                   t.census_detail())
        while time.monotonic() < start + 60 and t.all_images() != baseline_all:
            time.sleep(0.5)
        self.check("and the shell's command ended", t.all_images() == baseline_all, t.census_detail())
        print(f"       shell command gone after {time.monotonic() - start:.1f}s ({t.shell_orphan_note})")
        self.alive("a client disconnect during a shell command")
        if hasattr(t, "check_orphans_reaped"):
            t.check_orphans_reaped(self)
        rc, out, err = self.ssh(t.fault_command)
        self.check("session child fault: no exit status, connection closed", rc == 255 and out == b"",
                   f"rc={rc} out={out!r} err={err!r}")
        self.alive("a session child fault")
        self.mark("SSH SESSION RECLAIM OK")

        # Backpressure: a client that stops reading does not make the
        # server buffer without bound or stall other connections.
        size = t.backpressure_bytes
        slow = subprocess.Popen(self.client.base(self.op) + [t.large_output(size)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(t.settle * 2)
        self.alive("a client that is not reading")
        out = slow.stdout.read()
        slow_rc = slow.wait(timeout=300)
        self.check(f"stalled reader then receives all {size} bytes", slow_rc == 0 and len(out) == size,
                   f"rc={slow_rc} len={len(out)}")
        t.check_memory_bound(self)
        # Malformed handshakes.
        for name, data in [
            ("not SSH", b"GET / HTTP/1.0\r\n\r\n"),
            ("garbage binary packet", b"SSH-2.0-matrix\r\n" + b"\xff" * 64),
            ("oversized packet length", b"SSH-2.0-matrix\r\n" + (0x7FFFFFF0).to_bytes(4, "big") + b"\x00" * 60),
            ("banner only, then close", b"SSH-2.0-matrix\r\n"),
        ]:
            with socket.create_connection(("127.0.0.1", t.port), timeout=20) as s:
                s.sendall(data)
                s.shutdown(socket.SHUT_WR)
                s.settimeout(20)
                try:
                    while s.recv(4096):
                        pass
                except (ConnectionResetError, socket.timeout):
                    pass
            self.alive(f"a malformed handshake ({name})")
        # Unauthenticated connection held open until the auth timeout.
        with socket.create_connection(("127.0.0.1", t.port), timeout=60) as s:
            s.settimeout(t.auth_timeout + 30)
            start = time.monotonic()
            closed = False
            try:
                while s.recv(4096):
                    pass
                closed = True
            except (ConnectionResetError, socket.timeout) as e:
                closed = isinstance(e, ConnectionResetError)
            held = time.monotonic() - start
        self.check("idle unauthenticated connection dropped at the auth timeout",
                   closed and t.auth_timeout - 2 <= held <= t.auth_timeout + 20, f"closed={closed} held={held:.1f}s")
        print(f"       dropped after {held:.1f}s (auth timeout {t.auth_timeout}s)")
        self.alive("an authentication timeout")
        # Repeated authentication failures.
        many = [keygen(self.work / f"id_wrong{i}") for i in range(8)]
        extra = []
        for key in many:
            extra += ["-i", str(key)]
        rc, out, err = self.client.run(self.other, "true", extra=tuple(extra))
        self.check("repeated authentication failures refused", rc == 255 and out == b"", f"rc={rc} err={err!r}")
        self.alive("authentication failures")
        self.mark("SSH LISTENER SURVIVES SESSION OK")

        # Host key persistence and deliberate regeneration.
        second = t.restart()
        self.check("host key loaded, not regenerated, after restart",
                   not second["generated"] and second["public"] == host_key, str(second))
        rc, out, err = self.ssh("echo again")
        self.check("strict known_hosts still matches after restart", rc == 0 and out == b"again\n", f"rc={rc} err={err!r}")
        third = t.restart(regenerate=True)
        self.check("deliberate regeneration gives a new key", third["generated"] and third["public"] != host_key,
                   str(third))
        rc, out, err = self.ssh("echo changed")
        self.check("strict client refuses the regenerated key", rc == 255 and b"HOST IDENTIFICATION HAS CHANGED" in err,
                   f"rc={rc} err={err[:300]!r}")
        fourth = t.restart()
        self.check("regenerated key persists", not fourth["generated"] and fourth["public"] == third["public"],
                   str(fourth))
        self.client.trust(third["public"])
        rc, out, err = self.ssh("echo trusted")
        self.check("client trusting the new key connects", rc == 0 and out == b"trusted\n", f"rc={rc} err={err!r}")
        if hasattr(t, "check_host_key_custody"):
            t.check_host_key_custody(self)
        self.mark("SSH HOST KEY PERSISTENCE OK")
        t.stop()
        if hasattr(t, "negative_controls"):
            t.negative_controls(self)


class LinuxTarget:
    """sshd for Linux on 127.0.0.1, sessions run by /bin/sh -c."""

    entropy_checked = False
    settle = 0.5
    auth_timeout = 4
    large_output_bytes = 1_000_000
    backpressure_bytes = 8_000_000
    missing_command = "/nonexistent/program"
    cat_stdin = "cat"
    stdin_then_output = "cat; sleep 0.3; echo after"
    stdin_then_output_expect = b"first\nafter\n"
    stderr_command = "echo out; echo err >&2"
    fault_command = "kill -SEGV $$"
    shell_script = b"cd /\npwd\necho in-shell\nexit 3\n"
    shell_status = 3
    shell_orphan_note = "killed with the session's process group"
    # /bin/sh with pipes, not a terminal: no prompt.
    pty_prompt = b""
    pty_shell_steps = [
        (b"cd /\r", b"cd /\r\n"),
        (b"pwx\x7fd\r", b"pwx\x08 \x08d\r\n/\r\n"),
        (b"ech\x03", b"ech^C\r\n"),
        (b"echo in-shell\r", b"echo in-shell\r\nin-shell\r\n"),
        (b"exit 3\r", b"exit 3\r\n"),
    ]

    def shell_sleep_line(self, seconds):
        return f"sleep {seconds}".encode()

    def spawn_count(self):
        return 0

    def await_spawns(self, before, count, timeout=60):
        time.sleep(self.settle * count)
        return True

    def __init__(self, binary):
        self.binary = binary
        self.proc = None
        self.port = None

    def setup(self, work, authorized):
        self.work = work
        (work / "authorized_keys").write_text(authorized)
        self.file = work / "motd"
        self.file.write_text("hello from the matrix\n")
        self.port = free_port()

    def start(self, fresh=False, regenerate=False):
        log = self.work / "sshd.log"
        argv = [str(self.binary), "--listen", f"127.0.0.1:{self.port}", "--host-key", str(self.work / "host_key"),
                "--authorized-keys", str(self.work / "authorized_keys"),
                "--auth-timeout-ms", str(self.auth_timeout * 1000)]
        if regenerate:
            argv.append("--regenerate-host-key")
        self.log = open(log, "ab")
        mark = log.stat().st_size if log.exists() else 0
        self.proc = subprocess.Popen(argv, stderr=self.log, stdout=self.log, start_new_session=True)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            text = log.read_bytes()[mark:].decode(errors="replace")
            m = re.search(r"SSH HOST KEY (GENERATED|LOADED) (ssh-ed25519 \S+) (SHA256:\S+)", text)
            if m and "SSH LISTENING" in text:
                return {"generated": m.group(1) == "GENERATED", "public": m.group(2), "fingerprint": m.group(3)}
            time.sleep(0.1)
        raise Failed(f"sshd did not start: {log.read_text()[-2000:]}")

    def stop(self):
        if self.proc:
            self.proc.send_signal(signal.SIGTERM)
            self.proc.wait(timeout=10)
            self.proc = None

    def restart(self, regenerate=False):
        self.stop()
        return self.start(regenerate=regenerate)

    def commands(self):
        listing = sorted(os.listdir("/"))
        return [
            ("pwd", lambda rc, out, err: (rc == 0 and out == b"/\n", None)),
            ("ls /", lambda rc, out, err: (rc == 0 and sorted(out.decode().split()) == listing, None)),
            (f"cat {self.file}", lambda rc, out, err: (rc == 0 and out == self.file.read_bytes(), None)),
            ("uname -s", lambda rc, out, err: (rc == 0 and out == b"Linux\n", None)),
        ]

    def exit_command(self, status):
        return f"exit {status}"

    def sleep_command(self, seconds):
        return f"sleep {seconds}"

    def large_output(self, size):
        return f"head -c {size} /dev/zero"

    def large_output_expect(self, size):
        return b"\0" * size

    def shell_expect(self, rc, out, err):
        return rc == 3 and out == b"/\nin-shell\n", None

    def session_census(self):
        # Session children of this sshd.
        p = subprocess.run(["pgrep", "-P", str(self.proc.pid)], capture_output=True, text=True)
        return len(p.stdout.split())

    def all_images(self):
        p = subprocess.run(["pgrep", "-s", str(os.getsid(self.proc.pid))], capture_output=True, text=True)
        return len(p.stdout.split())

    def census_detail(self):
        return f"children={self.session_census()} session={self.all_images()}"

    def check_memory_bound(self, matrix):
        rss = int(re.search(r"VmHWM:\s+(\d+)", pathlib.Path(f"/proc/{self.proc.pid}/status").read_text()).group(1))
        matrix.check("server peak memory bounded under backpressure", rss < 64 * 1024, f"VmHWM={rss} kB")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=["linux", "absd"], required=True)
    ap.add_argument("--sshd", help="Linux sshd binary")
    ap.add_argument("--work")
    args, rest = ap.parse_known_args()
    work = pathlib.Path(args.work or tempfile.mkdtemp(prefix="ssh-matrix-"))
    work.mkdir(parents=True, exist_ok=True)
    if args.target == "linux":
        target = LinuxTarget(pathlib.Path(args.sshd))
    else:
        sys.path.insert(0, str(here))
        import ssh_absd  # noqa: E402
        target = ssh_absd.target(rest)
    matrix = Matrix(target, work)
    try:
        matrix.run()
    except Failed as e:
        print(f"SSH MATRIX FAILED: {e}", file=sys.stderr)
        target.stop()
        sys.exit(1)
    except BaseException:
        target.stop()
        raise
    print(f"SSH MATRIX OK target={args.target} checks={matrix.checks}")
    if not args.work:
        shutil.rmtree(work)


if __name__ == "__main__":
    main()
