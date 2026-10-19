#!/usr/bin/env python3
"""The operator image, built and booted the way afterboot(8) tells an
operator to (scripts/build-operator-image.sh, scripts/boot-operator.sh),
driven with the host's stock /usr/bin/ssh, ssh-keyscan, and ssh-keygen.

The image is built with /etc files that differ from every default
(address 10.0.2.20, port 2200, three connections, a 20 s login grace, a
45 s idle timeout), so each setting the boot shows can only have come
from /etc.

Markers (each printed only when every check behind it held):

  OPERATOR IMAGE OK            the built image holds exactly the command
                               set, the manual, /etc, and the keys (host
                               reader); it boots by the documented script,
                               serves, and halts on `shutdown` (script
                               status 0)
  HOST KEY FINGERPRINT OK      the console shows the host key's
                               fingerprint in plain text, in the form
                               `ssh-keygen -l` prints; it equals what
                               ssh-keyscan | ssh-keygen -lf - computes from
                               the live server and what the host computes
                               from the seed on the image; /var/log/sshd
                               has the same line; the public key line
                               trusted as is lets strict checking connect
  ETC CONFIG OK                address, port, connection limit, login
                               grace, and idle timeout from /etc take
                               effect, and the boot says which files it read
  ETC CONFIG MALFORMED REFUSED OK
                               a malformed /etc/sshd.conf or
                               /etc/network.conf stops sshd before it
                               listens, with the file, line, and reason in
                               plain text on the console; nothing serves;
                               replacing the file (--reconfigure) recovers
  LOGS OK                      /var/log/sshd and /var/log/fsd hold stamped
                               lines of this boot, readable and not
                               writable from sessions, `tail` works, they
                               survive a reboot, and the size bound
                               rotates sshd's log to sshd.0
  FILE TRANSFER OK             `ssh host 'cat > FILE' < local` and
                               `ssh host cat FILE > local` move binary files
                               (every byte value, 0 B to 1 MiB) byte for
                               byte, `>>` appends, the device holds them
                               after shutdown, and writes outside the
                               session's writable mounts are refused
  DATE UPTIME OK               `date` is the RTC's UTC time inside the host's
                               window, `uptime` counts this boot and names
                               its identity, which changes on reboot; `ls -l`
                               shows only recorded fields
"""

import argparse
import base64
import calendar
import hashlib
import importlib.util
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import operator_image as oi  # noqa: E402
import release_record  # noqa: E402
import absd_inputs  # noqa: E402
import ssh_absd  # noqa: E402
from e1000_rx import wait_rx_setup, RxSetupFailed

spec = importlib.util.spec_from_file_location("ssh_matrix", here / "ssh-matrix.py")
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)

KEYSCAN = "/usr/bin/ssh-keyscan"
KEYGEN = "/usr/bin/ssh-keygen"
SITE_SSHD = b"port 2200\nmax-connections 3\nlogin-grace-time 20\nidle-timeout 45\nmax-auth-tries 4\n"
SITE_NETWORK = b"address 10.0.2.20\nnetmask 255.255.255.0\ngateway 10.0.2.2\n"
LOG_LINE = re.compile(rb"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ (sshd|fsd): [ -~\t]*\n")


class Boot:
    """One run of scripts/boot-operator.sh in the background."""

    def __init__(self, out, port):
        self.out = pathlib.Path(out)
        self.port = port
        self.console = self.out / "console.log"
        if self.console.exists():
            self.console.unlink()
        self.proc = subprocess.Popen([str(here / "boot-operator.sh"), str(self.out), str(port)],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)

    def text(self):
        try:
            return self.console.read_bytes().decode(errors="replace")
        except FileNotFoundError:
            return ""

    def worker(self):
        """sshd's stream of every boot in this run (a reboot starts the
        framed offsets again at zero)."""
        if not self.console.exists():
            return ""
        return "\n".join(ssh_absd.captured(part) for part in self.console.read_bytes().split(b"ABSD KERNEL BOOT\n"))

    def await_text(self, pattern, count=1, timeout=300):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = re.findall(pattern, self.text())
            if len(found) >= count:
                return found
            if self.proc.poll() is not None:
                return re.findall(pattern, self.text()) or None
            time.sleep(0.5)
        return None

    def await_listening(self, count=1, timeout=300):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.worker().count("SSH LISTENING") >= count:
                try:
                    wait_rx_setup(self.text, lambda: self.proc.poll() is None, deadline)
                except RxSetupFailed as error:
                    print(f"OPERATOR RECEIVE SETUP FAILED reason={error}", file=sys.stderr)
                    return False
                return True
            if self.proc.poll() is not None:
                return False
            time.sleep(0.5)
        return False

    def status(self, timeout):
        try:
            out, _ = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, b""
        return self.proc.returncode, out

    def kill(self):
        if self.proc.poll() is None:
            for pid in reversed([self.proc.pid, *ssh_absd.descendants(self.proc.pid)]):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.proc.wait()


class OperatorMatrix(sm.Matrix):
    def __init__(self, args, work):
        self.work = work
        self.kernel = pathlib.Path(args.kernel).resolve()
        self.qemu = args.qemu
        self.op = sm.keygen(work / "id_operator")
        self.passed = []
        self.checks = 0
        self.port = ssh_absd.free_port()
        self.client = sm.Client(work, self.port)
        self.out = work / "operator"
        self.boot = None

    def ssh(self, command=None, **kw):
        return self.client.run(self.op, command, **kw)

    def env(self):
        return dict(os.environ, ABSD_KERNEL_RUN=str(self.kernel), ABSD_SKIP_BUILD="1",
                    ABSD_QEMU=self.qemu)

    def build_image(self):
        site = self.work / "site-etc"
        site.mkdir()
        (site / "sshd.conf").write_bytes(SITE_SSHD)
        (site / "network.conf").write_bytes(SITE_NETWORK)
        keys = self.work / "authorized_keys"
        keys.write_bytes((self.work / "id_operator.pub").read_bytes())
        started = time.monotonic()
        p = subprocess.run([str(here / "build-operator-image.sh"), "--authorized-keys", str(keys), "--etc", str(site),
                            str(self.out)], env=self.env(), capture_output=True, text=True)
        self.check("build-operator-image.sh builds the image", p.returncode == 0
                   and "OPERATOR IMAGE BUILT" in p.stdout, f"rc={p.returncode}\n{p.stdout[-1500:]}\n{p.stderr[-1500:]}")
        print(f"  (built in {time.monotonic() - started:.0f} s)")
        tree = oi.tree(self.out / oi.IMAGE)
        # The release layout: /bin and /share live in the release tree,
        # next to its record, and /absd/selected names it.
        release_id = release_record.release_id_from_env()
        root = release_record.tree_root(release_id)
        self.check("the image selects its release and carries the record",
                   tree.get(release_record.SELECTED) == release_record.selected_bytes(release_id)
                   and tree.get(f"{root}/release") == release_record.record_text(release_id).encode()
                   and not any(p.startswith(("/bin/", "/share/")) for p in tree),
                   repr(sorted(p for p in tree if not p.startswith(root + "/"))))
        bins = sorted(p[len(root + "/bin/"):] for p in tree if p.startswith(root + "/bin/"))
        want = sorted(oi.NATIVE + oi.PORTS + ["absd-sh"])
        self.check("/bin holds exactly the command set, no test helpers", bins == want, f"{bins} want {want}")
        # (The reader lists directories too; a page is a path no other
        # path is below.)
        pages = {p[len(root):]: d for p, d in tree.items() if p.startswith(root + "/share/man/")
                 and not any(q.startswith(p + "/") for q in tree)}
        rendered = dict(ssh_absd.manual(oi.ROOT))
        self.check("/share/man holds exactly the rendered manual", pages == rendered,
                   repr(set(pages) ^ set(rendered)))
        self.check("/etc holds the site's files", tree.get("/etc/sshd.conf") == SITE_SSHD
                   and tree.get("/etc/network.conf") == SITE_NETWORK, repr(sorted(p for p in tree if p.startswith("/etc"))))
        self.check("/ssh holds the operator's keys and no host key yet",
                   tree.get("/ssh/authorized_keys") == keys.read_bytes() and ssh_absd.SEED_PATH not in tree)
        self.check("the image (which will hold the host key) is readable by its owner only",
                   (self.out / oi.IMAGE).stat().st_mode & 0o777 == 0o600, oct((self.out / oi.IMAGE).stat().st_mode))
        manifest = (self.out / "MANIFEST").read_text()
        self.check("MANIFEST names the commits and every file", manifest.startswith("platform ")
                   and f"kernel {oi.identity(self.kernel)}" in manifest
                   and len(re.findall(r"^file [0-9a-f]{64} /", manifest, re.M))
                   == len([p for p in tree if not any(q.startswith(p + "/") for q in tree)]), manifest[:300])

    def start(self, out=None):
        self.boot = Boot(out or self.out, self.port)
        return self.boot

    def serving(self, count=1):
        ok = self.boot.await_listening(count)
        self.check("the boot serves" + (f" (boot {count})" if count > 1 else ""), ok,
                   self.boot.text()[-2000:])

    def shutdown(self):
        rc, out, err = self.ssh("shutdown")
        status, text = self.boot.status(180)
        self.check("`shutdown` halts it; boot-operator.sh exits 0", rc == 0 and status == 0
                   and b"the machine halted" in text, f"rc={rc} status={status} {text!r} {err!r}")

    # -- host key --------------------------------------------------------

    def host_key(self):
        lines = self.boot.await_text(r"(?m)^sshd: host key (256 SHA256:[A-Za-z0-9+/]{43} \(ED25519\))$")
        self.check("the console shows the fingerprint in plain text", bool(lines), self.boot.text()[-1500:])
        publics = re.findall(r"(?m)^sshd: host key (ssh-ed25519 [A-Za-z0-9+/=]+)$", self.boot.text())
        self.check("and the public key line", len(publics) == 1, repr(publics))
        fingerprint = lines[0].split()[1]
        scan = subprocess.run([KEYSCAN, "-p", str(self.port), "-t", "ed25519", "127.0.0.1"], capture_output=True,
                              timeout=60)
        listed = subprocess.run([KEYGEN, "-lf", "-"], input=scan.stdout, capture_output=True, timeout=60).stdout.decode()
        self.check("ssh-keyscan | ssh-keygen -lf - shows the same fingerprint",
                   re.fullmatch(rf"256 {re.escape(fingerprint)} \[127\.0\.0\.1\]:{self.port} \(ED25519\)\n", listed)
                   is not None, f"{listed!r} console {fingerprint}")
        seed = oi.tree(self.out / oi.IMAGE).get(ssh_absd.SEED_PATH)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        blob = base64.b64decode(public.split()[1])
        mine = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        self.check("the host's own ed25519 over the image's seed gives it too", mine == fingerprint
                   and public == publics[0], f"{mine} {public}")
        self.client.trust(publics[0])
        rc, out, err = self.ssh("cat /var/log/sshd")
        self.check("/var/log/sshd has the fingerprint line", rc == 0
                   and re.search(rf"Z sshd: host key 256 {re.escape(fingerprint)} \(ED25519\)\n".encode(), out)
                   is not None, f"rc={rc} {err!r} {out[-500:]!r}")
        self.mark("HOST KEY FINGERPRINT OK")
        return fingerprint

    # -- /etc ------------------------------------------------------------

    def etc_config(self):
        text = self.boot.text()
        self.check("the boot says the network came from /etc/network.conf",
                   "sshd: network 10.0.2.20/24 gateway 10.0.2.2 (/etc/network.conf)\n" in text, text[-1500:])
        self.check("and the limits from /etc/sshd.conf",
                   "sshd: port 2200, at most 3 connections, login grace 20 s, idle timeout 45 s, "
                   "4 authentication tries (/etc/sshd.conf)\n" in text, text[-1500:])
        # Address and port: QEMU forwards to 10.0.2.20:2200 only.
        rc, out, err = self.ssh("echo configured")
        self.check("a session reaches the address and port /etc names", rc == 0 and out == b"configured\n",
                   f"rc={rc} {err!r}")
        # Login grace: an unauthenticated connection is dropped after 20 s.
        with socket.create_connection(("127.0.0.1", self.port), timeout=90) as s:
            start = time.monotonic()
            banner = s.recv(256)
            s.settimeout(90)
            rest = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                rest += data
            waited = time.monotonic() - start
        self.check("an unauthenticated connection is dropped at the login grace (20 s)",
                   banner.startswith(b"SSH-2.0-") and 18 <= waited <= 40, f"after {waited:.1f} s")
        # Authentication tries (4): three refused keys and then the
        # operator's still get in; a fourth refusal ends the connection.
        wrong = [sm.keygen(self.work / f"id_wrong{i}") for i in range(4)]

        def offering(refused):
            extra = [arg for key in wrong[1:refused] for arg in ("-i", str(key))] + ["-i", str(self.op)]
            return self.client.run(wrong[0], "echo in", extra=tuple(extra))
        rc, out, err = offering(3)
        self.check("three refused keys, then the operator's: in (max-auth-tries 4)", rc == 0 and out == b"in\n",
                   f"rc={rc} {err!r}")
        rc, out, err = offering(4)
        self.check("four refused keys end the connection before the operator's is tried", rc == 255 and out == b"",
                   f"rc={rc} {err!r}")
        # Connections: three held; a fourth completes TCP but sshd does not
        # take it (no banner) until one ends.
        # Started one at a time: the per-source pre-authentication cap is
        # two, so a third connection opened before the first authenticates
        # is refused rather than queued.
        held = []
        try:
            for n in range(1, 4):
                held.append(subprocess.Popen(self.client.base(self.op) + ["/bin/cat"], stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE))
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline and self.boot.worker().count("exec \"/bin/cat\"") < n:
                    time.sleep(0.5)
            self.check("three sessions run at once", self.boot.worker().count("exec \"/bin/cat\"") >= 3,
                       self.boot.worker()[-800:])
            # The fourth is refused outright at the global cap (the
            # served-boot repair's `SSH GLOBAL REFUSED`), not left waiting
            # for a banner: a connection is admitted or ended, never queued.
            rc, out, err = self.ssh("echo fourth")
            self.check("a fourth connection is refused while three are held (global cap)",
                       rc == 255 and out == b"" and "SSH GLOBAL REFUSED source=" in self.boot.worker(),
                       f"rc={rc} {err!r} {self.boot.worker()[-300:]!r}")
            held[0].stdin.close()
            held[0].wait(timeout=120)
            rc, out, err = self.ssh("echo after")
            self.check("a new connection is served once one of the three ends", rc == 0 and out == b"after\n",
                       f"rc={rc} {err!r}")
        finally:
            for p in held:
                if p.stdin and not p.stdin.closed:
                    p.stdin.close()
                p.wait(timeout=120)
        # Idle timeout: an authenticated session with no traffic ends.
        start = time.monotonic()
        idle = subprocess.Popen(self.client.base(self.op) + ["/bin/cat"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            idle.wait(timeout=150)
        except subprocess.TimeoutExpired:
            idle.kill()
            idle.wait()
        waited = time.monotonic() - start
        self.check("a silent session ends at the idle timeout (45 s)", 43 <= waited <= 100, f"after {waited:.1f} s")
        log = self.ssh("cat /var/log/sshd")[1]
        self.check("sshd's log names the ends", b"authentication timeout" in log and b"idle timeout" in log
                   and b"4 authentication failures" in log,
                   log[-800:].decode(errors="replace"))
        self.mark("ETC CONFIG OK")

    def malformed(self):
        """Copies of the image with a malformed file each: refused with the
        reason on the console, nothing listens; the fix recovers."""
        cases = [
            ("sshd.conf", b"# typo\nPort 2200\n",
             'sshd: /etc/sshd.conf: line 2: unknown keyword "Port" (known: port, max-connections, '
             'login-grace-time, idle-timeout, max-auth-tries); fix the file (network.conf(5), sshd.conf(5), '
             'afterboot(8)); sshd is not running'),
            ("network.conf", b"address 10.0.2.20\nnetmask 255.255.255.0\ngateway 10.0.3.1\n",
             "sshd: /etc/network.conf: line 3: gateway 10.0.3.1 is not another host of 10.0.2.20/24; fix the file "
             "(network.conf(5), sshd.conf(5), afterboot(8)); sshd is not running"),
        ]
        bad = self.work / "operator-bad"
        for name, content, message in cases:
            shutil.rmtree(bad, ignore_errors=True)
            bad.mkdir()
            for f in (oi.ISO, oi.IMAGE, "MANIFEST"):
                shutil.copyfile(self.out / f, bad / f)
            etc = self.work / f"bad-{name}"
            etc.mkdir()
            (etc / name).write_bytes(content)
            p = subprocess.run([str(here / "build-operator-image.sh"), "--reconfigure", "--etc", str(etc), str(bad)],
                               env=self.env(), capture_output=True, text=True)
            self.check(f"--reconfigure replaces /etc/{name}", p.returncode == 0
                       and oi.tree(bad / oi.IMAGE).get(f"/etc/{name}") == content, p.stdout[-800:] + p.stderr[-800:])
            listed = (bad / "MANIFEST").read_text()
            before = (self.out / "MANIFEST").read_text()
            self.check("and MANIFEST then names the new file's digest, the rest kept",
                       f"file {hashlib.sha256(content).hexdigest()} /etc/{name}\n" in listed
                       and len(listed.splitlines()) == len(before.splitlines())
                       and set(listed.splitlines()) - set(before.splitlines())
                       == {f"file {hashlib.sha256(content).hexdigest()} /etc/{name}"}, listed[-600:])
            boot = self.start(bad)
            status, text = boot.status(300)
            console = boot.text()
            self.check(f"a malformed /etc/{name} stops the boot: script status 7, the reason in plain text",
                       status == 7 and (message + "\n") in console and "SSH LISTENING" not in boot.worker(),
                       f"status={status} {console[-1200:]}")
            boot.kill()
            good = self.work / f"good-{name}"
            good.mkdir()
            (good / name).write_bytes(SITE_SSHD if name == "sshd.conf" else SITE_NETWORK)
            p = subprocess.run([str(here / "build-operator-image.sh"), "--reconfigure", "--etc", str(good), str(bad)],
                               env=self.env(), capture_output=True, text=True)
            self.check("replacing the file again succeeds", p.returncode == 0, p.stdout[-800:] + p.stderr[-800:])
            self.boot = self.start(bad)
            self.serving()
            rc, out, err = self.ssh("echo recovered")
            self.check("and the image serves again", rc == 0 and out == b"recovered\n", f"rc={rc} {err!r}")
            self.shutdown()
        shutil.rmtree(bad)
        self.mark("ETC CONFIG MALFORMED REFUSED OK")

    # -- logs, transfer, time ----------------------------------------------

    def logs(self, boot_ids):
        rc, out, err = self.ssh("ls /var/log")
        self.check("/var/log lists logs, network sample and recovery projection", rc == 0 and out.split() == [b"fsd", b"network-recovery", b"network-status", b"sshd"], f"{out!r} {err!r}")
        rc, sample, err = self.ssh("cat /var/log/network-status")
        self.check("the owner network sample is exactly 512 bytes", rc == 0 and len(sample) == 512, f"rc={rc} bytes={len(sample)} {err!r}")
        for name in ("sshd", "fsd"):
            rc, out, err = self.ssh(f"cat /var/log/{name}")
            lines = out.splitlines(keepends=True)
            self.check(f"every line of /var/log/{name} is stamped", rc == 0 and lines
                       and all(LOG_LINE.fullmatch(line) for line in lines), repr([l for l in lines if not LOG_LINE.fullmatch(l)][:3]))
        fsd_log = self.ssh("cat /var/log/fsd")[1].decode()
        starts = re.findall(r"fsd: started: boot ([0-9a-f]{32}), uptime \d+ ms", fsd_log)
        self.check("fsd's log has each boot's start and identity, in order", starts == boot_ids, f"{starts} {boot_ids}")
        self.check("and its bindings", "fsd: FSD BIND slot=" in fsd_log and "fsd: FSD READY" in fsd_log)
        rc, out, err = self.ssh("tail -n 2 /var/log/sshd")
        self.check("tail reads the end of sshd's log", rc == 0 and len(out.splitlines()) == 2
                   and b"sshd: conn " in out, f"{out!r}")
        for command, what in [("echo forged > /var/log/sshd", "redirect"), ("rm /var/log/fsd", "rm"),
                              ("cp /etc/sshd.conf /var/log/new", "cp")]:
            rc, out, err = self.ssh(command)
            self.check(f"a session cannot write /var/log ({what})", rc != 0 and b"read-only" in (out + err).lower(),
                       f"rc={rc} {out!r} {err!r}")

    def rotation(self):
        """Sessions until sshd's log passes the bound once."""
        rounds = 0
        while rounds < 600:
            rc, out, err = self.ssh("ls /var/log")
            if b"sshd.0" in out:
                break
            rounds += 1
        rc, out, err = self.ssh("ls -l /var/log")
        sizes = {}
        for line in out.decode().splitlines():
            row = re.fullmatch(r"[d-] (?:ro|--) \d+ +(\d+) (?:-|[0-9]{4,12}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}) (\S+)", line)
            self.check("log listing has size and explicit mtime", row is not None, line)
            sizes[row.group(2)] = int(row.group(1))
        self.check("sshd's log rotated to sshd.0 at the 64 KiB bound", rc == 0 and "sshd.0" in sizes
                   and 60_000 < sizes["sshd.0"] <= 65_536 and sizes["sshd"] < 65_536, f"{rounds} rounds {out!r}")
        return rounds

    def transfer(self):
        import random
        rng = random.Random(20260927)
        cases = {"empty": b"", "one": b"\x00", "page": bytes(range(256)) * 16 + b"\r\n\x03\x04\x1a",
                 "odd": bytes(rng.getrandbits(8) for _ in range(65_537)),
                 "mib": bytes(rng.getrandbits(8) for _ in range(1 << 20)) + b"\x00\xff\r\n\x03"}
        for name, data in cases.items():
            start = time.monotonic()
            rc, out, err = self.ssh(f"cat > /home/operator/{name}", stdin=data, timeout=600)
            up = time.monotonic() - start
            self.check(f"upload {name} ({len(data)} B)", rc == 0 and out == b"" and err == b"", f"rc={rc} {err!r}")
            start = time.monotonic()
            rc, out, err = self.ssh(f"cat /home/operator/{name}", timeout=600)
            down = time.monotonic() - start
            self.check(f"download {name} is byte-exact", rc == 0 and out == data, f"rc={rc} {len(out)} {err!r}")
            rc, out, err = self.ssh(f"sha256sum /home/operator/{name}")
            self.check(f"the guest's sha256sum of {name} agrees", out.split()[:1] == [hashlib.sha256(data).hexdigest().encode()])
            if name == "mib":
                print(f"  (1 MiB: up {up:.1f} s, down {down:.1f} s)")
        rc, out, err = self.ssh("cat >> /home/operator/page", stdin=b"tail\n")
        rc2, out2, err2 = self.ssh("cat /home/operator/page")
        self.check("`cat >> FILE` appends", rc == 0 and out2 == cases["page"] + b"tail\n", f"{rc} {err!r}")
        rc, out, err = self.ssh("cat > /bin/intruder", stdin=b"x")
        self.check("an upload into /bin is refused", rc == 1 and b"read-only" in err, f"rc={rc} {err!r}")
        rc, out, err = self.ssh("cat > /ssh/authorized_keys", stdin=b"x")
        self.check("an upload into /ssh is refused", rc == 1 and b"not found" in err, f"rc={rc} {err!r}")
        # A client that disconnects mid-upload: sshd tells the shell (End),
        # the shell ends cat and exits, the slots come back, and the next
        # pipeline gets its spares. What arrived stays, cut short.
        upload = subprocess.Popen(self.client.base(self.op) + ["cat > /home/operator/cut"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        upload.stdin.write(b"\x03\x04" * 20_000)
        upload.stdin.flush()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and 'exec "cat > /home/operator/cut"' not in self.boot.worker():
            time.sleep(0.5)
        time.sleep(3)
        upload.kill()
        upload.wait()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not re.search(
                r'exec "cat > /home/operator/cut"\n(?:.*\n)*?SSH SESSION END pid=\d+ sent=1 exited=true forced=false '
                r'ms=\d+\nSSH FS RELEASE slot=\d+ spares=\[\d+, \d+\]', self.boot.worker()):
            time.sleep(0.5)
        rc, out, err = self.ssh("ls / | wc -l")
        started = re.findall(r"SSH SESSION CHILD pid=\d+ spawn_right=true argv0=/bin/absd-sh fs_slot=\d+ "
                             r"spares=\[(\d+, \d+)?\]", self.boot.worker())
        self.check("a disconnect mid-upload ends the shell and frees its slots: the next pipeline has its spares",
                   rc == 0 and out == b"6\n" and started and started[-1] != "", f"rc={rc} {out!r} {started[-3:]}")
        rc, out, err = self.ssh("cat /home/operator/missing")
        self.check("downloading a missing file fails", rc == 1 and out == b"" and b"not found" in err.lower(),
                   f"rc={rc} {err!r}")
        cases["page"] += b"tail\n"
        return cases

    def time_checks(self, boot_ids):
        before = time.time()
        rc, out, err = self.ssh("date")
        rc2, out2, err2 = self.ssh("date +%s")
        after = time.time()
        m = re.fullmatch(rb"(\w{3}) (\w{3}) ([ \d]\d) (\d\d):(\d\d):(\d\d) UTC (\d{4})\n", out)
        self.check("date prints the UTC time", rc == 0 and m is not None, f"{out!r} {err!r}")
        shown = calendar.timegm(time.strptime(out.decode().strip(), "%a %b %d %H:%M:%S UTC %Y"))
        self.check("inside the host's window (whole seconds)", int(before) - 2 <= shown <= after + 2,
                   f"{shown} not in [{before:.0f}, {after:.0f}]")
        self.check("date +%s is the same clock", rc2 == 0 and int(before) - 2 <= int(out2) <= after + 2, repr(out2))
        rc, out, err = self.ssh("date -s 2000")
        self.check("date sets nothing", rc == 2 and b"usage" in err, repr(err))
        first = self.ssh("uptime")[1]
        second = self.ssh("uptime")[1]
        pattern = rb"up (\d+) days (\d\d):(\d\d):(\d\d), (\d+) ticks since boot, boot ([0-9a-f]{32})\n"
        a, b = re.fullmatch(pattern, first), re.fullmatch(pattern, second)
        self.check("uptime counts this boot and names it", a is not None and b is not None
                   and int(b.group(5)) > int(a.group(5)) and a.group(6).decode() == boot_ids[-1],
                   f"{first!r} {second!r} {boot_ids}")
        rc, out, err = self.ssh("ls -l /home/operator")
        rows = out.decode().splitlines()
        self.check("ls -l shows kind, flag, links, size, mtime and name",
                   rc == 0 and rows and all(re.fullmatch(r"[d-] (ro|--) \d+ +\d+ (?:-|[0-9]{4,12}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}) \S+", r) for r in rows), repr(rows))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--qemu", default=oi.QEMU)
    args = ap.parse_args()
    work = pathlib.Path(args.work).resolve()
    if absd_inputs.is_kernel_source(args.kernel):
        raise SystemExit("refusing the canonical kernel checkout")
    m = OperatorMatrix(args, work)
    try:
        m.build_image()
        m.start()
        m.serving()
        m.host_key()
        rc, out, err = m.ssh("ls /")
        m.check("a session sees bin etc home share tmp var", rc == 0
                and sorted(out.split()) == [b"bin/", b"etc/", b"home/", b"share/", b"tmp/", b"var/"], repr(out))
        rc, out, err = m.ssh("ls /bin")
        m.check("and the whole command set", rc == 0 and sorted(out.decode().split())
                == sorted(oi.NATIVE + oi.PORTS + ["absd-sh"]), repr(out))
        rc, out, err = m.ssh("man afterboot")
        m.check("and the manual", rc == 0 and out == (oi.ROOT / "manpages" / "cat8" / "afterboot.0").read_bytes())
        boot_ids = [re.search(r"fsd: started: boot ([0-9a-f]{32})", m.ssh("cat /var/log/fsd")[1].decode()).group(1)]
        m.etc_config()
        files = m.transfer()
        m.time_checks(boot_ids)
        # Reboot: the same image comes back; logs and files survive.
        rc, out, err = m.ssh("reboot")
        m.check("reboot is accepted", rc == 0, repr(err))
        m.serving(count=2)
        boot_ids = re.findall(r"fsd: started: boot ([0-9a-f]{32})", m.ssh("cat /var/log/fsd")[1].decode())
        m.check("the reboot is a new boot", len(boot_ids) == 2 and boot_ids[0] != boot_ids[1], repr(boot_ids))
        m.logs(boot_ids)
        m.time_checks(boot_ids)
        rounds = m.rotation()
        m.mark(f"LOGS OK rotation_sessions={rounds}")
        m.mark("DATE UPTIME OK")
        m.shutdown()
        tree = oi.tree(m.out / oi.IMAGE)
        m.check("after shutdown the device holds every transferred file",
                all(tree.get(f"/home/operator/{name}") == data for name, data in files.items()))
        m.check("and both logs", all(p in tree for p in ("/var/log/sshd", "/var/log/sshd.0", "/var/log/fsd")))
        m.mark("FILE TRANSFER OK")
        m.mark("OPERATOR IMAGE OK")
        m.malformed()
    except sm.Failed as error:
        print(f"OPERATOR MATRIX FAILED: {error}", file=sys.stderr)
        if m.boot:
            print(m.boot.text()[-3000:], file=sys.stderr)
        sys.exit(1)
    finally:
        if m.boot:
            m.boot.kill()
    print(f"OPERATOR MATRIX OK checks={m.checks}")


if __name__ == "__main__":
    main()
