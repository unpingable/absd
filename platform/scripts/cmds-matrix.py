#!/usr/bin/env python3
"""The /bin command set over SSH (README "Commands").

One `net fsd` boot (scripts/ssh_absd.py) whose image carries every command
the platform installs under /bin: its own small `std` programs
(src/bin/*.rs) and the unmodified uutils programs and ripgrep
scripts/build-ports.sh builds, plus a few fixture files under /etc. The host's /usr/bin/ssh
drives an interactive shell on a PTY (one ordered stream of output and
errors per command), types each command, and compares everything shown
before the next prompt with the expected text exactly. Claims about the
device are checked with the host's own filesystem reader
(scripts/absd_fs.py); `sha256sum` against the host's hashlib; `df` and
`sync` against the image's own geometry, block references, and commit
sequence.

Markers (each printed only when every check behind it held):

  COMMAND OUTPUT OK        every installed command, run in a session,
                           prints exactly the expected text
  COMMAND WRITES OK        cp, mkdir, mv, rm change the session's own
                           mounts, and the device shows it
  COMMAND REFUSALS OK      writes into /bin, /etc, /ssh, mount points,
                           another session's /tmp, and narrowed children
                           (`ro`, `nofs`) are refused by name, and the
                           device is unchanged there
  COMMAND SPACE OK         df and sync report the device the host reads
  SHELL LISTS OK           `;`, `&&`, `||`, `echo -n`, `help`; arrow keys dropped
  COMMAND ABSENCES OK      commands deliberately not provided are absent
  MAN PAGES OK pages=...   man(1) prints every rendered page exactly (on a
                           PTY and in an exec session), refuses a missing
                           page, a wrong section, a path, and a process
                           without the manual by name, and `man -k` searches
                           the index; /share is read-only to sessions
  COMMAND SET OK names=... all of the above, for exactly these commands
  COMMAND SBASE PRESENT    the base userland's sbase ports are under /bin
                           (their behaviour is the guest qualification's,
                           userland/README.md; not checked here)

`--host-check` boots nothing: it checks the sbase ports against their
manifest (userland/PORTS.tsv) and the image's command list
(scripts/operator_image.py PORTS): every one listed for the image, none a
native command, a Rust port, a shell builtin, or a command deliberately not
provided (ABSENT, and `ps`); ports/NAME at the recorded digest; a manual
page for each and sbase(7) carrying sbase's licence. It prints
`COMMAND SBASE EXPECTED OK names=...`, or the first failure and status 1.
With `--without-image-list` (scripts/install-userland-ports.sh) it checks
everything but the image's list, and says so (`image_list=not-checked`).
"""

import argparse
import base64
import calendar
import hashlib
import json
import os
import pathlib
import re
import sys
import time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402
import ssh_absd  # noqa: E402
import mtime_reference  # noqa: E402
import importlib.util  # noqa: E402

spec = importlib.util.spec_from_file_location("ssh_matrix", here / "ssh-matrix.py")
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)

health_spec = importlib.util.spec_from_file_location("health_json_validator", here / "validate-health-json.py")
health_validator = importlib.util.module_from_spec(health_spec)
health_spec.loader.exec_module(health_validator)

PROMPT = b"absd$ "
# The platform's own commands (commands/<name>) and the ports (ports/<name>:
# uutils and ripgrep).
NATIVE = ["echo", "pwd", "ls", "cat", "printenv", "uname", "mkdir", "rm", "mv",
          "cp", "head", "tail", "wc", "sha256sum", "stat", "df", "sync", "man", "date", "uptime", "release",
          "sysinfo", "health", "net-status"]
PORTS = ["basename", "seq", "cut", "fold", "nl", "uniq", "base64", "rg"]
# Historical SBASE label now groups sbase and Toybox C ports; source origin
# is read from PORTS.tsv rather than inferred from this compatibility label.
# The base userland C ports (userland/PORTS.tsv, installed into ports/
# by scripts/install-userland-ports.sh): C programs through the C kit. A name
# here must not be a native command, a Rust port, a shell builtin, or ABSENT.
SBASE = ["printf", "test", "grep", "sort", "sed", "od", "cmp", "ed", "find", "diff", "hexdump", "tar"]
# Deliberately not provided (README "Commands", "Not provided").
# `ps` is a shell builtin answered by sshd (ps(1)), never a /bin program.
ABSENT = ["kill", "chmod", "chown", "touch", "ln", "top", "mount"]

LINES = "".join(f"line {i}\n" for i in range(1, 31)).encode()
WORDS = b"b\na\na\nc\nc\nc\n"
ALPHA = b"abcdefghijklmnopqrstuvwxyz\n"
PASSWD = b"root:x:0:0:root:/root:/bin/sh\noperator:x:1000:1000:operator:/home/operator:/bin/absd-sh\n"
BIG = "".join(f"row {i:05d}\n" for i in range(1, 15001)).encode()
# A file ripgrep classifies as binary (a NUL byte) with matches on both
# sides of it.
BLOB = b"row one\n\x00binary\nrow two\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


SUMS = f"{sha(ALPHA)}  /etc/alpha.txt\n{'0' * 64}  /etc/words.txt\n".encode()
FIXTURES = {"/etc/lines.txt": LINES, "/etc/words.txt": WORDS, "/etc/alpha.txt": ALPHA,
            "/etc/passwd.txt": PASSWD, "/etc/big.txt": BIG, "/etc/sums.txt": SUMS, "/etc/blob.bin": BLOB}


class CmdsTarget(ssh_absd.AbsdTarget):
    def files(self, authorized):
        files = [f for f in super().files(authorized) if f[0] not in {f"/bin/{n}" for n in NATIVE}]
        files += [(f"/bin/{name}", (self.root / "commands" / name).read_bytes()) for name in NATIVE]
        files += [(f"/bin/{name}", (self.root / "ports" / name).read_bytes()) for name in PORTS + SBASE]
        files += list(FIXTURES.items())
        return files


class Shell:
    """An interactive shell on a PTY: type a line, return what it showed
    before the next prompt (stdout and stderr in order, LF for CRLF)."""

    def __init__(self, matrix):
        self.term = matrix.client.terminal(matrix.op, extra=("-t",))
        sm.require(self.term.wait_raw(), "client never entered raw mode")
        sm.require(self.term.expect(PROMPT, timeout=120), f"no first prompt: {self.term.shown[-300:]!r}")
        self.times = {}

    def run(self, line, timeout=300):
        start = time.monotonic()
        self.term.type(line.encode() + b"\r")
        sm.require(self.term.expect(line.encode() + b"\r\n", timeout=60), f"no echo of {line!r}: {self.term.rest()!r}")
        sm.require(self.term.expect(PROMPT, timeout=timeout), f"no prompt after {line!r}: {self.term.rest()[-600:]!r}")
        self.times[line] = time.monotonic() - start
        return self.term.between.replace(b"\r\n", b"\n")

    def close(self):
        self.term.type(b"exit 0\r")
        status = self.term.wait(60)
        self.term.close()
        return status


class CmdsMatrix(sm.Matrix):
    def expect(self, shell, line, want, name=None):
        got = shell.run(line)
        self.check(name or line, got == want, f"got {got!r} want {want!r}")
        return got

    def expect_match(self, shell, line, pattern, name=None):
        got = shell.run(line)
        m = re.fullmatch(pattern, got.decode(errors="replace"), re.S)
        self.check(name or line, m is not None, f"got {got!r} want /{pattern}/")
        return m

    def device(self):
        return self.t.tree()

    def image_state(self):
        region = absd_fs.fs_region(self.t.image, ssh_absd.DEVICE_SECTORS)
        selected = absd_fs.select(region)
        geometry = absd_fs.geometry(region.sectors)
        used = {b for r in selected["records"] for b in r["blocks"]}
        return selected, geometry, used

    def share(self):
        """Files under /share on the device, by the paths a session sees
        (the device holds them in the release tree; the host reader also
        lists directories, which hold no content of their own)."""
        prefix = self.t.physical("/share") + "/"
        tree = {"/share/" + p[len(prefix):]: d for p, d in self.device().items() if p.startswith(prefix)}
        return {p: d for p, d in tree.items() if not any(q.startswith(p + "/") for q in tree)}

    def manual(self, sh):
        """man(1) over SSH against the pages scripts/render-man.sh rendered
        on the host (README "Manual pages")."""
        base = self.t.root / "manpages"
        pages = {}
        for path in sorted(base.glob("cat[1-9]/*.0")):
            pages[(path.parent.name[3:], path.stem)] = path.read_bytes()
        index = (base / "whatis").read_bytes()
        installed = self.share()
        want = {f"/share/man/cat{s}/{n}.0": d for (s, n), d in pages.items()}
        want["/share/man/whatis"] = index
        self.check("the image carries exactly the rendered manual under /share", installed == want,
                   str(sorted(set(installed) ^ set(want))))
        self.check("the rendered pages are real pages",
                   b"intro -- introduction to ABSD" in pages[("1", "intro")]
                   and b"QEMU-qualified on the 82540EM model" in pages[("4", "e1000")]
                   and all(d.split(b"\n", 1)[0].startswith(f"{n.upper()}({s})".encode()) and b"\nNAME\n" in d
                           for (s, n), d in pages.items()))
        # On the PTY, exactly the page. Pages whose examples show the
        # prompt `absd$ ` are compared by hash (the screen would look like
        # a prompt part way through), and in full through exec below.
        for line, key in [("man intro", ("1", "intro")), ("man 7 handles", ("7", "handles")),
                          ("man 4 e1000", ("4", "e1000")), ("man nvme", ("4", "nvme")),
                          ("man filesystem", ("7", "filesystem")), ("man 7 process", ("7", "process"))]:
            self.check(f"{line}: no prompt text inside the page", PROMPT not in pages[key])
            self.expect(sh, line, pages[key], f"{line} prints the rendered page")
        for line, key in [("man absd-sh", ("1", "absd-sh")), ("man 8 afterboot", ("8", "afterboot")),
                          ("man 1 man", ("1", "man"))]:
            self.expect(sh, f"{line} | sha256sum", f"{sha(pages[key])}  -\n".encode(),
                        f"{line} prints the rendered page (hash)")
        self.expect(sh, "man afterboot | head -n 1", pages[("8", "afterboot")].split(b"\n", 1)[0] + b"\n")
        # Every page in an exec session, byte for byte (no PTY, no shell).
        for (s, n), data in pages.items():
            for command in ([f"man {n}", f"man {s} {n}"] if n in {"intro", "absd-sh", "afterboot"} or s == "7"
                            else [f"man {s} {n}"]):
                rc, out, err = self.ssh(command)
                self.check(f"exec `{command}` prints the rendered page", rc == 0 and out == data and err == b"",
                           f"rc={rc} bytes={len(out)}/{len(data)} err={err!r}")
        rc, out, err = self.ssh("man nosuchpage")
        self.check("exec `man nosuchpage` refuses by name", rc == 1 and out == b""
                   and err == b"man: no entry for nosuchpage in the manual\n", f"rc={rc} out={out!r} err={err!r}")
        # Refusals, by name.
        self.expect(sh, "man nosuchpage", b"man: no entry for nosuchpage in the manual\nabsd-sh: man: exit status 1\n")
        self.expect(sh, "man 9 intro",
                    b"man: no entry for intro in section 9 of the manual\nabsd-sh: man: exit status 1\n")
        self.expect(sh, "man 8 intro",
                    b"man: no entry for intro in section 8 of the manual\nabsd-sh: man: exit status 1\n")
        self.expect(sh, "man ../../etc/motd", b"man: ../../etc/motd: not a page name\nabsd-sh: man: exit status 2\n")
        self.expect(sh, "man x intro",
                    b"man: usage: man [SECTION] NAME | man -k WORD\nabsd-sh: man: exit status 2\n")
        self.expect_match(sh, "nofs man intro",
                          r"man: /share/man: .+: no manual is visible to this process\nabsd-sh: man: exit status 1\n")
        # The index.
        matches = b"".join(l + b"\n" for l in index.splitlines() if b"file" in l.lower())
        # The base userland's pages (cmp, find, grep, od: "files") sort before filesystem(7) in the index, so
        # the filesystem line is required among the matches, not first.
        self.check("the index has a filesystem line",
                   b"\nfilesystem(7) - the ABSD filesystem and its file server\n" in b"\n" + matches, repr(matches))
        self.expect(sh, "man -k FILE", matches, "man -k matches the index, case ignored")
        self.expect(sh, "man -k zzzz", b"man: zzzz: nothing appropriate\nabsd-sh: man: exit status 1\n")
        # /share is the session's read-only view.
        self.expect(sh, "cp /etc/motd /share/man/motd",
                    b"cp: /etc/motd -> /share/man/motd: ABSD filesystem is mounted read-only\nabsd-sh: cp: exit status 1\n")
        self.expect(sh, "rm /share/man/whatis", b"rm: /share/man/whatis: ABSD filesystem is mounted read-only\n"
                    b"absd-sh: rm: exit status 1\n")
        after = self.share()
        self.check("/share unchanged on the device", after == want)
        names = ",".join(f"{n}({s})" for (s, n) in sorted(pages, key=lambda k: (k[1], k[0])))
        self.mark(f"MAN PAGES OK pages={names}")

    def run(self):
        t = self.t
        t.setup(self.work, (self.op.with_suffix(".pub")).read_text())
        first = t.start(fresh=True)
        self.client = sm.Client(self.work, t.port)
        self.client.trust(first["public"])
        bin_prefix = t.physical("/bin") + "/"
        installed = {p[len(bin_prefix):] for p in self.device() if p.startswith(bin_prefix)}
        self.check("the image carries every command", set(NATIVE + PORTS) <= installed, str(sorted(installed)))
        self.check("the image carries the sbase ports", set(SBASE) <= installed, str(sorted(installed)))
        self.mark(f"COMMAND SBASE PRESENT names={','.join(SBASE)}")
        system = {p: d for p, d in self.device().items() if p.startswith(ssh_absd.SYSTEM_PREFIXES)}

        sh = Shell(self)
        # -- COMMAND OUTPUT ---------------------------------------------------------
        self.expect(sh, "/bin/echo one two", b"one two\n")
        self.expect(sh, "/bin/pwd", b"/\n")
        self.expect(sh, "ls /etc", b"alpha.txt\nbig.txt\nblob.bin\nlines.txt\nmotd\npasswd.txt\nsums.txt\nwords.txt\n")
        self.expect(sh, "cat /etc/words.txt /etc/alpha.txt", WORDS + ALPHA)
        self.expect(sh, "printenv", b"")
        self.expect_match(sh, "uname -a", r"ABSD [a-z0-9.-]+ x86_64 x86_64-unknown-absd pid=\d+\n")
        self.expect(sh, "head -n 3 /etc/lines.txt", b"line 1\nline 2\nline 3\n")
        self.expect(sh, "head -c 5 /etc/alpha.txt", b"abcde")
        self.expect(sh, "head -n 2 /etc/lines.txt /etc/words.txt",
                    b"==> /etc/lines.txt <==\nline 1\nline 2\n\n==> /etc/words.txt <==\nb\na\n")
        self.expect(sh, "cat /etc/words.txt | head -n 1", b"b\n")
        self.expect(sh, "tail -n 3 /etc/lines.txt", b"line 28\nline 29\nline 30\n")
        self.expect(sh, "tail -c 4 /etc/alpha.txt", b"xyz\n")
        self.expect(sh, "cat /etc/words.txt | tail -n 2", b"c\nc\n")
        self.expect(sh, "tail -n 2 /etc/big.txt", b"row 14999\nrow 15000\n", "tail of a 150 KB file")
        self.expect(sh, "wc /etc/words.txt", b" 6  6 12 /etc/words.txt\n")
        self.expect(sh, "wc -l /etc/lines.txt /etc/words.txt", b"30 /etc/lines.txt\n 6 /etc/words.txt\n36 total\n")
        self.expect(sh, "cat /etc/alpha.txt | wc -c", b"27\n")
        ls_bytes = self.device()[self.t.physical("/bin/ls")]
        self.expect(sh, "sha256sum /etc/alpha.txt /bin/ls",
                    f"{sha(ALPHA)}  /etc/alpha.txt\n{sha(ls_bytes)}  /bin/ls\n".encode(), "sha256sum = host hashlib")
        self.expect(sh, "cat /etc/lines.txt | sha256sum", f"{sha(LINES)}  -\n".encode())
        self.expect(sh, "sha256sum -c /etc/sums.txt",
                    b"/etc/alpha.txt: OK\n/etc/words.txt: FAILED\nabsd-sh: sha256sum: exit status 1\n")
        motd = self.device()["/etc/motd"]
        self.expect_match(sh, "stat /etc/motd",
                          rf"path: /etc/motd\ntype: file\nsize: {len(motd)}\nread-only flag: no\n"
                          r"object: filesystem=[0-9a-f]{16} serial=\d+\nlinks: 1\nmodified: unknown\nmount: /etc \(read-only\)\n")
        metadata = mtime_reference.records(self.t.image)
        home_time = mtime_reference.timestamp(metadata['/home/operator']['mtime'], True)
        self.expect_match(sh, "stat /home/operator",
                          r"path: /home/operator\ntype: directory\nsize: 0\nread-only flag: no\n"
                          rf"object: filesystem=[0-9a-f]{{16}} serial=\d+\nlinks: 1\nmodified: {re.escape(home_time)}\nmount: /home/operator \(read-write\)\n")
        self.check('directory metadata has a positive timestamp control',
                   any(metadata[p]['mtime'] > 0 for p in ('/', '/home/operator')),
                   {p: metadata[p]['mtime'] for p in ('/', '/home/operator')})
        root_time = mtime_reference.timestamp(metadata['/']['mtime'], True)
        self.expect_match(sh, "stat /",
                          rf"path: /\ntype: directory\n.*modified: {re.escape(root_time)}\nmount: none \(a directory on the way to this session's mounts; read-only\)\n")
        etc = {p[len("/etc/"):]: d for p, d in self.device().items() if p.startswith("/etc/")}
        width = max(len(str(len(d))) for d in etc.values())
        self.expect(sh, "ls -l /etc", "".join(f"- -- 1 {len(d):>{width}} - {n}\n" for n, d in sorted(etc.items())).encode(),
                    "ls -l: kind, read-only flag, links, size, unknown mtime")
        self.expect(sh, "ls -l /", mtime_reference.root_listing(mtime_reference.records(self.t.image), self.t.physical),
                    "root listing retains exact names and columns with backing mtimes")
        self.expect(sh, "ls -x /", b"ls: unknown option -x (only -l)\nabsd-sh: ls: exit status 2\n")
        before = time.time()
        m = self.expect_match(sh, "date", r"(\w{3} \w{3} [ \d]\d \d\d:\d\d:\d\d UTC \d{4})\n")
        shown = calendar.timegm(time.strptime(m.group(1), "%a %b %d %H:%M:%S UTC %Y"))
        self.check("date is the host's UTC time, whole seconds", int(before) - 2 <= shown <= time.time() + 2,
                   f"{shown} vs {before:.0f}")
        self.expect_match(sh, "date +%s", r"\d{10}\n")
        self.expect(sh, "date -s 12:00", b"date: usage: date [-u] [+%s] (setting the clock and other formats are not "
                    b"supported)\nabsd-sh: date: exit status 2\n")
        self.expect_match(sh, "uptime", r"up \d+ days \d\d:\d\d:\d\d, \d+ ticks since boot, boot [0-9a-f]{32}\n")
        # The ports: unmodified uutils 0.12.0.
        self.expect(sh, "basename /home/operator/notes.txt .txt", b"notes\n")
        self.expect(sh, "seq 3", b"1\n2\n3\n")
        self.expect(sh, "seq -s , 1 2 7", b"1,3,5,7\n")
        self.expect(sh, "cut -d : -f 1,6 /etc/passwd.txt", b"root:/root\noperator:/home/operator\n")
        self.expect(sh, "fold -w 10 /etc/alpha.txt", b"abcdefghij\nklmnopqrst\nuvwxyz\n")
        self.expect(sh, "nl /etc/words.txt",
                    b"".join(f"{i + 1:6d}\t{w}\n".encode() for i, w in enumerate(WORDS.decode().split())))
        self.expect(sh, "uniq -c /etc/words.txt", b"      1 b\n      2 a\n      3 c\n")
        self.expect(sh, "cat /etc/words.txt | uniq | wc -l", b"3\n")
        encoded = base64.b64encode(ALPHA) + b"\n"
        self.expect(sh, "base64 /etc/alpha.txt", encoded)
        self.expect(sh, "base64 /etc/alpha.txt | base64 -d", ALPHA)
        # ripgrep 15.2.0, unmodified (rg(1)): one file, several files (in
        # the order given), a directory tree, and standard input named as
        # `-`. No terminal, so the output is the one-line-per-match form.
        self.expect(sh, 'rg -n "line 1[0-9]" /etc/lines.txt', b"".join(f"{i}:line {i}\n".encode() for i in range(10, 20)))
        self.expect(sh, "rg zzz /etc/lines.txt", b"absd-sh: rg: exit status 1\n", "rg: no match is status 1, nothing printed")
        self.expect(sh, "rg -c row /etc/big.txt", b"15000\n")
        self.expect(sh, 'rg -n "row 1234[0-9]" /etc/big.txt', b"".join(f"{i}:row {i}\n".encode() for i in range(12340, 12350)))
        self.expect(sh, "rg a /etc/words.txt /etc/alpha.txt", b"/etc/words.txt:a\n/etc/words.txt:a\n/etc/alpha.txt:" + ALPHA)
        self.expect(sh, 'rg -n --sort path "line 3" /etc', b"/etc/lines.txt:3:line 3\n/etc/lines.txt:30:line 30\n")
        self.expect(sh, "rg -l --sort path row /etc", b"/etc/big.txt\n", "rg: a tree walk skips the binary file")
        self.expect(sh, "rg -i -o B /etc/words.txt", b"b\n")
        self.expect(sh, "cat /etc/words.txt | rg -c c -", b"3\n", "rg: standard input, named as -")
        self.expect(sh, "cat /etc/big.txt | rg -c row -", b"15000\n")
        self.expect(sh, 'rg -o "row 000[0-9][0-9]" /etc/big.txt | wc -l', b"99\n", "rg in a pipeline")
        self.expect(sh, "rg row /etc/blob.bin", b'binary file matches (found "\\0" byte around offset 8)\n',
                    "rg: a binary file given by name stops at its first NUL")
        self.expect(sh, "rg -a row /etc/blob.bin", b"row one\nrow two\n", "rg -a searches it as text")
        # Refusals and errors: ripgrep's own status 2 for a missing path (the
        # text is std's ABSD message, not strerror), a bad flag, no pattern;
        # a session cannot name /ssh; a process without the file server
        # cannot read; -j asks for threads, which do not exist here.
        self.expect(sh, "rg x /etc/nothing",
                    b"rg: /etc/nothing: IO error for operation on /etc/nothing: ABSD path not found\n"
                    b"absd-sh: rg: exit status 2\n")
        self.expect(sh, "rg --nosuch x /etc/lines.txt", b"rg: unrecognized flag --nosuch\nabsd-sh: rg: exit status 2\n")
        self.expect(sh, "rg", b"rg: ripgrep requires at least one pattern to execute a search\nabsd-sh: rg: exit status 2\n")
        self.expect(sh, "rg ssh-ed25519 /ssh/authorized_keys",
                    b"rg: /ssh/authorized_keys: IO error for operation on /ssh/authorized_keys: ABSD path not found\n"
                    b"absd-sh: rg: exit status 2\n")
        self.expect(sh, "nofs rg row /etc/lines.txt",
                    b"rg: /etc/lines.txt: IO error for operation on /etc/lines.txt: ABSD path not found\n"
                    b"absd-sh: rg: exit status 2\n")
        self.expect(sh, "rg -j2 row /etc", b"rg: unsupported platform\nabsd-sh: rg: exit status 2\n",
                    "rg -j: the parallel walker needs threads; refused")
        # Usage errors are errors.
        self.expect(sh, "head -x 1 /etc/lines.txt",
                    b"head: usage: head [-n LINES | -c BYTES] [FILE...]\nabsd-sh: head: exit status 2\n")
        self.expect(sh, "cat /etc/nothing", b"cat: /etc/nothing: ABSD path not found\nabsd-sh: cat: exit status 1\n")
        self.expect(sh, "cat /etc", b"cat: /etc: ABSD path is a directory\nabsd-sh: cat: exit status 1\n")
        self.expect(sh, "echo mid | cat /etc/words.txt - /etc/alpha.txt", WORDS + b"mid\n" + ALPHA, "cat - is standard input")
        # A reader that is done: the writer gets a broken pipe, not a
        # signal, and ends quietly (the pipeline's status is the reader's).
        self.expect(sh, "cat /etc/big.txt | head -n 1", b"row 00001\n", "cat | head: no error when head is done")
        self.expect(sh, "ls -l /bin /etc /share/man/cat1 /share/man/cat7 /share/man/cat8 | head -n 1", b"/bin:\n",
                    "ls | head: no error when head is done")
        # An option a command does not have is a usage error, never a path.
        for line, message in [("cat -n /etc/words.txt", b"cat: unknown option -n (cat takes no options)"),
                              ("mv -f /etc/motd /home/operator/motd", b"mv: unknown option -f (mv takes no options)"),
                              ("cp -a /etc/motd /home/operator/motd", b"cp: unknown option -a (only -r)"),
                              ("rm -f /etc/motd", b"rm: unknown option -f (only -r)"),
                              ("mkdir -m 755 /home/operator/d", b"mkdir: unknown option -m (only -p)")]:
            self.expect(sh, line, message + f"\nabsd-sh: {line.split()[0]}: exit status 2\n".encode())
        self.expect(sh, "ls /etc -l", b"/etc:\nalpha.txt\nbig.txt\nblob.bin\nlines.txt\nmotd\npasswd.txt\nsums.txt\nwords.txt\n"
                    b"ls: -l: ABSD path not found\nabsd-sh: ls: exit status 1\n", "options come first; a later -l is a path")
        self.expect(sh, "ls -- /etc/motd", b"/etc/motd\n", "-- ends the options")
        self.mark("COMMAND OUTPUT OK")

        # -- COMMAND WRITES ---------------------------------------------------------------
        m = self.expect_match(sh, "df", r".*\n(/tmp/session-\d+) +rw\n/var/log +ro\n", "df lists this session's mounts")
        tmp = m.group(1)
        self.expect(sh, "mkdir -p /home/operator/w/sub", b"")
        self.expect(sh, "cp /etc/lines.txt /home/operator/w/lines", b"")
        self.expect(sh, "cp /etc/words.txt /etc/alpha.txt /home/operator/w/sub", b"")
        self.expect(sh, "cp -r /home/operator/w /home/operator/w2", b"")
        self.expect(sh, "ls /home/operator/w2 /home/operator/w2/sub",
                    b"/home/operator/w2:\nlines\nsub/\n/home/operator/w2/sub:\nalpha.txt\nwords.txt\n")
        self.expect(sh, "cd /home/operator", b"")
        self.expect(sh, "cp w/lines w/lines",
                    b"cp: w/lines -> w/lines: source and destination are the same file\nabsd-sh: cp: exit status 1\n")
        self.expect(sh, "cp -r w w/sub/inner",
                    b"cp: w -> w/sub/inner: cannot copy a directory into itself\nabsd-sh: cp: exit status 1\n")
        self.expect(sh, f"mv w2 {tmp}/w2", b"", "mv between this session's two writable mounts")
        self.expect(sh, f"ls {tmp}/w2/sub", b"alpha.txt\nwords.txt\n")
        self.expect(sh, "ls", b"w/\n", "ls with no argument lists the working directory")
        self.expect(sh, "ls w/lines", b"w/lines\n", "ls of a file lists the file")
        self.expect(sh, "cp w w3", b"cp: w -> w3: is a directory (use -r)\nabsd-sh: cp: exit status 1\n")
        self.expect(sh, "cp /etc/alpha.txt w/lines", b"", "cp onto an existing file replaces its bytes")
        self.expect(sh, "cat w/lines", ALPHA)
        self.expect(sh, "cp /etc/motd w", b"", "cp of one file into an existing directory")
        self.expect(sh, "ls w", b"lines\nmotd\nsub/\n")
        self.expect(sh, "mv w/motd w/sub", b"", "mv into an existing directory")
        self.expect(sh, "ls w/sub", b"alpha.txt\nmotd\nwords.txt\n")
        self.expect(sh, "mv w w/sub/inner",
                    b"mv: w -> w/sub/inner: cannot move a directory into itself\nabsd-sh: mv: exit status 1\n")
        self.expect(sh, "mv w /home/operator",
                    b"mv: w -> /home/operator/w: source and destination are the same object\nabsd-sh: mv: exit status 1\n",
                    "mv of a directory into its own parent is a move onto itself")
        self.expect(sh, "mkdir w", b"mkdir: w: ABSD path already exists\nabsd-sh: mkdir: exit status 1\n")
        self.expect(sh, "mkdir -p w", b"", "mkdir -p of an existing directory")
        self.expect(sh, "rm w", b"rm: w: is a directory (use -r)\nabsd-sh: rm: exit status 1\n")
        self.expect(sh, "rm -r w/sub/.", b"rm: w/sub/.: refusing to remove `.` or `..`\nabsd-sh: rm: exit status 1\n")
        self.expect(sh, "rm -r w/sub", b"")
        self.expect(sh, "rm w/lines", b"")
        self.expect(sh, "ls w", b"", "the directory is empty")
        self.expect(sh, "cp /etc/big.txt big", b"")
        self.expect(sh, "sha256sum big", f"{sha(BIG)}  big\n".encode())
        self.expect(sh, "cd /", b"")
        m = self.expect_match(sh, "sync -v", r"commit (\d+)\n")
        synced = int(m.group(1))
        selected, _, _ = self.image_state()
        self.check("sync: the commit it reports is the one the host reads", selected["seq"] == synced,
                   f"host seq {selected['seq']} sync {synced}")
        tree = self.device()
        home = sorted(p for p in tree if p.startswith(("/home/", "/tmp/")))
        self.check("the device holds what the commands wrote, and not what they removed",
                   tree.get("/home/operator/big") == BIG and tree.get(f"{tmp}/w2/lines") == LINES
                   and tree.get(f"{tmp}/w2/sub/words.txt") == WORDS and tree.get(f"{tmp}/w2/sub/alpha.txt") == ALPHA
                   and not any(p.startswith(("/home/operator/w/", "/home/operator/w2")) for p in tree), str(home))
        self.mark("COMMAND WRITES OK")

        # -- COMMAND REFUSALS --------------------------------------------------------------
        ro = b"ABSD filesystem is mounted read-only"
        nf = b"ABSD path not found"
        kept = b"a mount point of this session; the file server keeps it"
        refusals = [
            ("cp /etc/motd /bin/motd", b"cp: /etc/motd -> /bin/motd: " + ro, "cp"),
            ("cp /etc/motd /ssh/motd", b"cp: /etc/motd -> /ssh/motd: " + nf, "cp"),
            ("cp /ssh/host_ed25519_seed /home/operator/seed", b"cp: /ssh/host_ed25519_seed -> /home/operator/seed: " + nf, "cp"),
            ("cp -r /home/operator /etc/home-copy", b"cp: /home/operator -> /etc/home-copy: " + ro, "cp"),
            ("mv /home/operator/big /bin/big", b"mv: /home/operator/big -> /bin/big: " + ro, "mv"),
            ("mv /etc/motd /home/operator/motd", b"mv: /etc/motd -> /home/operator/motd: " + ro, "mv"),
            ("mv /home/operator/big /ssh/big", b"mv: /home/operator/big -> /ssh/big: " + nf, "mv"),
            (f"mv {tmp} /home/operator/t", f"mv: {tmp} -> /home/operator/t: ".encode() + kept, "mv"),
            ("rm /bin/ls", b"rm: /bin/ls: " + ro, "rm"),
            ("rm /etc/motd", b"rm: /etc/motd: " + ro, "rm"),
            ("rm /ssh/authorized_keys", b"rm: /ssh/authorized_keys: " + nf, "rm"),
            ("rm -r /home/operator", b"rm: /home/operator: " + kept, "rm"),
            ("rm -r /bin", b"rm: /bin: " + kept, "rm"),
            ("rm -r /home", b"rm: /home: holds " + kept, "rm"),
            ("rm -r /tmp", b"rm: /tmp: holds " + kept, "rm"),
            ("rm -r /", b"rm: /: holds " + kept, "rm"),
            ("rm -r /home/operator/..", b"rm: /home/operator/..: refusing to remove `.` or `..`", "rm"),
            ("rm -r /home/operator/../../home", b"rm: /home/operator/../../home: holds " + kept, "rm"),
            ("mkdir /bin/x", b"mkdir: /bin/x: " + ro, "mkdir"),
            ("ro cp /etc/motd /home/operator/ro-copy", b"cp: /etc/motd -> /home/operator/ro-copy: " + ro, "cp"),
            ("ro rm /home/operator/big", b"rm: /home/operator/big: " + ro, "rm"),
            ("nofs cat /etc/motd", b"cat: /etc/motd: " + nf, "cat"),
            ("nofs df", b"df: this process has no file server channel (-2)", "df"),
            ("nofs sync", b"sync: this process has no file server channel (-2)", "sync"),
        ]
        for line, message, command in refusals:
            self.expect(sh, line, message + f"\nabsd-sh: {command}: exit status 1\n".encode())
        # Another session sees neither this session's /tmp nor can it touch it.
        other = Shell(self)
        other_tmp = self.expect_match(other, "ls /tmp", r"(session-\d+)/\n", "a second session: its own /tmp only")
        self.check("the second session's /tmp is another", f"/tmp/{other_tmp.group(1)}" != tmp, tmp)
        self.expect(other, f"ls {tmp}", f"ls: {tmp}: ".encode() + nf + b"\nabsd-sh: ls: exit status 1\n")
        self.expect(other, f"cp {tmp}/w2/lines /home/operator/stolen",
                    f"cp: {tmp}/w2/lines -> /home/operator/stolen: ".encode() + nf + b"\nabsd-sh: cp: exit status 1\n")
        self.expect(other, f"rm -r {tmp}/w2", f"rm: {tmp}/w2: ".encode() + nf + b"\nabsd-sh: rm: exit status 1\n")
        self.expect(other, f"mv {tmp}/w2 /home/operator/w2",
                    f"mv: {tmp}/w2 -> /home/operator/w2: ".encode() + nf + b"\nabsd-sh: mv: exit status 1\n")
        self.check("the second session exits", other.close() == 0)
        self.expect(sh, f"ls {tmp}/w2", b"lines\nsub/\n", "this session's /tmp is untouched by the other")
        after = {p: d for p, d in self.device().items() if p.startswith(ssh_absd.SYSTEM_PREFIXES)}
        tree = self.device()
        self.check("/bin, /etc, /ssh unchanged; no refused write reached the device",
                   after == system and not any(p in tree for p in ["/home/operator/seed", "/home/operator/motd",
                                                                   "/home/operator/ro-copy", "/home/operator/stolen",
                                                                   "/home/operator/t", "/home/operator/w2"])
                   and tree.get("/home/operator/big") == BIG, str(set(after) ^ set(system)))
        self.expect(sh, "ls /home/operator", b"big\nw/\n", "the refused rm -r of /home touched nothing")
        self.mark("COMMAND REFUSALS OK")

        # -- COMMAND SPACE ------------------------------------------------------------------
        self.expect(sh, "sync", b"")
        m = self.expect_match(sh, "df",
                              r"Filesystem        1K-blocks      Used Available Use% Commit\n"
                              r"absd:([0-9a-f]{16}) +(\d+) +(\d+) +(\d+) +(\d+)% (\d+)\n"
                              r"Mounted on        Access\n/bin +ro\n/etc +ro\n/home/operator +rw\n/share +ro\n/tmp/session-\d+ +rw\n"
                              r"/var/log +ro\n")
        selected, geometry, used = self.image_state()
        fs_id, total, used_k, free_k, _, commit = m.groups()
        block_k = absd_fs.BLOCK // 1024
        self.check("df: the filesystem, its data blocks, and the blocks in use are the image's",
                   int(fs_id, 16) == selected["fs_id"] and int(total) == geometry["data_blocks"] * block_k
                   and int(used_k) == len(used) * block_k and int(free_k) == (geometry["data_blocks"] - len(used)) * block_k
                   and int(commit) == selected["seq"],
                   f"df={m.groups()} host fs={selected['fs_id']:016x} blocks={geometry['data_blocks']} "
                   f"used={len(used)} seq={selected['seq']}")
        rc, out, err = self.ssh("/bin/df")
        self.check("df in an exec session too", rc == 0 and out.startswith(b"Filesystem"), f"{rc} {out!r} {err!r}")
        # sysinfo: every line a live answer, checked against the kernel's
        # own accounting and the host's reading of the image.
        m = self.expect_match(sh, "sysinfo",
                              r"release: ([a-z0-9.-]+) \(kernel_abi \d+, fsd_protocol \d+, fs_format \d+, app_abi \d+\)\n"
                              r"boot: ([0-9a-f]{32}), up \d+ days \d\d:\d\d:\d\d \(\d+ ticks\)\n"
                              r"memory: (\d+) KiB free, (\d+) KiB allocated \((\d+) \+ (\d+) frames of 4096 bytes\)\n"
                              r"kernel: (\d+) process slots, (\d+) handles, (\d+) pipes, (\d+) cells\n"
                              r"filesystem: absd:([0-9a-f]{16}), (\d+) KiB, (\d+) KiB used \((\d+)%\), (\d+) KiB free, "
                              r"commit (\d+)\n")
        release, boot, free_k, alloc_k, free_f, alloc_f = m.group(1), m.group(2), *map(int, m.groups()[2:6])
        slots, handles, pipes, cells = map(int, m.groups()[6:10])
        fs_id, total_k, used_k, _, avail_k, commit = m.groups()[10:16]
        self.check("sysinfo: KiB follow the frames", free_k == free_f * 4 and alloc_k == alloc_f * 4, m.group(0))
        self.check("sysinfo: the kernel has a shell, sshd, fsd, init and sysinfo running", slots >= 5 and handles > 0
                   and pipes > 0, m.group(0))
        up = self.expect_match(sh, "uptime", r"up .*, boot ([0-9a-f]{32})\n")
        self.check("sysinfo: the boot is uptime's", up.group(1) == boot)
        rel = self.expect_match(sh, "release", r"release=([a-z0-9.-]+) .*\n")
        self.check("sysinfo: the release is release(1)'s", rel.group(1) == release)
        # df a moment later: the same filesystem and size; the session's
        # own log lines may have moved the commit sequence and a block.
        df_line = self.expect_match(sh, "df", r".*\nabsd:([0-9a-f]{16}) +(\d+) +(\d+) +(\d+) +\d+% (\d+)\n.*")
        df_id, df_total, df_used, df_avail, df_commit = df_line.groups()
        self.check("sysinfo: the filesystem line is df's",
                   (fs_id, total_k) == (df_id, df_total) and int(used_k) + int(avail_k) == int(total_k)
                   and abs(int(used_k) - int(df_used)) <= 4 and int(df_commit) >= int(commit),
                   f"{m.groups()[10:]} vs {df_line.groups()}")
        self.expect(sh, "sysinfo -v", b"sysinfo: usage: sysinfo\nabsd-sh: sysinfo: exit status 2\n")
        got = self.expect_match(sh, "nofs sysinfo", r"release: no file server serves this process\nboot: .*\nmemory: .*\n"
                                r"kernel: .*\nfilesystem: no file server channel\nabsd-sh: sysinfo: exit status 1\n",
                                "nofs sysinfo: the kernel lines still, the file server lines refused, status 1")
        rc, out, err = self.ssh("/bin/sysinfo")
        self.check("sysinfo in an exec session too", rc == 0 and out.startswith(b"release: ") and err == b"",
                   f"{rc} {out!r} {err!r}")
        # health: this boot's recovery line from the file server's log, the
        # same boot and release as sysinfo's, the configuration files sshd
        # started from, and the log sizes (docs/admin-on-box-20261015).
        h = self.expect_match(sh, "health",
                              r"release: ([a-z0-9.-]+)\n"
                              r"boot: ([0-9a-f]{32}), up \d+ days \d\d:\d\d:\d\d \(\d+ ticks\)\n"
                              r"recovery: previous=(none|ended|failed|not_ready) streak=(\d+) seq=(\d+)\n"
                              r"config: network (?:from /etc/network\.conf|built-in defaults \(no /etc/network\.conf\))\n"
                              r"config: sshd (?:from /etc/sshd\.conf|built-in defaults \(no /etc/sshd\.conf\))\n"
                              r"logs: fsd \d+ bytes, fsd\.0 (?:\d+ bytes|none), sshd \d+ bytes, sshd\.0 (?:\d+ bytes|none)\n")
        self.check("health: the boot and release are sysinfo's", (h.group(1), h.group(2)) == (release, boot), h.group(0))
        fsd_log = self.ssh("/bin/cat /var/log/fsd")[1].decode(errors="replace")
        self.check("health: the recovery line is this boot's, as the file server logged it",
                   re.search(rf"fsd: started: boot {boot}, .*\n(?:.*\n)*?.* fsd: FSD RECOVERY seq={h.group(5)} "
                             rf"streak={h.group(4)} previous={h.group(3)}\n", fsd_log) is not None, h.group(0))
        usage_v = self.expect(sh, "health -v", b"health: usage: health [--json]\nabsd-sh: health: exit status 2\n")
        usage_json = self.expect(sh, "health --json x", b"health: usage: health [--json]\nabsd-sh: health: exit status 2\n")
        self.expect_match(sh, "nofs health", r"release: unknown \(no file server serves this process\)\n(?:.*\n)*?"
                          r"absd-sh: health: exit status 1\n", "nofs health: unknown in place, status 1")
        rc, out, err = self.ssh("/bin/health")
        self.check("health in an exec session too", rc == 0 and out.startswith(b"release: ") and err == b"",
                   f"{rc} {out!r} {err!r}")
        rc, out, err = self.ssh("/bin/net-status")
        self.check("net-status is a boot/recovery-bound retained static sample", rc == 0 and err == b""
                   and out.startswith(b"network: retained owner sample (record_for_current_boot)\n")
                   and f"lifetime: boot:{boot}/recovery:".encode() in out
                   and b"configured: 10.0.2.15/24 gateway=10.0.2.2 port=22 origin=built-in defaults\n" in out,
                   f"{rc} {out!r} {err!r}")
        self.expect(sh, "net-status -v", b"net-status: usage: net-status\nabsd-sh: net-status: exit status 2\n")
        self.expect(sh, "nofs net-status", b"net-status: unavailable (fsd_absent)\nabsd-sh: net-status: exit status 1\n")
        rc, out, err = self.ssh("/bin/health --json")
        self.check("health JSON exec status", rc == 0 and err == b"", f"{rc} {out!r} {err!r}")
        self.check("health JSON exec document validates", health_validator.validate(out) == "complete")
        doc = json.loads(out)
        facts = {f["id"]: f for f in doc["facts"]}
        recovery = facts["fsd.recovery"]["value"]
        self.check("health JSON agrees with this boot's human/public-log facts",
                   doc["boot_id"] == boot and facts["fsd.release"]["value"] == release
                   and (recovery["previous"], recovery["streak"], recovery["seq"])
                   == (h.group(3), h.group(4), h.group(5)))
        nofs = sh.run("nofs health --json")
        suffix = b"absd-sh: health: exit status 1\n"
        self.check("nofs health JSON status", nofs.endswith(suffix), repr(nofs))
        raw = nofs[:-len(suffix)]
        self.check("nofs health JSON validates", health_validator.validate(raw) == "partial")
        partial = json.loads(raw)
        fsd_facts = [f for f in partial["facts"] if f["id"].startswith("fsd.")]
        self.check("nofs health JSON reports both missing FSD facts",
                   partial["boot_id"] == boot and len(fsd_facts) == 2
                   and all(f["availability"] == "unavailable" and f["reason"] == "fsd_absent"
                           and f["value"] is None for f in fsd_facts))
        observations = self.work / "health-json-observations"
        observations.mkdir(exist_ok=False)
        for name, data in [("exec.json", out), ("nofs.json", raw), ("nofs.session.txt", nofs),
                           ("usage-v.txt", usage_v), ("usage-json-x.txt", usage_json)]:
            (observations / name).write_bytes(data)
        (observations / "statuses.json").write_text(json.dumps({
            "exec": {"status": rc, "stderr_hex": err.hex()},
            "nofs": {"status": 1, "source": "checked exact shell exit-status line"},
            "bad_arguments": {"status": 2, "source": "checked exact usage and shell exit-status lines"},
            "validator": health_validator.SCHEMA,
        }, indent=2) + "\n")
        self.mark("HEALTH JSON COMMANDS OK exec=complete nofs=partial bad_args=2")
        self.mark("COMMAND SPACE OK")

        # -- SHELL LISTS ------------------------------------------------------------------
        # Lists, `echo -n`, `help`, and arrow keys, on the PTY.
        self.expect(sh, "cd /home/operator; pwd", b"/home/operator\n")
        self.expect(sh, "mkdir lst && ls lst && echo made", b"made\n")
        self.expect(sh, "mkdir lst && echo again || echo exists",
                    b"mkdir: lst: ABSD path already exists\nabsd-sh: mkdir: exit status 1\nexists\n")
        self.expect(sh, "cat /etc/nothing || echo missing; status",
                    b"cat: /etc/nothing: ABSD path not found\nabsd-sh: cat: exit status 1\nmissing\n0\n")
        self.expect(sh, "echo -n a; echo -n b; echo", b"ab\n")
        self.expect(sh, "cat /etc/words.txt | wc -l && rm -r lst && ls", b"6\nbig\nw/\n")
        self.expect(sh, "ls lst;", b"ls: lst: ABSD path not found\nabsd-sh: ls: exit status 1\n")
        self.expect(sh, "ls ;; ls", b"absd-sh: syntax error: empty command in list\n")
        self.expect(sh, "ls &", b"absd-sh: syntax error: `&` is not supported (there are no background jobs)\n")
        self.expect(sh, "echo \"a;b\" \"c && d\"", b"a;b c && d\n")
        self.expect_match(sh, "help", r"absd-sh: a line is pipelines joined by .*\n  pipeline: .*\n  CMD: .*\n"
                          r"  prefixes: .*\nbuiltins: cd \[DIR\].*\n  ps .*\nquoting: .*\n", "help prints the grammar")
        self.expect(sh, "help | wc -l", b"7\n")
        self.expect(sh, "cd /", b"")
        # An up arrow and a left arrow typed into a line: dropped, not run.
        sh.term.type(b"echo \x1b[Aup\x1b[D\r")
        sm.require(sh.term.expect(b"echo up\r\n", timeout=60), f"no echo: {sh.term.rest()!r}")
        sm.require(sh.term.expect(PROMPT, timeout=120), f"no prompt: {sh.term.rest()[-300:]!r}")
        self.check("arrow keys are dropped from the line", sh.term.between.replace(b"\r\n", b"\n") == b"up\n",
                   repr(sh.term.between))
        rc, out, err = self.ssh("mkdir /home/operator/x && ls /home/operator && rm -r /home/operator/x; ls /home/operator")
        self.check("an exec text with a list runs through the shell",
                   rc == 0 and out == b"big\nw/\nx/\nbig\nw/\n" and err == b"", f"{rc} {out!r} {err!r}")
        rc, out, err = self.ssh("cat /etc/nothing || ls /home/operator")
        self.check("exec: `||` after a failing command", rc == 0 and out == b"big\nw/\n"
                   and err == b"cat: /etc/nothing: ABSD path not found\nabsd-sh: cat: exit status 1\n",
                   f"{rc} {out!r} {err!r}")
        self.mark("SHELL LISTS OK")

        # -- COMMAND ABSENCES -----------------------------------------------------------------
        for name in ABSENT:
            self.expect(sh, name, f"absd-sh: {name}: not found\n".encode(), f"{name} is not provided")
        self.expect(sh, "/bin/ps", b"absd-sh: /bin/ps: not found\n", "ps is not a program")
        self.check("no absent command is on the device", not any(self.t.physical(f"/bin/{n}") in self.device()
                                                                for n in ABSENT + ["ps"]))
        self.mark("COMMAND ABSENCES OK")
        self.manual(sh)
        self.check("the session exits", sh.close() == 0)
        self.alive("the command matrix")

        starts = {line.split()[0]: sh.times[line] for line in
                  ["/bin/echo one two", "wc /etc/words.txt", "basename /home/operator/notes.txt .txt",
                   "nl /etc/words.txt", "rg -c row /etc/big.txt", "tail -n 2 /etc/big.txt"]}
        print("COMMAND START SECONDS " + " ".join(f"{k}={v:.1f}" for k, v in starts.items()), flush=True)
        t.stop()
        names = ",".join(NATIVE + PORTS)
        print(f"COMMAND SET OK names={names}", flush=True)


class HostCheckFailed(Exception):
    pass


def shell_builtins(root):
    """The names absd-sh runs itself (sh/src/lib.rs is_*_builtin): a /bin
    program of the same name would never run by its bare name."""
    text = (root / "sh" / "src" / "lib.rs").read_text()
    names = set()
    for which in ("is_output_builtin", "is_control_builtin"):
        found = re.search(rf"fn {which}\(name: &str\) -> bool \{{\s*matches!\(name, ([^)]*)\)", text)
        if not found:
            raise HostCheckFailed(f"sh/src/lib.rs: {which} not found")
        names |= set(re.findall(r'"([^"]+)"', found.group(1)))
    return names


def licence_lines(text):
    """sbase.LICENSE's lines as the ASCII manual renders them: the copyright
    sign as (C), accented letters plain, whitespace collapsed."""
    text = text.replace("\u00a9", "(C)").translate(str.maketrans({"\u0144": "n", "\u00e9": "e"}))
    return [" ".join(line.split()) for line in text.splitlines() if line.strip()]


def host_check(root=None, image_list=True):
    """The sbase ports' expectations, on the host only (no boot)."""
    root = pathlib.Path(root or here.parent)
    import operator_image as oi

    def need(ok, what):
        if not ok:
            raise HostCheckFailed(what)

    rows = [line.split("\t") for line in (root / "userland" / "PORTS.tsv").read_text().splitlines()
            if line.strip() and not line.startswith("#")]
    need(all(len(r) == 7 for r in rows), "userland/PORTS.tsv: a row without seven fields")
    table = {r[0]: r for r in rows}
    need([r[0] for r in rows] == SBASE, f"userland/PORTS.tsv names {[r[0] for r in rows]}, not {SBASE}")
    need(NATIVE == oi.NATIVE, f"NATIVE differs from scripts/operator_image.py's: {oi.NATIVE}")
    builtins = shell_builtins(root)
    for name in SBASE:
        need(name not in NATIVE + ["absd-sh"], f"{name}: a native command has the name")
        need(name not in PORTS, f"{name}: a Rust port has the name")
        need(name not in builtins, f"{name}: an absd-sh builtin has the name ({sorted(builtins)})")
        need(name not in ABSENT + ["ps"], f"{name}: deliberately not provided (ABSENT)")
    if image_list:
        missing = [n for n in SBASE if n not in oi.PORTS]
        need(not missing, f"scripts/operator_image.py:73 PORTS does not list {','.join(missing)}: the "
                          "operator image would not carry them (the hook: append them to PORTS; "
                          "docs/base-userland-20261012/RECORD.md)")
        need(sorted(oi.PORTS) == sorted(PORTS + SBASE), f"scripts/operator_image.py PORTS is {oi.PORTS}, "
                                                         f"not the Rust ports and the sbase ports {PORTS + SBASE}")
    need(not set(ABSENT) & set(oi.NATIVE + oi.PORTS), "an ABSENT command is in the image's list")
    # scripts/build-ports.sh assembles the ports elsewhere and passes it as
    # ABSD_PORTS_DIR; ports/ is published only after this check passes.
    ports = pathlib.Path(os.environ.get("ABSD_PORTS_DIR") or root / "ports")
    for name in SBASE:
        path = ports / name
        need(path.is_file(), f"ports/{name} missing: run scripts/build-ports.sh "
                             "(or scripts/install-userland-ports.sh)")
        data = path.read_bytes()
        need(sha(data) == table[name][5] and str(len(data)) == table[name][6],
             f"ports/{name} is {sha(data)} ({len(data)} bytes), not userland/PORTS.tsv's {table[name][5]} "
             f"({table[name][6]} bytes)")
        need((root / "man" / f"{name}.1").is_file(), f"man/{name}.1 missing")
        origin = table[name][1].split("-", 1)[0]
        need(re.search(rf"^\.Xr {origin} 7", (root / "man" / f"{name}.1").read_text(), re.M) is not None,
             f"man/{name}.1 does not refer to {origin}(7)")
    need((root / "man" / "sbase.7").is_file(), "man/sbase.7 missing")
    whatis = root / "manpages" / "whatis"
    if whatis.is_file():
        index = whatis.read_text()
        for page in [f"{n}(1)" for n in SBASE] + ["sbase(7)", "toybox(7)"]:
            need(re.search(rf"^{re.escape(page)} - ", index, re.M) is not None, f"manpages/whatis lacks {page}")
        rendered = " ".join((root / "manpages" / "cat7" / "sbase.0").read_text().split())
        for line in licence_lines((root / "userland" / "sbase.LICENSE").read_text()):
            need(line in rendered, f"the rendered sbase(7) lacks the licence line {line!r}")
        rendered = " ".join((root / "manpages" / "cat7" / "toybox.0").read_text().split())
        for line in licence_lines((root / "userland" / "diff" / "LICENSE").read_text()):
            need(line in rendered, f"the rendered toybox(7) lacks the licence line {line!r}")
    need((root / "man" / "toybox.7").is_file(), "man/toybox.7 missing")
    print(f"COMMAND SBASE EXPECTED OK names={','.join(SBASE)}" + ("" if image_list else " image_list=not-checked"),
          flush=True)


def main():
    if "--host-check" in sys.argv[1:]:
        try:
            host_check(image_list="--without-image-list" not in sys.argv[1:])
        except HostCheckFailed as e:
            print(f"COMMAND SBASE EXPECTED FAILED: {e}", file=sys.stderr)
            sys.exit(1)
        return
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    args, rest = ap.parse_known_args()
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    # Room for the ports (about 5 MB) beside the platform's commands.
    ssh_absd.IMAGE_BYTES = 32 * 1024 * 1024
    ssh_absd.DEVICE_SECTORS = ssh_absd.IMAGE_BYTES // 512
    base = ssh_absd.target(rest)
    target = CmdsTarget.__new__(CmdsTarget)
    target.__dict__.update(base.__dict__)
    matrix = CmdsMatrix(target, work)
    try:
        matrix.run()
    except (sm.Failed, ssh_absd.Failed) as e:
        print(f"CMDS MATRIX FAILED: {e}", file=sys.stderr)
        target.stop()
        sys.exit(1)
    except BaseException:
        target.stop()
        raise
    print(f"CMDS MATRIX OK checks={matrix.checks}")


if __name__ == "__main__":
    main()
