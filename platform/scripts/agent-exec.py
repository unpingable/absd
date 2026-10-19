#!/usr/bin/env python3
"""The agent execution driver: an external agent's tool calls, each run in
the guest as one SSH `exec` session under the authority sshd already binds
to a session (docs/agent-exec-20261012/CONTRACT.md).

Nothing here adds authority or works around a missing guest mechanism. A
call is the text an agent would send; the guest decides what it may do. The
driver adds host policy only, and refuses a call before any connection when

  - the text is a machine request (`shutdown`, `reboot`) in any route, at
    any position or nesting: the guest honours one from any session
    (ssh/src/conn.rs machine_request, the shell's builtins), so the agent
    is kept from it by this driver alone;
  - the text is empty (that would open an interactive shell reading the
    call's input);
  - its declared authority (`session`, `ro`, `nofs`) is not what the text
    asks of the shell: every command must carry the declared narrowing word
    (sh/src/lib.rs `authority`), the text must route through absd-sh (an
    argv-routed `ro CMD` would run /bin/ro, not narrow), and a narrowed call
    may not use a redirection the shell would open with the session's
    authority.

Calls run one at a time (a case marked `concurrent=N` overlaps N sessions
on purpose). After each, the driver waits for sshd's next quiescent
`SERVED CAPACITY` line and keeps one receipt (JSON line): the text's digest,
declared authority, route, status, exit status, stdout/stderr digests and
byte counts, wall seconds, the call's `exec`, `SSH SESSION CHILD`,
`session child exited`, `SSH FS RELEASE` lines (sshd's worker stream, which
the boot's serial log carries), and the capacity line before and after. It
ends with

  AGENT EXEC OK calls=N sessions=S refused_host=H refused_guest=G skipped=K capacity_equal=true|false
  AGENT EXEC FAILED <reason>

`--self-test` runs the whole case file against a fake sshd (no SSH, no
QEMU) plus the policy and parser checks. Otherwise the target is
scripts/ssh_absd.py's AbsdTarget (one `net fsd` boot) and every call is
scripts/ssh-matrix.py's Client.run; scripts/run-agent-exec.sh is the host
wrapper that applies the run rules.
"""

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import threading
import time

here = pathlib.Path(__file__).resolve().parent
DEFAULT_CASES = here.parent / "docs" / "agent-exec-20261012" / "cases.tsv"

DECLARED = ("session", "ro", "nofs")
MACHINE_WORDS = ("shutdown", "reboot")
NARROWING = {"ro": "ro", "nofs": "nofs"}
# The bytes that make sshd hand an exec text to absd-sh (ssh/src/main.rs
# shell_syntax).
SHELL_SYNTAX = '|<>";&'
# Rust's split_ascii_whitespace (sshd's argv split, conn.rs machine_request):
# U+0020, U+0009, U+000A, U+000C, U+000D; not U+000B.
ASCII_WS = " \t\n\x0c\r"
# Rust's char::is_whitespace (absd-sh's lexer, sh/src/lib.rs tokenize): the
# Unicode White_Space property. Python's str.isspace() also counts
# U+001C..U+001F, which Rust does not.
RUST_WS = frozenset("\t\n\x0b\x0c\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
                    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000")
# Capacity fields that must return between calls; boot and
# accepted_reclaimed are checked apart (same boot, exact session delta).
CAPACITY_FIELDS = ("slots", "pool", "net_sockets", "net_closing", "processes", "handles", "pipes", "cells",
                   "frames", "heap_pages_peak")
CAPACITY = re.compile(
    r"^SERVED CAPACITY boot=(?P<boot>[0-9a-f]{32}) accepted_reclaimed=(?P<accepted_reclaimed>\d+) "
    r"slots=(?P<slots>\d+) pool=(?P<pool>\d+) net_sockets=(?P<net_sockets>\d+) "
    r"net_closing=(?P<net_closing>\d+) processes=(?P<processes>\d+) handles=(?P<handles>\d+) "
    r"pipes=(?P<pipes>\d+) cells=(?P<cells>\d+) frames=(?P<frames>\d+) "
    r"heap_pages_peak=(?P<heap_pages_peak>\d+)(?: link=(?P<link>up|down|unknown)(?: heap_free_pages=(?P<heap_free_pages>\d+))?)?\r?$", re.MULTILINE)
CHILD = re.compile(r"^SSH SESSION CHILD pid=(?P<pid>\d+) spawn_right=(?P<spawn_right>\w+) argv0=(?P<argv0>\S+) "
                   r"fs_slot=(?P<fs_slot>\d+) spares=\[(?P<spares>[\d, ]*)\] control=(?P<control>\w+)\r?$", re.MULTILINE)
EXEC = re.compile(r'^sshd: conn (?P<conn>\d+): exec (?P<text>".*")(?P<refused> refused: .*)?\r?$', re.MULTILINE)
RELEASE = re.compile(r"^SSH FS RELEASE slot=(?P<slot>\d+) spares=\[(?P<spares>[\d, ]*)\] closed=(?P<closed>-?\d+)\r?$",
                     re.MULTILINE)
RECLAIMED = re.compile(r"^SSH SESSION RECLAIMED children_started=\d+\r?$", re.MULTILINE)
REFUSED_CONN = re.compile(r"^SSH (?:GLOBAL|PREAUTH) REFUSED .*?\r?$", re.MULTILINE)


class Failed(Exception):
    pass


class CaseError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# -- the guest's grammars, as the host reads them ---------------------------

def shell_syntax(text):
    """ssh/src/main.rs shell_syntax: any of these routes a text to absd-sh."""
    return any(c in text for c in SHELL_SYNTAX)


def route(text):
    return "shell" if shell_syntax(text) else "argv"


def ascii_words(text):
    """Rust's split_ascii_whitespace."""
    return [w for w in re.split(f"[{re.escape(ASCII_WS)}]+", text) if w]


def tokenize(line):
    """absd-sh's lexer (sh/src/lib.rs tokenize): ('word', text) and
    ('op', op) tokens. Raises CaseError where the shell would refuse."""
    tokens, word, in_word, i = [], [], False, 0

    def end():
        nonlocal word, in_word
        if in_word:
            tokens.append(("word", "".join(word)))
            word, in_word = [], False

    while i < len(line):
        c = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else None
        if c == '"':
            in_word = True
            i += 1
            while True:
                if i >= len(line):
                    raise CaseError("unterminated quote")
                c = line[i]
                if c == '"':
                    break
                if c == "\\":
                    i += 1
                    if i >= len(line):
                        raise CaseError("unterminated quote")
                    if line[i] in '"\\':
                        word.append(line[i])
                    else:
                        word += ["\\", line[i]]
                else:
                    word.append(c)
                i += 1
        elif c == "2" and not in_word and nxt == ">":
            i += 1
            append = i + 1 < len(line) and line[i + 1] == ">"
            i += append
            tokens.append(("op", "2>>" if append else "2>"))
        elif c == "|":
            end()
            if nxt == "|":
                i += 1
                tokens.append(("op", "||"))
            else:
                tokens.append(("op", "|"))
        elif c == ";":
            end()
            tokens.append(("op", ";"))
        elif c == "&" and nxt == "&":
            end()
            i += 1
            tokens.append(("op", "&&"))
        elif c == "&":
            raise CaseError("`&` (background or duplication) is refused by absd-sh")
        elif c == "<":
            end()
            tokens.append(("op", "<"))
        elif c == ">":
            end()
            if nxt == ">":
                i += 1
                tokens.append(("op", ">>"))
            else:
                tokens.append(("op", ">"))
        elif c in RUST_WS:
            end()
        else:
            in_word = True
            word.append(c)
        i += 1
    end()
    return tokens


def commands(text):
    """The commands of a shell line: [(words, [(redirect op, path)])]."""
    out, words, redirects = [], [], []
    tokens = tokenize(text)
    i = 0
    while i < len(tokens):
        kind, value = tokens[i]
        if kind == "word":
            words.append(value)
        elif value in ("<", ">", ">>", "2>", "2>>"):
            if i + 1 >= len(tokens) or tokens[i + 1][0] != "word":
                raise CaseError(f"redirection {value} without a path")
            redirects.append((value, tokens[i + 1][1]))
            i += 1
        else:
            if not words:
                raise CaseError(f"empty command before {value}")
            out.append((words, redirects))
            words, redirects = [], []
        i += 1
    if words:
        out.append((words, redirects))
    elif redirects:
        raise CaseError("a bare redirection")
    elif tokens and tokens[-1] == ("op", ";") and out:
        pass  # absd-sh accepts a trailing `;` (sh/src/lib.rs:381-386)
    elif tokens and tokens[-1][0] == "op":
        raise CaseError(f"a line ending in `{tokens[-1][1]}`")
    return out


def machine_word(word):
    return word in MACHINE_WORDS or word.rsplit("/", 1)[-1] in MACHINE_WORDS


def machine_request(text, depth=0):
    """Whether TEXT could reach sshd as a machine request, read
    conservatively: sshd's own exec grammar (ssh/src/conn.rs
    machine_request: a first word `shutdown`/`reboot`), the shell's
    builtins (sh/src/lib.rs: `shutdown`, `reboot` sent on the session
    control channel), and the same words anywhere else, including inside a
    quoted word a nested shell would read. Over-refuses (`echo reboot`) by
    design."""
    words = ascii_words(text)
    if words and machine_word(words[0]):
        return True
    if any(machine_word(w) for w in words):
        return True
    if shell_syntax(text) and depth < 4:
        try:
            tokens = tokenize(text)
        except CaseError:
            return False  # refused as unparseable by the narrowing check
        for kind, value in tokens:
            if kind != "word":
                continue
            if machine_word(value):
                return True
            if (shell_syntax(value) or any(c in RUST_WS for c in value)) and machine_request(value, depth + 1):
                return True
    return False


def host_policy(text, declared):
    """None if the driver may send TEXT, else why it refuses (before any
    connection)."""
    if declared not in DECLARED:
        return f"declared authority {declared!r} is not one of {'/'.join(DECLARED)}"
    if not any(c not in RUST_WS for c in text):
        return "empty text: sshd would start an interactive shell reading the call's input"
    if machine_request(text):
        return "machine request (shutdown/reboot): refused by host policy; the guest would honour it from any session"
    if route(text) == "argv":
        first = ascii_words(text)[0]
        if first in NARROWING:
            return (f"`{first}` on the argv route: sshd would run /bin/{first}, not narrow the command "
                    "(quote a word to route the text through absd-sh)")
        if declared != "session":
            return f"declared {declared} but the text routes as argv, where nothing narrows the session's authority"
        return None
    try:
        parsed = commands(text)
    except CaseError as e:
        return f"absd-sh would refuse the line: {e}"
    asked = set()
    for words, redirects in parsed:
        prefix = NARROWING.get(words[0], "session")
        if prefix != "session" and len(words) < 2:
            return f"`{words[0]}` without a program"
        asked.add(prefix)
        writes = [op for op, _ in redirects if op != "<"]
        if declared == "ro" and writes:
            return "declared ro but the line writes through a redirection the shell opens with the session's authority"
        if declared == "nofs" and redirects:
            return "declared nofs but the line has a redirection the shell opens with the session's authority"
    if asked != {declared}:
        return f"declared {declared} but the commands ask for {'/'.join(sorted(asked))}"
    return None


def rust_unquote(quoted):
    """A Rust `{:?}` string (sshd's exec line) back to its text."""
    body, out, i = quoted[1:-1], [], 0
    simple = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", '"': '"', "'": "'"}
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            m = re.match(r"u\{([0-9a-fA-F]+)\}", body[i + 1:])
            if m:
                out.append(chr(int(m.group(1), 16)))
                i += 1 + m.end()
                continue
            out.append(simple.get(body[i + 1], "\\" + body[i + 1]))
            i += 2
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


def predicted_argv0(text):
    if route(text) == "shell":
        return "/bin/absd-sh"
    first = ascii_words(text)[0]
    return first if "/" in first else f"/bin/{first}"


# -- the case file ---------------------------------------------------------

class Call:
    def __init__(self, cid, declared, timeout_s, stdin, expect, text, requires, line):
        self.id, self.declared, self.timeout_s, self.stdin_spec = cid, declared, timeout_s, stdin
        self.expect, self.text, self.requires, self.line = expect, text, requires, line
        m = re.fullmatch(r"([A-Za-z]+\d+)[a-z]?", cid)
        if not m:
            raise CaseError(f"line {line}: id {cid!r} is not CASE[letter], e.g. C3 or C3b")
        self.case = m.group(1)
        self.stdin = b""

    def opt(self, key, default=None):
        for k, v in self.expect:
            if k == key:
                return v
        return default

    def has(self, key):
        return any(k == key for k, _ in self.expect)


EXPECT_KEYS = {"rc", "rc!", "stdout~", "stderr~", "stdout=stdin", "refused", "cancelled", "exited",
               "scratch_differs", "host_absent", "concurrent", "accepted", "conn_refused", "guest-refusal"}
REQUIRES = re.compile(r"^#\s*requires\s+candidate\s+(\d+)\s*$")


def parse_expect(text, line):
    """Space-separated tokens: rc=N rc!=0 stdout~RE stderr~RE
    stdout=stdin:ID refused=host-policy cancelled exited=Code(N)
    scratch_differs=ID host_absent=PATH concurrent=N accepted=N
    conn_refused=N guest-refusal (`-` for none)."""
    out = []
    if text == "-":
        return out
    for token in text.split(" "):
        if not token:
            continue
        m = re.fullmatch(r"(rc!|rc|stdout~|stderr~|stdout=stdin|refused|exited|scratch_differs|host_absent|"
                         r"concurrent|accepted|conn_refused)(?:(?<=~)|[=:])(.+)", token)
        if token in ("cancelled", "guest-refusal"):
            out.append((token, True))
        elif m:
            key, value = m.group(1), m.group(2)
            if key in ("rc", "rc!", "concurrent", "accepted", "conn_refused") and not value.isdigit():
                raise CaseError(f"line {line}: {key} needs a number in {token!r}")
            if key == "refused" and value != "host-policy":
                raise CaseError(f"line {line}: refused= takes only host-policy")
            if key in ("stdout~", "stderr~"):
                try:
                    re.compile(value)
                except re.error as e:
                    raise CaseError(f"line {line}: bad regex {value!r}: {e}")
            out.append((key, value))
        else:
            raise CaseError(f"line {line}: unknown expectation {token!r}")
    return out


def load_cases(path, text=None):
    """The case file: tab-separated `id declared timeout_s stdin expect
    text`; `#` lines are comments, and `# requires candidate N` gates
    every row after it up to the next blank line."""
    path = pathlib.Path(path)
    if text is None:
        text = path.read_text()
    calls, requires, seen = [], None, set()
    for n, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            requires = None
            continue
        if raw.startswith("#"):
            m = REQUIRES.match(raw)
            if m:
                requires = int(m.group(1))
            continue
        cols = raw.split("\t")
        if len(cols) != 6:
            raise CaseError(f"line {n}: {len(cols)} tab-separated columns, want 6 (id declared timeout_s stdin expect text)")
        cid, declared, timeout_s, stdin, expect, body = cols
        if cid in seen:
            raise CaseError(f"line {n}: duplicate id {cid}")
        seen.add(cid)
        if declared not in DECLARED:
            raise CaseError(f"line {n}: declared {declared!r} is not one of {'/'.join(DECLARED)}")
        if not re.fullmatch(r"\d+", timeout_s) or not 1 <= int(timeout_s) <= 3600:
            raise CaseError(f"line {n}: timeout_s {timeout_s!r} is not 1..3600")
        call = Call(cid, declared, int(timeout_s), stdin, parse_expect(expect, n), body, requires, n)
        if stdin != "-":
            if not stdin.startswith("@"):
                raise CaseError(f"line {n}: stdin is - or @FILE (relative to the case file)")
            src = (path.parent / stdin[1:]).resolve()
            if path.parent.resolve() not in src.parents:
                raise CaseError(f"line {n}: stdin file {stdin} is outside the case file's directory")
            call.stdin = src.read_bytes()
        calls.append(call)
    ids = {c.id for c in calls}
    for c in calls:
        for key in ("stdout=stdin", "scratch_differs"):
            ref = c.opt(key)
            if ref is not None and ref not in ids:
                raise CaseError(f"line {c.line}: {key} names unknown call {ref}")
        if c.has("concurrent") and (not c.has("accepted") or not c.has("conn_refused")):
            raise CaseError(f"line {c.line}: concurrent= needs accepted= and conn_refused=")
    return calls


# -- the run ---------------------------------------------------------------

def capacity(text):
    m = None
    for m in CAPACITY.finditer(text):
        pass
    if m is None:
        return None
    return {k: v if v is None or k in ("boot", "link") else int(v) for k, v in m.groupdict().items()}


def capacity_diff(base, sample):
    if base is None or sample is None:
        return ["missing"]
    diff = [f"{f} {base[f]}->{sample[f]}" for f in CAPACITY_FIELDS if base[f] != sample[f]]
    if base["boot"] != sample["boot"]:
        diff.append("boot changed")
    return diff


def wait_for(predicate, timeout, step=0.2):
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value or time.monotonic() >= deadline:
            return value
        time.sleep(step)


class Runner:
    def __init__(self, transport, calls, receipts, candidate=0, baseline="first", out=print, settle_timeout=120):
        self.t = transport
        self.calls = calls
        self.receipts = pathlib.Path(receipts)
        self.candidate = candidate
        self.baseline_mode = baseline
        self.out = out
        self.settle_timeout = settle_timeout
        self.by_id = {}
        self.base = None

    def plan(self):
        """Every decision the driver makes before connecting, checked
        against the case file before anything boots or connects."""
        problems = []
        for c in self.calls:
            reason = host_policy(c.text, c.declared)
            if (reason is not None) != c.has("refused"):
                problems.append(f"{c.id}: host policy {'refuses' if reason else 'admits'} "
                                f"({reason or route(c.text)}) but the case expects {'a refusal' if c.has('refused') else 'a run'}")
        if problems:
            raise Failed("case file disagrees with host policy: " + "; ".join(problems))

    def record(self, receipt):
        with open(self.receipts, "a") as f:
            f.write(json.dumps(receipt, sort_keys=True) + "\n")

    def run(self):
        self.receipts.parent.mkdir(parents=True, exist_ok=True)
        self.receipts.write_text("")
        self.plan()
        start = wait_for(lambda: capacity(self.t.worker()), self.settle_timeout)
        if start is None:
            raise Failed("no quiescent SERVED CAPACITY line before the first call")
        if self.baseline_mode == "first":
            self.base = start
        cases, sessions, refused_host, refused_guest, skipped = set(), 0, 0, 0, set()
        capacity_equal = True
        failures = []
        for c in self.calls:
            if c.requires and c.requires != self.candidate:
                skipped.add(c.case)
                self.record({"id": c.id, "case": c.case, "status": "skipped",
                             "reason": f"requires candidate {c.requires}"})
                self.out(f"AGENT CALL {c.id} skipped (requires candidate {c.requires})")
                continue
            cases.add(c.case)
            receipt = self.call(c)
            self.by_id[c.id] = receipt
            if self.base is None and receipt.get("capacity_after"):
                self.base = receipt["capacity_after"]
                receipt["baseline"] = "this call's after-capacity is the baseline"
            receipt.setdefault("checks_failed", [])
            receipt["checks_failed"] += self.check(c, receipt)
            sessions += receipt.get("sessions", 0)
            refused_host += receipt["status"] == "refused-host"
            refused_guest += bool(receipt.get("guest_refused"))
            if receipt["status"] not in ("refused-host",) and receipt.get("capacity_after") is not None:
                receipt["capacity_diff"] = capacity_diff(self.base, receipt["capacity_after"])
                receipt["capacity_equal"] = not receipt["capacity_diff"]
                if not c.has("concurrent") and "baseline" not in receipt:
                    capacity_equal &= receipt["capacity_equal"]
            self.record(receipt)
            verdict = "ok" if not receipt["checks_failed"] else "FAILED"
            self.out(f"AGENT CALL {c.id} {verdict} status={receipt['status']} route={receipt.get('route', '-')} "
                     f"rc={receipt.get('rc')} capacity_equal={str(receipt.get('capacity_equal', '-')).lower()}"
                     + (f" :: {'; '.join(receipt['checks_failed'])}" if receipt["checks_failed"] else ""))
            if receipt["checks_failed"]:
                failures.append(f"{c.id}: {'; '.join(receipt['checks_failed'])}")
        skipped -= cases
        if self.t.machine_requests_seen():
            failures.append(f"a machine request reached the transport: {self.t.machine_requests_seen()}")
        if failures:
            summary = f"AGENT EXEC FAILED {failures[0]}" + (f" (+{len(failures) - 1} more)" if len(failures) > 1 else "")
        else:
            summary = (f"AGENT EXEC OK calls={len(cases)} sessions={sessions} refused_host={refused_host} "
                       f"refused_guest={refused_guest} skipped={len(skipped)} capacity_equal={str(capacity_equal).lower()}")
        self.record({"summary": summary})
        return summary, not failures

    # One call (or one concurrent group) ------------------------------------

    def call(self, c):
        receipt = {"id": c.id, "case": c.case, "text_sha256": sha256(c.text.encode()), "declared": c.declared,
                   "stdin_sha256": sha256(c.stdin), "stdin_bytes": len(c.stdin)}
        reason = host_policy(c.text, c.declared)
        if reason is not None:
            receipt.update(status="refused-host", refused="host-policy", reason=reason, sessions=0,
                           capacity_before=capacity(self.t.worker()))
            receipt["capacity_after"] = receipt["capacity_before"]
            return receipt
        receipt["route"] = route(c.text)
        worker0, serial0 = len(self.t.worker()), len(self.t.serial())
        before = capacity(self.t.worker())
        count0 = len(CAPACITY.findall(self.t.worker()))
        started = time.monotonic()
        if c.has("concurrent"):
            members = self.concurrent(c, worker0)
            accepted = sum(1 for m in members if m["rc"] != 255)
            receipt.update(status="ran", members=members, sessions=accepted, rc=None)
        else:
            rc, out, err, timed_out = self.t.run(c.text, c.stdin, c.timeout_s)
            accepted = 1
            receipt.update(status="cancelled" if timed_out else "ran", rc=rc, sessions=1,
                           stdout_sha256=sha256(out), stdout_bytes=len(out),
                           stderr_sha256=sha256(err), stderr_bytes=len(err))
            receipt["_out"], receipt["_err"] = out, err
        # sshd reports capacity only once quiescent: every session of the
        # call reclaimed and its slot released.
        settled = wait_for(lambda: len(CAPACITY.findall(self.t.worker())) > count0
                           and (capacity(self.t.worker()) or {}).get("accepted_reclaimed", -1)
                           >= (before or {}).get("accepted_reclaimed", 0) + accepted, self.settle_timeout)
        receipt["wall_s"] = round(time.monotonic() - started, 3)
        window = self.t.worker()[worker0:]
        receipt["serial_window"] = {"worker_from": worker0, "serial_from": serial0}
        receipt["capacity_before"] = before
        receipt["capacity_after"] = capacity(self.t.worker()) if settled else None
        receipt["lines"] = self.lines(window, self.t.serial()[serial0:])
        if not settled:
            receipt["checks_failed"] = [f"no new quiescent SERVED CAPACITY within {self.settle_timeout}s"]
        return receipt

    def concurrent(self, c, worker0):
        """N overlapped sessions: each started once the previous one's
        child is running (so at most one connection is unauthenticated at
        a time, below the per-source pre-auth limit); the one past the
        connection limit must be refused at the transport."""
        n = int(c.opt("concurrent"))
        results = [None] * n
        threads = []

        def one(i):
            rc, out, err, timed_out = self.t.run(c.text, c.stdin, c.timeout_s)
            results[i] = {"rc": rc, "timed_out": timed_out, "stdout_sha256": sha256(out), "stdout_bytes": len(out),
                          "stderr_sha256": sha256(err), "stderr_bytes": len(err), "_out": out, "_err": err}

        for i in range(n):
            children = len(CHILD.findall(self.t.worker()[worker0:]))
            refusals = len(REFUSED_CONN.findall(self.t.worker()[worker0:]))
            th = threading.Thread(target=one, args=(i,), daemon=True)
            th.start()
            threads.append(th)
            # Wait for this session's child, or for its refusal (or its end).
            wait_for(lambda: len(CHILD.findall(self.t.worker()[worker0:])) > children
                     or len(REFUSED_CONN.findall(self.t.worker()[worker0:])) > refusals
                     or not th.is_alive(), c.timeout_s)
        for th in threads:
            th.join(c.timeout_s + 30)
        return [r if r is not None else {"rc": None, "timed_out": True, "_out": b"", "_err": b""} for r in results]

    @staticmethod
    def lines(window, serial):
        found = {
            "exec": [m.group(0).rstrip("\r") for m in EXEC.finditer(window)],
            "child": [m.group(0).rstrip("\r") for m in CHILD.finditer(window)],
            "exited": re.findall(r"(?m)^sshd: conn \d+: session child exited: .*?(?=\r?$)", window),
            "end": re.findall(r"(?m)^sshd: conn \d+: end: .*?(?=\r?$)", window),
            "fs_release": [m.group(0).rstrip("\r") for m in RELEASE.finditer(window)],
            "reclaimed": [m.group(0).rstrip("\r") for m in RECLAIMED.finditer(window)],
            "conn_refused": [m.group(0).rstrip("\r") for m in REFUSED_CONN.finditer(window)],
            "kernel_ended": re.findall(r"(?m)^USER (?:EXIT|KILLED|FAULT) pid=\d+.*?(?=\r?$)", serial),
        }
        return found

    # Expectations ----------------------------------------------------------

    def check(self, c, r):
        bad = []
        if r["status"] == "refused-host":
            if not c.has("refused"):
                bad.append(f"refused by host policy: {r['reason']}")
            return bad
        if c.has("refused"):
            bad.append("expected a host-policy refusal, but the call ran")
        lines = r["lines"]
        if c.has("concurrent"):
            return bad + self.check_group(c, r)
        out, err = r.pop("_out"), r.pop("_err")
        # Every call: one exec line for this text, one child of the predicted
        # route and shape, and the slot that child held released.
        execs = [m for m in EXEC.finditer("\n".join(lines["exec"]))]
        if len(execs) != 1 or execs[0].group("refused"):
            bad.append(f"want one accepted exec line, got {lines['exec']}")
        elif rust_unquote(execs[0].group("text")) != c.text:
            bad.append(f"exec line names {execs[0].group('text')}, not the call's text")
        children = list(CHILD.finditer("\n".join(lines["child"])))
        if len(children) != 1:
            bad.append(f"want one SSH SESSION CHILD line, got {lines['child']}")
        else:
            ch = children[0].groupdict()
            r["child_pid"] = int(ch["pid"])
            shell = r["route"] == "shell"
            want = {"argv0": predicted_argv0(c.text), "spawn_right": str(shell).lower(), "control": str(shell).lower()}
            for k, v in want.items():
                if ch[k] != v:
                    bad.append(f"child {k}={ch[k]}, the {r['route']} route gives {v}")
            if not shell and ch["spares"].strip():
                bad.append(f"an argv child holds spares [{ch['spares']}]")
            releases = [m.groupdict() for m in RELEASE.finditer("\n".join(lines["fs_release"]))]
            if [x["slot"] for x in releases] != [ch["fs_slot"]]:
                bad.append(f"want SSH FS RELEASE of slot {ch['fs_slot']}, got {lines['fs_release']}")
        if c.has("cancelled"):
            if r["status"] != "cancelled":
                bad.append(f"expected the host to cancel at {c.timeout_s}s; the call ended rc={r['rc']}")
            elif "child_pid" in r and not any(re.match(rf"USER KILLED pid={r['child_pid']}\b", x)
                                                for x in lines["kernel_ended"]):
                bad.append(f"no USER KILLED pid={r['child_pid']} on the serial log: {lines['kernel_ended']}")
            return bad
        if r["status"] == "cancelled":
            bad.append(f"timed out after {c.timeout_s}s")
            return bad
        if len(lines["exited"]) != 1:
            bad.append(f"want one `session child exited` line, got {lines['exited']}")
        want_exit = c.opt("exited")
        if want_exit and not (lines["exited"] and lines["exited"][0].endswith(f"exited: {want_exit}")):
            bad.append(f"want exited: {want_exit}, got {lines['exited']}")
        rc = c.opt("rc")
        if rc is not None and r["rc"] != int(rc):
            bad.append(f"rc={r['rc']} want {rc} (stderr {err[-200:]!r})")
        rc_not = c.opt("rc!")
        if rc_not is not None and r["rc"] in (int(rc_not), 255, None):
            bad.append(f"rc={r['rc']} want a guest status other than {rc_not} (255 is the client's own failure)")
        if c.has("guest-refusal"):
            r["guest_refused"] = rc_not is not None and r["rc"] not in (int(rc_not), 255, None)
        for key, data in (("stdout~", out), ("stderr~", err)):
            pattern = c.opt(key)
            if pattern is not None and not re.search(pattern, data.decode(errors="replace")):
                bad.append(f"{key[:-1]} {data[:200]!r} does not match {pattern!r}")
        ref = c.opt("stdout=stdin")
        if ref is not None:
            source = next(x for x in self.calls if x.id == ref)
            if out != source.stdin:
                bad.append(f"stdout ({len(out)} B) is not {ref}'s input ({len(source.stdin)} B)")
        ref = c.opt("scratch_differs")
        if ref is not None:
            mine = re.fullmatch(rb"session-(\d+)/\n", out)
            theirs = self.by_id.get(ref, {}).get("scratch")
            r["scratch"] = mine.group(1).decode() if mine else None
            if not mine or theirs is None or r["scratch"] == theirs:
                bad.append(f"scratch {r['scratch']} vs {ref}'s {theirs}: want two different session-<id>")
        elif re.fullmatch(rb"session-(\d+)/\n", out):
            r["scratch"] = re.fullmatch(rb"session-(\d+)/\n", out).group(1).decode()
        path = c.opt("host_absent")
        if path is not None:
            absent = self.t.absent(path)
            r["host_absent"] = {path: absent}
            if not absent:
                bad.append(f"the host reader finds {path} on the image")
        return bad

    def check_group(self, c, r):
        bad = []
        members = r["members"]
        accepted = [m for m in members if m["rc"] != 255]
        refused = [m for m in members if m["rc"] == 255]
        if len(accepted) != int(c.opt("accepted")) or len(refused) != int(c.opt("conn_refused")):
            bad.append(f"accepted={len(accepted)} refused={len(refused)}, want {c.opt('accepted')}/{c.opt('conn_refused')}")
        if len(r["lines"]["conn_refused"]) < int(c.opt("conn_refused")):
            bad.append(f"want {c.opt('conn_refused')} SSH GLOBAL/PREAUTH REFUSED lines, got {r['lines']['conn_refused']}")
        if len(r["lines"]["child"]) != len(accepted) or len(r["lines"]["fs_release"]) != len(accepted):
            bad.append(f"children={len(r['lines']['child'])} releases={len(r['lines']['fs_release'])}, want {len(accepted)} each")
        rc = c.opt("rc")
        pattern = c.opt("stdout~")
        for i, m in enumerate(members):
            out, err = m.pop("_out"), m.pop("_err")
            if m["rc"] == 255:
                continue
            if rc is not None and m["rc"] != int(rc):
                bad.append(f"member {i}: rc={m['rc']} want {rc}")
            if pattern is not None and not re.search(pattern, out.decode(errors="replace")):
                bad.append(f"member {i}: stdout {out[:100]!r} does not match {pattern!r}")
        return bad


# -- the real transport ----------------------------------------------------

def guard(text):
    """The transport's own refusal, independent of the runner: no machine
    request and no empty text ever leaves the host."""
    if not any(c not in RUST_WS for c in text) or machine_request(text):
        raise Failed(f"transport refuses {text!r}: a machine request or an empty text")


class SshTransport:
    """One call = one Client.run (one ssh process, one exec session)."""

    def __init__(self, target, client, key, absd_fs):
        self.target, self.client, self.key, self.absd_fs = target, client, key, absd_fs
        self.sent = []

    def worker(self):
        return self.target.output()

    def serial(self):
        try:
            return self.target.serial()
        except FileNotFoundError:
            return ""

    def run(self, text, stdin, timeout):
        guard(text)
        self.sent.append(text)
        try:
            rc, out, err = self.client.run(self.key, text, stdin=stdin, timeout=timeout)
            return rc, out, err, False
        except subprocess.TimeoutExpired as e:
            # subprocess.run killed the client: the connection drops.
            return None, e.stdout or b"", e.stderr or b"", True

    def absent(self, path):
        """Whether the host's own reader finds no object at PATH (file or
        directory), retrying while the guest is mid-commit."""
        import ssh_absd
        physical = self.target.physical(path)
        for _ in range(20):
            try:
                region = self.absd_fs.fs_region(self.target.image, ssh_absd.DEVICE_SECTORS)
                selected = self.absd_fs.select(region)
                return physical not in self.absd_fs.tree(region, selected)
            except self.absd_fs.Refused:
                time.sleep(0.5)
        raise Failed("the host reader never found a committed image")

    def machine_requests_seen(self):
        return [t for t in self.sent if machine_request(t)]


def stop_on_signals(target):
    """N6: a SIGTERM, SIGINT or SIGHUP to the driver stops its QEMU. A
    SIGKILL cannot be caught; durable-boot's timeout (--boot-seconds)
    bounds QEMU then."""
    import signal

    def handler(signum, frame):
        target.stop()
        sys.exit(128 + signum)
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, handler)


def real_main(args, calls):
    sys.path.insert(0, str(here))
    import absd_fs
    import ssh_absd
    spec = importlib.util.spec_from_file_location("ssh_matrix", here / "ssh-matrix.py")
    sm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sm)
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    for stale in (work / "id_agent", work / "id_agent.pub"):
        stale.unlink(missing_ok=True)
    key = sm.keygen(work / "id_agent")
    target = ssh_absd.target(["--kernel", args.kernel, "--platform", args.platform, "--shell", args.shell,
                              "--qemu", args.qemu, "--boot-seconds", str(args.boot_seconds)])
    stop_on_signals(target)
    try:
        runner = Runner(None, calls, args.receipts or work / "receipts.jsonl", args.candidate, args.baseline)
        runner.plan()  # before anything boots
        target.setup(work, key.with_suffix(".pub").read_text())
        first = target.start(fresh=True)
        client = sm.Client(work, target.port)
        client.trust(first["public"])
        runner.t = SshTransport(target, client, key, absd_fs)
        import agent_warm
        # The adapter is restricted to the canonical fixed cases, not job files.
        try:
            return agent_warm.Rehearsal(sys.modules[__name__], runner).run()
        except agent_warm.wb.BaselineError as e:
            print('AGENT WARM coverage=NOT_ESTABLISHED reason=' + str(e))
            raise Failed(str(e)) from e
    finally:
        target.stop()


# -- self-test: a fake sshd ------------------------------------------------

class FakeSshd:
    """An in-process stand-in for the guest, enough to drive the runner:
    the worker lines sshd writes, a capacity census, a tiny filesystem, and
    a 4-connection limit. Faults: `leak` (one heap page per session),
    `ro_writes` (ro mkdir succeeds)."""

    BOOT = "0123456789abcdef0123456789abcdef"

    def __init__(self, leak=False, ro_writes=False, scale=1 / 60000):
        self.lock = threading.Lock()
        self.w, self.s = [], []
        self.conn = self.attempted = self.reclaimed = self.active = 0
        self.pid = 20
        self.heap = 100
        self.leak, self.ro_writes, self.scale = leak, ro_writes, scale
        self.files = {"/share/man/whatis": b"uname(1) - name\n"}
        self.dirs = {"/home/operator", "/share/man", "/bin"}
        self.sent = []
        self.machine = []
        self.census()

    def say(self, line):
        self.w.append(line + "\n")

    def census(self):
        self.say(f"SERVED CAPACITY boot={self.BOOT} accepted_reclaimed={self.reclaimed} slots=0 pool=0 net_sockets=1 "
                 f"net_closing=0 processes=4 handles=40 pipes=20 cells=6 frames=900 heap_pages_peak={self.heap} link=up")

    def worker(self):
        with self.lock:
            return "".join(self.w)

    def serial(self):
        with self.lock:
            return "".join(self.s)

    def machine_requests_seen(self):
        return self.machine

    def absent(self, path):
        return path not in self.files and path not in self.dirs

    def behave(self, text, stdin, sid):
        """(rc, stdout, stderr, sleep_ms) for a text the case file uses."""
        words = text.split()
        arg = words[-1].strip('"') if words else ""
        if text == "uname":
            return 0, b"ABSD 0.4.0 x86_64\n", b"", 0
        if text == "ls /share/man":
            return 0, b"cat1/\nwhatis\n", b"", 0
        if text == "ls /tmp":
            return 0, f"session-{sid}/\n".encode(), b"", 0
        if text == "ls /home/operator/agent":
            names = sorted(p.rsplit("/", 1)[1] for p in self.files if p.startswith("/home/operator/agent/"))
            return 0, "".join(n + "\n" for n in names).encode(), b"", 0
        if words[:1] == ["mkdir"] or words[:2] == ["ro", "mkdir"]:
            if words[0] == "ro" and not self.ro_writes:
                return 1, b"", f"mkdir: {arg}: read-only file system\n".encode(), 0
            if arg.startswith("/bin/"):
                return 1, b"", f"mkdir: {arg}: read-only file system\n".encode(), 0
            self.dirs.add(arg)
            return 0, b"", b"", 0
        if text.startswith("cat > "):
            self.files[arg] = stdin
            return 0, b"", b"", 0
        if words[:2] == ["ro", "cat"]:
            return (0, self.files[arg], b"", 0) if arg in self.files else (1, b"", b"cat: not found\n", 0)
        if words[:2] == ["nofs", "cat"]:
            return 1, b"", b"cat: no filesystem\n", 0
        if words[:2] == ["/bin/sshtest", "exit"]:
            return int(words[2]), b"", b"", 0
        if words[:2] == ["/bin/sshtest", "sleep"]:
            return 0, b"slept\n", b"", int(words[2])
        if words[:1] == ['"/bin/tcc"']:
            self.files["/home/operator/agent/t"] = b"\x7fELF"
            return 0, b"agent-exec tcc ok\n", b"", 0
        return 127, b"", f"absd-sh: {words[0]}: not found\n".encode(), 0

    def run(self, text, stdin, timeout):
        with self.lock:
            self.sent.append(text)
            if machine_request(text):
                self.machine.append(text)
            if self.active >= 4:
                self.w.append("SSH GLOBAL REFUSED source=Some(127.0.0.1) limit=4 slots=4 pool=4\n")
                return 255, b"", b"Connection closed by 127.0.0.1 port 2222\r\n", False
            self.active += 1
            self.conn += 1
            self.attempted += 1
            self.pid += 1
            conn, sid, pid = self.conn, self.attempted, self.pid
            shell = shell_syntax(text)
            argv0 = predicted_argv0(text)
            slot = 1 + (sid % 10)
            spares = f"[{slot % 10 + 1}, {(slot + 1) % 10 + 1}]" if shell else "[]"
            self.say(f"sshd: conn {conn}: from 127.0.0.1:5000{conn}")
            self.say(f"SSH SESSION CHILD pid={pid} spawn_right={str(shell).lower()} argv0={argv0} fs_slot={slot} "
                     f"spares={spares} control={str(shell).lower()}")
            self.say(f"sshd: conn {conn}: exec {json.dumps(text)}")
            self.s.append(f"SPAWN OK pid={pid} parent=3 program=image\n")
            rc, out, err, sleep_ms = self.behave(text, stdin, sid)
        cancelled = sleep_ms / 1000 > timeout
        time.sleep(min(sleep_ms * self.scale, 2))
        with self.lock:
            if cancelled:
                self.say(f"sshd: conn {conn}: end: client gone")
                self.s.append(f"USER KILLED pid={pid} by=3\n")
            else:
                self.say(f"sshd: conn {conn}: session child exited: Code({rc})")
                self.s.append(f"USER EXIT pid={pid} status={rc}\n")
            self.say(f"SSH FS RELEASE slot={slot} spares={spares} closed=0")
            self.say("SSH SESSION RECLAIMED children_started=0")
            self.reclaimed += 1
            self.active -= 1
            self.heap += self.leak
            if self.active == 0:
                self.census()
        if cancelled:
            return None, b"", b"", True
        return rc, out, err, False


POLICY_TABLE = [
    # (text, declared, refused?)
    ("uname", "session", False),
    ("ls /share/man", "session", False),
    ("reboot", "session", True),
    (" shutdown now ", "session", True),
    ("shutdown -r now", "session", True),
    ("shutdown +5", "session", True),
    ('echo a; reboot', "session", True),
    ('"reboot"', "session", True),
    ("ls | shutdown", "session", True),
    ('absd-sh -c "ls; reboot"', "session", True),
    ("/bin/reboot", "session", True),
    ("echo reboot", "session", True),
    ("", "session", True),
    ("   ", "session", True),
    ("shutdownx", "session", False),
    ('ro cat "/home/operator/agent/in.txt"', "ro", False),
    ("ro cat /home/operator/agent/in.txt", "ro", True),
    ('nofs cat "/share/man/whatis"', "nofs", False),
    ('ro cat "/x"', "session", True),
    ('cat "/x"', "ro", True),
    ('ls | ro cat', "ro", True),
    ('ro ls | ro cat', "ro", False),
    ('ro ls > "/home/operator/y"', "ro", True),
    ('ro cat < "/x"', "ro", False),
    ('nofs cat < "/x"', "nofs", True),
    ('nofs sshtest exit 0 | nofs cat', "nofs", False),
    ('ro', "ro", True),
    ('"ro"', "ro", True),
    ('ro "nofs"', "ro", False),
    ('cat "/x', "session", True),
    ("sleep 1 &", "session", True),
    ("mkdir /x;", "session", False),
    ('mkdir "/x" ;', "session", False),
    ("mkdir /x &&", "session", True),
    ("mkdir /x ||", "session", True),
    ("ls |", "session", True),
    ("ls ; ;", "session", True),
    ('ro\x1ccat "/x"', "ro", True),
    ('ro\x1ccat "/x"', "session", False),
    ("\x0bro cat /x", "session", False),
    ('ro\u2003cat "/x"', "ro", False),
    ("/bin/sshtest exit 3", "session", False),
    ("mkdir /bin/x", "session", False),
    ("mkdir /bin/x", "ro", True),
    ('cat > "/home/operator/agent/in.txt"', "session", False),
    ("ls /tmp", "admin", True),
]

PARSE_BAD = [
    ("C1\tsession\t60\t-\trc=0", "columns"),
    ("C1\tadmin\t60\t-\trc=0\tuname", "declared"),
    ("C1\tsession\t0\t-\trc=0\tuname", "timeout_s"),
    ("C1\tsession\t60\t-\trc=zero\tuname", "number"),
    ("C1\tsession\t60\t-\tbogus=1\tuname", "unknown expectation"),
    ("C1\tsession\t60\t-\trefused=yes\tuname", "host-policy"),
    ("C1\tsession\t60\tin.txt\trc=0\tuname", "stdin"),
    ("C1\tsession\t60\t@../../etc/passwd\trc=0\tuname", "outside"),
    ("C1\tsession\t60\t-\tstdout=stdin:C9\tuname", "unknown call"),
    ("C1\tsession\t60\t-\trc=0\tuname\nC1\tsession\t60\t-\trc=0\tuname", "duplicate"),
    ("1x\tsession\t60\t-\trc=0\tuname", "CASE"),
    ("C1\tsession\t60\t-\tconcurrent=5\tuname", "accepted="),
    ("C1\tsession\t60\t-\tstdout~(\tuname", "bad regex"),
]


def self_test(cases_path, scratch):
    checks = 0

    def ok(name, cond, detail=""):
        nonlocal checks
        checks += 1
        print(f"  {'ok  ' if cond else 'FAIL'} {name}{(': ' + str(detail)) if detail and not cond else ''}", flush=True)
        if not cond:
            raise Failed(f"self-test: {name}: {detail}")

    for text, declared, refused in POLICY_TABLE:
        reason = host_policy(text, declared)
        ok(f"policy {'refuses' if refused else 'admits'} {declared} {text!r}", (reason is not None) == refused, reason)
    ok("route: no shell syntax is argv", route("ls /share/man") == "argv" and predicted_argv0("ls /x") == "/bin/ls")
    ok("route: a quoted word goes to absd-sh", route('ro cat "/x"') == "shell" and predicted_argv0('ro cat "/x"') == "/bin/absd-sh")
    ok("lexer: quotes and operators", tokenize('a "b c" | d 2>> e && f; g < h > i') == [
        ("word", "a"), ("word", "b c"), ("op", "|"), ("word", "d"), ("op", "2>>"), ("word", "e"), ("op", "&&"),
        ("word", "f"), ("op", ";"), ("word", "g"), ("op", "<"), ("word", "h"), ("op", ">"), ("word", "i")])
    ok("lexer: U+001C..U+001F are not whitespace to absd-sh (Rust char::is_whitespace)",
       tokenize("a\x1cb\x1d\x1e\x1fc d") == [("word", "a\x1cb\x1d\x1e\x1fc"), ("word", "d")])
    ok("lexer: U+00A0, U+2003 and U+000B are whitespace to absd-sh",
       tokenize("a\xa0b\u2003c\x0bd") == [("word", "a"), ("word", "b"), ("word", "c"), ("word", "d")])
    ok("argv split: U+000B is not ASCII whitespace to Rust", ascii_words("a\x0bb c") == ["a\x0bb", "c"])
    ok("a trailing `;` is one command, as absd-sh parses it", commands("mkdir /x;") == [(["mkdir", "/x"], [])])

    class Client:
        def __init__(self):
            self.calls = []

        def run(self, key, text, stdin=b"", timeout=120):
            self.calls.append(text)
            return 0, b"", b""

    client = Client()
    transport = SshTransport(None, client, "key", None)
    for text in ("reboot", "echo a; shutdown now", "", "  "):
        try:
            transport.run(text, b"", 5)
            ok(f"SshTransport refuses {text!r} itself", False, "sent")
        except Failed:
            ok(f"SshTransport refuses {text!r} itself", client.calls == [])
    transport.run("uname", b"", 5)
    ok("SshTransport sends an admitted text once and records it",
       client.calls == ["uname"] and transport.sent == ["uname"] and transport.machine_requests_seen() == [])
    ok("lexer: escaped quote inside quotes", tokenize(r'"a\"b\\c\d"') == [("word", 'a"b\\c\\d')])
    for body, needle in PARSE_BAD:
        try:
            load_cases(pathlib.Path(cases_path), text=body + "\n")
            ok(f"case parser refuses ({needle})", False, "accepted")
        except CaseError as e:
            ok(f"case parser refuses ({needle})", needle in str(e), str(e))
    gated = load_cases(pathlib.Path(cases_path), text="C1\tsession\t60\t-\trc=0\tuname\n# requires candidate 2\n"
                       "C2\tsession\t60\t-\trc=0\tuname\nC2b\tsession\t60\t-\trc=0\tuname\n\nC3\tsession\t60\t-\trc=0\tuname\n")
    ok("`# requires candidate 2` gates the rows up to the next blank line",
       [c.requires for c in gated] == [None, 2, 2, None])

    calls = load_cases(cases_path)
    ok("the case file has 12 cases", len({c.case for c in calls}) == 12, sorted({c.case for c in calls}))
    ok("C12 alone requires candidate 2", {c.case for c in calls if c.requires == 2} == {"C12"})
    ok("C10 is the host-policy refusal", [c.id for c in calls if c.has("refused")] == ["C10"])

    def run(name, fake, candidate=0, baseline="first"):
        receipts = scratch / f"{name}.jsonl"
        lines = []
        summary, good = Runner(fake, calls, receipts, candidate, baseline, out=lines.append, settle_timeout=5).run()
        rows = [json.loads(x) for x in receipts.read_text().splitlines()]
        return summary, good, rows, lines

    fake0 = FakeSshd()
    summary, good, rows, lines = run("default", fake0)
    for line in lines:
        print("    " + line)
    print("    " + summary)
    ok("fake run: AGENT EXEC OK, C12 skipped", good and summary ==
       "AGENT EXEC OK calls=11 sessions=16 refused_host=1 refused_guest=3 skipped=1 capacity_equal=true", summary)
    by = {r.get("id"): r for r in rows}
    ok("a receipt per call plus the summary", len(rows) == len(calls) + 1 and rows[-1] == {"summary": summary})
    r = by["C1"]
    ok("receipt fields: digests, byte counts, route, status",
       r["stdout_sha256"] == sha256(b"ABSD 0.4.0 x86_64\n") and r["stdout_bytes"] == 18 and r["stderr_bytes"] == 0
       and r["route"] == "argv" and r["status"] == "ran" and r["text_sha256"] == sha256(b"uname"), r)
    ok("receipt lines: exec, CHILD, exited, FS RELEASE",
       r["lines"]["exec"] == ['sshd: conn 1: exec "uname"'] and "spawn_right=false argv0=/bin/uname" in r["lines"]["child"][0]
       and r["lines"]["exited"] == ["sshd: conn 1: session child exited: Code(0)"]
       and r["lines"]["fs_release"][0].startswith("SSH FS RELEASE slot="), r["lines"])
    ok("capacity before/after recorded and equal", r["capacity_before"]["accepted_reclaimed"] == 0
       and r["capacity_after"]["accepted_reclaimed"] == 1 and r["capacity_equal"] is True)
    ok("C3c: ro narrowing runs through absd-sh with control", by["C3c"]["route"] == "shell"
       and "argv0=/bin/absd-sh" in by["C3c"]["lines"]["child"][0] and "control=true" in by["C3c"]["lines"]["child"][0])
    ok("C10: refused before any connection, no session", by["C10"]["status"] == "refused-host"
       and by["C10"]["sessions"] == 0 and fake0.machine == [] and "reboot" not in fake0.sent)
    ok("C8: cancelled, USER KILLED of its child", by["C8"]["status"] == "cancelled"
       and any(x.startswith(f"USER KILLED pid={by['C8']['child_pid']}") for x in by["C8"]["lines"]["kernel_ended"]))
    ok("C11: 4 accepted, 1 refused at the transport", by["C11"]["sessions"] == 4
       and len(by["C11"]["lines"]["conn_refused"]) == 1 and [m["rc"] for m in by["C11"]["members"]].count(255) == 1)
    ok("C7: two different scratch directories", by["C7a"]["scratch"] != by["C7b"]["scratch"])
    ok("C12 receipt says skipped", by["C12a"]["status"] == "skipped")

    fake = FakeSshd()
    summary, good, rows, _ = run("candidate2", fake, candidate=2)
    ok("with candidate 2 the tcc case runs: calls=12", good and "calls=12 " in summary and "skipped=0" in summary, summary)
    ok("no machine request ever reached the transport", fake.machine == [] and all("reboot" not in t for t in fake.sent))

    summary, good, rows, _ = run("leak", FakeSshd(leak=True))
    ok("a heap page per call: OK but capacity_equal=false", good and summary.endswith("capacity_equal=false"), summary)
    summary, good, rows, _ = run("leak-after-first", FakeSshd(leak=True), baseline="after-first")
    ok("--baseline after-first still sees a growing heap", good and summary.endswith("capacity_equal=false"), summary)
    summary, good, rows, _ = run("ro-writes", FakeSshd(ro_writes=True))
    ok("ro mkdir that succeeds fails the run", not good and summary.startswith("AGENT EXEC FAILED C4:"), summary)

    bad_calls = load_cases(cases_path, text=(pathlib.Path(cases_path).read_text()
                                             .replace("C10\tsession\t5\t-\trefused=host-policy\treboot",
                                                      "C10\tsession\t5\t-\trc=0\treboot")))
    try:
        Runner(FakeSshd(), bad_calls, scratch / "plan.jsonl", out=lambda _: None).plan()
        ok("a case file that expects `reboot` to run is refused before connecting", False, "accepted")
    except Failed as e:
        ok("a case file that expects `reboot` to run is refused before connecting", "C10" in str(e), str(e))

    # The run script's kernel stamp (scripts/run-agent-exec.sh, kernel_stamp):
    # .absd-identity first, then HEAD only of a checkout, else `unknown`,
    # never the HEAD of a repository that encloses a copy without .git.
    script = here / "run-agent-exec.sh"
    ok("run-agent-exec.sh parses (sh -n)", subprocess.run(["sh", "-n", str(script)]).returncode == 0)
    func = re.search(r"# BEGIN kernel_stamp\n(.*?)# END kernel_stamp", script.read_text(), re.S)
    ok("run-agent-exec.sh defines kernel_stamp between its markers", func is not None)

    def stamp(path):
        r = subprocess.run(["sh", "-c", func.group(1) + 'kernel_stamp "$1"', "sh", str(path)],
                           capture_output=True, text=True)
        return r.stdout.strip()

    outer = scratch / "stamp-outer"
    copy = outer / "copy"
    copy.mkdir(parents=True)
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main",
           "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"]
    subprocess.run(git + ["init", "-q", str(outer)], check=True)
    subprocess.run(git + ["-C", str(outer), "commit", "-q", "--allow-empty", "-m", "outer"], check=True)
    ok("stamp: a copy with neither .absd-identity nor .git inside a repository is unknown",
       stamp(copy) == "unknown", stamp(copy))
    (copy / ".absd-identity").write_text("5a29fba\n")
    ok("stamp: .absd-identity names the copy", stamp(copy) == "5a29fba", stamp(copy))
    (outer / ".absd-identity").write_text("modified\n")
    ok("stamp: .absd-identity wins over a checkout's HEAD", stamp(outer) == "modified", stamp(outer))
    (outer / ".absd-identity").unlink()
    head = subprocess.run(["git", "-C", str(outer), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    ok("stamp: a checkout without .absd-identity is its HEAD", len(head) == 40 and stamp(outer) == head, stamp(outer))
    return checks


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cases", default=str(DEFAULT_CASES))
    ap.add_argument("--self-test", action="store_true", help="fake transport; no SSH, no QEMU")
    ap.add_argument("--work", help="work directory (keys, image, serial logs, receipts)")
    ap.add_argument("--receipts", help="receipt JSONL (default WORK/receipts.jsonl)")
    ap.add_argument("--candidate", type=int, default=0, help="run rows gated `# requires candidate N` for this N")
    ap.add_argument("--baseline", choices=["first", "after-first"], default="first",
                    help="capacity baseline: the first quiescent line (default) or the first call's after-line")
    ap.add_argument("--kernel")
    ap.add_argument("--platform", default=str(here.parent))
    ap.add_argument("--shell")
    ap.add_argument("--qemu", default="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand")
    ap.add_argument("--boot-seconds", type=int, default=3000)
    args = ap.parse_args()
    try:
        if args.self_test:
            import tempfile
            with tempfile.TemporaryDirectory(prefix="agent-exec-selftest-") as scratch:
                checks = self_test(pathlib.Path(args.cases), pathlib.Path(scratch))
            print(f"AGENT EXEC SELF-TEST OK checks={checks}")
            return 0
        if not (args.work and args.kernel and args.shell):
            ap.error("--work, --kernel and --shell are required (or --self-test)")
        calls = load_cases(args.cases)
        summary, good = real_main(args, calls)
        print(summary, flush=True)
        return 0 if good else 1
    except (Failed, CaseError) as e:
        print(f"AGENT EXEC FAILED {e}", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
