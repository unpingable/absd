#!/usr/bin/env python3
"""The agent job runner: one job is an executable, its inputs, an
explicit authority specification and resource constraints, run in the
guest through SSH exec sessions only (docs/agent-exec-20261012/JOB.md).

The runner reuses scripts/agent-exec.py: its host policy, its lexer, its
line matchers and capacity census, its transport (one ssh process per exec
session), and its guard that keeps a machine request from ever leaving the
host. A job is

  1. staged: `mkdir -p` of a fresh workspace under /home/operator/agent-jobs,
     each input and an uploaded executable written by `cat > FILE`;
  2. verified: every staged file and a /bin executable read back by a
     second exec (`ro cat`) and by the host's own reader of the image, both
     compared with the declared sha256;
  3. run: one exec session whose text the runner builds from the job's
     commands (quoted, so it always routes through absd-sh, with each
     command's `ro`/`nofs` word), under the harness's wall-clock timeout,
     output caps and optional cancellation;
  4. observed: the trusted lines from outside the worker (sshd's
     SSH SESSION CHILD, exited, end, SSH FS RELEASE and SERVED CAPACITY
     lines; the kernel's SPAWN OK and USER EXIT/KILLED/FAULT lines; fsd's
     FSD SWEEP and any recovery line) and the host reader's view of the
     image before and after; never the worker's stdout;
  5. collected: every declared artifact read back twice by separate execs
     and compared with the host reader's digest.

Summary lines: `AGENT JOB OK job=<name> outcome=<o> artifacts=N ...` or
`AGENT JOB FAILED job=<name> <reason>`, and for a job set
`AGENT JOB SET OK set=<name> jobs=N ...`. `--self-test` drives every path
against a fake guest (no SSH, no QEMU).

`--quiescence=session` (the default) waits for the global quiescent
SERVED CAPACITY line after every exec session and judges the census there.
`--quiescence=job` runs each `--job` file as a concurrent worker: no
census can exist while workers overlap, so each worker's receipts rest on
its own sequenced lines (scope=worker), and the quiescent line is waited
for once, after every worker's last session, where the census is judged
(scope=job). The library entry point is `run_workers`, or
`begin_workers`/`end_workers` around a harness's own threads (JOB.md
"Concurrent workers and quiescence").
"""

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import secrets
import sys
import threading
import time
import types

here = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("agent_exec", here / "agent-exec.py")
ae = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ae)

JOB_ROOT = "/home/operator/agent-jobs"
# sshd's one session binding (ssh/src/absd.rs session_mounts); no job can
# be granted any other.
SESSION_MOUNTS = [["/home/operator", "rw"], ["/tmp/session-<id>", "rw"], ["/bin", "ro"], ["/etc", "ro"],
                  ["/share", "ro"], ["/var/log", "ro"]]
OUTCOMES = ("complete", "failed", "guest-refused", "refused-host", "timeout", "cancelled", "output-cap",
            "undeclared-write", "lost")
DEFAULTS = {"timeout_s": 60, "stdout_cap": 1 << 20, "stderr_cap": 1 << 20, "artifact_cap": 4 << 20,
            "post_cancel_wait_s": 5}
# Capacity fields that are reusable occupancy: back to baseline after every
# job, judged at the quiescent line (N5's event rule). frames and
# heap_pages_peak are reported, not judged (N4's open attribution).
REUSABLE = ("slots", "pool", "net_sockets", "net_closing", "processes", "handles", "pipes", "cells")
REPORTED = ("frames", "heap_pages_peak")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
# The kernel's lines, matched as scripts/ssh_absd.py matches them.
SPAWN = re.compile(r"SPAWN OK pid=(\d+) parent=(\d+) program=\S+")
ENDED = re.compile(r"USER (EXIT|KILLED|FAULT) pid=(\d+)")
RESET = re.compile(r"^(?:FSD SWEEP|SERVED RECOVERY|SERVED SERVICE FAULT|DURABLE WORKER GENERATION)[^\r\n]*",
                   re.MULTILINE)
# fsd's grant records on its stdout (ssh/src/fsd_server.rs:130-150): the
# session's binding, one derived binding per command a shell starts with a
# spare (none for `nofs`, none when the shell lends its own channel), and
# the release with the scratch it removed.
FSD_BIND = re.compile(r"FSD BIND slot=(\d+) spares=\[[\d, ]*\] mounts=(\S+)")
FSD_DERIVE = re.compile(r"FSD DERIVE spare=(\d+) owner=(\d+) mounts=(\S+)")
FSD_RELEASE = re.compile(r"FSD RELEASE slot=(\d+) closed=\d+ scratch_removed=(\d+)")
# The cause each refusal label stands for, when the evidence shows it.
LABEL_CAUSE = {"write:/bin": "read-only-binding:/bin", "write:/share": "read-only-binding:/share",
               "write:/etc": "read-only-binding:/etc", "write:ro": "derived-read-only"}
SWEEP = re.compile(r"^FSD SWEEP scratch_removed=\d+", re.MULTILINE)
# fsd's own census, printed at a settled dispatcher boundary
# (ssh/src/fsd_server.rs report_capacity); reported only if it appears.
FSD_CAPACITY = re.compile(r"^FSD CAPACITY [^\r\n]*", re.MULTILINE)
QUIESCENCE = ("session", "job")
# Under --quiescence=job, the receipt fields that describe the whole boot,
# not one worker. Every other field of a worker's receipt is scope=worker.
JOB_SCOPED = frozenset({"census", "resets", "boot_sweep", "concurrent_workers", "quiescence", "fsd_capacity"})
NESTED = ("trusted", "untrusted", "authority")
PLACEHOLDER = re.compile(r"\{(exe|run|in:[^}]*|out:[^}]*)\}")


class JobError(Exception):
    """A job file that cannot be run as written (not a refusal)."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# -- the job file ----------------------------------------------------------

class Job:
    pass


def _need(cond, where, what):
    if not cond:
        raise JobError(f"{where}: {what}")


def _word_ok(word):
    return isinstance(word, str) and word and '"' not in word and "\\" not in word and not any(
        (ord(c) < 0x20 or ord(c) == 0x7f or (c in ae.RUST_WS and c != " ")) for c in word)


def load_job(obj, base, where):
    """One job object (JOB.md "The job file")."""
    j = Job()
    _need(isinstance(obj, dict), where, "a job is a JSON object")
    known = {"job", "requires", "description", "executable", "inputs", "authority", "commands", "join",
             "resources", "artifacts", "expect"}
    extra = set(obj) - known
    _need(not extra, where, f"unknown keys {sorted(extra)}")
    j.name = obj.get("job")
    _need(isinstance(j.name, str) and NAME.fullmatch(j.name), where, "`job` is a name [A-Za-z0-9._-]")
    where = f"{where} job {j.name}"
    req = obj.get("requires")
    _need(req is None or (isinstance(req, str) and re.fullmatch(r"candidate-\d+", req)), where,
          "`requires` is null or candidate-N")
    j.requires = int(req.split("-")[1]) if req else None
    j.description = obj.get("description", "")

    exe = obj.get("executable")
    _need(isinstance(exe, dict) and (("path" in exe) != ("upload" in exe)), where,
          "`executable` has exactly one of path (in /bin) or upload")
    j.exe_sha = exe.get("sha256")
    _need(j.exe_sha is None or re.fullmatch(r"[0-9a-f]{64}", j.exe_sha), where, "executable sha256 is 64 hex")
    if "path" in exe:
        _need(isinstance(exe["path"], str) and re.fullmatch(r"/bin/[A-Za-z0-9._-]+", exe["path"]), where,
              "executable path is /bin/NAME")
        j.exe_path, j.exe_upload = exe["path"], None
    else:
        _need(j.exe_sha is not None, where, "an uploaded executable needs its sha256")
        _need(isinstance(exe.get("name"), str) and NAME.fullmatch(exe["name"]), where, "executable name")
        j.exe_upload = _file(base, exe["upload"], where)
        j.exe_name = exe["name"]

    j.inputs = []
    for i, inp in enumerate(obj.get("inputs", [])):
        w = f"{where} input {i}"
        _need(isinstance(inp, dict) and set(inp) == {"name", "file", "sha256"}, w, "input is {name, file, sha256}")
        _need(NAME.fullmatch(inp["name"]), w, "input name")
        _need(re.fullmatch(r"[0-9a-f]{64}", inp["sha256"]), w, "input sha256 is 64 hex")
        j.inputs.append({"name": inp["name"], "data": _file(base, inp["file"], w), "sha256": inp["sha256"]})
    _need(len({i["name"] for i in j.inputs}) == len(j.inputs), where, "duplicate input names")

    auth = obj.get("authority", {})
    _need(isinstance(auth, dict) and set(auth) <= {"mounts", "may_write"}, where, "authority is {mounts, may_write}")
    j.mounts = auth.get("mounts")
    j.may_write = auth.get("may_write", ["out"])

    j.join = obj.get("join", "and")
    _need(j.join in ("and", "seq"), where, "`join` is and or seq")
    cmds = obj.get("commands")
    _need(isinstance(cmds, list) and cmds, where, "`commands` is a non-empty list")
    j.commands = []
    for i, c in enumerate(cmds):
        w = f"{where} command {i}"
        _need(isinstance(c, dict) and set(c) <= {"argv", "authority", "stdin", "stdout"} and "argv" in c, w,
              "command is {argv, authority, stdin, stdout}")
        _need(isinstance(c["argv"], list) and c["argv"] and all(_word_ok(x) for x in c["argv"]), w,
              'argv words are non-empty strings without ", \\ or control characters')
        a = c.get("authority", "session")
        _need(a in ae.DECLARED, w, f"authority is one of {'/'.join(ae.DECLARED)}")
        for key in ("stdin", "stdout"):
            _need(c.get(key) is None or (isinstance(c[key], str) and NAME.fullmatch(c[key])), w, f"{key} is a name")
        _need(c.get("stdin") is None or c["stdin"] in {x["name"] for x in j.inputs}, w, "stdin names an input")
        for x in c["argv"]:
            for m in PLACEHOLDER.finditer(x):
                p = m.group(1)
                if p.startswith("in:"):
                    _need(p[3:] in {i["name"] for i in j.inputs}, w, f"{{{p}}} names no input")
                elif p.startswith("out:"):
                    _need(NAME.fullmatch(p[4:]), w, f"{{{p}}} is not a name")
            _need("{" not in PLACEHOLDER.sub("", x) and "}" not in PLACEHOLDER.sub("", x), w,
                  f"unknown placeholder in {x!r}")
        j.commands.append({"argv": list(c["argv"]), "authority": a, "stdin": c.get("stdin"), "stdout": c.get("stdout")})

    res = dict(DEFAULTS)
    given = obj.get("resources", {})
    _need(isinstance(given, dict) and set(given) <= set(DEFAULTS) | {"cancel_after_s"}, where, "unknown resource")
    res.update(given)
    for k, v in res.items():
        _need(isinstance(v, (int, float)) and v > 0, where, f"resource {k} is a positive number")
    j.resources = res

    j.artifacts = []
    for i, a in enumerate(obj.get("artifacts", [])):
        w = f"{where} artifact {i}"
        _need(isinstance(a, dict) and set(a) <= {"name", "sha256"} and NAME.fullmatch(a.get("name", "")), w,
              "artifact is {name, sha256?}")
        _need(a.get("sha256") is None or re.fullmatch(r"[0-9a-f]{64}", a["sha256"]), w, "artifact sha256")
        j.artifacts.append(a)
    _need(len({a["name"] for a in j.artifacts}) == len(j.artifacts), where, "duplicate artifact names")
    for c in j.commands:
        _need(c["stdout"] is None or c["stdout"] in {a["name"] for a in j.artifacts}, where,
              f"stdout {c['stdout']} is not a declared artifact")

    exp = obj.get("expect", {"outcome": "complete"})
    _need(isinstance(exp, dict) and set(exp) <= {"outcome", "rc", "stderr_re", "refusal", "absent"}, where,
          "expect is {outcome, rc, stderr_re, refusal, absent}")
    _need(exp.get("outcome") in OUTCOMES, where, f"expect.outcome is one of {', '.join(OUTCOMES)}")
    if exp.get("stderr_re") is not None:
        re.compile(exp["stderr_re"])
    j.expect = exp
    return j


def _file(base, rel, where):
    _need(isinstance(rel, str), where, "file is a path relative to the job file")
    path = (base / rel).resolve()
    _need(base.resolve() in path.parents, where, f"{rel} is outside the job file's directory")
    _need(path.is_file(), where, f"{rel} does not exist")
    return path.read_bytes()


def load_jobs(path):
    """A job file: one job object, or {"set": NAME, "jobs": [...]}."""
    path = pathlib.Path(path)
    try:
        obj = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise JobError(f"{path.name}: not JSON: {e}")
    if isinstance(obj, dict) and "jobs" in obj:
        _need(set(obj) <= {"set", "description", "jobs"} and isinstance(obj["jobs"], list) and obj["jobs"],
              path.name, "a set is {set, description?, jobs: [...]}")
        _need(isinstance(obj.get("set"), str) and NAME.fullmatch(obj["set"]), path.name, "`set` is a name")
        jobs = [load_job(x, path.parent, f"{path.name}[{i}]") for i, x in enumerate(obj["jobs"])]
        name = obj["set"]
    else:
        jobs = [load_job(obj, path.parent, path.name)]
        name = None
    _need(len({j.name for j in jobs}) == len(jobs), path.name, "duplicate job names")
    return name, jobs


# -- what the runner sends ------------------------------------------------

def workspace(job, run):
    return f"{JOB_ROOT}/{job.name}-{run}"


def exe_path(job, ws):
    return job.exe_path if job.exe_upload is None else f"{ws}/exe/{job.exe_name}"


def substitute(word, job, ws, run):
    def one(m):
        p = m.group(1)
        if p == "exe":
            return exe_path(job, ws)
        if p == "run":
            return run
        if p.startswith("in:"):
            return f"{ws}/in/{p[3:]}"
        return f"{ws}/out/{p[4:]}"
    return PLACEHOLDER.sub(one, word)


def job_line(job, ws, run):
    """The exec text: every word quoted (so sshd hands it to absd-sh), each
    command's narrowing word first, redirections only to the workspace."""
    parts = []
    for c in job.commands:
        words = [substitute(w, job, ws, run) for w in c["argv"]]
        text = ("" if c["authority"] == "session" else c["authority"] + " ") + " ".join(f'"{w}"' for w in words)
        if c["stdin"]:
            text += f' < "{ws}/in/{c["stdin"]}"'
        if c["stdout"]:
            text += f' > "{ws}/out/{c["stdout"]}"'
        parts.append(text)
    return (" && " if job.join == "and" else " ; ").join(parts)


def job_policy(job, line):
    """None, or why the host refuses the job before any connection."""
    if ae.machine_request(line):
        return "machine-request", "shutdown/reboot in the job: refused by host policy (the guest would honour it)"
    if job.mounts is not None and job.mounts != SESSION_MOUNTS:
        return "mounts-not-grantable", "sshd binds one fixed mount set to every session (ssh/src/absd.rs session_mounts)"
    if job.may_write != ["out"]:
        return "may-write-not-grantable", "the harness can only observe writes to the workspace out/ directory"
    for words in (c["argv"] for c in job.commands):
        if not substitute(words[0], job, "/w", "r").startswith("/"):
            return "not-a-program-path", "argv[0] must be an absolute program path (no builtins)"
    try:
        parsed = ae.commands(line)
    except ae.CaseError as e:
        return "unparseable", f"absd-sh would refuse the line: {e}"
    asked = [ae.NARROWING.get(w[0], "session") for w, _ in parsed]
    if asked != [c["authority"] for c in job.commands]:
        return "authority-mismatch", f"line asks for {asked}"
    return None


# -- the runner ------------------------------------------------------------

def scoped(fields, default):
    """Under --quiescence=job every receipt field is {scope, value}, so no
    field can be read as a per-worker census."""
    out = {}
    for k, v in fields.items():
        scope = "job" if default == "job" or k in JOB_SCOPED else "worker"
        if k in NESTED and isinstance(v, dict):
            v = scoped(v, scope)
        out[k] = {"scope": scope, "value": v}
    return out


class Quiescence:
    """The shared state of concurrent workers in one boot (--quiescence=job).

    sshd prints the quiescent SERVED CAPACITY line only when it holds no
    session at all (ssh/src/absd.rs, the `slots.is_empty() && !ending`
    test), so while workers overlap no census exists. This is a limit of
    the evidence, not a rule of the contract. Each worker's session is
    attributed through sshd's own sequence instead:

    - `SSH SESSION CHILD pid= fs_slot=` is printed in the same loop turn as,
      and immediately before, `sshd: conn N: exec "TEXT"` (absd.rs
      Spawner::spawn, conn.rs exec), so the exec text names the child, its
      pid, its slot and its connection;
    - `sshd: conn N: session child exited|end` is that connection's;
    - the first `SSH FS RELEASE slot=S` after the child is that session's,
      because a slot is not bound again until it is released;
    - every bind of slot S is released exactly once, in order, before S is
      bound again, even when the child's spawn is then refused (the
      Binding's drop prints SSH FS RELEASE, absd.rs:338-350, and fsd prints
      FSD RELEASE, fsd_server.rs:138-143); so a session whose CHILD follows
      r SSH FS RELEASE lines of slot S holds the (r+1)-th `FSD BIND slot=S`
      on the serial, and that binding's `FSD DERIVE owner=S` and
      `FSD RELEASE slot=S` lines follow it, up to its release. Counting
      CHILD lines instead would shift after a bind whose spawn is refused.
    """

    def __init__(self, transport, settle_timeout=120, step=0.2):
        self.t, self.settle_timeout, self.step = transport, settle_timeout, step
        self.lock = threading.RLock()
        self.claimed = set()
        self.sessions = 0
        self.runs = []
        self.workspaces = set()
        self.attributed = set()
        self.missing_release = []

    def opened(self):
        with self.lock:
            self.sessions += 1

    def claim(self, w0, text):
        """The first unclaimed exec line at or after w0 whose text is TEXT,
        with the SSH SESSION CHILD line sshd printed immediately before it."""
        with self.lock:
            log = self.t.worker()
            same = [m for m in ae.EXEC.finditer(log, w0)
                    if not m.group("refused") and ae.rust_unquote(m.group("text")) == text]
            for m in same:
                if m.start() in self.claimed:
                    continue
                head = log[:m.start()].rstrip("\r\n")
                prev = head[head.rfind("\n") + 1:]
                ch = ae.CHILD.match(prev)
                if ch is None:
                    continue
                self.claimed.add(m.start())
                slot = ch["fs_slot"]
                k = 1 + sum(1 for r in ae.RELEASE.finditer(log, 0, m.start()) if r["slot"] == slot)
                return {"conn": m["conn"], "pos": m.start(), "child": ch.groupdict(), "child_line": prev.rstrip("\r"),
                        "k": k, "text_shared": len(same) > 1}
        return None

    def refused_conn(self, w0):
        """A connection sshd refused (SSH PREAUTH|GLOBAL REFUSED, absd.rs
        1043-1058, 1076-1086) at or after w0 and not yet claimed: it never
        reaches accepted_reclaimed, so it is uncounted."""
        def look():
            with self.lock:
                for m in ae.REFUSED_CONN.finditer(self.t.worker(), w0):
                    if ("refused", m.start()) not in self.claimed:
                        self.claimed.add(("refused", m.start()))
                        self.sessions -= 1
                        return m.group(0).rstrip("\r")
            return None
        return ae.wait_for(look, min(5, self.settle_timeout), self.step)

    def has_exec(self, w0, text):
        return any(not m.group("refused") and ae.rust_unquote(m.group("text")) == text and m.start() not in self.claimed
                   for m in ae.EXEC.finditer(self.t.worker(), w0))

    def attribute(self, w0, text):
        return ae.wait_for(lambda: self.claim(w0, text), self.settle_timeout, self.step)

    def ended(self, sess):
        """The session's own end lines, once its SSH FS RELEASE is there
        (and its exit or end line, or the timeout)."""
        def look():
            log = self.t.worker()
            pos, conn, slot, pid = sess["pos"], sess["conn"], sess["child"]["fs_slot"], sess["child"]["pid"]
            rel = next((m for m in ae.RELEASE.finditer(log, pos) if m["slot"] == slot), None)
            mine = re.findall(rf"(?m)^sshd: conn {conn}: (?:session child exited|end): [^\r\n]*", log[pos:])
            exited = re.findall(rf"(?m)^sshd: conn {conn}: session child exited: Code\((\d+)\)", log[pos:])
            return {"release": rel.group(0).rstrip("\r") if rel else None, "exited_lines": mine,
                    "exit": int(exited[0]) if len(exited) == 1 else None,
                    "session_end": re.findall(rf"(?m)^SSH SESSION END pid={pid} [^\r\n]*", log[pos:])}
        got = ae.wait_for(lambda: (lambda e: e if e["release"] and e["exited_lines"] else None)(look()),
                          self.settle_timeout, self.step)
        return got or look()

    def fsd_segment(self, sess):
        """The serial from the k-th FSD BIND of the session's slot to that
        binding's FSD RELEASE (or the end of the serial so far)."""
        serial = self.t.serial()
        slot, k = sess["child"]["fs_slot"], sess["k"]
        binds = [m for m in FSD_BIND.finditer(serial) if m.group(1) == slot]
        if len(binds) < k:
            return None
        b = binds[k - 1]
        rel = next((m for m in FSD_RELEASE.finditer(serial, b.start()) if m.group(1) == slot), None)
        return serial[b.start():rel.end() if rel else len(serial)]

    def begin_run(self, worker, job, ws, line):
        words = [w for w in re.findall(r'"([^"]*)"', line) if w.startswith("/")]
        entry = {"worker": worker, "job": job, "ws": ws, "paths": [self.t.physical(w) for w in words],
                 "start": time.monotonic(), "end": None}
        with self.lock:
            self.runs.append(entry)
        return entry

    def end_run(self, entry):
        with self.lock:
            entry["end"] = time.monotonic()

    def foreign(self, path):
        """A path outside every worker's workspace, the job root and /tmp."""
        if path == self.t.physical(JOB_ROOT) or path == "/tmp" or path.startswith("/tmp/"):
            return False
        with self.lock:
            spaces = [self.t.physical(w) for w in self.workspaces]
        return not any(path == w or path.startswith(w + "/") for w in spaces)

    def claim_writes(self, entry, changes):
        """Of the changes outside every workspace seen in ENTRY's run
        window, the ones the evidence ties to ENTRY's worker: no other
        worker's run window overlapped (sole-run-window), or only ENTRY's
        line names the path (named-in-line). The rest stay unattributed
        and fail the job at its end."""
        with self.lock:
            others = [e for e in self.runs if e is not entry and e["start"] <= entry["end"]
                      and (e["end"] is None or e["end"] >= entry["start"])]
        named = lambda e, p: any(p == w or p.startswith(w.rstrip("/") + "/") for w in e["paths"])
        mine = []
        for p in changes:
            if not others:
                mine.append({"path": p, "attribution": "sole-run-window"})
            elif named(entry, p) and not any(named(e, p) for e in others):
                mine.append({"path": p, "attribution": "named-in-line"})
        with self.lock:
            self.attributed.update(x["path"] for x in mine)
        return mine, sorted({f"{e['worker']}/{e['job']}" for e in others})


class JobRunner:
    def __init__(self, transport, receipts, candidate=0, cancel_after=None, tscale=1.0, settle_timeout=120,
                 out=print, baseline=None, step=0.2, quiescence="session", shared=None, worker=None):
        self.t = transport
        self.receipts = pathlib.Path(receipts)
        self.candidate = candidate
        self.cancel_after = cancel_after
        self.tscale = tscale
        self.settle_timeout = settle_timeout
        self.out = out
        self.base = baseline
        self.step = step
        if quiescence not in QUIESCENCE:
            raise ae.Failed(f"--quiescence is one of {'/'.join(QUIESCENCE)}")
        if (quiescence == "job") != (shared is not None):
            raise ae.Failed("--quiescence=job runs through a shared Quiescence (run_workers)")
        self.quiescence = quiescence
        self.q = shared
        self.worker = worker

    def record(self, obj):
        if self.q is None:
            with open(self.receipts, "a") as f:
                f.write(json.dumps(obj, sort_keys=True) + "\n")
            return
        if "job_receipt" in obj:
            obj = {"job_receipt": scoped(obj["job_receipt"], "worker")}
        elif "job_end" in obj:
            obj = {"job_end": scoped(obj["job_end"], "job")}
        elif "summary" in obj:
            obj = {"summary": {"scope": "worker", "value": obj["summary"]}}
        else:
            obj = scoped(obj, "worker")
        with self.q.lock, open(self.receipts, "a") as f:
            f.write(json.dumps(obj, sort_keys=True) + "\n")

    def start(self):
        self.receipts.parent.mkdir(parents=True, exist_ok=True)
        if not self.receipts.exists():
            self.receipts.write_text("")
        if self.base is None:
            self.base = ae.wait_for(lambda: ae.capacity(self.t.worker()), self.settle_timeout, self.step)
            if self.base is None:
                raise ae.Failed("no quiescent SERVED CAPACITY line before the first job")
        sweeps = SWEEP.findall(self.t.serial())
        self.boot_sweep = sweeps[-1] if sweeps else None

    def plan(self, jobs):
        """Before anything connects: every job's host-policy decision must be
        what it expects."""
        bad = []
        for j in jobs:
            run = "0" * 8
            refused = job_policy(j, job_line(j, workspace(j, run), run))
            if (refused is not None) != (j.expect["outcome"] == "refused-host"):
                bad.append(f"{j.name}: host policy {'refuses' if refused else 'admits'} it but it expects "
                           f"{j.expect['outcome']}")
        if bad:
            raise ae.Failed("job file disagrees with host policy: " + "; ".join(bad))

    # One exec session that is not the job's run ---------------------------

    def exec(self, job, phase, text, stdin=b""):
        if self.q is not None:
            return self.exec_worker(job, phase, text, stdin)
        w0 = len(self.t.worker())
        count0 = len(ae.CAPACITY.findall(self.t.worker()))
        rc, out, err, timed_out = self.t.run(text, stdin, 120)
        settled = self.settle(count0, 1)
        window = self.t.worker()[w0:]
        rec = {"job": job.name, "phase": phase, "text_sha256": sha256(text.encode()), "rc": rc,
               "stdout_sha256": sha256(out), "stdout_bytes": len(out), "stderr_bytes": len(err),
               "child": [m.group(0).rstrip("\r") for m in ae.CHILD.finditer(window)],
               "fs_release": [m.group(0).rstrip("\r") for m in ae.RELEASE.finditer(window)],
               "capacity_after": ae.capacity(self.t.worker()) if settled else None}
        self.record(rec)
        if timed_out or not settled:
            raise ae.Failed(f"{phase}: {'timed out' if timed_out else 'no quiescent SERVED CAPACITY line'}")
        return rc, out, err

    def exec_worker(self, job, phase, text, stdin):
        """--quiescence=job: one exec session judged on its own lines; no
        census is waited for."""
        w0 = len(self.t.worker())
        self.q.opened()
        rc, out, err, timed_out = self.t.run(text, stdin, 120)
        refused = self.q.refused_conn(w0) if rc == 255 and not self.q.has_exec(w0, text) else None
        if refused:
            self.record({"job": job.name, "worker": self.worker, "phase": phase, "text_sha256": sha256(text.encode()),
                         "rc": rc, "refused_connection": refused, "census": "judged once at job end (job_end)"})
            raise ae.Failed(f"{phase}: worker {self.worker}: connection refused by sshd under contention: {refused}")
        sess = self.q.attribute(w0, text)
        end = self.q.ended(sess) if sess else None
        rec = {"job": job.name, "worker": self.worker, "phase": phase, "text_sha256": sha256(text.encode()), "rc": rc,
               "stdout_sha256": sha256(out), "stdout_bytes": len(out), "stderr_bytes": len(err),
               "child": [sess["child_line"]] if sess else [], "text_shared": sess["text_shared"] if sess else None,
               "fs_release": [end["release"]] if end and end["release"] else [],
               "exit": end["exit"] if end else None, "census": "judged once at job end (job_end)"}
        self.record(rec)
        if timed_out:
            raise ae.Failed(f"{phase}: timed out")
        if sess is None:
            raise ae.Failed(f"{phase}: worker {self.worker}: no exec line with its SSH SESSION CHILD for this session")
        if not end["release"]:
            self.q.missing_release.append(f"{self.worker}/{job.name}/{phase}"
                                          + (" (text shared: blame ambiguous)" if sess["text_shared"] else ""))
            raise ae.Failed(f"{phase}: worker {self.worker}: no SSH FS RELEASE of slot {sess['child']['fs_slot']}")
        return rc, out, err

    def settle(self, count0, accepted):
        before = None
        caps = list(ae.CAPACITY.finditer(self.t.worker()))
        if caps[:count0]:
            before = int(caps[count0 - 1].group("accepted_reclaimed"))
        return ae.wait_for(lambda: len(ae.CAPACITY.findall(self.t.worker())) > count0
                           and (ae.capacity(self.t.worker()) or {}).get("accepted_reclaimed", -1)
                           >= (before or 0) + accepted, self.settle_timeout, self.step)

    # A job ----------------------------------------------------------------

    def run_job(self, job):
        """Returns (summary line, ok)."""
        run = secrets.token_hex(4)
        ws = workspace(job, run)
        line = job_line(job, ws, run)
        r = {"job": job.name, "run": run, "workspace": ws, "line": line, "line_sha256": sha256(line.encode()),
             "authority": {"commands": [c["authority"] for c in job.commands], "mounts": SESSION_MOUNTS,
                           "may_write": [f"{ws}/out"]},
             "resources": job.resources, "expect": job.expect, "refusals": [], "failures": [],
             "trusted": {}, "untrusted": {}}
        if self.q is not None:
            r["worker"] = self.worker
            r["quiescence"] = "job"
            with self.q.lock:
                self.q.workspaces.add(ws)
        if job.requires and job.requires != self.candidate:
            r["outcome"] = "skipped"
            self.record({"job_receipt": r})
            return f"AGENT JOB SKIPPED job={job.name} requires=candidate-{job.requires}", True
        refused = job_policy(job, line)
        if refused:
            kind, why = refused
            r["outcome"] = "refused-host"
            expected = job.expect.get("refusal")
            match = "yes" if expected == kind else "no"
            r["refusals"].append({"by": "host-policy", "observed": f"controller-line:{kind}", "evidence": "host-policy",
                                  "cause": kind, "reason": why, "expected": expected, "match": match})
            self.out(f"AGENT JOB REFUSAL job={job.name} by=host-policy observed=controller-line:{kind} "
                     f"evidence=host-policy connected=false cause={kind} expected={expected or 'none'} match={match}")
            return self.finish(job, r)
        try:
            self.stage(job, ws, r)
            self.execute(job, ws, line, r, run)
        except ae.Failed as e:
            r["failures"].append(str(e))
            r.setdefault("outcome", "lost")
        return self.finish(job, r)

    def stage(self, job, ws, r):
        rc, _, err = self.exec(job, "stage", f'mkdir -p "{ws}/in" "{ws}/out" "{ws}/exe"')
        if rc != 0:
            raise ae.Failed(f"stage: mkdir rc={rc} {err[-200:]!r}")
        staged = [(f"{ws}/in/{i['name']}", i["data"], i["sha256"], f"input {i['name']}") for i in job.inputs]
        if job.exe_upload is not None:
            staged.append((exe_path(job, ws), job.exe_upload, job.exe_sha, "executable"))
        for path, data, want, what in staged:
            if sha256(data) != want:
                raise ae.Failed(f"{what}: the controller's file has sha256 {sha256(data)}, the job declares {want}")
            rc, _, err = self.exec(job, "upload", f'cat > "{path}"', data)
            if rc != 0:
                raise ae.Failed(f"upload {what}: rc={rc} {err[-200:]!r}")
        snap = self.t.snapshot()
        identity = []
        for path, _, want, what in staged + ([(job.exe_path, None, job.exe_sha, "executable")]
                                             if job.exe_upload is None else []):
            rc, out, _ = self.exec(job, "verify", f'ro cat "{path}"')
            host = snap.get(self.t.physical(path))
            host_sha = host[-1] if host else None
            entry = {"what": what, "path": path, "exec_sha256": sha256(out) if rc == 0 else None,
                     "host_sha256": host_sha, "declared_sha256": want}
            identity.append(entry)
            if rc != 0 or host_sha is None or sha256(out) != host_sha or (want is not None and host_sha != want):
                raise ae.Failed(f"{what} identity: {entry}")
        r["trusted"]["staged_identity"] = identity

    def execute(self, job, ws, line, r, run):
        res = job.resources
        entry = sess = refused = None
        if self.q is not None:
            # The run window opens before the "before" image, so it encloses
            # both snapshots: a write another worker makes after this
            # snapshot always meets an open window of this worker's.
            entry = self.q.begin_run(self.worker, job.name, ws, line)
        before_snap = self.t.snapshot()
        w0, s0 = len(self.t.worker()), len(self.t.serial())
        count0 = len(ae.CAPACITY.findall(self.t.worker()))
        cancel_after = self.cancel_after if self.cancel_after is not None else res.get("cancel_after_s")
        if self.q is not None:
            self.q.opened()
        handle = self.t.start(line, b"", {"stdout": int(res["stdout_cap"]), "stderr": int(res["stderr_cap"])})
        started, child_at, outcome = time.monotonic(), None, None
        while outcome is None:
            now = time.monotonic()
            if self.q is not None:
                if sess is None:
                    sess = self.q.claim(w0, line)
                    if sess is not None:
                        child_at = now
            elif child_at is None and ae.CHILD.search(self.t.worker()[w0:]):
                child_at = now
            if handle.exceeded():
                outcome = "output-cap"
            elif handle.done():
                outcome = "exited"
            elif cancel_after is not None and child_at is not None and now - child_at >= cancel_after * self.tscale:
                handle.kill()
                outcome = "cancelled"
            elif now - started >= res["timeout_s"] * self.tscale:
                handle.kill()
                outcome = "timeout"
            else:
                time.sleep(min(0.05, 0.05 * self.tscale) if self.tscale < 1 else 0.05)
        rc, out, err, totals = handle.result()
        r["wall_s"] = round(time.monotonic() - started, 3)
        r["untrusted"] = {"note": "the worker's own output: evidence of what it said, not of what it did",
                          "client_rc": rc, "stdout_sha256": sha256(out), "stdout_bytes_kept": len(out),
                          "stderr_sha256": sha256(err), "stderr_bytes_kept": len(err),
                          "stdout_bytes_seen": totals["stdout"], "stderr_bytes_seen": totals["stderr"],
                          "stderr_head": err[:200].decode(errors="replace")}
        if self.q is None:
            settled = self.settle(count0, 1)
            window, serial = self.t.worker()[w0:], self.t.serial()[s0:]
            t = self.trusted(window, serial, settled, r)
            after_snap = self.t.snapshot()
            changed = diff(before_snap, after_snap)
            allowed = self.t.physical(f"{ws}/out")
            r["trusted"]["image_changes"] = changed
            # Scratch belongs to the session and is removed at its release
            # (fsd/src/server.rs:19-22): anything of it still there is residue.
            residue = [p for p in after_snap if p.startswith("/tmp/")]
            if residue:
                r["failures"].append(f"scratch left after the session's release: {residue}")
            undeclared = [p for p in changed if p != allowed and not p.startswith(allowed + "/")
                          and p != "/tmp" and not p.startswith("/tmp/")]
        else:
            if sess is None and rc == 255 and not self.q.has_exec(w0, line):
                refused = self.q.refused_conn(w0)
            if refused:
                t = {"census": "judged once at job end (job_end)", "depth": None, "refused_connection": refused}
                r["trusted"].update(t)
                r["failures"].append(f"worker {self.worker}: connection refused by sshd under contention: {refused}")
                serial = None
            else:
                if sess is None:
                    sess = self.q.attribute(w0, line)
                serial = self.q.fsd_segment(sess) if sess else None
                t = self.trusted_worker(job, sess, self.q.ended(sess) if sess else None, self.t.serial()[s0:], serial,
                                        r)
            serial = serial or ""
            after_snap = self.t.snapshot()
            self.q.end_run(entry)
            changed = diff(before_snap, after_snap)
            allowed, own = self.t.physical(f"{ws}/out"), self.t.physical(ws)
            # Only the worker's own workspace is its own; other workers'
            # workspaces and live scratch change under it. A write outside
            # every workspace is this worker's only where the evidence says
            # so (Quiescence.claim_writes); scratch residue is judged at
            # job end, when no session is live.
            mine = [p for p in changed if p == own or p.startswith(own + "/")]
            claimed, overlapping = self.q.claim_writes(entry, [p for p in changed if self.q.foreign(p)])
            r["trusted"]["image_changes"] = mine + [x["path"] for x in claimed]
            r["trusted"]["write_attribution"] = claimed
            r["concurrent_workers"] = overlapping
            undeclared = [p for p in mine if p != allowed and not p.startswith(allowed + "/")] + \
                [x["path"] for x in claimed]
            changed = r["trusted"]["image_changes"]
        r["undeclared_writes"] = undeclared
        for p in undeclared:
            self.out(f"AGENT JOB UNDECLARED WRITE job={job.name} path={p} by=harness-observed prevented=false")

        # The outcome, from trusted observations first.
        if outcome == "exited":
            if t.get("exit") is None:
                outcome = "lost"
                r["failures"].append(f"no `session child exited` line (client rc={rc})")
            else:
                if rc != t["exit"]:
                    r["failures"].append(f"client rc={rc} but sshd logged exited: Code({t['exit']})")
                outcome = "complete" if t["exit"] == 0 else "failed"
        r["outcome"] = outcome
        if outcome in ("cancelled", "timeout", "output-cap"):
            self.after_cancel(job, ws, r, t, after_snap, outcome)
        r["image_unchanged"] = not changed
        if outcome == "failed":
            self.refusal(job, ws, run, r, t, after_snap, serial)
        self.collect(job, ws, r, after_snap)

    def refusal(self, job, ws, run, r, t, snap, serial):
        """The guest failed the job's line. State only what was observed,
        each fact with its source; derive a cause only where a trusted grant
        record explains an observed absence; the job file's expectation is
        reported beside it, never instead of it."""
        observed, evidence, causes = [f"exit:{t['exit']}"], ["sshd-exit"], []
        slot = t.get("fs_slot")
        binds = [m.group(2) for m in FSD_BIND.finditer(serial) if m.group(1) == slot]
        derives = [m.group(3) for m in FSD_DERIVE.finditer(serial) if m.group(2) == slot]
        mounts = lambda text: [(x.rsplit(":", 1)[0], x.rsplit(":", 1)[1]) for x in text.split(",")]
        for c in job.commands:
            for word in c["argv"][1:]:
                path = substitute(word, job, ws, run)
                if not path.startswith("/") or " " in path or self.t.physical(path) in snap:
                    continue
                observed.append(f"absent:{path}")
                if "host-reader" not in evidence:
                    evidence.append("host-reader")
                if c["authority"] == "ro":
                    ro = [d for d in derives if all(rw == "ro" for _, rw in mounts(d))]
                    if ro:
                        observed.append("derive:all-ro")
                        evidence.append("fsd-derive")
                        causes.append("derived-read-only")
                elif c["authority"] == "session" and binds:
                    cover = [m for m, rw in mounts(binds[-1]) if path == m or path.startswith(m.rstrip("/") + "/")]
                    if cover and dict(mounts(binds[-1]))[cover[0]] == "ro":
                        observed.append(f"binding:{cover[0]}:ro")
                        evidence.append("fsd-bind")
                        causes.append(f"read-only-binding:{cover[0]}")
        if any(c["authority"] == "nofs" for c in job.commands):
            observed.append(f"derives:{len(derives)}")
            if "fsd-derive" not in evidence:
                evidence.append("fsd-derive")
        if t.get("depth") is not None:
            observed.append(f"tree:processes={t['processes']},depth={t['depth']}")
            evidence.append("kernel-spawn")
        cause = causes[0] if causes and len(set(causes)) == 1 else "undistinguished"
        expected = job.expect.get("refusal")
        match = "yes" if expected is not None and LABEL_CAUSE.get(expected) == cause else "no"
        entry = {"by": "guest", "observed": observed, "evidence": evidence, "cause": cause, "expected": expected,
                 "match": match, "worker_stderr_untrusted": r["untrusted"]["stderr_head"]}
        r["refusals"].append(entry)
        if expected is not None and match == "no" and cause != "undistinguished":
            r["failures"].append(f"the job expects {expected} but the evidence shows {cause}")
        head = r["untrusted"]["stderr_head"].splitlines()[0][:120] if r["untrusted"]["stderr_head"] else ""
        self.out(f"AGENT JOB REFUSAL job={job.name} by=guest observed={';'.join(observed)} "
                 f"evidence={','.join(evidence)} cause={cause} expected={expected or 'none'} match={match} "
                 f"worker_stderr={head!r} (untrusted)")

    def trusted(self, window, serial, settled, r):
        """What the runner observed outside the worker."""
        t = {"settled": bool(settled)}
        children = [m.groupdict() for m in ae.CHILD.finditer(window)]
        t["child_lines"] = [m.group(0).rstrip("\r") for m in ae.CHILD.finditer(window)]
        if len(children) != 1:
            r["failures"].append(f"want one SSH SESSION CHILD line, got {t['child_lines']}")
            r["trusted"].update(t)
            t["depth"] = None
            return t
        ch = children[0]
        if (ch["argv0"], ch["spawn_right"], ch["control"]) != ("/bin/absd-sh", "true", "true"):
            r["failures"].append(f"the job's session child is not absd-sh with control: {ch}")
        root = ch["pid"]
        tree = {root: 1}
        spawns = SPAWN.findall(serial)
        for pid, parent in spawns:
            if parent in tree:
                tree[pid] = tree[parent] + 1
        ended = {pid: kind for kind, pid in ENDED.findall(serial)}
        t["processes"] = len(tree)
        t["depth"] = max(tree.values())
        t["spawns"] = [f"pid={p} parent={q}" for p, q in spawns if p in tree]
        t["ended"] = {p: ended.get(p) for p in tree}
        exited = re.findall(r"(?m)^sshd: conn \d+: session child exited: Code\((\d+)\)", window)
        t["exit"] = int(exited[0]) if len(exited) == 1 else None
        t["exited_lines"] = re.findall(r"(?m)^sshd: conn \d+: (?:session child exited|end): [^\r\n]*", window)
        releases = [m.groupdict() for m in ae.RELEASE.finditer(window)]
        t["fs_release"] = [m.group(0).rstrip("\r") for m in ae.RELEASE.finditer(window)]
        t["fs_released"] = [x["slot"] for x in releases] == [ch["fs_slot"]]
        t["fs_slot"] = ch["fs_slot"]
        t["fsd_release"] = [f"slot={a} scratch_removed={b}" for a, b in FSD_RELEASE.findall(serial) if a == ch["fs_slot"]]
        # A shell that did not end its commands within the grace is killed
        # with them left running (ssh/src/absd.rs:28-35): a forced end.
        t["session_end"] = re.findall(r"(?m)^SSH SESSION END [^\r\n]*", window)
        if any("forced=true" in x for x in t["session_end"]):
            r["failures"].append(f"forced session end, its commands may outlive it: {t['session_end']}")
        t["resets"] = RESET.findall(serial) + RESET.findall(window)
        t["boot_sweep"] = self.boot_sweep
        cap = ae.capacity(self.t.worker()) if settled else None
        t["capacity_before"] = self.base
        t["capacity_after"] = cap
        t["reusable_diff"] = [f"{f} {self.base[f]}->{cap[f]}" for f in REUSABLE if cap and self.base[f] != cap[f]] \
            if cap else ["missing"]
        t["reported_diff"] = [f"{f} {self.base[f]}->{cap[f]}" for f in REPORTED if cap and self.base[f] != cap[f]] \
            if cap else ["missing"]
        if cap and cap["boot"] != self.base["boot"]:
            t["reusable_diff"].append("boot changed")
        t["capacity_equal"] = not t["reusable_diff"]
        if not settled:
            r["failures"].append("no quiescent SERVED CAPACITY line after the job")
        if t["depth"] > 2:
            r["failures"].append(f"process tree depth {t['depth']} > 2")
        if not t["fs_released"]:
            r["failures"].append(f"want SSH FS RELEASE of slot {ch['fs_slot']}, got {t['fs_release']}")
        gone = [p for p, k in t["ended"].items() if k is None]
        if gone:
            r["failures"].append(f"processes of the job with no USER EXIT/KILLED/FAULT line: {gone}")
        if not t["capacity_equal"]:
            r["failures"].append(f"census not back to baseline (N5 rule, judged at the quiescent line): "
                                 f"{t['reusable_diff']}")
        if t["resets"]:
            r["failures"].append(f"a service reset during the job: {t['resets']}")
        r["trusted"].update(t)
        return t

    def trusted_worker(self, job, sess, end, serial, segment, r):
        """--quiescence=job: what the runner observed outside the worker,
        from this session's own sequenced lines (Quiescence). No census:
        it is judged once, at job end."""
        t = {"census": "judged once at job end (job_end)"}
        if sess is None:
            r["failures"].append(f"worker {self.worker}: no exec line with its SSH SESSION CHILD for the job's run")
            t["depth"] = None
            r["trusted"].update(t)
            return t
        ch = sess["child"]
        t["child_lines"] = [sess["child_line"]]
        t["attribution"] = {"conn": sess["conn"], "fs_slot": ch["fs_slot"], "k": sess["k"],
                            "rule": "CHILD before its exec line; k-th FSD BIND of the slot is its k-th child"}
        if (ch["argv0"], ch["spawn_right"], ch["control"]) != ("/bin/absd-sh", "true", "true"):
            r["failures"].append(f"the job's session child is not absd-sh with control: {ch}")
        root = ch["pid"]
        tree = {root: 1}
        spawns = SPAWN.findall(serial)
        for pid, parent in spawns:
            if parent in tree:
                tree[pid] = tree[parent] + 1
        ended = {pid: kind for kind, pid in ENDED.findall(serial)}
        t["processes"] = len(tree)
        t["depth"] = max(tree.values())
        t["spawns"] = [f"pid={p} parent={q}" for p, q in spawns if p in tree]
        t["ended"] = {p: ended.get(p) for p in tree}
        t["exit"] = end["exit"]
        t["exited_lines"] = end["exited_lines"]
        t["fs_release"] = [end["release"]] if end["release"] else []
        t["fs_released"] = bool(end["release"])
        t["fs_slot"] = ch["fs_slot"]
        t["fsd_release"] = [f"slot={a} scratch_removed={b}" for a, b in FSD_RELEASE.findall(segment or "")
                            if a == ch["fs_slot"]]
        if segment is None:
            r["failures"].append(f"worker {self.worker}: no FSD BIND #{sess['k']} of slot {ch['fs_slot']} on the serial")
        t["fsd_capacity"] = FSD_CAPACITY.findall(segment or "")
        t["session_end"] = end["session_end"]
        if any("forced=true" in x for x in t["session_end"]):
            r["failures"].append(f"forced session end, its commands may outlive it: {t['session_end']}")
        t["resets"] = RESET.findall(serial) + RESET.findall(self.t.worker()[sess["pos"]:])
        t["boot_sweep"] = self.boot_sweep
        if t["depth"] > 2:
            r["failures"].append(f"process tree depth {t['depth']} > 2")
        if not t["fs_released"]:
            self.q.missing_release.append(f"{self.worker}/{job.name}/run")
            r["failures"].append(f"worker {self.worker}: no SSH FS RELEASE of slot {ch['fs_slot']}")
        gone = [p for p, k in t["ended"].items() if k is None]
        if gone:
            r["failures"].append(f"processes of the job with no USER EXIT/KILLED/FAULT line: {gone}")
        if t["resets"]:
            r["failures"].append(f"a service reset during the job: {t['resets']}")
        r["trusted"].update(t)
        return t

    def after_cancel(self, job, ws, r, t, after_snap, outcome):
        """The harness ended the job: its child is gone, its fs authority
        released, the census back, and nothing it started writes later."""
        wait = job.resources["post_cancel_wait_s"] * self.tscale
        time.sleep(wait)
        later = self.t.snapshot()
        late = diff(after_snap, later)
        if self.q is not None:
            # Other workers write their own workspaces meanwhile: only this
            # worker's workspace is judged here; the rest at job end.
            own = self.t.physical(ws)
            late = [p for p in late if p == own or p.startswith(own + "/")]
        r["trusted"]["late_writes"] = late
        r["trusted"]["post_cancel_wait_s"] = wait
        if late:
            r["failures"].append(f"writes after the job ended: {late}")
        killed = [p for p, k in t.get("ended", {}).items() if k == "KILLED"]
        ended = t.get("ended") or {}
        gone = str(all(ended.values())).lower() if ended else "unknown"
        self.out(f"AGENT JOB ENDED job={job.name} by=harness reason={outcome} child_gone={gone} killed={len(killed)} "
                 f"fs_released={str(t.get('fs_released', False)).lower()} "
                 + (f"census_equal={str(t.get('capacity_equal', False)).lower()} " if self.q is None
                    else f"census=job-end worker={self.worker} ")
                 + f"late_write={str(bool(late)).lower()}")
        if outcome == "output-cap":
            over = [k for k in ("stdout", "stderr") if r["untrusted"][f"{k}_bytes_seen"] > job.resources[f"{k}_cap"]]
            caps = ",".join(f"{k}>{int(job.resources[k + '_cap'])}" for k in over)
            expected = job.expect.get("refusal")
            match = "yes" if expected == "output-cap" else "no"
            r["refusals"].append({"by": "harness", "observed": caps, "evidence": "client-byte-count",
                                  "cause": "output-cap", "expected": expected, "match": match})
            self.out(f"AGENT JOB REFUSAL job={job.name} by=harness observed=bytes:{caps} evidence=client-byte-count "
                     f"enforced_by_guest=false cause=output-cap expected={expected or 'none'} match={match}")

    def collect(self, job, ws, r, snap):
        complete = r["outcome"] == "complete"
        out_dir = self.t.physical(f"{ws}/out")
        present = sorted(p[len(out_dir) + 1:] for p in snap if p.startswith(out_dir + "/"))
        declared = {a["name"] for a in job.artifacts}
        r["artifacts_present"] = present
        extra = [n for n in present if n not in declared]
        if extra:
            r["failures"].append(f"undeclared artifacts in out/: {extra}")
        for name in job.expect.get("absent", []):
            if name in present:
                r["failures"].append(f"{name} exists in out/ but must not")
        collected = []
        for a in job.artifacts:
            if a["name"] not in present:
                if complete:
                    r["failures"].append(f"artifact {a['name']} missing")
                continue
            path = f"{ws}/out/{a['name']}"
            host = snap[self.t.physical(path)][-1]
            reads = []
            for i in range(2):
                rc, out, _ = self.exec(job, f"collect-{i + 1}", f'ro cat "{path}"')
                reads.append(sha256(out) if rc == 0 else None)
                size = len(out)
            entry = {"name": a["name"], "sha256": host, "bytes": size, "reads": reads, "complete": complete}
            if reads != [host, host]:
                r["failures"].append(f"artifact {a['name']}: exec reads {reads} vs host reader {host}")
            if size > job.resources["artifact_cap"]:
                r["failures"].append(f"artifact {a['name']} is {size} B, over artifact_cap")
            if a.get("sha256") and complete and host != a["sha256"]:
                r["failures"].append(f"artifact {a['name']} sha256 {host}, the job expects {a['sha256']}")
            collected.append(entry)
        r["artifacts"] = collected

    def finish(self, job, r):
        exp = job.expect
        bad = list(r["failures"])
        if not satisfies(exp["outcome"], r):
            bad.append(f"outcome {r['outcome']} (image_unchanged={r.get('image_unchanged')}, "
                       f"undeclared={len(r.get('undeclared_writes') or [])}), the job expects {exp['outcome']}")
        if r.get("undeclared_writes") and exp["outcome"] != "undeclared-write":
            bad.append(f"undeclared writes {r['undeclared_writes']}")
        t = r["trusted"]
        if "rc" in exp and t.get("exit") != exp["rc"]:
            bad.append(f"trusted exit {t.get('exit')}, the job expects {exp['rc']}")
        if exp.get("stderr_re") is not None and not re.search(exp["stderr_re"], r["untrusted"].get("stderr_head", "")):
            bad.append(f"stderr (untrusted) does not match {exp['stderr_re']!r}")
        r["verdict"] = "FAILED" if bad else "OK"
        r["problems"] = bad
        self.record({"job_receipt": r})
        n = sum(1 for a in r.get("artifacts", []) if a["complete"])
        who = f"job={job.name}" if self.q is None else f"job={job.name} worker={self.worker}"
        if bad:
            return f"AGENT JOB FAILED {who} {bad[0]}" + (f" (+{len(bad) - 1} more)" if len(bad) > 1 else ""), False
        census = f"capacity_equal={str(t.get('capacity_equal', True)).lower()}" if self.q is None else "census=job-end"
        return (f"AGENT JOB OK {who} outcome={r['outcome']} expected={exp['outcome']} artifacts={n} "
                f"undeclared={len(r.get('undeclared_writes') or [])} "
                f"processes={t.get('processes', 0)} {census}"), True

    def run_set(self, name, jobs):
        if self.q is None:
            self.start()
        self.plan(jobs)
        lines, good, counts = [], True, {}
        for j in jobs:
            summary, ok = self.run_job(j)
            self.out(summary)
            lines.append(summary)
            good &= ok
            m = re.search(r"outcome=(\S+)", summary)
            key = m.group(1) if m else ("skipped" if "SKIPPED" in summary else "failed")
            counts[key] = counts.get(key, 0) + 1
        if name is not None:
            detail = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            who = f"set={name}" if self.q is None else f"set={name} worker={self.worker}"
            last = (f"AGENT JOB SET OK {who} jobs={len(jobs)} {detail}" if good
                    else f"AGENT JOB SET FAILED {who} jobs={len(jobs)} {detail}")
            self.out(last)
            self.record({"summary": last})
        return good


def satisfies(expected, r):
    """Whether the observed result meets the expected outcome. The runner
    never relabels what it observed: `guest-refused` is met by a trusted
    non-zero exit with the image unchanged, `undeclared-write` by an
    observed write outside out/."""
    if expected == "guest-refused":
        return r["outcome"] == "failed" and r.get("image_unchanged") is True
    if expected == "undeclared-write":
        return bool(r.get("undeclared_writes"))
    return r["outcome"] == expected


def diff(a, b):
    return sorted(p for p in set(a) | set(b) if a.get(p) != b.get(p))


# -- concurrent workers (--quiescence=job) ---------------------------------

def worker_name(set_name, jobs):
    return set_name if set_name is not None else jobs[0].name


def slot_counts(worker_log, serial):
    """Every bind pairs with one release: per slot, the FSD BIND, SSH FS
    RELEASE and FSD RELEASE counts over the boot must be equal, or the
    (r+1)-th-bind rule (Quiescence) is not trusted."""
    counts = {}
    for kind, pattern, text, group in (("bind", FSD_BIND, serial, 1), ("sshd_release", ae.RELEASE, worker_log, "slot"),
                                       ("fsd_release", FSD_RELEASE, serial, 1)):
        for m in pattern.finditer(text):
            c = counts.setdefault(m.group(group), {"bind": 0, "sshd_release": 0, "fsd_release": 0})
            c[kind] += 1
    return all(len(set(c.values())) == 1 for c in counts.values()), counts


def begin_workers(transport, receipts, workers, candidate=0, cancel_after=None, tscale=1.0, settle_timeout=120,
                  out=print, step=0.2):
    """Before any worker starts: the baseline census (the quiescent line
    before the first session), every job's host-policy plan, the job root,
    and the image as it stands. WORKERS is [(set_name, jobs)], one entry per
    `--job` file. Returns (lead, runners): run each runner's
    `run_set(set_name, jobs)` on its own thread (or through its own
    transport), then call end_workers(lead, runners)."""
    q = Quiescence(transport, settle_timeout, step)
    kw = dict(candidate=candidate, cancel_after=cancel_after, tscale=tscale, settle_timeout=settle_timeout, out=out,
              step=step, quiescence="job", shared=q)
    names = [worker_name(n, j) for n, j in workers]
    if len(set(names)) != len(names):
        raise ae.Failed(f"worker names are not distinct: {names}")
    lead = JobRunner(transport, receipts, worker="(job)", **kw)
    lead.start()
    for _, jobs in workers:
        lead.plan(jobs)
    # The job root exists before any worker's window opens, so creating it
    # is never seen as a write inside one.
    lead.exec(types.SimpleNamespace(name="(job)"), "job-root", f'mkdir -p "{JOB_ROOT}"')
    lead.start_snap = transport.snapshot()
    runners = []
    for name in names:
        r = JobRunner(transport, receipts, baseline=lead.base, worker=name, **kw)
        r.boot_sweep = lead.boot_sweep
        runners.append(r)
    return lead, runners


def end_workers(lead, runners):
    """After every worker's last session: wait once for the quiescent
    SERVED CAPACITY line that follows all of them and judge the N5 census
    there; report N4's frames/heap figures; check scratch residue, writes
    no worker accounts for, and that every session's release arrived."""
    q, t = lead.q, lead.t
    want = lead.base["accepted_reclaimed"] + q.sessions
    cap = ae.wait_for(lambda: (lambda c: c if c and c["accepted_reclaimed"] >= want else None)(ae.capacity(t.worker())),
                      lead.settle_timeout, lead.step)
    e = {"workers": [r.worker for r in runners], "sessions": q.sessions, "capacity_before": lead.base,
         "capacity_after": cap, "accepted_reclaimed_wanted": want}
    problems = []
    if cap is None:
        problems.append(f"no quiescent SERVED CAPACITY line after every worker's sessions (accepted_reclaimed>={want})")
        e["reusable_diff"] = e["reported_diff"] = ["missing"]
    else:
        e["reusable_diff"] = [f"{f} {lead.base[f]}->{cap[f]}" for f in REUSABLE if lead.base[f] != cap[f]]
        if cap["boot"] != lead.base["boot"]:
            e["reusable_diff"].append("boot changed")
        e["reported_diff"] = [f"{f} {lead.base[f]}->{cap[f]}" for f in REPORTED if lead.base[f] != cap[f]]
        if e["reusable_diff"]:
            problems.append(f"census not back to baseline (N5 rule, judged at the job-end quiescent line): "
                            f"{e['reusable_diff']}")
    e["capacity_equal"] = cap is not None and not e["reusable_diff"]
    found = FSD_CAPACITY.findall(t.serial())
    e["fsd_capacity"] = found[-1].rstrip("\r") if found else None
    end_snap = t.snapshot()
    e["scratch_residue"] = [p for p in end_snap if p.startswith("/tmp/")]
    if e["scratch_residue"]:
        problems.append(f"scratch left after every session's release: {e['scratch_residue']}")
    e["unattributed_writes"] = [p for p in diff(lead.start_snap, end_snap) if q.foreign(p) and p not in q.attributed]
    if e["unattributed_writes"]:
        problems.append(f"writes outside every workspace that no worker's evidence accounts for: "
                        f"{e['unattributed_writes']}")
    e["missing_release"] = list(q.missing_release)
    if q.missing_release:
        problems.append(f"no SSH FS RELEASE for {', '.join(q.missing_release)}")
    worker_log, serial = t.worker(), t.serial()
    e["fsd_attribution_consistent"], counts = slot_counts(worker_log, serial)
    if not e["fsd_attribution_consistent"]:
        problems.append(f"FSD BIND, SSH FS RELEASE and FSD RELEASE counts per slot differ: {counts}")
    e["problems"] = problems
    e["verdict"] = "FAILED" if problems else "OK"
    lead.record({"job_end": e})
    reported = ",".join(x.replace(" ", ":") for x in e["reported_diff"]) or "none"
    if problems:
        line = f"AGENT JOB QUIESCENT FAILED workers={len(runners)} sessions={q.sessions} scope=job {problems[0]}" + \
            (f" (+{len(problems) - 1} more)" if len(problems) > 1 else "")
    else:
        line = (f"AGENT JOB QUIESCENT OK workers={len(runners)} sessions={q.sessions} census_equal=true "
                f"reported={reported} fsd_capacity={'present' if e['fsd_capacity'] else 'absent'} scope=job")
    lead.out(line)
    return not problems


def run_workers(transport, receipts, workers, **kw):
    """--quiescence=job: every (set_name, jobs) in WORKERS runs on its own
    thread through TRANSPORT (one ssh process per exec session); the
    census is judged once, after all of them. True if every worker and the
    job end are OK."""
    lead, runners = begin_workers(transport, receipts, workers, **kw)
    results = [False] * len(runners)

    def one(i, set_name, jobs):
        try:
            results[i] = runners[i].run_set(set_name, jobs)
        except ae.Failed as e:
            runners[i].out(f"AGENT JOB FAILED worker={runners[i].worker} {e}")
    threads = [threading.Thread(target=one, args=(i, n, j), daemon=True) for i, (n, j) in enumerate(workers)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    ended = end_workers(lead, runners)
    return all(results) and ended


# -- the real transport ----------------------------------------------------

class SshJob:
    """One exec session as a Popen of ssh-matrix's client argv, with the
    harness's output caps applied as the bytes arrive."""

    def __init__(self, argv, caps):
        import subprocess
        self.p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.caps, self.bufs, self.seen, self.over = caps, {"stdout": bytearray(), "stderr": bytearray()}, \
            {"stdout": 0, "stderr": 0}, None
        self.lock = threading.Lock()
        self.threads = [threading.Thread(target=self.pump, args=(n, f), daemon=True)
                        for n, f in (("stdout", self.p.stdout), ("stderr", self.p.stderr))]
        for th in self.threads:
            th.start()

    def pump(self, name, f):
        while True:
            chunk = f.read1(65536)
            if not chunk:
                return
            with self.lock:
                self.seen[name] += len(chunk)
                room = self.caps[name] - len(self.bufs[name])
                self.bufs[name] += chunk[:max(room, 0)]
                if self.seen[name] > self.caps[name] and self.over is None:
                    self.over = name
                    self.p.kill()

    def exceeded(self):
        return self.over

    def done(self):
        return self.p.poll() is not None

    def kill(self):
        self.p.kill()

    def result(self):
        self.p.wait()
        for th in self.threads:
            th.join(10)
        killed = self.over is not None or self.p.returncode < 0
        return (None if killed else self.p.returncode), bytes(self.bufs["stdout"]), bytes(self.bufs["stderr"]), \
            dict(self.seen)


class SshJobTransport(ae.SshTransport):
    def start(self, text, stdin, caps):
        ae.guard(text)
        self.sent.append(text)
        return SshJob(self.client.base(self.key) + [text], caps)

    def snapshot(self):
        return {o[0]: o[1:] for o in self.target.system_objects()}

    def physical(self, path):
        return self.target.physical(path)


def real_main(args, sets):
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
    ae.stop_on_signals(target)
    receipts = args.receipts or work / "job-receipts.jsonl"
    runner = JobRunner(None, receipts, args.candidate, args.cancel_after)
    print('AGENT JOB WARM coverage=NOT_ESTABLISHED '
          'reason=no-reviewed-workspace-and-effect-reset-contract')
    for name, jobs in sets:
        runner.plan(jobs)  # before anything boots
    try:
        target.setup(work, key.with_suffix(".pub").read_text())
        first = target.start(fresh=True)
        client = sm.Client(work, target.port)
        client.trust(first["public"])
        runner.t = SshJobTransport(target, client, key, absd_fs)
        if args.quiescence == "job":
            return run_workers(runner.t, receipts, sets, candidate=args.candidate, cancel_after=args.cancel_after)
        good = True
        for name, jobs in sets:
            good &= runner.run_set(name, jobs)
        return good
    finally:
        target.stop()


# -- self-test: a fake guest ----------------------------------------------

class FakeGuest:
    """Enough of sshd, absd-sh, fsd and the kernel's lines to drive the job
    runner: one session per exec, the session's mounts, `ro`/`nofs`,
    redirections opened with the session's authority, a spawn right only
    for the session shell, kill on client drop, and the quiescent census.
    Faults: `late_write` (commands outlive a dropped session),
    `handle_leak` (one handle per session), `ro_writes` (ro is ignored),
    `tcc` (a /bin/tcc exists), `spawn_leak` (a nested shell may spawn),
    `forced_end` (sshd reports a forced session end), `bin_writable` (/bin
    is mounted read-write), `nofs_reads` (nofs is ignored), `no_release`
    (a session whose text contains this string is never released),
    `refuse_conn` (a connection whose text contains this string is refused,
    as sshd's GLOBAL limit refuses it).
    `rendezvous=N` holds every `sshtest sleep` until N are running, so
    concurrent workers' runs overlap for certain."""

    BOOT = "fedcba9876543210fedcba9876543210"

    def __init__(self, tscale, late_write=False, handle_leak=False, ro_writes=False, tcc=False, spawn_leak=False,
                 forced_end=False, bin_writable=False, nofs_reads=False, no_release=None, rendezvous=None,
                 refuse_conn=None):
        self.refuse_conn = refuse_conn
        self.spawn_leak, self.forced_end = spawn_leak, forced_end
        self.no_release = no_release
        self.rendezvous = threading.Barrier(rendezvous) if rendezvous else None
        self.bin_writable, self.nofs_reads = bin_writable, nofs_reads
        self.lock = threading.RLock()
        self.w, self.s = [], ["FSD SWEEP scratch_removed=0\n"]
        self.tscale = tscale
        self.late_write, self.handle_leak, self.ro_writes = late_write, handle_leak, ro_writes
        self.conn = self.sid = self.reclaimed = self.active = 0
        self.pid = 30
        self.handles = 57
        self.sent = []
        self.dirs = {"/", "/bin", "/etc", "/share", "/share/man", "/home", "/home/operator", "/tmp", "/var",
                     "/var/log"}
        self.files = {f"/bin/{n}": f"ELF:{n}".encode() for n in
                      ("cat", "ls", "mkdir", "echo", "printenv", "sshtest", "absd-sh", "man", "uname")}
        if tcc:
            self.files["/bin/tcc"] = b"ELF:tcc"
        self.files["/share/man/whatis"] = b"cat(1) - copy\n"
        self.files["/etc/motd"] = b"Welcome\n"
        self.census()

    # transport interface
    def worker(self):
        with self.lock:
            return "".join(self.w)

    def serial(self):
        with self.lock:
            return "".join(self.s)

    def physical(self, path):
        return path

    def snapshot(self):
        with self.lock:
            snap = {d: ("dir",) for d in self.dirs}
            snap.update({p: (sha256(b),) for p, b in self.files.items()})
            return snap

    def machine_requests_seen(self):
        return [t for t in self.sent if ae.machine_request(t)]

    def run(self, text, stdin, timeout):
        job = self.start(text, stdin, {"stdout": 1 << 30, "stderr": 1 << 30})
        rc, out, err, _ = job.result()
        return rc, out, err, False

    def start(self, text, stdin, caps):
        ae.guard(text)
        self.sent.append(text)
        return FakeJob(self, text, stdin, caps)

    # the guest
    def census(self):
        self.w.append(f"SERVED CAPACITY boot={self.BOOT} accepted_reclaimed={self.reclaimed} slots=0 pool=0 "
                      f"net_sockets=1 net_closing=0 processes=4 handles={self.handles} pipes=24 cells=6 "
                      f"frames=640 heap_pages_peak=250\n")

    def mounts(self, sid):
        return [("/home/operator", True), (f"/tmp/session-{sid}", True), ("/bin", self.bin_writable), ("/etc", False),
                ("/share", False), ("/var/log", False)]

    def access(self, auth, sid, path, write):
        """None if allowed, else the error text."""
        if auth == "nofs" and not (self.nofs_reads and not write):
            return "no filesystem"
        for m, rw in self.mounts(sid):
            if path == m or path.startswith(m + "/"):
                if write and (not rw or (auth == "ro" and not self.ro_writes)):
                    return "Read-only file system (os error 30)"
                return None
        return "No such file or directory (os error 2)"

    def new_pid(self):
        with self.lock:
            self.pid += 1
            return self.pid


class FakeJob:
    def __init__(self, guest, text, stdin, caps):
        self.g, self.text, self.stdin, self.caps = guest, text, stdin, caps
        self.out, self.err = bytearray(), bytearray()
        self.seen = {"stdout": 0, "stderr": 0}
        self.over = None
        self.killed = threading.Event()
        self.finished = threading.Event()
        self.rc = None
        self.thread = threading.Thread(target=self.session, daemon=True)
        self.thread.start()

    # client side
    def exceeded(self):
        return self.over

    def done(self):
        return self.finished.is_set()

    def kill(self):
        self.killed.set()

    def result(self):
        self.finished.wait(30)
        return (None if (self.killed.is_set() or self.over) else self.rc), bytes(self.out[:self.caps["stdout"]]), \
            bytes(self.err[:self.caps["stderr"]]), dict(self.seen)

    def emit(self, stream, data):
        buf = self.out if stream == "stdout" else self.err
        buf += data
        self.seen[stream] += len(data)
        if self.seen[stream] > self.caps[stream] and self.over is None:
            self.over = stream
            self.killed.set()

    # guest side
    def session(self):
        g = self.g
        with g.lock:
            if g.active >= 4 or (g.refuse_conn and g.refuse_conn in self.text):
                g.w.append("SSH GLOBAL REFUSED source=Some(127.0.0.1) limit=4 slots=4 pool=4\n")
                self.rc = 255
                self.finished.set()
                return
            g.active += 1
            g.conn += 1
            g.sid += 1
            conn, sid = g.conn, g.sid
            shell = g.new_pid()
            slot = 1 + sid % 10
            g.dirs.add(f"/tmp/session-{sid}")
            g.s.append(f"SPAWN OK pid={shell} parent=3 program=image\n")
            g.s.append(f"FSD BIND slot={slot} spares=[{slot % 10 + 1}, {(slot + 1) % 10 + 1}] mounts="
                       + ",".join(f"{m}:{'rw' if rw else 'ro'}" for m, rw in g.mounts(sid)) + "\n")
            g.w.append(f"SSH SESSION CHILD pid={shell} spawn_right=true argv0=/bin/absd-sh fs_slot={slot} "
                       f"spares=[{slot % 10 + 1}, {(slot + 1) % 10 + 1}] control=true\n")
            g.w.append(f"sshd: conn {conn}: exec {json.dumps(self.text)}\n")
        self.sid, self.shell, self.slot = sid, shell, slot
        status = self.shell_line(self.text, shell, depth=1)
        late = None
        with g.lock:
            if self.killed.is_set():
                g.w.append(f"sshd: conn {conn}: end: client gone\n")
                if not g.late_write:
                    g.s.append(f"USER KILLED pid={shell} by=2\n")
                else:
                    late = True
            else:
                self.rc = status
                g.w.append(f"sshd: conn {conn}: session child exited: Code({status})\n")
                g.s.append(f"USER EXIT pid={shell} status={status}\n")
            if g.forced_end:
                g.w.append(f"SSH SESSION END pid={shell} sent=1 exited=false forced=true ms=10000 read=false\n")
            if not (g.no_release and g.no_release in self.text):
                g.s.append(f"FSD RELEASE slot={slot} closed=3 scratch_removed=1 fs_objects=40 bound=0 opens=1 "
                           f"draining=0\n")
                g.w.append(f"SSH FS RELEASE slot={slot} spares=[{slot % 10 + 1}, {(slot + 1) % 10 + 1}] closed=0\n")
            g.w.append("SSH SESSION RECLAIMED children_started=0\n")
            for p in [p for p in g.files if p.startswith(f"/tmp/session-{sid}/")]:
                del g.files[p]
            g.dirs.discard(f"/tmp/session-{sid}")
            g.reclaimed += 1
            g.active -= 1
            g.handles += g.handle_leak
            if g.active == 0:
                g.census()
        self.finished.set()
        if late:
            # The fault: the shell's commands outlive the dropped session.
            time.sleep(0.1)
            self.killed.clear()
            self.shell_line(self.text, shell, depth=1, resume=True)
            with g.lock:
                g.s.append(f"USER EXIT pid={shell} status=0\n")

    def parse(self, text):
        """[(join, words, redirects)] from absd-sh's tokens."""
        out, words, redirects, join = [], [], [], None
        tokens = ae.tokenize(text)
        i = 0
        while i < len(tokens):
            kind, value = tokens[i]
            if kind == "word":
                words.append(value)
            elif value in ("<", ">", ">>", "2>", "2>>"):
                redirects.append((value, tokens[i + 1][1]))
                i += 1
            else:
                if words:
                    out.append((join, words, redirects))
                words, redirects, join = [], [], value
            i += 1
        if words:
            out.append((join, words, redirects))
        return out

    def shell_line(self, text, shell, depth, resume=False):
        g = self.g
        status = 0
        steps = self.parse(text)
        start = getattr(self, "resume_at", 0) if resume else 0
        for index, (join, words, redirects) in enumerate(steps):
            if index < start:
                continue
            if self.killed.is_set():
                self.resume_at = index
                return 130
            if join == "&&" and status != 0:
                break
            if join == "||" and status == 0:
                break
            status = self.command(words, redirects, shell, depth)
            if status is None:
                self.resume_at = index + 1
                return 130
        return status

    def command(self, words, redirects, shell, depth):
        g, sid = self.g, self.sid
        auth = ae.NARROWING.get(words[0], "session")
        if auth != "session":
            words = words[1:]
        prog, args = words[0], words[1:]
        if "/" not in prog:
            prog = "/bin/" + prog  # absd-sh resolves a bare word under /bin
        stdin = self.stdin if depth == 1 else b""
        for op, path in redirects:
            if op == "<":
                why = g.access("session", sid, path, False)
                if why or path not in g.files:
                    self.emit("stderr", f"absd-sh: {path}: {why or 'not found'}\n".encode())
                    return 1
                stdin = g.files[path]
        out_path = next((p for op, p in redirects if op == ">"), None)
        if out_path:
            why = g.access("session", sid, out_path, True)
            if why:
                self.emit("stderr", f"absd-sh: {out_path}: {why}\n".encode())
                return 1
            with g.lock:
                g.files[out_path] = b""
        if depth >= 2 and not g.spawn_leak:
            self.emit("stderr", f"absd-sh: {prog}: cannot run: permission denied\n".encode())
            return 126
        if prog not in g.files:
            self.emit("stderr", f"absd-sh: {prog}: not found\n".encode())
            return 127
        pid = g.new_pid()
        with g.lock:
            g.s.append(f"SPAWN OK pid={pid} parent={shell} program=image\n")
            if auth != "nofs" and depth == 1:
                ms = ",".join(f"{m}:{'rw' if rw and auth == 'session' else 'ro'}" for m, rw in g.mounts(sid))
                g.s.append(f"FSD DERIVE spare={self.slot % 10 + 1} owner={self.slot} mounts={ms}\n")
        buf = bytearray()

        def write(data):
            if out_path:
                buf.extend(data)
                with g.lock:
                    g.files[out_path] = bytes(buf)
            else:
                self.emit("stdout", data)

        status = self.program(prog, args, auth, stdin, write, pid)
        with g.lock:
            if status is None:
                if not g.late_write:
                    g.s.append(f"USER KILLED pid={pid} by={shell}\n")
            else:
                g.s.append(f"USER EXIT pid={pid} status={status}\n")
        return status

    def program(self, prog, args, auth, stdin, write, pid):
        g, sid = self.g, self.sid
        name = prog.rsplit("/", 1)[-1]

        def fail(msg):
            self.emit("stderr", f"{name}: {msg}\n".encode())
            return 1

        if g.files[prog].startswith(b"\x7fELF-fake"):
            write(b"agent-exec tcc ok\n")
            return 0
        if name == "cat":
            if not args:
                write(stdin)
                return 0
            for path in args:
                why = g.access(auth, sid, path, False)
                if why or path not in g.files:
                    return fail(f"{path}: {why or 'No such file or directory (os error 2)'}")
                write(g.files[path])
            return 0
        if name == "ls":
            path = args[0] if args else "/"
            why = g.access(auth, sid, path, False)
            if why or path not in g.dirs:
                return fail(f"{path}: {why or 'not a directory'}")
            kids = sorted({q[len(path.rstrip('/')) + 1:].split("/")[0] + ("/" if q in g.dirs else "")
                           for q in list(g.dirs) + list(g.files) if q.startswith(path.rstrip("/") + "/")})
            write("".join(k + "\n" for k in kids).encode())
            return 0
        if name == "mkdir":
            parents = "-p" in args
            status = 0
            for path in [a for a in args if a != "-p"]:
                why = g.access(auth, sid, path, True)
                if why:
                    status = fail(f"{path}: {why}")
                    continue
                with g.lock:
                    parts = path.strip("/").split("/")
                    chain = ["/" + "/".join(parts[:i]) for i in range(1, len(parts) + 1)] if parents else [path]
                    if not parents and (path in g.dirs or (path.rsplit("/", 1)[0] or "/") not in g.dirs):
                        status = fail(f"{path}: File exists or no parent (os error 17)")
                        continue
                    g.dirs.update(chain)
            return status
        if name == "echo":
            write((" ".join(args) + "\n").encode())
            return 0
        if name == "printenv":
            return 0
        if name == "tcc":
            src, dst = args[0], args[args.index("-o") + 1]
            for path, w in ((src, False), (dst, True)):
                why = g.access(auth, sid, path, w)
                if why:
                    return fail(f"{path}: {why}")
            with g.lock:
                g.files[dst] = b"\x7fELF-fake\n" + g.files[src]
            return 0
        if name == "absd-sh" and args[:1] == ["-c"]:
            return self.shell_line(args[1], pid, depth=2)
        if name == "sshtest":
            if args[0] == "exit":
                return int(args[1])
            if args[0] == "sleep":
                if g.rendezvous is not None:
                    try:
                        g.rendezvous.wait(5)
                    except threading.BrokenBarrierError:
                        pass
                if self.killed.wait(int(args[1]) / 1000 * g.tscale) and not g.late_write:
                    return None
                if self.killed.is_set():
                    time.sleep(min(int(args[1]) / 1000 * g.tscale, 0.1))
                write(b"slept\n")
                return 0
            if args[0] == "drip":
                while not self.killed.is_set():
                    write(b"drip drip drip drip drip drip drip drip\n")
                    time.sleep(0.001)
                return None
            if args[0] == "zeros":
                left = int(args[1])
                while left > 0:
                    if self.killed.is_set():
                        return None
                    n = min(4096, left)
                    write(b"\0" * n)
                    left -= n
                return 0
        return 0


def self_test(jobs_dir, scratch):
    checks = 0

    def ok(name, cond, detail=""):
        nonlocal checks
        checks += 1
        print(f"  {'ok  ' if cond else 'FAIL'} {name}{(': ' + str(detail)) if detail and not cond else ''}", flush=True)
        if not cond:
            raise ae.Failed(f"self-test: {name}: {detail}")

    tscale = 0.05

    def run(tag, path_or_jobs, guest, candidate=0, cancel_after=None, name=None):
        lines = []
        runner = JobRunner(guest, scratch / f"{tag}.jsonl", candidate, cancel_after, tscale=tscale,
                           settle_timeout=3, out=lines.append, step=0.01)
        if isinstance(path_or_jobs, (str, pathlib.Path)):
            name, jobs = load_jobs(path_or_jobs)
        else:
            jobs = path_or_jobs
        good = runner.run_set(name, jobs)
        rows = [json.loads(x) for x in (scratch / f"{tag}.jsonl").read_text().splitlines()]
        receipts = {x["job_receipt"]["job"]: x["job_receipt"] for x in rows if "job_receipt" in x}
        return good, lines, receipts

    # The job file's own rules.
    bad = [
        ({"job": "x"}, "executable"),
        ({"job": "x y", "executable": {"path": "/bin/cat"}, "commands": [{"argv": ["{exe}"]}]}, "`job` is a name"),
        ({"job": "x", "executable": {"path": "/usr/bin/cat"}, "commands": [{"argv": ["{exe}"]}]}, "/bin/NAME"),
        ({"job": "x", "executable": {"upload": "inputs/data.txt", "name": "d"}, "commands": [{"argv": ["{exe}"]}]},
         "needs its sha256"),
        ({"job": "x", "executable": {"path": "/bin/cat"}, "commands": [{"argv": ['a"b']}]}, "argv words"),
        ({"job": "x", "executable": {"path": "/bin/cat"}, "commands": [{"argv": ["a\x1cb"]}]}, "argv words"),
        ({"job": "x", "executable": {"path": "/bin/cat"}, "commands": [{"argv": ["{exe}"], "authority": "root"}]},
         "authority is one of"),
        ({"job": "x", "executable": {"path": "/bin/cat"}, "commands": [{"argv": ["{in:nope}"]}]}, "names no input"),
        ({"job": "x", "executable": {"path": "/bin/cat"}, "commands": [{"argv": ["{env:HOME}"]}]},
         "unknown placeholder"),
        ({"job": "x", "executable": {"path": "/bin/cat"}, "commands": [{"argv": ["{exe}"], "stdout": "o"}]},
         "not a declared artifact"),
        ({"job": "x", "executable": {"path": "/bin/cat"}, "commands": [{"argv": ["{exe}"]}],
          "inputs": [{"name": "d", "file": "../../../etc/passwd", "sha256": "0" * 64}]}, "outside"),
        ({"job": "x", "executable": {"path": "/bin/cat"}, "commands": [{"argv": ["{exe}"]}],
          "resources": {"memory": 1}}, "unknown resource"),
        ({"job": "x", "executable": {"path": "/bin/cat"}, "commands": [{"argv": ["{exe}"]}],
          "expect": {"outcome": "fine"}}, "expect.outcome"),
    ]
    for obj, needle in bad:
        try:
            load_job(obj, pathlib.Path(jobs_dir), "t")
            ok(f"job file refused ({needle})", False, "accepted")
        except JobError as e:
            ok(f"job file refused ({needle})", needle in str(e), str(e))

    # The three example jobs.
    good, lines, rec = run("analysis", jobs_dir / "readonly-analysis.json", FakeGuest(tscale))
    for line in lines:
        print("    " + line)
    ok("read-only analysis: AGENT JOB OK, complete, 4 artifacts", good and lines[-1].startswith(
        "AGENT JOB OK job=readonly-analysis outcome=complete expected=complete artifacts=4 "), lines)
    r = rec["readonly-analysis"]
    data = (jobs_dir / "inputs" / "data.txt").read_bytes()
    ok("artifacts: each read twice by exec, equal to the host reader's digest",
       all(a["reads"] == [a["sha256"], a["sha256"]] for a in r["artifacts"])
       and {a["name"]: a["sha256"] for a in r["artifacts"]}["copy.txt"] == sha256(data)
       and {a["name"]: a["sha256"] for a in r["artifacts"]}["env.txt"] == sha256(b""), r["artifacts"])
    ok("staged identity: exec read-back, host reader and declared digest agree",
       all(x["exec_sha256"] == x["host_sha256"] for x in r["trusted"]["staged_identity"]), r["trusted"]["staged_identity"])
    ok("trusted metadata: absd-sh child, depth 2, every process ended, slot released, census equal",
       r["trusted"]["depth"] == 2 and all(r["trusted"]["ended"].values()) and r["trusted"]["fs_released"]
       and r["trusted"]["capacity_equal"] and r["trusted"]["exit"] == 0, r["trusted"])
    ok("the worker's output is filed as untrusted", r["untrusted"]["note"].startswith("the worker's own output"))
    ok("the job line routes through absd-sh with its narrowing words",
       r["line"].startswith('ro "/bin/cat" ') and ' nofs "/bin/printenv" > ' in r["line"])

    good, lines, rec = run("compile-skip", jobs_dir / "compile-run.json", FakeGuest(tscale))
    ok("compile-run is skipped without candidate 2", good and lines[-1].startswith("AGENT JOB SKIPPED job=compile-run"),
       lines)
    good, lines, rec = run("compile", jobs_dir / "compile-run.json", FakeGuest(tscale, tcc=True), candidate=2)
    ok("compile-run with candidate 2: complete, 2 artifacts", good and lines[-1].startswith(
        "AGENT JOB OK job=compile-run outcome=complete expected=complete artifacts=2 "), lines)

    guest = FakeGuest(tscale)
    good, lines, rec = run("misbehaving", jobs_dir / "misbehaving.json", guest)
    for line in lines:
        print("    " + line)
    ok("misbehaving set: every member ends as it expects", good and lines[-1].startswith(
        "AGENT JOB SET OK set=misbehaving jobs=11 "), lines[-1])
    def refusal_line(job):
        return next((x for x in lines if x.startswith(f"AGENT JOB REFUSAL job={job} ")), "")

    for job, by, cause, expected, match, evidence in [
            ("write-bin", "guest", "read-only-binding:/bin", "write:/bin", "yes", "sshd-exit,host-reader,fsd-bind,kernel-spawn"),
            ("write-share", "guest", "read-only-binding:/share", "write:/share", "yes", "sshd-exit,host-reader,fsd-bind,kernel-spawn"),
            ("ro-write", "guest", "derived-read-only", "write:ro", "yes", "sshd-exit,host-reader,fsd-derive,kernel-spawn"),
            ("nofs-read", "guest", "undistinguished", "read:nofs", "no", "sshd-exit,fsd-derive,kernel-spawn"),
            ("spawn-depth", "guest", "undistinguished", "spawn-depth", "no", "sshd-exit,kernel-spawn"),
            ("machine-halt", "host-policy", "machine-request", "machine-request", "yes", "host-policy"),
            ("machine-nested", "host-policy", "machine-request", "machine-request", "yes", "host-policy"),
            ("output-cap", "harness", "output-cap", "output-cap", "yes", "client-byte-count")]:
        x = refusal_line(job)
        ok(f"{job}: by={by} evidence={evidence} cause={cause} expected={expected} match={match}",
           f"by={by} " in x and f" evidence={evidence} " in x and f" cause={cause} expected={expected} match={match}" in x,
           x)
    ok("write-bin states what it observed: the exit, the absent target, the read-only binding",
       "observed=exit:1;absent:/bin/agent-x;binding:/bin:ro;" in refusal_line("write-bin"), refusal_line("write-bin"))
    ok("nofs-read claims no image evidence and no cause (N11)",
       "image" not in refusal_line("nofs-read") and "host-reader" not in refusal_line("nofs-read")
       and "derives:0" in refusal_line("nofs-read"), refusal_line("nofs-read"))
    ok("refusal causes are observed, never copied from the job file",
       all(r.get("cause") != r.get("expected") or r.get("match") == "yes"
           for j in rec.values() for r in j.get("refusals", [])))
    ok("output-cap: the harness killed a child that would not stop (drip), on the stream that tripped",
       any(x.startswith("AGENT JOB ENDED job=output-cap") and "killed=0" not in x for x in lines)
       and "observed=bytes:stdout>4096" in refusal_line("output-cap"), [x for x in lines if "output-cap" in x])
    ok("spawn-depth: the nested shell's start is refused, no grandchild (depth 2)",
       rec["spawn-depth"]["trusted"]["depth"] == 2 and rec["spawn-depth"]["trusted"]["exit"] == 126)
    for job in ("timeout", "cancel-late-write", "output-cap"):
        ok(f"{job}: child gone, fs released, census equal, no late write",
           any(x.startswith(f"AGENT JOB ENDED job={job} by=harness") and "child_gone=true" in x
               and "fs_released=true" in x and "census_equal=true" in x and "late_write=false" in x for x in lines),
           [x for x in lines if job in x])
    ok("cancel: the write the job would have made after the cancel never happened",
       "late" not in rec["cancel-late-write"]["artifacts_present"])
    ok("undeclared write outside out/ is observed, not prevented",
       rec["undeclared-write"]["undeclared_writes"] and any(x.startswith("AGENT JOB UNDECLARED WRITE job=undeclared-write")
                                                           for x in lines))
    ok("no machine request reached the transport", guest.machine_requests_seen() == [])

    # --cancel-after overrides the job's own.
    _, jobs = load_jobs(jobs_dir / "readonly-analysis.json")
    slow = load_job({"job": "slow", "executable": {"path": "/bin/sshtest"},
                     "commands": [{"argv": ["{exe}", "sleep", "60000"], "authority": "nofs"}],
                     "expect": {"outcome": "cancelled"}}, jobs_dir, "t")
    good, lines, rec = run("cancel-cli", [slow], FakeGuest(tscale), cancel_after=1)
    ok("--cancel-after cancels a job that names none", good and rec["slow"]["outcome"] == "cancelled", lines)

    # Faults the runner must catch.
    good, lines, rec = run("late", jobs_dir / "misbehaving.json", FakeGuest(tscale, late_write=True))
    ok("a guest whose commands outlive the cancel: the late write fails the job",
       not good and any(x.startswith("AGENT JOB FAILED job=cancel-late-write") for x in lines),
       [x for x in lines if "cancel-late" in x])
    good, lines, rec = run("leak", jobs_dir / "readonly-analysis.json", FakeGuest(tscale, handle_leak=True))
    ok("a +1 handle at the quiescent line fails the job (N5 event rule)",
       not good and "census not back to baseline" in lines[-1], lines[-1])
    good, lines, rec = run("rowrites", jobs_dir / "misbehaving.json", FakeGuest(tscale, ro_writes=True))
    ok("an ro that writes fails ro-write", not good and any(x.startswith("AGENT JOB FAILED job=ro-write") for x in lines))
    set_obj = json.loads((jobs_dir / "misbehaving.json").read_text())

    def member(name, **changes):
        obj = json.loads(json.dumps(next(j for j in set_obj["jobs"] if j["job"] == name)))
        for k, v in changes.items():
            obj["expect" if k == "expect" else k] = v if k != "expect" else {**obj["expect"], **v}
        return load_job(obj, jobs_dir, "t")

    good, lines, rec = run("wrong-cause", [member("write-bin", expect={"refusal": "write:ro"})], FakeGuest(tscale))
    x = next((y for y in lines if y.startswith("AGENT JOB REFUSAL job=write-bin")), "")
    ok("a wrong expected cause: the line reports the observed cause with match=no, and the job fails",
       not good and "cause=read-only-binding:/bin expected=write:ro match=no" in x
       and "the job expects write:ro but the evidence shows read-only-binding:/bin" in lines[-1], [x, lines[-1]])
    for fault, name, needle in [("spawn_leak", "spawn-depth", "depth 3 > 2"),
                                ("forced_end", "write-bin", "forced session end"),
                                ("bin_writable", "write-bin", "the job expects guest-refused"),
                                ("nofs_reads", "nofs-read", "the job expects guest-refused")]:
        good, lines, rec = run(f"fault-{fault}", [member(name)], FakeGuest(tscale, **{fault: True}))
        ok(f"fault {fault}: {name} fails ({needle})", not good and needle in lines[-1], lines[-1])
    for name, change, kind in [("mounts", {"authority": {"mounts": [["/", "rw"]], "may_write": ["out"]}},
                                "mounts-not-grantable"),
                               ("maywrite", {"authority": {"may_write": ["/home/operator"]}}, "may-write-not-grantable"),
                               ("bare", {"commands": [{"argv": ["cat", "/etc/motd"], "authority": "ro"}]},
                                "not-a-program-path")]:
        obj = {"job": f"policy-{name}", "executable": {"path": "/bin/cat"},
               "commands": [{"argv": ["{exe}", "/etc/motd"], "authority": "ro"}],
               "expect": {"outcome": "refused-host", "refusal": kind}, **change}
        guest = FakeGuest(tscale)
        good, lines, rec = run(f"policy-{name}", [load_job(obj, jobs_dir, "t")], guest)
        ok(f"host policy refuses {kind} before connecting, match=yes",
           good and f"cause={kind} expected={kind} match=yes" in lines[0] and guest.sent == [], lines)
    wrong = json.loads((jobs_dir / "readonly-analysis.json").read_text())
    wrong["inputs"][0]["sha256"] = "0" * 64
    (scratch / "inputs").mkdir(exist_ok=True)
    (scratch / "inputs" / "data.txt").write_bytes(data)
    (scratch / "wrong.json").write_text(json.dumps(wrong))
    guest = FakeGuest(tscale)
    good, lines, rec = run("wrong-input", scratch / "wrong.json", guest)
    ok("a staged input whose digest is not the declared one stops the job before its run",
       not good and "the job declares" in lines[-1] and not any(t.startswith('ro "/bin/cat"') for t in guest.sent),
       lines[-1])
    wrong = json.loads((jobs_dir / "readonly-analysis.json").read_text())
    wrong["artifacts"][0]["sha256"] = "1" * 64
    (scratch / "wrong-art.json").write_text(json.dumps(wrong))
    good, lines, rec = run("wrong-art", scratch / "wrong-art.json", FakeGuest(tscale))
    ok("an artifact whose digest is not the expected one fails the job", not good and "the job expects" in lines[-1],
       lines[-1])
    # --quiescence=session is the default, and its receipts are the ones
    # before job-level quiescence existed: no field is scoped, the census
    # is judged per job (these key sets are frozen from 12b3b7c3).
    good, lines, rec = run("default-shape", jobs_dir / "readonly-analysis.json", FakeGuest(tscale))
    rows = [json.loads(x) for x in (scratch / "default-shape.jsonl").read_text().splitlines()]
    receipt = next(x["job_receipt"] for x in rows if "job_receipt" in x)
    ok("default mode: quiescence=session, receipts unchanged (no scope, census judged per job)",
       JobRunner(None, scratch / "x.jsonl").quiescence == "session"
       and sorted(receipt) == ["artifacts", "artifacts_present", "authority", "expect", "failures", "image_unchanged",
                               "job", "line", "line_sha256", "outcome", "problems", "refusals", "resources", "run",
                               "trusted", "undeclared_writes", "untrusted", "verdict", "wall_s", "workspace"]
       and "capacity_after" in receipt["trusted"] and "capacity_equal" in receipt["trusted"]
       and all(sorted(x) == ["capacity_after", "child", "fs_release", "job", "phase", "rc", "stderr_bytes",
                             "stdout_bytes", "stdout_sha256", "text_sha256"] for x in rows if "phase" in x)
       and "capacity_equal=true" in lines[-1] and "scope" not in json.dumps(rows), lines[-1])

    def worker_job(name, ms, word):
        return load_job({"job": name, "executable": {"path": "/bin/sshtest"},
                         "commands": [{"argv": ["{exe}", "sleep", str(ms)], "authority": "nofs"},
                                      {"argv": ["/bin/echo", word], "authority": "ro", "stdout": "said.txt"}],
                         "artifacts": [{"name": "said.txt", "sha256": sha256(f"{word}\n".encode())}]}, jobs_dir, "t")

    def run_job_mode(tag, workers, guest):
        lines = []
        good = run_workers(guest, scratch / f"{tag}.jsonl", workers, tscale=tscale, settle_timeout=3,
                           out=lines.append, step=0.01)
        rows = [json.loads(x) for x in (scratch / f"{tag}.jsonl").read_text().splitlines()]
        return good, lines, rows

    def value(field):
        return field["value"] if isinstance(field, dict) and set(field) == {"scope", "value"} else None

    guest = FakeGuest(tscale, rendezvous=2)
    good, lines, rows = run_job_mode("concurrent", [(None, [worker_job("agent-a", 4000, "alpha")]),
                                                    (None, [worker_job("agent-b", 4000, "beta")])], guest)
    for line in lines:
        print("    " + line)
    receipts = {value(x["job_receipt"]["job"]): x["job_receipt"] for x in rows if "job_receipt" in x}
    ends = [x["job_end"] for x in rows if "job_end" in x]
    ok("job mode: two overlapping workers OK, each OK line says census=job-end",
       good and all(any(x.startswith(f"AGENT JOB OK job={w} worker={w} outcome=complete") and "census=job-end" in x
                        for x in lines) for w in ("agent-a", "agent-b")), lines)
    log = guest.worker()
    runs = {w: (log.index(value(value(receipts[w]["trusted"])["child_lines"])[0]),
                log.index(value(value(receipts[w]["trusted"])["fs_release"])[0]))
            for w in ("agent-a", "agent-b")}
    ok("job mode: the two runs overlapped (each run's child started before the other's release)",
       runs["agent-a"][0] < runs["agent-b"][1] and runs["agent-b"][0] < runs["agent-a"][1], runs)

    def follows(child_line, needle):
        at = log.index(child_line) + len(child_line) + 1
        nxt = log[at:log.index("\n", at)]
        return nxt.startswith("sshd: conn ") and " exec " in nxt and needle in ae.rust_unquote(nxt.split(" exec ", 1)[1])

    attributed = []
    for w, rr in receipts.items():
        t = value(rr["trusted"])
        child = value(t["child_lines"])[0]
        slot = ae.CHILD.match(child)["fs_slot"]
        attributed.append(follows(child, value(rr["workspace"]))
                          and value(t["fs_release"])[0].startswith(f"SSH FS RELEASE slot={slot} ")
                          and value(t["fsd_release"]) == [f"slot={slot} scratch_removed=1"]
                          and value(t["exit"]) == 0 and value(t["fs_released"]) is True)
    for x in rows:
        if "phase" in x and value(x["worker"]) != "(job)":
            ws = value(receipts[value(x["job"])]["workspace"])
            needle = '"/bin/sshtest"' if value(x["phase"]) == "verify" else ws
            attributed.append(len(value(x["child"])) == 1 and follows(value(x["child"])[0], needle))
    ok("job mode: every receipt's child, exit and release are its own session's lines (CHILD before its exec, "
       "k-th FSD BIND)", all(attributed) and len(attributed) > 2, attributed)
    ok("job mode: the census is judged once, at job end, and back to baseline",
       len(ends) == 1 and value(ends[0]["capacity_equal"]) is True and value(ends[0]["capacity_after"]) is not None
       and value(ends[0]["sessions"]) == sum(1 for x in rows if "phase" in x) + 2
       and lines[-1].startswith("AGENT JOB QUIESCENT OK workers=2 ") and "census_equal=true" in lines[-1]
       and not any(k.startswith("capacity") for rr in receipts.values() for k in value(rr["trusted"]))
       and not any(k.startswith("capacity") for x in rows if "phase" in x for k in x), lines[-1])
    ok("job mode: N4 frames/heap figures are reported only at job end",
       "reported_diff" in ends[0] and not any("reported_diff" in value(rr["trusted"]) for rr in receipts.values()))

    def all_scoped(obj, nested=False):
        for k, v in obj.items():
            if not isinstance(v, dict) or set(v) != {"scope", "value"} or v["scope"] not in ("worker", "job"):
                return False
            if k in NESTED and isinstance(v["value"], dict) and not all_scoped(v["value"], True):
                return False
        return True

    ok("job mode: scope=worker or scope=job on every receipt field, census fields scope=job",
       all(all_scoped(x["job_receipt"]) if "job_receipt" in x else all_scoped(x["job_end"]) if "job_end" in x
           else x["summary"]["scope"] in ("worker", "job") if "summary" in x else all_scoped(x) for x in rows)
       and all(v["scope"] == "job" for v in ends[0].values())
       and all(value(rr["trusted"])["census"]["scope"] == "job" for rr in receipts.values()), rows[:2])

    lines = []
    good = run_workers(FakeGuest(tscale, tcc=True), scratch / "three.jsonl",
                       [load_jobs(jobs_dir / f) for f in ("compile-run.json", "readonly-analysis.json", "misbehaving.json")],
                       candidate=2, tscale=tscale, settle_timeout=3, out=lines.append, step=0.01)
    ok("job mode: the three example job files as concurrent workers, misbehaving set included, all as expected",
       good and "AGENT JOB SET OK set=misbehaving worker=misbehaving jobs=11 " in "\n".join(lines)
       and lines[-1].startswith("AGENT JOB QUIESCENT OK workers=3 "), [x for x in lines if "FAILED" in x] or lines[-1])

    guest = FakeGuest(tscale, rendezvous=2, no_release='"sleep" "4001"')
    good, lines, rows = run_job_mode("no-release", [(None, [worker_job("agent-a", 4000, "alpha")]),
                                                    (None, [worker_job("agent-lost", 4001, "lost")])], guest)
    for line in lines:
        print("    " + line)
    ok("job mode: a worker whose SSH FS RELEASE never arrives fails the job by name",
       not good and any(x.startswith("AGENT JOB FAILED job=agent-lost worker=agent-lost worker agent-lost: "
                                     "no SSH FS RELEASE") for x in lines)
       and any(x.startswith("AGENT JOB OK job=agent-a worker=agent-a") for x in lines)
       and lines[-1].startswith("AGENT JOB QUIESCENT FAILED ") and "agent-lost/agent-lost/run" in json.dumps(rows[-1]),
       lines)

    # A bind whose spawn is refused (process table full): sshd binds, the
    # spawn fails, the Binding's drop releases it, and no CHILD is printed.
    # The next session on that slot holds the third bind, not the second.
    child = "SSH SESSION CHILD pid={} spawn_right=true argv0=/bin/absd-sh fs_slot=3 spares=[4, 5] control=true\n"
    release = "SSH FS RELEASE slot=3 spares=[4, 5] closed=0\n"
    stub = types.SimpleNamespace(
        worker=lambda: (child.format(40) + 'sshd: conn 1: exec "\\"a\\""\n' + "sshd: conn 1: session child exited: Code(0)\n"
                        + release + release + 'sshd: conn 2: exec "\\"x\\"" refused: process table full\n'
                        + child.format(41) + 'sshd: conn 3: exec "\\"b\\""\n'
                        + "sshd: conn 3: session child exited: Code(0)\n" + release),
        serial=lambda: ("FSD BIND slot=3 spares=[4, 5] mounts=/home/operator:rw\n"
                        "FSD RELEASE slot=3 closed=1 scratch_removed=1\n"
                        "FSD BIND slot=3 spares=[4, 5] mounts=/home/operator:rw\n"
                        "FSD RELEASE slot=3 closed=0 scratch_removed=0\n"
                        "FSD BIND slot=3 spares=[4, 5] mounts=/home/operator:rw\n"
                        "FSD DERIVE spare=4 owner=3 mounts=/bin:ro\n"
                        "FSD RELEASE slot=3 closed=2 scratch_removed=1\n"),
        physical=lambda path: path)
    q = Quiescence(stub, settle_timeout=1, step=0.01)
    sess = q.claim(0, '"b"')
    segment = q.fsd_segment(sess) or ""
    consistent, counts = slot_counts(stub.worker(), stub.serial())
    ok("job mode: a refused spawn between two binds does not shift the next session's bind (k from releases)",
       sess is not None and sess["k"] == 3 and sess["child"]["pid"] == "41" and "FSD DERIVE spare=4 owner=3" in segment
       and FSD_RELEASE.findall(segment) == [("3", "1")] and segment.count("FSD BIND") == 1 and consistent
       and counts == {"3": {"bind": 3, "sshd_release": 3, "fsd_release": 3}}, (sess, segment, counts))

    # A write landing just before a worker's "before" image, made by a run
    # that ended in that moment: it must never be charged to the worker as
    # sole-run-window; it stays unattributed and fails the run.
    guest = FakeGuest(tscale)
    lines = []
    lead, runners = begin_workers(guest, scratch / "gap.jsonl", [(None, [worker_job("agent-a", 1000, "alpha")])],
                                  tscale=tscale, settle_timeout=3, out=lines.append, step=0.01)
    original = lead.q.begin_run

    def begin_with_gap_write(worker, job, ws, line):
        # Another run opens, writes and closes, all before this window opens.
        ghost = original("agent-ghost", "ghost", f"{JOB_ROOT}/ghost", '"/bin/true"')
        with guest.lock:
            guest.files["/home/operator/ghost-write"] = b"x"
        lead.q.end_run(ghost)
        return original(worker, job, ws, line)
    lead.q.begin_run = begin_with_gap_write
    good = runners[0].run_set(None, [worker_job("agent-a", 1000, "alpha")])
    ended = end_workers(lead, runners)
    rows = [json.loads(x) for x in (scratch / "gap.jsonl").read_text().splitlines()]
    receipt = next(x["job_receipt"] for x in rows if "job_receipt" in x)
    end_row = next(x["job_end"] for x in rows if "job_end" in x)
    ok("job mode: a foreign write at the run window's opening is not charged to the worker; it fails the run",
       good and not ended and value(value(receipt["trusted"])["write_attribution"]) == []
       and value(end_row["unattributed_writes"]) == ["/home/operator/ghost-write"]
       and lines[-1].startswith("AGENT JOB QUIESCENT FAILED ") and "no worker's evidence accounts for" in lines[-1],
       lines)

    guest = FakeGuest(tscale, refuse_conn="agent-jobs/agent-refused-")
    started = time.monotonic()
    good, lines, rows = run_job_mode("refused", [(None, [worker_job("agent-a", 1000, "alpha")]),
                                                 (None, [worker_job("agent-refused", 1000, "no")])], guest)
    ok("job mode: a connection sshd refuses is uncounted and fails only its worker, by name, without a timeout",
       not good and any(x.startswith("AGENT JOB FAILED job=agent-refused worker=agent-refused stage: worker "
                                     "agent-refused: connection refused by sshd under contention: SSH GLOBAL REFUSED")
                        for x in lines)
       and any(x.startswith("AGENT JOB OK job=agent-a worker=agent-a") for x in lines)
       and lines[-1].startswith("AGENT JOB QUIESCENT OK ") and time.monotonic() - started < 2.5, lines)

    try:
        FakeGuest(tscale).start('"/bin/absd-sh" "-c" "reboot"', b"", {"stdout": 1, "stderr": 1})
        ok("the transport refuses a machine request on its own", False, "sent")
    except ae.Failed:
        ok("the transport refuses a machine request on its own", True)
    return checks


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--job", action="append", default=[],
                    help="job file (JSON); repeatable, one boot for all; under --quiescence=job each is one worker")
    ap.add_argument("--self-test", action="store_true", help="fake guest; no SSH, no QEMU")
    ap.add_argument("--jobs-dir", default=str(here.parent / "docs" / "agent-exec-20261012" / "jobs"))
    ap.add_argument("--work")
    ap.add_argument("--receipts")
    ap.add_argument("--candidate", type=int, default=0)
    ap.add_argument("--cancel-after", type=float, help="cancel every job this many seconds after its child starts")
    ap.add_argument("--quiescence", choices=QUIESCENCE, default="session",
                    help="session: judge the quiescent census after every exec session (one job at a time); "
                         "job: run each --job file as a concurrent worker and judge the census once, at job end")
    ap.add_argument("--kernel")
    ap.add_argument("--platform", default=str(here.parent))
    ap.add_argument("--shell")
    ap.add_argument("--qemu", default="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand")
    ap.add_argument("--boot-seconds", type=int, default=3000)
    args = ap.parse_args()
    try:
        if args.self_test:
            import tempfile
            with tempfile.TemporaryDirectory(prefix="agent-job-selftest-") as scratch:
                checks = self_test(pathlib.Path(args.jobs_dir), pathlib.Path(scratch))
            print(f"AGENT JOB SELF-TEST OK checks={checks}")
            return 0
        if not (args.job and args.work and args.kernel and args.shell):
            ap.error("--job, --work, --kernel and --shell are required (or --self-test)")
        sets = [load_jobs(p) for p in args.job]
        return 0 if real_main(args, sets) else 1
    except (ae.Failed, JobError) as e:
        print(f"AGENT JOB FAILED {e}", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
