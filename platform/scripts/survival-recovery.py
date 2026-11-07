#!/usr/bin/env python3
"""Qualification-only served service faults and same-QEMU recovery, under
the recovery budget (kernel docs/service-lifecycle-20261008/RECOVERY-BUDGET.md).

The host sends controls only after each completed SSH listener record.
Each component is faulted `--faults` times in one QEMU process. With
`--expect reset` (the default, two faults) every fault is followed by a
guest reset and a further served boot, and the last boot halts on
`shutdown`. With `--expect stop` the last fault must instead end the
machine with the budget's named stop (code 20, QEMU status 83) and no
further boot. Under the owner's storage fence and decision (2026-10-19,
coordination record #63) the budget is retained but inert: only the first fault and
its reset run as before, the next boot must be the strict pre-ready
refusal, and the countdown prints `WRITABLE RECOVERY UNSUPPORTED (owner
2026-10-19; #63)`, never a pass. `--then-clear` after a clean halt boots
the same image again and clears with an orderly `reboot` (fence (a)); with
`--expect stop` the image the first fault fenced is refused again. `--then-exit0`, `--then-escalated-reboot`
and `--then-fault-at-end` each use a fresh image: the unclean end they
cause must be refused on the next boot with zero writes and the image
unchanged (fence (b)).
`--no-recovery-lines` runs the same sequence against a build that
predates the budget (the bounded negative control: it only shows the
resets kept coming). The controls are absent from the installed sshd
image and use no guest console input.

`--fault` picks the kind of service fault:
- `exit` (the default): a voluntary exit with status 7
  (`qualification-sshd-fault`, or `qualification-fsd-exit` with the ISO
  option `served-fsd-exit-test`); init names the exit.
- `hang`: the service stops making progress while still running, spinning
  in user mode (`qualification-sshd-hang`, or `qualification-fsd-hang` with
  the ISO option `served-fsd-hang-test`, after which sshd also blocks in its
  exchange with the file server).
- `block` (sshd only): sshd sleeps in the kernel forever
  (`qualification-sshd-block`).
For `hang` and `block` the control never replies (a 20 s SSH timeout is the
expected outcome) and init's liveness judgment must print
`SERVED LIVENESS STALE component=<c> idle_ticks>=60000 ...` before a
`SERVED RECOVERY BEGIN reason=... unresponsive ...` line and the same
reset or budget stop as an exit fault. Every boot checked as healthy must
have no `SERVED LIVENESS STALE` line (`SERVED LIVENESS GAP` is allowed).
The post-fault wait allows 600 s for the 60000-tick bound under TCG.

`--expect silent` is the baseline negative control for an init without the
liveness judgment: one `hang` or `block` fault, then `--silent-seconds` of
host time in which QEMU keeps running, no reset and no `SERVED RECOVERY` or
`SERVED LIVENESS` line appears, and an SSH probe does not succeed. It ends
by stopping QEMU (the guest is hung) and prints
`SERVED LIVENESS SILENT OUTAGE CONFIRMED`.
"""

import argparse
import importlib.util
import os
import pathlib
import re
import subprocess
import sys
import time


here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("served_matrix", here / "served-matrix.py")
served = importlib.util.module_from_spec(spec)
spec.loader.exec_module(served)
from e1000_rx import wait_rx_setup
import storage_fence_guest as fence_guest

# The countdown's disclosure line (coordination record #63): automatic writable
# recovery stays unsupported; the operator act (release.py recover) is the
# only writable recovery, and it is never exercised here.
UNSUPPORTED = "AUTOMATIC WRITABLE RECOVERY UNSUPPORTED (owner 2026-10-19; #63: operator act only)"
BUDGET = 3
BUDGET_STOP_STATUS = "83"
UNREAPED_STOP_STATUS = "71"
# Whether the build under test names the failed component and charges the
# ledger (set from --no-recovery-lines for the baseline negative control).
NAMED = True
LIVENESS_BOUND = 60000
# Owner decision 2026-10-19 (coordination record #63): the three-reset recovery
# budget is retained and disclosed but inert. A served recovery reset is an
# unclean end, so the strict storage fence refuses the next generation
# before readiness; writable recovery after an unclean stop is unsupported
# and the budget's multi-boot countdown cannot be exercised. The fault loop
# checks the first fault and its reset as before, then the refused
# successor, and prints the UNSUPPORTED capability line (never a pass).
CONTROL_TIMEOUT = 20

# component -> fault kind -> what the host sends, the ISO option the file
# server needs, the service's own line (and the stream it is on), and the
# reason init must name.
FAULTS = {
    "sshd": {
        "exit": {
            "command": "qualification-sshd-fault",
            "iso_option": "",
            "stream": "worker",
            "service": r"SERVED SERVICE FAULT component=sshd reason=qualification",
            # The file server sees sshd's channel close and may already have
            # been reaped when init names the fault: status 0 then, else running.
            "begin": r"SERVED RECOVERY BEGIN reason=served worker fault file_server_status=(running|0)",
        },
        "hang": {
            "command": "qualification-sshd-hang",
            "iso_option": "",
            "stream": "worker",
            "service": r"SERVED SERVICE HANG component=sshd kind=spin reason=qualification",
            "begin": r"SERVED RECOVERY BEGIN reason=served worker unresponsive file_server_status=running",
        },
        "block": {
            "command": "qualification-sshd-block",
            "iso_option": "",
            "stream": "worker",
            "service": r"SERVED SERVICE HANG component=sshd kind=block reason=qualification",
            "begin": r"SERVED RECOVERY BEGIN reason=served worker unresponsive file_server_status=running",
        },
    },
    "fsd": {
        "exit": {
            "command": "qualification-fsd-exit",
            "iso_option": "served-fsd-exit-test",
            "stream": "serial",
            "service": r"FSD QUALIFICATION EXIT status=7",
            "begin": r"SERVED RECOVERY BEGIN reason=file server ended while the worker ran file_server_status=7",
        },
        "hang": {
            "command": "qualification-fsd-hang",
            "iso_option": "served-fsd-hang-test",
            "stream": "serial",
            "service": r"FSD QUALIFICATION HANG kind=spin",
            "begin": r"SERVED RECOVERY BEGIN reason=file server unresponsive file_server_status=running",
        },
    },
}

STALE_RE = re.compile(
    r"(?m)^SERVED LIVENESS STALE component=(\w+) idle_ticks=(\d+) bound=(\d+) "
    r"sshd_idle_ticks=(\d+) fsd_idle_ticks=(\d+)$")


def fault_plan(component, fault):
    """The control plan for one component and fault kind, or ValueError."""
    try:
        return FAULTS[component][fault]
    except KeyError:
        raise ValueError(f"no qualification control for component={component} fault={fault}") from None


def is_liveness_fault(fault):
    return fault in ("hang", "block")


def liveness_record(serial, component, begin):
    """Checks a stalled boot's liveness judgment: exactly one STALE line,
    naming `component`, at or past the bound, consistent with that
    component's own idle count, and before the first line matching `begin`
    (a regex for the SERVED RECOVERY BEGIN line; None checks only that some
    BEGIN line follows). Returns the parsed STALE fields."""
    stale = list(STALE_RE.finditer(serial))
    loose = re.findall(r"(?m)^SERVED LIVENESS STALE .*$", serial)
    if len(loose) != len(stale):
        raise RuntimeError(f"malformed SERVED LIVENESS STALE line: {loose}")
    if len(stale) != 1:
        raise RuntimeError(f"expected one SERVED LIVENESS STALE line, found {len(stale)}: {loose}")
    match = stale[0]
    named, idle, bound, sshd_idle, fsd_idle = match.group(1), *map(int, match.groups()[1:])
    if named != component:
        raise RuntimeError(f"liveness named component={named}, expected {component}: {match.group(0)}")
    if bound != LIVENESS_BOUND:
        raise RuntimeError(f"liveness bound={bound}, expected {LIVENESS_BOUND}")
    if idle < LIVENESS_BOUND:
        raise RuntimeError(f"liveness judged component={named} at idle_ticks={idle} < {LIVENESS_BOUND}")
    own = sshd_idle if component == "sshd" else fsd_idle
    if own != idle:
        raise RuntimeError(f"idle_ticks={idle} differs from {component}_idle_ticks={own}")
    begin_re = begin if begin is not None else r"SERVED RECOVERY BEGIN .*"
    first_begin = re.search(rf"(?m)^{begin_re}$", serial)
    if not first_begin:
        raise RuntimeError(f"no recovery line matching {begin_re!r} after the liveness judgment")
    if match.start() > first_begin.start():
        raise RuntimeError("SERVED RECOVERY BEGIN precedes SERVED LIVENESS STALE")
    any_begin = re.search(r"(?m)^SERVED RECOVERY BEGIN ", serial)
    if any_begin.start() < match.start():
        raise RuntimeError("a SERVED RECOVERY BEGIN line precedes SERVED LIVENESS STALE")
    return {"component": named, "idle_ticks": idle, "bound": bound,
            "sshd_idle_ticks": sshd_idle, "fsd_idle_ticks": fsd_idle}


def no_stale(serial, what):
    """A healthy boot never judges a service stale."""
    stale = re.findall(r"(?m)^SERVED LIVENESS STALE .*$", serial)
    if stale:
        raise RuntimeError(f"{what} has a liveness judgment: {stale}")
    gaps = re.findall(r"(?m)^SERVED LIVENESS GAP ticks=(\d+)$", serial)
    return [int(gap) for gap in gaps]


def control_without_reply(client, key, command):
    """Sends a control that never replies. A timeout or a failed command is
    expected; a successful reply is a failure."""
    try:
        sent = ssh(client, key, command, timeout=CONTROL_TIMEOUT)
    except subprocess.TimeoutExpired:
        return "timeout"
    if sent.returncode == 0:
        raise RuntimeError(f"{command} returned a successful SSH command")
    return f"returncode={sent.returncode}"


class RecoveryTarget(served.ServedTarget):
    def sshd_iso(self, regenerate=False):
        options = "net fsd served"
        # survival-pre-ready.py subclasses this target without a fault: the
        # exit plan is the default there, as for --fault.
        extra = fault_plan(self.component, getattr(self, "fault", "exit"))["iso_option"]
        if extra:
            options += " " + extra
        return self.iso(0, self.sshd_elf, options=options, server=self.fsd_elf)


def ssh(client, key, command, timeout=90):
    argv = client.base(key)
    argv[-1:-1] = ["-o", "IdentityAgent=none"]
    env = os.environ.copy()
    env.pop("SSH_AUTH_SOCK", None)
    env.pop("SSH_AGENT_PID", None)
    return subprocess.run(argv + [command], capture_output=True, timeout=timeout, env=env)


def boot_parts(target):
    raw = target.log.read_bytes()
    serial = raw.decode(errors="replace").split("ABSD KERNEL BOOT\n")[1:]
    captured = served.captured_all(raw)
    assert len(serial) == len(captured), (len(serial), len(captured))
    return list(zip(serial, captured))


def ready(target, index, runner_pid, timeout=300):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if target.proc.poll() is not None:
            raise RuntimeError("QEMU ended before the next served state")
        if target.proc.pid != runner_pid:
            raise RuntimeError("host relaunched QEMU instead of a guest reset")
        parts = boot_parts(target)
        if len(parts) > index + 1:
            raise RuntimeError("an unexpected additional guest reset occurred")
        if len(parts) > index:
            serial, worker = parts[index]
            fsd_id = re.search(r"(?m)^FSD CAPACITY boot=([0-9a-f]{32}) ", serial)
            ssh_id = re.search(r"(?m)^SERVED CAPACITY boot=([0-9a-f]{32}) ", worker)
            if ("FSD READY " in serial and
                    re.search(r"(?m)^SSH LISTENING port=\d+ authorized_keys=\d+ preauth_per_source=2$", worker)
                    and fsd_id and ssh_id):
                if fsd_id.group(1) != ssh_id.group(1):
                    raise RuntimeError("FSD/SSH boot identities differ")
                wait_rx_setup(target.serial, lambda: target.proc.poll() is None, deadline)
                current = boot_parts(target)
                if len(current) != index + 1:
                    raise RuntimeError("guest changed generation during receive setup")
                return fsd_id.group(1), serial, worker
        time.sleep(0.2)
    raise RuntimeError(f"served boot {index + 1} did not reach a complete ready record")


def current_boot(target, index, runner_pid):
    if target.proc.poll() is not None or target.proc.pid != runner_pid:
        raise RuntimeError("the qualified QEMU process is no longer running")
    parts = boot_parts(target)
    if len(parts) != index + 1:
        raise RuntimeError(f"expected boot {index + 1}, found {len(parts)} boots")
    return parts[index]


def committed_tree(target):
    for _ in range(20):
        try:
            return target.tree()
        except served.ssh_absd.absd_fs.Refused:
            time.sleep(0.5)
    raise RuntimeError("host image reader never found a committed filesystem state")


def recovery_lines(serial, worker, streak, previous):
    """The ledger the file server charged before READY and the streak sshd
    advertised before listening, both for this boot."""
    fsd = re.search(r"(?m)^FSD RECOVERY seq=(\d+) streak=(\d+) previous=(\w+)$", serial)
    if not fsd:
        raise RuntimeError(f"no FSD RECOVERY line before READY: {serial[-1500:]}")
    if int(fsd.group(2)) != streak or fsd.group(3) != previous:
        raise RuntimeError(f"ledger charged streak={fsd.group(2)} previous={fsd.group(3)}, "
                           f"expected streak={streak} previous={previous}")
    if serial.index("FSD RECOVERY ") > serial.index("FSD READY "):
        raise RuntimeError("the ledger was charged after READY")
    ssh = re.search(r"(?m)^SSH RECOVERY streak=(\d+)$", worker)
    if not ssh or int(ssh.group(1)) != streak:
        raise RuntimeError(f"sshd advertised {ssh.group(0) if ssh else 'no streak'}, expected {streak}")
    if worker.index("SSH RECOVERY ") > worker.index("SSH LISTENING "):
        raise RuntimeError("the streak was advertised after the listener record")
    return int(fsd.group(1))


def recover_record(target, index, session_pid, expect_stop):
    serial, worker = boot_parts(target)[index]
    needed = ["SERVED RECOVERY BEGIN "]
    if expect_stop:
        needed += [f"SERVED RECOVERY ESCALATED reason=recovery_budget_exhausted streak={BUDGET} budget={BUDGET} ",
                   "outcome=stop code=20", "MACHINE STOP code=20"]
        forbidden = ["SERVED RECOVERY RESET ", "MACHINE RECOVER RESET"]
    else:
        needed += ["SERVED RECOVERY RESET ", "SERVED RECOVERY CENSUS processes=", "MACHINE RECOVER RESET pid=1"]
        forbidden = ["SERVED RECOVERY ESCALATED "]
    for marker in needed:
        if marker not in serial:
            raise RuntimeError(f"boot {index + 1} lacks {marker}: {serial[-1500:]}")
    for marker in forbidden:
        if marker in serial:
            raise RuntimeError(f"boot {index + 1} has {marker} where it must not: {serial[-1500:]}")
    if "SERVED RECOVERY REFUSED" in serial:
        raise RuntimeError(f"recovery was refused: {serial[-1500:]}")
    plan = fault_plan(target.component, target.fault)
    if NAMED and not re.search(rf"(?m)^{plan['begin']}$", serial):
        raise RuntimeError(f"the {target.component} {target.fault} fault is not named: {serial[-1500:]}")
    stream = serial if plan["stream"] == "serial" else worker
    if not re.search(rf"(?m)^{plan['service']}$", stream):
        raise RuntimeError(f"the {target.component} qualification {target.fault} line is absent")
    if is_liveness_fault(target.fault):
        stale = liveness_record(serial, target.component, plan["begin"] if NAMED else None)
        print(f"RECOVERY LIVENESS component={target.component} fault={target.fault} boot={index + 1} "
              f"idle_ticks={stale['idle_ticks']} sshd_idle_ticks={stale['sshd_idle_ticks']} "
              f"fsd_idle_ticks={stale['fsd_idle_ticks']}", flush=True)
    else:
        no_stale(serial, f"boot {index + 1} (exit fault)")
    if not expect_stop:
        records = re.findall(
            r"(?m)^SERVED RECOVERY PROCESS pid=(\d+) parent=(\d+) state=(\w+) handles=(\d+) cpu=(\w+)$",
            serial,
        )
        if not records:
            raise RuntimeError("pre-reset process census is missing")
        matching = [record for record in records if int(record[0]) == session_pid]
        reaped = re.search(rf"(?m)^(?:SERVED RECOVERY REAP|INIT ORPHAN REAPED) pid={session_pid}(?: |$)", serial)
        if not matching and not reaped:
            raise RuntimeError("active session has neither pre-reset residue nor terminal reap evidence")
        print(f"RECOVERY RESIDUE component={target.component} boot={index + 1} "
              f"session_pid={session_pid} session_records={matching} all={records}", flush=True)
    if "SSH LISTENING" not in worker:
        raise RuntimeError("fault occurred before listener readiness")


def active_session(client, key, target, index, runner_pid):
    """Starts a long-running session and returns (process, child pid)."""
    active_argv = client.base(key)
    active_argv[-1:-1] = ["-o", "IdentityAgent=none"]
    env = os.environ.copy()
    env.pop("SSH_AUTH_SOCK", None)
    env.pop("SSH_AGENT_PID", None)
    before = len(re.findall(r"SSH SESSION CHILD pid=(\d+)", current_boot(target, index, runner_pid)[1]))
    active = subprocess.Popen(active_argv + ["/bin/sshtest sleep 600000"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    deadline = time.monotonic() + 60
    session_pid = None
    while time.monotonic() < deadline:
        children = re.findall(r"SSH SESSION CHILD pid=(\d+)", current_boot(target, index, runner_pid)[1])
        if len(children) > before:
            session_pid = int(children[-1])
            break
        time.sleep(0.2)
    if session_pid is None:
        active.kill()
        raise RuntimeError("active session child did not start")
    if active.poll() is not None:
        raise RuntimeError("active session ended before the service fault")
    return active, session_pid


def end_session(active):
    if active.poll() is None:
        active.kill()
    active.communicate(timeout=30)


def serve_and_check(target, client, key, index, runner_pid, marker, args, streak, previous):
    """Boot `index` is ready: check its ledger lines, serve an authenticated
    command, write and read back the synced marker, and check the disk."""
    boot_id, serial, worker = ready(target, index, runner_pid)
    no_stale(serial, f"healthy boot {index + 1}")
    if args.recovery_lines:
        recovery_lines(serial, worker, streak, previous)
    current_boot(target, index, runner_pid)
    probe = ssh(client, key, "/bin/fsd-probe read /etc/motd")
    current_boot(target, index, runner_pid)
    if probe.returncode != 0 or b"read: " not in probe.stdout:
        raise RuntimeError(f"boot {index + 1} did not serve an authenticated command: {probe.stderr!r}")
    if index > 0:
        check = ssh(client, key, "/bin/cat /home/operator/recovery-marker")
        if check.returncode != 0 or check.stdout != marker:
            raise RuntimeError("synced marker did not survive the machine reset")
    # Every served generation writes, and the write is committed: a
    # generation that only reads after a reset proves nothing about
    # writes (audit E1). Boot 1 also leaves the marker the later boots
    # read back.
    name = "recovery-marker" if index == 0 else f"recovery-marker-boot{index + 1}"
    written = ssh(client, key, f"/bin/fsd-probe write /home/operator/{name} 32")
    if written.returncode != 0 or b"write: 32 bytes" not in written.stdout:
        raise RuntimeError(f"boot {index + 1} sync marker write failed: {written.stderr!r}")
    tree = committed_tree(target)
    if tree.get(f"/home/operator/{name}") != marker:
        raise RuntimeError(f"boot {index + 1} completed-sync marker not visible in committed image")
    # No scratch of an earlier generation is on the committed disk after a
    # reset: the file server sweeps /tmp before it serves (audit C1, E1).
    if index > 0:
        stale = sorted(path for path in tree if path.startswith("/tmp/"))
        if stale:
            raise RuntimeError(f"pre-reset scratch survived the reset: {stale}")
    if args.recovery_lines:
        # The ledger is on the committed disk, charged for this boot, and
        # no session can read it: /var/state is not a session mount.
        ledger = tree.get("/var/state/recovery", b"").decode(errors="replace")
        if f" boot={boot_id} streak={streak} " not in ledger:
            raise RuntimeError(f"committed ledger does not name this boot and streak: {ledger!r}")
        peek = ssh(client, key, "/bin/cat /var/state/recovery")
        if peek.returncode == 0 or b"streak=" in peek.stdout or not peek.stderr.strip():
            raise RuntimeError(f"a session could read the recovery ledger: {peek.stdout!r} {peek.stderr!r}")
        print(f"RECOVERY LEDGER NOT A SESSION PATH boot={index + 1} refused={peek.stderr.strip()!r}", flush=True)
        # The streak is in both services' logs, which sessions can read.
        fsd_log = tree.get("/var/log/fsd", b"").decode(errors="replace")
        sshd_log = tree.get("/var/log/sshd", b"").decode(errors="replace")
        if f"FSD RECOVERY seq=" not in fsd_log or f" streak={streak} previous=" not in fsd_log:
            raise RuntimeError("the charged streak is not in /var/log/fsd")
        if f"SSH RECOVERY streak={streak}" not in sshd_log:
            raise RuntimeError("the advertised streak is not in /var/log/sshd")
    gaps = no_stale(current_boot(target, index, runner_pid)[0], f"healthy boot {index + 1}")
    if gaps:
        print(f"RECOVERY LIVENESS GAP boot={index + 1} ticks={gaps}", flush=True)
    return boot_id


def new_target(args, component, work):
    target = RecoveryTarget.__new__(RecoveryTarget)
    target.kernel = pathlib.Path(args.kernel).resolve()
    target.root = pathlib.Path(args.platform).resolve()
    target.qemu = args.qemu
    target.shell = target.root / "commands/absd-sh"
    target.boot_seconds = 3600
    target.proc, target.boots, target.port = None, 0, None
    target.component = component
    target.fault = args.fault
    target.sshd_elf = pathlib.Path(args.sshd_controls).resolve()
    target.fsd_elf = target.root / "absd-fsd.elf"
    target.case_root = work
    return target


def first_start(target, key, work):
    """Builds an image in `work` and boots it served in a new QEMU (guest
    resets allowed); returns (client, runner pid)."""
    target.setup(work, key.with_suffix(".pub").read_text())
    os.environ["ABSD_QEMU_REBOOT"] = "allow"
    try:
        info = target.start()
    finally:
        os.environ.pop("ABSD_QEMU_REBOOT", None)
    client = served.sm.Client(work, target.port)
    client.trust(info["public"])
    return client, target.proc.pid


def fresh_start(target, key, name):
    """A new image for one fence case. Its first served boot has no history
    and is admitted; an image an unclean end has fenced is never reused."""
    target.stop()
    work = target.case_root / name
    work.mkdir()
    return first_start(target, key, work)


def kernel_reason(target):
    declared = getattr(target, "storage_fence", None)
    if declared:
        raise RuntimeError(f"the successor refusal predicates cover undeclared served boots only "
                           f"(storage-fence={declared})")
    return "not_declared"


def refused_in_place(target, runner_pid, index, timeout=300):
    """The same-QEMU successor of an unfinalized end (a guest reset after
    an escalated reboot or a fault): QEMU ends with status 7 after exactly
    `index + 1` boots, and boot `index + 1` is the strict pre-ready refusal
    with zero block writes, flushes and errors. A ready or writable
    successor, a missing line or a further boot raises RuntimeError."""
    if target.proc is None or target.proc.pid != runner_pid:
        raise RuntimeError("the qualified QEMU process is not the one that took the unclean end")
    status = target.status(timeout)
    return fence_guest.require_successor_in_log(target.log.read_bytes(), status, index, kernel_reason(target))


MARKER_PATH = "/home/operator/recovery-marker"


def marker_on_image(image, marker):
    """Owner fence (d), and the durability check the writable successor
    used to make: the refused image, read by the host's own filesystem
    reader (read-only), still holds the synced marker byte for byte."""
    absd_fs = served.ssh_absd.absd_fs
    region = absd_fs.fs_region(image, served.ssh_absd.DEVICE_SECTORS)
    selected = absd_fs.select(region)
    record = absd_fs.tree(region, selected).get(MARKER_PATH)
    if record is None or not served.ssh_absd.record_is_file(region, selected, record):
        raise RuntimeError(f"the refused image has no {MARKER_PATH}: the synced marker was lost")
    if absd_fs.content(region, selected, record) != marker:
        raise RuntimeError("the refused image's synced marker differs from what was written")


def refused_restart(target, name, marker):
    """Replaces restart() after an unfinalized end: the same image booted
    cold in a new QEMU is refused before readiness, with zero writes and
    flushes and the image sha256 unchanged (refused_cold_boot); then the
    unchanged image is read on the host and must still hold the synced
    marker that boot 1 wrote (marker_on_image)."""
    refusal = fence_guest.refused_cold_boot(target, os.environ.get("ABSD_BLOCK_ATTACH", "ata"), name, served=True)
    fence_guest.require_served_successor_refusal(pathlib.Path(refusal["log"]).read_bytes(), refusal["status"])
    marker_on_image(target.image, marker)
    print(f"RECOVERY MARKER EXTRACTED OK case={name} path={MARKER_PATH} bytes={len(marker)} reader=host_read_only",
          flush=True)
    return refusal


class Outcome:
    """Honest case accounting: OK (exit 0) only when every planned case ran
    with its fence expectation. A capability the fence makes unexercisable
    is printed as UNSUPPORTED and is never counted as a case or a pass."""

    def __init__(self, planned):
        self.planned, self.done, self.unsupported_lines = list(planned), [], []

    def ran(self, case):
        self.done.append(case)

    def unsupported(self, case, detail):
        line = f"{UNSUPPORTED} case={case} {detail}"
        print(line, flush=True)
        self.unsupported_lines.append(line)

    def verdict(self):
        if sorted(self.done) != sorted(self.planned):
            print(f"SERVED RECOVERY MATRIX FAILED: case count planned={self.planned} ran={self.done}",
                  file=sys.stderr, flush=True)
            return 1
        for line in self.unsupported_lines:
            print(line, flush=True)
        print(f"SERVED RECOVERY MATRIX OK cases={len(self.done)}", flush=True)
        return 0


FOLLOW_ONS = (("then_exit0", "exit0"), ("then_escalated_reboot", "escalated-reboot"),
              ("then_fault_at_end", "fault-at-end"))


def components(args):
    return ("sshd", "fsd") if args.component == "both" else (args.component,)


def planned_cases(args):
    cases = []
    for component in components(args):
        if args.expect == "silent":
            cases.append(f"{component}:silent")
            continue
        cases.append(f"{component}:fault-loop")
        if args.then_clear:
            cases.append(f"{component}:" + ("clear-after-stop" if args.expect == "stop" else "clear-after-clean-halt"))
        cases += [f"{component}:{name}" for flag, name in FOLLOW_ONS if getattr(args, flag)]
    return cases


def one_case(args, component, key, outcome):
    work = pathlib.Path(args.work) / component
    work.mkdir(parents=True, exist_ok=False)
    target = new_target(args, component, work)
    marker = bytes(i % 251 for i in range(32))
    try:
        if args.expect == "silent":
            client, runner_pid = first_start(target, key, work)
            command = fault_plan(component, args.fault)["command"]
            silent_case(args, target, client, key, runner_pid, marker, component, args.fault, command)
            outcome.ran(f"{component}:silent")
            return
        fault_loop(args, component, target, key, work, marker, outcome)
        outcome.ran(f"{component}:fault-loop")
        if args.then_clear:
            if args.expect == "stop":
                # The first fault's unfinalized reset fenced the image; the
                # budget stop it once preceded is unreachable (UNSUPPORTED).
                clear_case(args, target, None, key, marker, 1)
                outcome.ran(f"{component}:clear-after-stop")
            else:
                client = clean_halt_predecessor(args, target, key, marker)
                clear_case(args, target, client, key, marker, 0)
                outcome.ran(f"{component}:clear-after-clean-halt")
        if args.then_exit0:
            exit0_case(args, target, key, marker)
            outcome.ran(f"{component}:exit0")
        if args.then_escalated_reboot:
            escalated_reboot_case(args, target, key, marker)
            outcome.ran(f"{component}:escalated-reboot")
        if args.then_fault_at_end:
            fault_at_end_case(args, target, key, marker)
            outcome.ran(f"{component}:fault-at-end")
    finally:
        target.stop()


def fault_loop(args, component, target, key, work, marker, outcome):
    """The first served fault under the owner's storage fence (decision
    2026-10-19, coordination record #63). The first boot serves, the fault is sent
    with a session running, and init names it and spends one recovery reset
    exactly as before (recover_record: BEGIN, census, RESET, MACHINE RECOVER
    RESET, no escalation, the session's residue or reap). The reset is not
    finalized, so the next boot in the same QEMU is the strict pre-ready
    refusal (status 7, no FSD READY or SSH LISTENING, zero writes, flushes
    and errors, no further reset), and a cold retry of the same image is
    refused with the image unchanged. The budget's multi-boot countdown
    (--faults > 1, --expect stop) cannot be exercised: UNSUPPORTED."""
    client, runner_pid = first_start(target, key, work)
    fault = args.fault
    hangs = is_liveness_fault(fault)
    command = fault_plan(component, fault)["command"]
    # A hang is judged only after the 60000-tick bound, then reset and boot
    # under TCG on a loaded host.
    after_fault = 600 if hangs else 300
    serve_and_check(target, client, key, 0, runner_pid, marker, args, 0, "none")
    active, session_pid = active_session(client, key, target, 0, runner_pid)
    try:
        if hangs:
            sent = control_without_reply(client, key, command)
            print(f"RECOVERY FAULT SENT component={component} fault={fault} boot=1 control={sent}", flush=True)
        else:
            triggered = ssh(client, key, command)
            if triggered.returncode == 0:
                raise RuntimeError("fault control returned a successful SSH command")
        refused_in_place(target, runner_pid, 1, timeout=after_fault)
    finally:
        end_session(active)
    recover_record(target, 0, session_pid, False)
    refused_restart(target, f"{component}-fault-retry", marker)
    print(f"SERVED RECOVERY FIRST FAULT REFUSED OK component={component} fault={fault} resets=1 successor=refused "
          f"status=7 block_writes=0 block_flushes=0 image_unchanged=true runner_pid={runner_pid}", flush=True)
    outcome.unsupported(f"{component}:fault-loop", f"budget={BUDGET} countdown=not_exercisable "
                        f"faults_requested={args.faults} expect={args.expect}")


def clean_halt_predecessor(args, target, key, marker):
    """Owner fence (a) for clear_case, since the fault loop now ends refused: a
    fresh image serves once, writes the synced marker, and halts on
    `shutdown` with a finalized orderly end (status 3)."""
    client, runner_pid = fresh_start(target, key, "clear")
    serve_and_check(target, client, key, 0, runner_pid, marker, args, 0, "none")
    halted = ssh(client, key, "shutdown")
    if halted.returncode != 0:
        raise RuntimeError(f"shutdown of the clean predecessor failed: {halted.stderr!r}")
    status = target.status(300)
    if status != "3":
        raise RuntimeError(f"the clean predecessor did not halt cleanly: {status}")
    serial = boot_parts(target)[0][0]
    if "FSD FINALIZED boot=" not in serial or "SERVED SHUTDOWN FINALIZED status=0" not in serial:
        raise RuntimeError(f"the clean predecessor's end was not finalized: {serial[-1500:]}")
    print("RECOVERY CLEAN PREDECESSOR OK status=3 finalized=yes", flush=True)
    return client


def silent_case(args, target, client, key, runner_pid, marker, component, fault, command):
    """Baseline negative control for an init without the liveness judgment:
    after one hang the guest stays up, unreset and unserved for
    `--silent-seconds` of host time. QEMU is then stopped (the guest is
    hung and cannot be halted from inside)."""
    plan = fault_plan(component, fault)
    serve_and_check(target, client, key, 0, runner_pid, marker, args, 0, "none")
    outcome = control_without_reply(client, key, command)
    print(f"RECOVERY FAULT SENT component={component} fault={fault} boot=1 control={outcome}", flush=True)
    started = time.monotonic()
    deadline = started + args.silent_seconds
    service_seen = False
    while True:
        # current_boot fails if QEMU ended, was relaunched, or reset.
        serial, worker = current_boot(target, 0, runner_pid)
        for line in ("SERVED RECOVERY", "SERVED LIVENESS"):
            found = re.findall(rf"(?m)^{line}.*$", serial)
            if found:
                raise RuntimeError(f"the baseline init reacted to the hang: {found}")
        stream = serial if plan["stream"] == "serial" else worker
        service_seen = service_seen or bool(re.search(rf"(?m)^{plan['service']}$", stream))
        if time.monotonic() >= deadline:
            break
        time.sleep(1)
    if not service_seen:
        raise RuntimeError(f"the {component} qualification {fault} line is absent")
    try:
        probe = ssh(client, key, "/bin/pwd", timeout=CONTROL_TIMEOUT)
    except subprocess.TimeoutExpired:
        probe_outcome = "timeout"
    else:
        if probe.returncode == 0:
            raise RuntimeError(f"the hung guest still served a command: {probe.stdout!r}")
        probe_outcome = f"returncode={probe.returncode}"
    serial, _ = current_boot(target, 0, runner_pid)
    if re.search(r"(?m)^SERVED (RECOVERY|LIVENESS)", serial):
        raise RuntimeError("the baseline init reacted to the hang during the probe")
    seconds = int(time.monotonic() - started)
    print(f"SERVED LIVENESS SILENT OUTAGE CONFIRMED component={component} fault={fault} "
          f"seconds={seconds} probe={probe_outcome} runner_pid={runner_pid}", flush=True)
    target.stop()


def restart(target):
    """Boots the same image again in a new QEMU process."""
    os.environ["ABSD_QEMU_REBOOT"] = "allow"
    try:
        target.start(expect_sweep=True)
    finally:
        os.environ.pop("ABSD_QEMU_REBOOT", None)
    return target.proc.pid


def clear_case(args, target, client, key, marker, carried):
    """After a clean halt (owner fence (a), carried 0) the image serves
    again, an orderly `reboot` keeps the streak clear, and the next boot
    starts at zero. After an unfinalized end (carried > 0: the fault loop's
    first reset; the budget's terminal stop is no longer reachable) the
    same image is refused before readiness (fence (b)); nothing clears it."""
    if carried:
        refused_restart(target, "clear-after-stop-refused", marker)
        print(f"RECOVERY STREAK CLEAR REFUSED OK carried={carried} successor=refused status=7 "
              f"block_writes=0 block_flushes=0 image_unchanged=true", flush=True)
        return
    runner_pid = restart(target)
    serve_and_check(target, client, key, 0, runner_pid, marker, args, carried, "failed" if carried else "ended")
    rebooted = ssh(client, key, "reboot")
    if rebooted.returncode != 0:
        raise RuntimeError(f"reboot request failed: {rebooted.stderr!r}")
    serve_and_check(target, client, key, 1, runner_pid, marker, args, 0, "ended")
    serial = boot_parts(target)[0][0]
    if "SERVED SHUTDOWN action=restart " not in serial or "MACHINE RESTART ARMED" not in serial:
        raise RuntimeError(f"the orderly restart is not recorded: {serial[-1500:]}")
    finalized(serial)
    halted = ssh(client, key, "shutdown")
    if halted.returncode != 0:
        raise RuntimeError(f"shutdown after the clear failed: {halted.stderr!r}")
    status = target.status(300)
    if status != "3":
        raise RuntimeError(f"boot after the clear did not halt cleanly: {status}")
    print(f"RECOVERY STREAK CLEAR OK carried={carried} cleared_by=reboot", flush=True)


def finalized(serial):
    """init's verdict was recorded by the file server's finalize run, after
    the drain and before the restart was armed or the halt taken."""
    if "FSD FINALIZED boot=" not in serial or "SERVED SHUTDOWN FINALIZED status=0" not in serial:
        raise RuntimeError(f"the orderly end was not finalized: {serial[-1500:]}")
    if not (serial.index("SERVED SHUTDOWN action=") < serial.index("FSD FINALIZED boot=")
            < serial.index("SERVED SHUTDOWN FINALIZED status=0")):
        raise RuntimeError("finalize happened out of order")
    if "MACHINE RESTART ARMED" in serial and serial.index("SERVED SHUTDOWN FINALIZED") > serial.index("MACHINE RESTART ARMED"):
        raise RuntimeError("the restart was armed before the finalize verdict")


def shell_session(client, key, target, index, runner_pid, line):
    """A shell session running `line` as its child: both appear as session
    children. Returns the ssh process."""
    argv = client.base(key)
    argv[-1:-1] = ["-o", "IdentityAgent=none"]
    env = os.environ.copy()
    env.pop("SSH_AUTH_SOCK", None)
    env.pop("SSH_AGENT_PID", None)
    before = len(re.findall(r"SSH SESSION CHILD pid=(\d+)", current_boot(target, index, runner_pid)[1]))
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    proc.stdin.write(line.encode() + b"\n")
    proc.stdin.flush()
    deadline = time.monotonic() + 60
    shell_pid = None
    while time.monotonic() < deadline:
        serial, worker = current_boot(target, index, runner_pid)
        children = re.findall(r"SSH SESSION CHILD pid=(\d+)", worker)
        if shell_pid is None and len(children) > before:
            shell_pid = children[-1]
        # The shell's own child shows in the kernel's spawn line.
        if shell_pid is not None and re.search(rf"(?m)^SPAWN OK pid=\d+ parent={shell_pid} ", serial):
            return proc
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("the shell session did not start its child")


def escalated_reboot_case(args, target, key, marker):
    """A `reboot` whose orderly end escalates after the file server stopped
    (a shell killed without END leaves a child init cannot reap, audit D2):
    sshd recorded the request and the file server committed, but init never
    finalized, so the next generation (same QEMU, after the reset) is
    refused before readiness with zero writes (owner fence (b)), and a cold
    retry of the same image is refused with the image unchanged."""
    client, runner_pid = fresh_start(target, key, "escalated-reboot")
    serve_and_check(target, client, key, 0, runner_pid, marker, args, 0, "none")
    session = shell_session(client, key, target, 0, runner_pid, "/bin/sshtest sleep 600000")
    try:
        killed = ssh(client, key, "qualification-kill-shells")
        if killed.returncode == 0:
            raise RuntimeError("the kill-shells control returned a successful SSH command")
        time.sleep(3)
        rebooted = ssh(client, key, "reboot")
        if rebooted.returncode != 0:
            raise RuntimeError(f"reboot request failed: {rebooted.stderr!r}")
        refused_in_place(target, runner_pid, 1)
    finally:
        end_session(session)
    serial = boot_parts(target)[0][0]
    needed = ["SERVED SHUTDOWN UNREAPED adopted_child_residue=true",
              "SERVED SHUTDOWN ESCALATED requested=restart reason=unreaped outcome=recovery_reset code=17",
              "FSD STOPPED "]
    for marker_line in needed:
        if marker_line not in serial:
            raise RuntimeError(f"escalated reboot lacks {marker_line}: {serial[-1500:]}")
    if "FSD FINALIZED" in serial or "SERVED SHUTDOWN FINALIZED" in serial:
        raise RuntimeError("an escalated end must not be finalized")
    refused_restart(target, "escalated-reboot-retry", marker)
    print("RECOVERY ESCALATED REBOOT REFUSED OK successor=refused status=7 block_writes=0 block_flushes=0 "
          "image_unchanged=true", flush=True)


def fault_at_end_case(args, target, key, marker):
    """sshd faults right after writing its requested-end fact: init sees a
    fault, not a request, and resets without finalizing, so the next
    generation (same QEMU) is refused before readiness with zero writes
    (owner fence (b)), and a cold retry is refused with the image unchanged."""
    client, runner_pid = fresh_start(target, key, "fault-at-end")
    serve_and_check(target, client, key, 0, runner_pid, marker, args, 0, "none")
    armed = ssh(client, key, "qualification-sshd-fault-at-end")
    if armed.returncode == 0:
        raise RuntimeError("the fault-at-end control returned a successful SSH command")
    rebooted = ssh(client, key, "reboot")
    if rebooted.returncode != 0:
        raise RuntimeError(f"reboot request failed: {rebooted.stderr!r}")
    refused_in_place(target, runner_pid, 1)
    serial, worker = boot_parts(target)[0]
    if "SERVED SERVICE FAULT component=sshd reason=qualification_at_end" not in worker:
        raise RuntimeError("the fault after the end fact is absent")
    if not re.search(r"(?m)^SERVED RECOVERY BEGIN reason=served worker fault file_server_status=(running|0)$", serial):
        raise RuntimeError(f"the fault after the end fact did not take the fault path: {serial[-1500:]}")
    if "SERVED SHUTDOWN action=" in serial or "FSD FINALIZED" in serial:
        raise RuntimeError("a fault after the end fact must not be an orderly end")
    refused_restart(target, "fault-at-end-retry", marker)
    print("RECOVERY FAULT AT END REFUSED OK successor=refused status=7 block_writes=0 block_flushes=0 "
          "image_unchanged=true", flush=True)


def exit0_case(args, target, key, marker):
    """An unexpected sshd exit 0 with a session running: init reads it as
    a halt request and stops with code 17 (as before) without finalizing;
    the same image booted again is refused before readiness with zero
    writes and the image unchanged (owner fence (b))."""
    client, runner_pid = fresh_start(target, key, "exit0")
    serve_and_check(target, client, key, 0, runner_pid, marker, args, 0, "none")
    boot_id = ready(target, 0, runner_pid)[0]
    active, _ = active_session(client, key, target, 0, runner_pid)
    try:
        exited = ssh(client, key, "qualification-sshd-exit")
        if exited.returncode == 0:
            raise RuntimeError("the exit control returned a successful SSH command")
        status = target.status(300)
        if status != UNREAPED_STOP_STATUS:
            raise RuntimeError(f"unexpected exit 0 with a session did not stop with code 17: status {status}")
    finally:
        end_session(active)
    # The pair is incomplete on disk: the file server reached its orderly
    # end (its fact names this boot) and sshd asked for nothing (its end
    # fact is still all zero), so the next charge must count a failure.
    serial = boot_parts(target)[0][0]
    if "FSD STOPPED " not in serial:
        raise RuntimeError(f"the file server did not reach its orderly end: {serial[-1500:]}")
    tree = committed_tree(target)
    stopped = tree.get("/var/state/facts/served-stopped", b"")
    ended = tree.get("/var/state/facts/served-end", b"")
    if not stopped.startswith(f"boot={boot_id}".encode()):
        raise RuntimeError(f"the stopped fact does not name this boot: {stopped!r}")
    if ended.strip(b"\0") != b"":
        raise RuntimeError(f"an end fact exists after an unexpected exit 0: {ended!r}")
    refused_restart(target, "exit0-successor", marker)
    print("RECOVERY EXIT0 REFUSED OK successor=refused status=7 block_writes=0 block_flushes=0 "
          "image_unchanged=true", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--sshd-controls", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--qemu", default="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand")
    parser.add_argument("--component", choices=("sshd", "fsd", "both"), default="both")
    parser.add_argument("--faults", type=int, default=2,
                        help="recorded only: under the owner storage fence (2026-10-19, #63) one fault is "
                             "injected, its reset's successor is refused, and the budget's countdown is "
                             "reported UNSUPPORTED (default 2)")
    parser.add_argument("--expect", choices=("reset", "stop", "silent"), default="reset",
                        help="reset and stop are recorded only (the countdown is UNSUPPORTED: the first "
                             "reset's successor is refused); silent is the baseline init without liveness, "
                             "where the fault does nothing at all")
    parser.add_argument("--fault", choices=("exit", "hang", "block"), default="exit",
                        help="service fault kind: voluntary exit 7, user-mode spin, or kernel sleep (sshd only)")
    parser.add_argument("--silent-seconds", type=int, default=240,
                        help="host seconds the --expect silent control watches the hung guest (default 240)")
    parser.add_argument("--no-recovery-lines", dest="recovery_lines", action="store_false",
                        help="do not require the ledger lines (a build before the recovery budget)")
    parser.add_argument("--then-clear", action="store_true",
                        help="afterwards: after the fault loop the same image is refused (fence (b)); the "
                             "streak-clearing reboot runs on a fresh image after a clean halt (fence (a))")
    parser.add_argument("--then-exit0", action="store_true",
                        help="afterwards show an unexpected sshd exit 0 does not clear the streak")
    parser.add_argument("--then-escalated-reboot", action="store_true",
                        help="afterwards show a reboot that escalates after the file server stopped does not clear it")
    parser.add_argument("--then-fault-at-end", action="store_true",
                        help="afterwards show an sshd fault after its end fact does not clear it")
    args = parser.parse_args()
    global NAMED
    NAMED = args.recovery_lines
    if args.fault == "block" and args.component != "sshd":
        parser.error("--fault block exists only for --component sshd (the file server has no block control)")
    if args.expect == "silent":
        if not is_liveness_fault(args.fault):
            parser.error("--expect silent needs --fault hang or block")
        if args.component != "sshd":
            parser.error("--expect silent runs against a baseline init that has no served-fsd-hang-test "
                         "option: only --component sshd can be hung there")
        if args.then_clear or args.then_exit0 or args.then_escalated_reboot or args.then_fault_at_end:
            parser.error("--expect silent ends by stopping the hung guest; no follow-on cases")
        if args.silent_seconds < 1:
            parser.error("--silent-seconds must be at least 1")
        args.faults = 1
    if args.faults < 1:
        parser.error("--faults must be at least 1")
    if args.expect == "stop" and args.faults != BUDGET + 1:
        parser.error(f"--expect stop needs --faults {BUDGET + 1}: three resets, then the fourth failure stops")
    key = pathlib.Path(args.key).resolve()
    if not key.is_file() or not key.with_suffix(".pub").is_file():
        parser.error("exact campaign key and public key must already exist")
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=False)
    outcome = Outcome(planned_cases(args))
    for component in components(args):
        one_case(args, component, key, outcome)
    sys.exit(outcome.verdict())


if __name__ == "__main__":
    main()
