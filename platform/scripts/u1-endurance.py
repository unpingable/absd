#!/usr/bin/env python3
"""U1 endurance guest: launch, observe, stop, report (docs/u1-endurance-20261008/).

One ABSD served boot of the operator image (scripts/build-operator-image.sh)
under QEMU, run unattended, observed from the host over ordinary SSH
sessions. Every guest is isolated by name: its own run directory, disk
image copy, host port, QEMU process name and pid file, console, and record.

  u1-endurance.py launch  --run-root DIR --guest NAME --image BUILD_OUT --identity KEY [--profile A] [--port N]
  u1-endurance.py observe --run RUN [--interval S] [--rounds N] [--duration S] [--unresponsive-after N]
  u1-endurance.py probe   --run RUN            one round, printed
  u1-endurance.py stop    --run RUN [--kill]   ends the observer, then an orderly `shutdown` (or SIGKILL)
  u1-endurance.py pause   --run RUN            SIGSTOP the guest (an induced hang; recorded as an intervention)
  u1-endurance.py resume  --run RUN            SIGCONT (recorded)
  u1-endurance.py report  --run RUN            summary and verdict from the record

A run is RUN = DIR/NAME/<run id>/ holding manifest.json (what was launched,
from what), absd-operator.{iso,img} (a copy, disposable), console.log,
qemu.pid, qemu.status (QEMU's exit status, written when it exits),
qemu.out (QEMU's own stderr), rounds.jsonl (one line per observation
round), state.json (the run's classification so far), and known_hosts.

Health is observed per round, each probe bounded by a timeout, in this
order; a running QEMU pid alone is never health:

  process    the pid is alive (or qemu.status says how it ended); host RSS
  console    boots seen, fault markers, the latest SERVED/FSD CAPACITY census
             (init's, fsd's and the kernel's raw lines and sshd's framed ones)
  banner     TCP connect to the forwarded port and sshd's SSH-2.0 banner
  ssh        a fresh session: `echo` of a nonce, timed
  uptime     boot id (a reset is a changed id), ticks monotonic
  fs         write a round file, read it back, sha256sum, append a journal
             line, `sync -v`; the anchor file written at launch still reads
  services   `df` (the file server), `release`; every 10th round `ls -l /var/log`
  transfer   every 20th round: 64 KiB up and down, sha256 both sides

Classification (docs/u1-endurance-20261008/README.md): a round is ok,
degraded (a probe failed or was slow, the guest is still serving),
measurement (the observer itself failed; never counted against the guest),
or a guest failure (GUEST_EXIT, GUEST_RESET, STATE_LOSS, SERVICE_FAILURE,
GUEST_UNRESPONSIVE after N consecutive rounds without a session,
AUTH_REFUSED, HOST_KEY_CHANGED). A QEMU exit by signal or by the host is
HOST_INTERRUPTED, not a guest failure. The first guest failure ends the
endurance clock at the last ok round; it is never reset by anything this
tool does. Nothing here restarts a guest. An intervention (pause, resume)
is recorded and disqualifies the run from any U1 verdict.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import random
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import operator_image as oi  # noqa: E402
import ssh_absd  # noqa: E402

SSH = "/usr/bin/ssh"
QEMU = "qemu-system-x86_64"
# A named guest configuration. `qualified` names the gate that ran this
# shape of served boot on the canonical pair; the launcher refuses an
# unqualified profile unless --unqualified says the operator knows.
PROFILES = {
    # The control: exactly scripts/boot-operator.sh's machine (the operator
    # matrix's), TCG, one CPU, IDE disk, e1000 on QEMU's user network.
    "A": dict(vcpus=1, storage="ata", accel="tcg", cpu="max,vendor=GenuineIntel,+rdrand",
              qualified="operator matrix (run-operator-matrix.sh), TCG", purpose="control: boring, no injected failures"),
    # The same machine under KVM: the containment matrix's KVM column.
    "AK": dict(vcpus=1, storage="ata", accel="kvm", cpu="host",
               qualified="containment matrix KVM column (run-contain-matrix.sh); not the operator matrix",
               purpose="control under KVM"),
    "B": dict(vcpus=2, storage="nvme", accel="kvm", cpu="host", qualified=None,
              purpose="SMP + NVMe (served boots run on UP on the canonical pair: not supportable yet)"),
    "C": dict(vcpus=4, storage="nvme", accel="kvm", cpu="host", qualified=None, purpose="higher concurrency (as B)"),
    "D": dict(vcpus=2, storage="ata", accel="kvm", cpu="host", qualified=None, purpose="SMP + ATA (as B)"),
    "E": dict(vcpus=2, storage="nvme", accel="kvm", cpu="host", qualified=None,
              purpose="controlled network interruptions: a resilience experiment, never a U1 success"),
    "F": dict(vcpus=2, storage="nvme", accel="kvm", cpu="host", qualified=None,
              purpose="periodic service failure/recovery: a resilience experiment, never a U1 success"),
    "AN": dict(vcpus=1, storage="nvme", accel="tcg", cpu="max,vendor=GenuineIntel,+rdrand", qualified=None,
               purpose="control shape on NVMe (durable matrices ran NVMe; the served operator image has not)"),
}
# Lines init, fsd and the kernel write; any after readiness means the boot
# ended or reset. SERVED SHUTDOWN action= is the orderly end (stop).
RESET_MARKERS = ["ABSD PANIC", "KERNEL FAULT", "SERVED RECOVERY BEGIN", "MACHINE STOP", "SERVED SHUTDOWN ESCALATED",
                 "MACHINE RECOVER RESET", "MACHINE RESTART"]
FAULT_MARKERS = RESET_MARKERS + ["SERVED SHUTDOWN action="]
CAPACITY = re.compile(r"SERVED CAPACITY boot=([0-9a-f]+) accepted_reclaimed=(\d+) slots=(\d+) pool=(\d+) net_sockets=(\d+) "
                      r"net_closing=(\d+) processes=(\d+) handles=(\d+) pipes=(\d+) cells=(\d+) frames=(\d+) heap_pages_peak=(\d+)")
FSD_CAPACITY = re.compile(r"FSD CAPACITY boot=([0-9a-f]+) settled_releases=(\d+) fs_objects=(\d+) rotated_logs=(\d+) "
                          r"bound=(\d+) opens=(\d+) draining=(\d+) heap_pages_peak=(\d+)")
HALT = re.compile(r"SERVED SHUTDOWN action=halt worker_status=\d+ file_server_status=\d+ orphans_reaped=\d+ drained=\w+")
UPTIME = re.compile(rb"up (\d+) days (\d\d):(\d\d):(\d\d), (\d+) ticks since boot, boot ([0-9a-f]{32})\n")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def seconds_between(a, b):
    return int((datetime.datetime.fromisoformat(b) - datetime.datetime.fromisoformat(a)).total_seconds())


def git_head(path):
    try:
        return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path, default=None):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json(path, value):
    tmp = pathlib.Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n")
    tmp.replace(path)


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, TypeError):
        return False


# -- the guest ------------------------------------------------------------------

class Run:
    def __init__(self, path):
        self.path = pathlib.Path(path).resolve()
        self.manifest = read_json(self.path / "manifest.json")
        if not self.manifest:
            raise SystemExit(f"{self.path}: no manifest.json (not a run directory)")
        self.reload()

    def reload(self):
        self.state = read_json(self.path / "state.json", {})

    def save(self):
        write_json(self.path / "state.json", self.state)

    # process
    def pid(self):
        try:
            return int((self.path / "qemu.pid").read_text().strip())
        except (FileNotFoundError, ValueError):
            return None

    def alive(self):
        pid = self.pid()
        if pid is None:
            return False
        try:
            cmdline = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return False
        # The pid must still be our QEMU (pids are reused after a host reboot).
        return str(self.path).encode() in cmdline and b"qemu-system" in cmdline

    def exit_status(self):
        try:
            return int((self.path / "qemu.status").read_text().strip())
        except (FileNotFoundError, ValueError):
            return None

    def exit_kind(self):
        """How QEMU ended: ('guest', detail) for a guest-decided end
        (isa-debug-exit: 4*code+3, always odd), ('host', detail) for a
        signal or a host-side end (0, >= 128, 'terminating on signal')."""
        status = self.exit_status()
        try:
            out = (self.path / "qemu.out").read_text(errors="replace")
        except FileNotFoundError:
            out = ""
        if status is None:
            return None, "no status yet"
        if "terminating on signal" in out or status >= 128 or status == 0:
            return "host", f"qemu status {status}: {out.strip()[-160:] or 'ended by the host or a signal'}"
        names = {3: "halted (orderly)", 7: "panic or failed workload", 11: "kernel fault", 71: "MACHINE STOP 17",
                 75: "MACHINE STOP 18", 79: "MACHINE STOP 19", 83: "MACHINE STOP 20"}
        return "guest", f"qemu status {status}: {names.get(status, 'guest exit code ' + str((status - 3) // 4))}"

    def observer_pid(self):
        try:
            pid = int((self.path / "observer.pid").read_text())
        except (FileNotFoundError, ValueError):
            return None
        return pid if pid_alive(pid) else None

    def rss_kib(self):
        pid = self.pid()
        try:
            for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
        except OSError:
            pass
        return None

    # console
    def console(self):
        """(raw bytes, text): the text is the raw console (init, fsd, the
        kernel write plain lines) plus sshd's decoded framed stream, as
        scripts/served-matrix.py's seen()."""
        try:
            data = (self.path / "console.log").read_bytes()
        except FileNotFoundError:
            return b"", ""
        framed = "\n".join(ssh_absd.captured(part) for part in data.split(b"ABSD KERNEL BOOT\n"))
        return data, data.decode(errors="replace") + "\n" + framed

    def console_facts(self):
        raw, text = self.console()
        boots = raw.count(b"ABSD KERNEL BOOT")
        faults = {m: text.count(m) for m in FAULT_MARKERS if m in text}
        cap = CAPACITY.findall(text)
        fsd = FSD_CAPACITY.findall(text)
        keys = ["boot", "accepted_reclaimed", "slots", "pool", "net_sockets", "net_closing", "processes", "handles",
                "pipes", "cells", "frames", "heap_pages_peak"]
        fkeys = ["boot", "settled_releases", "fs_objects", "rotated_logs", "bound", "opens", "draining", "heap_pages_peak"]
        return {"bytes": len(raw), "boots": boots, "faults": faults, "listening": text.count("SSH LISTENING"),
                "census_count": len(cap), "fsd_census_count": len(fsd),
                "census": dict(zip(keys, [cap[-1][0]] + [int(x) for x in cap[-1][1:]])) if cap else None,
                "fsd_census": dict(zip(fkeys, [fsd[-1][0]] + [int(x) for x in fsd[-1][1:]])) if fsd else None}

    # ssh
    def ssh_argv(self, extra=()):
        m = self.manifest
        return [SSH, "-F", "/dev/null", "-p", str(m["host_port"]), "-i", m["identity"],
                "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={self.path / 'known_hosts'}", "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=0", "-o", "LogLevel=ERROR", *extra,
                "operator@127.0.0.1"]

    def ssh(self, command=None, stdin=b"", timeout=120):
        """(rc, stdout, stderr, seconds); rc None on a host-side timeout."""
        argv = self.ssh_argv() + ([command] if command is not None else [])
        start = time.monotonic()
        try:
            p = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr, round(time.monotonic() - start, 2)
        except subprocess.TimeoutExpired as e:
            return None, e.stdout or b"", e.stderr or b"", round(time.monotonic() - start, 2)

    def banner(self, timeout=5.0):
        start = time.monotonic()
        try:
            with socket.create_connection(("127.0.0.1", self.manifest["host_port"]), timeout=timeout) as s:
                s.settimeout(timeout)
                data = s.recv(64)
            return data.startswith(b"SSH-2.0"), data[:32].decode(errors="replace"), round(time.monotonic() - start, 2)
        except OSError as e:
            return False, str(e), round(time.monotonic() - start, 2)

    def identity_ok(self):
        """The launch identity must still be there and private, or every
        session fails with Permission denied for a host-side reason."""
        try:
            st = os.stat(self.manifest["identity"])
        except OSError as e:
            raise RuntimeError(f"identity {self.manifest['identity']}: {e}")
        if st.st_mode & 0o077:
            raise RuntimeError(f"identity {self.manifest['identity']}: mode {oct(st.st_mode & 0o777)} is not private")


# -- launch --------------------------------------------------------------------

def qemu_argv(profile, run, port, guest, guest_port, memory):
    p = PROFILES[profile]
    argv = [QEMU]
    if p["accel"] == "kvm":
        argv += ["-accel", "kvm"]
    argv += ["-cpu", p["cpu"]]
    if p["vcpus"] != 1:
        argv += ["-smp", str(p["vcpus"])]
    if memory:
        argv += ["-m", memory]
    argv += ["-rtc", "base=utc", "-cdrom", str(run / oi.ISO)]
    image = str(run / oi.IMAGE)
    if p["storage"] == "ata":
        argv += ["-drive", f"file={image},format=raw,if=ide,index=0"]
    else:
        argv += ["-drive", f"if=none,id=nvm,file={image},format=raw", "-device", "nvme,serial=absd,drive=nvm"]
    net = ".".join(guest.split(".")[:3]) + ".0/24"
    argv += ["-netdev", f"user,id=n0,net={net},hostfwd=tcp:127.0.0.1:{port}-{guest}:{guest_port}",
             "-device", "e1000,netdev=n0", "-display", "none", "-serial", f"file:{run / 'console.log'}",
             "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
             "-pidfile", str(run / "qemu.pid"), "-name", f"guest=u1-{run.parent.name},process=u1-{run.parent.name}"]
    return argv


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def launch(args):
    if args.profile not in PROFILES:
        raise SystemExit(f"unknown profile {args.profile}; one of {', '.join(PROFILES)}")
    profile = PROFILES[args.profile]
    if profile["qualified"] is None and not args.unqualified:
        raise SystemExit(f"profile {args.profile} is not qualified on the canonical pair ({profile['purpose']}); "
                         "pass --unqualified to launch it as an experiment")
    image_out = pathlib.Path(args.image).resolve()
    for name in (oi.ISO, oi.IMAGE, "MANIFEST"):
        if not (image_out / name).is_file():
            raise SystemExit(f"{image_out}: no {name} (build it with scripts/build-operator-image.sh)")
    identity = pathlib.Path(args.identity).resolve()
    if not identity.is_file():
        raise SystemExit(f"{identity}: no such identity")
    fingerprint_line = subprocess.run(["ssh-keygen", "-lf", str(identity)], capture_output=True, text=True).stdout.strip()
    guest_dir = pathlib.Path(args.run_root).resolve() / args.guest
    for other in guest_dir.glob("*/qemu.pid"):
        r = Run(other.parent)
        if r.alive():
            raise SystemExit(f"guest {args.guest} is already running: {other.parent}")
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = guest_dir / run_id
    run.mkdir(parents=True)
    shutil.copy2(image_out / oi.ISO, run / oi.ISO)
    if args.reuse_image:
        src = pathlib.Path(args.reuse_image).resolve()
        shutil.copy2(src, run / oi.IMAGE)
        lineage = str(src)
    else:
        shutil.copy2(image_out / oi.IMAGE, run / oi.IMAGE)
        lineage = None
    os.chmod(run / oi.IMAGE, 0o600)
    guest, guest_port = oi.endpoint(run / oi.IMAGE)
    port = args.port or free_port()
    argv = qemu_argv(args.profile, run, port, guest, int(guest_port), args.memory)
    image_manifest = (image_out / "MANIFEST").read_text()
    manifest = {
        "run_id": run_id, "guest": args.guest, "profile": args.profile, "profile_detail": profile,
        "launched": now(), "host": socket.gethostname(), "host_port": port, "guest_endpoint": f"{guest}:{guest_port}",
        "memory": args.memory or "qemu default", "qemu": argv,
        "qemu_version": subprocess.run([QEMU, "--version"], capture_output=True, text=True).stdout.split("\n")[0],
        "identity": str(identity), "identity_fingerprint": fingerprint_line,
        "image_source": str(image_out), "image_lineage": lineage,
        "image_manifest_head": [l for l in image_manifest.splitlines() if not l.startswith("file ")],
        "image_manifest_sha256": sha256(image_manifest.encode()),
        "iso_sha256": sha256((run / oi.ISO).read_bytes()), "image_sha256_at_launch": sha256((run / oi.IMAGE).read_bytes()),
        "platform": git_head(HERE.parent), "platform_root": str(HERE.parent),
        "tool": str(pathlib.Path(__file__).resolve()), "tool_sha256": sha256(pathlib.Path(__file__).read_bytes()),
    }
    write_json(run / "manifest.json", manifest)
    # QEMU detached from this shell; its exit status lands in qemu.status.
    script = f"""#!/bin/sh
{' '.join(shlex.quote(a) for a in argv)}
echo $? > {shlex.quote(str(run / 'qemu.status'))}
"""
    (run / "launch.sh").write_text(script)
    os.chmod(run / "launch.sh", 0o755)
    with open(run / "qemu.out", "wb") as out:
        subprocess.Popen(["setsid", "sh", str(run / "launch.sh")], stdout=out, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, start_new_session=True)
    r = Run(run)
    deadline = time.monotonic() + args.ready_timeout
    publics = []
    while time.monotonic() < deadline:
        raw, text = r.console()
        publics = re.findall(r"(?m)^sshd: host key (ssh-ed25519 [A-Za-z0-9+/=]+)$", text)
        if "SSH LISTENING" in text and publics:
            break
        if r.exit_status() is not None:
            raise SystemExit(f"QEMU exited with status {r.exit_status()} before serving; see {run / 'console.log'}")
        time.sleep(1)
    else:
        raise SystemExit(f"no SSH LISTENING within {args.ready_timeout} s; see {run / 'console.log'}")
    (run / "known_hosts").write_text(f"[127.0.0.1]:{port} {publics[0]}\n")
    fingerprint = re.findall(r"(?m)^sshd: host key (256 SHA256:\S+ \(ED25519\))$", text)
    # First contact: the boot id, and the anchor the run will verify forever.
    rc, out, err, secs = r.ssh("uptime", timeout=120)
    m = UPTIME.fullmatch(out) if rc == 0 else None
    if m is None:
        raise SystemExit(f"first session failed: rc={rc} {out!r} {err!r}")
    boot_id = m.group(6).decode()
    prior = {}
    if lineage:
        # What the previous run left: its anchor and journal are part of
        # the state this run must keep (a new run, lineage recorded).
        rc1, out1, _, _ = r.ssh("cat /home/operator/u1/anchor")
        rc2, out2, _, _ = r.ssh("wc -l /home/operator/u1/journal")
        prior = {"anchor": out1.decode(errors="replace") if rc1 == 0 else None,
                 "journal_lines": int(out2.split()[0]) if rc2 == 0 and out2.split() else 0}
        if rc1 == 0:
            rc3, _, _, _ = r.ssh(f"cp /home/operator/u1/anchor /home/operator/u1/anchor-before-{run_id}")
    anchor = f"u1 {args.guest} {run_id} boot {boot_id}\n".encode()
    rc1, _, err1, _ = r.ssh("mkdir -p /home/operator/u1")
    rc2, _, err2, _ = r.ssh("cat > /home/operator/u1/anchor", stdin=anchor)
    rc3, out3, _, _ = r.ssh("cat /home/operator/u1/anchor")
    if not (rc1 == rc2 == rc3 == 0 and out3 == anchor):
        raise SystemExit(f"could not write the anchor: {rc1} {err1!r} {rc2} {err2!r} {out3!r}")
    state = {"run": str(run), "launched": manifest["launched"], "boot_id": boot_id, "host_key": fingerprint[:1],
             "anchor_sha256": sha256(anchor), "prior": prior, "journal_lines": prior.get("journal_lines", 0),
             "rounds": 0, "ok": 0, "degraded": 0, "measurement": 0, "consecutive_unresponsive": 0,
             "consecutive_service": 0, "last_ok_time": manifest["launched"], "failure": None, "interventions": [],
             "observers": [], "verdict": "RUNNING"}
    write_json(run / "state.json", state)
    print(f"U1 LAUNCHED guest={args.guest} run={run} profile={args.profile} port={port} boot={boot_id} pid={r.pid()}")
    print(f"  ssh -p {port} -i {identity} -o UserKnownHostsFile={run / 'known_hosts'} operator@127.0.0.1")


# -- observe -------------------------------------------------------------------

def probe_round(r, index, nonce, slow):
    """One round: every probe, each bounded; returns the round record.
    Raises only for host-side (measurement) conditions."""
    rec = {"round": index, "time": now(), "probes": {}, "failed": [], "slow": [], "failure": None}
    P = rec["probes"]
    r.identity_ok()
    load = os.getloadavg()
    P["host"] = {"load1": round(load[0], 2), "cpus": os.cpu_count(), "rss_kib": r.rss_kib()}
    rec["host_overloaded"] = load[0] > (os.cpu_count() or 1)

    alive = r.alive()
    kind, detail = r.exit_kind()
    P["process"] = {"alive": alive, "pid": r.pid(), "exit_status": r.exit_status(), "exit_kind": kind}
    facts = r.console_facts()
    P["console"] = facts
    if not alive:
        if kind == "host":
            rec["failure"] = {"kind": "HOST_INTERRUPTED", "detail": f"{detail}; faults {facts['faults']}"}
        else:
            rec["failure"] = {"kind": "GUEST_EXIT", "detail": f"{detail}; faults {facts['faults']}"}
        return rec
    if facts["boots"] > 1 or any(m in facts["faults"] for m in RESET_MARKERS):
        rec["failure"] = {"kind": "GUEST_RESET", "detail": f"boots={facts['boots']} faults={facts['faults']}"}
        # Keep probing: a reset guest may serve again, and that is evidence too.

    ok, text, secs = r.banner()
    P["banner"] = {"ok": ok, "text": text, "seconds": secs}
    if not ok:
        rec["failed"].append("banner")

    rc, out, err, secs = r.ssh(f"echo u1 {nonce}", timeout=slow * 4)
    want = f"u1 {nonce}\n".encode()
    P["ssh"] = {"rc": rc, "ok": rc == 0 and out == want, "seconds": secs, "err": err.decode(errors="replace")[-200:]}
    if secs > slow:
        rec["slow"].append("ssh")
    if not P["ssh"]["ok"]:
        rec["failed"].append("ssh")
        if rc == 255 and b"Permission denied" in err:
            rec["failure"] = rec["failure"] or {"kind": "AUTH_REFUSED", "detail": err.decode(errors="replace")[-200:]}
        if rc == 255 and b"REMOTE HOST IDENTIFICATION HAS CHANGED" in err:
            rec["failure"] = rec["failure"] or {"kind": "HOST_KEY_CHANGED", "detail": "sshd's key is not the launched one"}
        return rec  # no session: nothing below can run

    rc, out, err, secs = r.ssh("uptime", timeout=slow * 4)
    m = UPTIME.fullmatch(out) if rc == 0 else None
    P["uptime"] = {"ok": m is not None, "seconds": secs, "ticks": int(m.group(5)) if m else None,
                   "boot": m.group(6).decode() if m else None, "raw": out.decode(errors="replace")[:120]}
    if m is None:
        rec["failed"].append("uptime")
    else:
        if P["uptime"]["boot"] != r.state["boot_id"]:
            rec["failure"] = rec["failure"] or {"kind": "GUEST_RESET", "detail": f"boot {P['uptime']['boot']} != {r.state['boot_id']}"}
        last = r.state.get("last_ticks")
        if last is not None and P["uptime"]["ticks"] <= last:
            rec["failure"] = rec["failure"] or {"kind": "GUEST_RESET", "detail": f"ticks {P['uptime']['ticks']} <= {last}"}

    data = f"round {index} {nonce} {now()}\n".encode()
    steps = {}
    rc, _, err, s1 = r.ssh("cat > /home/operator/u1/round", stdin=data, timeout=slow * 4)
    steps["write"] = (rc == 0, s1, err)
    rc, out, err, s2 = r.ssh("cat /home/operator/u1/round", timeout=slow * 4)
    steps["read"] = (rc == 0 and out == data, s2, err)
    rc, out, err, s3 = r.ssh("sha256sum /home/operator/u1/round", timeout=slow * 4)
    steps["sha"] = (rc == 0 and out.split()[:1] == [sha256(data).encode()], s3, err)
    rc, _, err, s4 = r.ssh("cat >> /home/operator/u1/journal", stdin=data, timeout=slow * 4)
    steps["append"] = (rc == 0, s4, err)
    rc, out, err, s5 = r.ssh("sync -v", timeout=slow * 4)
    commit = re.fullmatch(rb"commit (\d+)\n", out) if rc == 0 else None
    steps["sync"] = (commit is not None, s5, err)
    rc, out, err, s6 = r.ssh("cat /home/operator/u1/anchor", timeout=slow * 4)
    steps["anchor"] = (rc == 0 and sha256(out) == r.state["anchor_sha256"], s6, err)
    # State is lost only on a definite answer: the file read fully with
    # other bytes, or the file server says it is not there. A dropped
    # session or a refused request is a failed probe, not a verdict.
    anchor_lost = (rc == 0 and sha256(out) != r.state["anchor_sha256"]) or (rc == 1 and b"not found" in err)
    rc, out, err, s7 = r.ssh("wc -l /home/operator/u1/journal", timeout=slow * 4)
    try:
        lines = int(out.split()[0]) if rc == 0 and out.split() else None
    except ValueError:
        lines = None
    steps["journal"] = (lines is not None, s7, err)
    P["fs"] = {k: {"ok": v[0], "seconds": v[1], "err": v[2].decode(errors="replace")[-120:]} for k, v in steps.items()}
    P["fs"]["commit"] = int(commit.group(1)) if commit else None
    P["fs"]["journal_lines"] = lines
    for k, v in steps.items():
        if not v[0]:
            rec["failed"].append(f"fs.{k}")
        if v[1] > slow:
            rec["slow"].append(f"fs.{k}")
    if anchor_lost:
        rec["failure"] = rec["failure"] or {"kind": "STATE_LOSS", "detail": "the anchor does not read back"}
    if lines is not None and lines < r.state.get("journal_lines", 0):
        rec["failure"] = rec["failure"] or {"kind": "STATE_LOSS", "detail": f"journal shrank {r.state.get('journal_lines')} -> {lines}"}

    rc, out, err, s8 = r.ssh("df", timeout=slow * 4)
    dfm = re.search(rb"absd:([0-9a-f]{16}) +(\d+) +(\d+) +(\d+) +(\d+)% (\d+)\n", out) if rc == 0 else None
    P["df"] = {"ok": dfm is not None, "seconds": s8, "used_k": int(dfm.group(3)) if dfm else None,
               "free_k": int(dfm.group(4)) if dfm else None, "err": err.decode(errors="replace")[-120:]}
    if dfm is None:
        rec["failed"].append("df")
    rc, out, err, s9 = r.ssh("release", timeout=slow * 4)
    P["release"] = {"ok": rc == 0 and out.startswith(b"release="), "seconds": s9, "text": out.decode(errors="replace").strip()[:120]}
    if not P["release"]["ok"]:
        rec["failed"].append("release")
    if index % 10 == 0:
        rc, out, err, s10 = r.ssh("ls -l /var/log", timeout=slow * 4)
        P["logs"] = {"ok": rc == 0, "seconds": s10, "text": out.decode(errors="replace")[:300]}
    if index % 20 == 0:
        blob = bytes(random.Random(nonce).getrandbits(8) for _ in range(65_536))
        rc1, _, err1, t1 = r.ssh("cat > /home/operator/u1/blob", stdin=blob, timeout=slow * 10)
        rc2, out2, err2, t2 = r.ssh("cat /home/operator/u1/blob", timeout=slow * 10)
        rc3, out3, _, t3 = r.ssh("sha256sum /home/operator/u1/blob", timeout=slow * 4)
        okb = rc1 == 0 and rc2 == 0 and out2 == blob and rc3 == 0 and out3.split()[:1] == [sha256(blob).encode()]
        P["transfer"] = {"ok": okb, "up_seconds": t1, "down_seconds": t2, "bytes": len(blob)}
        if not okb:
            rec["failed"].append("transfer")
    return rec


SERVICE_PROBES = ("uptime", "fs.write", "fs.read", "fs.sha", "fs.append", "fs.sync", "fs.journal", "df", "release")


def classify(r, rec, unresponsive_after):
    """Fold a round into the run state; returns the round class."""
    st = r.state
    st["rounds"] = rec["round"]
    st["last_round_time"] = rec["time"]
    if rec.get("measurement_error"):
        # The observer failed, not the guest: no counter moves.
        st["measurement"] = st.get("measurement", 0) + 1
        rec["class"] = "measurement"
        return "measurement"
    up = rec["probes"].get("uptime")
    if up and up.get("ticks") is not None:
        st["last_ticks"] = up["ticks"]
    fs = rec["probes"].get("fs")
    if fs and fs.get("journal_lines") is not None:
        st["journal_lines"] = fs["journal_lines"]
    session = bool(rec["probes"].get("ssh", {}).get("ok"))
    if rec.get("host_overloaded"):
        st["host_overloaded_rounds"] = st.get("host_overloaded_rounds", 0) + 1
    if not session and rec["probes"].get("process", {}).get("alive"):
        # A guest that did not serve did not serve: the round counts. The
        # host's load is recorded beside it, so a hang under host overload
        # is a failure whose attribution is marked ambiguous, never a
        # failure hidden until the host is quiet.
        st["consecutive_unresponsive"] = st.get("consecutive_unresponsive", 0) + 1
        st["consecutive_unresponsive_overloaded"] = st.get("consecutive_unresponsive_overloaded", 0) + (1 if rec.get("host_overloaded") else 0)
        if st["consecutive_unresponsive"] >= unresponsive_after and rec["failure"] is None:
            n, o = st["consecutive_unresponsive"], st["consecutive_unresponsive_overloaded"]
            rec["failure"] = {"kind": "GUEST_UNRESPONSIVE", "detail": f"{n} consecutive rounds without a session",
                              "host_overloaded_rounds": o,
                              "attribution": "ambiguous: the host was over its CPU count" if o else "guest"}
    elif session:
        st["consecutive_unresponsive"] = 0
        st["consecutive_unresponsive_overloaded"] = 0
    # Sessions work but the guest cannot do its work: the claim needs both.
    if session and any(p in rec["failed"] for p in SERVICE_PROBES):
        st["consecutive_service"] = st.get("consecutive_service", 0) + 1
        if st["consecutive_service"] >= unresponsive_after and rec["failure"] is None:
            rec["failure"] = {"kind": "SERVICE_FAILURE",
                              "detail": f"sessions work, but {sorted(set(rec['failed']) & set(SERVICE_PROBES))} failed "
                                        f"{st['consecutive_service']} rounds running"}
    elif session:
        st["consecutive_service"] = 0
    if rec["failure"]:
        cls = "failure"
        if st.get("failure") is None:
            st["failure"] = dict(rec["failure"], round=rec["round"], time=rec["time"])
            st["verdict"] = "INTERRUPTED" if rec["failure"]["kind"] == "HOST_INTERRUPTED" else "FAILED"
            # The clock stops at the last round that was fully ok, not at
            # the detection: a failure lies between the two.
            st["endurance_seconds"] = seconds_between(st["launched"], st.get("last_ok_time", st["launched"]))
    elif rec["failed"] or rec["slow"]:
        cls = "degraded"
        st["degraded"] = st.get("degraded", 0) + 1
    else:
        cls = "ok"
        st["ok"] = st.get("ok", 0) + 1
        st["last_ok_time"] = rec["time"]
    rec["class"] = cls
    return cls


STOP_REQUESTED = False


def _stop_handler(signum, frame):
    global STOP_REQUESTED
    STOP_REQUESTED = True


def observe(args):
    r = Run(args.run)
    if r.observer_pid():
        raise SystemExit(f"an observer (pid {r.observer_pid()}) is already watching {r.path}")
    if r.state.get("stopped"):
        raise SystemExit(f"{r.path} was stopped by the operator ({r.state['stopped']['kind']}); nothing to observe")
    pidfile = r.path / "observer.pid"
    pidfile.write_text(str(os.getpid()))
    signal.signal(signal.SIGTERM, _stop_handler)
    signal.signal(signal.SIGINT, _stop_handler)
    r.state.setdefault("observers", []).append({"started": now(), "pid": os.getpid(), "interval": args.interval,
                                                "slow": args.slow, "unresponsive_after": args.unresponsive_after,
                                                "rounds": args.rounds, "duration": args.duration})
    r.save()
    if not r.alive() and r.state.get("failure") is None:
        kind, detail = r.exit_kind()
        kind = {"host": "HOST_INTERRUPTED", "guest": "GUEST_EXIT", None: "HOST_INTERRUPTED"}[kind]
        r.state["failure"] = {"kind": kind, "detail": f"no live QEMU for this run at observer start: {detail}",
                              "round": r.state.get("rounds", 0), "time": now()}
        r.state["verdict"] = "FAILED" if kind == "GUEST_EXIT" else "INTERRUPTED"
        r.state["endurance_seconds"] = seconds_between(r.state["launched"], r.state.get("last_ok_time", r.state["launched"]))
        r.save()
        print(f"U1 OBSERVE {kind}: {r.state['failure']['detail']}")
        pidfile.unlink()
        return 2
    index = r.state.get("rounds", 0)
    end = time.monotonic() + args.duration if args.duration else None
    rounds_left = args.rounds
    try:
        while not STOP_REQUESTED:
            index += 1
            nonce = f"{random.getrandbits(32):08x}"
            started = time.monotonic()
            try:
                rec = probe_round(r, index, nonce, args.slow)
            except Exception as e:  # the observer itself failed: measurement, not the guest
                rec = {"round": index, "time": now(), "probes": {}, "failed": [], "slow": [],
                       "failure": None, "measurement_error": repr(e)}
            cls = classify(r, rec, args.unresponsive_after)
            rec["round_seconds"] = round(time.monotonic() - started, 1)
            with open(r.path / "rounds.jsonl", "a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
            r.save()
            c = rec["probes"].get("console", {}).get("census") or {}
            print(f"U1 ROUND {index} {rec['time']} {cls.upper():11} ssh={rec['probes'].get('ssh', {}).get('seconds')}s "
                  f"ticks={rec['probes'].get('uptime', {}).get('ticks')} frames={c.get('frames')} heap={c.get('heap_pages_peak')} "
                  f"handles={c.get('handles')} rss={rec['probes'].get('host', {}).get('rss_kib')}k "
                  f"failed={rec['failed']} slow={rec['slow']}"
                  + (f" FAILURE={rec['failure']}" if rec["failure"] else "")
                  + (f" MEASUREMENT={rec['measurement_error']}" if rec.get("measurement_error") else ""), flush=True)
            if not rec["probes"].get("process", {}).get("alive", True):
                break  # nothing more to observe
            if r.state.get("failure") and args.stop_on_failure:
                break
            if rounds_left is not None:
                rounds_left -= 1
                if rounds_left <= 0:
                    break
            if end is not None and time.monotonic() >= end:
                break
            wait = max(0.0, args.interval - (time.monotonic() - started))
            while wait > 0 and not STOP_REQUESTED:
                time.sleep(min(wait, 1.0))
                wait -= 1.0
    finally:
        pidfile.unlink(missing_ok=True)
        r.state.setdefault("observers", [])[-1]["ended"] = now()
        r.state["observers"][-1]["stop_requested"] = STOP_REQUESTED
        r.save()
    report(argparse.Namespace(run=str(r.path)))
    return 0 if r.state.get("failure") is None else 1


def probe(args):
    r = Run(args.run)
    rec = probe_round(r, r.state.get("rounds", 0) + 1, f"{random.getrandbits(32):08x}", args.slow)
    print(json.dumps(rec, indent=1, sort_keys=True))
    return 0 if not rec["failed"] and rec["failure"] is None else 1


def end_observer(r, timeout=60):
    """The observer must be gone before the guest is ended, or it would
    record the end as a guest failure and overwrite the record."""
    pid = r.observer_pid()
    if pid is None:
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and pid_alive(pid):
        time.sleep(0.5)
    if pid_alive(pid):
        raise SystemExit(f"the observer (pid {pid}) did not end within {timeout} s; stop it first")
    print(f"U1 STOP observer pid={pid} ended")
    r.reload()


def stop(args):
    r = Run(args.run)
    end_observer(r)
    pid = r.pid()
    if args.kill:
        if r.alive():
            os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and r.exit_status() is None:
            time.sleep(0.5)
        print(f"U1 STOP killed pid={pid} status={r.exit_status()}")
        note = {"kind": "OPERATOR_KILL", "detail": f"SIGKILL by `stop --kill`; qemu status {r.exit_status()}", "time": now()}
    else:
        if not r.alive():
            # Never send `shutdown` to a port this run no longer owns.
            print(f"U1 STOP not running (qemu status {r.exit_status()}); nothing to shut down")
            note = {"kind": "OPERATOR_STOP_NOOP", "detail": f"not running; qemu status {r.exit_status()}", "time": now()}
            r.state["stopped"] = note
            r.save()
            return 0
        rc, out, err, secs = r.ssh("shutdown", timeout=120)
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline and r.exit_status() is None:
            time.sleep(0.5)
        status = r.exit_status()
        raw, text = r.console()
        halt = HALT.findall(text)
        acct = re.findall(rb"(?m)^DURABLE status=\d+ frames=\d+ processes=\d+ cells=\d+ pipes=\d+.*$", raw)
        orderly = status == 3 and bool(halt) and "drained=true" in halt[-1] and "orphans_reaped=0" in halt[-1]
        print(f"U1 STOP shutdown rc={rc} status={status} orderly={orderly} halt={halt[-1:]} "
              f"accounting={[a.decode() for a in acct[-1:]]}")
        note = {"kind": "OPERATOR_SHUTDOWN", "detail": f"ssh shutdown rc={rc}; qemu status {status}; {halt[-1:]}",
                "time": now(), "orderly": orderly, "accounting": [a.decode() for a in acct[-1:]]}
        if status is None:
            print(f"U1 STOP the guest did not end within {args.timeout} s; still running")
            r.state["stop_attempt"] = note
            r.save()
            return 1
    r.state["stopped"] = note
    if r.state.get("verdict") == "RUNNING":
        r.state["verdict"] = "STOPPED"
    r.save()
    # Nothing of the guest may remain: its QEMU and its launch wrapper.
    left = []
    for p in pathlib.Path("/proc").glob("[0-9]*/cmdline"):
        try:
            cmd = p.read_bytes()
        except OSError:
            continue
        if str(r.path).encode() in cmd and (b"qemu-system" in cmd or b"launch.sh" in cmd):
            left.append(int(p.parent.name))
    print(f"U1 STOP processes_left={left} image_sha256={sha256((r.path / oi.IMAGE).read_bytes())[:16]}")
    return 0 if not left else 1


def intervene(args, sig):
    r = Run(args.run)
    if not r.alive():
        raise SystemExit("not running")
    os.kill(r.pid(), sig)
    kind = "PAUSE" if sig == signal.SIGSTOP else "RESUME"
    r.state.setdefault("interventions", []).append({"kind": kind, "time": now(), "pid": r.pid()})
    r.save()
    print(f"U1 {kind} pid={r.pid()} at {now()} (recorded: this run can no longer support a U1 verdict)")
    return 0


def report(args):
    r = Run(args.run)
    rounds = [json.loads(l) for l in (r.path / "rounds.jsonl").read_text().splitlines()] if (r.path / "rounds.jsonl").exists() else []
    st = r.state
    ssh_secs = sorted(x["probes"]["ssh"]["seconds"] for x in rounds if x["probes"].get("ssh", {}).get("ok"))
    census = [x["probes"]["console"]["census"] for x in rounds if x["probes"].get("console", {}).get("census")]
    counts = [x["probes"]["console"]["census_count"] for x in rounds if x["probes"].get("console")]
    rss = [x["probes"]["host"]["rss_kib"] for x in rounds if x["probes"].get("host", {}).get("rss_kib")]
    first_c, last_c = (census[0], census[-1]) if census else (None, None)
    gaps = [seconds_between(a["time"], b["time"]) for a, b in zip(rounds, rounds[1:])]
    print(f"U1 REPORT guest={r.manifest['guest']} run={r.manifest['run_id']} profile={r.manifest['profile']} "
          f"platform={r.manifest['platform'][:8]} image={r.manifest['image_manifest_sha256'][:8]} tool={r.manifest.get('tool_sha256', '')[:8]}")
    print(f"  verdict={st.get('verdict')} rounds={st.get('rounds', 0)} ok={st.get('ok', 0)} degraded={st.get('degraded', 0)} "
          f"measurement={st.get('measurement', 0)} host_overloaded={st.get('host_overloaded_rounds', 0)} failure={st.get('failure')}")
    if st.get("interventions"):
        print(f"  interventions={st['interventions']}: NOT a U1 candidate run")
    if ssh_secs:
        print(f"  ssh session seconds: min={ssh_secs[0]} median={ssh_secs[len(ssh_secs) // 2]} max={ssh_secs[-1]} n={len(ssh_secs)}")
    if first_c:
        print("  guest census first -> last: " + " ".join(f"{k}={first_c[k]}->{last_c[k]}" for k in
                                                       ("accepted_reclaimed", "frames", "heap_pages_peak", "handles", "pipes", "cells", "processes", "net_sockets"))
              + f" (census lines {counts[0]}->{counts[-1]}{'' if counts[-1] > counts[0] or len(counts) < 2 else ': NOT GROWING, the console stream may be stuck'})")
    fsd = [x["probes"]["console"]["fsd_census"] for x in rounds if x["probes"].get("console", {}).get("fsd_census")]
    if fsd:
        print("  fsd census first -> last: " + " ".join(f"{k}={fsd[0][k]}->{fsd[-1][k]}" for k in
                                                     ("settled_releases", "fs_objects", "rotated_logs", "heap_pages_peak")))
    if rss:
        print(f"  qemu rss kib first={rss[0]} last={rss[-1]} max={max(rss)}")
    if rounds:
        last = rounds[-1]["probes"]
        print(f"  last: ticks={last.get('uptime', {}).get('ticks')} df_used_k={last.get('df', {}).get('used_k')} "
              f"commit={last.get('fs', {}).get('commit')} journal_lines={last.get('fs', {}).get('journal_lines')} "
              f"console_bytes={last.get('console', {}).get('bytes')} faults={last.get('console', {}).get('faults')}")
    if gaps:
        interval = (st.get("observers") or [{}])[-1].get("interval") or 0
        print(f"  round gaps seconds: max={max(gaps)}" + (" (observation had a gap wider than twice the interval)" if interval and max(gaps) > 2 * interval else ""))
    if st.get("stopped"):
        print(f"  stopped: {st['stopped']}")
    if st.get("endurance_seconds") is not None:
        print(f"  endurance clock stopped at {st['endurance_seconds']} s (last ok round before {st['failure']['kind']})")
    elif rounds:
        secs = seconds_between(st["launched"], st.get("last_ok_time", st["launched"]))
        print(f"  endurance clock: {secs} s from launch to the last ok round, verdict {st.get('verdict')}"
              + (" (with observation gaps, see above)" if gaps and interval and max(gaps) > 2 * interval else ""))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    l = sub.add_parser("launch")
    l.add_argument("--run-root", required=True)
    l.add_argument("--guest", required=True, help="a name: its own directory, port, process name")
    l.add_argument("--image", required=True, help="build-operator-image.sh's OUT (iso, img, MANIFEST)")
    l.add_argument("--identity", required=True, help="the operator's private key the image authorizes")
    l.add_argument("--profile", default="A")
    l.add_argument("--port", type=int, help="host port to forward (default: a free one)")
    l.add_argument("--memory", help="QEMU -m (default: QEMU's default, as boot-operator.sh)")
    l.add_argument("--reuse-image", help="continue from an existing image file (a new run, lineage recorded)")
    l.add_argument("--unqualified", action="store_true")
    l.add_argument("--ready-timeout", type=int, default=600)
    for name in ("observe", "probe", "stop", "pause", "resume", "report"):
        s = sub.add_parser(name)
        s.add_argument("--run", required=True)
        if name in ("observe", "probe"):
            s.add_argument("--slow", type=float, default=30.0, help="seconds after which a probe counts as slow")
        if name == "observe":
            s.add_argument("--interval", type=float, default=300.0)
            s.add_argument("--rounds", type=int)
            s.add_argument("--duration", type=float, help="seconds")
            s.add_argument("--unresponsive-after", type=int, default=3)
            s.add_argument("--stop-on-failure", action="store_true", help="stop observing at the first guest failure (default: keep recording)")
        if name == "stop":
            s.add_argument("--kill", action="store_true")
            s.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()
    if args.command == "launch":
        return launch(args)
    if args.command == "observe":
        return observe(args)
    if args.command == "probe":
        return probe(args)
    if args.command == "stop":
        return stop(args)
    if args.command == "pause":
        return intervene(args, signal.SIGSTOP)
    if args.command == "resume":
        return intervene(args, signal.SIGCONT)
    if args.command == "report":
        return report(args)


if __name__ == "__main__":
    sys.exit(main())
