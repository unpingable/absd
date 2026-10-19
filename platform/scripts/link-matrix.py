#!/usr/bin/env python3
"""Vertical A link cases (kernel docs/service-lifecycle-20261008/
DEGRADED-OPERATION-LIVENESS.md §6, §9 item 5, §10 (a)(b)). Every boot starts
stopped with QMP; the link is set before `cont`, moved with `set_link n0`, and
the harness waits on sshd's `SSH NET` lines. QEMU's e1000 completes TX with
the link down; §10 (b)'s link outcome is reached only through the kernel's
`nic-tx-hold` qualification fixture, which shows the driver's rule, not a
device's. Nothing here speaks for a physical NIC (§10 (c))."""

import argparse, importlib.util, os, pathlib, re, shutil, subprocess, sys, tempfile, threading, time

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("survival_recovery", here / "survival-recovery.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
served, sm, ssh_absd = recovery.served, recovery.served.sm, recovery.served.ssh_absd
from served_ram import served_qemu

NET = re.compile(r"(?m)^SSH NET link=(up|down|unknown) disabled=(0|1|unknown) rx_missed=(\d+) link_errors=(\d+)$")
TX = re.compile(r"(?m)^SSH NET TX held=(0|1) no_carrier=(\d+)$")
FIXTURE = "NIC TX HOLD FIXTURE ARMED"
CAPACITY = re.compile(r"(?m)^SERVED CAPACITY boot=[0-9a-f]{32} accepted_reclaimed=(\d+) slots=(\d+) pool=(\d+) "
                      r"net_sockets=(\d+) net_closing=(\d+) processes=(\d+) handles=(\d+) pipes=(\d+) cells=(\d+) "
                      r"frames=\d+ heap_pages_peak=\d+ link=(up|down|unknown)(?: heap_free_pages=\d+)?$")
FAULT = "SERVED SERVICE FAULT component=sshd reason=nic_disabled"
BEGIN = re.compile(r"(?m)^SERVED RECOVERY BEGIN reason=served worker fault file_server_status=(running|0)$")
CASES = ("link-down-at-boot", "loss-after-ready", "flaps", "persistent-outage", "absent-nic",
         "disabled-nic", "disabled-nic-budget", "tx-hold", "tx-hold-stuck")
FLAPS, OUTAGE_SECONDS, IDLE_SECONDS, TRANSFER_BYTES = 5, 20, 10, 16_000_000
LANE, MAX_LOAD = str(here.parent.parent), 10.0


class Refused(Exception):
    """A U1 host rule would be broken by the next QEMU launch."""


def host_rules():
    """U1 host rules, re-read before every QEMU launch (run-link-matrix.sh
    also checks once at its start): 1-minute load <= 10, no QEMU of this lane."""
    with open("/proc/loadavg") as f:
        load = f.read().split()[0]
    if float(load) > MAX_LOAD:
        raise Refused(f"load={load}")
    for cmdline in pathlib.Path("/proc").glob("[0-9]*/cmdline"):
        try:
            argv = cmdline.read_bytes().split(b"\0")
        except OSError:  # the process ended while we looked
            continue
        if b"qemu-system" in argv[0] and LANE.encode() in b" ".join(argv):
            raise Refused("lane qemu running")


class LinkTarget(served.ServedTarget):
    ring_fault, tx_hold, conf = False, None, None

    def sshd_iso(self, regenerate=False):
        options = ("net fsd served" + (" nic-ring-fault" if self.ring_fault else "")
                   + (f" {self.tx_hold}" if self.tx_hold else ""))
        iso = self.iso(0, self.root / "sshd.elf", options=options, server=self.root / "absd-fsd.elf")
        host_rules()  # every launch builds its ISO here last, so this is the check right before QEMU starts
        return iso

    def files(self, authorized):
        return super().files(authorized) + ([("/etc/sshd.conf", self.conf)] if self.conf else [])


class LinkMatrix(sm.Matrix):
    qmp = None

    def fresh(self, name):
        (self.work / name).mkdir()
        self.t.setup(self.work / name, self.op.with_suffix(".pub").read_text())

    def boot(self, name, link_up=True, reboot="allow"):
        t = self.t
        self.fresh(name)
        qmp_dir = tempfile.mkdtemp(prefix="absd-qmp-")  # AF_UNIX path length limit
        path, armed = os.path.join(qmp_dir, "qmp.sock"), {}

        def arm():
            try:
                qmp = served.Qmp(path, time.monotonic() + 300)
                qmp.set_link(link_up)
                qmp.execute("cont")
                armed["qmp"] = qmp
            except Exception as e:  # reported by the check below
                armed["error"] = e

        thread = threading.Thread(target=arm, daemon=True)
        thread.start()
        os.environ["ABSD_QEMU_REBOOT"] = reboot
        try:
            info = t.start(qemu_extra=f"{t.qemu} -S -qmp unix:{path},server,nowait",
                           expect_nic_fault=t.ring_fault)
        finally:
            os.environ.pop("ABSD_QEMU_REBOOT", None)
            shutil.rmtree(qmp_dir, ignore_errors=True)
        thread.join(60)
        self.qmp = armed.get("qmp")
        self.check(f"{name}: receive preparation matches the boot's observation mode",
                   info["receive_prepared"] == (not t.ring_fault), repr(info["receive_prepared"]))
        self.check(f"{name}: link set over QMP before the guest ran", self.qmp is not None, repr(armed.get("error")))
        self.client = sm.Client(t.work, t.port)
        self.client.trust(info["public"])
        return t.proc.pid

    def part(self, index=0):
        return recovery.boot_parts(self.t)[index]  # (serial, worker)

    def until(self, what, probe, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = probe()
            if value:
                return value
            time.sleep(0.2)
        raise sm.Failed(f"{what}: not within {timeout} s")

    def await_net(self, count, link):
        lines = self.until(f"SSH NET line {count}", lambda: (l := NET.findall(self.part()[1]))[count - 1:] and l)
        self.check(f"SSH NET line {count} says link={link}", lines[count - 1][0] == link, repr(lines))

    def await_tx(self, count, held, timeout=60):
        lines = self.until(f"SSH NET TX line {count}", lambda: (l := TX.findall(self.part()[1]))[count - 1:] and l,
                           timeout)
        self.check(f"SSH NET TX line {count} says held={held}", lines[count - 1][0] == held, repr(lines))
        return lines

    def children(self):
        return len(re.findall(r"SSH SESSION CHILD pid=\d+", self.part()[1]))

    def session(self, command):
        """Starts `command` over SSH and returns once its session child runs."""
        before = self.children()
        proc = subprocess.Popen(self.client.base(self.op) + [command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.until(f"session child for {command!r}", lambda: self.children() > before)
        return proc

    def transfer(self, result, timeout):
        """Starts the large transfer over SSH; returns once its session child
        runs. Its (rc, out, err) lands in `result["r"]`."""
        t, before = self.t, self.children()
        thread = threading.Thread(daemon=True, target=lambda: result.update(
            r=self.client.run(self.op, t.large_output(TRANSFER_BYTES), timeout=timeout)))
        thread.start()
        self.until("transfer child", lambda: self.children() > before)
        return thread

    def motd(self, what):
        rc, out, err = self.ssh("/bin/cat /etc/motd")
        self.check(what, rc == 0 and out == ssh_absd.MOTD, f"rc={rc} {err!r}")

    def halt(self, what):
        rc, out, err = self.ssh("shutdown")
        status = self.t.status(served.SHUTDOWN_SECONDS) if rc == 0 else None
        self.check(f"{what}: shutdown halts (status 3)", status == "3", f"rc={rc} status={status} {err!r}")

    def streak_kept(self, name, runner_pid, fixture=False):
        """One boot, same QEMU, no recovery or disable; an orderly reboot then
        shows previous=ended: the outage never charged the streak."""
        t = self.t
        serial, worker = self.part()
        self.check(f"{name}: one boot, same QEMU, no SERVED RECOVERY, no NIC DISABLED, no fault, fixture={fixture}",
                   len(recovery.boot_parts(t)) == 1 and t.proc.pid == runner_pid and "SERVED RECOVERY" not in serial
                   and "NIC DISABLED" not in serial and FAULT not in worker and (FIXTURE in serial) == fixture,
                   serial[-800:])
        recovery.recovery_lines(serial, worker, 0, "none")
        rc, out, err = self.ssh("reboot")
        self.check(f"{name}: reboot accepted", rc == 0, f"rc={rc} {err!r}")
        _, serial, worker = recovery.ready(t, 1, runner_pid)
        recovery.recovery_lines(serial, worker, 0, "ended")
        self.halt(name)
        self.qmp.close()

    def link_down_at_boot(self):
        pid = self.boot("link-down-at-boot", link_up=False)
        serial, worker = self.part()
        self.check("the kernel grants the NIC with the link down",
                   "NIC LINK DOWN AT PROBE " in serial and "NIC UNAVAILABLE" not in serial, serial[-600:])
        self.check("readiness path: SSH RECOVERY, SSH NET link=down disabled=0, SSH LISTENING, in that order",
                   "SSH NET link=down disabled=0 " in worker and worker.index("SSH RECOVERY ")
                   < worker.index("SSH NET link=down disabled=0 ") < worker.index("SSH LISTENING "), worker[-600:])
        rc, out, err = self.ssh("/bin/cat /etc/motd", timeout=60)
        self.check("unreachable while down (readiness is not reachability)", rc != 0 and b"timed out" in err, f"rc={rc}")
        self.qmp.set_link(True)
        self.await_net(2, "up")
        self.motd("an authenticated command after restoration, nothing restarted")
        self.streak_kept("link-down-at-boot", pid)
        self.mark("LINK DOWN AT BOOT OK")

    def loss_after_ready(self):
        t, result = self.t, {}
        pid = self.boot("loss-after-ready")
        self.await_net(1, "up")
        long = self.session(t.sleep_command(600))
        transfer = self.transfer(result, 600)  # §10 (a): its child runs before the loss
        self.qmp.set_link(False)
        self.await_net(2, "down")
        time.sleep(OUTAGE_SECONDS)  # the outage is the input, not a wait for state
        self.qmp.set_link(True)
        self.await_net(3, "up")
        transfer.join(600)
        rc, out, err = result.get("r", (None, b"", b"no result"))
        self.check("§10 (a): output outstanding at the loss arrives intact",
                   rc == 0 and out == t.large_output_expect(TRANSFER_BYTES), f"rc={rc} len={len(out)} {err!r}")
        self.check("the long session survived the outage", long.poll() is None)
        self.motd("a second command succeeds after the outage")
        long.kill()
        long.communicate(timeout=30)
        self.check("QEMU's device completed every send: no SSH NET TX line without the fixture",
                   "SSH NET TX " not in self.part()[1], self.part()[1][-600:])
        self.streak_kept("loss-after-ready", pid)
        self.mark(f"LINK LOSS AFTER READY OK outage_s={OUTAGE_SECONDS} transfer_bytes={TRANSFER_BYTES}")

    def flaps(self):
        pid = self.boot("flaps")
        self.await_net(1, "up")
        for cycle in range(FLAPS):
            self.qmp.set_link(False)
            self.await_net(2 + 2 * cycle, "down")
            self.qmp.set_link(True)
            self.await_net(3 + 2 * cycle, "up")
        time.sleep(2)  # ten sample periods: a spurious extra line would show here
        lines = NET.findall(self.part()[1])
        self.check("one SSH NET line per transition, none repeated",
                   len(lines) == 1 + 2 * FLAPS and all(a[0] != b[0] for a, b in zip(lines, lines[1:])), repr(lines))
        self.motd("an authenticated command after the flaps")
        self.streak_kept("flaps", pid)
        self.mark(f"LINK FLAPS OK cycles={FLAPS} lines={len(lines)}")

    def persistent_outage(self):
        t = self.t
        t.conf = f"idle-timeout {IDLE_SECONDS}\n".encode()
        try:
            pid = self.boot("persistent-outage")
        finally:
            t.conf = None
        self.await_net(1, "up")
        first = self.until("first capacity line", lambda: CAPACITY.findall(self.part()[1]))[-1]
        self.check("the first quiescent capacity line says link=up", first[9] == "up", repr(first))
        idle = self.session(t.sleep_command(600))
        self.qmp.set_link(False)
        self.await_net(2, "down")
        # Idle timeout (10 s), then the unanswered close lingers 30 s, then the slot returns.
        after = self.until("capacity line after the idle timeout", lambda: [c for c in CAPACITY.findall(
            self.part()[1]) if int(c[0]) > int(first[0])], timeout=IDLE_SECONDS + 90)[-1]
        self.check("sshd ended the session at its idle timeout", "end: idle timeout" in self.part()[1])
        self.check("occupancy returned during the outage, line says link=down",
                   after[1:9] == first[1:9] and after[9] == "down", f"{first} -> {after}")
        self.qmp.set_link(True)
        self.await_net(3, "up")
        self.motd("a new login succeeds after the outage")
        idle.kill()
        idle.communicate(timeout=30)
        self.streak_kept("persistent-outage", pid)
        self.mark(f"LINK PERSISTENT OUTAGE OK idle_s={IDLE_SECONDS} accepted_reclaimed={after[0]}")

    def absent_nic(self):
        t = self.t
        self.fresh("absent-nic")
        log = t.work / "absent-nic.serial.log"
        # `-nic none`: without it QEMU's pc machine adds its default e1000.
        run = subprocess.run([str(t.kernel / "scripts/durable-boot.sh"), str(t.sshd_iso()), str(t.image), str(log),
                              "180", *served_qemu(t.qemu), "-nic", "none"], capture_output=True, text=True, timeout=240,
                             env=dict(os.environ, ABSD_QEMU_REBOOT="allow"))
        raw = log.read_bytes()
        serial, workers = raw.decode(errors="replace"), served.captured_all(raw)
        self.check("absent NIC: one boot, status 7, refused before readiness, no reset, no SSH NET",
                   run.stdout.strip() == "7" and len(workers) == 1 and "NIC UNAVAILABLE Absent" in serial
                   and "nic: NoNic" in workers[0] and "SSH LISTENING" not in workers[0] and "SSH NET" not in workers[0]
                   and "SERVED RECOVERY REFUSED generation_not_ready" in serial and "MACHINE RECOVER RESET" not in serial,
                   f"status={run.stdout!r} {serial[-800:]}")
        self.mark("ABSENT NIC REFUSED OK status=7")

    def disabled_nic(self):
        """§6.4, one-shot: the ring-fault boot under ABSD_QEMU_REBOOT=exit ends
        QEMU at the recovery reset; the same image then boots an ISO without
        the option (harness only, D6)."""
        t = self.t
        t.ring_fault = True
        try:
            self.boot("disabled-nic", reboot="exit")
            status = t.status(300)
        finally:
            t.ring_fault = False
        self.qmp.close()
        serial, worker = self.part()
        self.check("the device disabled itself at its first ring access",
                   "NIC RING FAULT INJECTED" in serial and "NIC DISABLED reason=rx-head-outside-ring" in serial, serial[-800:])
        self.check("sshd: SSH LISTENING, then SSH NET link=down disabled=1, then the named fault",
                   "SSH NET link=down disabled=1 " in worker and FAULT in worker and worker.index("SSH LISTENING ")
                   < worker.index("SSH NET link=down disabled=1 ") < worker.index(FAULT), worker[-800:])
        self.recovered_after_one_reset("disabled-nic", status, serial)
        self.mark("DISABLED NIC RECOVERED OK resets=1 streak=1")

    def recovered_after_one_reset(self, name, status, serial, armed=None):
        """The §6.4 tail shared by the one-shot device cases: the faulting
        boot (under ABSD_QEMU_REBOOT=exit) ended QEMU at the guest reset after
        init spent one reset under the unchanged budget; the same image then
        boots without the fault option (harness only, D6), carries no `armed`
        banner, recovers with streak 1, logs in and halts."""
        t = self.t
        self.check("QEMU ended at the guest reset (status 0 under ABSD_QEMU_REBOOT=exit)", status == "0", f"status={status}")
        self.check("init spent one reset under the unchanged budget",
                   BEGIN.search(serial) is not None and "SERVED RECOVERY RESET " in serial
                   and "MACHINE RECOVER RESET" in serial and "SERVED RECOVERY ESCALATED" not in serial, serial[-800:])
        os.environ["ABSD_QEMU_REBOOT"] = "allow"
        try:
            t.start(expect_sweep=True)
        finally:
            os.environ.pop("ABSD_QEMU_REBOOT", None)
        _, serial, worker = recovery.ready(t, 0, t.proc.pid)
        recovery.recovery_lines(serial, worker, 1, "failed")
        if armed:
            self.check("the next boot carries no fixture", armed not in serial, serial[-600:])
        self.motd("a login on the next boot")
        self.halt(name)

    def disabled_nic_budget(self):
        """Negative control: the fault on every boot spends three resets; the fourth stops."""
        t = self.t
        t.ring_fault = True
        try:
            self.boot("disabled-nic-budget", reboot="allow")
            status = t.status(1800)
        finally:
            t.ring_fault = False
        self.qmp.close()
        parts = recovery.boot_parts(t)
        self.check("four boots, then the named stop (QEMU status 83)",
                   status == recovery.BUDGET_STOP_STATUS and len(parts) == recovery.BUDGET + 1,
                   f"status={status} boots={len(parts)}")
        for index, (serial, worker) in enumerate(parts):
            recovery.recovery_lines(serial, worker, index, "none" if index == 0 else "failed")
            self.check(f"boot {index + 1}: named fault after SSH LISTENING",
                       FAULT in worker and worker.index("SSH LISTENING ") < worker.index(FAULT), worker[-400:])
        last = parts[-1][0]
        escalated = re.search(rf"(?m)^SERVED RECOVERY ESCALATED reason=recovery_budget_exhausted streak={recovery.BUDGET} "
                              rf"budget={recovery.BUDGET} reaped=\d+ children_drained=\w+ outcome=stop code=20$", last)
        self.check("the fourth fault escalates with code 20",
                   escalated is not None and "MACHINE STOP code=20" in last, last[-800:])
        self.mark(f"DISABLED NIC BUDGET OK resets={recovery.BUDGET} status={status}")

    def tx_hold(self):
        """§10 (b) on QEMU through the kernel's qualification fixture: a
        descriptor posted without carrier is held (`nic-tx-hold`), so a send
        bound expires with the link down while a transfer is in flight. The
        outcome must be the link's: `SSH NET TX held=1`, no disable, no
        reset, streak unchanged; then released when carrier returns. This
        shows the driver's rule, not the device's. On QEMU the held
        descriptor is almost always released by the reap in the next SSH NET
        sample's `nic_info`, not by the next send; sshd prints held=0 after
        its first send not refused for lack of carrier, so this case does not
        show the send-path release."""
        t, result = self.t, {}
        t.tx_hold = "nic-tx-hold"
        try:
            pid = self.boot("tx-hold")
        finally:
            t.tx_hold = None
        self.await_net(1, "up")
        long = self.session(t.sleep_command(600))
        transfer = self.transfer(result, 600)
        lost = time.monotonic()
        self.qmp.set_link(False)
        self.check("the transfer is in flight at the loss", transfer.is_alive())
        self.await_net(2, "down")
        self.await_tx(1, "1", timeout=OUTAGE_SECONDS)
        time.sleep(max(0.0, OUTAGE_SECONDS - (time.monotonic() - lost)))  # the outage is the input
        self.qmp.set_link(True)
        self.await_net(3, "up")
        lines = self.await_tx(2, "0")
        transfer.join(600)
        rc, out, err = result.get("r", (None, b"", b"no result"))
        self.check("§10 (b): the transfer in flight at the loss arrives intact",
                   rc == 0 and out == t.large_output_expect(TRANSFER_BYTES), f"rc={rc} len={len(out)} {err!r}")
        self.check("the long session survived the outage", long.poll() is None)
        worker = self.part()[1]
        final = TX.findall(worker)
        no_carrier = int(lines[1][1])
        self.check("the link outcome was named and counted: held=1 then held=0, one line each, no_carrier >= 1",
                   [h for h, _ in final] == ["1", "0"] and no_carrier >= 1 and int(final[0][1]) >= 1, repr(final))
        self.check("the outcome is the link's: every SSH NET line says disabled=0",
                   all(n[1] == "0" for n in NET.findall(worker)), repr(NET.findall(worker)))
        self.motd("a command succeeds after the hold")
        long.kill()
        long.communicate(timeout=30)
        # streak_kept's in-guest reboot boots the same ISO, so that boot is armed too; no loss follows it.
        self.streak_kept("tx-hold", pid, fixture=True)
        self.mark(f"LINK TX HOLD OK outage_s={OUTAGE_SECONDS} no_carrier={no_carrier} transfer_bytes={TRANSFER_BYTES}")

    def tx_hold_stuck(self):
        """Device-side control: the fixture never releases the held
        descriptor, so the bound that runs once carrier is back expires with
        carrier present. That is a device outcome: NIC DISABLED, the A4
        fault, one reset under the unchanged budget (§6.4 shape, as
        disabled-nic: the boot ends QEMU at the reset, then the same image
        boots without the option)."""
        t, result = self.t, {}
        t.tx_hold = "nic-tx-hold-stuck"
        try:
            self.boot("tx-hold-stuck", reboot="exit")
            self.await_net(1, "up")
            transfer = self.transfer(result, 120)
            self.qmp.set_link(False)
            self.check("the transfer is in flight at the loss", transfer.is_alive())
            self.await_net(2, "down")
            self.await_tx(1, "1", timeout=OUTAGE_SECONDS)
            self.qmp.set_link(True)
            status = t.status(300)
        finally:
            t.tx_hold = None
        self.qmp.close()
        serial, worker = self.part()
        self.check("the kernel armed the stuck fixture and disabled the NIC on the carrier-present expiry",
                   f"{FIXTURE} mode=stuck " in serial and "NIC DISABLED reason=tx-timeout" in serial, serial[-800:])
        self.check("sshd: SSH NET TX held=1, then SSH NET link=down disabled=1, then the named fault",
                   "SSH NET TX held=1 " in worker and "SSH NET link=down disabled=1 " in worker and FAULT in worker
                   and worker.index("SSH NET TX held=1 ") < worker.index("SSH NET link=down disabled=1 ")
                   < worker.index(FAULT), worker[-800:])
        self.recovered_after_one_reset("tx-hold-stuck", status, serial, armed=FIXTURE)
        self.mark("TX HOLD STUCK RECOVERED OK resets=1 streak=1")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--only", choices=CASES)
    args, rest = ap.parse_known_args()
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    base = ssh_absd.target(rest)
    target = LinkTarget.__new__(LinkTarget)
    target.__dict__.update(base.__dict__)
    matrix = LinkMatrix(target, work)
    try:
        for name in (args.only,) if args.only else CASES:
            getattr(matrix, name.replace("-", "_"))()
            target.stop()
    except Refused as e:
        print(f"LINK MATRIX REFUSED {e}", file=sys.stderr)
        target.stop()
        sys.exit(1)
    except (sm.Failed, ssh_absd.Failed, RuntimeError) as e:
        print(f"LINK MATRIX FAILED: {e}", file=sys.stderr)
        target.stop()
        sys.exit(1)
    except BaseException:
        target.stop()
        raise
    print(f"LINK MATRIX OK checks={matrix.checks}")


if __name__ == "__main__":
    main()
