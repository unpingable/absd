#!/usr/bin/env python3
"""The file server's release rule under load (scripts/run-fsd-release-load.sh).

One `net fsd` boot, QEMU pinned to a CPU set, and CPU hogs pinned to the
same set, so that the guest is starved whatever the host's size. Then
ROUNDS sessions, each `ssh host /bin/fsd-probe garbage` or `... leave`: the
probe writes four bytes no frame may have, or one whole request, and
exits; sshd releases the slot, often before the file server has read the
channel. Meanwhile a second session appends and syncs a file the whole
time.

Counted, not sampled: every garbage send is dropped and breaks nothing
(since the 2026-10-02 audit repair the file server drops bytes that are no
frame and the channel goes on; `FSD CHANNEL BROKEN` no longer exists),
every session released (`FSD RELEASE`) with nothing left open
and its scratch removed, no binding refused (`FSD BIND REFUSED`, which a
leaked holder would cause; `FSD BIND DEFERRED`, a bind that waited for a
released slot's last request to be refused, is counted and reported), the
other session's file
whole on the device, and every slot the load used binding again afterwards (three shells at once,
since sessions bind the lowest free slot). The
last line is `FSD RELEASE LOAD OK` or `FSD RELEASE LOAD FAILED`.

Under check-all.sh this ordering is only sometimes produced; the host test
`release_answers_what_was_sent_and_bind_discards_what_predates_it`
(fsd/src/tests.rs) fixes it. This script is not part of check-all.sh.
"""

import argparse
import importlib.util
import pathlib
import re
import subprocess
import sys
import time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import ssh_absd  # noqa: E402

spec = importlib.util.spec_from_file_location("fsd_matrix", here / "fsd-matrix.py")
fm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fm)

RELEASE = re.compile(r"FSD RELEASE slot=(\d+) closed=(\d+) scratch_removed=(\d+)")
BIND = re.compile(r"FSD BIND slot=(\d+) ")


def hog(cpus):
    """One busy loop pinned to `cpus`, in its own session (killed by PID)."""
    return subprocess.Popen(["taskset", "-c", cpus, "sh", "-c", "while :; do :; done"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--rounds", type=int, default=40)
    ap.add_argument("--hogs", type=int, default=12)
    ap.add_argument("--cpus", default="0-3", help="CPU set for QEMU and the hogs (taskset -c)")
    ap.add_argument("--hold-ms", type=int, default=30000, help="how long the other session writes")
    args, rest = ap.parse_known_args()
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    t = ssh_absd.target(rest)
    t.qemu = f"taskset -c {args.cpus} {t.qemu}"
    m = fm.FsdMatrix(t, work)
    hogs = []
    failures = []

    def expect(name, ok, detail=""):
        print(f"  {'ok  ' if ok else 'FAIL'} {name}{(': ' + detail) if detail and not ok else ''}", flush=True)
        if not ok:
            failures.append(name)

    try:
        t.setup(work, m.op.with_suffix(".pub").read_text())
        first = t.start(fresh=True)
        m.client = fm.sm.Client(work, t.port)
        m.client.trust(first["public"])
        rc, out, err = m.ssh("/bin/fsd-probe garbage")
        expect("an unloaded garbage send is dropped and the session ends normally",
               rc == 0 and out == b"garbage: sent\n", f"rc={rc} {out!r} {err!r}")
        base = len(t.serial())
        hogs = [hog(args.cpus) for _ in range(args.hogs)]
        other = m.shell_async([f"/bin/fsd-probe hold /home/operator/bystander {args.hold_ms}", "cat /etc/motd"])
        time.sleep(2)
        sent = {"garbage": 0, "leave": 0}
        refused_start = 0
        started = time.monotonic()
        for i in range(args.rounds):
            what = "garbage" if i % 2 == 0 else "leave"
            rc, out, err = m.ssh(f"/bin/fsd-probe {what}", timeout=600)
            if out == f"{what}: sent\n".encode():
                sent[what] += 1
            else:
                refused_start += 1
                print(f"  round {i}: rc={rc} out={out!r} err={err[-200:]!r}", flush=True)
        elapsed = time.monotonic() - started
        ro, oo, eo = m.finish(other, timeout=args.hold_ms / 1000 + 600)
        sessions = args.rounds + 1
        settled = m.wait_for(lambda: len(RELEASE.findall(t.serial()[base:])) >= sessions, timeout=120)
        for h in hogs:
            h.kill()
        for h in hogs:
            h.wait()
        hogs = []
        serial = t.serial()[base:]

        broken = serial.count("FSD CHANNEL BROKEN")
        releases = [tuple(map(int, r)) for r in RELEASE.findall(serial)]
        histogram = {}
        for _, closed, scratch in releases:
            histogram[(closed, scratch)] = histogram.get((closed, scratch), 0) + 1
        bind_refused = serial.count("FSD BIND REFUSED")
        deferred = serial.count("FSD BIND DEFERRED")
        slots_used = sorted({int(s) for s in BIND.findall(serial)})
        expect(f"every session started ({args.rounds} rounds)", refused_start == 0, f"{refused_start} did not")
        expect("no garbage send breaks a channel", broken == 0 and sent["garbage"] > 0,
               f"sent={sent['garbage']} reported_broken={broken}")
        expect("every session was released", settled and len(releases) == sessions,
               f"releases={len(releases)} sessions={sessions}")
        expect("every release closed nothing and removed one scratch directory",
               all(closed == 0 and scratch == 1 for _, closed, scratch in releases), str(histogram))
        expect("no binding was refused (nothing leaked, no reply left unread)", bind_refused == 0, str(bind_refused))
        expect("the file server never failed and no session end was forced",
               "FSD FAILED" not in serial and "forced=true" not in serial, serial[-600:])
        held = re.search(r"hold: (\d+) lines", oo.decode(errors="replace"))
        lines_on_device = t.tree().get("/home/operator/bystander", b"")
        expect("the other session wrote throughout and its file is whole on the device",
               ro == 0 and held is not None and fm.lines(oo)[-1] == ssh_absd.MOTD.decode().strip()
               and lines_on_device == "".join(f"line {i}\n" for i in range(1, int(held.group(1)) + 1)).encode()
               if held else False,
               f"rc={ro} out={oo[-200:]!r} err={eo[-200:]!r}")

        # Slots bind lowest-free first, so one session at a time would only
        # ever show slot 1 again: three shells at once, four times over,
        # reach every slot the load used (shells take a slot and spares).
        after = len(t.serial())
        rebound = 0
        for round_ in range(4):
            # Paced: one source (QEMU's NAT) may hold two unauthenticated
            # connections at once, so each shell has started before the
            # next connection opens; the three sessions still overlap.
            shells = []
            for i in range(3):
                spawned = t.spawn_count()
                shells.append(m.shell_async([f"/bin/fsd-probe write /home/operator/rebound-{round_}-{i} 100", "cat /etc/motd"]))
                t.await_spawns(spawned, 1)
            for p in shells:
                rc, out, err = m.finish(p)
                rebound += rc == 0 and fm.lines(out)[-1:] == [ssh_absd.MOTD.decode().strip()]
        slots_after = sorted({int(s) for s in BIND.findall(t.serial()[after:])})
        expect("every slot the load used serves again afterwards", rebound == 12 and set(slots_used) <= set(slots_after)
               and "FSD BIND REFUSED" not in t.serial()[after:],
               f"rebound={rebound}/12 used={slots_used} after={slots_after}")
        print(f"FSD RELEASE LOAD sent_garbage={sent['garbage']} broken_reported={broken} sent_leave={sent['leave']} "
              f"releases={len(releases)} sessions={sessions} closed_scratch={histogram} bind_refused={bind_refused} "
              f"bind_deferred={deferred} "
              f"held_lines={held.group(1) if held else 'none'} rebinds={rebound}/12 slots={slots_used} "
              f"hogs={args.hogs} cpus={args.cpus} rounds_s={elapsed:.0f}", flush=True)
    finally:
        for h in hogs:
            h.kill()
        for h in hogs:
            h.wait()
        t.stop()
    if failures:
        print(f"FSD RELEASE LOAD FAILED: {failures}")
        sys.exit(1)
    print("FSD RELEASE LOAD OK")


if __name__ == "__main__":
    main()
