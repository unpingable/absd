#!/usr/bin/env python3
"""Measures the e1000 cold receive window on the kernel's `net-probe` boot.

Usage: nic-cold-rx.py WORKDIR DELAY_MS QEMU_COMMAND...

Measurement only: not part of `make check`; `make nic-cold-rx-measure` runs
it (docs/NETWORK.md, "Limits", the QEMU receive gate).

Starts QEMU like scripts/nic-reflect.py (e1000 on a unix `-netdev dgram`
pair), with QEMU's MMIO write trace on, so the guest's writes to the e1000
receive control register (RCTL, BAR offset 0x100) carry host timestamps
(`-msg timestamp=on`).
Once the guest's broadcast hello arrives, waits DELAY_MS, sends one
reflectable frame, and times its reflection. Then ends the probe with the
quit frame. Prints one JSON line: host-clock times (seconds) of the last
RCTL write, the hello, the send and the reflection, and the derived
milliseconds. Every time is the host's CLOCK_REALTIME (QEMU's trace
timestamps and time.time()).
"""
import json, os, re, socket, subprocess, sys, time

ETHERTYPE = b"\x88\xb5"
HOST_MAC = bytes.fromhex("020000000001")


def main():
    workdir, delay_ms, *qemu = sys.argv[1:]
    delay = float(delay_ms) / 1000
    os.makedirs(workdir, exist_ok=True)
    host, guest, log, trace = (os.path.join(workdir, n) for n in ("host.sock", "guest.sock", "serial.log", "trace.log"))
    for p in (host, guest, log, trace):
        if os.path.exists(p):
            os.unlink(p)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(host)
    command = qemu + ["-serial", f"file:{log}", "-device", "e1000,netdev=n0",
                      "-netdev", f"dgram,id=n0,local.type=unix,local.path={guest},remote.type=unix,remote.path={host}",
                      "-msg", "timestamp=on", "-trace", "memory_region_ops_write", "-D", trace]
    started = time.time()
    proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = {"delay_ms": float(delay_ms), "qemu_started": started}
    try:
        deadline = time.monotonic() + 120
        mac = None
        while mac is None:
            if time.monotonic() > deadline or proc.poll() is not None:
                raise SystemExit(f"no NIC PROBE READY (qemu {proc.poll()})")
            try:
                found = re.search(rb"NIC PROBE READY mac=([0-9a-f:]{17})\n", open(log, "rb").read())
                if found:
                    mac = bytes.fromhex(found.group(1).decode().replace(":", ""))
            except FileNotFoundError:
                pass
            time.sleep(0.002)
        result["ready_seen"] = time.time()
        sock.settimeout(10)
        hello = sock.recv(4096)
        result["hello"] = time.time()
        if hello[6:12] != mac or hello[14:24] != b"ABSD-HELLO":
            raise SystemExit("unexpected hello")
        time.sleep(delay)
        frame = mac + HOST_MAC + ETHERTYPE + b"E" + bytes(range(45))
        result["sent"] = time.time()
        sock.sendto(frame, guest)
        sock.settimeout(10)
        got = sock.recv(4096)
        result["reflected"] = time.time()
        if got[12:15] != ETHERTYPE + b"E":
            raise SystemExit("unexpected reflection")
        sock.sendto(mac + HOST_MAC + ETHERTYPE + b"Q" + b"\0" * 45, guest)
        result["qemu_status"] = proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    # QEMU's log backend prefixes each trace line with pid@seconds.microseconds.
    rctl = []
    for line in open(trace, errors="replace"):
        hit = re.match(r"\d+@(\d+\.\d+):memory_region_ops_write .*addr 0x([0-9a-f]+) value 0x([0-9a-f]+) size \d+ name '([^']*)'", line)
        # Addresses are absolute; the e1000's 128 KiB register BAR is aligned, so RCTL is base + 0x100.
        if hit and hit.group(4).startswith("e1000") and int(hit.group(2), 16) & 0x1ffff == 0x100:
            rctl.append((float(hit.group(1)), int(hit.group(3), 16)))
    result["rctl_writes"] = [[t, hex(v)] for t, v in rctl]
    enable = [t for t, v in rctl if v & 2]
    if enable:
        t = enable[-1]
        result["rctl_enable"] = t
        ms = lambda a: round(1000 * (result[a] - t), 1)
        result.update(send_after_enable_ms=ms("sent"), reflect_after_enable_ms=ms("reflected"),
                      reflect_after_send_ms=round(1000 * (result["reflected"] - result["sent"]), 1),
                      hello_after_enable_ms=ms("hello"))
    print(json.dumps(result))


main()
