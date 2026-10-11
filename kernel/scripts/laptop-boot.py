#!/usr/bin/env python3
"""Boots an ISO on a synthetic laptop-shaped QEMU machine and reads the
console back from the screen alone.

The machine has no serial port, no debug-exit device, and no legacy disk
(profile `thinkpad`: q35, OVMF, the ISO as a USB stick on xHCI, NVMe
namespaces, VGA). Evidence comes only from the display. The host polls
QEMU screendumps (from the kernel's first line on, the guest is paused
for each one and resumed for a bounded slice between them; it is never
otherwise touched) and decodes every row, cell by cell, against glyphs
read straight from the X11 PCF font (scripts/font-8x13.py): a cell whose
pixels are not exactly one glyph in one of the two console colour pairs
makes the screen "not a console" and it is skipped. Successive screens are merged by row
overlap into a transcript, written where a serial log would go. A screen
that does not overlap the transcript so far is a gap: rows scrolled past
between two polls. Gaps are counted and reported, never papered over.
Once the screen shows `ABSD HALT code=N` and stops changing, the final
screen is checked pixel for pixel against the transcript by the oracle
framebuffer-check.py uses.

    laptop-boot.py --iso ISO --log TRANSCRIPT [--screen OUT.ppm]
        [--profile NAME] [--nvme IMAGE[:SERIAL]]... [--machine-extra OPTS]
        [--cpu MODEL] [--memory SIZE] [--timeout S] [--reset-boots N]

Prints `LAPTOP BOOT <label> status=S halt=N lines=L gaps=G profile=P` per
boot; S is what QEMU's debug-exit device would have returned (4 * code +
3), or 124 when no halt appeared, so harnesses written against debug-exit
can use it. `--reset-boots N` issues N warm resets (HMP system_reset)
after each halt, writing each later boot's transcript to LOG.resetK.
"""

import argparse
import hashlib
import importlib.util
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True

here = pathlib.Path(__file__).resolve().parent
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, here / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fbcheck = load("fbcheck", "framebuffer-check.py")
font = fbcheck.font

OVMF_CODE = ["/usr/share/OVMF/OVMF_CODE_4M.fd"]
OVMF_VARS = ["/usr/share/OVMF/OVMF_VARS_4M.fd"]
OVMF_FLAT = ["/usr/share/ovmf/OVMF.fd", "/usr/share/qemu/OVMF.fd"]


def fail(message):
    print(f"LAPTOP BOOT FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def first(paths):
    return next((p for p in paths if os.path.exists(p)), None)


def profile_args(args, work):
    """QEMU arguments for a named machine shape (no display, monitor, gdb)."""
    machine = "q35"
    if args.machine_extra:
        machine += "," + args.machine_extra
    base = ["-nodefaults", "-machine", machine, "-cpu", args.cpu, "-m", args.memory,
            "-serial", "none", "-parallel", "none", "-device", args.vga]
    stick = ["-drive", f"if=none,id=stick,file={args.iso},format=raw,readonly=on",
             "-device", "qemu-xhci,id=xhci",
             "-device", "usb-storage,bus=xhci.0,drive=stick,bootindex=1"]
    if args.profile in ("thinkpad", "thinkpad-cdrom"):
        code, vars_ = first(OVMF_CODE), first(OVMF_VARS)
        if code and vars_:
            copy = work / "OVMF_VARS.fd"
            shutil.copyfile(vars_, copy)
            firmware = ["-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
                        "-drive", f"if=pflash,format=raw,unit=1,file={copy}"]
        elif first(OVMF_FLAT):
            firmware = ["-bios", first(OVMF_FLAT)]
        else:
            fail("no OVMF firmware found")
    elif args.profile in ("thinkpad-bios", "thinkpad-bios-cdrom"):
        firmware = []
    else:
        fail(f"unknown profile {args.profile}")
    if args.profile.endswith("-cdrom"):
        # The ISO as an optical disc on q35's built-in AHCI controller.
        stick = ["-drive", f"if=none,id=cd,file={args.iso},format=raw,media=cdrom,readonly=on",
                 "-device", "ide-cd,drive=cd,bus=ide.0,bootindex=1"]
    nvme = []
    for index, spec in enumerate(args.nvme):
        image, _, serial = spec.partition(":")
        nvme += ["-drive", f"if=none,id=nvm{index},file={image},format=raw",
                 "-device", f"nvme,serial={serial or 'absd'},drive=nvm{index}"]
    return base + firmware + stick + nvme + args.qemu_extra


class Monitor:
    def __init__(self, path):
        self.path = path

    def command(self, text):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(60)
            client.connect(self.path)
            buffer = b""
            while b"(qemu) " not in buffer:
                buffer += client.recv(65536)
            client.sendall(text.encode() + b"\n")
            buffer = b""
            while b"(qemu) " not in buffer:
                chunk = client.recv(65536)
                if not chunk:
                    break
                buffer += chunk
            return buffer.decode(errors="replace")


class NotConsole(Exception):
    pass


class Screen:
    """Decodes a screendump into console rows, exactly or not at all."""

    def __init__(self):
        self.glyphs = font.glyphs()
        self.size = None
        self.cache = {}

    def decode(self, path):
        width, height, pixels = fbcheck.read_ppm(path)
        if (width, height) != self.size:
            self.size = (width, height)
            self.scale = 2 if width >= 1600 else 1
            self.columns = width // (8 * self.scale)
            self.rows = min(height // (13 * self.scale), 256)
            self.table = {}
            cw, ch = 8 * self.scale, 13 * self.scale
            for colors in (fbcheck.NORMAL, fbcheck.FAULT):
                fg, bg = fbcheck.rgb(colors[0]), fbcheck.rgb(colors[1])
                for code, bits in self.glyphs.items():
                    cell = b"".join(
                        fg if bits[y // self.scale] & (0x80 >> (x // self.scale)) else bg
                        for y in range(ch) for x in range(cw))
                    self.table[cell] = chr(code)
            self.cache = {}
        cell_w, cell_h = 8 * self.scale, 13 * self.scale
        stride = width * 3
        band = stride * cell_h
        rows = []
        for index in range(self.rows):
            block = pixels[index * band : (index + 1) * band]
            key = hashlib.blake2b(block, digest_size=16).digest()
            text = self.cache.get(key)
            if text is None:
                chars = []
                for column in range(self.columns):
                    cell = b"".join(
                        block[y * stride + column * cell_w * 3 : y * stride + (column + 1) * cell_w * 3]
                        for y in range(cell_h))
                    found = self.table.get(cell)
                    if found is None:
                        raise NotConsole(f"row {index} column {column}")
                    chars.append(found)
                text = "".join(chars).rstrip(" ")
                self.cache[key] = text
            rows.append(text)
        return rows


def orderings(rows):
    """Candidate oldest-to-newest orders: start after each blank row."""
    blanks = [i for i, row in enumerate(rows) if not row.strip()]
    if not blanks:
        return [rows]
    out = []
    for b in blanks:
        order = rows[b + 1 :] + rows[: b + 1]
        while order and not order[-1].strip():
            order.pop()
        # Before the ring wraps the leading rows are the never-used blank tail.
        while order and not order[0].strip():
            order.pop(0)
        out.append(order)
    return out


def overlap(transcript, shot):
    """Largest k with transcript[-k:] == shot[:k]."""
    for k in range(min(len(transcript), len(shot)), 0, -1):
        if transcript[-k:] == shot[:k]:
            return k
    return 0


# Bounds, in seconds, of how long the guest runs between two screens.
SLICE_MIN = 0.002
SLICE_MAX = 0.02


def capture(monitor, screen, work, deadline, label, stale=None):
    """Polls screens until a halt notice holds still; returns rows, code, gaps.

    Once the kernel's first line is on screen the guest runs in slices: it
    is paused (HMP `stop`, which also stops its virtual clock and timers)
    while a screen is dumped and decoded, then resumed for a slice sized so
    that less than a screen of rows scrolls by in one. Left running, a
    burst of console output outpaces the host's polling however fast it
    decodes, and the rows scrolled past are gaps.
    """
    shot = work / f"{label}.ppm"
    transcript = []
    gaps = 0
    last = None
    still = 0
    halted = re.compile(r"^ABSD HALT code=(\d+)$")
    started = False
    run = SLICE_MAX
    while time.monotonic() < deadline:
        paused = started
        if paused:
            monitor.command("stop")
        pace = run if started else 0.02
        try:
            monitor.command(f"screendump {shot}")
            try:
                rows = screen.decode(shot)
            except (NotConsole, ValueError, FileNotFoundError):
                stale = None
                continue
            if stale is not None:
                # The previous boot's screen survives a warm reset until the
                # firmware draws, and a deterministic boot can end on the very
                # same pixels: only screens after a non-console one count.
                pace = 0.05
                continue
            candidates = orderings(rows)
            if not started:
                order = candidates[0]
                if not order or order[0] != "ABSD KERNEL BOOT":
                    continue
                started = True
                transcript = []
                best, k = order, 0
            else:
                best, k = max(((c, overlap(transcript, c)) for c in candidates), key=lambda p: p[1])
                if k == 0 and best and transcript:
                    gaps += 1
                # Rows that appeared during the last slice set the next one.
                scrolled = len(best) - k
                if scrolled > screen.rows // 4:
                    run = max(run / 2, SLICE_MIN)
                elif scrolled < screen.rows // 8:
                    run = min(run * 2, SLICE_MAX)
                pace = run
            # The newest row may still be growing; it is taken again next time
            # unless the console has halted.
            final = bool(best) and halted.match(best[-1])
            new = best[k:] if final else best[k:-1] if len(best) > k else []
            transcript += new
            if final:
                if rows == last:
                    still += 1
                    if still >= 3:
                        return transcript, int(final.group(1)), gaps, rows
                else:
                    still = 0
            last = rows
        finally:
            if paused:
                monitor.command("cont")
            time.sleep(pace)
    return transcript, None, gaps, last


def lines_of(rows, columns):
    """Joins wrapped rows (a full row continues on the next) into lines."""
    lines, current = [], ""
    for row in rows:
        current += row
        if len(row.rstrip()) < columns:
            lines.append(current.rstrip(" "))
            current = ""
    if current:
        lines.append(current.rstrip(" "))
    return lines


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iso", required=True)
    parser.add_argument("--log", required=True, help="transcript output (one line per console line)")
    parser.add_argument("--screen")
    parser.add_argument("--profile", default="thinkpad")
    parser.add_argument("--nvme", action="append", default=[], help="IMAGE[:SERIAL]; repeatable")
    parser.add_argument("--machine-extra", default="")
    parser.add_argument("--cpu", default="qemu64")
    parser.add_argument("--memory", default="512M")
    parser.add_argument("--vga", default="VGA")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--reset-boots", type=int, default=0)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--qemu-extra", action="append", default=[])
    parser.add_argument("--describe", help="write the command, HMP 'info qtree' and 'info chardev' here")
    args = parser.parse_args()
    args.qemu_extra = [word for extra in args.qemu_extra for word in extra.split()]

    # The system temporary directory ($TMPDIR honoured): the monitor socket
    # path must fit a sockaddr_un (108 bytes), which deep log paths do not.
    work = pathlib.Path(tempfile.mkdtemp(prefix="laptop-boot."))
    results = []
    try:
        monitor_path = str(work / "monitor")
        command = [args.qemu] + profile_args(args, work) + [
            "-display", "none", "-no-shutdown",
        ] + ([] if args.reset_boots else [
            # -no-reboot turns HMP system_reset into a shutdown as well, so
            # only boots without planned warm resets use it.
            "-no-reboot",
        ]) + [
            "-monitor", f"unix:{monitor_path},server=on,wait=off",
        ]
        qemu = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        monitor = Monitor(monitor_path)
        try:
            for _ in range(400):
                if os.path.exists(monitor_path):
                    break
                if qemu.poll() is not None:
                    fail(f"QEMU exited: {qemu.stderr.read().decode(errors='replace').strip()}")
                time.sleep(0.05)
            if qemu.poll() is not None:
                fail(f"QEMU exited: {qemu.stderr.read().decode(errors='replace').strip()}")
            if args.describe:
                def clean(text):
                    # HMP echoes the command with cursor escapes first.
                    body = text.replace("\r", "").split("\n", 1)[-1]
                    return body.replace("(qemu) ", "")
                pathlib.Path(args.describe).write_text(
                    "$ " + " ".join(command) + "\n\n# info qtree\n" + clean(monitor.command("info qtree"))
                    + "\n# info chardev\n" + clean(monitor.command("info chardev")) + "\n")
            screen = Screen()
            deadline = time.monotonic() + args.timeout
            stale = None
            for boot in range(args.reset_boots + 1):
                label = "boot" if boot == 0 else f"reset{boot}"
                rows, code, gaps, final = capture(monitor, screen, work, deadline, label, stale)
                if code is not None and args.screen:
                    target = args.screen if boot == 0 else f"{args.screen}.{label}.ppm"
                    monitor.command(f"screendump {os.path.abspath(target)}")
                results.append((label, rows, code, gaps))
                if code is None:
                    if args.screen:
                        # Kept for diagnosis: what the screen showed at the end.
                        monitor.command(f"screendump {os.path.abspath(args.screen)}.{label}-timeout.ppm")
                    break
                stale = final
                if boot < args.reset_boots:
                    monitor.command("system_reset")
        finally:
            if qemu.poll() is None:
                try:
                    monitor.command("quit")
                except OSError:
                    qemu.kill()
                try:
                    qemu.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    qemu.kill()
                    qemu.wait()
    finally:
        shutil.rmtree(work, ignore_errors=True)

    ok = True
    for label, rows, code, gaps in results:
        path = pathlib.Path(args.log if label == "boot" else f"{args.log}.{label}")
        lines = lines_of(rows, screen.columns) if rows else []
        # The halt notice is screen-only; keep it out of the serial-shaped
        # transcript and report it through the status.
        if code is not None and lines and lines[-1] == f"ABSD HALT code={code}":
            lines = lines[:-1]
        path.write_text("".join(line + "\n" for line in lines))
        status = 124 if code is None else 4 * code + 3
        print(f"LAPTOP BOOT {label} status={status} halt={'none' if code is None else code} "
              f"lines={len(lines)} gaps={gaps} profile={args.profile}")
        if code is None:
            ok = False
            continue
        if args.screen:
            target = args.screen if label == "boot" else f"{args.screen}.{label}.ppm"
            good, reason = fbcheck.check(fbcheck.read_ppm(target), path.read_bytes(), code)
            if not good:
                print(f"LAPTOP SCREEN FAILED {label}: {reason}", file=sys.stderr)
                ok = False
            else:
                print(f"LAPTOP SCREEN OK {label} {reason}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
