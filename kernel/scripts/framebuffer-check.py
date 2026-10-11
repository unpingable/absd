#!/usr/bin/env python3
"""Host oracle for the framebuffer console.

Boots an ISO under QEMU with an HMP monitor socket, waits for a serial
marker, takes QEMU screendumps, and requires the whole screen to be exactly
what the serial stream implies: the host replays the serial bytes through
its own model of the console (8x13 cells, deferred wrap, a ring of rows
with a blank row kept ahead of the cursor, failure colours from the first
`ABSD PANIC:` or `KERNEL FAULT vector=` line, and serial-only `RECORD `
lines left out), renders every cell with
glyphs read straight from the X11 PCF font, and compares every pixel. The
kernel's own rasterizer is not used.

    framebuffer-check.py --iso ISO --serial LOG --screen OUT.ppm \
        --until MARKER [--halt-code N] [--firmware OVMF.fd] [--timeout S]
"""

import argparse
import importlib.util
import os
import pathlib
import re
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("font8x13", here / "font-8x13.py")
font = importlib.util.module_from_spec(spec)
spec.loader.exec_module(font)

NORMAL = (0xE0E0E0, 0x102040)
FAULT = (0xFFFFFF, 0xA00000)
FAULT_LINES = (b"ABSD PANIC: ", b"KERNEL FAULT vector=")
# Lines the kernel writes to serial only (serial::record_only).
RECORD_LINE = b"RECORD "
CONSOLE = re.compile(
    rb"FRAMEBUFFER CONSOLE OK width=(\d+) height=(\d+) pitch=\d+ bpp=\d+ rgb=\S+ "
    rb"columns=(\d+) rows=(\d+) scale=(\d+) "
)


def fail(message):
    print(f"FRAMEBUFFER CHECK FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def rgb(value):
    return bytes(((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF))


def read_ppm(path):
    data = pathlib.Path(path).read_bytes()
    fields, offset = [], 0
    while len(fields) < 4:
        while data[offset : offset + 1].isspace():
            offset += 1
        if data[offset : offset + 1] == b"#":
            offset = data.index(b"\n", offset) + 1
            continue
        end = offset
        while not data[end : end + 1].isspace():
            end += 1
        fields.append(data[offset:end])
        offset = end
    offset += 1
    if fields[0] != b"P6" or fields[3] != b"255":
        raise ValueError(f"unexpected PPM header {fields}")
    width, height = int(fields[1]), int(fields[2])
    pixels = data[offset : offset + width * height * 3]
    if len(pixels) != width * height * 3:
        raise ValueError("truncated PPM")
    return width, height, pixels


def model(stream, columns, rows, halt_code):
    """Final text grid: {(column, row): (byte or None, (fg, bg))}."""
    grid = {}
    extent = [0] * rows
    column = row = 0
    colors = NORMAL

    def clear(target):
        for cell in range(extent[target]):
            grid[(cell, target)] = (None, colors)
        extent[target] = 0

    def newline():
        nonlocal column, row
        column = 0
        row = (row + 1) % rows
        clear(row)
        clear((row + 1) % rows)

    def draw(byte):
        nonlocal column
        if column == columns:
            newline()
        grid[(column, row)] = (byte if 0x20 <= byte <= 0x7E else ord("?"), colors)
        column += 1
        extent[row] = max(extent[row], column)

    if halt_code is not None:
        stream = stream + b"\0HALT"
    at_line_start = True
    index = 0
    while index < len(stream):
        if stream[index:] == b"\0HALT":
            if halt_code != 0:
                colors = FAULT
            for byte in f"ABSD HALT code={halt_code}\n".encode():
                if byte == 0x0A:
                    newline()
                else:
                    draw(byte)
            break
        byte = stream[index]
        if at_line_start and stream.startswith(RECORD_LINE, index):
            # Serial-only record (the survey boot's verbose lines).
            end = stream.find(b"\n", index)
            index = len(stream) if end < 0 else end + 1
            continue
        if at_line_start and stream.startswith(FAULT_LINES, index):
            colors = FAULT
        at_line_start = byte == 0x0A
        if byte == 0x0A:
            newline()
        elif byte == 0x0D:
            column = 0
        elif byte == 0x09:
            stop = min((column // 8 + 1) * 8, columns)
            while column < stop:
                draw(0x20)
        else:
            draw(byte)
        index += 1
    return grid


def check(screen, serial, halt_code):
    width, height, pixels = screen
    start = serial.find(b"ABSD KERNEL BOOT\n")
    found = CONSOLE.search(serial)
    if start < 0 or not found:
        return False, "serial log lacks the boot or console line"
    fb_width, fb_height, columns, rows, scale = (int(v) for v in found.groups())
    if (width, height) != (fb_width, fb_height):
        return False, f"screendump {width}x{height} but console {fb_width}x{fb_height}"
    # The grid comes from the screen size alone, never from the kernel's
    # report, so a console claiming a smaller grid cannot shrink the check.
    expected_scale = 2 if width >= 1600 else 1
    expected = (width // (8 * expected_scale), min(height // (13 * expected_scale), 256), expected_scale)
    if (columns, rows, scale) != expected:
        return False, f"console reports columns={columns} rows={rows} scale={scale}, screen implies {expected}"
    glyphs = font.glyphs()
    grid = model(serial[start:], columns, rows, halt_code)
    cell_w, cell_h = 8 * scale, 13 * scale
    stride = width * 3
    drawn = fault_cells = 0
    for cell_row in range(rows):
        for cell_column in range(columns):
            byte, (fg, bg) = grid.get((cell_column, cell_row), (None, NORMAL))
            bits = glyphs[byte] if byte is not None else [0] * 13
            drawn += byte is not None
            fault_cells += byte is not None and (fg, bg) == FAULT
            fg_px, bg_px = rgb(fg), rgb(bg)
            for y in range(cell_h):
                line = bits[y // scale]
                base = (cell_row * cell_h + y) * stride + cell_column * cell_w * 3
                expected = b"".join(
                    fg_px if line & (0x80 >> (x // scale)) else bg_px for x in range(cell_w)
                )
                if pixels[base : base + cell_w * 3] != expected:
                    shown = chr(byte) if byte is not None else "blank"
                    return False, f"cell column={cell_column} row={cell_row} ({shown!r}) differs at y={y}"
    if drawn == 0:
        return False, "no drawn cells: the comparison would be vacuous"
    # Outside the text grid only the initial clear ever drew.
    background = rgb(NORMAL[1])
    for y in range(height):
        first = columns * cell_w if y < rows * cell_h else 0
        row_bytes = pixels[y * stride + first * 3 : (y + 1) * stride]
        if row_bytes != background * (width - first):
            return False, f"margin pixel row {y} is not background"
    return True, f"cells={columns * rows} drawn={drawn} fault_cells={fault_cells} columns={columns} rows={rows}"


def monitor(path, command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(30)
        client.connect(path)
        buffer = b""
        while b"(qemu) " not in buffer:
            buffer += client.recv(4096)
        client.sendall(command.encode() + b"\n")
        buffer = b""
        while b"(qemu) " not in buffer:
            chunk = client.recv(4096)
            if not chunk:
                break
            buffer += chunk
        return buffer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iso", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--screen", required=True)
    parser.add_argument("--until", required=True, help="serial line that precedes the halt")
    parser.add_argument("--halt-code", type=int)
    parser.add_argument("--firmware")
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    args = parser.parse_args()

    log = pathlib.Path(args.serial)
    sock = str(log) + ".monitor"
    for stale in (log, pathlib.Path(sock), pathlib.Path(args.screen)):
        if stale.exists():
            stale.unlink()
    command = args.qemu.split() + [
        "-cdrom", args.iso, "-display", "none", "-serial", f"file:{log}",
        "-monitor", f"unix:{sock},server=on,wait=off",
        "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
    ]
    if args.firmware:
        command += ["-bios", args.firmware]
    qemu = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + args.timeout
        marker = args.until.encode()
        while True:
            if qemu.poll() is not None:
                fail(f"QEMU exited with status {qemu.returncode} before {args.until!r}")
            if time.monotonic() > deadline:
                fail(f"timed out waiting for {args.until!r}")
            if log.exists() and marker in log.read_bytes():
                break
            time.sleep(0.2)
        # The halt notice is drawn after the last serial byte; retry the
        # screendump until the screen settles or the deadline passes.
        reason = "no screendump"
        while time.monotonic() < deadline:
            monitor(sock, f"screendump {args.screen}")
            if os.path.exists(args.screen):
                ok, reason = check(read_ppm(args.screen), log.read_bytes(), args.halt_code)
                if ok:
                    print(f"FRAMEBUFFER SCREEN OK {reason} screen={args.screen}")
                    break
            time.sleep(0.5)
        else:
            fail(reason)
    finally:
        if qemu.poll() is None:
            try:
                monitor(sock, "quit")
            except OSError:
                qemu.kill()
            try:
                qemu.wait(timeout=30)
            except subprocess.TimeoutExpired:
                qemu.kill()
                qemu.wait()
        if os.path.exists(sock):
            os.unlink(sock)


if __name__ == "__main__":
    main()
