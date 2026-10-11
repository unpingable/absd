#!/usr/bin/env python3
"""Checks for the physical survey boot (scripts/survey-gate.sh).

    survey-check.py trace TRACE [--expect-forbidden]
        QEMU trace (-trace serial_write -trace memory_region_ops_write
        -trace pci_cfg_write -trace 'pci_nvme_*' -trace ide_bus_exec_cmd):
        from the kernel's first serial line on, every device write must go
        to the COM1 UART, the 8259 PICs, the 8254 PIT, or the PCI
        configuration address latch (0xcf8), and no PCI configuration
        write, NVMe command or register access, or ATA command may appear.
        With --expect-forbidden (the positive control) at least one of each
        of: a configuration write, an NVMe register write, and an e1000
        register write must appear instead, proving the trace sees them.

    survey-check.py visible LOG
        The console transcript or serial log LOG ends with the survey
        summary; replaying it through framebuffer-check.py's console model
        (the model the screen was matched against pixel for pixel), every
        summary line and the halt notice must be on the final screen.
"""

import collections
import importlib.util
import pathlib
import re
import sys

sys.dont_write_bytecode = True

MARKER = b"ABSD KERNEL BOOT\n"
ALLOWED = {"serial", "pic", "pit", "pci-conf-idx"}
FORBIDDEN_EVENTS = ("pci_cfg_write", "pci_nvme_", "ide_bus_exec_cmd")


def fail(message):
    print(f"SURVEY CHECK FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def trace(path, expect_forbidden):
    lines = pathlib.Path(path).read_text(errors="replace").splitlines()
    positions, values = [], []
    for index, line in enumerate(lines):
        found = re.match(r"serial_write write addr 0x00 val 0x([0-9a-f]+)$", line)
        if found:
            positions.append(index)
            values.append(int(found.group(1), 16))
    at = bytes(values).find(MARKER)
    if at < 0:
        fail(f"{path}: the kernel's first line is not in the serial trace")
    counts = collections.Counter()
    for line in lines[positions[at]:]:
        written = re.match(r"memory_region_ops_write .* name '([^']*)'$", line)
        if written:
            counts["write " + written.group(1)] += 1
        elif line.startswith(FORBIDDEN_EVENTS):
            counts[line.split()[0]] += 1
    bad = {key: value for key, value in counts.items()
           if not (key.startswith("write ") and key[6:] in ALLOWED)}
    summary = " ".join(f"{key.replace(' ', ':')}={value}" for key, value in sorted(counts.items()))
    if expect_forbidden:
        wanted = ["pci_cfg_write", "write nvme", "write e1000"]
        missing = [name for name in wanted if not any(key.startswith(name) for key in bad)]
        if missing:
            fail(f"{path}: positive control lacks {missing}: {summary}")
        print(f"trace sees device initialization: {summary}")
    else:
        if bad:
            fail(f"{path}: device writes after the kernel's first line: {bad}")
        print(f"after the kernel's first line only {'/'.join(sorted(ALLOWED))} were written: {summary}")


def visible(path):
    here = pathlib.Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("fbcheck", here / "framebuffer-check.py")
    fbcheck = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fbcheck)
    stream = pathlib.Path(path).read_bytes()
    stream = stream[stream.find(MARKER):]
    found = fbcheck.CONSOLE.search(stream)
    if not found:
        fail(f"{path}: no FRAMEBUFFER CONSOLE OK line")
    _, _, columns, rows, _ = (int(v) for v in found.groups())
    grid = fbcheck.model(stream, columns, rows, 0)
    screen = ["".join(chr(grid.get((c, r), (None, None))[0] or 32) for c in range(columns)).rstrip()
              for r in range(rows)]
    text = stream.decode(errors="replace").splitlines()
    try:
        start = max(i for i, line in enumerate(text) if line.startswith("ABSD PHYSICAL SURVEY v1"))
    except ValueError:
        fail(f"{path}: no survey summary")
    summary = text[start:] + ["ABSD HALT code=0"]
    if summary[-2] != "SAFE TO POWER OFF":
        fail(f"{path}: summary does not end with SAFE TO POWER OFF")
    for line in summary:
        if len(line) > columns:
            fail(f"{path}: summary line wider than {columns} columns: {line!r}")
        if line not in screen:
            fail(f"{path}: summary line not on the final screen: {line!r}")
    print(f"summary lines={len(summary)} all on the final {columns}x{rows} screen")


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "trace":
        trace(sys.argv[2], "--expect-forbidden" in sys.argv[3:])
    elif len(sys.argv) == 3 and sys.argv[1] == "visible":
        visible(sys.argv[2])
    else:
        fail(__doc__)


if __name__ == "__main__":
    main()
