#!/usr/bin/env python3
"""One feature policy for every platform durable-ISO build.

Use kernel_make() as the command prefix in Python, or run this file from
shell. Select the supported ABI even for importer/non-served durable steps
so a builder cannot accidentally omit it when switching to served mode.
The standalone media.py external probe is not a durable/served image.
Guest launchers share the corresponding RAM policy in served_ram.py.
"""
import os
from pathlib import Path
import subprocess
import sys

FEATURES = "frame-admission-v0"
# Current durable/FSD profile: absd-kernel abi/src/program.rs FILE_SERVER_SLOTS.
# The logger has a separate private channel; it is not a session pool slot.
FILE_SERVER_SLOTS = 18


def file_server_started(serial, *, logger_present):
    """One exact start record for the declared profile, including its logger."""
    channels = 1 + FILE_SERVER_SLOTS + int(logger_present)
    expected = f"FILE SERVER START pid=2 channels={channels}"
    records = [line for line in serial.splitlines() if line.startswith("FILE SERVER START ")]
    return records == [expected]


def kernel_make():
    return [sys.executable, str(Path(__file__).resolve())]


def main(args):
    # Callers cannot replace the policy; command-line make assignments also
    # override inherited EXTERNAL_KERNEL_FEATURES (including make -e).
    if any("EXTERNAL_KERNEL_FEATURES" in arg or "frame-reservation" in arg for arg in args):
        raise ValueError("served kernel features are owned by served_kernel.py")
    smp = bool(args and args[0] == "--operator-smp")
    if smp:
        args = args[1:]
    features = FEATURES + (",smp-operator" if smp else "")
    env = dict(os.environ, EXTERNAL_KERNEL_FEATURES=features)
    return subprocess.call(["make", *args, f"EXTERNAL_KERNEL_FEATURES={features}"], env=env)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ValueError as error:
        sys.exit(str(error))
