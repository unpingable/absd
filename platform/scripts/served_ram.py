#!/usr/bin/env python3
"""Shared QEMU RAM floor for durable/served launchers (host-only policy).

The frame-admission-v0 runner minimum is 256 MiB. ABSD_GUEST_RAM, an
explicit memory argument, and existing QEMU -m options may only raise it.
Non-served low-memory qualification probes do not use this policy.
"""
import os
import re
import shlex
import sys

DEFAULT_GUEST_RAM = "256M"
MIN_GUEST_RAM_BYTES = 256 * 1024 * 1024


def ram_bytes(value):
    # QEMU's bare number is MiB. Also accept its size=...,slots=...,maxmem=...
    # form, judging initial size rather than the hotplug maximum.
    parts = value.split(",")
    size = parts[0].removeprefix("size=")
    keys = set()
    for option in parts[1:]:
        key, separator, setting = option.partition("=")
        if key not in ("slots", "maxmem") or key in keys or not separator or not setting:
            raise ValueError(f"unsupported guest RAM option {option!r}")
        keys.add(key)
    match = re.fullmatch(r"([0-9]+)([kKMGT]?)", size)
    if not match:
        raise ValueError(f"unsupported guest RAM {value!r}: use MiB or K/M/G/T")
    scale = {"": 2**20, "k": 2**10, "K": 2**10, "M": 2**20,
             "G": 2**30, "T": 2**40}[match[2]]
    result = int(match[1]) * scale
    if result < MIN_GUEST_RAM_BYTES:
        raise ValueError(f"served guest RAM {value!r} is below the 256M minimum")
    return result


def served_qemu(argv, memory=None, env=None):
    """Return a fresh argv with one validated -m, preserving larger requests.

    Accept either a shell-style QEMU command string or an argv sequence.
    Validate every supplied size, including duplicate -m options, so a low
    setting cannot be hidden by another option. Normalize to one final -m.
    No process is started here.
    """
    words = shlex.split(argv) if isinstance(argv, str) else list(argv)
    env = os.environ if env is None else env
    sizes = [DEFAULT_GUEST_RAM]
    if "ABSD_GUEST_RAM" in env:
        sizes.append(env["ABSD_GUEST_RAM"])
    if memory is not None:
        sizes.append(memory)
    result = []
    index = 0
    while index < len(words):
        word = words[index]
        if word == "-m":
            index += 1
            if index == len(words):
                raise ValueError("QEMU -m requires a guest RAM size")
            sizes.append(words[index])
        elif word.startswith("-m="):
            sizes.append(word[3:])
        elif word in ("--m", "--memory", "-memory") or word.startswith(("--m=", "--memory=", "-memory=")):
            raise ValueError("use QEMU -m for guest RAM")
        else:
            result.append(word)
        index += 1
    if not result:
        raise ValueError("a QEMU command is required")
    # Prefer a caller's equally sized spelling/options over the default.
    selected = max(enumerate(sizes), key=lambda item: (ram_bytes(item[1]), item[0]))[1]
    return [*result, "-m", selected]


def main(args):
    # Shell launchers delegate argv construction here instead of reimplementing
    # parsing in shell. exec preserves their exit-status and process ownership.
    if args and args[0] == "--durable-boot":
        if len(args) < 7:
            raise ValueError("--durable-boot SCRIPT ISO IMAGE LOG TIMEOUT QEMU...")
        command = [*args[1:6], *served_qemu(args[6:])]
    elif args and args[0] == "--":
        command = served_qemu(args[1:])
    else:
        raise ValueError("usage: served_ram.py -- QEMU... | --durable-boot SCRIPT ISO IMAGE LOG TIMEOUT QEMU...")
    os.execvp(command[0], command)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except ValueError as error:
        sys.exit(str(error))
