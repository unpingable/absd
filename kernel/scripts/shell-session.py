#!/usr/bin/env python3
"""Drive the ABSD shell over QEMU's serial socket.

Usage: shell-session.py SOCKET LOG COMMAND...

Connects to the unix socket QEMU serves the serial port on, records every
byte received into LOG, and sends the next COMMAND (plus newline) each time
the shell prints its prompt. Exits 0 once QEMU closes the socket
after the last command, non-zero on a timeout.
"""
import re
import socket
import sys
import time

# The prompt starts a line, or directly follows the previous prompt (the
# shell does not echo, so an empty command leaves "> > "). Anchoring matters:
# kernel lines such as "USER PREEMPT pid=1 -> pid=2" contain "> " too, and a
# read that ends right after "-> " must not be taken for the prompt. The
# prompt need not end the output: init may print right after it.
PROMPT = re.compile(rb"(?:^|\n)> ")
TIMEOUT = 60.0
# Let the guest enter its first console read before replying. This makes the
# shell boot's blocking/wakeup assertion independent of host socket timing.
FIRST_PROMPT_SETTLE = 0.05


def main() -> int:
    path, log_path, *commands = sys.argv[1:]
    deadline = time.monotonic() + TIMEOUT
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    while True:
        try:
            sock.connect(path)
            break
        except OSError:
            if time.monotonic() > deadline:
                print("shell-session: QEMU never opened the socket", file=sys.stderr)
                return 1
            time.sleep(0.05)
    sock.settimeout(1.0)
    output = bytearray()
    pending = list(commands)
    first_prompt = True
    with open(log_path, "wb") as log:
        while True:
            if time.monotonic() > deadline:
                print("shell-session: timed out", file=sys.stderr)
                return 1
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                return 0 if not pending else 1
            log.write(chunk)
            log.flush()
            output += chunk
            prompt = PROMPT.search(output) if pending else None
            if prompt:
                if first_prompt:
                    time.sleep(FIRST_PROMPT_SETTLE)
                    first_prompt = False
                command = pending.pop(0)
                sock.sendall(command.encode() + b"\n")
                del output[: prompt.end()]


if __name__ == "__main__":
    sys.exit(main())
