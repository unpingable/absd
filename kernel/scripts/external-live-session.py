#!/usr/bin/env python3
"""Drive ABSD's bounded post-boot external-input protocol over COM1."""

from pathlib import Path
import re
import socket
import sys
import time


READY = b"EXTERNAL INPUT READY protocol=absd-stream-v1 max=131072 credit=64"
ACCEPTED = b"EXTERNAL INPUT ACCEPTED protocol=absd-stream-v1"
CREDIT = re.compile(rb"EXTERNAL INPUT CREDIT offset=([0-9]+) max=([0-9]+)")
MAGIC = b"ABSDST01"
TIMEOUT = 180.0


def send_fragmented(sock: socket.socket, data: bytes) -> None:
    widths = (1, 2, 5, 3, 8)
    offset = 0
    turn = 0
    while offset < len(data):
        end = min(len(data), offset + widths[turn % len(widths)])
        sock.sendall(data[offset:end])
        offset = end
        turn += 1
        time.sleep(0.001)


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: external-live-session.py SOCKET LOG INPUT MODE",
            file=sys.stderr,
        )
        return 2
    socket_path, log_path, input_path, mode = sys.argv[1:]
    if mode not in {"normal", "fragmented", "coalesced", "malformed", "truncated"}:
        print(f"unknown live-input mode: {mode}", file=sys.stderr)
        return 2

    deadline = time.monotonic() + TIMEOUT
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    while True:
        try:
            sock.connect(socket_path)
            break
        except OSError:
            if time.monotonic() >= deadline:
                print("external-live: QEMU never opened the socket", file=sys.stderr)
                return 1
            time.sleep(0.02)
    sock.settimeout(0.5)

    lines = bytearray()
    source = None
    header_sent = False
    accepted = False
    truncated_sent = False
    with open(log_path, "wb") as log:
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                if source is not None:
                    source.close()
                return 0
            log.write(chunk)
            log.flush()
            lines.extend(chunk)
            while b"\n" in lines:
                raw_line, _, remainder = lines.partition(b"\n")
                lines = bytearray(remainder)
                line = raw_line.rstrip(b"\r")
                if line == READY and not header_sent:
                    header_sent = True
                    if mode == "malformed":
                        sock.sendall(b"BADHDR00")
                        continue
                    source = open(Path(input_path), "rb", buffering=0)
                    if mode == "fragmented":
                        send_fragmented(sock, MAGIC)
                    else:
                        sock.sendall(MAGIC)
                    continue
                if line == ACCEPTED:
                    accepted = True
                    continue
                match = CREDIT.fullmatch(line)
                if match is None or not accepted or source is None:
                    continue
                maximum = int(match.group(2))
                if mode == "truncated" and not truncated_sent:
                    truncated_sent = True
                    declared = min(maximum, 16)
                    sock.sendall(declared.to_bytes(2, "big") + b"short")
                    continue
                if mode == "truncated":
                    continue
                payload = source.read(maximum)
                if not payload:
                    sock.sendall(b"\x00\x00")
                    source.close()
                    source = None
                    continue
                record = len(payload).to_bytes(2, "big") + payload
                if mode == "fragmented":
                    send_fragmented(sock, record)
                else:
                    sock.sendall(record)
                if mode == "normal":
                    time.sleep(0.002)
        print("external-live: timed out", file=sys.stderr)
        if source is not None:
            source.close()
        return 1


if __name__ == "__main__":
    sys.exit(main())
