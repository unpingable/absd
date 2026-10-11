#!/usr/bin/env python3
"""Decode ABSD's hex-framed external output and compare exact bytes."""

import re
import sys
from pathlib import Path

BEGIN = b"EXTERNAL OUTPUT BEGIN encoding=hex"
CHUNK = re.compile(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)")
END = re.compile(rb"EXTERNAL OUTPUT END bytes=([0-9]+) digest=([0-9a-f]{8})")


def fail(message: str) -> None:
    raise SystemExit(f"external output: {message}")


def main() -> None:
    printing = len(sys.argv) == 3 and sys.argv[1] == "--print"
    if len(sys.argv) != 3:
        fail("usage: check-external-output.py SERIAL EXPECTED | --print SERIAL")
    lines = Path(sys.argv[2 if printing else 1]).read_bytes().splitlines()
    begins = [index for index, line in enumerate(lines) if line == BEGIN]
    ends = [(index, END.fullmatch(line)) for index, line in enumerate(lines)]
    ends = [(index, match) for index, match in ends if match is not None]
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0][0]:
        fail("missing, duplicate, or misordered frame boundary")

    data = bytearray()
    for line in lines[begins[0] + 1 : ends[0][0]]:
        match = CHUNK.fullmatch(line)
        if match is None:
            continue
        offset = int(match.group(1), 16)
        if offset != len(data):
            fail(f"non-contiguous chunk at {offset}, expected {len(data)}")
        try:
            data.extend(bytes.fromhex(match.group(2).decode("ascii")))
        except ValueError as error:
            fail(f"invalid chunk hex: {error}")

    declared_count = int(ends[0][1].group(1))
    declared_digest = int(ends[0][1].group(2), 16)
    digest = 0x811C9DC5
    for byte in data:
        digest = ((digest ^ byte) * 0x01000193) & 0xFFFFFFFF
    if declared_count != len(data) or declared_digest != digest:
        fail("end record does not match decoded bytes")
    if printing:
        sys.stdout.buffer.write(bytes(data))
        return
    expected = Path(sys.argv[2]).read_bytes()
    if data != expected:
        fail(f"decoded {len(data)} bytes do not match {len(expected)} expected bytes")


if __name__ == "__main__":
    main()
