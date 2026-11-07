#!/usr/bin/env python3
"""Checks a boot's EVIDENCE DIGEST line against its captured serial log.

The kernel keeps a running FNV-1a-64 digest and count of every byte it
writes to the console stream (src/serial.rs, `byte_out`) and prints

    EVIDENCE DIGEST bytes=N fnv1a=XXXXXXXXXXXXXXXX tx-dropped=D

covering every byte before that line (docs/hardware/NO-UART-EVIDENCE.md).
This script recomputes the digest over the raw log bytes before each such
line and checks the count and digest. Every line that starts with
`EVIDENCE DIGEST` must be the whole current form above, all three fields
and its newline: an older or truncated line fails. It also fails when there
is no line, when `tx-dropped` is not 0 (the kernel's transmit wait ran out
for that many bytes, which were then never written to the UART, so the log
cannot match), or when either value differs. The log is read as raw bytes: no newline or encoding
translation, so a capture that rewrote line endings fails, as it should.

Usage:
  evidence-digest.py SERIAL.LOG [--digest HEX]   (--digest: also require
                                                  this value, e.g. read off
                                                  a screen photograph)
  evidence-digest.py --self-test
"""
import re
import sys

OFFSET = 0xCBF29CE484222325
PRIME = 0x100000001B3
START = re.compile(rb"^EVIDENCE DIGEST", re.M)
LINE = re.compile(rb"EVIDENCE DIGEST bytes=(\d+) fnv1a=([0-9a-f]{16}) tx-dropped=(\d+)\n")


def fnv1a(data, state=OFFSET):
    for byte in data:
        state = ((state ^ byte) * PRIME) & 0xFFFFFFFFFFFFFFFF
    return state


def check(log, want_digest=None):
    """Returns a list of (ok, message), one per EVIDENCE DIGEST line."""
    results = []
    for start in START.finditer(log):
        match = LINE.match(log, start.start())
        if not match:
            end = log.find(b"\n", start.start())
            text = log[start.start(): end if end >= 0 else len(log)]
            results.append((False, f"malformed or truncated line: {text!r}"))
            continue
        claimed_bytes = int(match.group(1))
        claimed = int(match.group(2), 16)
        dropped = int(match.group(3))
        prefix = log[: match.start()]
        actual = fnv1a(prefix)
        problems = []
        if dropped:
            problems.append(f"kernel reports {dropped} dropped UART bytes")
        if len(prefix) != claimed_bytes:
            problems.append(f"bytes: line says {claimed_bytes}, log has {len(prefix)}")
        if actual != claimed:
            problems.append(f"fnv1a: line says {claimed:016x}, log gives {actual:016x}")
        if want_digest is not None and claimed != want_digest:
            problems.append(f"fnv1a {claimed:016x} is not the expected {want_digest:016x}")
        message = (f"EVIDENCE DIGEST bytes={claimed_bytes} fnv1a={claimed:016x}: "
                   + ("matches the log" if not problems else "; ".join(problems)))
        results.append((not problems, message))
    if not results:
        results.append((False, "no EVIDENCE DIGEST line"))
    return results


def self_test():
    # FNV-1a-64 reference vectors.
    assert fnv1a(b"") == 0xCBF29CE484222325
    assert fnv1a(b"a") == 0xAF63DC4C8601EC8C
    assert fnv1a(b"foobar") == 0x85944171F73967E8

    def boot(body):
        return body + b"EVIDENCE DIGEST bytes=%d fnv1a=%016x tx-dropped=0\n" % (len(body), fnv1a(body))

    body = b"ABSD KERNEL BOOT\nAMDVI AHCI permitted lba=0 read=done\nAMDVI ENFORCE OK\n"
    good = boot(body)
    assert all(ok for ok, _ in check(good)), check(good)
    # Bytes after the line (e.g. a trailing summary) do not matter.
    assert all(ok for ok, _ in check(good + b"after\n"))
    # An expected digest (from a photograph) must match too.
    assert all(ok for ok, _ in check(good, fnv1a(body)))
    # Negative controls: each must fail.
    negatives = {
        "no line": body,
        "one byte changed": good.replace(b"ENFORCE OK", b"ENFORCE OX", 1),
        "a byte inserted": b"x" + good,
        "a byte removed": good[1:],
        "CRLF capture": good.replace(b"\n", b"\r\n"),
        "count wrong": good.replace(b"bytes=%d" % len(body), b"bytes=%d" % (len(body) + 1)),
        "digest wrong": good.replace(b"%016x" % fnv1a(body), b"%016x" % (fnv1a(body) ^ 1)),
        "uart dropped": good.replace(b"tx-dropped=0", b"tx-dropped=3"),
        "tx-dropped omitted": good.replace(b" tx-dropped=0", b""),
        "no line terminator": good[:-1],
        "truncated in the digest": good[: good.index(b"fnv1a=") + 10],
        "truncated after fnv1a": good[: good.index(b" tx-dropped")] + b"\n",
        "tx-dropped empty": good.replace(b"tx-dropped=0", b"tx-dropped="),
        "good line then an omitted one": good + boot(good + b"more\n")[len(good):].replace(b" tx-dropped=0", b""),
    }
    for name, log in negatives.items():
        assert not all(ok for ok, _ in check(log)), f"negative control passed: {name}"
    assert not all(ok for ok, _ in check(good, fnv1a(body) ^ 2)), "wrong photographed digest passed"
    # Two lines: each covers everything before it.
    second = boot(good + b"more\n")
    assert all(ok for ok, _ in check(second)) and len(check(second)) == 2
    print("evidence-digest: self-test ok (%d negative controls)" % (len(negatives) + 1))


def main(argv):
    if argv == ["--self-test"]:
        self_test()
        return 0
    if not argv or argv[0].startswith("-"):
        print(__doc__, file=sys.stderr)
        return 2
    want = None
    if len(argv) == 3 and argv[1] == "--digest":
        want = int(argv[2], 16)
    elif len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[0], "rb") as handle:
        log = handle.read()
    results = check(log, want)
    for ok, message in results:
        print(("ok: " if ok else "FAILED: ") + message)
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
