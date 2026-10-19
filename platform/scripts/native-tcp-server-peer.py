#!/usr/bin/env python3
"""Fixed-port independent Linux TCP client for the separately admitted VM.

Run inside its fresh isolated namespace; this creates no namespace or QEMU.
The ABSD owner must already be running. Retain capture separately. No negative
case or native PASS is inferred merely from this client's local result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import time

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-tcp-server-peer: optimized Python is refused")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    assert not args.result.exists(), "fresh result path required"
    deadline = time.monotonic() + 8
    data = bytes((i * 131 ^ (i >> 7)) & 255 for i in range(3072))
    sock = None
    try:
        # The runner has already observed trusted LISTEN readiness. Keep one
        # connection attempt alive; abandoning short attempts creates real RSTs
        # when their delayed SYN-ACKs arrive. Kernel SYN retransmissions retain
        # this attempt's sequence identity and are classified by the capture.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(min(4, max(0.001, deadline - time.monotonic())))
        sock.bind(("192.0.2.1", 42030))
        sock.connect(("192.0.2.100", 7005))
        local, peer = sock.getsockname(), sock.getpeername()
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        result = bytearray()
        while True:
            assert time.monotonic() < deadline, "echo deadline"
            sock.settimeout(deadline - time.monotonic())
            block = sock.recv(4097 - len(result))
            if not block:
                break
            result.extend(block)
            assert len(result) <= 4096, "echo byte bound"
        assert bytes(result) == data, "echo mismatch"
        verdict = {"disposition": "PASS", "scope": "independent Linux socket client only",
                   "local": local, "peer": peer, "bytes": len(result),
                   "sha256": hashlib.sha256(result).hexdigest(), "write_half_closed": True, "read_EOF": True}
    except BaseException as error:
        verdict = {"disposition": "FAIL", "error": repr(error)}
        raise
    finally:
        if sock is not None:
            sock.close()
        if "verdict" in locals():
            with args.result.open("x") as output:
                json.dump(verdict, output, indent=2)
                output.write("\n")


if __name__ == "__main__":
    main()
