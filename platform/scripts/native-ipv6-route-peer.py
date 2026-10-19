#!/usr/bin/env python3
"""Bounded Linux AF_INET6 DNS application; the Linux kernel performs routing/ND."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import time
import types

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("optimized Python refused")
SOURCE = Path(__file__).with_name("native-ipv6-peer.py")
SOURCE_HASH = "c72d3146d9eb26850208ce5cd85744209ee41af140fa878b523da73b4d90da37"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    parser.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args()
    assert 1 <= args.timeout <= 180 and args.work.is_dir()
    with SOURCE.open("rb") as stream:
        data = stream.read((1 << 20) + 1)
    assert len(data) <= 1 << 20 and hashlib.sha256(data).hexdigest() == SOURCE_HASH
    codec = types.ModuleType("route_linux_dns")
    codec.__file__ = str(SOURCE)
    exec(compile(data, str(SOURCE), "exec"), codec.__dict__)
    peer = codec.Peer("fd00:ab5d:2::9", 42010, 42011, ("fd00:ab5d:1::15", 7002), args.timeout)
    signal.signal(signal.SIGTERM, lambda *_: peer.stop.set())
    signal.signal(signal.SIGINT, lambda *_: peer.stop.set())
    try:
        codec.write_json(args.work / "PEER-READY.json", {"pid": os.getpid(), "bind": "fd00:ab5d:2::9", "port": 42010,
                         "source": ["fd00:ab5d:1::15", 7002], "transport": "Linux AF_INET6 SOCK_DGRAM"})
        while not peer.stop.is_set() and not (args.work / "PEER-STOP").exists():
            peer.stop.wait(0.02)
    finally:
        peer.close()
        codec.write_json(args.work / "PEER-RESULT.json", {"records": peer.records, "errors": peer.errors,
                         "disposition": "FAIL" if peer.errors else "PASS", "pid": os.getpid()})
    if peer.errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
