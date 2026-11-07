#!/usr/bin/env python3
"""Two bounded ordinary Linux TCP sockets; no generated network packets.

Run only in the occurrence-owned peer namespace. The 42100 socket records
whether any application byte was received. The 42101 socket echoes exactly
bytes 0..63 and observes the caller's half-close. The router generates ICMP.
Both sockets stay open after both rows finish, until the runner publishes
its stop file after the guest has ended and the router capture has closed
(PEER-STOP), so no peer close is ever ordered against guest speed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import tempfile
import time

GUEST = "192.0.2.100"
ROUTER = "192.0.2.1"
PEER = "198.51.100.2"
ERROR_PORT, POSITIVE_PORT = 42100, 42101
POSITIVE = bytes(range(64))
NEGATIVE = bytes(i % 251 for i in range(1024))


def atomic(path, value):
    """Publish one complete immutable JSON record without a partial reader."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".mtu-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def run(output, stop_file, timeout=60, zero_window=1.5):
    assert 2 <= timeout <= 90 and 1 <= zero_window <= 3
    started = time.monotonic_ns()
    deadline = time.monotonic() + timeout
    listeners, streams, rows, events = {}, {}, {}, []
    report = {"schema": "absd-native-tcp-mtu-peer/1", "disposition": "FAIL",
              "pid": os.getpid(), "network_namespace_inode": os.stat("/proc/self/ns/net").st_ino,
              "bind": PEER, "started_monotonic_ns": started,
              "zero_read_window_ns": int(zero_window * 1_000_000_000), "events": events,
              "runner_stop_received": False}

    def event(kind, port, **values):
        assert len(events) < 64, "peer event bound"
        events.append({"event": kind, "port": port, "monotonic_ns": time.monotonic_ns(), **values})

    try:
        for port in (ERROR_PORT, POSITIVE_PORT):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listeners[listener] = port
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.setblocking(False)
            listener.bind((PEER, port))
            listener.listen(1)
        atomic(output.with_suffix(".ready.json"), {
            "schema": "absd-native-tcp-mtu-peer-ready/1", "pid": os.getpid(),
            "network_namespace_inode": report["network_namespace_inode"],
            "bind": PEER, "ports": [ERROR_PORT, POSITIVE_PORT],
            "ready_monotonic_ns": time.monotonic_ns()})
        while len(rows) != 2 or not all(row["finished"] for row in rows.values()):
            now = time.monotonic()
            assert now < deadline, "peer absolute deadline"
            readable, writable, _ = select.select(
                list(listeners) + [s for s, r in streams.items() if not r["finished"] and not r["eof"]],
                [s for s, r in streams.items() if r["port"] == POSITIVE_PORT and r["sent"] < len(r["received"])],
                [], min(0.02, deadline - now))
            for current in readable:
                if current in listeners:
                    port = listeners[current]
                    stream, source = current.accept()
                    stream.setblocking(False)
                    stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    try:
                        assert port not in rows and source == (GUEST, 7100 if port == ERROR_PORT else 7101), "exact single connection tuple"
                    except BaseException:
                        stream.close()
                        raise
                    at = time.monotonic_ns()
                    row = {"port": port, "source": list(source), "destination": [PEER, port],
                           "accepted_monotonic_ns": at, "received": bytearray(), "sent": 0,
                           "finished": False, "eof": False, "reset": False}
                    rows[port], streams[stream] = row, row
                    event("accept", port, source=list(source), destination=[PEER, port])
                    continue
                row = streams[current]
                try:
                    data = current.recv(65)
                except BlockingIOError:
                    continue
                except ConnectionResetError:
                    row["reset"] = True
                    data = b""
                event("read", row["port"], bytes=len(data), hex=data.hex(), reset=row["reset"])
                if data:
                    row["received"].extend(data)
                    if row["port"] == ERROR_PORT:
                        raise AssertionError("MTU-refused connection delivered application bytes")
                    assert len(row["received"]) <= 64 and POSITIVE.startswith(row["received"]), "positive literal prefix"
                else:
                    row["eof"] = not row["reset"]
                    if row["port"] == ERROR_PORT:
                        row["finished"] = True
                        row["completion"] = "reset" if row["reset"] else "eof"
                        row["finished_monotonic_ns"] = time.monotonic_ns()
                    else:
                        assert row["received"] == POSITIVE and not row["reset"], "positive complete request/half-close"
            for current in writable:
                row = streams[current]
                try:
                    count = current.send(bytes(row["received"])[row["sent"]:])
                except BlockingIOError:
                    continue
                assert count > 0
                event("write", POSITIVE_PORT, offset=row["sent"], bytes=count,
                      hex=bytes(row["received"])[row["sent"]:row["sent"] + count].hex())
                row["sent"] += count
            for stream, row in streams.items():
                if row["finished"]:
                    continue
                if row["port"] == ERROR_PORT and time.monotonic_ns() - row["accepted_monotonic_ns"] >= int(zero_window * 1e9):
                    # One final actual nonblocking read closes the boundary.
                    try:
                        last = stream.recv(1)
                    except BlockingIOError:
                        last = None
                    except ConnectionResetError:
                        row["reset"], last = True, b""
                    assert last in (None, b""), "error connection late application byte"
                    row["finished"], row["completion"] = True, "bounded-no-data"
                    event("zero-window-ended", ERROR_PORT, pending_read_would_block=last is None,
                          bytes=0, elapsed_ns=time.monotonic_ns() - row["accepted_monotonic_ns"])
                if row["port"] == POSITIVE_PORT and row["eof"] and row["sent"] == 64:
                    stream.shutdown(socket.SHUT_WR)
                    row["finished"], row["completion"] = True, "echo-and-half-close"
                    event("shutdown-write", POSITIVE_PORT, bytes=64)
                if row["finished"]:
                    row["finished_monotonic_ns"] = time.monotonic_ns()
            # Listeners stay open to detect an unrequested reconnect.
        assert rows[ERROR_PORT]["received"] == b"" and rows[POSITIVE_PORT]["received"] == POSITIVE
        # Hold every socket open until the runner's stop; a reconnect still fails.
        while not stop_file.exists():
            now = time.monotonic()
            assert now < deadline, "peer absolute deadline before runner stop"
            readable, _, _ = select.select(list(listeners), [], [], min(0.02, deadline - now))
            assert not readable, "unrequested reconnect after both rows finished"
        report["runner_stop_received"] = True
        report["runner_stop_monotonic_ns"] = time.monotonic_ns()
        report["disposition"] = "PASS"
        return report
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        for stream in list(streams) + list(listeners):
            stream.close()
        report["sockets_closed"] = True
        report["connections"] = []
        for row in rows.values():
            value = dict(row)
            body = bytes(value.pop("received"))
            value.update(received_bytes=len(body), received_hex=body.hex(),
                         received_sha256=hashlib.sha256(body).hexdigest())
            report["connections"].append(value)
        report["ended_monotonic_ns"] = time.monotonic_ns()
        atomic(output, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    def stopped(_signum, _frame):
        raise KeyboardInterrupt("TCP peer terminated")

    signal.signal(signal.SIGTERM, stopped)
    signal.signal(signal.SIGINT, stopped)
    run(args.output, args.stop_file, args.timeout)


if __name__ == "__main__":
    main()
