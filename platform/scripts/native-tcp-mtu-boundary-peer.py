#!/usr/bin/env python3
"""Disclosed raw ICMP boundary inputs and two ordinary Linux TCP sockets.

The actor sends only its five source-defined ICMP inputs. Linux owns TCP/ARP.
The matching ICMP is a raw fixture, never claimed to be router-generated.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import tempfile
import time

GUEST, ROUTER, PEER = bytes((192, 0, 2, 100)), bytes((192, 0, 2, 1)), bytes((198, 51, 100, 2))
GUEST_MAC, ROUTER_MAC = bytes.fromhex("525400123456"), bytes.fromhex("525500000601")
BODY, ECHO = bytes(i % 251 for i in range(1024)), bytes(range(64))
CASES = ("bad-checksum", "wrong-sequence", "equal-mtu", "matching", "empty-history")


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + str(len(data) // 2) + "H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "hex": data.hex()}


def write(path, value):
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".mtu-boundary-")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def checked_submission(frame):
    assert 14 + 40 <= len(frame) <= 1514 and frame[:14] == ROUTER_MAC + GUEST_MAC + b"\x08\0"
    ip = frame[14:]
    assert ip[0] == 0x45 and len(ip) == int.from_bytes(ip[2:4], "big") > 576
    assert ip[6:8] == b"\x40\0" and ip[9] == 6 and ip[12:20] == GUEST + PEER and checksum(ip[:20]) == 0
    tcp = ip[20:]
    header = (tcp[12] >> 4) * 4
    assert 20 <= header <= 60 and tcp[:4] == struct.pack("!HH", 7100, 42100)
    assert tcp[header:] == BODY and checksum(ip[12:20] + b"\0\6" + len(tcp).to_bytes(2, "big") + tcp) == 0
    return ip


def control(submitted, case):
    assert case in CASES
    ip = checked_submission(submitted)
    quote = bytearray(ip[:28])
    mtu = len(ip) if case == "equal-mtu" else 576
    if case == "wrong-sequence":
        quote[27] ^= 1
    body = bytearray(b"\3\4\0\0\0\0" + mtu.to_bytes(2, "big") + quote)
    body[2:4] = checksum(bytes(body)).to_bytes(2, "big")
    if case == "bad-checksum":
        body[2] ^= 1
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 23100, 0, 64, 1, 0, ROUTER, GUEST))
    header[10:12] = checksum(bytes(header)).to_bytes(2, "big")
    return GUEST_MAC + ROUTER_MAC + b"\x08\0" + bytes(header) + bytes(body)


def serial_output(path):
    if not path.exists():
        return b""
    raw = path.read_bytes()
    assert len(raw) <= 8 * 1024 * 1024
    output = bytearray()
    for line in raw.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            break
        match = re.fullmatch(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)\r?\n", line)
        if match:
            assert int(match[1], 16) == len(output) and len(match[2]) % 2 == 0
            output.extend(bytes.fromhex(match[2].decode()))
            assert len(output) <= 3 * 1024 * 1024
    return bytes(output)


def records(output, kind):
    rows = []
    for line in output.decode("ascii").splitlines(keepends=True):
        if line.endswith("\n") and line.startswith("TCP MTU BOUNDARY " + kind + " "):
            row = {}
            for word in line.rstrip("\r\n").split()[4:]:
                assert word.count("=") == 1
                key, value = word.split("=")
                assert key not in row
                row[key] = value
            assert row.get("v") == "1"
            rows.append(row)
    return rows


def acknowledgement(output, index, frame):
    if index == 3:
        rows = records(output, "REFUSED")
    else:
        rows = [row for row in records(output, "CASE") if row.get("index") == str(index)]
    if not rows:
        return None
    assert len(rows) == 1
    row = rows[0]
    expected = {"code": "17", "mtu": "576", "sockets": "1", "logical": "1", "effects": "unknown"} if index == 3 else {
        "case": CASES[index], "code": "0", "connected": "0" if index == 4 else "1",
        "sockets": "0" if index == 4 else "2", "logical": "3" if index == 4 else "1"}
    assert all(row.get(key) == value for key, value in expected.items()), "native boundary acknowledgement"
    receives = [value for value in records(output, "FRAME") if value.get("direction") == "rx" and value.get("ordinal") == row["receive_ordinal"]]
    assert len(receives) == 1 and receives[0]["hex"] == frame.hex() and receives[0]["bytes"] == str(len(frame))
    assert int(receives[0]["at_ms"]) <= int(row["at_ms"])
    return row


def actor(args, report):
    end = time.monotonic() + args.timeout

    def left():
        assert time.monotonic() < end, "raw actor absolute deadline"
        return min(0.01, end - time.monotonic())

    report.update(network_namespace_inode=os.stat("/proc/self/ns/net").st_ino, tap=args.tap,
                  cases=[], reads=[], scope="Five disclosed raw ICMP inputs; full interface census is capture/native, not this selected socket")
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
        link.bind((args.tap, 0))
        write(args.output.with_suffix(".ready.json"), {"schema": "absd-tcp-mtu-boundary-actor-ready/1", "pid": os.getpid(),
            "network_namespace_inode": report["network_namespace_inode"], "tap": args.tap})
        while True:
            link.settimeout(left())
            try:
                value, address = link.recvfrom(2048)
            except socket.timeout:
                continue
            assert len(report["reads"]) < 256, "selected raw socket read bound"
            report["reads"].append({"at_monotonic_ns": time.monotonic_ns(), "packet_type": address[2], "frame": identity(value)})
            if address[2] != 4 and len(value) >= 54 and value[6:12] == GUEST_MAC and value[12:14] == b"\x08\0" and value[23] == 6:
                ip = value[14:]
                header = (ip[32] >> 4) * 4
                if ip[20:24] == struct.pack("!HH", 7100, 42100) and ip[20 + header:] == BODY:
                    checked_submission(value)
                    submitted = value
                    break
        report["submitted"] = identity(submitted)
        for index, case in enumerate(CASES):
            kind = "EMPTY_READY" if index == 4 else "CONTROLS_READY"
            while not records(serial_output(args.serial), kind):
                left()
                time.sleep(0.002)
            frame = control(submitted, "matching" if index == 4 else case)
            row = {"index": index, "case": case, "frame": identity(frame), "send_monotonic_ns": time.monotonic_ns()}
            assert link.send(frame) == len(frame), "complete raw control send"
            report["cases"].append(row)
            while True:
                left()
                ack = acknowledgement(serial_output(args.serial), index, frame)
                if ack is not None:
                    row.update(native_acknowledgement=ack, ack_read_monotonic_ns=time.monotonic_ns())
                    break
                time.sleep(0.002)
    report["raw_socket_closed"] = True


def tcp_server(args, report):
    listeners, streams, rows, events = {}, {}, {}, []
    end = time.monotonic() + args.timeout
    report.update(network_namespace_inode=os.stat("/proc/self/ns/net").st_ino, connections=[], events=events)

    def event(kind, port, **values):
        assert len(events) < 128
        events.append({"event": kind, "port": port, "monotonic_ns": time.monotonic_ns(), **values})

    try:
        for port in (42100, 42101):
            listener = socket.socket()
            listeners[listener] = port
            listener.bind(("198.51.100.2", port))
            listener.listen(1)
            listener.setblocking(False)
        write(args.output.with_suffix(".ready.json"), {"schema": "absd-tcp-mtu-boundary-server-ready/1", "pid": os.getpid(),
            "network_namespace_inode": report["network_namespace_inode"], "ports": [42100, 42101], "bind": "198.51.100.2"})
        while not args.stop_file.exists():
            assert time.monotonic() < end, "TCP server absolute deadline"
            readable, writable, _ = select.select(list(listeners) + [s for s, r in streams.items() if not r["eof"]],
                [s for s, r in streams.items() if r["port"] == 42101 and r["sent"] < len(r["body"])], [], 0.01)
            for current in readable:
                if current in listeners:
                    port = listeners[current]
                    stream, source = current.accept()
                    try:
                        assert port not in rows and source == ("192.0.2.100", 7100 if port == 42100 else 7101)
                    except BaseException:
                        stream.close()
                        raise
                    stream.setblocking(False)
                    stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    row = {"port": port, "source": list(source), "body": bytearray(), "sent": 0, "eof": False,
                           "write_closed": False, "accepted_monotonic_ns": time.monotonic_ns()}
                    rows[port], streams[stream] = row, row
                    event("accept", port, source=list(source))
                    continue
                row = streams[current]
                try:
                    value = current.recv(1025)
                except BlockingIOError:
                    continue
                event("read", row["port"], bytes=len(value), hex=value.hex())
                if value:
                    row["body"].extend(value)
                    expected = BODY if row["port"] == 42100 else ECHO
                    assert len(row["body"]) <= len(expected) and expected.startswith(row["body"])
                else:
                    row["eof"] = True
                    assert row["port"] == 42101 and row["body"] == ECHO, "target socket must remain open through empty-history stage"
            for current in writable:
                row = streams[current]
                try:
                    count = current.send(bytes(row["body"])[row["sent"]:])
                except BlockingIOError:
                    continue
                assert count > 0
                value = bytes(row["body"])[row["sent"]:row["sent"] + count]
                event("write", 42101, offset=row["sent"], bytes=count, hex=value.hex())
                row["sent"] += count
            for stream, row in streams.items():
                if row["port"] == 42101 and row["eof"] and row["sent"] == 64 and not row["write_closed"]:
                    stream.shutdown(socket.SHUT_WR)
                    row["write_closed"] = True
                    event("shutdown-write", 42101, bytes=64)
        assert set(rows) == {42100, 42101} and rows[42100]["body"] == BODY and rows[42100]["sent"] == 0 and not rows[42100]["eof"]
        assert rows[42101]["body"] == ECHO and rows[42101]["sent"] == 64 and rows[42101]["eof"] and rows[42101]["write_closed"]
        report["runner_stop_received"] = True
    finally:
        for current in list(streams) + list(listeners):
            current.close()
        report["sockets_closed"] = True
        report["connections"] = [{key: value for key, value in row.items() if key != "body"} | {"received": identity(bytes(row["body"]))} for row in rows.values()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("actor", "server"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--tap")
    parser.add_argument("--serial", type=Path)
    parser.add_argument("--stop-file", type=Path)
    args = parser.parse_args()
    if not 10 <= args.timeout <= 150:
        parser.error("timeout must be10..150")
    if args.mode == "actor" and (not args.tap or args.serial is None) or args.mode == "server" and args.stop_file is None:
        parser.error("actor requires tap/serial; server requires stop-file")

    def stop(_signum, _frame):
        raise KeyboardInterrupt("boundary peer terminated")

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    report = {"schema": "absd-tcp-mtu-boundary-" + args.mode + "/1", "mode": args.mode, "pid": os.getpid(),
              "start_monotonic_ns": time.monotonic_ns(), "disposition": "FAIL"}
    try:
        (actor if args.mode == "actor" else tcp_server)(args, report)
        report["disposition"] = "PASS"
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        report["end_monotonic_ns"] = time.monotonic_ns()
        write(args.output, report)


if __name__ == "__main__":
    main()
