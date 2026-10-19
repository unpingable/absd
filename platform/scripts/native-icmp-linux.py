#!/usr/bin/env python3
"""Independent Linux ICMP-to-UDP controls. This does not execute ABSD source."""
import argparse
import datetime
import errno
import json
import pathlib
import socket
import struct
import time

IP_RECVERR = 11
SO_EE_ORIGIN_ICMP = 2


def control(data, connected):
    # The fixture owns the destination socket before closing it, so the
    # expected port-unreachable concerns a deliberately retired local peer.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.bind(("127.0.0.1", 0))
        address = peer.getsockname()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(("127.0.0.1", 0))
        client.setsockopt(socket.SOL_IP, IP_RECVERR, 1)
        client.setblocking(False)
        if connected:
            client.connect(address)
            assert client.send(data) == len(data)
        else:
            assert client.sendto(data, address) == len(data)
        deadline = time.monotonic() + 2
        while True:
            try:
                received, ancillary, flags, destination = client.recvmsg(
                    4096, 4096, socket.MSG_ERRQUEUE
                )
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise AssertionError("Linux did not report ICMP by the local deadline")
                time.sleep(0.005)
        assert received == data
        assert destination == address
        assert flags & socket.MSG_ERRQUEUE
        records = []
        for level, kind, value in ancillary:
            if level == socket.SOL_IP and kind == IP_RECVERR:
                number, origin, icmp_type, code, padding, info, detail = struct.unpack(
                    "=IBBBBII", value[:16]
                )
                assert number == errno.ECONNREFUSED
                assert origin == SO_EE_ORIGIN_ICMP
                assert (icmp_type, code) == (3, 3)
                records.append({"errno": number, "origin": origin,
                                "icmp_type": icmp_type, "code": code,
                                "info": info, "detail": detail})
        assert len(records) == 1
        return {"connected": connected, "local": client.getsockname(),
                "retired_peer": address, "data_hex": data.hex(), "error": records[0]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    result = {"schema_version": 1,
              "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "scope": "Independent Linux loopback UDP/ICMP controls only; no ABSD execution",
              "cases": [], "result": "FAIL"}
    try:
        # Literal RFC 1035 A question; no ABSD DNS writer is imported.
        query = bytes.fromhex("12340100000100000000000003777777076578616d706c650000010001")
        for data, connected in [(query, False), (query, True), (b"", False)]:
            result["cases"].append(control(data, connected))
        result["result"] = "PASS"
    except Exception as error:
        result["error"] = repr(error)
        raise
    finally:
        (args.output / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print("PASS independent Linux ICMP port-unreachable controls=3 ABSD_execution=none")


if __name__ == "__main__":
    main()
