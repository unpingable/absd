#!/usr/bin/env python3
"""Finite Linux UDP fixture, not a general DHCP server. No host service changes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import time

ROOT = Path(__file__).resolve().parent.parent
PROFILES = ('no-offer', 'malformed-offer', 'unauthorized-offer', 'valid-offer-noack')
HOST = bytes([192, 0, 2, 1]);GUEST = bytes([192, 0, 2, 100])
MAC = bytes.fromhex('525400123456')


def require(value, message):
    if not value:raise ValueError(message)


def options(data, allow_duplicate=False):
    require(240 <= len(data) <= 1200 and data[236:240] == bytes([99, 130, 83, 99]), 'bounded DHCP cookie')
    rows = {};at = 240
    while at < len(data):
        tag = data[at];at += 1
        if tag == 0:continue
        if tag == 255:
            require(not any(data[at:]), 'DHCP tail');return rows, at - 1
        require(at < len(data), 'option length absent');size = data[at];at += 1
        require(at + size <= len(data) and (allow_duplicate or tag not in rows), 'option size/duplicate')
        rows.setdefault(tag, []).append((at, data[at:at + size]));at += size
    raise ValueError('option terminator absent')


def offer(discover, profile):
    require(profile in PROFILES[1:], 'no Offer in silent profile')
    require(discover[:4] == bytes([1, 1, 6, 0]) and discover[12:28] == bytes(16)
            and discover[28:34] == MAC, 'exact direct guest BOOTP')
    opts, _ = options(discover)
    require(opts[53][0][1] == b'\x01', 'Discover required')
    template = bytes.fromhex((ROOT / 'fixtures/native-dhcp/captured-offer.hex').read_text())
    metadata = json.loads((ROOT / 'fixtures/native-dhcp/captured-offer.json').read_bytes())
    require(len(template) == metadata['payload_bytes'] and hashlib.sha256(template).hexdigest() == metadata['payload_sha256'], 'captured Offer vector identity')
    data = bytearray(template);data[4:8] = discover[4:8];data[28:34] = MAC
    fields, end = options(data)
    require(fields[53][0][1] == b'\x02' and fields[54][0][1] == HOST and data[16:20] == GUEST, 'captured Offer profile')
    if profile == 'malformed-offer':data[end:end] = bytes([53, 1, 2])
    elif profile == 'unauthorized-offer':
        at = fields[54][0][0];data[at:at + 4] = bytes([192, 0, 2, 2])
    return bytes(data)


def defer_offer(first_discover_ns, absolute_deadline, stopped,
                now=time.monotonic, now_ns=time.monotonic_ns, pause=time.sleep):
    # RX setup allowance for this continuous, non-icount TCG profile. Never
    # restart discovery, the peer deadline, or the guest's acquisition clock.
    not_before = first_discover_ns + 1_100_000_000
    while now_ns() < not_before:
        require(not stopped() and now() < absolute_deadline, 'Offer setup guard interrupted/expired')
        pause(min(0.01, max(0.0, (not_before - now_ns()) / 1_000_000_000),
                  max(0.0, absolute_deadline - now())))
    require(not stopped() and now() < absolute_deadline, 'Offer setup guard interrupted/expired')
    ready = now_ns()
    require(ready >= not_before, 'Offer setup guard incomplete')
    return {'first_discover_monotonic_ns': first_discover_ns,
            'offer_not_before_monotonic_ns': not_before,
            'send_ready_monotonic_ns': ready}


def record_event(out, event_type, data, **fields):
    require(len(out['events']) < 64, 'peer observation bound')
    row = {'event': event_type, 'monotonic_ns': time.monotonic_ns(), 'bytes': len(data),
           'hex': data.hex(), 'sha256': hashlib.sha256(data).hexdigest(), **fields}
    out['events'].append(row);return row


def serve(args):
    work = args.work.resolve();require(work.is_dir(), 'owned precreated peer directory required')
    require(os.geteuid() == 0 and args.interface == 'dhcp-tap0', 'dedicated root namespace fixture required')
    stop = False
    def stopped(_signal, _frame):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, stopped);signal.signal(signal.SIGINT, stopped)
    out = {'schema_version': 1, 'profile': args.profile, 'events': [], 'errors': [], 'sent': 0,
           'pid': os.getpid(), 'netns_inode': os.stat('/proc/self/ns/net').st_ino}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.interface.encode() + b'\0')
        sock.bind(('0.0.0.0', 67));sock.settimeout(0.1)
        ready = {**out, 'bound': list(sock.getsockname()), 'interface': args.interface,
                 'ifindex': socket.if_nametoindex(args.interface), 'executable': os.readlink('/proc/self/exe')}
        temporary = work / 'PEER-READY.tmp'
        with temporary.open('x') as stream:
            json.dump(ready, stream, indent=2);stream.flush();os.fsync(stream.fileno())
        require(not (work / 'PEER-READY.json').exists(), 'readiness already exists')
        temporary.rename(work / 'PEER-READY.json')
        deadline = time.monotonic() + args.timeout;selected_xid = None
        while not stop and time.monotonic() < deadline:
            try:data, source = sock.recvfrom(1201)
            except socket.timeout:continue
            require(source == ('0.0.0.0', 68), 'guest UDP source tuple')
            fields, _ = options(data);kind = fields[53][0][1]
            require(kind in (b'\x01', b'\x03') and data[:4] == bytes([1, 1, 6, 0])
                    and data[28:34] == MAC, 'guest DHCP profile')
            current = data[4:8]
            observed = record_event(out, 'receive', data, source=list(source), kind=kind[0])
            if kind == b'\x03':
                require(args.profile == 'valid-offer-noack' and current == selected_xid and fields[54][0][1] == HOST
                        and fields[50][0][1] == GUEST, 'unexpected selecting REQUEST')
            elif args.profile != 'no-offer' and out['sent'] == 0:
                packet = offer(data, args.profile)
                timing = defer_offer(observed['monotonic_ns'], deadline, lambda: stop)
                require(sock.sendto(packet, ('255.255.255.255', 68)) == len(packet), 'partial fixture datagram')
                selected_xid = current
                out['sent'] += 1;record_event(out, 'send', packet, destination=['255.255.255.255', 68], trigger_discover_sha256=observed['sha256'], **timing)
        require(stop, 'peer wall deadline reached without normal runner reconciliation')
    except BaseException as error:
        out['errors'].append(repr(error));raise
    finally:
        sock.close();out['socket_closed'] = True;out['ended_monotonic_ns'] = time.monotonic_ns()
        with (work / 'PEER-RESULT.json').open('x') as stream:json.dump(out, stream, indent=2);stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=PROFILES, required=True)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=210)
    args = parser.parse_args();require(__debug__ and not os.environ.get('PYTHONOPTIMIZE'), 'normal Python assertions required')
    require(30 <= args.timeout <= 240, 'peer wall bound');serve(args)


if __name__ == '__main__':main()
