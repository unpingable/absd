#!/usr/bin/env python3
"""Bounded native ICMP probe on an independent Linux-host Ethernet fixture.

This fixture constructs ARP/ICMP/UDP frames over QEMU's existing dgram wire.
It is not a Linux-kernel router/PMTU test. Use an admitted private kernel
checkout; no guest admission is acquired here. --controls executes no ABSD.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time

if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
    raise SystemExit('native-icmp-matrix: optimized Python is refused; oracle assertions are required')

spec = importlib.util.spec_from_file_location('net_matrix', Path(__file__).with_name('net-matrix.py'))
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)


def pattern(length):
    return bytes(((i * 131) ^ (i >> 7)) & 255 for i in range(length))


def udp(data, source, target, source_ip, target_ip):
    body = struct.pack('!HHHH', source, target, 8 + len(data), 0) + data
    pseudo = source_ip + target_ip + struct.pack('!BBH', 0, 17, len(body))
    checksum = n.checksum(pseudo + body) or 65535
    return body[:6] + struct.pack('!H', checksum) + body[8:]


def quote(frame, kind, code, mtu=0, unrelated=False, bad_checksum=False):
    original = frame[14:]
    quoted = bytearray(original[:28])
    quoted[8] = max(0, quoted[8] - 1)
    if unrelated:
        quoted[20] ^= 1  # Uncorrelated quoted local UDP source port.
    quoted[10:12] = b'\0\0'
    quoted[10:12] = struct.pack('!H', n.checksum(bytes(quoted[:20])))
    body = struct.pack('!BBHHH', kind, code, 0, 0, mtu) + bytes(quoted)
    checksum = n.checksum(body) ^ (1 if bad_checksum else 0)
    body = body[:2] + struct.pack('!H', checksum) + body[4:]
    return n.ethernet(frame[6:12], n.ipv4(body, src=bytes([10, 0, 2, 9])))


class Fixture:
    def __init__(self):
        self.records = []
        self.advice = []
        self.dns = []
        self.lengths = []

    def handle(self, frame):
        assert len(self.records) < 32, 'bounded frame census exceeded'
        self.records.append({'direction': 'guest-to-fixture', 'frame_hex': frame.hex()})
        if frame[12:14] == b'\x08\x06':
            if len(frame) >= 42 and frame[20:22] == b'\0\1' and frame[38:42] == n.HOST_IP:
                body = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 2,
                                   n.HOST_MAC, n.HOST_IP, frame[22:28], frame[28:32])
                return [n.ethernet(frame[6:12], body, 0x0806)]
            return []
        assert len(frame) >= 42 and frame[12:14] == b'\x08\0', 'unexpected native frame'
        ip = frame[14:]
        length = struct.unpack('!H', ip[2:4])[0]
        ip = ip[:length]
        assert len(ip) == length and ip[0] == 0x45 and ip[9] == 17
        assert ip[6:8] == b'\x40\0' and n.checksum(ip[:20]) == 0
        assert ip[12:20] == n.GUEST_IP + n.HOST_IP
        body = ip[20:]
        source, target, udp_length, checksum = struct.unpack('!HHHH', body[:8])
        assert udp_length == len(body) and checksum != 0
        assert n.checksum(n.GUEST_IP + n.HOST_IP + struct.pack('!BBH', 0, 17, len(body)) + body) == 0
        data = body[8:]
        responses = []
        if (source, target) == (7200, 42150):
            expected = b'\x01\x00\x00\x01' + b'\0' * 6 + b'\x04icmp\x07example\0\0\x01\0\x01'
            assert data[2:] == expected and len(self.dns) < 2
            if self.dns:
                assert data == self.dns[0], 'DNS retransmit changed query bytes'
            self.dns.append(data)
            cases = [('dns-bad-checksum', 1, False, True),
                     ('dns-unrelated', 2, True, False),
                     ('dns-port-unreachable', 3, False, False)]
            for label, code, unrelated, bad in cases:
                answer = quote(frame, 3, code, unrelated=unrelated, bad_checksum=bad)
                self.advice.append({'case': label, 'frame_hex': answer.hex(), 'original_hex': frame.hex()})
                responses.append(answer)
        elif (source, target) == (7201, 42151):
            self.lengths.append(len(data))
            assert data == pattern(len(data))
            if self.lengths == [1000]:
                for label, mtu, unrelated, bad in [
                    ('udp-bad-checksum', 900, False, True),
                    ('udp-unrelated', 800, True, False),
                    ('udp-mtu-below-floor', 68, False, False),
                    ('udp-fragmentation-needed', 576, False, False),
                ]:
                    answer = quote(frame, 3, 4, mtu, unrelated, bad)
                    self.advice.append({'case': label, 'frame_hex': answer.hex(), 'original_hex': frame.hex()})
                    responses.append(answer)
            else:
                assert self.lengths == [1000, 548], 'refused 549B or unexpected UDP data reached fixture'
                body = udp(data, target, source, n.HOST_IP, n.GUEST_IP)
                responses.append(n.ethernet(frame[6:12], n.ipv4(body, protocol=17)))
        else:
            raise AssertionError('ungranted peer or unexpected tuple reached fixture: ' + str((source, target)))
        return responses

    def finish(self):
        assert 1 <= len(self.dns) <= 2
        assert self.lengths == [1000, 548]
        assert len(self.advice) == 4 + 3 * len(self.dns)
        return {'dns_query_submissions': len(self.dns), 'udp_lengths': self.lengths,
                'forbidden_549_seen': False, 'wrong_peer_seen': False,
                'minimum_quote_bytes': 28, 'injected_advice': len(self.advice)}


def controls():
    fixture = Fixture()
    guest_mac = bytes.fromhex('02000000000f')
    query = bytes.fromhex('1234010000010000000000000469636d70076578616d706c650000010001')
    def native(source, target, data):
        body = udp(data, source, target, n.GUEST_IP, n.HOST_IP)
        frame = n.ethernet(n.HOST_MAC, n.ipv4(body, protocol=17, src=n.GUEST_IP, dst=n.HOST_IP))
        return frame[:6] + guest_mac + frame[12:]
    for source, target, data in [(7200, 42150, query), (7201, 42151, pattern(1000)),
                                 (7201, 42151, pattern(548))]:
        answers = fixture.handle(native(source, target, data))
        for answer in answers:
            assert n.checksum(answer[14:34]) == 0
    for event in fixture.advice:
        frame = bytes.fromhex(event['frame_hex'])
        original = bytes.fromhex(event['original_hex'])
        assert len(frame) == 70 and len(frame[42:]) == 28
        assert n.checksum(frame[42:62]) == 0
        assert frame[50] + 1 == original[22], 'quoted TTL was not decremented'
        assert frame[44:50] == original[16:22] and frame[54:62] == original[26:34]
        expected = bytearray(original[34:42])
        if 'unrelated' in event['case']:
            expected[0] ^= 1
        assert frame[62:70] == expected
        assert (n.checksum(frame[34:]) != 0) == ('bad-checksum' in event['case'])
    negative_controls = []
    for label, source, target, data in [('forbidden-549', 7201, 42151, pattern(549)),
                                       ('wrong-peer', 7201, 42152, pattern(548))]:
        negative = Fixture()
        negative.handle(native(7201, 42151, pattern(1000)))
        try:
            negative.handle(native(source, target, data))
        except AssertionError:
            negative_controls.append(label)
        else:
            raise AssertionError('fixture accepted negative control ' + label)
    try:
        Fixture().finish()
    except AssertionError:
        negative_controls.append('missing-consumer')
    else:
        raise AssertionError('fixture accepted absent consumers')
    return {'case': 'fixture-controls-only', 'ABSD_execution': False,
            'oracle': fixture.finish(), 'negative_controls': negative_controls, 'advice': fixture.advice}


def guest(kernel, elf, work):
    fixture = Fixture()
    qemu = None
    submitted_frames = 0
    platform = Path(__file__).resolve().parent.parent
    revisions = {name: subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
                 for name, path in [('platform', platform), ('kernel', Path(kernel))]}
    dirty = {name: subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain'], text=True)
             for name, path in [('platform', platform), ('kernel', Path(kernel))]}
    with tempfile.TemporaryDirectory(prefix='absd-icmp-', dir='/tmp') as short:
        host_path, guest_path = str(Path(short) / 'host.sock'), str(Path(short) / 'guest.sock')
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.bind(host_path)
            sock.settimeout(0.05)
            iso, image = n.build_iso(kernel, elf, str(work), 1)
            log = str(work / 'icmp.serial.log')
            qemu = n.start_qemu(iso, image, log, [
                '-netdev', f'dgram,id=n0,local.type=unix,local.path={guest_path},remote.type=unix,remote.path={host_path}',
                '-object', f'filter-dump,id=f0,netdev=n0,file={work / "icmp.pcap"}'])
            (work / 'LAUNCH.json').write_text(json.dumps({'qemu_pid': qemu.pid, 'kernel': str(Path(kernel).resolve()),
                'elf': str(Path(elf).resolve()), 'elf_sha256': hashlib.sha256(Path(elf).read_bytes()).hexdigest(),
                'source_revisions': revisions, 'source_dirty_state': dirty,
                'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'boot_helper_sha256': hashlib.sha256(Path(n.__file__).read_bytes()).hexdigest(),
                'log': log, 'wire': 'independent Python Ethernet fixture, not Linux kernel routing'}, indent=2) + '\n')
            end = time.monotonic() + n.BOOT_TIMEOUT
            while qemu.poll() is None:
                if time.monotonic() >= end:
                    raise TimeoutError('native ICMP fixture wall deadline')
                try:
                    frame = sock.recv(4096)
                except socket.timeout:
                    continue
                for response in fixture.handle(frame):
                    assert sock.sendto(response, guest_path) == len(response)
                    submitted_frames += 1
                    assert len(fixture.records) < 32, 'bounded bidirectional frame census exceeded'
                    fixture.records.append({'direction': 'fixture-to-guest', 'frame_hex': response.hex()})
            done, counters = n.finish_boot(qemu, log, rb'ICMP SERVICE DONE dns=1 udp=1 sockets=0')
            fields = dict(field.split('=', 1) for field in counters.split() if '=' in field)
            assert int(fields['rx_frames']) == submitted_frames, (counters, submitted_frames)
            assert int(fields['rx_refused']) == 0 and int(fields['rx_missed']) == 0, counters
            output = n.stdout_of(log).decode('utf-8')
            for expected in ['ICMP CONSUMER index=0 kind=1 status=0', 'ICMP CONSUMER index=1 kind=1 status=0',
                             'ICMP DNS LOOKUP name=icmp.example result=Err(Transport(Icmp(DestinationUnreachable { code: 3 })))',
                             'ICMP UDP REFUSED bytes=549 maximum=548 local_not_queued=1 wrong_peer=Denied',
                             'ICMP UDP COMPLETE mtu=576 maximum=548 refused=549 echoed=548 denied=1']:
                assert expected in output, (expected, output)
            return {'case': 'native-icmp-frame-fixture', 'oracle': fixture.finish(),
                    'counters': counters, 'fixture_submitted_frames': submitted_frames, 'output': output}
        finally:
            sock.close()
            try:
                (work / 'FIXTURE.json').write_text(json.dumps({'records': fixture.records, 'advice': fixture.advice,
                    'fixture_submitted_frames': submitted_frames}, indent=2) + '\n')
            finally:
                if qemu is not None and qemu.poll() is None:
                    qemu.terminate()
                    try:
                        qemu.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        qemu.kill()
                        qemu.wait(timeout=10)


def main():
    def terminate(signum, frame):
        raise KeyboardInterrupt('driver terminated')
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('work', type=Path)
    parser.add_argument('--controls', action='store_true')
    parser.add_argument('--kernel')
    parser.add_argument('--elf')
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    results = []
    try:
        results.append(controls())
        if not args.controls:
            if not args.kernel or not args.elf:
                raise ValueError('guest requires --kernel and --elf, with separate admission')
            results.append(guest(args.kernel, args.elf, args.work))
    except BaseException as error:
        (args.work / 'RESULT.json').write_text(json.dumps({'disposition': 'FAIL', 'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'results': results, 'error': repr(error)}, indent=2) + '\n')
        raise
    (args.work / 'RESULT.json').write_text(json.dumps({'disposition': 'PASS', 'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'results': results}, indent=2) + '\n')
    print('NATIVE ICMP MATRIX OK cases=' + str(len(results)))


if __name__ == '__main__':
    main()
