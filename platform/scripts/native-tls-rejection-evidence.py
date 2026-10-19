#!/usr/bin/env python3
"""Additive complete client-output receipt for ended P02-P05/P02b/W03 cases.

Ciphertext is session-specific. The exact captured stream must match every Linux
recv digest, contain only ClientHello + CCS + one 24-byte encrypted record, and
OpenSSL must have authenticated/decoded the specific fatal alert. This checker
binds that existing decoder observation; it does not decrypt ciphertext itself.
Canonical build/boot/native/census/cleanup qualification remains separate.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

spec = importlib.util.spec_from_file_location('alert_receipt', Path(__file__).with_name('native-tls-alert-evidence.py'))
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
require = common.require
MAX_PCAP = 16 * 1024 * 1024
CCS = bytes.fromhex('140303000101')
RECORD_HEADER = bytes.fromhex('1703030013')
PROFILES = {
    'P02': (7302, 'untrusted', 'CertificateRejected', 'TLSV1_ALERT_UNKNOWN_CA'),
    'P02b': (7303, 'signature-failure', 'CertificateRejected', 'TLSV1_ALERT_DECRYPT_ERROR'),
    'P03': (7304, 'wrong-name', 'CertificateRejected', 'SSLV3_ALERT_BAD_CERTIFICATE'),
    'P04': (7305, 'expired', 'CertificateRejected', 'SSLV3_ALERT_CERTIFICATE_EXPIRED'),
    'P05': (7306, 'future', 'CertificateRejected', 'SSLV3_ALERT_CERTIFICATE_EXPIRED'),
    'W03': (7313, 'bad-handshake-tag', 'TlsRejected', 'SSLV3_ALERT_BAD_RECORD_MAC'),
}


def checksum(data):
    if len(data) & 1:data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def client_stream(data, port):
    require(24 <= len(data) <= MAX_PCAP, 'PCAP byte bound')
    variants = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
                b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
    require(data[:4] in variants, 'PCAP magic')
    endian = variants[data[:4]]
    require(struct.unpack(endian + 'HH', data[4:8]) == (2, 4)
            and struct.unpack(endian + 'I', data[20:24])[0] == 1, 'Ethernet PCAP required')
    at = 24;base = None;segments = [];packets = 0
    source = bytes([10, 0, 2, 15]);destination = bytes([10, 0, 2, 2])
    while at < len(data):
        require(at + 16 <= len(data), 'partial PCAP frame header')
        _, _, size, original = struct.unpack(endian + 'IIII', data[at:at + 16]);at += 16
        require(size == original and at + size <= len(data), 'partial PCAP frame')
        frame = data[at:at + size];at += size;packets += 1
        require(packets <= 100000, 'PCAP packet bound')
        if len(frame) < 14 or frame[12:14] != b'\x08\x00':continue
        ip = frame[14:]
        require(len(ip) >= 20 and ip[0] >> 4 == 4, 'short IPv4 packet')
        if ip[9] != 6 or ip[12:16] != source or ip[16:20] != destination:continue
        ihl = (ip[0] & 15) * 4;length = int.from_bytes(ip[2:4], 'big')
        require(20 <= ihl <= length <= len(ip) and not (int.from_bytes(ip[6:8], 'big') & 0x3fff),
                'fragmented or malformed client IPv4')
        tcp = ip[ihl:length]
        require(len(tcp) >= 20, 'short client TCP')
        if tcp[:4] != struct.pack('!HH', port, 4443):continue
        require(checksum(ip[:ihl]) == 0 and
                checksum(source + destination + b'\0\x06' + struct.pack('!H', len(tcp)) + tcp) == 0,
                'client IP/TCP checksum')
        header = (tcp[12] >> 4) * 4
        require(20 <= header <= len(tcp), 'client TCP header length')
        sequence = int.from_bytes(tcp[4:8], 'big');flags = tcp[13];payload = tcp[header:]
        if flags & 2:
            require(not payload and (base is None or base == (sequence + 1) & 0xffffffff),
                    'new/changed SYN or SYN data')
            base = (sequence + 1) & 0xffffffff
        if payload:
            require(base is not None, 'client data before captured SYN')
            offset = (sequence - base) & 0xffffffff
            require(offset + len(payload) <= 8192, 'client stream byte bound')
            segments.append((offset, payload))
    require(base is not None and segments, 'client SYN/data absent')
    end = max(at + len(payload) for at, payload in segments)
    stream = bytearray(end);seen = bytearray(end)
    for at, payload in segments:
        for index, byte in enumerate(payload, at):
            require(not seen[index] or stream[index] == byte, 'different retransmitted client byte')
            stream[index] = byte;seen[index] = 1
    require(all(seen), 'client stream gap')
    return bytes(stream)


def evaluate(buffers, pcap, expected):
    result, fixture, inputs = (common.decode(buffers[name]) for name in common.FILES)
    identity = result['case'];require(identity in PROFILES, 'exact rejection case required')
    port, mode, classification, reason = PROFILES[identity]
    case = fixture['case']
    require(case['id'] == identity and case['peer_mode'] == mode and case['local_port'] == port
            and case['expect_http'] is False, 'rejection profile differs')
    require(result['disposition'] == 'PASS' and result['actual_class'] == classification
            and result['measured_qemu_exit'] == 3, 'canonical rejection PASS absent')
    require(result['fixture'] == fixture and inputs['selected_case'] == case, 'evaluated case disagreement')
    common.inspect_sources(inputs, expected)
    require(type(fixture['accepts']) is int and fixture['accepts'] == 1
            and type(fixture['guard_accepts']) is int and fixture['guard_accepts'] == 0
            and fixture['errors'] == [] and type(fixture['request_bytes']) is int
            and fixture['request_bytes'] == 0 and fixture['request_sha256'] == common.digest(b'')
            and fixture['server_handshake_complete'] is False, 'extra flow/HTTP/completed handshake')
    events = fixture['events'];require(isinstance(events, list) and 5 <= len(events) <= 300, 'event bound')
    times = [event['monotonic_ns'] for event in events]
    require(all(type(value) is int and value >= 0 for value in times) and times == sorted(times), 'event order')
    require(events[0]['event'] == 'accept' and events[0]['role'] == 'tls'
            and events[0]['source'] == ['10.0.2.15', port], 'accepted tuple')
    terminal = events[-1]
    require(terminal['event'] == 'connection-ended' and terminal['error_type'] == 'SSLError'
            and isinstance(terminal['reason'], str)
            and re.match(r'^\[SSL: ' + reason + r'\] ', terminal['reason']), 'decoded peer fatal alert differs')
    require(events[-2]['event'] == 'handshake-failure-alert-drained', 'OpenSSL handshake failure observation absent')
    reads = [event for event in events if event['event'] == 'tcp-read']
    stream = client_stream(pcap, port);at = 0
    for event in reads:
        count = event['bytes']
        require(type(count) is int and count > 0 and at + count <= len(stream), 'recv byte count')
        require(event['sha256'] == common.digest(stream[at:at + count]), 'captured bytes differ from Linux recv')
        at += count
    require(at == len(stream) and reads and reads[0]['bytes'] == 239, 'unreceived/extra client bytes or initial flight')
    require(stream[:5] == bytes.fromhex('16030100ea'), 'complete pinned ClientHello frame absent')
    post = stream[239:]
    require(len(post) == 30 and post[:6] == CCS and post[6:11] == RECORD_HEADER,
            'only exact CCS plus one 24-byte encrypted alert record permitted')
    return {'case': identity, 'client_stream_bytes': len(stream), 'client_stream_sha256': common.digest(stream),
            'post_failure_bytes': len(post), 'post_failure_hex': post.hex(),
            'post_failure_sha256': common.digest(post), 'openssl_decoded_alert': reason,
            'ciphertext_limit': 'Exact per-run capture/recv correspondence and authenticated OpenSSL alert observation; '
                                'no fixed ciphertext, independent decryption by this checker or native clock-order claim.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-dir', type=Path, required=True)
    for name in ('result', 'fixture', 'case-inputs', 'pcap'):parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True);common.source_arguments(parser)
    args = parser.parse_args(argv)
    require(not sys.flags.optimize, 'optimized Python refused')
    require(not args.output.resolve().is_relative_to(args.case_dir.resolve()), 'separate new receipt required')
    expected = common.expected_sources(args)
    paths = {name: args.case_dir / name for name in common.FILES}
    buffers = {};pcap = None;runner = None
    hashes = dict(zip(common.FILES, (args.result_sha256, args.fixture_sha256, args.case_inputs_sha256)))
    require(all(re.fullmatch('[0-9a-f]{64}', value) for value in [*hashes.values(), args.pcap_sha256]), 'exact custody hashes required')
    output = {'schema': 'absd-tls-rejection-output-receipt/1', 'disposition': 'FAIL', 'expected_sources': expected,
              'required_canonical_runner_sha256': common.RUNNER_SHA256,
              'limits': 'Additive output receipt only; canonical build/boot/native/census/cleanup are separate prerequisites.'}
    try:
        for name, path in paths.items():
            buffers[name] = common.bounded(path);require(common.digest(buffers[name]) == hashes[name], 'custody hash: ' + name)
        with (args.case_dir / 'tls.pcap').open('rb') as stream:pcap = stream.read(MAX_PCAP + 1)
        require(len(pcap) <= MAX_PCAP and common.digest(pcap) == args.pcap_sha256, 'PCAP custody hash/bound')
        runner = common.bounded(args.runner);require(common.digest(runner) == common.RUNNER_SHA256, 'canonical runner differs')
        output['receipt'] = evaluate(buffers, pcap, expected);output['disposition'] = 'PASS_BOUNDED_REJECTION_OUTPUT'
    except (ValueError, KeyError, TypeError, OSError) as error:output['error'] = str(error)
    try:
        common.unchanged({name: paths[name] for name in buffers}, buffers)
        if pcap is not None:
            with (args.case_dir / 'tls.pcap').open('rb') as stream:after = stream.read(MAX_PCAP + 1)
            require(after == pcap, 'PCAP changed before seal')
        if runner is not None:require(common.bounded(args.runner) == runner, 'runner changed before seal')
    except (ValueError, OSError) as error:output['disposition'] = 'FAIL';output['seal_error'] = str(error)
    output['evaluated_inputs'] = {name: {'path': str(paths[name]), 'bytes': len(data), 'sha256': common.digest(data)}
                                  for name, data in buffers.items()}
    if pcap is not None:output['pcap'] = {'path': str(args.case_dir / 'tls.pcap'), 'bytes': len(pcap), 'sha256': common.digest(pcap)}
    if runner is not None:output['runner'] = {'path': str(args.runner), 'bytes': len(runner), 'sha256': common.digest(runner)}
    with args.output.open('x') as stream:json.dump(output, stream, indent=2);stream.write('\n')
    return 0 if output['disposition'] == 'PASS_BOUNDED_REJECTION_OUTPUT' else 1


if __name__ == '__main__':raise SystemExit(main())
