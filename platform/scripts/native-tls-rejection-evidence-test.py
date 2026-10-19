#!/usr/bin/env python3
"""Synthetic artifact controls only: no TLS decryption, native run or Linux peer."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('rejection_receipt', Path(__file__).with_name('native-tls-rejection-evidence.py'))
checker = importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
SOURCES = {'platform': {'revision': '1' * 40, 'tree': '2' * 40},
           'kernel': {'revision': '3' * 40, 'tree': '4' * 40}}
HELLO = bytes.fromhex('16030100ea') + b'h' * 234
# Deliberately opaque synthetic bytes, not real TLS ciphertext or a reference alert.
POST = checker.CCS + checker.RECORD_HEADER + bytes(range(19))


def frame(port, sequence, payload=b'', flags=16):
    source = bytes([10, 0, 2, 15]);destination = bytes([10, 0, 2, 2])
    tcp = bytearray(struct.pack('!HHIIBBHHH', port, 4443, sequence, 0, 80, flags, 4096, 0, 0) + payload)
    pseudo = source + destination + b'\0\x06' + struct.pack('!H', len(tcp))
    tcp[16:18] = struct.pack('!H', checker.checksum(pseudo + tcp))
    ip = bytearray(bytes.fromhex('450000000000400040060000') + source + destination)
    ip[2:4] = struct.pack('!H', 20 + len(tcp));ip[10:12] = struct.pack('!H', checker.checksum(ip))
    return b'\0' * 12 + b'\x08\x00' + ip + tcp


def pcap(port, stream=HELLO + POST, segments=None):
    packets = [frame(port, 99, flags=2)]
    for offset, payload in segments if segments is not None else [(0, stream)]:
        packets.append(frame(port, 100 + offset, payload))
    packets.append(frame(port, 100 + len(stream), flags=20))
    return struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + b''.join(
        struct.pack('<IIII', 0, i, len(packet), len(packet)) + packet for i, packet in enumerate(packets))


def buffers(identity='P02', post=POST, parts=None):
    port, mode, classification, reason = checker.PROFILES[identity]
    case = {'id': identity, 'peer_mode': mode, 'local_port': port, 'expect_http': False}
    events = [{'event': 'accept', 'role': 'tls', 'source': ['10.0.2.15', port]},
              {'event': 'tcp-read', 'bytes': len(HELLO), 'sha256': checker.common.digest(HELLO)},
              {'event': 'tcp-write', 'bytes': 1, 'stream_offset': 0}]
    at = 0
    for size in parts if parts is not None else [6, len(post) - 6]:
        if size:events.append({'event': 'tcp-read', 'bytes': size, 'sha256': checker.common.digest(post[at:at + size])})
        at += size
    events += [{'event': 'handshake-failure-alert-drained'},
               {'event': 'connection-ended', 'error_type': 'SSLError', 'reason': '[SSL: ' + reason + '] synthetic decoder fixture'}]
    for i, event in enumerate(events):event['monotonic_ns'] = i
    fixture = {'case': case, 'events': events, 'accepts': 1, 'guard_accepts': 0, 'errors': [],
               'request_bytes': 0, 'request_sha256': checker.common.digest(b''), 'server_handshake_complete': False}
    result = {'case': identity, 'disposition': 'PASS', 'actual_class': classification,
              'measured_qemu_exit': 3, 'fixture': fixture}
    inputs = {'selected_case': case, 'case_manifest_sha256': checker.common.MANIFEST_SHA256,
              'source': {name: {**value, 'dirty_state': '', 'clean_required': True} for name, value in SOURCES.items()}}
    return {name: json.dumps(value).encode() for name, value in zip(checker.common.FILES, (result, fixture, inputs))}


def changed_fixture(raw, change):
    raw = copy.deepcopy(raw);fixture = json.loads(raw['FIXTURE.json']);change(fixture)
    result = json.loads(raw['RESULT.json']);result['fixture'] = fixture
    raw['FIXTURE.json'] = json.dumps(fixture).encode();raw['RESULT.json'] = json.dumps(result).encode()
    return raw


class RejectionControls(unittest.TestCase):
    def test_all_six_profiles_and_session_specific_ciphertext(self):
        for identity, profile in checker.PROFILES.items():
            port = profile[0]
            for ciphertext in (bytes(range(19)), bytes(reversed(range(19)))):
                post = checker.CCS + checker.RECORD_HEADER + ciphertext
                receipt = checker.evaluate(buffers(identity, post), pcap(port, HELLO + post), SOURCES)
                self.assertEqual(receipt['post_failure_hex'], post.hex())
                self.assertEqual(receipt['openssl_decoded_alert'], profile[3])

    def test_fragmented_receives_and_duplicate_out_of_order_packets(self):
        stream = HELLO + POST
        capture = pcap(7302, segments=[(239, POST), (0, HELLO), (239, POST)])
        for cut in range(1, 30):
            self.assertEqual(checker.evaluate(buffers(parts=[cut, 30 - cut]), capture, SOURCES)['post_failure_bytes'], 30)
        self.assertEqual(checker.client_stream(capture, 7302), stream)

    def test_each_captured_byte_substitution_refused_against_recv_hashes(self):
        for at in range(len(POST)):
            changed = bytearray(POST);changed[at] ^= 1
            with self.assertRaises(ValueError):checker.evaluate(buffers(), pcap(7302, HELLO + changed), SOURCES)

    def test_extra_short_duplicate_and_wrong_record_envelope_refused(self):
        for post in (POST[:-1], POST + b'x', POST * 2, b'x' + POST,
                     b'\x15' + POST[1:], POST[:6] + b'\x16' + POST[7:]):
            with self.assertRaises(ValueError):checker.evaluate(buffers(post=post, parts=[len(post)]), pcap(7302, HELLO + post), SOURCES)

    def test_wrong_decoded_alert_and_non_SSL_teardown_refused(self):
        for field, value in [('reason', '[SSL: TLSV1_ALERT_UNKNOWN_PSK_IDENTITY] wrong'),
                             ('error_type', 'ConnectionResetError'), ('event', 'peer-eof')]:
            raw = changed_fixture(buffers(), lambda f: f['events'][-1].update({field: value}))
            with self.assertRaises(ValueError):checker.evaluate(raw, pcap(7302), SOURCES)

    def test_no_failure_marker_extra_flow_HTTP_or_handshake_refused(self):
        for key, value in [('accepts', 2), ('guard_accepts', 1), ('errors', ['x']),
                           ('request_bytes', 1), ('server_handshake_complete', True)]:
            raw = changed_fixture(buffers(), lambda f: f.update({key: value}))
            with self.assertRaises(ValueError):checker.evaluate(raw, pcap(7302), SOURCES)
        raw = changed_fixture(buffers(), lambda f: f['events'][-2].update(event='other'))
        with self.assertRaises(ValueError):checker.evaluate(raw, pcap(7302), SOURCES)

    def test_missing_extra_or_altered_receive_digest_refused(self):
        for change in (lambda f: f['events'].pop(3),
                       lambda f: f['events'][3].update(sha256='0' * 64),
                       lambda f: f['events'][3].update(bytes=True),
                       lambda f: f['events'].insert(4, dict(f['events'][3]))):
            with self.assertRaises(ValueError):checker.evaluate(changed_fixture(buffers(), change), pcap(7302), SOURCES)

    def test_actual_source_clean_binding_and_result_prerequisites_refused(self):
        for component in SOURCES:
            for key, value in [('revision', 'f' * 40), ('tree', 'e' * 40), ('dirty_state', ' M x'), ('clean_required', False)]:
                raw = buffers();x = json.loads(raw['CASE-INPUTS.json']);x['source'][component][key] = value
                raw['CASE-INPUTS.json'] = json.dumps(x).encode()
                with self.assertRaises(ValueError):checker.evaluate(raw, pcap(7302), SOURCES)
        for key, value in [('disposition', 'FAIL'), ('actual_class', 'Success'), ('measured_qemu_exit', 0)]:
            raw = buffers();x = json.loads(raw['RESULT.json']);x[key] = value;raw['RESULT.json'] = json.dumps(x).encode()
            with self.assertRaises(ValueError):checker.evaluate(raw, pcap(7302), SOURCES)

    def test_gap_conflicting_retransmit_and_wrong_tuple_refused(self):
        for capture in (pcap(7302, segments=[(0, HELLO), (240, POST)]),
                        pcap(7302, segments=[(0, HELLO + POST), (239, b'x' + POST[1:])]), pcap(7303)):
            with self.assertRaises(ValueError):checker.client_stream(capture, 7302)

    def test_truncated_and_checksum_mutated_capture_refused(self):
        original = pcap(7302)
        for data in (original[:23], original[:-1], original + b'x'):
            with self.assertRaises(ValueError):checker.client_stream(data, 7302)
        changed = bytearray(original);changed[24 + 16 + 14 + 10] ^= 1
        with self.assertRaises(ValueError):checker.client_stream(bytes(changed), 7302)

    def test_duplicate_JSON_key_and_fixture_disagreement_refused(self):
        raw = buffers();raw['RESULT.json'] = b'{"case":"P02","case":"P03"}'
        with self.assertRaises(ValueError):checker.evaluate(raw, pcap(7302), SOURCES)
        raw = buffers();x = json.loads(raw['FIXTURE.json']);x['accepts'] = 2;raw['FIXTURE.json'] = json.dumps(x).encode()
        with self.assertRaises(ValueError):checker.evaluate(raw, pcap(7302), SOURCES)

    def test_cli_binds_all_buffers_runner_and_separate_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);case = root / 'case';case.mkdir();raw = buffers();capture = pcap(7302)
            for name, data in raw.items():(case / name).write_bytes(data)
            (case / 'tls.pcap').write_bytes(capture)
            runner = root / 'runner.py';runner.write_bytes(b'# synthetic runner\n')
            with mock.patch.object(checker.common, 'RUNNER_SHA256', checker.common.digest(runner.read_bytes())):
                args = ['--case-dir', str(case), '--runner', str(runner), '--pcap-sha256', checker.common.digest(capture)]
                for name, flag in zip(checker.common.FILES, ('result', 'fixture', 'case-inputs')):
                    args += ['--' + flag + '-sha256', checker.common.digest(raw[name])]
                for name, values in SOURCES.items():
                    for field, value in values.items():args += ['--' + name + '-' + field, value]
                self.assertEqual(checker.main(args + ['--output', str(root / 'PASS.json')]), 0)
                self.assertEqual(json.loads((root / 'PASS.json').read_bytes())['disposition'], 'PASS_BOUNDED_REJECTION_OUTPUT')
                with self.assertRaises(ValueError):checker.main(args + ['--output', str(case / 'overwrite.json')])
                changed = bytearray(capture);changed[-1] ^= 1;(case / 'tls.pcap').write_bytes(changed)
                self.assertEqual(checker.main(args + ['--output', str(root / 'FAIL.json')]), 1)


if __name__ == '__main__':unittest.main()
