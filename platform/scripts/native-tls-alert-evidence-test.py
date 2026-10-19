#!/usr/bin/env python3
"""Synthetic artifact controls only; not native execution or Linux controls."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('alert_receipt', Path(__file__).with_name('native-tls-alert-evidence.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
ALERT = bytes.fromhex('15030300020232')
SOURCES = {'platform': {'revision': '1' * 40, 'tree': '2' * 40},
           'kernel': {'revision': '3' * 40, 'tree': '4' * 40}}


def fixture(payload=ALERT, parts=None, terminal='eof'):
    events = [
        {'event': 'accept', 'role': 'tls', 'source': ['10.0.2.15', 7311]},
        {'event': 'tcp-read', 'bytes': 239, 'sha256': checker.digest(b'initial fixture bytes')},
        *[{'event': 'tcp-write', 'bytes': n, 'stream_offset': at}
          for n, at in [(1, 0), (2, 1), (2, 3)]],
        {'event': 'raw-record', 'bytes_hex': 'ff03030000', 'phase': 'handshake'}]
    at = 0
    for n in parts if parts is not None else [len(payload)]:
        if n:
            events.append({'event': 'tcp-read', 'bytes': n, 'sha256': checker.digest(payload[at:at + n])})
        at += n
    if terminal == 'eof':
        events.append({'event': 'tcp-read', 'bytes': 0, 'sha256': checker.digest(b'')})
    elif terminal == 'reset':
        events.append({'event': 'connection-ended', 'error_type': 'ConnectionResetError', 'reason': 'fixture reset'})
    for i, event in enumerate(events):
        event['monotonic_ns'] = i + 1
    return {'case': {'id': 'W01', 'peer_mode': 'bad-record', 'local_port': 7311, 'expect_http': False},
            'accepts': 1, 'guard_accepts': 0, 'errors': [], 'request_bytes': 0,
            'request_sha256': checker.digest(b''), 'server_handshake_complete': False, 'events': events}


def buffers(peer=None):
    peer = fixture() if peer is None else peer
    result = {'disposition': 'PASS', 'case': 'W01', 'actual_class': 'TlsRejected',
              'measured_qemu_exit': 3, 'fixture': peer}
    inputs = {'selected_case': peer['case'], 'case_manifest_sha256': checker.MANIFEST_SHA256,
              'source': {name: {**identity, 'dirty_state': '', 'clean_required': True}
                         for name, identity in SOURCES.items()}}
    return {name: json.dumps(value).encode() for name, value in zip(checker.FILES, (result, peer, inputs))}


class ReceiptControls(unittest.TestCase):
    def test_all_64_byte_partitions_and_both_terminal_shapes(self):
        for cuts in range(64):
            parts = [];start = 0
            for at in range(1, 7):
                if cuts & (1 << (at - 1)):
                    parts.append(at - start);start = at
            parts.append(7 - start)
            for terminal in ('eof', 'reset'):
                result = checker.inspect_fixture(fixture(parts=parts, terminal=terminal))
                self.assertEqual(result['record_hex'], '15030300020232')
                self.assertEqual(sum(r['bytes'] for r in result['reads']), 7)

    def test_original_no_alert_then_reset_shape_is_not_established(self):
        with self.assertRaises(checker.NotEstablished):
            checker.inspect_fixture(fixture(payload=b'', terminal='reset'))

    def test_every_short_prefix_and_missing_terminal_refused(self):
        for n in range(7):
            with self.assertRaises(checker.NotEstablished):
                checker.inspect_fixture(fixture(payload=ALERT[:n]))
        with self.assertRaises(checker.NotEstablished):
            checker.inspect_fixture(fixture(terminal=None))

    def test_wrong_alert_fields_and_reference_OpenSSL_record_refused(self):
        for at in range(7):
            changed = bytearray(ALERT);changed[at] ^= 1
            with self.assertRaises(checker.NotEstablished):
                checker.inspect_fixture(fixture(payload=bytes(changed)))
        with self.assertRaises(checker.NotEstablished):
            checker.inspect_fixture(fixture(payload=bytes.fromhex('1503010002020a')))

    def test_mixed_extra_and_altered_receive_bytes_refused(self):
        for payload in (b'x' + ALERT, ALERT + b'x', ALERT * 2):
            with self.assertRaises(checker.NotEstablished):
                checker.inspect_fixture(fixture(payload=payload))
        bad = fixture();bad['events'][6]['sha256'] = '0' * 64
        with self.assertRaises(checker.NotEstablished):checker.inspect_fixture(bad)
        bad = fixture();bad['events'][6]['bytes'] = True
        with self.assertRaises(ValueError):checker.inspect_fixture(bad)

    def test_wrong_flow_case_errors_HTTP_or_handshake_refused(self):
        changes = [('accepts', 2), ('guard_accepts', 1), ('errors', ['fixture error']),
                   ('request_bytes', 1), ('server_handshake_complete', True)]
        for key, value in changes:
            bad = fixture();bad[key] = value
            with self.assertRaises(ValueError):checker.inspect_fixture(bad)
        for key, value in [('source', ['10.0.2.15', 7312]), ('role', 'guard')]:
            bad = fixture();bad['events'][0][key] = value
            with self.assertRaises(ValueError):checker.inspect_fixture(bad)
        bad = fixture();bad['case']['id'] = 'P01'
        with self.assertRaises(ValueError):checker.inspect_fixture(bad)

    def test_trigger_prelude_substitutions_refused(self):
        for index, key, value in [(5, 'bytes_hex', 'ff03030001'), (5, 'phase', 'response'),
                                  (4, 'stream_offset', 2), (2, 'bytes', True), (1, 'bytes', 0)]:
            bad = fixture();bad['events'][index][key] = value
            with self.assertRaises(ValueError):checker.inspect_fixture(bad)

    def test_order_data_after_EOF_and_unexpected_event_refused(self):
        bad = fixture();bad['events'][6]['monotonic_ns'] = 1
        with self.assertRaises(ValueError):checker.inspect_fixture(bad)
        bad = fixture();extra = copy.deepcopy(bad['events'][-1]);extra['monotonic_ns'] += 1;bad['events'].append(extra)
        with self.assertRaises(ValueError):checker.inspect_fixture(bad)
        bad = fixture();bad['events'][6]['event'] = 'handshake-failure-alert-drained'
        with self.assertRaises(ValueError):checker.inspect_fixture(bad)

    def test_canonical_and_runtime_prerequisites_refused(self):
        self.assertEqual(checker.evaluate(buffers(), SOURCES)['received_bytes'], 7)
        for name, key, value in [('RESULT.json', 'disposition', 'FAIL'),
                                  ('RESULT.json', 'measured_qemu_exit', 7),
                                  ('CASE-INPUTS.json', 'case_manifest_sha256', '0' * 64)]:
            raw = buffers();bad = json.loads(raw[name]);bad[key] = value;raw[name] = json.dumps(bad).encode()
            with self.assertRaises(ValueError):checker.evaluate(raw, SOURCES)
        raw = buffers();bad = json.loads(raw['CASE-INPUTS.json']);bad['source']['platform']['revision'] = 'ae30';raw['CASE-INPUTS.json'] = json.dumps(bad).encode()
        with self.assertRaises(ValueError):checker.evaluate(raw, SOURCES)
        raw = buffers();bad = json.loads(raw['FIXTURE.json']);bad['accepts'] = 2;raw['FIXTURE.json'] = json.dumps(bad).encode()
        with self.assertRaises(ValueError):checker.evaluate(raw, SOURCES)

    def test_explicit_source_identities_bind_both_components_and_clean_state(self):
        for component in SOURCES:
            for field, value in [('revision', '5' * 40), ('tree', '6' * 40),
                                 ('dirty_state', ' M source'), ('clean_required', False)]:
                raw = buffers();inputs = json.loads(raw['CASE-INPUTS.json'])
                inputs['source'][component][field] = value
                raw['CASE-INPUTS.json'] = json.dumps(inputs).encode()
                with self.assertRaises(ValueError):checker.evaluate(raw, SOURCES)
        for invalid in ({}, {'platform': SOURCES['platform']},
                        {**SOURCES, 'kernel': {'revision': 'short', 'tree': '4' * 40}}):
            with self.assertRaises(ValueError):checker.evaluate(buffers(), invalid)
        # A composed run is admitted explicitly; no specific historical tree is privileged.
        fresh = copy.deepcopy(SOURCES);fresh['platform']['revision'] = 'a' * 40
        fresh['kernel']['tree'] = 'b' * 40
        raw = buffers();inputs = json.loads(raw['CASE-INPUTS.json'])
        for name, identity in fresh.items():inputs['source'][name].update(identity)
        raw['CASE-INPUTS.json'] = json.dumps(inputs).encode()
        self.assertEqual(checker.evaluate(raw, fresh)['received_bytes'], 7)
        with self.assertRaises(ValueError):checker.evaluate(raw, SOURCES)

    def test_duplicate_JSON_keys_and_non_object_refused(self):
        for raw in (b'{"case":1,"case":2}', b'[]'):
            with self.assertRaises(ValueError):checker.decode(raw)

    def test_each_evaluated_file_content_mutation_detected_before_seal(self):
        for changed in checker.FILES:
            with tempfile.TemporaryDirectory() as directory:
                paths = {name: Path(directory) / name for name in checker.FILES};raw = buffers()
                for name, path in paths.items():path.write_bytes(raw[name])
                checker.unchanged(paths, raw)
                data = bytearray(raw[changed]);data[0] ^= 1;paths[changed].write_bytes(data)
                with self.assertRaisesRegex(ValueError, 'changed before seal'):
                    checker.unchanged(paths, raw)

    def test_CLI_hash_binding_receipt_and_no_canonical_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);case = root / 'W01';case.mkdir();raw = buffers()
            for name, data in raw.items():(case / name).write_bytes(data)
            args = ['--case-dir', str(case)]
            for name, flag in zip(checker.FILES, ('result', 'fixture', 'case-inputs')):
                args.extend(['--' + flag + '-sha256', checker.digest(raw[name])])
            for name, identity in SOURCES.items():
                for kind, value in identity.items():args.extend(['--' + name + '-' + kind, value])
            runner = root / 'runner.py';runner.write_bytes(b'# synthetic runner fixture\n')
            args.extend(['--runner', str(runner)])
            self.enterContext(mock.patch.object(checker, 'RUNNER_SHA256', checker.digest(runner.read_bytes())))
            out = root / 'receipt.json'
            self.assertEqual(checker.main(args + ['--output', str(out)]), 0)
            result = json.loads(out.read_bytes());self.assertEqual(result['disposition'], 'PASS_BOUNDED_SOCKET_RECEIPT')
            self.assertEqual({n: r['sha256'] for n, r in result['evaluated_inputs'].items()},
                             {n: checker.digest(b) for n, b in raw.items()})
            with self.assertRaises(ValueError):checker.main(args + ['--output', str(case / 'new.json')])
            bad = args.copy();bad[bad.index('--fixture-sha256') + 1] = '0' * 64
            self.assertEqual(checker.main(bad + ['--output', str(root / 'fail.json')]), 1)
            self.assertEqual(json.loads((root / 'fail.json').read_bytes())['disposition'], 'FAIL')
            runner.write_bytes(b'# changed runner\n')
            self.assertEqual(checker.main(args + ['--output', str(root / 'runner-fail.json')]), 1)
            self.assertEqual(json.loads((root / 'runner-fail.json').read_bytes())['disposition'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
