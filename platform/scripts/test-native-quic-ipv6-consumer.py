#!/usr/bin/env python3
"""Execution-host controls for the explicit IPv6 QUIC consumer composition.

Synthetic records and literal capture vectors establish oracle behavior, not
native execution or cryptographic validity. Do not run on the shared host.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


BASE = load('quic6_base_controls', 'native-quic-q01-source-controls.py')
VECTORS = load('quic6_literal_vectors', 'test-native-quic-ipv6-wire.py')
BUILDER = load('quic6_builder_controls', 'build-native-quic-fixture.py')
MATRIX, MANIFEST = BASE.MATRIX, BASE.MANIFEST
CASES = {case['id']: case for case in MANIFEST['native_occurrences']}


def line(prefix, **values):
    return prefix + ' ' + ' '.join(key + '=' + str(value) for key, value in values.items())


def proof(identity='Q01'):
    case = CASES[identity]
    output, fixture, _ = BASE.proof()
    rows = {}
    for text in output.splitlines():
        prefix = text[:text.index(' case=')] if ' case=' in text else text[:text.index(' vendor=')]
        row = MATRIX.fields(text)
        if 'case' in row:
            row['case'] = identity
        if 'local_port' in row:
            row['local_port'] = str(case['local_port'])
        for key in ('before_ms', 'constructed_ms', 'owner_expiry_ms', 'start_ms', 'last_send_ms',
                    'fence_ms', 'end_ms', 'deadline_ms', 'grant_expiry_ms', 'at_ms'):
            if key in row:
                row[key] = str(int(row[key]) + 1200)
        rows[prefix] = row
    report = rows['QUIC RESULT']
    report['phase'] = 'Fenced'
    for prefix in ('QUIC FIXTURE SEND', 'QUIC FIXTURE RX'):
        rows[prefix].update(peer_ip='fd00:ab5d::2', family='6', scope='1')
    port = case['local_port']
    frames = [] if identity == 'Q17' else [VECTORS.NS, VECTORS.NA, VECTORS.packet(port=port), VECTORS.packet(False, port=port)]
    wire = VECTORS.wire.observe(VECTORS.pcap(frames), case, VECTORS.GM, VECTORS.PM)
    fixture.update(readiness_profile=MATRIX.development_profile(case, 'ipv6'), transport_family='ipv6',
                   peer_policy='standard', response_flight_sealed=False)
    if identity != 'Q17':
        guest, peer = wire['guest_udp'][0], wire['peer_udp'][0]
        fixture['events'] = [dict(event='udp-receive', bytes=1200, sha256=guest['sha256'], source=guest['source']),
                             dict(event='initial-observed', bytes=1200, sha256=guest['sha256']),
                             dict(event='udp-send', bytes=1200, sha256=peer['sha256'], source=peer['source'], destination=peer['destination'])]
        rows['QUIC FIXTURE RX']['sha256'] = peer['sha256']
    if identity in ('Q08', 'Q17'):
        for key in ('authenticated', 'request_fin', 'peer_fin', 'request_acked', 'connection_drained', 'close_accepted'):
            report[key] = 'false'
        report.update(sent_stream='0', received_stream='0')
        fixture.update(authenticated=False, request_bytes=0, echo_enqueued_bytes=0, request_fin=False, echo_fin_enqueued=False)
    if identity == 'Q08':
        report.update(outcome='Protocol', transport_error_code='304', transport_close_origin='local')
        fixture.update(mode='wrong-root', peer_policy='q08-one-response-flight-v1', response_flight_sealed=True,
                       certificate_selection={'kind':'untrusted', 'sha256':'d'*64, 'client_root_sha256':'e'*64})
        received, initial, sent = fixture['events']
        fixture['events'] = [received, initial,
            dict(event='q08-response-flight', policy='q08-one-response-flight-v1', initial_sha256=initial['sha256'],
                 datagrams=[{key:sent[key] for key in ('bytes', 'sha256', 'destination')}]), sent,
            dict(event='q08-response-flight-fenced', policy='q08-one-response-flight-v1',
                 tx_bytes=1200, tx_datagrams=1, later_engine_work=False, later_send=False)]
    if identity == 'Q17':
        report.update(outcome='Native', native_failure_kind='Native', native_error_code='2', native_error_detail='none',
                      transport_error_code='none', send_accepted='0', send_bytes='0', received='0', receive_bytes='0',
                      receive_calls='0', engine_transmits='0', entropy_attempts='0', close_calls='0')
        rows.pop('QUIC FIXTURE RX')
        rows['QUIC FIXTURE SEND']['peer_port'] = '4444'
        rows['QUIC FIXTURE NATIVE_COUNTS']['receive_delivered'] = '0'
        fixture.update(rx_datagrams=0, tx_datagrams=0, rx_bytes=0, tx_bytes=0, events=[])
    rows.update({
        'QUIC IPV6 RX SETUP': dict(case=identity, nic_ready_ms=0, ready_ms=1100, delta_ms=1100, continuous_vm_required=1),
        'QUIC SERVICE FAMILY': dict(case=identity, family=6, scope=1, local_ip='fd00:ab5d::15', peer_ip='fd00:ab5d::2', peer_port=4443),
        'QUIC TRANSPORT': dict(case=identity, family=6, scope=1, peer_ip='fd00:ab5d::2', peer_port=4443),
        'QUIC IPV6 CLIENT AUTHORITY': dict(case=identity, nic=0, block='false', input=10, output=11),
        'QUIC SERVICE RETIRE': dict(case=identity, sockets_before_fence=0, sockets_after_fence=0),
    })
    order = ['QUIC SERVICE SELECTOR', 'QUIC IPV6 RX SETUP', 'QUIC SERVICE FAMILY', 'QUIC SERVICE GRANT',
             'QUIC CPU', 'QUIC TRANSPORT', 'QUIC BEGIN', 'QUIC IPV6 CLIENT AUTHORITY', 'QUIC FIXTURE SEND',
             'QUIC FIXTURE RX', 'QUIC RESULT', 'QUIC CHILD EXIT', 'QUIC FIXTURE NATIVE_COUNTS',
             'QUIC SERVICE RETIRE', 'QUIC SERVICE DONE']
    return '\n'.join(line(prefix, **rows[prefix]) for prefix in order if prefix in rows), fixture, wire


class ConsumerControls(unittest.TestCase):
    def check(self, identity='Q01', values=None):
        return MATRIX.verify_native(CASES[identity], *(values or proof(identity)), MANIFEST, family='ipv6')

    def test_ipv4_default_still_calibrates(self):
        MATRIX.verify_native(CASES['Q01'], *BASE.proof(), MANIFEST)

    def test_only_three_explicit_ipv6_profiles_are_admitted(self):
        for identity in ('Q01', 'Q08', 'Q17'):
            self.assertEqual(MATRIX.development_profile(CASES[identity], 'ipv6'), identity.lower()+'-ipv6-development')
        for case in (CASES['Q03'], dict(CASES['Q01'], local_port=7801), dict(CASES['Q08'], peer_mode='echo')):
            with self.assertRaises(RuntimeError): MATRIX.development_profile(case, 'ipv6')
        with self.assertRaises(RuntimeError): MATRIX.development_profile(CASES['Q01'], 'unknown')

    def test_echo_exact_native_wire_and_pipe_correspondence_calibrates(self):
        self.check()

    def test_bounded_wrong_root_calibrates(self):
        self.check('Q08')

    def test_q08_after_flight_input_cannot_establish_application_absence(self):
        out, fixture, wire = proof('Q08')
        fixture['events'].append(dict(event='q08-after-flight-input', bytes=1200, sha256='f'*64,
                                      engine_delivered=False))
        with self.assertRaisesRegex(RuntimeError, 'native Q08 received input after the response flight'):
            self.check('Q08', (out, fixture, wire))

    def test_preengine_capability_denial_calibrates(self):
        self.check('Q17')

    def test_family_scope_and_peer_substitution_refuse(self):
        for before, after in [('family=6', 'family=4'), ('scope=1', 'scope=2'),
                              ('fd00:ab5d::2', 'fd00:ab5d::3'), ('local_ip=fd00:ab5d::15', 'local_ip=fd00:ab5d::16')]:
            out, fixture, wire = proof()
            with self.subTest(before=before), self.assertRaises(RuntimeError): self.check(values=(out.replace(before, after), fixture, wire))

    def test_pregrant_settling_and_original_deadline_refuse_changes(self):
        for before, after in [('ready_ms=1100', 'ready_ms=1099'), ('delta_ms=1100', 'delta_ms=1101'),
                              ('continuous_vm_required=1', 'continuous_vm_required=0'), ('deadline_ms=11210', 'deadline_ms=11211')]:
            out, fixture, wire = proof()
            with self.subTest(before=before), self.assertRaises(RuntimeError): self.check(values=(out.replace(before, after), fixture, wire))

    def test_child_nic_block_or_equal_pipe_roles_refuse(self):
        for before, after in [('nic=0', 'nic=1'), ('block=false', 'block=true'), ('output=11', 'output=10')]:
            out, fixture, wire = proof()
            with self.subTest(before=before), self.assertRaises(RuntimeError): self.check(values=(out.replace(before, after), fixture, wire))

    def test_missing_authority_or_socket_retirement_refuses(self):
        for prefix in ('QUIC IPV6 CLIENT AUTHORITY ', 'QUIC SERVICE RETIRE '):
            out, fixture, wire = proof()
            out = '\n'.join(row for row in out.splitlines() if not row.startswith(prefix))
            with self.assertRaises(RuntimeError): self.check(values=(out, fixture, wire))

    def test_receive_bytes_without_exact_capture_refuse(self):
        out, fixture, wire = proof(); wire['peer_udp'][0]['sha256'] = 'f'*64
        with self.assertRaises(RuntimeError): self.check(values=(out, fixture, wire))

    def test_q08_every_send_requires_capture_and_fence(self):
        for mode in ('missing-capture', 'late-send', 'changed-batch'):
            out, fixture, wire = proof('Q08')
            if mode == 'missing-capture': wire['peer_udp'] = []
            elif mode == 'late-send': fixture['events'].append(copy.deepcopy(next(row for row in fixture['events'] if row['event']=='udp-send')))
            else: fixture['events'][2]['datagrams'][0]['sha256'] = 'f'*64
            with self.subTest(mode=mode), self.assertRaises(RuntimeError): self.check('Q08', (out, fixture, wire))

    def test_q08_application_receipt_or_other_protocol_refusal_refuse(self):
        for before, after in [('transport_error_code=304', 'transport_error_code=298'), ('received_stream=0', 'received_stream=1')]:
            out, fixture, wire = proof('Q08')
            with self.assertRaises(RuntimeError): self.check('Q08', (out.replace(before, after), fixture, wire))

    def test_denial_to_the_authorized_port_is_not_the_negative_case(self):
        out, fixture, wire = proof('Q17')
        out = out.replace('bytes=1200 peer_ip=fd00:ab5d::2 peer_port=4444', 'bytes=1200 peer_ip=fd00:ab5d::2 peer_port=4443')
        with self.assertRaises(RuntimeError): self.check('Q17', (out, fixture, wire))

    def test_denial_refuses_engine_entropy_receive_or_acceptance(self):
        for key in ('entropy_attempts', 'engine_transmits', 'send_accepted', 'received', 'receive_calls', 'sent_stream'):
            out, fixture, wire = proof('Q17')
            with self.subTest(key=key), self.assertRaises(RuntimeError): self.check('Q17', (out.replace(key+'=0', key+'=1'), fixture, wire))

    def test_denial_refuses_neighbor_or_peer_input(self):
        for mode in ('nd', 'udp', 'peer'):
            out, fixture, wire = proof('Q17')
            if mode == 'nd': wire['nd'] = [{}]
            elif mode == 'udp': wire['guest_udp'] = [{}]; wire['guest_udp_count'] = 1
            else: fixture['rx_datagrams'] = 1
            with self.subTest(mode=mode), self.assertRaises(RuntimeError): self.check('Q17', (out, fixture, wire))

    def test_private_case_profiles_do_not_modify_the_wire_classifier(self):
        untouched = VECTORS.wire.accounting(); before = repr(untouched.PROFILES)
        first, second = MATRIX.ipv6_accounting(CASES['Q01']), MATRIX.ipv6_accounting(CASES['Q08'])
        self.assertEqual(repr(untouched.PROFILES), before)
        self.assertEqual(set(untouched.PROFILES), {'udp', 'tcp'})
        self.assertEqual(first.original.PROFILES['quic6']['udp'], [7800, 4443])
        self.assertEqual(second.original.PROFILES['quic6']['udp'], [7807, 4443])

    def test_changed_helper_pin_refuses_before_import(self):
        with mock.patch.object(MATRIX, 'sha', return_value='f'*64), self.assertRaises(RuntimeError):
            MATRIX.ipv6_accounting(CASES['Q01'])


class BuildReceiptControls(unittest.TestCase):
    def receipt(self):
        return dict(source_revision='a'*40, source_tree='b'*40, transport_family='ipv6', root_der={'sha256':'c'*64},
                    outputs={'quic_echo':{'sha256':'d'*64}}, tracked_dirty=False, untracked_source=False)

    def test_exact_same_source_family_root_and_child_calibrate(self):
        BUILDER.verify_ipv6_client(self.receipt(), 'd'*64, 'c'*64, 'a'*40, 'b'*40)

    def test_source_tree_family_root_child_or_dirty_substitution_refuse(self):
        for key in ('source_revision', 'source_tree', 'transport_family', 'root_der', 'outputs', 'tracked_dirty', 'untracked_source'):
            receipt = self.receipt(); receipt[key] = True if key.endswith('dirty') or key=='untracked_source' else 'wrong'
            # Nested receipt objects remain objects, so refusal tests the identity rather than Python type errors.
            if key == 'root_der': receipt[key] = {'sha256':'f'*64}
            if key == 'outputs': receipt[key] = {'quic_echo':{'sha256':'f'*64}}
            with self.subTest(key=key), self.assertRaises(ValueError): BUILDER.verify_ipv6_client(receipt, 'd'*64, 'c'*64, 'a'*40, 'b'*40)

    def test_matrix_child_receipt_checks_match_builder(self):
        receipt = self.receipt(); admission = dict(sources={'platform':dict(revision='a'*40, tree='b'*40)}, client_sha256='d'*64)
        MATRIX.verify_ipv6_client_receipt(receipt, admission, {'sha256':'c'*64})
        receipt['transport_family'] = 'ipv4'
        with self.assertRaises(RuntimeError): MATRIX.verify_ipv6_client_receipt(receipt, admission, {'sha256':'c'*64})


class DriverReasonControls(unittest.TestCase):
    def evaluate(self, directory, refused=1, missed=0, sidecar_changed=False):
        work = Path(directory); reasons = MATRIX.ipv6_accounting(CASES['Q17'])
        capture = work/'quic.pcap'; serial = work/'quic.serial.log'
        capture.write_bytes(VECTORS.pcap([VECTORS.mld()]))
        serial.write_bytes(b'NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n'
                           b'NIC RX FILTERED dst=33:33:00:00:00:16\n')
        marker = SimpleNamespace(capture=capture, serial=serial)
        marker.annotation = {key:dict(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                             for key, path in [('capture', capture), ('serial', serial)]}
        marker.annotation.update(previous_absent=None, observation=None)
        sidecar = copy.deepcopy(marker.annotation)
        if sidecar_changed: sidecar['capture']['bytes'] += 1
        (work/'NIC-READY-CAPTURE.json').write_text(json.dumps(sidecar))
        return reasons.evaluate(work, marker, dict(rx_refused=str(refused), rx_missed=str(missed), tx_refused='0', tx_errors='0'), VECTORS.GM, VECTORS.PM, 'quic6')

    def test_full_linux_mld_driver_reason_correspondence_calibrates(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.evaluate(directory)['disposition'], 'PASS')

    def test_counter_mismatch_or_exhausted_reason_budget_refuses(self):
        for refused, missed in [(0, 0), (5, 0), (1, 1)]:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(AssertionError):
                self.evaluate(directory, refused, missed)

    def test_changed_serialized_sidecar_refuses(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(AssertionError):
            self.evaluate(directory, sidecar_changed=True)


if __name__ == '__main__':
    unittest.main()
