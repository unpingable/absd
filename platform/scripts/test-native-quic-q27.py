#!/usr/bin/env python3
"""Execution-host Q27 selection, peer methods and complete artifact controls.

Synthetic serial/capture records test the real oracle, and real Linux UDP
queues plus a controlled raw socket test the actual peer methods. Neither is
a native Q27 run or proof that an ICMP reporter is authenticated. All methods
remain UNRUN until invoked on the admitted execution host.
"""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


ART = module('q27_artifact_vectors', 'test-native-quic-icmp.py')
METHODS = module('q27_peer_vectors', 'test-native-quic-icmp-peer.py')
SELECTION = module('q27_selection_vectors', 'test-native-quic-control-selection.py')
MATRIX, WIRE, PEER = ART.MATRIX, ART.WIRE, METHODS.PEER
CASE = ART.CASES['Q27']
PROFILE = 'q27-icmp-1200-development'
MANIFEST_SHA256 = 'a1cd3276a017ac4e2507f919d0c1c362391b4125a72df74f1786e60bbffb6b57'
OLD_MANIFEST_SHA256 = '7cdd23841480012b15ab3dbafaf0bf4a104318ed20b0f0894c126e5ab574646f'


def proof(**kwargs):
    output, fixture, wire = ART.proof('Q27', **kwargs)
    fixture['icmp_policy'] = 'q27-literal-quote-v1'
    return output, fixture, wire


def check(output, fixture, wire):
    return MATRIX.verify_native(CASE, output, fixture, wire, ART.MANIFEST)


class Q27Controls(unittest.TestCase):
    def test_exact_amended_manifest_identity_and_unchanged_case_contract(self):
        self.assertEqual(hashlib.sha256((ROOT.parent / 'quic/CASES.json').read_bytes()).hexdigest(),
                         MANIFEST_SHA256)
        self.assertEqual((CASE['id'], CASE['ordinal'], CASE['local_port'], CASE['name'],
                          CASE['peer_mode'], CASE['icmp_mtu'], CASE['native_error_codes'],
                          CASE['grant_lifetime_ms'], CASE['expected_outcome']),
                         ('Q27', 26, 7826, 'icmp-1200', 'icmp-1200', 1200, [14], 15000, 'Native'))
        self.assertEqual(CASE['requires'], ['recent_submitted_quote', 'peer_icmp_sent',
                                           'pipe_fenced', 'no_mtu_override'])

    def test_runner_peer_and_wire_admit_only_current_q27_profile(self):
        self.assertEqual(MATRIX.development_profile(CASE), PROFILE)
        self.assertEqual(PEER.development_profile(CASE), PROFILE)
        self.assertEqual(MATRIX.peer_control_cases(CASE), ['Q01'])
        for parser in (MATRIX.development_profile, PEER.development_profile):
            with self.assertRaisesRegex(RuntimeError, 'IPv6'):
                parser(CASE, 'ipv6')
        output, fixture, wire = proof()
        self.assertEqual(check(output, fixture, wire)['actual_outcome'], 'Native')

    def test_retired_1228_selector_and_native15_case_list_refuse(self):
        for changed in (dict(CASE, peer_mode='icmp-1228', icmp_mtu=1228),
                        dict(CASE, native_error_codes=[14, 15])):
            for parser in (MATRIX.development_profile, PEER.development_profile):
                with self.subTest(changed=changed, parser=parser.__name__), self.assertRaises(RuntimeError):
                    parser(changed)
            initial = ART.original('Q27')
            with self.assertRaises(WIRE.Refusal):
                WIRE.observe(ART.pcap([initial, ART.advice(initial, changed['icmp_mtu'])]),
                             changed, ART.GM, ART.PM)

    def test_q27_selector_mutations_refuse_in_runner_and_peer(self):
        for key, value in (('local_port', 7825), ('icmp_mtu', 1228), ('icmp_mtu', True),
                           ('icmp_mtu', 1200.0), ('icmp_mtu', '1200'), ('peer_mode', 'echo'),
                           ('expected_outcome', 'Complete'), ('grant_lifetime_ms', 15001),
                           ('missing_output', True), ('missing_time', True), ('queue_control', True),
                           ('suppress_reply', True), ('interrupt_phase', 'Handshake'),
                           ('interrupt_delay_ms', 1)):
            for parser in (MATRIX.development_profile, PEER.development_profile):
                with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                    parser(dict(CASE, **{key: value}))

    def test_control_selection_is_q01_and_native_selection_is_q27(self):
        cases = SELECTION.CASES
        for requested in ([], ['Q01']):
            self.assertEqual(MATRIX.select_development_cases(cases, PROFILE, 'ipv4', True, requested),
                             (['Q01'], ['Q01'], 'q01-development'))
        for requested in ([], ['Q27']):
            self.assertEqual(MATRIX.select_development_cases(cases, PROFILE, 'ipv4', False, requested),
                             (['Q27'], ['Q01'], PROFILE))
        with self.assertRaisesRegex(RuntimeError, 'real Linux prerequisite Q01'):
            MATRIX.select_development_cases(cases, PROFILE, 'ipv4', True, ['Q27'])
        with self.assertRaisesRegex(RuntimeError, 'exact case'):
            MATRIX.select_development_cases(cases, PROFILE, 'ipv4', False, ['Q01'])

    def test_real_cli_writes_actual_q01_labels_and_usable_native_prerequisite(self):
        for requested in ([], ['Q01']):
            with SELECTION.runner_fixture(PROFILE) as invoke:
                code, receipt, cases, calls, native_calls = invoke(requested)
                self.assertEqual((code, native_calls, calls), (0, 0, [('Q01', {'timeout': 1})]))
                for row in (receipt, cases['Q01']):
                    self.assertEqual(row['readiness_profile'], 'q01-development')
                    self.assertEqual(row['requested_readiness_profile'], PROFILE)
                    self.assertFalse(row['ABSD_execution'])
                    self.assertFalse(row['canonical_campaign_acceptance'])
                for key in ('requested_case_ids', 'attempted_case_ids', 'completed_case_ids'):
                    self.assertEqual(receipt[key], ['Q01'])
                self.assertEqual(receipt['missing_requested_case_ids'], [])
                code, native, _, calls, native_calls = invoke(controls=False, control_receipt=receipt)
                self.assertEqual((code, native_calls, calls), (0, 1, []))
                self.assertEqual(native['completed_case_ids'], ['Q27'])
                self.assertEqual(native['readiness_profile'], PROFILE)

    def test_real_cli_controls_refuse_native_condition(self):
        with SELECTION.runner_fixture(PROFILE) as invoke, \
             self.assertRaisesRegex(RuntimeError, 'real Linux prerequisite Q01'):
            invoke(['Q27'])

    def test_native_reader_refuses_old_manifest_or_relabelled_q27_calibration(self):
        for changes in ({'case_manifest_sha256': OLD_MANIFEST_SHA256},
                        {'readiness_profile': PROFILE}, {'completed_case_ids': ['Q27']}):
            with SELECTION.runner_fixture(PROFILE) as invoke:
                _, receipt, _, _, _ = invoke()
                receipt.update(changes)
                code, result, _, _, native_calls = invoke(controls=False, control_receipt=receipt)
                self.assertEqual((code, native_calls), (1, 0))
                self.assertIn('independent limited Q01 control is incomplete', result['error']['message'])

    def test_complete_native14_literal_quote_and_all_ledger_correspondence(self):
        for outgoing in (False, True):
            for raw_first in (False, True):
                output, fixture, wire = proof(outgoing_copy=outgoing, raw_first=raw_first)
                observed = check(output, fixture, wire)
                self.assertEqual(observed['icmp']['native_error_code'], 14)
                self.assertEqual(observed['icmp']['native_error_detail'], 1200)
                self.assertEqual(observed['icmp']['captured_guest_udp'], 1)
                self.assertTrue(observed['icmp']['result_eof'])
                self.assertEqual(len(bytes.fromhex(wire['icmp'][0]['frame_hex'])), 70)

    def test_native15_is_not_an_alternate_q27_success(self):
        output, fixture, wire = proof(code=15)
        with self.assertRaisesRegex(RuntimeError, 'typed native error differs: native_error_code'):
            check(output, fixture, wire)

    def test_native14_wrong_details_refuse(self):
        output, fixture, wire = proof()
        for detail in (0, 576, 1172, 1227, 1228):
            with self.subTest(detail=detail), self.assertRaises(RuntimeError):
                check(ART.change(output, 'QUIC RESULT', native_error_detail=detail), fixture, wire)

    def test_equal1228_advice_is_not_q27_wire_evidence(self):
        initial = ART.original('Q27')
        for mtu in (0, 576, 1227, 1228):
            with self.subTest(mtu=mtu), self.assertRaises(WIRE.Refusal):
                WIRE.observe(ART.pcap([initial, ART.advice(initial, mtu)]), CASE, ART.GM, ART.PM)

    def test_missing_duplicate_or_udp_substitution_refuses_full_capture(self):
        initial = ART.original('Q27')
        advice = ART.advice(initial, 1200)
        substitute = METHODS.BASE.frame(METHODS.INITIAL, guest=False, case_id='Q27')
        for frames in ([initial], [initial, advice, advice], [initial, substitute],
                       [initial, advice, substitute]):
            with self.subTest(length=len(frames)), self.assertRaises(WIRE.Refusal):
                WIRE.observe(ART.pcap(frames), CASE, ART.GM, ART.PM)

    def test_actual_peer_socket_and_raw_frame_emit_exactly_one_1200_quote(self):
        with METHODS.fixture('Q27') as (peer, sender, raw):
            METHODS.deliver_udp(peer, sender)
            self.assertEqual(raw.sent, [])
            METHODS.deliver_frame(peer, raw)
            expected = METHODS.expected_error(METHODS.original('Q27'), 1200)
            self.assertEqual(raw.sent, [expected])
            self.assertEqual(len(expected), 70)
            self.assertEqual(expected[40:42], (1200).to_bytes(2, 'big'))
            self.assertEqual(expected[42:], METHODS.original('Q27')[14:42])
            self.assertEqual(peer.icmp_send_result['actual_sent_bytes'], 70)
            peer.try_icmp_send()
            self.assertEqual(raw.sent, [expected])
            peer.close_icmp_socket()
            self.assertTrue(raw.closed and peer.raw_socket_closed)
            self.assertIsNone(peer.connection)
            self.assertEqual((peer.tx_packets, peer.tx_bytes), (0, 0))

    def test_actual_peer_uncertain_or_partial_send_never_retries(self):
        for outcome in (69, OSError('fixture uncertain raw send')):
            with self.subTest(outcome=str(outcome)), METHODS.fixture('Q27', outcome) as (peer, sender, raw):
                METHODS.deliver_udp(peer, sender)
                with self.assertRaises((RuntimeError, OSError)):
                    METHODS.deliver_frame(peer, raw)
                self.assertTrue(peer.icmp_send_attempted and peer.icmp_failed)
                self.assertFalse(peer.icmp_send_completed)
                with self.assertRaisesRegex(RuntimeError, 'permanently refused'):
                    peer.try_icmp_send()
                self.assertEqual(len(raw.sent), 1)

    def test_q27_peer_has_no_pki_engine_or_linux_emulation(self):
        self.assertIsNone(PEER.load_peer_pki(CASE, '/not-read'))
        with self.assertRaisesRegex(RuntimeError, 'cannot construct an engine'):
            PEER.configuration(None, client=True, case=CASE)
        with self.assertRaisesRegex(RuntimeError, 'separate Linux Q01'):
            PEER.linux_control(CASE, None)

    def test_q27_policy_label_cannot_substitute_for_actual_completed_evidence(self):
        output, fixture, wire = proof()
        for change in ({'icmp_policy': 'q25-q26-q28-literal-quote-v1'},
                       {'raw_socket_closed': False}, {'icmp_send_completed': False},
                       {'engine_constructed': True}, {'icmp_failed': True}):
            changed = copy.deepcopy(fixture)
            changed.update(change)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                check(output, changed, wire)

    def test_socket_raw_capture_and_native_send_identity_are_all_required(self):
        output, fixture, wire = proof(outgoing_copy=False)
        for target in ('socket', 'raw', 'capture', 'native'):
            changed, observed, serial = copy.deepcopy(fixture), copy.deepcopy(wire), output
            if target == 'socket':
                ART.event(changed, 'udp-receive')['sha256'] = '0' * 64
            elif target == 'raw':
                ART.event(changed, 'icmp-frame-receive')['frame_hex'] = ART.original('Q26').hex()
            elif target == 'capture':
                observed['guest_udp'][0]['sha256'] = '0' * 64
            else:
                serial = ART.change(serial, 'QUIC FIXTURE SEND', sha256='0' * 64)
            with self.subTest(target=target), self.assertRaises(RuntimeError):
                check(serial, changed, observed)

    def test_normal_reap_true_eof_and_absent_authority_are_required(self):
        output, fixture, wire = proof()
        for prefix, values in (('QUIC CHILD EXIT', {'kind': 3}),
                               ('QUIC CHILD AUTHORITY RETIRED', {'result_eof': 'false'}),
                               ('QUIC CHILD AUTHORITY RETIRED', {'grant_live': 'true'}),
                               ('QUIC CHILD AUTHORITY RETIRED', {'sockets': 1}),
                               ('QUIC FIXTURE NATIVE_COUNTS', {'send_requests': 0}),
                               ('QUIC FIXTURE NATIVE_COUNTS', {'receive_delivered': 1})):
            with self.subTest(prefix=prefix, values=values), self.assertRaises(RuntimeError):
                check(ART.change(output, prefix, **values), fixture, wire)

    def test_original_guest_clocks_and_no_after_fence_send_are_required(self):
        output, fixture, wire = proof()
        for prefix, values in (('QUIC SERVICE GRANT', {'owner_expiry_ms': 16001}),
                               ('QUIC RESULT', {'deadline_ms': 16000}),
                               ('QUIC FIXTURE NATIVE_COUNTS', {'at_ms': 74}),
                               ('QUIC FIXTURE SEND', {'at_ms': 76}),
                               ('QUIC RESULT', {'sends_after_fence': 1})):
            with self.subTest(prefix=prefix, values=values), self.assertRaises(RuntimeError):
                check(ART.change(output, prefix, **values), fixture, wire)


if __name__ == '__main__':
    unittest.main(verbosity=2)
