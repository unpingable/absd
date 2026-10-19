#!/usr/bin/env python3
"""Execution-host composition and close-origin controls; synthetic evidence only."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


BASE = load('quic_combined_base', 'native-quic-q01-source-controls.py')
IPV6 = load('quic_combined_ipv6', 'test-native-quic-ipv6-consumer.py')
MATRIX, MANIFEST = BASE.MATRIX, BASE.MANIFEST
CASES = {case['id']: case for case in MANIFEST['native_occurrences']}


class CloseOriginControls(unittest.TestCase):
    def test_selected_ipv4_profiles_calibrate_with_original_numeric_codes(self):
        proofs = [('Q01', BASE.proof()), ('Q03', BASE.initial_loss_proof()),
                  ('Q19', BASE.queue_proof()), ('Q08', BASE.wrong_root_proof())]
        proofs += [(case['id'], BASE.auth_proof(case)) for case in BASE.AUTH_CASES]
        for identity, (output, fixture, wire) in proofs:
            with self.subTest(case=identity):
                MATRIX.verify_native(CASES[identity], output, fixture, wire, MANIFEST)

    def test_same_authentication_code_with_other_origin_refuses(self):
        for case in [BASE.Q08, *BASE.AUTH_CASES]:
            output, fixture, wire = (BASE.wrong_root_proof() if case['id'] == 'Q08'
                                     else BASE.auth_proof(case))
            before, after = ('peer', 'local') if case['id'] == 'Q11' else ('local', 'peer')
            changed = output.replace('transport_close_origin=' + before,
                                     'transport_close_origin=' + after)
            self.assertNotEqual(changed, output)
            with self.subTest(case=case['id']), self.assertRaisesRegex(RuntimeError, 'different transport close origin'):
                MATRIX.verify_native(case, changed, fixture, wire, MANIFEST)

    def test_missing_and_unknown_origin_refuse(self):
        for origin in (None, '', 'Local', 'remote'):
            output, fixture, wire = BASE.wrong_root_proof()
            changed = output.replace('transport_close_origin=local',
                                     '' if origin is None else 'transport_close_origin=' + origin)
            with self.subTest(origin=origin), self.assertRaises(RuntimeError):
                MATRIX.verify_native(BASE.Q08, changed, fixture, wire, MANIFEST)

    def test_code_and_origin_must_be_present_together(self):
        for code, origin in [('none', 'local'), ('none', 'peer'), ('304', 'none'), ('0', 'none')]:
            report = dict(transport_error_code=code, transport_close_origin=origin)
            with self.subTest(code=code, origin=origin), self.assertRaisesRegex(RuntimeError, 'pair differs'):
                MATRIX.verify_transport_close_origin(CASES['Q14'], report)

    def test_complete_stays_strict_on_peer_no_error_close(self):
        output, fixture, wire = BASE.proof()
        changed = output.replace('transport_error_code=none', 'transport_error_code=0')
        changed = changed.replace('transport_close_origin=none', 'transport_close_origin=peer')
        with self.assertRaisesRegex(RuntimeError, 'Complete has a transport close cause'):
            MATRIX.verify_native(CASES['Q01'], changed, fixture, wire, MANIFEST)

    def test_ipv6_positive_wrong_root_and_denied_destination_calibrate(self):
        for identity in ('Q01', 'Q08', 'Q17'):
            output, fixture, wire = IPV6.proof(identity)
            with self.subTest(case=identity):
                MATRIX.verify_native(CASES[identity], output, fixture, wire, MANIFEST, 'ipv6')

    def test_ipv6_peer_304_cannot_qualify_local_wrong_root(self):
        output, fixture, wire = IPV6.proof('Q08')
        changed = output.replace('transport_close_origin=local', 'transport_close_origin=peer')
        with self.assertRaisesRegex(RuntimeError, 'different transport close origin'):
            MATRIX.verify_native(CASES['Q08'], changed, fixture, wire, MANIFEST, 'ipv6')


class CompositionControls(unittest.TestCase):
    def test_both_families_select_q08_fence_and_standard_q01(self):
        peer = BASE.PEER_MODULE
        for family in ('ipv4', 'ipv6'):
            self.assertEqual(peer.response_policy(CASES['Q08'], family), 'q08-one-response-flight-v1')
            self.assertEqual(peer.response_policy(CASES['Q01'], family), 'standard')
            self.assertTrue(peer.one_response_policy(CASES['Q08'], family))
            self.assertFalse(peer.one_response_policy(CASES['Q01'], family))

    def test_ipv4_auth_and_queue_profiles_survive_family_composition(self):
        peer = BASE.PEER_MODULE
        for identity in ('Q09', 'Q10', 'Q11'):
            self.assertEqual(peer.response_policy(CASES[identity], 'ipv4'), 'auth-one-response-flight-v1')
            with self.assertRaises(RuntimeError):
                peer.response_policy(CASES[identity], 'ipv6')
        self.assertEqual(peer.response_policy(CASES['Q19'], 'ipv4'), 'standard')
        with self.assertRaises(RuntimeError):
            peer.response_policy(CASES['Q19'], 'ipv6')
        self.assertEqual(len(peer.queue_fixture_datagrams()), 4)
        self.assertTrue(all(len(row) == 16 for row in peer.queue_fixture_datagrams()))

    def test_linux_ipv6_wrong_root_uses_selected_family_validator(self):
        observed, pki = BASE.WrongRootControls().linux()
        observed['transport_family'] = 'ipv6'
        observed['fixture'].update(transport_family='ipv6', readiness_profile='q08-ipv6-development')
        MATRIX.verify_linux_auth_refusal(CASES['Q08'], observed, pki, 'ipv6')
        with self.assertRaises(RuntimeError):
            MATRIX.verify_linux_auth_refusal(CASES['Q08'], observed, pki, 'ipv4')
        observed['fixture']['transport_family'] = 'ipv4'
        with self.assertRaises(RuntimeError):
            MATRIX.verify_linux_auth_refusal(CASES['Q08'], observed, pki, 'ipv6')

    def test_denied_ipv6_profile_never_selects_authentication_fixture(self):
        self.assertEqual(BASE.PEER_MODULE.response_policy(CASES['Q17'], 'ipv6'), 'standard')
        self.assertEqual(MATRIX.development_profile(CASES['Q17'], 'ipv6'), 'q17-ipv6-development')
        with self.assertRaises(RuntimeError):
            BASE.PEER_MODULE.response_policy(CASES['Q17'], 'ipv4')


if __name__ == '__main__':
    unittest.main()
