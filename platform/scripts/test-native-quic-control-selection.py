#!/usr/bin/env python3
"""Execution-host controls for actual Linux calibration selection and labels.

The runner uses synthetic peer/native callbacks here. Real argv parsing,
selection, receipt writing and the unchanged native prerequisite reader run;
these controls establish no protocol, native execution or authority behavior.
"""
from contextlib import contextmanager
import copy
import importlib.util
import json
from pathlib import Path
import socket
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('quic_control_selection', ROOT/'native-quic-q01.py')
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)
MANIFEST = json.loads((ROOT.parent/'quic/CASES.json').read_text())
CASES = {case['id']:case for case in MANIFEST['native_occurrences'] + MANIFEST['conditional_native_occurrences']}
PROFILES = [
    ('ipv4', 'Q01', 'q01-development'),
    ('ipv4', 'Q02', 'q02-partial-ipc-development'),
    ('ipv4', 'Q03', 'q03-initial-loss-development'),
    ('ipv4', 'Q04', 'q04-stream-loss-development'),
    ('ipv4', 'Q05', 'q05-duplicate-reorder-development'),
    ('ipv4', 'Q06', 'q06-flow-pause-development'),
    ('ipv4', 'Q07', 'q07-silent-development'),
    ('ipv4', 'Q08', 'q08-wrong-root-development'),
    ('ipv4', 'Q09', 'q09-wrong-name-development'),
    ('ipv4', 'Q10', 'q10-expired-development'),
    ('ipv4', 'Q11', 'q11-wrong-alpn-development'),
    ('ipv4', 'Q12', 'q12-truncated-header-development'),
    ('ipv4', 'Q13', 'q13-invalid-tag-development'),
    ('ipv4', 'Q14', 'q14-long-retry-development'),
    ('ipv4', 'Q16', 'q16-unknown-cid-development'),
    ('ipv4', 'Q18', 'q18-unauthorized-source-development'),
    ('ipv4', 'Q19', 'q19-queue-exhausted-development'),
    ('ipv4', 'Q21', 'q21-interrupt-handshake-development'),
    ('ipv4', 'Q22', 'q22-interrupt-stream-development'),
    ('ipv4', 'Q23', 'q23-owner-expiry-development'),
    ('ipv4', 'Q24', 'q24-link-failure-development'),
    ('ipv4', 'Q29', 'q29-missing-output-development'),
    ('ipv4', 'Q30', 'q30-missing-time-development'),
    ('ipv6', 'Q01', 'q01-ipv6-development'),
    ('ipv6', 'Q08', 'q08-ipv6-development'),
    ('ipv6', 'Q17', 'q17-ipv6-development'),
]
MAPPED = [row for row in PROFILES if row[1] in ('Q24', 'Q29', 'Q30', 'Q17')]
DIGEST = 'c'*64


@contextmanager
def runner_fixture(profile, family='ipv4'):
    """Exercise main's real filesystem receipts with explicit synthetic calls."""
    with tempfile.TemporaryDirectory(prefix='quic-control-selection-') as temporary:
        root = Path(temporary)
        source, kernel = root/'source', root/'kernel'
        source.mkdir()
        kernel.mkdir()
        admission_path, pki_path = root/'admission.json', root/'pki.json'
        pki_path.write_text(json.dumps(dict(private_keys_in_evidence=False,
            public_certificates=[], leaf_certificates={},
            root_der=dict(path='synthetic-public-root.der', sha256=DIGEST), validation_unix_time=time.time())))
        wire_name = 'native-quic-ipv6-wire.py' if family == 'ipv6' else 'native-quic-wire.py'
        admission = dict(readiness_profile=profile, transport_family=family, disposition='GO',
            runner_source_sha256=DIGEST, peer_source_sha256=DIGEST,
            wire_source_sha256=MATRIX.IPV6_PINS.get(wire_name, DIGEST),
            accounting_source_sha256=MATRIX.IPV6_PINS['native-ipv6-accounting.py'],
            reason_accounting_source_sha256=MATRIX.IPV6_PINS['native-ipv6-reason-accounting.py'],
            python_sha256=DIGEST, host_name=socket.gethostname(),
            machine_id=Path('/etc/machine-id').read_text().strip(), peer_controls_go=True, native_execution_go=True,
            minimum_remaining_before_case_seconds=1200, review_records=[dict(path='synthetic-review', sha256=DIGEST)],
            case_manifest_sha256=DIGEST, peer_closure_path='synthetic-closure', peer_closure_sha256=DIGEST,
            peer_site_packages='synthetic-site', absolute_deletion_deadline_epoch=time.time()+3600,
            peer_timeout_seconds=1, sources=dict(platform=dict(path=str(source)), kernel=dict(path=str(kernel))),
            wire_macs=dict(guest='52:54:00:12:34:56', peer=Path('/sys/class/net/lo/address').read_text().strip()),
            tap='lo', measure_sha256=DIGEST, net_helper_sha256=DIGEST)
        counter = 0

        def invoke(case_ids=(), controls=True, control_receipt=None, linux_error=False, fixture_profile=None,
                   admission_profile=None):
            nonlocal counter
            work = root/('work'+str(counter))
            counter += 1
            current_admission = copy.deepcopy(admission)
            if admission_profile is not None:
                current_admission['readiness_profile'] = admission_profile
            if control_receipt is not None:
                path = root/('controls'+str(counter)+'.json')
                path.write_text(json.dumps(control_receipt))
                current_admission['linux_controls_result'] = dict(path=str(path), sha256=DIGEST)
            admission_path.write_text(json.dumps(current_admission))
            calls = []

            def linux(case, pki, **kwargs):
                calls.append((case['id'], kwargs))
                if linux_error:
                    raise RuntimeError('synthetic Linux calibration failure')
                return dict(error=None, actual_outcome='Complete', peer_fin=True,
                    fixture=dict(errors=[], request_bytes=4096, request_fin=True, echo_fin_enqueued=True,
                        readiness_profile=fixture_profile or MATRIX.development_profile(case, family),
                        transport_family=family, events=[]))

            peer = SimpleNamespace(validate_pki=lambda pki:None,
                verify_runtime=lambda *args:dict(synthetic_runtime=True), linux_control=linux)

            def load(name, path):
                return peer if name == 'native_quic_peer' else SimpleNamespace(synthetic_helper=True)

            argv = [MATRIX.__file__, '--admission', str(admission_path), '--profile', profile,
                '--family', family, '--pki', str(pki_path), '--manifest', str(ROOT.parent/'quic/CASES.json'),
                '--work', str(work)]
            if controls:
                argv.append('--controls')
            else:
                argv += ['--source', str(source), '--kernel', str(kernel), '--measure-tools', str(root/'measure.py')]
            for identity in case_ids:
                argv += ['--case', identity]
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(MATRIX.os, 'geteuid', return_value=0), \
                 mock.patch.object(MATRIX, 'sha', side_effect=lambda path:MATRIX.IPV6_PINS.get(Path(path).name, DIGEST)), \
                 mock.patch.object(MATRIX, 'module', side_effect=load), \
                 mock.patch.object(MATRIX, 'native_case', side_effect=lambda case,*args:dict(case=case['id'], synthetic_native=True)) as native:
                code = MATRIX.main()
                result = json.loads((work/'RESULT.json').read_text())
                case_results = {path.stem:json.loads(path.read_text()) for path in work.glob('Q[0-9][0-9].json')}
                return code, result, case_results, calls, native.call_count
        yield invoke


class SelectionControls(unittest.TestCase):
    def test_native_default_and_explicit_selection_preserve_every_profile(self):
        for family, identity, profile in PROFILES:
            for requested in ([], [identity]):
                with self.subTest(family=family, profile=profile, requested=requested):
                    selected, prerequisite, actual = MATRIX.select_development_cases(CASES, profile, family, False, requested)
                    self.assertEqual((selected, actual), ([identity], profile))
                    self.assertEqual(prerequisite, ['Q01'] if (family, identity, profile) in MAPPED else [identity])

    def test_mapped_controls_default_and_explicit_select_only_actual_q01(self):
        for family, identity, profile in MAPPED:
            for requested in ([], ['Q01']):
                with self.subTest(profile=profile, requested=requested):
                    selected, prerequisite, actual = MATRIX.select_development_cases(CASES, profile, family, True, requested)
                    self.assertEqual((selected, prerequisite, actual), (['Q01'], ['Q01'],
                        'q01-ipv6-development' if family == 'ipv6' else 'q01-development'))

    def test_controls_never_select_a_mapped_native_condition(self):
        for family, identity, profile in MAPPED:
            with self.subTest(profile=profile), self.assertRaisesRegex(RuntimeError, 'real Linux prerequisite Q01'):
                MATRIX.select_development_cases(CASES, profile, family, True, [identity])

    def test_unmapped_controls_keep_default_and_explicit_case_and_profile(self):
        for family, identity, profile in PROFILES:
            if (family, identity, profile) in MAPPED:
                continue
            for requested in ([], [identity]):
                with self.subTest(profile=profile, requested=requested):
                    self.assertEqual(MATRIX.select_development_cases(CASES, profile, family, True, requested),
                                     ([identity], [identity], profile))

    def test_native_refuses_substituted_q01_for_mapped_profiles(self):
        for family, identity, profile in MAPPED:
            with self.subTest(profile=profile), self.assertRaisesRegex(RuntimeError, 'exact case'):
                MATRIX.select_development_cases(CASES, profile, family, False, ['Q01'])

    def test_controls_refuse_unrelated_duplicate_unknown_and_multiple_cases(self):
        for requested in (['Q02'], ['Q01', 'Q01'], ['Q99'], ['Q01', 'Q29']):
            with self.subTest(requested=requested), self.assertRaises(RuntimeError):
                MATRIX.select_development_cases(CASES, 'q29-missing-output-development', 'ipv4', True, requested)

    def test_family_and_profile_are_not_inferred_from_control_mapping(self):
        for family, profile in (('ipv6', 'q29-missing-output-development'), ('ipv4', 'q17-ipv6-development'),
                                ('ipv6', 'q01-development'), ('ipv4', 'q01-ipv6-development'),
                                ('ipv5', 'q01-development'), ('ipv4', 'q29-invented')):
            with self.subTest(family=family, profile=profile), self.assertRaises(RuntimeError):
                MATRIX.select_development_cases(CASES, profile, family, True, [])

    def test_original_native_selector_still_validates_before_mapping(self):
        changed = copy.deepcopy(CASES)
        changed['Q29']['missing_output'] = False
        with self.assertRaisesRegex(RuntimeError, 'authority selector'):
            MATRIX.select_development_cases(changed, 'q29-missing-output-development', 'ipv4', True, [])

    def test_actual_calibration_selector_is_also_validated(self):
        changed = copy.deepcopy(CASES)
        changed['Q01']['peer_mode'] = 'missing-output'
        with self.assertRaisesRegex(RuntimeError, 'bounded development case'):
            MATRIX.select_development_cases(changed, 'q29-missing-output-development', 'ipv4', True, [])


class RunnerReceiptControls(unittest.TestCase):
    def assert_calibration(self, result, case_result, profile, family):
        actual = 'q01-ipv6-development' if family == 'ipv6' else 'q01-development'
        for row in (result, case_result):
            self.assertEqual(row['readiness_profile'], actual)
            self.assertEqual(row['requested_readiness_profile'], profile)
            self.assertEqual(row['transport_family'], family)
            self.assertFalse(row['ABSD_execution'])
            self.assertFalse(row['canonical_campaign_acceptance'])
        for key in ('requested_case_ids', 'attempted_case_ids', 'completed_case_ids'):
            self.assertEqual(result[key], ['Q01'])
        self.assertEqual(result['missing_requested_case_ids'], [])
        self.assertEqual(result['unattempted_case_ids'], [])
        self.assertEqual(case_result['case'], 'Q01')

    def test_real_main_writes_actual_q01_labels_for_every_mapped_profile(self):
        for family, identity, profile in MAPPED:
            with self.subTest(profile=profile), runner_fixture(profile, family) as invoke:
                code, result, cases, calls, native_calls = invoke()
                self.assertEqual(code, 0)
                self.assertEqual(result['disposition'], 'PASS')
                self.assert_calibration(result, cases['Q01'], profile, family)
                self.assertEqual(calls, [('Q01', dict(timeout=1, **({'family':'ipv6'} if family == 'ipv6' else {})))])
                self.assertEqual(native_calls, 0)

    def test_real_cli_explicit_q01_writes_the_same_actual_calibration(self):
        for family, identity, profile in MAPPED:
            with self.subTest(profile=profile), runner_fixture(profile, family) as invoke:
                code, result, cases, _, native_calls = invoke(['Q01'])
                self.assertEqual((code, native_calls), (0, 0))
                self.assert_calibration(result, cases['Q01'], profile, family)

    def test_real_cli_refuses_explicit_native_conditions_with_controls(self):
        for family, identity, profile in MAPPED:
            with self.subTest(profile=profile), runner_fixture(profile, family) as invoke, \
                 self.assertRaisesRegex(RuntimeError, 'real Linux prerequisite Q01'):
                invoke([identity])

    def test_real_cli_native_mode_refuses_q01_substitution(self):
        for family, identity, profile in MAPPED:
            with self.subTest(profile=profile), runner_fixture(profile, family) as invoke, \
                 self.assertRaisesRegex(RuntimeError, 'exact case'):
                invoke(['Q01'], controls=False)

    def test_admission_stays_bound_to_requested_profile(self):
        with runner_fixture('q29-missing-output-development') as invoke, \
             self.assertRaisesRegex(RuntimeError, 'explicit limited profile differs'):
            invoke(admission_profile='q01-development')

    def test_failed_calibration_keeps_actual_identity_without_completed_native_case(self):
        with runner_fixture('q30-missing-time-development') as invoke:
            code, result, cases, calls, native_calls = invoke(linux_error=True)
            self.assertEqual((code, result['disposition'], native_calls), (1, 'FAIL', 0))
            self.assertEqual(result['readiness_profile'], 'q01-development')
            self.assertEqual(result['requested_readiness_profile'], 'q30-missing-time-development')
            self.assertEqual(result['requested_case_ids'], ['Q01'])
            self.assertEqual(result['attempted_case_ids'], ['Q01'])
            self.assertEqual(result['completed_case_ids'], [])
            self.assertEqual(result['missing_requested_case_ids'], ['Q01'])
            self.assertEqual(cases, {})

    def test_ipv6_actual_peer_profile_must_be_q01_not_requested_q17(self):
        with runner_fixture('q17-ipv6-development', 'ipv6') as invoke:
            code, result, cases, _, native_calls = invoke(fixture_profile='q17-ipv6-development')
            self.assertEqual((code, result['disposition'], native_calls), (1, 'FAIL', 0))
            self.assertIn('actual Linux IPv6 fixture differs', result['error']['message'])
            self.assertEqual(result['completed_case_ids'], [])

    def test_generated_receipts_pass_the_unchanged_native_prerequisite_reader(self):
        for family, identity, profile in MAPPED:
            with self.subTest(profile=profile), runner_fixture(profile, family) as invoke:
                _, control, _, _, _ = invoke()
                code, native, _, linux_calls, native_calls = invoke(controls=False, control_receipt=control)
                self.assertEqual((code, native_calls, linux_calls), (0, 1, []))
                self.assertEqual(native['readiness_profile'], profile)
                self.assertEqual(native['requested_readiness_profile'], profile)
                self.assertEqual(native['requested_case_ids'], [identity])
                self.assertEqual(native['attempted_case_ids'], [identity])
                self.assertEqual(native['completed_case_ids'], [identity])

    def test_native_reader_refuses_receipt_relabelled_as_requested_condition(self):
        with runner_fixture('q29-missing-output-development') as invoke:
            _, receipt, _, _, _ = invoke()
            receipt['readiness_profile'] = 'q29-missing-output-development'
            code, result, _, _, native_calls = invoke(controls=False, control_receipt=receipt)
            self.assertEqual((code, native_calls), (1, 0))
            self.assertIn('independent limited Q01 control is incomplete', result['error']['message'])

    def test_native_reader_refuses_incomplete_or_substituted_calibration_ids(self):
        with runner_fixture('q30-missing-time-development') as invoke:
            _, receipt, _, _, _ = invoke()
            for key, value in (('completed_case_ids', []), ('requested_case_ids', ['Q30']),
                               ('attempted_case_ids', ['Q30']), ('missing_requested_case_ids', ['Q01'])):
                changed = copy.deepcopy(receipt)
                changed[key] = value
                with self.subTest(key=key):
                    code, result, _, _, native_calls = invoke(controls=False, control_receipt=changed)
                    self.assertEqual((code, native_calls), (1, 0))
                    self.assertIn('independent limited Q01 control is incomplete', result['error']['message'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
