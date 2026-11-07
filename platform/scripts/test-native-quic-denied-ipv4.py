#!/usr/bin/env python3
"""Finite actual-checker and passive-peer controls, authored for offhost use.

Synthetic native records are oracle controls, not native denial evidence.
Real local UDP exercises the passive Peer path only, never ABSD authority.
"""
import copy
import hashlib
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


ART = module('denied_authority_vectors', 'test-native-quic-authority.py')
METHODS = module('denied_peer_vectors', 'test-native-quic-authority-peer.py')
SELECTION = module('denied_selection_vectors', 'test-native-quic-control-selection.py')
IPV6 = module('denied_ipv6_vectors', 'test-native-quic-ipv6-consumer.py')
MATRIX, MANIFEST, PEER, WIRE = ART.MATRIX, ART.MANIFEST, METHODS.PEER, METHODS.WIRE
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q17')
PROFILE = 'q17-denied-destination-development'
REQUEST = b'ABSD_QUIC_DENIED'


def proof():
    report = {name: '0' for name in MANIFEST['report']['fields']}
    report.update(case='Q17', outcome='Native', phase='Fenced', native_failure_kind='Native',
        native_error_code='2', native_error_detail='none', transport_error_code='none', transport_close_origin='none',
        send_calls='1', pipe_fenced='true', unknown_send='false', no_native_pair='false',
        receive_calls='0', close_calls='0', partial_pipe_reads='0', partial_pipe_writes='0',
        heap_observed_high_pages='0', frames_observed_high='0',
        last_send_ms='12', fence_ms='16', start_ms='10', end_ms='18', deadline_ms='10010', grant_expiry_ms='15001',
        pending_exhausted_sha256='none', pending_retry_sha256='none')
    for name in ('authenticated', 'request_fin', 'peer_fin', 'request_acked', 'connection_drained', 'close_accepted'):
        report[name] = 'false'
    rows = [
        ART.line('QUIC SERVICE SELECTOR', case='Q17', unix_seconds=1792279191, local_port=7816, grant_lifetime_ms=15000),
        ART.line('QUIC SERVICE GRANT', case='Q17', before_ms=1, constructed_ms=2, owner_expiry_ms=15001, local_port=7816, peer_port=4443),
        ART.line('QUIC FIXTURE SEND', case='Q17', ordinal=1, at_ms=13, bytes=len(REQUEST),
                 peer_ip='10.0.2.2', peer_port=4444, sha256=hashlib.sha256(REQUEST).hexdigest()),
        ART.line('QUIC FIXTURE NATIVE_COUNTS', case='Q17', at_ms=17, send_requests=1, receive_delivered=0,
                 sends_after_owner_expiry=0, partial_request_bytes=0, partial_reply_bytes=0),
        ART.line('QUIC CHILD AUTHORITY RETIRED', case='Q17', reaped_ms=20, retired_ms=21,
                 process_handle_live='false', pipe_live='false', grant_live='false', sockets=0,
                 result_eof='true', owner_expired='false'),
        ART.line('QUIC CHILD EXIT', case='Q17', kind=1, status=0, killed='false'),
        'QUIC CONSUMER case=Q17 begin',
        ART.line('QUIC CPU', vendor='GenuineIntel', family=6, model=60, leaf1_eax=0x306c0, leaf1_ecx=1 << 30, rdrand=1),
        ART.line('QUIC BEGIN', case='Q17', start_ms=10, deadline_ms=10010, grant_expiry_ms=15001,
                 unix_time='Some(1792279191)', native_pair='true'),
        ART.line('QUIC PHASE', case='Q17', phase='Init', at_ms=10),
        ART.line('QUIC PHASE', case='Q17', phase='Fenced', at_ms=17),
        ART.line('QUIC RESULT', **report),
        'QUIC CONSUMER case=Q17 end',
        ART.line('QUIC SERVICE RETIRE', case='Q17', sockets_before_fence=0, sockets_after_fence=0),
        ART.line('QUIC SERVICE DONE', case='Q17', sockets=0, processes_before=2, processes_after=2,
                 handles_before=13, handles_after=13, pipes_before=2, pipes_after=2, cells_before=1, cells_after=1)]
    fixture = dict(case='Q17', mode='denied-destination', transport_family='ipv4', readiness_profile=PROFILE,
        denied_policy='q17-ipv4-denied-destination-v1', canonical_campaign_acceptance=False,
        engine_constructed=False, certificate_selection=None, errors=[], thread_alive=False,
        authenticated=False, request_fin=False, echo_fin_enqueued=False, terminated=None,
        request_bytes=0, echo_enqueued_bytes=0, passive_receive_count=0,
        rx_datagrams=0, tx_datagrams=0, rx_bytes=0, tx_bytes=0, private_material_included=False,
        events=[dict(event='peer-ended', stopped=True, deadline_reached=False)])
    wire = WIRE.observe(METHODS.pcap([]), CASE, METHODS.GM, METHODS.PM)
    return '\n'.join(rows), fixture, wire


def check(values=None):
    return MATRIX.verify_native(CASE, *(values or proof()), MANIFEST)


class DeniedIpv4Controls(unittest.TestCase):
    def test_real_full_checker_accepts_exact_preengine_denial(self):
        result = check()
        self.assertEqual(result['actual_outcome'], 'Native')
        self.assertEqual(result['denial']['native_error_code'], 2)
        self.assertEqual(result['denial']['attempted_port'], 4444)
        self.assertTrue(result['denial']['result_eof'])

    def test_profile_case_mode_port_and_flags_are_exact(self):
        for parser in (MATRIX.development_profile, PEER.development_profile):
            self.assertEqual(parser(CASE), PROFILE)
            for key, value in (('local_port', 7800), ('local_port', True), ('peer_mode', 'echo'),
                    ('expected_outcome', 'Complete'), ('native_error_codes', [8]), ('grant_lifetime_ms', 14999),
                    ('interrupt_phase', 'Handshake'), ('interrupt_delay_ms', 1), ('missing_time', True),
                    ('missing_output', True), ('queue_control', True), ('suppress_reply', True), ('requires', [])):
                with self.subTest(parser=parser.__name__, key=key), self.assertRaises(RuntimeError):
                    parser(dict(CASE, **{key: value}))

    def test_actual_selection_maps_linux_q01_and_keeps_native_q17(self):
        for requested in ([], ['Q01']):
            self.assertEqual(MATRIX.select_development_cases(SELECTION.CASES, PROFILE, 'ipv4', True, requested),
                             (['Q01'], ['Q01'], 'q01-development'))
        self.assertEqual(MATRIX.select_development_cases(SELECTION.CASES, PROFILE, 'ipv4', False, []),
                         (['Q17'], ['Q01'], PROFILE))
        for controls, requested in ((True, ['Q17']), (False, ['Q01']), (False, ['Q17', 'Q17'])):
            with self.assertRaises(RuntimeError):
                MATRIX.select_development_cases(SELECTION.CASES, PROFILE, 'ipv4', controls, requested)
        with self.assertRaises(RuntimeError):
            MATRIX.select_development_cases(SELECTION.CASES, PROFILE, 'ipv6', False, [])

    def test_real_argparse_requires_the_explicit_profile_name(self):
        for profile, expected in ((PROFILE, 0), ('q17-development', 2), ('q17-ipv4', 2)):
            result = subprocess.run([sys.executable, MATRIX.__file__, '--profile', profile, '--help'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, expected, result.stderr)

    def test_real_main_labels_linux_calibration_q01_not_denial(self):
        with SELECTION.runner_fixture(PROFILE) as invoke:
            code, receipt, cases, calls, native_calls = invoke()
            self.assertEqual((code, calls, native_calls), (0, [('Q01', dict(timeout=1))], 0))
            for record in (receipt, cases['Q01']):
                self.assertEqual(record['readiness_profile'], 'q01-development')
                self.assertEqual(record['requested_readiness_profile'], PROFILE)
                self.assertFalse(record['ABSD_execution'])

    def test_linux_sockets_cannot_claim_native_denial(self):
        with self.assertRaisesRegex(RuntimeError, 'separate Linux Q01'):
            PEER.linux_control(CASE, None)
        self.assertIsNone(PEER.load_peer_pki(CASE, Path('/nonexistent-Q17-private-material')))

    def test_real_peer_constructor_stays_engine_and_pki_free(self):
        value = PEER.Peer(CASE, None, '127.0.0.1', 0, ('127.0.0.1', 9), startup_timeout=180)
        try:
            self.assertIsNone(value.connection)
            self.assertIsNone(value.pki)
            value.drive_timer(0)
            value.flush()
        finally:
            value.close()
        fixture = value.report()
        MATRIX.verify_ipv4_denied_peer(CASE, fixture, proof()[2])

    def test_actual_udp_input_is_retained_then_refused(self):
        with METHODS.fixture('Q17') as (value, sender):
            sender.sendto(REQUEST, value.socket.getsockname())
            with self.assertRaisesRegex(RuntimeError, 'Q17 passive fixture unexpectedly received UDP'):
                value.receive_authority()
            self.assertEqual((value.rx_packets, value.rx_bytes, value.passive_receive_count), (1, len(REQUEST), 1))
            self.assertEqual(value.events[0]['data_hex'], REQUEST.hex())
            self.assertEqual(value.events[1]['event'], 'passive-input')
            self.assertEqual(value.tx_packets, 0)

    def test_send_timer_and_flush_cannot_bypass_passive_peer(self):
        with METHODS.fixture('Q17') as (value, sender):
            with self.assertRaises(RuntimeError):
                value.send(REQUEST)
            with self.assertRaises(socket.timeout):
                sender.recvfrom(64)
            value.connection = METHODS.PublicConnection()
            for operation in (lambda: value.drive_timer(0), value.flush, lambda: value.send(REQUEST)):
                with self.assertRaises(RuntimeError):
                    operation()
            self.assertEqual(value.connection.calls, [])

    def test_existing_ipv6_profile_and_full_denial_proof_remain_accepted(self):
        self.assertEqual(MATRIX.development_profile(CASE, 'ipv6'), 'q17-ipv6-development')
        self.assertEqual(PEER.development_profile(CASE, 'ipv6'), 'q17-ipv6-development')
        MATRIX.verify_native(CASE, *IPV6.proof('Q17'), MANIFEST, family='ipv6')

    def test_zero_udp_capture_and_wrong_wire_selector_controls(self):
        self.assertEqual(proof()[2]['udp_count'], 0)
        for changed in (dict(CASE, local_port=7817), dict(CASE, peer_mode='echo')):
            with self.assertRaises(WIRE.Refusal):
                WIRE.observe(METHODS.pcap([]), changed, METHODS.GM, METHODS.PM)

    def test_both_captured_udp_directions_refuse(self):
        for guest in (True, False):
            frame = METHODS.frame(REQUEST, 'Q17', guest=guest)
            with self.assertRaises(WIRE.Refusal):
                WIRE.observe(METHODS.pcap([frame]), CASE, METHODS.GM, METHODS.PM)

    def test_attempted_destination_body_and_ordinal_cannot_change(self):
        output, fixture, wire = proof()
        for key, value in (('peer_ip', '10.0.2.3'), ('peer_port', 4443), ('bytes', 15),
                           ('sha256', '0'*64), ('ordinal', 2), ('family', 6), ('scope', 1)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                check((ART.change(output, 'QUIC FIXTURE SEND', **{key: value}), fixture, wire))

    def test_missing_or_repeated_attempt_is_not_denial(self):
        output, fixture, wire = proof()
        with self.assertRaises(RuntimeError):
            check((ART.without(output, 'QUIC FIXTURE SEND'), fixture, wire))
        send = next(row for row in output.splitlines() if row.startswith('QUIC FIXTURE SEND '))
        with self.assertRaises(RuntimeError):
            check((output.replace(send, send+'\n'+send), fixture, wire))

    def test_stale_link_unknown_and_transport_failure_cannot_substitute(self):
        output, fixture, wire = proof()
        for key, value in (('outcome', 'Entropy'), ('native_failure_kind', 'Unknown'), ('native_error_code', 8),
                    ('native_error_code', 9), ('native_error_detail', 1), ('unknown_send', 'true'),
                    ('transport_error_code', 304), ('transport_close_origin', 'local')):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                check((ART.change(output, 'QUIC RESULT', **{key: value}), fixture, wire))

    def test_zero_accepted_entropy_engine_receive_and_app_work(self):
        output, fixture, wire = proof()
        for key in ('send_accepted', 'send_bytes', 'received', 'receive_bytes', 'receive_calls', 'engine_transmits',
                    'entropy_attempts', 'unexpected_rng_draws', 'sent_stream', 'received_stream', 'close_calls',
                    'sends_after_fence', 'queue_fills', 'queue_retry_accepted', 'exhausted'):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                check((ART.change(output, 'QUIC RESULT', **{key: 1}), fixture, wire))
        for key in ('authenticated', 'request_fin', 'peer_fin', 'request_acked', 'connection_drained', 'close_accepted'):
            with self.assertRaises(RuntimeError):
                check((ART.change(output, 'QUIC RESULT', **{key: 'true'}), fixture, wire))

    def test_complete_native_framing_census_is_exact(self):
        output, fixture, wire = proof()
        for key, value in (('send_requests', 0), ('send_requests', 2), ('receive_delivered', 1),
                ('sends_after_owner_expiry', 1), ('partial_request_bytes', 1), ('partial_reply_bytes', 1)):
            with self.assertRaises(RuntimeError):
                check((ART.change(output, 'QUIC FIXTURE NATIVE_COUNTS', **{key: value}), fixture, wire))

    def test_original_grant_and_valid_named_pair_are_required(self):
        output, fixture, wire = proof()
        for key, value in (('local_port', 7817), ('peer_port', 4444), ('owner_expiry_ms', 15002), ('constructed_ms', 11)):
            with self.assertRaises(RuntimeError):
                check((ART.change(output, 'QUIC SERVICE GRANT', **{key: value}), fixture, wire))
        for prefix, key, value in (('QUIC BEGIN', 'native_pair', 'false'), ('QUIC BEGIN', 'unix_time', 'None'),
                                  ('QUIC RESULT', 'no_native_pair', 'true')):
            with self.assertRaises(RuntimeError):
                check((ART.change(output, prefix, **{key: value}), fixture, wire))

    def test_optional_native_times_are_present_and_canonical(self):
        output, fixture, wire = proof()
        for key in ('last_send_ms', 'fence_ms'):
            for value in ('none', '-1', '01', '1.0'):
                with self.assertRaises(RuntimeError):
                    check((ART.change(output, 'QUIC RESULT', **{key: value}), fixture, wire))

    def test_send_fence_end_reap_and_census_time_boundaries(self):
        output, fixture, wire = proof()
        check((ART.change(output, 'QUIC FIXTURE NATIVE_COUNTS', at_ms=21), fixture, wire))
        for prefix, key, value in (('QUIC FIXTURE SEND', 'at_ms', 11), ('QUIC FIXTURE SEND', 'at_ms', 17),
                ('QUIC RESULT', 'end_ms', 15), ('QUIC FIXTURE NATIVE_COUNTS', 'at_ms', 15),
                ('QUIC FIXTURE NATIVE_COUNTS', 'at_ms', 22), ('QUIC CHILD AUTHORITY RETIRED', 'reaped_ms', 17),
                ('QUIC CHILD AUTHORITY RETIRED', 'retired_ms', 10010), ('QUIC BEGIN', 'deadline_ms', 10011)):
            with self.subTest(prefix=prefix, key=key), self.assertRaises(RuntimeError):
                check((ART.change(output, prefix, **{key: value}), fixture, wire))

    def test_normal_reap_true_eof_and_no_live_authority_are_required(self):
        output, fixture, wire = proof()
        for key in ('process_handle_live', 'pipe_live', 'grant_live', 'owner_expired'):
            with self.assertRaises(RuntimeError):
                check((ART.change(output, 'QUIC CHILD AUTHORITY RETIRED', **{key: 'true'}), fixture, wire))
        for key, value in (('result_eof', 'false'), ('sockets', 1)):
            with self.assertRaises(RuntimeError):
                check((ART.change(output, 'QUIC CHILD AUTHORITY RETIRED', **{key: value}), fixture, wire))
        for key, value in (('kind', 2), ('status', 1), ('killed', 'true')):
            with self.assertRaises(RuntimeError):
                check((ART.change(output, 'QUIC CHILD EXIT', **{key: value}), fixture, wire))

    def test_missing_lifecycle_or_wrong_buffered_publication_refuses(self):
        output, fixture, wire = proof()
        for prefix in ('QUIC BEGIN', 'QUIC CHILD AUTHORITY RETIRED', 'QUIC CHILD EXIT', 'QUIC SERVICE RETIRE'):
            with self.assertRaises(RuntimeError):
                check((ART.without(output, prefix), fixture, wire))
        with self.assertRaises(RuntimeError):
            check((ART.move_before(output, 'QUIC CHILD AUTHORITY RETIRED', 'QUIC FIXTURE NATIVE_COUNTS'), fixture, wire))

    def test_object_or_socket_retention_refuses(self):
        output, fixture, wire = proof()
        for key in ('processes_after', 'handles_after', 'pipes_after', 'cells_after', 'sockets'):
            with self.assertRaises(RuntimeError):
                check((ART.change(output, 'QUIC SERVICE DONE', **{key: 999}), fixture, wire))
        for key in ('sockets_before_fence', 'sockets_after_fence'):
            with self.assertRaises(RuntimeError):
                check((ART.change(output, 'QUIC SERVICE RETIRE', **{key: 1}), fixture, wire))

    def test_peer_labels_cannot_hide_engine_certificate_or_input(self):
        output, fixture, wire = proof()
        for key, value in (('engine_constructed', True), ('certificate_selection', {}), ('authenticated', True),
                ('transport_family', 'ipv6'), ('denied_policy', 'other'), ('case', 'Q01'), ('mode', 'echo'),
                ('request_bytes', 1), ('rx_datagrams', 1), ('tx_bytes', 1), ('passive_receive_count', 1)):
            changed = copy.deepcopy(fixture); changed[key] = value
            with self.assertRaises(RuntimeError):
                check((output, changed, wire))

    def test_peer_must_end_before_deadline_with_complete_event_census(self):
        output, fixture, wire = proof()
        for events in ([], [dict(event='peer-ended')],
                [dict(event='peer-ended', stopped=True, deadline_reached=True)],
                fixture['events']+[dict(event='udp-receive', bytes=16)],
                fixture['events']+[dict(event='udp-send', bytes=16)]):
            changed = copy.deepcopy(fixture); changed['events'] = events
            with self.assertRaises(RuntimeError):
                check((output, changed, wire))

    def test_wire_census_and_canonical_json_integers_are_exact(self):
        output, fixture, wire = proof()
        for key in ('udp_count', 'guest_udp_count', 'guest_udp_bytes', 'unexpected_frames'):
            for value in (1, False, -1, 0.0, '0'):
                changed = copy.deepcopy(wire); changed[key] = value
                with self.assertRaises(RuntimeError):
                    check((output, fixture, changed))
        for key, value in (('family', 6), ('scope', 1)):
            changed = copy.deepcopy(wire); changed[key] = value
            with self.assertRaises(RuntimeError):
                check((output, fixture, changed))
        for value in (False, -1, 0.0, '0'):
            changed = copy.deepcopy(fixture); changed['rx_bytes'] = value
            with self.assertRaises(RuntimeError):
                check((output, changed, wire))


if __name__ == '__main__':
    unittest.main()
