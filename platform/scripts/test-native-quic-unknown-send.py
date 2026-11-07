#!/usr/bin/env python3
"""Finite Q20 proof controls; execute on the isolated test host only.

Synthetic records and a literal checksum-valid IPv4/UDP vector exercise proof
refusals. They establish no actual native execution or cryptographic validity.
"""
import copy
import hashlib
import importlib.util
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('old_quic_controls', ROOT / 'scripts/native-quic-q01-source-controls.py')
OLD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(OLD)
MATRIX, PEER, WIRE, MANIFEST = OLD.MATRIX, OLD.PEER_MODULE, OLD.WIRE, OLD.MANIFEST
Q20 = next(c for c in MANIFEST['native_occurrences'] if c['id'] == 'Q20')
INITIAL = b'\xc0\0\0\0\1' + b'\0' * 1195
# Independent one's-complement calculation fixes both checksums in this vector.
# Its QUIC body is deliberately synthetic; only the public header is exercised.
HEADER = bytes.fromhex('0271000000025254001234560800450004cc0001400040111e100a00020f0a0002021e8b115b04b8ed86')


def observe(frames):
    return WIRE.observe(OLD.pcap(frames), Q20, '52:54:00:12:34:56', '02:71:00:00:00:02')


def line(prefix, **fields):
    return prefix + ' ' + ' '.join(k + '=' + str(v) for k, v in fields.items())


def proof():
    output, _, _ = OLD.proof()
    report = MATRIX.fields(next(s for s in output.splitlines() if s.startswith('QUIC RESULT ')))
    report.update(case='Q20', outcome='Native', native_failure_kind='Unknown', native_error_code='none',
                  native_error_detail='-110', transport_error_code='none', authenticated='false',
                  sent_stream='0', received_stream='0', request_fin='false', peer_fin='false',
                  request_acked='false', connection_drained='false', close_accepted='false',
                  close_calls='0', unknown_send='true', send_accepted='0', send_bytes='0',
                  received='0', receive_bytes='0', receive_calls='1', last_send_ms='2019',
                  fence_ms='2270', end_ms='2271', start_ms='2010', deadline_ms='12010',
                  grant_expiry_ms='17001', no_native_pair='false')
    output = '\n'.join([
        line('QUIC SERVICE SELECTOR', case='Q20', local_port=7819),
        line('QUIC SERVICE DONE', case='Q20', sockets=0,
             **{n+'_'+when:1 for n in ('processes','handles','pipes','cells') for when in ('before','after')}),
        line('QUIC Q20 RX SETUP', case='Q20', nic_ready_ms=530, ready_ms=1630,
             delta_ms=1100, continuous_vm_required=1),
        line('QUIC SERVICE GRANT', case='Q20', before_ms=2001, constructed_ms=2002,
             owner_expiry_ms=17001, local_port=7819, peer_port=4443),
        line('QUIC CPU', vendor='GenuineIntel', leaf1_eax=0x306c0, leaf1_ecx=1<<30, family=6, model=60, rdrand=1),
        line('QUIC BEGIN', case='Q20', start_ms=2010, deadline_ms=12010, grant_expiry_ms=17001),
        line('QUIC RESULT', **report),
        line('QUIC CHILD EXIT', case='Q20', kind=1, status=0, killed='false'),
        line('QUIC FIXTURE NATIVE_COUNTS', case='Q20', send_requests=1, receive_delivered=0,
             sends_after_owner_expiry=0, partial_request_bytes=0, partial_reply_bytes=0),
        line('QUIC FIXTURE SEND', case='Q20', ordinal=1, at_ms=2020, bytes=1200, peer_ip='10.0.2.2', peer_port=4443),
        line('QUIC FIXTURE SUPPRESSED_REPLY', case='Q20', at_ms=2021, opcode=1, status=0, framed_bytes=14)])
    digest = hashlib.sha256(INITIAL).hexdigest()
    fixture = dict(case='Q20', readiness_profile='q20-unknown-send-development', mode='unknown-send',
                   canonical_campaign_acceptance=False, authenticated=False, request_bytes=0,
                   echo_enqueued_bytes=0, request_fin=False, echo_fin_enqueued=False,
                   certificate_selection=None, completion_policy='q20-one-initial-sink-v1', engine_constructed=False,
                   errors=[], thread_alive=False, rx_datagrams=1, rx_bytes=1200, tx_datagrams=0, tx_bytes=0,
                   events=[dict(event='udp-receive', bytes=1200, sha256=digest, source=['10.0.2.15',7819]),
                           dict(event='initial-observed', bytes=1200, sha256=digest,
                                receive_ordinal=1, quic_version=1, engine_delivered=False),
                           dict(event='q20-initial-sink', bytes=1200, sha256=digest,
                                policy='q20-one-initial-sink-v1', engine_constructed=False, response_datagrams=0)])
    return output, fixture, observe([HEADER + INITIAL])


def check(output, fixture, wire):
    return MATRIX.verify_native(Q20, output, fixture, wire, MANIFEST)


def sink():
    value = object.__new__(PEER.Peer)
    value.case, value.connection, value.initial_sha256 = Q20, None, None
    value.rx_packets, value.events, value.lock = 1, [], threading.Lock()
    return value


class UnknownCompletionControls(unittest.TestCase):
    def test_profile_and_actual_linux_q01_prerequisite(self):
        self.assertEqual(MATRIX.development_profile(Q20), 'q20-unknown-send-development')
        self.assertEqual(PEER.development_profile(Q20), 'q20-unknown-send-development')
        self.assertEqual(MATRIX.peer_control_cases(Q20), ['Q01'])
        self.assertEqual(MATRIX.peer_control_cases(OLD.CASE), ['Q01'])
        cases = {case['id']:case for case in MANIFEST['native_occurrences']}
        self.assertEqual(MATRIX.select_development_cases(cases, 'q20-unknown-send-development', 'ipv4', True, None), (['Q01'], ['Q01'], 'q01-development'))
        self.assertEqual(MATRIX.select_development_cases(cases, 'q20-unknown-send-development', 'ipv4', False, None), (['Q20'], ['Q01'], 'q20-unknown-send-development'))
        for module in (MATRIX, PEER):
            with self.assertRaises(RuntimeError): module.development_profile(dict(Q20, peer_mode='echo'))
            with self.assertRaises(RuntimeError): module.development_profile(dict(Q20, local_port=7818))
            with self.assertRaises(RuntimeError): module.development_profile(Q20, family='ipv6')

    def test_linux_cannot_claim_native_completion_loss(self):
        with self.assertRaisesRegex(RuntimeError, 'native IPC'):
            PEER.linux_control(Q20, {}, timeout=1)

    def test_one_initial_sink_and_a_second_receipt_refuses(self):
        peer = sink()
        self.assertTrue(peer.accept_unknown_initial(INITIAL))
        self.assertIsNone(peer.connection)
        self.assertEqual([e['event'] for e in peer.events], ['initial-observed', 'q20-initial-sink'])
        peer.rx_packets += 1
        with self.assertRaises(RuntimeError): peer.accept_unknown_initial(INITIAL)

    def test_sink_refuses_other_version_shape_or_engine(self):
        for data in (INITIAL[:-1], b'\x40' + INITIAL[1:], INITIAL[:4] + b'\2' + INITIAL[5:]):
            with self.subTest(data=data[:5]), self.assertRaises(RuntimeError): sink().accept_unknown_initial(data)
        peer = sink(); peer.connection = object()
        with self.assertRaises(RuntimeError): peer.accept_unknown_initial(INITIAL)

    def test_literal_one_direction_wire_calibrates(self):
        wire = observe([OLD.ARP_BROADCAST, HEADER + INITIAL])
        self.assertEqual((wire['frame_count'], wire['guest_udp_count'], len(wire['peer_udp'])), (2,1,0))
        self.assertEqual(wire['guest_udp'][0]['sha256'], hashlib.sha256(INITIAL).hexdigest())

    def test_wire_refuses_retry_empty_wrong_port_or_bad_checksum(self):
        for frames in ([], [OLD.ARP_BROADCAST], [HEADER+INITIAL, HEADER+INITIAL], [OLD.GUEST],
                       [HEADER + INITIAL[:-1] + b'\1']):
            with self.subTest(frames=len(frames)), self.assertRaises(WIRE.Refusal): observe(frames)

    def test_positive_effect_is_compatible_with_zero_child_acknowledgements(self):
        result = check(*proof())
        self.assertEqual(result['actual_outcome'], 'Native')
        self.assertEqual(result['typed_report']['send_accepted'], '0')

    def test_missing_or_repeated_effect_refuses(self):
        for count in (0,2):
            output, fixture, wire = proof()
            wire['guest_udp'] *= count
            with self.assertRaises(RuntimeError): check(output, fixture, wire)

    def test_only_a_complete_successful_send_reply_establishes_loss(self):
        for before, after in [('opcode=1','opcode=2'), ('status=0 framed_bytes=14','status=4 framed_bytes=14'),
                              ('framed_bytes=14','framed_bytes=13')]:
            output, fixture, wire = proof()
            with self.subTest(before=before), self.assertRaises(RuntimeError):
                check(output.replace(before,after), fixture, wire)
        output, fixture, wire = proof()
        output = '\n'.join(s for s in output.splitlines() if not s.startswith('QUIC FIXTURE SUPPRESSED_REPLY'))
        with self.assertRaises(RuntimeError): check(output, fixture, wire)

    def test_retry_acceptance_exhaustion_or_extra_service_operation_refuses(self):
        for before, after in [('send_calls=1','send_calls=2'), ('send_accepted=0','send_accepted=1'),
                              ('exhausted=0','exhausted=1'), ('send_bytes=0','send_bytes=1200'),
                              ('send_requests=1','send_requests=2'), ('close_calls=0','close_calls=1'),
                              ('partial_request_bytes=0','partial_request_bytes=1'),
                              ('sends_after_fence=0','sends_after_fence=1')]:
            output, fixture, wire = proof()
            with self.subTest(before=before), self.assertRaises(RuntimeError):
                check(output.replace(before,after), fixture, wire)

    def test_wrong_typed_failure_or_application_claim_refuses(self):
        for before, after in [('native_failure_kind=Unknown','native_failure_kind=Native'),
                              ('native_error_detail=-110','native_error_detail=-5'),
                              ('unknown_send=true','unknown_send=false'), ('pipe_fenced=true','pipe_fenced=false'),
                              ('authenticated=false','authenticated=true'), ('sent_stream=0','sent_stream=1')]:
            output, fixture, wire = proof()
            with self.subTest(before=before), self.assertRaises(RuntimeError):
                check(output.replace(before,after), fixture, wire)

    def test_reordered_suppression_or_extended_deadline_refuses(self):
        for before, after in [('at_ms=2021 opcode=1','at_ms=2271 opcode=1'),
                              ('at_ms=2020 bytes=1200','at_ms=2018 bytes=1200'),
                              ('deadline_ms=12010','deadline_ms=12011')]:
            output, fixture, wire = proof()
            with self.subTest(before=before), self.assertRaises(RuntimeError):
                check(output.replace(before,after), fixture, wire)

    def test_peer_engine_reply_application_or_changed_effect_refuses(self):
        for change in ('engine', 'response', 'application', 'hash', 'tuple', 'reordered'):
            output, fixture, wire = proof()
            if change == 'engine': fixture['engine_constructed'] = True
            elif change == 'response': wire['peer_udp'] = [copy.deepcopy(wire['guest_udp'][0])]
            elif change == 'application': fixture['request_bytes'] = 1
            elif change == 'hash': fixture['events'][0]['sha256'] = 'e'*64
            elif change == 'tuple': wire['guest_udp'][0]['source'][1] = 7818
            else: fixture['events'][0], fixture['events'][1] = fixture['events'][1], fixture['events'][0]
            with self.subTest(change=change), self.assertRaises(RuntimeError): check(output, fixture, wire)

    def test_no_certificate_was_selected_for_the_sink(self):
        _, fixture, _ = proof()
        MATRIX.verify_certificate_selection(Q20, fixture, {})
        fixture['certificate_selection'] = {'kind':'valid'}
        with self.assertRaises(RuntimeError): MATRIX.verify_certificate_selection(Q20, fixture, {})

    def test_child_failure_and_resource_difference_refuse(self):
        for before, after in [('status=0 killed=false','status=1 killed=false'), ('handles_after=1','handles_after=2')]:
            output, fixture, wire = proof()
            with self.subTest(before=before), self.assertRaises(RuntimeError):
                check(output.replace(before,after), fixture, wire)

    def test_pregrant_settling_is_required_bounded_and_continuous(self):
        output, fixture, wire = proof()
        without_setup = '\n'.join(s for s in output.splitlines() if not s.startswith('QUIC Q20 RX SETUP '))
        with self.assertRaisesRegex(RuntimeError, 'pre-grant NIC settling'): check(without_setup, fixture, wire)
        for before, after in [('delta_ms=1100','delta_ms=1099'),
                              ('continuous_vm_required=1','continuous_vm_required=0'),
                              ('ready_ms=1630 delta_ms=1100','ready_ms=529 delta_ms=1100'),
                              ('ready_ms=1630 delta_ms=1100','ready_ms=2130 delta_ms=1600'),
                              ('ready_ms=1630 delta_ms=1100','ready_ms=3530 delta_ms=3000')]:
            with self.subTest(before=before), self.assertRaisesRegex(RuntimeError, 'pre-grant NIC settling'):
                check(output.replace(before,after), fixture, wire)


if __name__ == '__main__':
    unittest.main()
