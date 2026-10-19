#!/usr/bin/env python3
"""Focused Q01 evidence controls, to run only on the execution host.

Literal Ethernet vectors and synthetic result records test refusals. They are
not network traffic, native qualification or evidence of protocol behavior.
"""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import struct
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
WIRE = load('quic_wire_controls', ROOT / 'scripts/native-quic-wire.py')
MATRIX = load('quic_matrix_controls', ROOT / 'scripts/native-quic-q01.py')
PEER_MODULE = load('quic_peer_controls', ROOT / 'scripts/native-quic-q01-peer.py')
CASE = json.loads((ROOT / 'quic/CASES.json').read_text())['native_occurrences'][0]
MANIFEST = json.loads((ROOT / 'quic/CASES.json').read_text())
GUEST = bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e78115b0011e125717569632d77697265000000000000000000')
PEER = bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e780011e125717569632d77697265000000000000000000')
WRONG_PORT = bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e79115b0011e124717569632d77697265000000000000000000')
ARP = bytes.fromhex('ffffffffffff525400123456080600010800060400015254001234560a00020f0000000000000a000202000000000000000000000000000000000000')
# Literal first ARP frame from the failed native 632 occurrence; RFC 826 permits
# this broadcast request target. Its failure remains recorded independently.
ARP_BROADCAST = bytes.fromhex('ffffffffffff525400123456080600010800060400015254001234560a00020fffffffffffff0a000202000000000000000000000000000000000000')

def pcap(frames):
    return struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + b''.join(
        struct.pack('<IIII', index, 0, len(frame), len(frame)) + frame
        for index, frame in enumerate(frames, 1))

def observe(raw):
    return WIRE.observe(raw, CASE, '52:54:00:12:34:56', '02:71:00:00:00:02')

class WireControls(unittest.TestCase):
    def test_broadcast_request_target_calibrates(self):
        result = observe(pcap([ARP_BROADCAST, GUEST, PEER]))
        self.assertEqual((result['frame_count'], result['arp_count'], result['udp_count']), (3, 1, 2))
    def test_broadcast_target_with_unicast_request_refuses(self):
        changed = bytearray(ARP_BROADCAST); changed[:6] = bytes.fromhex('027100000002')
        with self.assertRaises(WIRE.Refusal): observe(pcap([bytes(changed), GUEST, PEER]))
    def test_broadcast_target_reply_refuses(self):
        changed = bytearray(ARP_BROADCAST); changed[:6] = bytes.fromhex('027100000002'); changed[20:22] = b'\0\2'
        with self.assertRaises(WIRE.Refusal): observe(pcap([bytes(changed), GUEST, PEER]))
    def test_arp_reply_with_broadcast_destination_refuses(self):
        changed = bytearray(ARP_BROADCAST); changed[20:22] = b'\0\2'; changed[32:38] = bytes.fromhex('027100000002')
        with self.assertRaises(WIRE.Refusal): observe(pcap([bytes(changed), GUEST, PEER]))
    def test_arp_target_ip_change_refuses(self):
        changed = bytearray(ARP_BROADCAST); changed[41] ^= 1
        with self.assertRaises(WIRE.Refusal): observe(pcap([bytes(changed), GUEST, PEER]))
    def test_complete_census_with_odd_udp_and_arp(self):
        result = observe(pcap([ARP, GUEST, PEER]))
        self.assertEqual((result['frame_count'], result['arp_count'], result['udp_count']), (3, 1, 2))
        self.assertTrue(all(row['ip_checksum_valid'] and row['udp_checksum_valid']
                            for row in result['guest_udp'] + result['peer_udp']))
    def test_qemu_65536_snaplen_is_valid(self):
        raw = bytearray(pcap([GUEST, PEER])); raw[16:20] = struct.pack('<I', 65536)
        self.assertEqual(observe(bytes(raw))['udp_count'], 2)
    def test_data_checksum_change_refuses(self):
        changed = bytearray(GUEST); changed[42] ^= 1
        with self.assertRaises(WIRE.Refusal): observe(pcap([bytes(changed), PEER]))
    def test_ipv4_header_checksum_change_refuses(self):
        changed = bytearray(GUEST); changed[22] ^= 1
        with self.assertRaises(WIRE.Refusal): observe(pcap([bytes(changed), PEER]))
    def test_absent_udp_checksum_refuses(self):
        changed = bytearray(GUEST); changed[40:42] = b'\0\0'
        with self.assertRaises(WIRE.Refusal): observe(pcap([bytes(changed), PEER]))
    def test_valid_checksums_wrong_port_refuses(self):
        with self.assertRaises(WIRE.Refusal): observe(pcap([WRONG_PORT, PEER]))
    def test_third_mac_refuses(self):
        changed = bytearray(GUEST); changed[6] = 4
        with self.assertRaises(WIRE.Refusal): observe(pcap([bytes(changed), PEER]))
    def test_additional_non_ipv4_frame_refuses(self):
        extra = bytearray(GUEST); extra[12:14] = b'\x86\xdd'
        with self.assertRaises(WIRE.Refusal): observe(pcap([GUEST, PEER, bytes(extra)]))
    def test_arp_identity_change_refuses(self):
        changed = bytearray(ARP); changed[22] ^= 2
        with self.assertRaises(WIRE.Refusal): observe(pcap([bytes(changed), GUEST, PEER]))
    def test_truncated_capture_refuses(self):
        with self.assertRaises(WIRE.Refusal): observe(pcap([GUEST, PEER])[:-1])
    def test_missing_peer_direction_refuses(self):
        with self.assertRaises(WIRE.Refusal): observe(pcap([GUEST]))

def proof():
    digest = hashlib.sha256(bytes(97 + i % 26 for i in range(4096))).hexdigest()
    report = {field:'0' for field in MANIFEST['report']['fields']}
    report.update(case='Q01', outcome='Complete', authenticated='true', sent_stream='4096', received_stream='4096',
        request_fin='true', peer_fin='true', request_acked='true', connection_drained='true', close_accepted='true',
        pipe_fenced='true', unknown_send='false', native_failure_kind='none', native_error_code='none',
        native_error_detail='none', transport_error_code='none', transport_close_origin='none',
        entropy_attempts='1', engine_transmits='1', send_calls='1', send_accepted='1', send_bytes='1200', received='1', receive_bytes='1200',
        last_send_ms='20', fence_ms='100', start_ms='10', end_ms='101', deadline_ms='10010', grant_expiry_ms='15001')
    def line(prefix, **fields): return prefix + ' ' + ' '.join(key+'='+str(value) for key,value in fields.items())
    output = '\n'.join([
        line('QUIC SERVICE SELECTOR', case='Q01', local_port=7800),
        line('QUIC SERVICE DONE', case='Q01', sockets=0, **{n+'_'+when:1 for n in ('processes','handles','pipes','cells') for when in ('before','after')}),
        line('QUIC SERVICE GRANT', case='Q01', before_ms=1, constructed_ms=2, owner_expiry_ms=15001, local_port=7800, peer_port=4443),
        line('QUIC CPU', vendor='GenuineIntel', leaf1_eax=0x306c0, leaf1_ecx=1<<30, family=6, model=60, rdrand=1),
        line('QUIC RESULT', **report),
        line('QUIC BEGIN', case='Q01', start_ms=10, deadline_ms=10010, grant_expiry_ms=15001),
        line('QUIC CHILD EXIT', case='Q01', kind=1, status=0, killed='false'),
        line('QUIC FIXTURE NATIVE_COUNTS', case='Q01', send_requests=1, receive_delivered=1, sends_after_owner_expiry=0, partial_request_bytes=0, partial_reply_bytes=0),
        line('QUIC FIXTURE SEND', case='Q01', ordinal=1, at_ms=21, bytes=1200, peer_ip='10.0.2.2', peer_port=4443),
        line('QUIC FIXTURE RX', case='Q01', ordinal=1, at_ms=50, bytes=1200, peer_ip='10.0.2.2', peer_port=4443, sha256='b'*64)])
    fixture = dict(readiness_profile='q01-development', canonical_campaign_acceptance=False, authenticated=True, request_bytes=4096, echo_enqueued_bytes=4096, request_sha256=digest,
        request_fin=True, echo_fin_enqueued=True, errors=[], thread_alive=False, rx_datagrams=1, tx_datagrams=1,
        rx_bytes=1200, tx_bytes=1200, events=[
            dict(event='initial-observed', sha256='a'*64),
            dict(event='udp-receive', bytes=1200),
            dict(event='udp-send', bytes=1200, sha256='b'*64, source=['10.0.2.2',4443], destination=['10.0.2.15',7800])])
    wire = dict(guest_udp=[dict(sha256='a'*64, bytes=1200)],
        peer_udp=[dict(sha256='b'*64, bytes=1200, source=['10.0.2.2',4443], destination=['10.0.2.15',7800])])
    return output, fixture, wire

class ResultControls(unittest.TestCase):
    def check(self, output, fixture, wire): return MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)
    def test_positive_exact_correspondence(self): self.check(*proof())
    def test_missing_fin_refuses_even_with_cleanup(self):
        output, fixture, wire = proof(); output = output.replace('peer_fin=true', 'peer_fin=false')
        with self.assertRaises(RuntimeError): self.check(output, fixture, wire)
    def test_resource_difference_refuses(self):
        output, fixture, wire = proof(); output = output.replace('handles_after=1', 'handles_after=2')
        with self.assertRaises(RuntimeError): self.check(output, fixture, wire)
    def test_extended_deadline_refuses(self):
        output, fixture, wire = proof(); output = output.replace('deadline_ms=10010', 'deadline_ms=10011')
        with self.assertRaises(RuntimeError): self.check(output, fixture, wire)
    def test_native_rx_without_capture_refuses(self):
        output, fixture, wire = proof(); wire['peer_udp'][0]['sha256'] = 'c'*64
        with self.assertRaises(RuntimeError): self.check(output, fixture, wire)
    def test_peer_enqueue_without_exact_body_refuses(self):
        output, fixture, wire = proof(); fixture['request_sha256'] = 'c'*64
        with self.assertRaises(RuntimeError): self.check(output, fixture, wire)
    def test_incomplete_native_ledger_refuses(self):
        output, fixture, wire = proof(); output = output.replace('receive_delivered=1', 'receive_delivered=2')
        with self.assertRaises(RuntimeError): self.check(output, fixture, wire)
    def test_abnormal_child_refuses(self):
        output, fixture, wire = proof(); output = output.replace('status=0 killed=false', 'status=1 killed=false')
        with self.assertRaises(RuntimeError): self.check(output, fixture, wire)
    def test_peer_error_close_refuses_even_after_echo(self):
        output, fixture, wire = proof(); fixture['terminated'] = {'error_code':1}
        with self.assertRaises(RuntimeError): self.check(output, fixture, wire)

class LinuxOutcomeControls(unittest.TestCase):
    def test_complete_body_fin_without_terminal_calibrates(self):
        self.assertEqual(PEER_MODULE.linux_outcome(True, True, 4096, None), 'Complete')
    def test_complete_body_fin_with_nonzero_terminal_refuses(self):
        terminal = {'error_code':1, 'frame_type':0, 'reason_phrase':'nonzero termination'}
        self.assertEqual(PEER_MODULE.linux_outcome(True, True, 4096, terminal), 'Protocol')
    def test_complete_body_fin_with_idle_timeout_stays_deadline(self):
        terminal = {'error_code':1, 'frame_type':0, 'reason_phrase':'Idle timeout'}
        self.assertEqual(PEER_MODULE.linux_outcome(True, True, 4096, terminal), 'Deadline')

Q08 = next(case for case in MANIFEST['native_occurrences'] if case['id'] == 'Q08')
# Literal odd-length UDP vectors with source/destination port7807. Increasing
# the Q01 port by7 reduces the transmitted one's-complement checksum by7.
GUEST_Q08 = bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e7f115b0011e11e717569632d77697265000000000000000000')
PEER_Q08 = bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e7f0011e11e717569632d77697265000000000000000000')


class WrongRootWireControls(unittest.TestCase):
    def observe(self, case, frames):
        return WIRE.observe(pcap(frames), case, '52:54:00:12:34:56', '02:71:00:00:00:02')
    def test_literal_q08_port7807_calibrates(self):
        value = self.observe(Q08, [ARP_BROADCAST, GUEST_Q08, PEER_Q08])
        self.assertEqual((value['frame_count'], value['arp_count'], value['udp_count']), (3, 1, 2))
        self.assertEqual(value['guest_udp'][0]['source'], ['10.0.2.15', 7807])
        self.assertEqual(value['peer_udp'][0]['destination'], ['10.0.2.15', 7807])
        self.assertTrue(all(row['ip_checksum_valid'] and row['udp_checksum_valid']
                            for row in value['guest_udp'] + value['peer_udp']))
    def test_wrong_case_profile_refuses(self):
        with self.assertRaises(WIRE.Refusal):
            self.observe(dict(Q08, id='Q09'), [GUEST_Q08, PEER_Q08])
    def test_wrong_mode_refuses(self):
        with self.assertRaises(WIRE.Refusal):
            self.observe(dict(Q08, peer_mode='echo'), [GUEST_Q08, PEER_Q08])
    def test_wrong_declared_port_refuses(self):
        with self.assertRaises(WIRE.Refusal):
            self.observe(dict(Q08, local_port=7800), [GUEST_Q08, PEER_Q08])
    def test_q01_wire_port_cannot_qualify_q08(self):
        with self.assertRaises(WIRE.Refusal): self.observe(Q08, [GUEST, PEER])


def wrong_root_proof():
    output, fixture, wire = proof()
    output = output.replace('Q01', 'Q08').replace('local_port=7800', 'local_port=7807')
    output = output.replace('outcome=Complete', 'outcome=Protocol').replace('transport_error_code=none', 'transport_error_code=304')
    output = output.replace('transport_close_origin=none', 'transport_close_origin=local')
    for field in ('authenticated', 'request_fin', 'peer_fin', 'request_acked', 'connection_drained', 'close_accepted'):
        output = output.replace(field+'=true', field+'=false')
    output = output.replace('sent_stream=4096', 'sent_stream=0').replace('received_stream=4096', 'received_stream=0')
    fixture.update(readiness_profile='q08-wrong-root-development', authenticated=False, request_bytes=0,
        echo_enqueued_bytes=0, request_fin=False, echo_fin_enqueued=False, terminated={'error_code':304},
        certificate_selection={'kind':'untrusted', 'sha256':'d'*64, 'client_root_sha256':'e'*64})
    fixture['events'][-1]['destination'][1] = 7807
    wire['peer_udp'][0]['destination'][1] = 7807
    fixture.update(mode='wrong-root', peer_policy='q08-one-response-flight-v1', response_flight_sealed=True)
    initial, received, sent = fixture['events']
    received.update(sha256=initial['sha256'])
    initial.update(bytes=1200)
    fixture['events'] = [received, initial,
        dict(event='q08-response-flight', policy='q08-one-response-flight-v1',
             initial_sha256=initial['sha256'], datagrams=[{key:sent[key] for key in ('bytes','sha256','destination')}]),
        sent, dict(event='q08-response-flight-fenced', policy='q08-one-response-flight-v1',
                   tx_datagrams=1, tx_bytes=1200, later_engine_work=False, later_send=False)]
    return output, fixture, wire


class WrongRootControls(unittest.TestCase):
    def test_certificate_selection_event_preserves_kind(self):
        peer = object.__new__(PEER_MODULE.Peer)
        peer.lock, peer.events = threading.Lock(), []
        selection = {'kind':'untrusted', 'sha256':'d'*64, 'client_root_sha256':'e'*64}
        peer.event('certificate-selection', **selection)
        self.assertEqual(len(peer.events), 1)
        record = json.loads(json.dumps(peer.events[0]))
        self.assertEqual(record['event'], 'certificate-selection')
        self.assertTrue(all(record[key] == value for key, value in selection.items()))
    def native(self, output, fixture, wire):
        return MATRIX.verify_native(Q08, output, fixture, wire, MANIFEST)
    def linux(self):
        _, fixture, _ = wrong_root_proof()
        fixture['terminated']['error_code'] = 298
        observed = dict(actual_outcome='Protocol', authenticated=False, received_bytes=0,
            peer_fin=False, terminal={'error_code':298, 'frame_type':6, 'reason_phrase':'chain refusal'}, fixture=fixture)
        pki = dict(leaf_certificates={'untrusted':{'sha256':'d'*64}}, root_der={'sha256':'e'*64})
        return observed, pki
    def test_native_wrong_root_calibrates(self): self.native(*wrong_root_proof())
    def test_native_unrelated_protocol_error_refuses(self):
        output, fixture, wire = wrong_root_proof(); output = output.replace('transport_error_code=304', 'transport_error_code=298')
        with self.assertRaises(RuntimeError): self.native(output, fixture, wire)
    def test_native_application_receipt_refuses(self):
        output, fixture, wire = wrong_root_proof(); output = output.replace('received_stream=0', 'received_stream=1')
        with self.assertRaises(RuntimeError): self.native(output, fixture, wire)
    def test_native_send_after_fence_refuses(self):
        output, fixture, wire = wrong_root_proof(); output = output.replace('sends_after_fence=0', 'sends_after_fence=1')
        with self.assertRaises(RuntimeError): self.native(output, fixture, wire)
    def test_native_unestablished_peer_certificate_refuses(self):
        output, fixture, wire = wrong_root_proof(); fixture['certificate_selection']['kind'] = 'valid'
        with self.assertRaises(RuntimeError): self.native(output, fixture, wire)
    def test_linux_wrong_root_calibrates(self):
        observed, pki = self.linux(); MATRIX.verify_linux_wrong_root(Q08, observed, pki)
    def test_linux_timeout_is_not_root_refusal(self):
        observed, pki = self.linux(); observed['terminal']['error_code'] = 1
        with self.assertRaises(RuntimeError): MATRIX.verify_linux_wrong_root(Q08, observed, pki)
    def test_linux_authenticated_state_refuses(self):
        observed, pki = self.linux(); observed['authenticated'] = True
        with self.assertRaises(RuntimeError): MATRIX.verify_linux_wrong_root(Q08, observed, pki)
    def test_linux_wrong_certificate_bytes_refuse(self):
        observed, pki = self.linux(); observed['fixture']['certificate_selection']['sha256'] = 'f'*64
        with self.assertRaises(RuntimeError): MATRIX.verify_linux_wrong_root(Q08, observed, pki)
    def test_profile_and_peer_certificate_selection(self):
        self.assertEqual(PEER_MODULE.peer_certificate(Q08), 'untrusted')
        self.assertEqual(PEER_MODULE.peer_certificate(CASE), 'valid')
        changed = dict(Q08, peer_mode='echo')
        with self.assertRaises(RuntimeError): PEER_MODULE.development_profile(changed)
    def test_parent_selector_and_child_calibrate(self):
        selectors = {'ABSD_QUIC_CASE':'Q08', 'ABSD_QUIC_UNIX_SECONDS':'1792227748'}
        MATRIX.verify_parent_build({'service_selectors':selectors, 'reused_client_sha256':'a'*64}, selectors, 'a'*64)
    def test_default_q01_parent_cannot_qualify_q08(self):
        selectors = {'ABSD_QUIC_CASE':'Q08', 'ABSD_QUIC_UNIX_SECONDS':'1792227748'}
        built = dict(service_selectors=dict(selectors, ABSD_QUIC_CASE='Q01'), reused_client_sha256='a'*64)
        with self.assertRaises(RuntimeError): MATRIX.verify_parent_build(built, selectors, 'a'*64)


AUTH_EXPECTED = {
    'Q09': ('q09-wrong-name-development', 'wrong-name', ['absd-echo/1'], 298),
    'Q10': ('q10-expired-development', 'expired', ['absd-echo/1'], 301),
    'Q11': ('q11-wrong-alpn-development', 'valid', ['other-echo/1'], 376),
}
AUTH_VECTORS = {
    'Q09': (
        bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e80115b0011e11d717569632d77697265000000000000000000'),
        bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e800011e11d717569632d77697265000000000000000000')),
    'Q10': (
        bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e81115b0011e11c717569632d77697265000000000000000000'),
        bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e810011e11c717569632d77697265000000000000000000')),
    'Q11': (
        bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e82115b0011e11b717569632d77697265000000000000000000'),
        bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e820011e11b717569632d77697265000000000000000000')),
}
AUTH_CASES = [case for case in MANIFEST['native_occurrences'] if case['id'] in AUTH_EXPECTED]


def auth_proof(case):
    output, fixture, wire = wrong_root_proof()
    profile, leaf, alpn, code = AUTH_EXPECTED[case['id']]
    output = output.replace('Q08', case['id']).replace('local_port=7807', 'local_port='+str(case['local_port']))
    output = output.replace('transport_error_code=304', 'transport_error_code='+str(code))
    if case['id'] == 'Q11':
        output = output.replace('transport_close_origin=local', 'transport_close_origin=peer')
    fixture.update(readiness_profile=profile, mode=case['peer_mode'], terminated={'error_code':code},
                   peer_policy='auth-one-response-flight-v1')
    for event in fixture['events']:
        if event['event'].startswith('q08-response-flight'):
            event['event'] = event['event'].replace('q08-', 'auth-', 1)
            event['policy'] = 'auth-one-response-flight-v1'
    fixture['certificate_selection'].update(kind=leaf, configured_alpn=alpn)
    sent, = (event for event in fixture['events'] if event['event'] == 'udp-send')
    sent['destination'][1] = case['local_port']
    planned, = (event for event in fixture['events'] if event['event'] == 'auth-response-flight')
    planned['datagrams'] = [{key:sent[key] for key in ('bytes','sha256','destination')}]
    wire['peer_udp'][0]['destination'][1] = case['local_port']
    return output, fixture, wire


class AuthProfileControls(unittest.TestCase):
    def linux(self, case):
        _, fixture, _ = auth_proof(case)
        _, leaf, _, code = AUTH_EXPECTED[case['id']]
        observed = dict(actual_outcome='Protocol', authenticated=False, received_bytes=0,
            peer_fin=False, terminal={'error_code':code, 'frame_type':6, 'reason_phrase':'selected refusal'}, fixture=fixture)
        pki = dict(leaf_certificates={leaf:{'sha256':'d'*64}}, root_der={'sha256':'e'*64})
        return observed, pki
    def test_each_actual_peer_runner_and_wire_selection_calibrates(self):
        self.assertEqual([case['id'] for case in AUTH_CASES], ['Q09', 'Q10', 'Q11'])
        for case in AUTH_CASES:
            with self.subTest(case=case['id']):
                profile, leaf, alpn, _ = AUTH_EXPECTED[case['id']]
                self.assertEqual(case['transport_error_codes'], [AUTH_EXPECTED[case['id']][3]])
                self.assertEqual(PEER_MODULE.development_profile(case), profile)
                self.assertEqual(MATRIX.development_profile(case), profile)
                self.assertEqual(PEER_MODULE.peer_certificate(case), leaf)
                self.assertEqual(PEER_MODULE.peer_alpn(case), alpn)
                wire = WIRE.observe(pcap([ARP_BROADCAST, *AUTH_VECTORS[case['id']]]),
                    case, '52:54:00:12:34:56', '02:71:00:00:00:02')
                self.assertEqual(wire['guest_udp'][0]['source'][1], case['local_port'])
                self.assertEqual(wire['peer_udp'][0]['destination'][1], case['local_port'])
                self.assertEqual((wire['frame_count'], wire['arp_count'], wire['udp_count']), (3, 1, 2))
    def test_each_wrong_mode_refuses_all_three_selectors(self):
        for case in AUTH_CASES:
            with self.subTest(case=case['id']):
                changed = dict(case, peer_mode='echo')
                with self.assertRaises(RuntimeError): PEER_MODULE.development_profile(changed)
                with self.assertRaises(RuntimeError): MATRIX.development_profile(changed)
                with self.assertRaises(WIRE.Refusal):
                    WIRE.observe(pcap(AUTH_VECTORS[case['id']]), changed, '52:54:00:12:34:56', '02:71:00:00:00:02')
    def test_each_wrong_declared_port_refuses_wire(self):
        for case in AUTH_CASES:
            with self.subTest(case=case['id']), self.assertRaises(WIRE.Refusal):
                WIRE.observe(pcap(AUTH_VECTORS[case['id']]), dict(case, local_port=7800),
                    '52:54:00:12:34:56', '02:71:00:00:00:02')
    def test_each_native_auth_refusal_calibrates(self):
        for case in AUTH_CASES:
            with self.subTest(case=case['id']): MATRIX.verify_native(case, *auth_proof(case), MANIFEST)
    def test_each_native_unrelated_error_refuses(self):
        for case in AUTH_CASES:
            output, fixture, wire = auth_proof(case)
            output = output.replace('transport_error_code='+str(AUTH_EXPECTED[case['id']][3]), 'transport_error_code=1')
            with self.subTest(case=case['id']), self.assertRaises(RuntimeError):
                MATRIX.verify_native(case, output, fixture, wire, MANIFEST)
    def test_each_linux_auth_refusal_calibrates(self):
        for case in AUTH_CASES:
            observed, pki = self.linux(case)
            with self.subTest(case=case['id']): MATRIX.verify_linux_auth_refusal(case, observed, pki)
    def test_each_linux_unrelated_error_refuses(self):
        for case in AUTH_CASES:
            observed, pki = self.linux(case); observed['terminal']['error_code'] = 1
            with self.subTest(case=case['id']), self.assertRaises(RuntimeError):
                MATRIX.verify_linux_auth_refusal(case, observed, pki)
    def test_each_application_byte_after_refusal_refuses(self):
        for case in AUTH_CASES:
            output, fixture, wire = auth_proof(case); output = output.replace('received_stream=0', 'received_stream=1')
            with self.subTest(case=case['id']), self.assertRaises(RuntimeError):
                MATRIX.verify_native(case, output, fixture, wire, MANIFEST)
    def test_valid_alpn_cannot_qualify_q11_mismatch(self):
        case = next(case for case in AUTH_CASES if case['id'] == 'Q11')
        output, fixture, wire = auth_proof(case)
        fixture['certificate_selection']['configured_alpn'] = ['absd-echo/1']
        with self.assertRaises(RuntimeError): MATRIX.verify_native(case, output, fixture, wire, MANIFEST)


Q03 = next(case for case in MANIFEST['native_occurrences'] if case['id'] == 'Q03')
Q03_GUEST = bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e7a115b0011e123717569632d77697265000000000000000000')
Q03_PEER = bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e7a0011e123717569632d77697265000000000000000000')


def initial_loss_proof():
    output, fixture, wire = proof()
    output = output.replace('Q01', 'Q03').replace('local_port=7800', 'local_port=7802')
    for field in ('engine_transmits', 'send_calls', 'send_accepted', 'send_requests'):
        output = output.replace(field+'=1', field+'=2')
    output = output.replace('send_bytes=1200', 'send_bytes=2400')
    output += '\nQUIC FIXTURE SEND case=Q03 ordinal=2 at_ms=22 bytes=1200 peer_ip=10.0.2.2 peer_port=4443'
    fixture.update(readiness_profile='q03-initial-loss-development', initial_drops=1,
                   rx_datagrams=2, rx_bytes=2400)
    fixture['events'] = [
        dict(event='udp-receive', bytes=1200, sha256='a'*64),
        dict(event='initial-drop', bytes=1200, sha256='a'*64, receive_ordinal=1, engine_delivered=False),
        dict(event='udp-receive', bytes=1200, sha256='c'*64),
        dict(event='initial-observed', bytes=1200, sha256='c'*64, receive_ordinal=2),
        dict(event='udp-send', bytes=1200, sha256='b'*64, source=['10.0.2.2',4443], destination=['10.0.2.15',7802])]
    wire.update(guest_udp_count=2, guest_udp=[
        dict(sha256='a'*64, bytes=1200, ordinal=1, first_byte=0xc0),
        dict(sha256='c'*64, bytes=1200, ordinal=2, first_byte=0xc0)])
    wire['peer_udp'][0]['destination'][1] = 7802
    return output, fixture, wire


class InitialLossControls(unittest.TestCase):
    def peer(self, mode='initial-loss'):
        peer = PEER_MODULE.Peer.__new__(PEER_MODULE.Peer)
        peer.mode = mode; peer.initial_drops = 0; peer.connection = None
        peer.rx_packets = 1; peer.events = []; peer.lock = threading.Lock()
        return peer
    def test_joint_actual_selectors_and_literal_port7802_calibrate(self):
        self.assertEqual(PEER_MODULE.development_profile(Q03), 'q03-initial-loss-development')
        self.assertEqual(MATRIX.development_profile(Q03), 'q03-initial-loss-development')
        self.assertEqual(PEER_MODULE.peer_certificate(Q03), 'valid')
        self.assertEqual(PEER_MODULE.peer_alpn(Q03), ['absd-echo/1'])
        wire = WIRE.observe(pcap([ARP_BROADCAST, Q03_GUEST, Q03_PEER]), Q03,
                            '52:54:00:12:34:56', '02:71:00:00:00:02')
        self.assertEqual(wire['guest_udp'][0]['source'][1], 7802)
        self.assertEqual(wire['peer_udp'][0]['destination'][1], 7802)
    def test_wrong_mode_refuses_three_selectors(self):
        changed = dict(Q03, peer_mode='echo')
        with self.assertRaises(RuntimeError): PEER_MODULE.development_profile(changed)
        with self.assertRaises(RuntimeError): MATRIX.development_profile(changed)
        with self.assertRaises(WIRE.Refusal):
            WIRE.observe(pcap([Q03_GUEST, Q03_PEER]), changed, '52:54:00:12:34:56', '02:71:00:00:00:02')
    def test_wrong_port_refuses_wire(self):
        with self.assertRaises(WIRE.Refusal):
            WIRE.observe(pcap([Q03_GUEST, Q03_PEER]), dict(Q03, local_port=7800),
                         '52:54:00:12:34:56', '02:71:00:00:00:02')
    def test_actual_method_omits_once_before_engine_and_echo_mode_never_omits(self):
        # Opaque post-validation bytes; this control does not parse a QUIC packet.
        peer = self.peer(); data = b'\xc0' + bytes(1199)
        self.assertTrue(peer.drop_initial(data)); peer.rx_packets = 2
        self.assertFalse(peer.drop_initial(data))
        self.assertEqual(peer.initial_drops, 1); self.assertIsNone(peer.connection)
        event = json.loads(json.dumps(peer.events))[0]
        self.assertEqual((event['event'], event['receive_ordinal'], event['engine_delivered']), ('initial-drop', 1, False))
        self.assertEqual(event['sha256'], hashlib.sha256(data).hexdigest())
        positive = self.peer('echo')
        self.assertFalse(positive.drop_initial(data)); self.assertEqual(positive.events, [])
    def test_omission_after_engine_construction_refuses(self):
        peer = self.peer(); peer.connection = object()
        with self.assertRaises(RuntimeError): peer.drop_initial(bytes(1200))
        self.assertEqual(peer.initial_drops, 0); self.assertEqual(peer.events, [])
    def test_native_loss_recovery_proof_calibrates(self):
        MATRIX.verify_native(Q03, *initial_loss_proof(), MANIFEST)
    def test_echo_without_actual_drop_refuses(self):
        output, fixture, wire = initial_loss_proof(); fixture['initial_drops'] = 0
        with self.assertRaises(RuntimeError): MATRIX.verify_native(Q03, output, fixture, wire, MANIFEST)
    def test_drop_delivered_to_engine_cannot_qualify_loss(self):
        output, fixture, wire = initial_loss_proof(); fixture['events'][1]['engine_delivered'] = True
        with self.assertRaises(RuntimeError): MATRIX.verify_native(Q03, output, fixture, wire, MANIFEST)
    def test_accepted_initial_before_drop_refuses(self):
        output, fixture, wire = initial_loss_proof(); fixture['events'][1], fixture['events'][3] = fixture['events'][3], fixture['events'][1]
        with self.assertRaises(RuntimeError): MATRIX.verify_native(Q03, output, fixture, wire, MANIFEST)
    def test_missing_captured_retry_refuses(self):
        output, fixture, wire = initial_loss_proof(); wire['guest_udp'] = wire['guest_udp'][:1]
        with self.assertRaises(RuntimeError): MATRIX.verify_native(Q03, output, fixture, wire, MANIFEST)
    def test_socket_receipt_and_first_response_event_reordering_refuse(self):
        for moved, destination in [(0, 1), (2, 3), (4, 3)]:
            output, fixture, wire = initial_loss_proof()
            event = fixture['events'].pop(moved); fixture['events'].insert(destination, event)
            with self.subTest(moved=moved, destination=destination), self.assertRaises(RuntimeError):
                MATRIX.verify_native(Q03, output, fixture, wire, MANIFEST)
    def test_original_fifteen_second_grant_cannot_extend(self):
        output, fixture, wire = initial_loss_proof(); output = output.replace('15001', '16001')
        with self.assertRaises(RuntimeError): MATRIX.verify_native(Q03, output, fixture, wire, MANIFEST)


Q19 = next(case for case in MANIFEST['native_occurrences'] if case['id'] == 'Q19')
Q19_GUEST = bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e8a115b0011e113717569632d77697265000000000000000000')
Q19_PEER = bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e8a0011e113717569632d77697265000000000000000000')
QUEUE_BYTES = [bytes.fromhex('414253442d51554555452d3030303000'),
               bytes.fromhex('414253442d51554555452d3030303001'),
               bytes.fromhex('414253442d51554555452d3030303002'),
               bytes.fromhex('414253442d51554555452d3030303003')]


def queue_proof():
    output, fixture, wire = proof()
    output = output.replace('Q01','Q19').replace('local_port=7800','local_port=7818')
    for before, after in [('queue_fills=0','queue_fills=4'),('exhausted=0','exhausted=1'),
            ('queue_retry_accepted=0','queue_retry_accepted=1'),('send_calls=1','send_calls=6'),
            ('send_accepted=1','send_accepted=5'),('send_bytes=1200','send_bytes=1264'),
            ('send_requests=1','send_requests=6'),('pending_exhausted_sha256=0','pending_exhausted_sha256='+'a'*64),
            ('pending_retry_sha256=0','pending_retry_sha256='+'a'*64)]:
        output = output.replace(before,after)
    output = '\n'.join(line for line in output.splitlines() if not line.startswith('QUIC FIXTURE SEND '))
    output += '\nQUIC PHASE case=Q19 phase=QueueFull at_ms=15\nQUIC FIXTURE QUEUE RELEASE case=Q19 at_ms=16 trigger=real_Initial_Exhausted'
    for ordinal in range(1,7):
        output += '\nQUIC FIXTURE SEND case=Q19 ordinal=%d at_ms=%d bytes=%d peer_ip=10.0.2.2 peer_port=4443' % (ordinal,10+ordinal,16 if ordinal<=4 else 1200)
    events=[];captured=[]
    for ordinal,data in enumerate(QUEUE_BYTES):
        digest=hashlib.sha256(data).hexdigest()
        events += [dict(event='udp-receive',bytes=16,sha256=digest),
                   dict(event='queue-fixture-received',ordinal=ordinal,receive_ordinal=ordinal+1,
                        bytes=16,sha256=digest,engine_delivered=False)]
        captured.append(dict(sha256=digest,bytes=16,ordinal=ordinal+1,first_byte=0x41))
    events += [dict(event='udp-receive',bytes=1200,sha256='a'*64),
               dict(event='initial-observed',bytes=1200,sha256='a'*64,receive_ordinal=5),
               dict(event='udp-send',bytes=1200,sha256='b'*64,source=['10.0.2.2',4443],destination=['10.0.2.15',7818])]
    fixture.update(readiness_profile='q19-queue-exhausted-development',unique_queue_fixture_datagrams=4,
                   rx_datagrams=5,rx_bytes=1264,events=events)
    wire.update(guest_udp_count=5,guest_udp=captured+[dict(sha256='a'*64,bytes=1200,ordinal=5,first_byte=0xc0)])
    wire['peer_udp'][0]['destination'][1]=7818
    return output,fixture,wire


class QueueExhaustionControls(unittest.TestCase):
    def peer(self, mode='queue-exhausted'):
        peer=PEER_MODULE.Peer.__new__(PEER_MODULE.Peer)
        peer.mode=mode;peer.queue_fills=0;peer.connection=None;peer.rx_packets=1
        peer.events=[];peer.lock=threading.Lock()
        return peer
    def test_joint_selectors_and_literal_port7818_calibrate(self):
        self.assertEqual(PEER_MODULE.development_profile(Q19),'q19-queue-exhausted-development')
        self.assertEqual(MATRIX.development_profile(Q19),'q19-queue-exhausted-development')
        self.assertEqual(PEER_MODULE.peer_certificate(Q19),'valid')
        self.assertEqual(PEER_MODULE.peer_alpn(Q19),['absd-echo/1'])
        wire=WIRE.observe(pcap([ARP_BROADCAST,Q19_GUEST,Q19_PEER]),Q19,'52:54:00:12:34:56','02:71:00:00:00:02')
        self.assertEqual(wire['guest_udp'][0]['source'][1],7818)
    def test_wrong_mode_and_port_refuse(self):
        with self.assertRaises(RuntimeError):PEER_MODULE.development_profile(dict(Q19,peer_mode='echo'))
        with self.assertRaises(RuntimeError):MATRIX.development_profile(dict(Q19,peer_mode='echo'))
        for changed in [dict(Q19,peer_mode='echo'),dict(Q19,local_port=7800),dict(Q19,id='Q01')]:
            with self.subTest(case=changed),self.assertRaises(WIRE.Refusal):
                WIRE.observe(pcap([Q19_GUEST,Q19_PEER]),changed,'52:54:00:12:34:56','02:71:00:00:00:02')
    def test_actual_hook_accepts_only_four_literal_ordered_prefills(self):
        self.assertEqual(PEER_MODULE.queue_fixture_datagrams(),QUEUE_BYTES)
        peer=self.peer()
        for ordinal,data in enumerate(QUEUE_BYTES):
            peer.rx_packets=ordinal+1;self.assertTrue(peer.accept_queue_fixture(data))
        peer.rx_packets=5;self.assertFalse(peer.accept_queue_fixture(b'\xc0'+bytes(1199)))
        self.assertEqual(peer.queue_fills,4);self.assertIsNone(peer.connection)
        self.assertEqual([row['ordinal']for row in json.loads(json.dumps(peer.events))],[0,1,2,3])
        self.assertFalse(self.peer('echo').accept_queue_fixture(QUEUE_BYTES[0]))
    def test_actual_hook_wrong_bytes_order_count_and_engine_state_refuse(self):
        for data in [QUEUE_BYTES[1],QUEUE_BYTES[0][:-1]+b'X',b'\xc0'+bytes(1199)]:
            with self.subTest(data=data[:16]),self.assertRaises(RuntimeError):self.peer().accept_queue_fixture(data)
        for name,value in [('rx_packets',2),('connection',object())]:
            peer=self.peer();setattr(peer,name,value)
            with self.assertRaises(RuntimeError):peer.accept_queue_fixture(QUEUE_BYTES[0])
            self.assertEqual(peer.queue_fills,0)
    def test_extra_prefill_after_exact_four_refuses(self):
        peer=self.peer()
        for ordinal,data in enumerate(QUEUE_BYTES):
            peer.rx_packets=ordinal+1;peer.accept_queue_fixture(data)
        peer.rx_packets=5
        with self.assertRaises(RuntimeError):peer.accept_queue_fixture(QUEUE_BYTES[0])
        output,fixture,wire=queue_proof();wire['guest_udp'].append(dict(wire['guest_udp'][0]))
        with self.assertRaises(RuntimeError):MATRIX.verify_queue_prelude(fixture,wire)
    def test_native_pending_and_complete_echo_calibrate(self):
        MATRIX.verify_native(Q19,*queue_proof(),MANIFEST)
    def test_missing_or_extra_fixture_count_refuses(self):
        for count in [3,5]:
            output,fixture,wire=queue_proof();fixture['unique_queue_fixture_datagrams']=count
            with self.assertRaises(RuntimeError):MATRIX.verify_native(Q19,output,fixture,wire,MANIFEST)
    def test_reordered_or_substituted_capture_refuses(self):
        for mutate in ['order','bytes','hash']:
            output,fixture,wire=queue_proof()
            if mutate=='order':wire['guest_udp'][0],wire['guest_udp'][1]=wire['guest_udp'][1],wire['guest_udp'][0]
            elif mutate=='bytes':wire['guest_udp'][0]['bytes']=17
            else:wire['guest_udp'][0]['sha256']='c'*64
            with self.subTest(mutation=mutate),self.assertRaises(RuntimeError):MATRIX.verify_native(Q19,output,fixture,wire,MANIFEST)
    def test_forged_prefill_or_response_before_initial_refuses(self):
        for mutate in ['receipt','engine','order','send']:
            output,fixture,wire=queue_proof()
            if mutate=='receipt':fixture['events'][1]['receive_ordinal']=2
            elif mutate=='engine':fixture['events'][1]['engine_delivered']=True
            elif mutate=='order':fixture['events'][0],fixture['events'][1]=fixture['events'][1],fixture['events'][0]
            else:fixture['events'].insert(0,fixture['events'].pop())
            with self.subTest(mutation=mutate),self.assertRaises(RuntimeError):MATRIX.verify_native(Q19,output,fixture,wire,MANIFEST)
    def test_pending_hash_exhaustion_retry_and_parent_release_are_required(self):
        for before,after in [('pending_retry_sha256='+'a'*64,'pending_retry_sha256='+'c'*64),
                ('exhausted=1','exhausted=0'),('queue_retry_accepted=1','queue_retry_accepted=0'),
                ('trigger=real_Initial_Exhausted','trigger=other'),('phase=QueueFull','phase=Handshake')]:
            output,fixture,wire=queue_proof()
            with self.subTest(field=before),self.assertRaises(RuntimeError):MATRIX.verify_native(Q19,output.replace(before,after),fixture,wire,MANIFEST)
    def boundary_proof(self, accepted=256, sent_bytes=302464):
        output,fixture,wire=queue_proof()
        output=output.replace('engine_transmits=1','engine_transmits='+str(accepted-4))
        output=output.replace('send_accepted=5','send_accepted='+str(accepted))
        output=output.replace('send_calls=6','send_calls='+str(accepted+1))
        output=output.replace('send_requests=6','send_requests='+str(accepted+1))
        output=output.replace('send_bytes=1264','send_bytes='+str(sent_bytes))
        for ordinal in range(7,accepted+2):
            output+='\nQUIC FIXTURE SEND case=Q19 ordinal=%d at_ms=20 bytes=1200 peer_ip=10.0.2.2 peer_port=4443'%ordinal
        return output,fixture,wire
    def test_actual_transport_packet_limit_includes_four_prefills(self):
        MATRIX.verify_native(Q19,*self.boundary_proof(),MANIFEST)
        with self.assertRaisesRegex(RuntimeError,'native transmit budget differs'):
            MATRIX.verify_native(Q19,*self.boundary_proof(accepted=257,sent_bytes=303664),MANIFEST)
    def test_actual_transport_byte_limit_is_not_expanded_by_prefills(self):
        # Counter-oracle calibration only; the fixed1200-byte engine plus four
        #16-byte prefills reaches a smaller bound before all byte capacity.
        MATRIX.verify_native(Q19,*self.boundary_proof(sent_bytes=307200),MANIFEST)
        with self.assertRaisesRegex(RuntimeError,'native transmit budget differs'):
            MATRIX.verify_native(Q19,*self.boundary_proof(sent_bytes=307201),MANIFEST)
    def test_missing_native_ledger_or_echo_fin_refuses(self):
        for before,after in [('send_requests=6','send_requests=5'),('peer_fin=true','peer_fin=false'),('pipe_fenced=true','pipe_fenced=false')]:
            output,fixture,wire=queue_proof()
            with self.subTest(field=before),self.assertRaises(RuntimeError):MATRIX.verify_native(Q19,output.replace(before,after),fixture,wire,MANIFEST)

class ResponseFlightControls(unittest.TestCase):
    class Engine:
        def __init__(self, batch): self.batch, self.calls, self.timers = batch, 0, 0
        def datagrams_to_send(self, now):
            self.calls += 1
            return list(self.batch)
        def get_timer(self): self.timers += 1; return None
    class Socket:
        def __init__(self): self.sent = []
        def sendto(self, data, destination): self.sent.append((data, destination)); return len(data)
        def getsockname(self): return ('10.0.2.2',4443)
    def peer(self, case=Q08, batch=None):
        peer = object.__new__(PEER_MODULE.Peer)
        peer.response_policy = PEER_MODULE.response_policy(case)
        peer.one_response_flight = PEER_MODULE.one_response_policy(case)
        peer.response_flight_sealed = False
        peer.initial_sha256, peer.rx_packets = 'a'*64, 1
        peer.tx_packets, peer.tx_bytes = 0, 0
        peer.expected_source = ('10.0.2.15',case['local_port'])
        peer.lock, peer.events = threading.Lock(), []
        peer.socket = self.Socket()
        peer.connection = self.Engine(batch if batch is not None else [(b'a'*1200,peer.expected_source)])
        return peer
    def test_policy_is_exact_q08_and_q01_stays_standard(self):
        self.assertTrue(PEER_MODULE.one_response_policy(Q08))
        self.assertFalse(PEER_MODULE.one_response_policy(CASE))
        with self.assertRaises(RuntimeError): PEER_MODULE.one_response_policy(dict(Q08,peer_mode='echo'))
    def test_actual_flush_seals_one_complete_batch_and_never_polls_again(self):
        for count in (1,2,4):
            with self.subTest(datagrams=count):
                batch=[(bytes([97+i])*1200,('10.0.2.15',7807)) for i in range(count)]
                peer=self.peer(batch=batch); peer.flush(); peer.drive_timer(100.0); peer.flush()
                self.assertEqual((peer.connection.calls,peer.connection.timers), (1,0))
                self.assertEqual(peer.socket.sent,batch)
                self.assertEqual([row['event'] for row in peer.events],
                    ['q08-response-flight']+['udp-send']*count+['q08-response-flight-fenced'])
                self.assertEqual(peer.events[0]['datagrams'],
                    [dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),destination=list(destination))
                     for data,destination in batch])
                self.assertEqual(peer.events[-1]['tx_datagrams'],count)
                self.assertEqual(peer.events[-1]['tx_bytes'],1200*count)
                self.assertTrue(peer.response_flight_sealed)
    def test_actual_direct_send_after_fence_refuses_before_socket(self):
        peer = self.peer(); peer.flush()
        with self.assertRaises(RuntimeError): peer.send(b'later')
        self.assertEqual(len(peer.socket.sent),1)
    def test_standard_q01_timer_and_flush_continue(self):
        peer = self.peer(CASE); peer.flush(); peer.drive_timer(100.0)
        self.assertEqual((peer.connection.calls,peer.connection.timers), (2,1))
        self.assertEqual(len(peer.socket.sent),2)
        self.assertFalse(peer.response_flight_sealed)
    def test_first_batch_empty_or_over_bound_refuses(self):
        for count in (0,5):
            peer = self.peer(batch=[(b'a',('10.0.2.15',7807))]*count)
            with self.assertRaises(RuntimeError): peer.flush()
            self.assertEqual(peer.socket.sent,[])
    def test_first_batch_wrong_destination_refuses(self):
        peer = self.peer(batch=[(b'a',('10.0.2.15',7808))])
        with self.assertRaises(RuntimeError): peer.flush()
        self.assertEqual(peer.socket.sent,[])
    def test_extra_send_after_fence_cannot_qualify(self):
        output, fixture, wire = wrong_root_proof()
        fixture['events'].append(copy.deepcopy(next(row for row in fixture['events'] if row['event']=='udp-send')))
        with self.assertRaises(RuntimeError): MATRIX.verify_native(Q08,output,fixture,wire,MANIFEST)
    def test_every_first_batch_send_still_requires_capture(self):
        output, fixture, wire = wrong_root_proof(); wire['peer_udp']=[]
        with self.assertRaises(RuntimeError): MATRIX.verify_native(Q08,output,fixture,wire,MANIFEST)
    def test_changed_batch_digest_or_fence_order_refuses(self):
        for mutation in ('digest','order'):
            _, fixture, _ = wrong_root_proof()
            if mutation=='digest': fixture['events'][2]['datagrams'][0]['sha256']='f'*64
            else: fixture['events'][3],fixture['events'][4]=fixture['events'][4],fixture['events'][3]
            with self.assertRaises(RuntimeError): MATRIX.verify_q08_response_flight(fixture)


class SelectedAuthFlightControls(unittest.TestCase):
    def test_exact_auth_modes_select_policy_and_standard_paths_stay_standard(self):
        for case in AUTH_CASES:
            self.assertEqual(PEER_MODULE.response_policy(case), 'auth-one-response-flight-v1')
            with self.assertRaises(RuntimeError): PEER_MODULE.response_policy(dict(case, peer_mode='echo'))
        self.assertEqual(PEER_MODULE.response_policy(Q08), 'q08-one-response-flight-v1')
        for case in (CASE, Q03):
            self.assertEqual(PEER_MODULE.response_policy(case), 'standard')
    def test_actual_full_batches_for_each_auth_case_and_no_later_engine_or_send(self):
        for case in AUTH_CASES:
            for count in (1,2,4):
                with self.subTest(case=case['id'], count=count):
                    batch=[(bytes([97+i])*1200, ('10.0.2.15',case['local_port'])) for i in range(count)]
                    peer=ResponseFlightControls().peer(case, batch)
                    peer.flush(); peer.drive_timer(100.0); peer.flush()
                    self.assertEqual((peer.connection.calls, peer.connection.timers), (1,0))
                    self.assertEqual(peer.socket.sent, batch)
                    self.assertEqual([row['event'] for row in peer.events],
                        ['auth-response-flight']+['udp-send']*count+['auth-response-flight-fenced'])
                    planned, = (event for event in peer.events if event['event']=='auth-response-flight')
                    self.assertEqual(planned['datagrams'],
                        [dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),destination=list(destination))
                         for data,destination in batch])
                    self.assertEqual(planned['policy'], 'auth-one-response-flight-v1')
                    with self.assertRaises(RuntimeError): peer.send(b'later')
                    self.assertEqual(peer.socket.sent, batch)
    def test_selected_auth_empty_or_overfull_batches_refuse_before_socket(self):
        for case in AUTH_CASES:
            for count in (0,5):
                peer=ResponseFlightControls().peer(case, [(b'a',('10.0.2.15',case['local_port']))]*count)
                with self.subTest(case=case['id'], count=count), self.assertRaises(RuntimeError): peer.flush()
                self.assertEqual(peer.socket.sent, [])
    def test_each_named_auth_proof_and_original_code_calibrates(self):
        for case in AUTH_CASES:
            output, fixture, wire=auth_proof(case)
            MATRIX.verify_auth_response_flight(case, fixture)
            MATRIX.verify_native(case, output, fixture, wire, MANIFEST)
            self.assertIn('transport_error_code='+str(AUTH_EXPECTED[case['id']][3]), output)
    def test_wrong_case_mode_or_policy_cannot_establish_the_auth_flight(self):
        for case in AUTH_CASES:
            _, fixture, _=auth_proof(case)
            for changed in (CASE, dict(case, peer_mode='echo')):
                with self.assertRaises(RuntimeError): MATRIX.verify_auth_response_flight(changed,fixture)
            fixture['peer_policy']='q08-one-response-flight-v1'
            with self.assertRaises(RuntimeError): MATRIX.verify_auth_response_flight(case,fixture)
    def test_missing_capture_or_late_send_refuses_each_native_case(self):
        for case in AUTH_CASES:
            for mode in ('missing-capture','late-send'):
                output, fixture, wire=auth_proof(case)
                if mode=='missing-capture': wire['peer_udp']=[]
                else: fixture['events'].append(copy.deepcopy(next(event for event in fixture['events'] if event['event']=='udp-send')))
                with self.subTest(case=case['id'], mode=mode), self.assertRaises(RuntimeError):
                    MATRIX.verify_native(case, output, fixture, wire, MANIFEST)
    def test_changed_complete_batch_or_reordered_fence_refuses_each_case(self):
        for case in AUTH_CASES:
            for mode in ('batch','order'):
                _, fixture, _=auth_proof(case)
                planned, = (event for event in fixture['events'] if event['event']=='auth-response-flight')
                fence, = (event for event in fixture['events'] if event['event']=='auth-response-flight-fenced')
                if mode=='batch': planned['datagrams'][0]['sha256']='f'*64
                else:
                    fixture['events'].remove(fence); fixture['events'].insert(fixture['events'].index(planned), fence)
                with self.assertRaises(RuntimeError): MATRIX.verify_auth_response_flight(case, fixture)


class NativeAfterFlightControls(unittest.TestCase):
    def append_input(self, case, fixture):
        ordinal=fixture['rx_datagrams']+1
        fixture['rx_datagrams']+=1; fixture['rx_bytes']+=1200
        fixture['events'].extend([
            dict(event='udp-receive', bytes=1200, sha256='c'*64, source=['10.0.2.15',case['local_port']]),
            dict(event=('q08' if case['id']=='Q08' else 'auth')+'-after-flight-input',
                 bytes=1200,sha256='c'*64,receive_ordinal=ordinal,engine_delivered=False)])
    def test_native_authentication_refuses_any_after_flight_input(self):
        for case in [Q08,*AUTH_CASES]:
            for count in (1,2):
                output,fixture,wire=wrong_root_proof() if case['id']=='Q08' else auth_proof(case)
                for _ in range(count): self.append_input(case,fixture)
                with self.subTest(case=case['id'], count=count), self.assertRaisesRegex(RuntimeError,'discarded after the response flight'):
                    MATRIX.verify_native(case,output,fixture,wire,MANIFEST)
    def test_linux_authentication_close_input_remains_allowed(self):
        for case in [Q08,*AUTH_CASES]:
            observed,pki=WrongRootControls().linux() if case['id']=='Q08' else AuthProfileControls().linux(case)
            self.append_input(case,observed['fixture'])
            MATRIX.verify_linux_auth_refusal(case,observed,pki)


if __name__ == '__main__':
    unittest.main()
