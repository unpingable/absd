#!/usr/bin/env python3
"""Finite Q12 source/oracle controls for the declared execution host only.

Literal captures and synthetic reports calibrate evidence refusal. They never
establish native delivery or an actual protocol result.
"""
import copy
import hashlib
import importlib.util
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('q12_base', ROOT / 'native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
MATRIX, PEER, WIRE, MANIFEST = BASE.MATRIX, BASE.PEER_MODULE, BASE.WIRE, BASE.MANIFEST
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q12')
TRUNCATED = bytes.fromhex('c00000000108')
TRUNCATED_SHA = hashlib.sha256(TRUNCATED).hexdigest()
GUEST = bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e83115b0011e11a717569632d77697265000000000000000000')
ORDINARY = bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e830011e11a717569632d77697265000000000000000000')
TRUNCATED_FRAME = bytes.fromhex('52540012345602710000000208004500002200014000401122ba0a0002020a00020f115b1e83000ef6dac00000000108000000000000000000000000')


def line(prefix, fields):
    return prefix + ' ' + ' '.join(key + '=' + str(value) for key, value in fields.items())


def proof():
    output, fixture, wire = BASE.proof()
    output = output.replace('Q01', 'Q12').replace('local_port=7800', 'local_port=7811')
    lines = []
    for text in output.splitlines():
        if text.startswith('QUIC RESULT '):
            fields = MATRIX.fields(text)
            fields.update(received='2', receive_bytes='1206')
            text = line('QUIC RESULT', fields)
        elif text.startswith('QUIC FIXTURE NATIVE_COUNTS '):
            fields = MATRIX.fields(text)
            fields['receive_delivered'] = '2'
            text = line('QUIC FIXTURE NATIVE_COUNTS', fields)
        elif text.startswith('QUIC FIXTURE RX '):
            fields = MATRIX.fields(text)
            lines.append(line('QUIC FIXTURE RX', dict(fields, ordinal='1', at_ms='30', bytes='6', sha256=TRUNCATED_SHA)))
            text = line('QUIC FIXTURE RX', dict(fields, ordinal='2'))
        lines.append(text)
    fixture.update(readiness_profile='q12-truncated-header-development', mode='truncated-header',
                   tx_datagrams=2, tx_bytes=1206,
                   certificate_selection={'kind':'valid', 'sha256':'d' * 64, 'client_root_sha256':'e' * 64})
    normal = next(row for row in fixture['events'] if row['event'] == 'udp-send')
    normal['destination'][1] = 7811
    malformed = dict(normal, fixture='truncated-header', bytes=6, sha256=TRUNCATED_SHA)
    fixture['events'] = [dict(event='udp-receive', bytes=1200, sha256='a' * 64, source=['10.0.2.15',7811]),
                         dict(event='initial-observed', bytes=1200, sha256='a' * 64), malformed, normal]
    wire['guest_udp'][0].update(source=['10.0.2.15',7811], destination=['10.0.2.2',4443])
    wire['peer_udp'][0]['destination'][1] = 7811
    wire['peer_udp'].insert(0, {key:value for key,value in malformed.items() if key not in ('event','fixture')})
    return '\n'.join(lines), fixture, wire


class Socket:
    def __init__(self):
        self.sent = []
    def getsockname(self):
        return ('10.0.2.2', 4443)
    def sendto(self, data, destination):
        self.sent.append((bytes(data), destination))
        return len(data)


def peer():
    value = object.__new__(PEER.Peer)
    value.case, value.mode, value.family = CASE, 'truncated-header', 'ipv4'
    value.expected_source = ('10.0.2.15',7811)
    value.one_response_flight = value.response_flight_sealed = False
    value.connection, value.initial_sha256 = object(), 'a' * 64
    value.tx_packets = value.tx_bytes = 0
    value.socket, value.lock = Socket(), threading.Lock()
    value.events = [dict(event='initial-observed', bytes=1200, sha256='a' * 64)]
    return value


class TruncatedHeaderControls(unittest.TestCase):
    def check(self, evidence):
        return MATRIX.verify_native(CASE, *evidence, MANIFEST)

    def test_existing_case_profile_certificate_and_standard_policy(self):
        self.assertEqual((CASE['local_port'], CASE['peer_mode'], CASE['expected_outcome']), (7811, 'truncated-header', 'Complete'))
        self.assertEqual(MATRIX.development_profile(CASE), 'q12-truncated-header-development')
        self.assertEqual(PEER.development_profile(CASE), 'q12-truncated-header-development')
        self.assertEqual(PEER.peer_certificate(CASE), 'valid')
        self.assertEqual(PEER.peer_terminal_codes(CASE), (0,))
        self.assertEqual(PEER.response_policy(CASE), 'standard')

    def test_case_mode_port_or_ipv6_substitution_refuses(self):
        for changed in (dict(CASE, id='Q01'), dict(CASE, local_port=7800), dict(CASE, peer_mode='echo')):
            with self.subTest(case=changed):
                with self.assertRaises(RuntimeError): MATRIX.development_profile(changed)
                with self.assertRaises(RuntimeError): PEER.development_profile(changed)
        with self.assertRaises(RuntimeError): MATRIX.development_profile(CASE, 'ipv6')
        with self.assertRaises(RuntimeError): PEER.development_profile(CASE, 'ipv6')

    def test_literal_is_quic_v1_initial_prefix_with_missing_declared_cid(self):
        self.assertEqual(PEER.truncated_header_datagram(), TRUNCATED)
        self.assertEqual(TRUNCATED, b'\xc0\x00\x00\x00\x01\x08')
        self.assertEqual((len(TRUNCATED), int.from_bytes(TRUNCATED[1:5], 'big'), TRUNCATED[5]), (6, 1, 8))

    def test_peer_sends_exact_literal_once_before_normal_response(self):
        value = peer()
        value.send_truncated_header()
        self.assertEqual(value.socket.sent, [(TRUNCATED, ('10.0.2.15',7811))])
        self.assertEqual((value.tx_packets, value.tx_bytes), (1, 6))
        self.assertEqual(value.events[-1]['fixture'], 'truncated-header')
        with self.assertRaises(RuntimeError): value.send_truncated_header()
        value.send(b'ordinary')
        self.assertEqual(value.socket.sent[-1], (b'ordinary', ('10.0.2.15',7811)))
        self.assertNotIn('fixture', value.events[-1])

    def test_peer_requires_selected_family_and_accepted_initial_before_send(self):
        for key, changed in [('family','ipv6'), ('connection',None), ('initial_sha256',None), ('mode','echo')]:
            value = peer()
            setattr(value, key, changed)
            with self.subTest(field=key), self.assertRaises(RuntimeError): value.send_truncated_header()
            self.assertEqual(value.socket.sent, [])

    def test_changed_bytes_cannot_carry_truncated_fixture_tag(self):
        value = peer()
        with self.assertRaises(RuntimeError): value.send(TRUNCATED[:-1] + b'\x09', fixture='truncated-header')
        self.assertEqual(value.socket.sent, [])

    def test_literal_checksum_valid_complete_capture_calibrates(self):
        result = WIRE.observe(BASE.pcap([BASE.ARP_BROADCAST, GUEST, TRUNCATED_FRAME, ORDINARY]), CASE,
                              '52:54:00:12:34:56', '02:71:00:00:00:02')
        self.assertEqual((result['frame_count'], result['arp_count'], result['udp_count']), (4, 1, 3))
        self.assertEqual((result['peer_udp'][0]['bytes'], result['peer_udp'][0]['sha256']), (6, TRUNCATED_SHA))
        self.assertTrue(all(row['ip_checksum_valid'] and row['udp_checksum_valid'] for row in result['peer_udp']))

    def test_changed_capture_checksum_or_tuple_refuses(self):
        changed = bytearray(TRUNCATED_FRAME)
        changed[42] ^= 1
        for frames in ([GUEST, bytes(changed), ORDINARY], [BASE.GUEST, TRUNCATED_FRAME, ORDINARY]):
            with self.assertRaises(WIRE.Refusal):
                WIRE.observe(BASE.pcap(frames), CASE, '52:54:00:12:34:56', '02:71:00:00:00:02')

    def test_complete_native_proof_requires_actual_malformed_delivery(self):
        observed = self.check(proof())
        self.assertEqual(observed['actual_outcome'], 'Complete')
        self.assertEqual(observed['typed_report']['received'], '2')

    def test_ordinary_echo_renamed_q12_cannot_qualify(self):
        output, fixture, wire = BASE.proof()
        output = output.replace('Q01','Q12').replace('local_port=7800','local_port=7811')
        fixture.update(readiness_profile='q12-truncated-header-development', mode='truncated-header')
        with self.assertRaises(RuntimeError): self.check((output,fixture,wire))

    def test_missing_tagged_socket_send_refuses(self):
        output, fixture, wire = proof()
        fixture['events'][2].pop('fixture')
        with self.assertRaises(RuntimeError): self.check((output,fixture,wire))

    def test_changed_exact_bytes_or_tuple_refuses_even_if_capture_changes(self):
        for key, value in [('bytes',5), ('sha256','c' * 64), ('source',['10.0.2.2',4444]), ('destination',['10.0.2.15',7800])]:
            output, fixture, wire = proof()
            fixture['events'][2][key] = copy.deepcopy(value)
            wire['peer_udp'][0][key] = copy.deepcopy(value)
            with self.subTest(field=key), self.assertRaises(RuntimeError): self.check((output,fixture,wire))

    def test_missing_or_duplicated_malformed_capture_refuses(self):
        for mode in ('missing','duplicate'):
            output, fixture, wire = proof()
            if mode == 'missing': wire['peer_udp'].pop(0)
            else: wire['peer_udp'].insert(0,copy.deepcopy(wire['peer_udp'][0]))
            with self.subTest(mode=mode), self.assertRaises(RuntimeError): self.check((output,fixture,wire))

    def test_socket_capture_count_or_order_substitution_refuses(self):
        for mode in ('socket-count','wire-order','socket-order'):
            output, fixture, wire = proof()
            if mode == 'socket-count': fixture['events'].append(copy.deepcopy(fixture['events'][-1]))
            elif mode == 'wire-order': wire['peer_udp'].reverse()
            else: fixture['events'][2:] = reversed(fixture['events'][2:])
            with self.subTest(mode=mode), self.assertRaises(RuntimeError): self.check((output,fixture,wire))

    def test_native_rx_hash_or_bytes_must_match_captured_literal(self):
        for before, after in [('sha256=' + TRUNCATED_SHA,'sha256=' + 'c' * 64), ('at_ms=30 bytes=6','at_ms=30 bytes=5')]:
            output, fixture, wire = proof()
            with self.subTest(field=before), self.assertRaises(RuntimeError): self.check((output.replace(before,after),fixture,wire))

    def test_captured_malformed_datagram_without_native_delivery_refuses(self):
        output, fixture, wire = proof()
        lines = [row for row in output.splitlines()
                 if not (row.startswith('QUIC FIXTURE RX ') and 'sha256=' + TRUNCATED_SHA in row)]
        output = '\n'.join(lines).replace('received=2', 'received=1').replace('receive_bytes=1206', 'receive_bytes=1200')
        output = output.replace('receive_delivered=2', 'receive_delivered=1').replace('ordinal=2', 'ordinal=1')
        with self.assertRaisesRegex(RuntimeError, 'exact malformed native RECEIVE ordinal/hash absent'):
            self.check((output, fixture, wire))

    def test_malformed_native_receive_must_be_first_ordinal(self):
        output, fixture, wire = proof()
        lines = output.splitlines()
        indexes = [i for i,row in enumerate(lines) if row.startswith('QUIC FIXTURE RX ')]
        first, second = (MATRIX.fields(lines[i]) for i in indexes)
        lines[indexes[0]] = line('QUIC FIXTURE RX',dict(second,ordinal='1',at_ms='30'))
        lines[indexes[1]] = line('QUIC FIXTURE RX',dict(first,ordinal='2',at_ms='50'))
        with self.assertRaisesRegex(RuntimeError,'exact malformed native RECEIVE ordinal/hash absent'):
            self.check(('\n'.join(lines),fixture,wire))

    def test_delivered_malformed_input_cannot_replace_full_authenticated_success(self):
        for before, after in [('authenticated=true','authenticated=false'), ('sent_stream=4096','sent_stream=4095'),
                              ('received_stream=4096','received_stream=4095'), ('request_fin=true','request_fin=false'),
                              ('peer_fin=true','peer_fin=false'), ('request_acked=true','request_acked=false'),
                              ('connection_drained=true','connection_drained=false'), ('transport_error_code=none','transport_error_code=0')]:
            output, fixture, wire = proof()
            with self.subTest(field=before), self.assertRaises(RuntimeError): self.check((output.replace(before,after),fixture,wire))

    def test_original_deadline_fence_and_resource_checks_remain_required(self):
        for before, after in [('deadline_ms=10010','deadline_ms=10011'), ('owner_expiry_ms=15001','owner_expiry_ms=15002'),
                              ('pipe_fenced=true','pipe_fenced=false'), ('sends_after_fence=0','sends_after_fence=1'),
                              ('handles_after=1','handles_after=2'), ('receive_delivered=2','receive_delivered=1')]:
            output, fixture, wire = proof()
            with self.subTest(field=before), self.assertRaises(RuntimeError): self.check((output.replace(before,after),fixture,wire))

    def test_linux_fixture_establishment_has_no_native_delivery_claim(self):
        _, fixture, _ = proof()
        fixture['events'][0]['source'] = ['127.0.0.1',49152]
        for row in fixture['events'][2:]:
            row.update(source=['127.0.0.1',49153], destination=['127.0.0.1',49152])
        MATRIX.verify_truncated_header(CASE,fixture,linux_control=True)
        with self.assertRaises(RuntimeError): MATRIX.verify_truncated_header(CASE,fixture)
        fixture['events'][2]['sha256'] = 'c' * 64
        with self.assertRaises(RuntimeError): MATRIX.verify_truncated_header(CASE,fixture,linux_control=True)

    def test_original_standard_echo_control_still_calibrates(self):
        MATRIX.verify_native(BASE.CASE,*BASE.proof(),MANIFEST)


if __name__ == '__main__':
    unittest.main()
