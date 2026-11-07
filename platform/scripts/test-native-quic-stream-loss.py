#!/usr/bin/env python3
"""Finite Q04 source/oracle controls; actual protocol evidence stays runtime-only."""
from pathlib import Path
import importlib.util
import json
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('quic_stream_loss_base', ROOT / 'scripts/native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
MATRIX, PEER, WIRE = BASE.MATRIX, BASE.PEER_MODULE, BASE.WIRE
MANIFEST = json.loads((ROOT / 'quic/CASES.json').read_text())
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q04')
GUEST = bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e7b115b0011e122717569632d77697265000000000000000000')
PEER_PACKET = bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e7b0011e122717569632d77697265000000000000000000')


def one(fixture, event):
    selected = [row for row in fixture['events'] if row['event'] == event]
    if len(selected) != 1: raise RuntimeError('one exact event required: ' + event)
    return selected[0]


def proof():
    output, fixture, wire = BASE.proof()
    output = output.replace('Q01', 'Q04').replace('local_port=7800', 'local_port=7803')
    for key in ('engine_transmits', 'send_calls', 'send_accepted', 'send_requests'):
        output = output.replace(key + '=1', key + '=4')
    output = output.replace('send_bytes=1200', 'send_bytes=2280').replace('last_send_ms=20', 'last_send_ms=24')
    lines = [line for line in output.splitlines() if not line.startswith('QUIC FIXTURE SEND ')]
    packets = [(1200, 'a' * 64, 0xc0), (80, 'c' * 64, 0xe0), (500, 'd' * 64, 0x40), (500, 'e' * 64, 0x40)]
    for ordinal, (length, digest, _) in enumerate(packets, 1):
        lines.append('QUIC FIXTURE SEND case=Q04 ordinal=%d at_ms=%d bytes=%d peer_ip=10.0.2.2 peer_port=4443 sha256=%s' % (ordinal, 20 + ordinal, length, digest))
    for ordinal, before, after in ((3, 0, 1), (4, 1, 2)):
        length, digest, _ = packets[ordinal - 1]
        lines.append('QUIC STREAM TX case=Q04 engine_ordinal=%d native_request_ordinal=%d accepted_ordinal=%d bytes=%d sha256=%s stream_frames_before=%d stream_frames_after=%d authenticated=true' % (ordinal, ordinal, ordinal, length, digest, before, after))
    source, destination = ['10.0.2.15', 7803], ['10.0.2.2', 4443]
    received = [dict(event='udp-receive', receive_ordinal=i, bytes=length, sha256=digest, first_byte=first, source=list(source))
                for i, (length, digest, first) in enumerate(packets, 1)]
    def delivery(i): return dict(event='engine-delivered', **{key: received[i - 1][key] for key in ('receive_ordinal', 'bytes', 'sha256', 'source')})
    fixture.update(mode='stream-loss', readiness_profile='q04-stream-loss-development', stream_drops=1, initial_drops=0,
                   rx_datagrams=4, rx_bytes=2280)
    fixture['events'] = [received[0], dict(event='initial-observed', receive_ordinal=1, bytes=1200, sha256='a' * 64), delivery(1),
        received[1], delivery(2), dict(event='handshake', receive_ordinal=2, alpn='absd-echo/1', early_data=False, resumed=False),
        received[2], dict(event='stream-datagram-drop', receive_ordinal=3, bytes=500, sha256='d' * 64, first_byte=0x40,
            authenticated_before=True, request_bytes_before=512, request_fin_before=False,
            engine_delivered=False, frame_proof='requires-native-public-counter'),
        received[3], delivery(4), dict(event='udp-send', bytes=1200, sha256='b' * 64, source=destination, destination=source)]
    wire.update(guest_udp_count=4, guest_udp=[dict(bytes=length, sha256=digest, first_byte=first, ordinal=i, source=list(source), destination=list(destination))
                for i, (length, digest, first) in enumerate(packets, 1)])
    wire['peer_udp'][0]['destination'][1] = 7803
    return '\n'.join(lines), fixture, wire


class StreamLossControls(unittest.TestCase):
    def check(self, output, fixture, wire): return MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)

    def peer(self, authenticated=True, mode='stream-loss'):
        class Engine:
            def __init__(self): self.received = []
            def receive_datagram(self, data, source, now): self.received.append((data, source, now))
        peer = object.__new__(PEER.Peer)
        peer.mode, peer.authenticated, peer.connection = mode, authenticated, Engine()
        peer.rx_packets, peer.stream_drops, peer.received, peer.request_fin = 3, 0, bytearray(b'abc'), False
        peer.lock, peer.events = threading.Lock(), []
        return peer

    def test_exact_case_profile_certificate_and_tuple_calibrate(self):
        self.assertEqual((CASE['peer_mode'], CASE['local_port'], CASE['expected_outcome']), ('stream-loss', 7803, 'Complete'))
        self.assertEqual(PEER.development_profile(CASE), 'q04-stream-loss-development')
        self.assertEqual(MATRIX.development_profile(CASE), 'q04-stream-loss-development')
        self.assertEqual((PEER.peer_certificate(CASE), PEER.peer_terminal_codes(CASE)), ('valid', (0,)))
        self.assertEqual(PEER.response_policy(CASE), 'standard')

    def test_wrong_case_mode_port_or_ipv6_refuses(self):
        for changed in (dict(CASE, id='Q03'), dict(CASE, peer_mode='echo'), dict(CASE, local_port=7800)):
            with self.subTest(case=changed):
                with self.assertRaises(RuntimeError): PEER.development_profile(changed)
                with self.assertRaises(RuntimeError): MATRIX.development_profile(changed)
                with self.assertRaises(WIRE.Refusal): WIRE.observe(BASE.pcap([GUEST, PEER_PACKET]), changed, '52:54:00:12:34:56', '02:71:00:00:00:02')
        with self.assertRaises(RuntimeError): PEER.development_profile(CASE, 'ipv6')
        with self.assertRaises(RuntimeError): MATRIX.development_profile(CASE, 'ipv6')

    def test_literal7803_capture_checksum_and_ordinary_ports_refuse(self):
        value = WIRE.observe(BASE.pcap([BASE.ARP_BROADCAST, GUEST, PEER_PACKET]), CASE, '52:54:00:12:34:56', '02:71:00:00:00:02')
        self.assertEqual((value['frame_count'], value['guest_udp'][0]['source'][1]), (3, 7803))
        self.assertTrue(all(row['ip_checksum_valid'] and row['udp_checksum_valid'] for row in value['guest_udp'] + value['peer_udp']))
        with self.assertRaises(WIRE.Refusal): WIRE.observe(BASE.pcap([BASE.GUEST, BASE.PEER]), CASE, '52:54:00:12:34:56', '02:71:00:00:00:02')

    def test_real_peer_method_omits_once_before_engine_delivery(self):
        peer = self.peer(); data = b'\x40' + b'x' * 39
        self.assertFalse(peer.deliver_datagram(data, ('10.0.2.15', 7803), 1.0))
        self.assertEqual(peer.connection.received, [])
        self.assertEqual(one({'events': peer.events}, 'stream-datagram-drop')['sha256'], PEER.digest(data))
        peer.rx_packets += 1
        self.assertTrue(peer.deliver_datagram(data, ('10.0.2.15', 7803), 2.0))
        self.assertEqual(peer.connection.received, [(data, ('10.0.2.15', 7803), 2.0)])
        self.assertEqual([row['event'] for row in peer.events], ['stream-datagram-drop', 'engine-delivered'])

    def test_actual_method_does_not_omit_initial_or_prehandshake_or_echo(self):
        for peer, data in ((self.peer(), b'\xc0' + b'x' * 39), (self.peer(authenticated=False), b'\x40x'), (self.peer(mode='echo'), b'\x40x')):
            with self.subTest(mode=peer.mode, authenticated=peer.authenticated):
                self.assertTrue(peer.deliver_datagram(data, ('10.0.2.15', 7803), 1.0))
                self.assertEqual(peer.stream_drops, 0)
                self.assertEqual(len(peer.connection.received), 1)

    def test_actual_method_does_not_claim_loss_after_full_fin(self):
        peer = self.peer(); peer.received = bytearray(4096); peer.request_fin = True
        self.assertTrue(peer.deliver_datagram(b'\x40x', ('10.0.2.15', 7803), 1.0))
        self.assertEqual(peer.stream_drops, 0)

    def test_synthetic_full_native_correspondence_calibrates(self):
        self.assertEqual(self.check(*proof())['actual_outcome'], 'Complete')

    def test_linux_reference_is_only_header_selected_omission(self):
        _, fixture, _ = proof()
        self.assertEqual(MATRIX.verify_stream_loss(fixture)['sha256'], 'd' * 64)
        self.assertEqual(fixture['request_bytes'], 4096)

    def test_ordinary_echo_or_stale_built_stream_event_cannot_qualify(self):
        for mutation in ('echo', 'stale'):
            output, fixture, wire = proof()
            if mutation == 'echo': fixture['stream_drops'] = 0
            else: one(fixture, 'stream-datagram-drop').update(event='application-datagram-drop', built_stream_bytes=512)
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_initial_omission_is_not_stream_omission(self):
        output, fixture, wire = proof(); drop = one(fixture, 'stream-datagram-drop')
        drop.update(first_byte=0xc0, receive_ordinal=1, sha256='a' * 64, bytes=1200)
        with self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_drop_must_follow_matching_socket_and_handshake(self):
        for mutation in ('drop_first', 'handshake_late', 'ordinal', 'hash'):
            output, fixture, wire = proof(); drop = one(fixture, 'stream-datagram-drop')
            if mutation == 'drop_first': fixture['events'].insert(0, fixture['events'].pop(fixture['events'].index(drop)))
            elif mutation == 'handshake_late': fixture['events'].append(fixture['events'].pop(fixture['events'].index(one(fixture, 'handshake'))))
            elif mutation == 'ordinal': drop['receive_ordinal'] = 4
            else: drop['sha256'] = 'f' * 64
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_forged_engine_delivery_or_omitted_delivery_refuses(self):
        for mutation in ('delivered_drop', 'missing_other', 'reordered'):
            output, fixture, wire = proof()
            if mutation == 'delivered_drop': fixture['events'].insert(8, dict(event='engine-delivered', receive_ordinal=3, bytes=500, sha256='d' * 64, source=['10.0.2.15',7803]))
            elif mutation == 'missing_other': fixture['events'].pop(4)
            else: fixture['events'][3], fixture['events'][4] = fixture['events'][4], fixture['events'][3]
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_complete_socket_capture_census_refuses_missing_extra_or_reordered(self):
        for mutation in ('missing', 'extra', 'reordered', 'extra_send'):
            output, fixture, wire = proof()
            if mutation == 'missing': wire['guest_udp'].pop(2)
            elif mutation == 'extra': wire['guest_udp'].append(dict(wire['guest_udp'][-1]))
            elif mutation == 'reordered': wire['guest_udp'][2], wire['guest_udp'][3] = wire['guest_udp'][3], wire['guest_udp'][2]
            else: wire['peer_udp'].append(dict(wire['peer_udp'][0]))
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_short_header_without_positive_stream_counter_refuses(self):
        output, fixture, wire = proof(); output = '\n'.join(line for line in output.splitlines() if not line.startswith('QUIC STREAM TX case=Q04 engine_ordinal=3 '))
        with self.assertRaisesRegex(RuntimeError, 'NOT_ESTABLISHED'): self.check(output, fixture, wire)

    def test_identical_later_datagram_annotation_cannot_prove_earlier_omission(self):
        output, fixture, wire = proof()
        output = '\n'.join(line for line in output.splitlines() if not line.startswith('QUIC STREAM TX case=Q04 engine_ordinal=3 '))
        output = output.replace('sha256=' + 'e' * 64, 'sha256=' + 'd' * 64)
        wire['guest_udp'][3]['sha256'] = 'd' * 64
        for row in fixture['events']:
            if row['event'] in ('udp-receive', 'engine-delivered') and row['receive_ordinal'] == 4:
                row['sha256'] = 'd' * 64
        with self.assertRaisesRegex(RuntimeError, 'NOT_ESTABLISHED'): self.check(output, fixture, wire)

    def test_counter_zero_rewind_missing_or_wrong_case_refuses(self):
        for before, after in (('stream_frames_after=1', 'stream_frames_after=0'), ('stream_frames_before=0', 'stream_frames_before=2'),
                              ('stream_frames_before=0', ''), ('QUIC STREAM TX case=Q04', 'QUIC STREAM TX case=Q01')):
            output, fixture, wire = proof()
            with self.subTest(field=before), self.assertRaises(RuntimeError): self.check(output.replace(before, after), fixture, wire)

    def test_observation_must_bind_exact_native_request_hash_and_size(self):
        for before, after in (('native_request_ordinal=3', 'native_request_ordinal=2'), ('accepted_ordinal=3', 'accepted_ordinal=0'),
                              ('accepted_ordinal=3', 'accepted_ordinal=2'),
                              ('engine_ordinal=3', 'engine_ordinal=5'), ('sha256=' + 'd' * 64, 'sha256=' + 'f' * 64),
                              ('bytes=500 sha256=' + 'd' * 64, 'bytes=499 sha256=' + 'd' * 64)):
            output, fixture, wire = proof()
            # Hash substitution changes both native reports, so capture still discriminates it.
            with self.subTest(field=before), self.assertRaises(RuntimeError): self.check(output.replace(before, after), fixture, wire)

    def test_complete_accepted_send_capture_counts_and_bytes_are_required(self):
        for before, after in (('send_bytes=2280', 'send_bytes=2281'), ('send_accepted=4', 'send_accepted=5')):
            output, fixture, wire = proof()
            with self.subTest(field=before), self.assertRaises(RuntimeError): self.check(output.replace(before, after), fixture, wire)

    def test_nonstream_owner_send_hash_and_order_also_bind_capture(self):
        for mutation in ('hash', 'order'):
            output, fixture, wire = proof()
            lines = output.splitlines()
            first = next(i for i, row in enumerate(lines) if row.startswith('QUIC FIXTURE SEND case=Q04 ordinal=1 '))
            second = next(i for i, row in enumerate(lines) if row.startswith('QUIC FIXTURE SEND case=Q04 ordinal=2 '))
            if mutation == 'hash': lines[first] = lines[first].replace('sha256=' + 'a' * 64, 'sha256=' + 'f' * 64)
            else:
                lines[first] = lines[first].replace('sha256=' + 'a' * 64, 'sha256=' + 'c' * 64).replace('bytes=1200 ', 'bytes=80 ')
                lines[second] = lines[second].replace('sha256=' + 'c' * 64, 'sha256=' + 'a' * 64).replace('bytes=80 ', 'bytes=1200 ')
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): self.check('\n'.join(lines), fixture, wire)

    def test_complete_none_cause_and_full_transfer_predicates_remain_strict(self):
        for before, after in (('transport_error_code=none', 'transport_error_code=1'), ('transport_close_origin=none', 'transport_close_origin=peer'),
                              ('authenticated=true', 'authenticated=false'), ('sent_stream=4096', 'sent_stream=4095'),
                              ('peer_fin=true', 'peer_fin=false'), ('request_acked=true', 'request_acked=false'),
                              ('connection_drained=true', 'connection_drained=false')):
            output, fixture, wire = proof()
            with self.subTest(field=before), self.assertRaises(RuntimeError): self.check(output.replace(before, after), fixture, wire)

    def test_original_deadline_resource_fence_and_selected_grant_remain_strict(self):
        for before, after in (('deadline_ms=10010', 'deadline_ms=10011'), ('owner_expiry_ms=15001', 'owner_expiry_ms=15002'),
                              ('handles_after=1', 'handles_after=2'), ('pipe_fenced=true', 'pipe_fenced=false'),
                              ('sends_after_fence=0', 'sends_after_fence=1'), ('local_port=7803', 'local_port=7800')):
            output, fixture, wire = proof()
            with self.subTest(field=before), self.assertRaises(RuntimeError): self.check(output.replace(before, after), fixture, wire)

    def test_omission_after_all_body_or_fin_is_not_established(self):
        for before in (4096, 4097):
            output, fixture, wire = proof(); one(fixture, 'stream-datagram-drop')['request_bytes_before'] = before
            with self.subTest(bytes=before), self.assertRaises(RuntimeError): self.check(output, fixture, wire)
        output, fixture, wire = proof(); one(fixture, 'stream-datagram-drop')['request_fin_before'] = True
        with self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_fixture_and_wire_numbers_require_nonnegative_json_ints(self):
        targets = [('fixture', 'stream_drops'), ('fixture', 'initial_drops'),
                   ('fixture', 'rx_datagrams'), ('fixture', 'rx_bytes'),
                   ('stream-datagram-drop', 'receive_ordinal'), ('stream-datagram-drop', 'bytes'),
                   ('stream-datagram-drop', 'first_byte'), ('stream-datagram-drop', 'request_bytes_before'),
                   ('handshake', 'receive_ordinal'), ('engine-delivered', 'bytes'),
                   ('udp-receive', 'bytes'), ('wire-initial', 'first_byte')]
        for target, field in targets:
            for value in (True, False, -1, 3.0, '3', None):
                output, fixture, wire = proof()
                if target == 'fixture': row = fixture
                elif target == 'wire-initial': row = wire['guest_udp'][0]
                else: row = next(row for row in fixture['events'] if row['event'] == target)
                row[field] = value
                with self.subTest(target=target, field=field, value=value), self.assertRaises(RuntimeError):
                    self.check(output, fixture, wire)

    def test_existing_q01_without_observer_remains_accepted(self):
        self.assertEqual(MATRIX.verify_native(BASE.CASE, *BASE.proof(), MANIFEST)['actual_outcome'], 'Complete')


if __name__ == '__main__':
    unittest.main()
