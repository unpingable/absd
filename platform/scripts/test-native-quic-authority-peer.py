#!/usr/bin/env python3
"""Finite authority-peer controls. Authored here; run only on the owned VM.

Actual Peer methods and Linux UDP sockets establish local I/O/ledger behavior.
Synthetic public Initial headers do not establish authenticated QUIC traffic,
ABSD execution, owner expiry or native startup-role/time refusal.
"""
import builtins
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PEER = module('authority_peer', ROOT/'native-quic-q01-peer.py')
WIRE = module('authority_wire', ROOT/'native-quic-wire.py')
MANIFEST = json.loads((ROOT.parent/'quic/CASES.json').read_text())
CASES = {row['id']:row for row in MANIFEST['native_occurrences']}
# Public parser-valid QUICv1 Initial: 8-byte destination/source CIDs, empty
# token, 1174-byte protected packet body. No decryption/authentication claim.
PREFIX = b'\xc0\x00\x00\x00\x01\x08DCIDQ23!\x08SCIDQ23!\x00\x44\x96'
INITIAL = PREFIX + b'x' * (1200 - len(PREFIX))
MARKER = b'\x00ABSD-QUIC-Q23-INITIAL-OBSERVED'
GM, PM = '52:54:00:12:34:56', '02:71:00:00:00:02'


def digest(data):
    return hashlib.sha256(data).hexdigest()


@contextmanager
def fixture(case_id='Q23'):
    """No thread/engine; call the production receive/send methods on real UDP."""
    sender, receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for sock in (sender, receiver):
            sock.bind(('127.0.0.1', 0))
            sock.settimeout(0.1)
        value = object.__new__(PEER.Peer)
        value.__dict__.update(case=copy.deepcopy(CASES[case_id]), mode=CASES[case_id]['peer_mode'],
            family='ipv4', pki=None, expected_source=sender.getsockname(), socket=receiver,
            connection=None, initial_sha256=None, marker_sent=False, marker_trigger=None,
            passive_receive_count=0, certificate_selection=None, authenticated=False,
            received=bytearray(), echoed=0, request_fin=False, echo_fin=False, terminated=None,
            rx_packets=0, tx_packets=0, rx_bytes=0, tx_bytes=0, started_io=False,
            deadline=time.monotonic()+1, operation_timeout=0.5, stop=threading.Event(),
            lock=threading.Lock(), events=[], errors=[], initial_drops=0, stream_drops=0,
            tag_batches=0, tag_mutations=0, reorder_calls=0, reorder_held=None,
            reorder_abandoned=False, reorder_batches=0, reorder_established=False,
            flow_started_ns=None, flow_until_ns=None, flow_released=False, flow_flushes=0,
            queue_fills=0, response_policy='standard', one_response_flight=False,
            response_flight_sealed=False, interrupt_stream_fenced=False,
            interrupt_stream_trigger=None, thread=threading.current_thread())
        yield value, sender
    finally:
        sender.close()
        receiver.close()


def deliver(value, sender, data=INITIAL):
    assert sender.sendto(data, value.socket.getsockname()) == len(data)
    value.receive_authority()


def frame(data, case_id='Q23', guest=True, sport=None):
    src, dst = ('10.0.2.15', '10.0.2.2') if guest else ('10.0.2.2', '10.0.2.15')
    sm, dm = (GM, PM) if guest else (PM, GM)
    sp, dp = (CASES[case_id]['local_port'], 4443) if guest else (4443, CASES[case_id]['local_port'])
    if sport is not None:
        sp = sport
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    udp = struct.pack('!HHHH', sp, dp, len(data)+8, 0)+data
    udp = udp[:6]+struct.pack('!H', WIRE.checksum(s+d+b'\x00\x11'+struct.pack('!H', len(udp))+udp) or 0xffff)+udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp)+20, 1, 0x4000, 64, 17, 0, s, d)
    ip = ip[:10]+struct.pack('!H', WIRE.checksum(ip))+ip[12:]
    return bytes.fromhex(dm.replace(':', ''))+bytes.fromhex(sm.replace(':', ''))+b'\x08\x00'+ip+udp


def pcap(frames):
    result = b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1)
    for index, data in enumerate(frames):
        result += struct.pack('<IIII', 1, index, len(data), len(data))+data
    return result


def observe(frames, case_id='Q23'):
    return WIRE.observe(pcap(frames), CASES[case_id], GM, PM)


class PublicConnection:
    def __init__(self):
        self.calls = []

    def get_timer(self):
        self.calls.append('get_timer')
        return 0

    def handle_timer(self, **kwargs):
        self.calls.append('handle_timer')

    def datagrams_to_send(self, **kwargs):
        self.calls.append('datagrams_to_send')
        return [(b'output', ('127.0.0.1', 4443))]


class AuthorityPeerControls(unittest.TestCase):
    def test_exact_profiles(self):
        for case_id, policy in (('Q23', 'q23-owner-expiry-v1'), ('Q29', 'q29-missing-output-v1'), ('Q30', 'q30-missing-time-v1')):
            self.assertEqual(PEER.development_profile(CASES[case_id]), policy.removesuffix('-v1')+'-development')
            self.assertEqual(PEER.AUTHORITY_POLICIES[case_id], policy)

    def test_profile_tuple_and_flags_refuse(self):
        for case_id in ('Q23', 'Q29', 'Q30'):
            for key, changed in (('local_port', 7800), ('peer_mode', 'echo'), ('expected_outcome', 'Complete'),
                                 ('grant_lifetime_ms', 2999), ('missing_output', not CASES[case_id]['missing_output']),
                                 ('missing_time', not CASES[case_id]['missing_time']), ('interrupt_phase', 'Handshake'),
                                 ('interrupt_delay_ms', 1), ('queue_control', True), ('suppress_reply', True)):
                with self.subTest(case=case_id, key=key), self.assertRaises(RuntimeError):
                    PEER.development_profile(dict(CASES[case_id], **{key:changed}))
        with self.assertRaisesRegex(RuntimeError, 'marker'):
            PEER.development_profile(dict(CASES['Q23'], observation_marker_hex='00'))

    def test_authority_profiles_are_not_ipv6(self):
        for case_id in ('Q23', 'Q29', 'Q30'):
            with self.assertRaises(RuntimeError):
                PEER.development_profile(CASES[case_id], 'ipv6')

    def test_real_initial_causes_one_exact_marker_and_ordered_custody(self):
        with fixture() as (value, sender):
            deliver(value, sender)
            self.assertEqual(sender.recvfrom(65536)[0], MARKER)
            self.assertEqual([row['event'] for row in value.events],
                ['udp-receive', 'initial-observed', 'owner-expiry-input', 'udp-send', 'expiry-observation-marker'])
            self.assertEqual(value.events[0]['data_hex'], INITIAL.hex())
            self.assertEqual(value.events[0]['receive_ordinal'], 1)
            self.assertEqual(value.events[3]['data_hex'], MARKER.hex())
            self.assertEqual(value.events[3]['send_ordinal'], 1)
            self.assertEqual(value.marker_trigger, {'receive_ordinal':1, 'bytes':1200, 'sha256':digest(INITIAL),
                'marker_hex':MARKER.hex(), 'marker_sha256':digest(MARKER), 'destination':list(sender.getsockname())})
            self.assertEqual((value.tx_packets, value.tx_bytes), (1, len(MARKER)))
            self.assertIsNone(value.connection)

    def test_repeated_initial_receipts_never_send_a_second_marker(self):
        with fixture() as (value, sender):
            deliver(value, sender)
            sender.recvfrom(65536)
            deliver(value, sender, INITIAL[:-1]+b'y')
            self.assertEqual(value.rx_packets, 2)
            self.assertEqual(len([r for r in value.events if r['event'] == 'owner-expiry-input']), 2)
            self.assertEqual(value.marker_trigger['sha256'], digest(INITIAL))
            with self.assertRaises(socket.timeout):
                sender.recvfrom(65536)
            self.assertEqual(value.tx_packets, 1)

    def test_marker_send_before_initial_and_other_bytes_refuse_without_io(self):
        with fixture() as (value, sender):
            with self.assertRaisesRegex(RuntimeError, 'only one canonical'):
                value.send(MARKER, fixture='owner-expiry-marker')
            deliver(value, sender)
            sender.recvfrom(65536)
            for data, tag in ((MARKER, 'owner-expiry-marker'), (b'x', None), (MARKER, 'long-retry')):
                with self.subTest(data=data, tag=tag), self.assertRaises(RuntimeError):
                    value.send(data, fixture=tag)
            with self.assertRaises(socket.timeout):
                sender.recvfrom(65536)

    def test_first_marker_exact_bytes_tag_and_trigger_are_required(self):
        for mutation in ('bytes', 'tag', 'hash', 'ordinal'):
            with self.subTest(mutation=mutation), fixture() as (value, sender):
                # Establish the actual parsed socket receipt, delaying its send
                # only in this deterministic negative-control setup.
                with mock.patch.object(value, 'send'):
                    deliver(value, sender)
                data, tag = MARKER, 'owner-expiry-marker'
                if mutation == 'bytes':
                    data = MARKER[:-1]+b'x'
                elif mutation == 'tag':
                    tag = None
                elif mutation == 'hash':
                    value.marker_trigger['sha256'] = '0'*64
                else:
                    value.marker_trigger['receive_ordinal'] = 2
                with self.assertRaisesRegex(RuntimeError, 'only one canonical'):
                    value.send(data, fixture=tag)
                self.assertEqual(value.tx_packets, 0)
                with self.assertRaises(socket.timeout):
                    sender.recvfrom(65536)

    def test_checksum_independent_public_initial_shape_refuses(self):
        variants = [INITIAL[:1199], INITIAL+b'x', b'\x40'+INITIAL[1:]]
        variants += [INITIAL[:1]+version.to_bytes(4, 'big')+INITIAL[5:] for version in (0, 2, 0xffffffff)]
        variants += [bytes([kind])+INITIAL[1:] for kind in (0x80, 0xd0, 0xe0, 0xf0)]
        for data in variants:
            with self.subTest(size=len(data), prefix=data[:5]), fixture() as (value, sender):
                with self.assertRaises((RuntimeError, ValueError)):
                    deliver(value, sender, data)
                self.assertEqual(value.events[0]['data_hex'], data.hex())
                self.assertEqual(value.tx_packets, 0)
                self.assertIsNone(value.marker_trigger)

    def test_passive_actual_input_is_retained_then_refused(self):
        for case_id in ('Q29', 'Q30'):
            with self.subTest(case=case_id), fixture(case_id) as (value, sender):
                with self.assertRaisesRegex(RuntimeError, 'passive fixture unexpectedly'):
                    deliver(value, sender, b'unexpected input')
                self.assertEqual([row['event'] for row in value.events], ['udp-receive', 'passive-input'])
                self.assertEqual(value.events[0]['data_hex'], b'unexpected input'.hex())
                self.assertEqual(value.passive_receive_count, 1)
                self.assertEqual((value.tx_packets, value.echoed, len(value.received)), (0, 0, 0))
                with self.assertRaises(socket.timeout):
                    sender.recvfrom(65536)

    def test_wrong_tuple_and_oversize_keep_exact_received_bytes(self):
        for wrong_tuple in (False, True):
            with self.subTest(tuple=wrong_tuple), fixture() as (value, sender):
                if wrong_tuple:
                    value.expected_source = ('127.0.0.1', sender.getsockname()[1]+1)
                data = INITIAL if wrong_tuple else INITIAL+b'x'
                with self.assertRaisesRegex(RuntimeError, 'unexpected source|ceiling'):
                    deliver(value, sender, data)
                self.assertEqual(value.events[0]['data_hex'], data.hex())
                self.assertEqual((value.rx_packets, value.rx_bytes, value.tx_packets), (1, len(data), 0))

    def test_actual_run_passive_branch_never_imports_engine(self):
        original = builtins.__import__
        def refuse_engine(name, *args, **kwargs):
            if name.startswith('aioquic'):
                raise AssertionError('passive run imported aioquic')
            return original(name, *args, **kwargs)
        for case_id in ('Q29', 'Q30'):
            with self.subTest(case=case_id), fixture(case_id) as (value, sender):
                sender.sendto(b'input', value.socket.getsockname())
                with mock.patch('builtins.__import__', side_effect=refuse_engine):
                    value.run()
                self.assertEqual(value.errors[0]['type'], 'RuntimeError')
                self.assertIn('passive fixture unexpectedly', value.errors[0]['message'])
                self.assertEqual(value.events[0]['data_hex'], b'input'.hex())
                self.assertEqual(value.events[-1]['event'], 'peer-ended')

    def test_actual_constructor_and_run_keep_authority_profiles_engine_free(self):
        original = builtins.__import__
        def refuse_engine(name, *args, **kwargs):
            if name in ('aioquic.quic.connection', 'aioquic.quic.configuration'):
                raise AssertionError('authority run imported an engine/configuration')
            return original(name, *args, **kwargs)
        for case_id in ('Q23', 'Q29', 'Q30'):
            with self.subTest(case=case_id), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.bind(('127.0.0.1', 0))
                sender.settimeout(1)
                value = None
                try:
                    with mock.patch('builtins.__import__', side_effect=refuse_engine):
                        value = PEER.Peer(CASES[case_id], object(), '127.0.0.1', 0,
                                          sender.getsockname(), timeout=0.2, startup_timeout=1)
                        if case_id == 'Q23':
                            sender.sendto(INITIAL, ('127.0.0.1', value.port))
                            self.assertEqual(sender.recvfrom(65536)[0], MARKER)
                        value.close()
                        row = value.report()
                    self.assertIsNone(value.pki)
                    self.assertIsNone(value.connection)
                    self.assertEqual(row['errors'], [])
                    self.assertFalse(row['thread_alive'])
                    self.assertEqual(row['tx_datagrams'], int(case_id == 'Q23'))
                finally:
                    if value is not None and value.thread.is_alive():
                        value.close()

    def test_actual_flush_and_timer_do_no_engine_work(self):
        for case_id in ('Q23', 'Q29', 'Q30'):
            with self.subTest(case=case_id), fixture(case_id) as (value, _):
                value.flush()
                value.drive_timer(123)
                engine = PublicConnection()
                value.connection = engine
                with self.assertRaisesRegex(RuntimeError, 'engine-free'):
                    value.flush()
                with self.assertRaisesRegex(RuntimeError, 'engine-free'):
                    value.drive_timer(123)
                self.assertEqual(engine.calls, [])
                self.assertEqual(value.tx_packets, 0)

    def test_passive_send_refuses_on_actual_dispatch(self):
        for case_id in ('Q29', 'Q30'):
            with self.subTest(case=case_id), fixture(case_id) as (value, sender):
                with self.assertRaises(RuntimeError):
                    value.send(MARKER, fixture='owner-expiry-marker')
                self.assertEqual(value.tx_packets, 0)
                with self.assertRaises(socket.timeout):
                    sender.recvfrom(65536)

    def test_no_authority_pki_path_is_read(self):
        class NoRead:
            def __fspath__(self):
                raise AssertionError('authority PKI path read')
        for case_id in ('Q23', 'Q29', 'Q30'):
            self.assertIsNone(PEER.load_peer_pki(CASES[case_id], NoRead()))
        with self.assertRaisesRegex(RuntimeError, 'PKI is required'):
            PEER.load_peer_pki(CASES['Q01'], None)

    def test_linux_passive_dispatch_refuses_before_engine_or_sockets(self):
        with mock.patch.object(PEER, 'configuration', side_effect=AssertionError('engine config called')), \
             mock.patch.object(PEER.socket, 'socket', side_effect=AssertionError('socket opened')):
            for case_id in ('Q29', 'Q30'):
                with self.assertRaisesRegex(RuntimeError, 'no Linux socket equivalent'):
                    PEER.linux_control(CASES[case_id], None)

    def test_receive_event_exhaustion_does_not_consume_queued_kernel_bytes(self):
        with fixture() as (value, sender):
            value.events = [{} for _ in range(4089)]
            sender.sendto(INITIAL, value.socket.getsockname())
            with self.assertRaisesRegex(RuntimeError, 'ceiling before I/O'):
                value.receive_authority()
            self.assertEqual(value.socket.recvfrom(65536)[0], INITIAL)
            self.assertEqual(value.rx_packets, 0)

    def test_send_event_exhaustion_emits_no_kernel_bytes(self):
        with fixture() as (value, sender):
            value.rx_packets = 1
            value.initial_sha256 = digest(INITIAL)
            value.marker_trigger = {'receive_ordinal':1, 'sha256':digest(INITIAL)}
            value.events = [{} for _ in range(4089)]
            with self.assertRaisesRegex(RuntimeError, 'ceiling before I/O'):
                value.send(MARKER, fixture='owner-expiry-marker')
            with self.assertRaises(socket.timeout):
                sender.recvfrom(65536)
            self.assertEqual(value.tx_packets, 0)

    def test_receive_packet_ceiling_preserves_kernel_bytes(self):
        with fixture() as (value, sender):
            value.rx_packets = 512
            sender.sendto(INITIAL, value.socket.getsockname())
            with self.assertRaisesRegex(RuntimeError, 'receive ceiling before I/O'):
                value.receive_authority()
            self.assertEqual(value.socket.recvfrom(65536)[0], INITIAL)

    def test_report_binds_authority_policy_and_no_engine(self):
        for case_id in ('Q23', 'Q29', 'Q30'):
            with self.subTest(case=case_id), fixture(case_id) as (value, _):
                row = value.report()
                self.assertEqual(row['authority_policy'], PEER.AUTHORITY_POLICIES[case_id])
                self.assertFalse(row['engine_constructed'])
                self.assertFalse(row['marker_sent'])
                self.assertIsNone(row['marker_trigger'])
                self.assertIsNone(row['certificate_selection'])


class AuthorityWireControls(unittest.TestCase):
    def test_exact_marker_after_initial_and_repeat_initial_census(self):
        row = observe([frame(INITIAL), frame(MARKER, guest=False), frame(INITIAL)])
        self.assertEqual((row['guest_udp_count'], len(row['peer_udp'])), (2, 1))
        self.assertEqual(row['peer_udp'][0]['data_hex'], MARKER.hex())
        self.assertEqual(row['guest_udp'][0]['long_header_version'], 1)
        self.assertTrue(all(r['ip_checksum_valid'] and r['udp_checksum_valid'] for r in row['guest_udp']))

    def test_empty_passive_capture(self):
        for case_id in ('Q29', 'Q30'):
            row = observe([], case_id)
            self.assertEqual((row['frame_count'], row['guest_udp_count'], len(row['peer_udp'])), (0, 0, 0))

    def test_passive_any_udp_in_either_direction_refuses(self):
        for case_id in ('Q29', 'Q30'):
            for guest in (False, True):
                with self.subTest(case=case_id, guest=guest), self.assertRaises(WIRE.Refusal):
                    observe([frame(INITIAL, case_id, guest)], case_id)

    def test_marker_order_extra_missing_or_wrong_bytes_refuse(self):
        good = [frame(INITIAL), frame(MARKER, guest=False)]
        variants = [good[::-1], good[:1], good+[good[1]],
                    [good[0], frame(MARKER[:-1]+b'x', guest=False)],
                    [good[0], frame(INITIAL, guest=False)]]
        for frames in variants:
            with self.subTest(frames=len(frames)), self.assertRaises(WIRE.Refusal):
                observe(frames)

    def test_recomputed_checksum_wrong_version_type_or_size_refuses(self):
        for data in [INITIAL[:1]+v.to_bytes(4, 'big')+INITIAL[5:] for v in (0, 2, 0xffffffff)] + \
                    [bytes([v])+INITIAL[1:] for v in (0x40, 0x80, 0xd0, 0xe0, 0xf0)] + [INITIAL[:1199]]:
            with self.subTest(prefix=data[:5]), self.assertRaises(WIRE.Refusal):
                observe([frame(data), frame(MARKER, guest=False)])

    def test_wrong_marker_source_port_checksum_or_extra_frame_refuses(self):
        initial, reply = frame(INITIAL), frame(MARKER, guest=False)
        corrupted = reply[:-1]+bytes([reply[-1]^1])
        for frames in ([initial, frame(MARKER, guest=False, sport=4444)],
                       [initial, corrupted], [initial, reply, initial[:12]+b'\x86\xdd'+initial[14:]]):
            with self.subTest(frames=len(frames)), self.assertRaises(WIRE.Refusal):
                observe(frames)

    def test_existing_q01_still_requires_both_directions(self):
        with self.assertRaises(WIRE.Refusal):
            observe([frame(INITIAL, 'Q01')], 'Q01')
        row = observe([frame(INITIAL, 'Q01'), frame(b'reply', 'Q01', False)], 'Q01')
        self.assertEqual((row['guest_udp_count'], len(row['peer_udp'])), (1, 1))


if __name__ == '__main__':
    unittest.main(verbosity=2)
