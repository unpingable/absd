#!/usr/bin/env python3
"""Q24 actual peer/socket and complete wire controls, authored only on build_host.

Run on the owned test VM with the exact public peer closure. Synthetic valid
Initial headers and callback receipts exercise fixture state/custody only;
they do not establish a real QEMU link transition or native typed outcome.
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


PEER = module('link_peer', ROOT/'native-quic-q01-peer.py')
WIRE = module('link_wire', ROOT/'native-quic-wire.py')
CASES = {row['id']:row for row in json.loads((ROOT.parent/'quic/CASES.json').read_text())['native_occurrences']}
# Public parser-valid QUICv1 Initial; no ciphertext validity/authentication claim.
PREFIX = b'\xc0\x00\x00\x00\x01\x08DCIDQ24!\x08SCIDQ24!\x00\x44\x96'
INITIAL = PREFIX + b'x' * (1200 - len(PREFIX))
GM, PM = '52:54:00:12:34:56', '02:71:00:00:00:02'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def acknowledgment():
    return {'qmp_acknowledged':True, 'qmp_receipt':'/fixture/QMP-LINK.json',
            'qmp_receipt_sha256':'a'*64, 'exact_qemu_pid':42, 'device_id':'quicnic'}


@contextmanager
def fixture(callback=None):
    """Use real kernel UDP queues and actual Peer methods, without a thread."""
    sender, receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for sock in (sender, receiver):
            sock.bind(('127.0.0.1', 0))
            sock.settimeout(0.1)
        action = mock.Mock(side_effect=callback if callback is not None else acknowledgment)
        value = object.__new__(PEER.Peer)
        value.__dict__.update(case=copy.deepcopy(CASES['Q24']), mode='link-failure', family='ipv4',
            pki=None, expected_source=sender.getsockname(), socket=receiver, connection=None,
            initial_sha256=None, marker_sent=False, marker_trigger=None, passive_receive_count=0,
            certificate_selection=None, authenticated=False, received=bytearray(), echoed=0,
            request_fin=False, echo_fin=False, terminated=None, rx_packets=0, tx_packets=0,
            rx_bytes=0, tx_bytes=0, started_io=False, deadline=time.monotonic()+1,
            operation_timeout=0.5, stop=threading.Event(), lock=threading.Lock(), events=[], errors=[],
            initial_drops=0, stream_drops=0, tag_batches=0, tag_mutations=0, reorder_calls=0,
            reorder_held=None, reorder_abandoned=False, reorder_batches=0, reorder_established=False,
            flow_started_ns=None, flow_until_ns=None, flow_released=False, flow_flushes=0,
            queue_fills=0, response_policy='standard', one_response_flight=False,
            response_flight_sealed=False, interrupt_stream_fenced=False, interrupt_stream_trigger=None,
            thread=threading.current_thread(), link_action=action, link_action_attempted=False,
            link_action_result=None, link_trigger=None)
        yield value, sender, action
    finally:
        sender.close()
        receiver.close()


def deliver(value, sender, data=INITIAL):
    assert sender.sendto(data, value.socket.getsockname()) == len(data)
    value.receive_link()


def frame(data, guest=True, case_id='Q24', sport=None):
    src, dst = ('10.0.2.15', '10.0.2.2') if guest else ('10.0.2.2', '10.0.2.15')
    sm, dm = (GM, PM) if guest else (PM, GM)
    sp, dp = (CASES[case_id]['local_port'], 4443) if guest else (4443, CASES[case_id]['local_port'])
    if sport is not None:
        sp = sport
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    udp = struct.pack('!HHHH', sp, dp, len(data)+8, 0)+data
    check = WIRE.checksum(s+d+b'\x00\x11'+struct.pack('!H', len(udp))+udp) or 0xffff
    udp = udp[:6]+struct.pack('!H', check)+udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp)+20, 1, 0x4000, 64, 17, 0, s, d)
    ip = ip[:10]+struct.pack('!H', WIRE.checksum(ip))+ip[12:]
    return bytes.fromhex(dm.replace(':', ''))+bytes.fromhex(sm.replace(':', ''))+b'\x08\x00'+ip+udp


def arp(reply=False):
    gm, pm = bytes.fromhex(GM.replace(':', '')), bytes.fromhex(PM.replace(':', ''))
    source, destination = (pm, gm) if reply else (gm, b'\xff'*6)
    sip, tip = ('10.0.2.2', '10.0.2.15') if reply else ('10.0.2.15', '10.0.2.2')
    target = gm if reply else b'\xff'*6
    return (destination+source+b'\x08\x06'+struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2 if reply else 1)
            +source+socket.inet_aton(sip)+target+socket.inet_aton(tip))


def pcap(frames):
    result = b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1)
    for index, data in enumerate(frames):
        result += struct.pack('<IIII', 1, index, len(data), len(data))+data
    return result


def observe(frames, case_id='Q24'):
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

    def receive_datagram(self, *args, **kwargs):
        self.calls.append('receive_datagram')


class LinkPeerControls(unittest.TestCase):
    def test_exact_q24_profile_and_standard_policy(self):
        self.assertEqual(PEER.development_profile(CASES['Q24']), 'q24-link-failure-development')
        self.assertEqual(PEER.Q24_LINK_POLICY, 'q24-link-failure-v1')
        self.assertEqual(PEER.response_policy(CASES['Q24']), 'standard')
        self.assertFalse(PEER.one_response_policy(CASES['Q24']))
        with self.assertRaises(RuntimeError):
            PEER.development_profile(CASES['Q24'], 'ipv6')

    def test_q24_profile_substitutions_refuse(self):
        for key, changed in (('local_port', 7800), ('peer_mode', 'echo'), ('expected_outcome', 'Complete'),
                             ('grant_lifetime_ms', 14999), ('missing_output', True), ('missing_time', True),
                             ('interrupt_phase', 'Handshake'), ('interrupt_delay_ms', 1), ('queue_control', True),
                             ('suppress_reply', True), ('native_error_codes', [8, 9, 10, 11])):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                PEER.development_profile(dict(CASES['Q24'], **{key:changed}))

    def test_missing_noncallable_or_foreign_callback_refuses_before_socket(self):
        with mock.patch.object(PEER.socket, 'socket', side_effect=AssertionError('socket opened')):
            for callback in (None, False, 1, acknowledgment()):
                with self.subTest(callback=callback), self.assertRaisesRegex(RuntimeError, 'callable link_action'):
                    PEER.Peer(CASES['Q24'], object(), '127.0.0.1', 0, ('127.0.0.1', 7823), link_action=callback)
            for case_id in ('Q01', 'Q08', 'Q21', 'Q22', 'Q23', 'Q29', 'Q30'):
                with self.subTest(case=case_id), self.assertRaisesRegex(RuntimeError, 'cannot carry a callback'):
                    PEER.Peer(CASES[case_id], object(), '127.0.0.1', 0, ('127.0.0.1', 7823), link_action=acknowledgment)

    def test_callback_is_keyword_only(self):
        with self.assertRaises(TypeError):
            PEER.Peer(CASES['Q24'], None, '127.0.0.1', 0, ('127.0.0.1', 7823), 1, 1, 'ipv4', acknowledgment)

    def test_actual_receipt_precedes_exact_callback_and_full_ledger(self):
        def callback():
            self.assertEqual([e['event'] for e in value.events],
                             ['udp-receive', 'initial-observed', 'link-failure-input', 'link-action-begin'])
            self.assertEqual(value.events[0]['data_hex'], INITIAL.hex())
            self.assertEqual(value.events[0]['source'], list(sender.getsockname()))
            self.assertEqual(value.link_trigger['sha256'], digest(INITIAL))
            self.assertTrue(value.link_action_attempted)
            self.assertEqual(value.rx_packets, 1)
            return acknowledgment()
        with fixture(callback) as (value, sender, action):
            deliver(value, sender)
            action.assert_called_once_with()
            row = value.events[-1]
            self.assertEqual(row['event'], 'link-action')
            self.assertEqual({key:row[key] for key in acknowledgment()}, acknowledgment())
            self.assertEqual((row['trigger_receive_ordinal'], row['trigger_sha256']), (1, digest(INITIAL)))
            self.assertFalse(value.events[2]['engine_delivered'])
            self.assertEqual((value.rx_bytes, value.tx_bytes, value.tx_packets), (1200, 0, 0))
            self.assertIsNone(value.connection)
            with self.assertRaises(socket.timeout):
                sender.recvfrom(65536)

    def test_later_actual_initials_keep_full_receipts_without_another_callback(self):
        with fixture() as (value, sender, action):
            inputs = [INITIAL, INITIAL[:-1]+b'y', INITIAL]
            for data in inputs:
                deliver(value, sender, data)
            action.assert_called_once_with()
            raw = [e for e in value.events if e['event'] == 'udp-receive']
            self.assertEqual([e['receive_ordinal'] for e in raw], [1, 2, 3])
            self.assertEqual([e['data_hex'] for e in raw], [data.hex() for data in inputs])
            self.assertTrue(all(e['engine_delivered'] is False for e in raw))
            self.assertEqual(len([e for e in value.events if e['event'] == 'initial-observed']), 1)
            self.assertEqual(len([e for e in value.events if e['event'] == 'link-failure-input']), 3)
            self.assertEqual(value.link_trigger['sha256'], digest(inputs[0]))
            self.assertEqual((value.tx_packets, value.tx_bytes), (0, 0))

    def test_action_before_receipt_and_after_completion_refuses(self):
        with fixture() as (value, sender, action):
            with self.assertRaisesRegex(RuntimeError, 'first parsed Initial'):
                value.perform_link_action()
            action.assert_not_called()
            deliver(value, sender)
            with self.assertRaisesRegex(RuntimeError, 'only once'):
                value.perform_link_action()
            action.assert_called_once_with()

    def test_substituted_action_trigger_refuses(self):
        for key, changed in (('receive_ordinal', 2), ('sha256', '0'*64), ('bytes', 1199)):
            with self.subTest(key=key), fixture() as (value, sender, action):
                with mock.patch.object(value, 'perform_link_action'):
                    deliver(value, sender)
                value.link_trigger[key] = changed
                with self.assertRaisesRegex(RuntimeError, 'first parsed Initial'):
                    value.perform_link_action()
                action.assert_not_called()

    def test_callback_exception_is_sticky_and_reported_without_udp(self):
        def fail():
            raise ValueError('exact callback failure')
        with fixture(fail) as (value, sender, action):
            sender.sendto(INITIAL, value.socket.getsockname())
            value.run()
            action.assert_called_once_with()
            self.assertEqual(value.errors[0]['type'], 'ValueError')
            self.assertIn('exact callback failure', value.errors[0]['message'])
            self.assertEqual(value.events[-2]['event'], 'link-action-failed')
            self.assertEqual(value.events[-1]['event'], 'peer-ended')
            self.assertTrue(value.link_action_attempted)
            self.assertIsNone(value.link_action_result)
            with self.assertRaisesRegex(RuntimeError, 'only once'):
                value.perform_link_action()
            action.assert_called_once_with()
            with self.assertRaises(socket.timeout):
                sender.recvfrom(65536)

    def test_missing_false_or_wrong_callback_binding_never_completes(self):
        variants = [None, [], {}, dict(acknowledgment(), qmp_acknowledged=False)]
        for key, changed in (('qmp_acknowledged', 1), ('qmp_receipt', ''), ('qmp_receipt', None),
                             ('qmp_receipt_sha256', 'x'*64), ('qmp_receipt_sha256', 'a'*63),
                             ('exact_qemu_pid', True), ('exact_qemu_pid', 0), ('exact_qemu_pid', '42'),
                             ('device_id', 'other')):
            variants.append(dict(acknowledgment(), **{key:changed}))
        for result in variants:
            with self.subTest(result=result), fixture(lambda:result) as (value, sender, action):
                with self.assertRaisesRegex(RuntimeError, 'acknowledged QMP receipt'):
                    deliver(value, sender)
                action.assert_called_once_with()
                self.assertTrue(value.link_action_attempted)
                self.assertIsNone(value.link_action_result)
                self.assertEqual(value.events[-1]['event'], 'link-action-failed')
                self.assertFalse(any(e['event'] == 'link-action' for e in value.events))

    def test_malformed_initials_are_retained_before_refusal_without_action(self):
        variants = [INITIAL[:1199], INITIAL+b'x', b'\x40'+INITIAL[1:]]
        variants += [INITIAL[:1]+v.to_bytes(4, 'big')+INITIAL[5:] for v in (0, 2, 0xffffffff)]
        variants += [bytes([v])+INITIAL[1:] for v in (0x80, 0xd0, 0xe0, 0xf0)]
        variants += [INITIAL[:5]+b'\xff'+INITIAL[6:]]
        for data in variants:
            with self.subTest(size=len(data), prefix=data[:6]), fixture() as (value, sender, action):
                with self.assertRaises((RuntimeError, ValueError)):
                    deliver(value, sender, data)
                self.assertEqual(value.events[0]['data_hex'], data.hex())
                self.assertEqual(value.events[0]['sha256'], digest(data))
                action.assert_not_called()
                self.assertFalse(value.link_action_attempted)
                self.assertIsNone(value.link_trigger)

    def test_wrong_source_retains_actual_input_before_refusal(self):
        with fixture() as (value, sender, action):
            value.expected_source = ('127.0.0.2', sender.getsockname()[1])
            with self.assertRaisesRegex(RuntimeError, 'unexpected source'):
                deliver(value, sender)
            self.assertEqual(value.events[0]['source'], list(sender.getsockname()))
            self.assertEqual(value.events[0]['data_hex'], INITIAL.hex())
            action.assert_not_called()

    def test_receive_event_budget_keeps_queued_kernel_input(self):
        with fixture() as (value, sender, action):
            value.events = [{} for _ in range(4089)]
            sender.sendto(INITIAL, value.socket.getsockname())
            with self.assertRaisesRegex(RuntimeError, 'ceiling before I/O'):
                value.receive_link()
            self.assertEqual(value.socket.recvfrom(65536)[0], INITIAL)
            self.assertEqual(value.rx_packets, 0)
            action.assert_not_called()

    def test_exact_event_reservation_boundary_allows_complete_transition(self):
        with fixture() as (value, sender, action):
            value.events = [{} for _ in range(4088)]
            deliver(value, sender)
            action.assert_called_once_with()
            self.assertEqual(len(value.events), 4093)
            self.assertEqual(value.events[-1]['event'], 'link-action')

    def test_callback_budget_refuses_before_external_action(self):
        with fixture() as (value, sender, action):
            with mock.patch.object(value, 'perform_link_action'):
                deliver(value, sender)
            value.events = [{} for _ in range(4094)]
            with self.assertRaisesRegex(RuntimeError, 'ceiling before I/O or callback'):
                value.perform_link_action()
            action.assert_not_called()
            self.assertFalse(value.link_action_attempted)

    def test_receive_packet_and_byte_ceiling_preserve_queued_input(self):
        for key, maximum in (('rx_packets', 512), ('rx_bytes', 512*1200)):
            with self.subTest(key=key), fixture() as (value, sender, action):
                setattr(value, key, maximum)
                sender.sendto(INITIAL, value.socket.getsockname())
                with self.assertRaisesRegex(RuntimeError, 'receive ceiling before I/O'):
                    value.receive_link()
                self.assertEqual(value.socket.recvfrom(65536)[0], INITIAL)
                action.assert_not_called()

    def test_actual_send_flush_timer_and_delivery_cannot_use_engine_or_udp(self):
        with fixture() as (value, sender, action):
            value.flush()
            value.drive_timer(123)
            with self.assertRaisesRegex(RuntimeError, 'cannot send UDP'):
                value.send(b'output')
            engine = PublicConnection()
            value.connection = engine
            for operation in (value.flush, lambda:value.drive_timer(123),
                              lambda:value.deliver_datagram(INITIAL, value.expected_source, 123)):
                with self.assertRaisesRegex(RuntimeError, 'engine|output-free'):
                    operation()
            self.assertEqual(engine.calls, [])
            self.assertEqual(value.tx_packets, 0)
            action.assert_not_called()
            with self.assertRaises(socket.timeout):
                sender.recvfrom(65536)

    def test_actual_delivery_preserves_minimal_prior_peer_fixtures(self):
        source, current = ('127.0.0.1', 4443), 123
        for mode in ('echo', 'stream-loss'):
            with self.subTest(mode=mode):
                engine = mock.Mock(spec=['receive_datagram'])
                value = object.__new__(PEER.Peer)
                value.__dict__.update(mode=mode, authenticated=True, connection=engine,
                    rx_packets=3, stream_drops=0, received=bytearray(b'abc'),
                    request_fin=False, lock=threading.Lock(), events=[])
                self.assertFalse(hasattr(value, 'case'))
                if mode == 'stream-loss':
                    self.assertFalse(value.deliver_datagram(b'\x40first', source, current))
                    engine.receive_datagram.assert_not_called()
                    self.assertEqual(value.stream_drops, 1)
                    self.assertEqual(value.events[0]['event'], 'stream-datagram-drop')
                    self.assertFalse(value.events[0]['engine_delivered'])
                self.assertTrue(value.deliver_datagram(b'\x40next', source, current))
                engine.receive_datagram.assert_called_once_with(b'\x40next', source, now=current)
                self.assertEqual(value.stream_drops, 1 if mode == 'stream-loss' else 0)
                self.assertEqual([e['event'] for e in value.events],
                    ['stream-datagram-drop', 'engine-delivered'] if mode == 'stream-loss' else [])

    def test_actual_constructor_thread_parser_and_callback_have_no_engine_or_pki(self):
        called = threading.Event()
        def callback():
            called.set()
            return acknowledgment()
        original = builtins.__import__
        def forbid_engine(name, *args, **kwargs):
            if name in ('aioquic.quic.connection', 'aioquic.quic.configuration'):
                raise AssertionError('Q24 imported an engine')
            return original(name, *args, **kwargs)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.bind(('127.0.0.1', 0))
            value = None
            try:
                with mock.patch('builtins.__import__', side_effect=forbid_engine):
                    value = PEER.Peer(CASES['Q24'], object(), '127.0.0.1', 0, sender.getsockname(),
                                      timeout=0.3, startup_timeout=1, link_action=callback)
                    sender.sendto(INITIAL, ('127.0.0.1', value.port))
                    self.assertTrue(called.wait(1), 'actual constructor thread did not call after Initial')
                    value.close()
                row = value.report()
                self.assertEqual(row['errors'], [])
                self.assertFalse(row['thread_alive'])
                self.assertTrue(row['link_action_completed'])
                self.assertIsNone(value.pki)
                self.assertIsNone(value.connection)
                self.assertEqual(row['tx_datagrams'], 0)
            finally:
                if value is not None and value.thread.is_alive():
                    value.close()

    def test_report_binds_policy_trigger_and_callback_without_private_material(self):
        with fixture() as (value, sender, _):
            deliver(value, sender)
            row = value.report()
            self.assertEqual(row['link_policy'], 'q24-link-failure-v1')
            self.assertTrue(row['link_action_attempted'])
            self.assertTrue(row['link_action_completed'])
            self.assertEqual(row['link_action_result'], acknowledgment())
            self.assertEqual(row['link_trigger']['receive_ordinal'], 1)
            self.assertEqual(row['link_trigger']['sha256'], digest(INITIAL))
            self.assertFalse(row['engine_constructed'])
            self.assertFalse(row['private_material_included'])
            self.assertIsNone(row['certificate_selection'])

    def test_pki_and_linux_q24_refuse_without_engine_or_socket(self):
        class NoRead:
            def __fspath__(self):
                raise AssertionError('PKI path read')
        self.assertIsNone(PEER.load_peer_pki(CASES['Q24'], NoRead()))
        with mock.patch.object(PEER.socket, 'socket', side_effect=AssertionError('socket opened')):
            with self.assertRaisesRegex(RuntimeError, 'separate Linux Q01'):
                PEER.linux_control(CASES['Q24'], None)
        with mock.patch('builtins.__import__', side_effect=AssertionError('engine imported')):
            with self.assertRaisesRegex(RuntimeError, 'cannot construct'):
                PEER.configuration(None, case=CASES['Q24'])


class LinkWireControls(unittest.TestCase):
    def test_all_arp_and_initial_frames_have_full_census_and_hashes(self):
        frames = [arp(), arp(True), frame(INITIAL), frame(INITIAL[:-1]+b'y')]
        row = observe(frames)
        self.assertEqual((row['frame_count'], row['arp_count'], row['guest_udp_count'], len(row['peer_udp'])), (4, 2, 2, 0))
        self.assertEqual(row['pcap_sha256'], digest(pcap(frames)))
        self.assertEqual([r['frame_sha256'] for r in row['frames']], [digest(f) for f in frames])
        self.assertEqual([r['ordinal'] for r in row['guest_udp']], [3, 4])
        self.assertEqual([r['data_hex'] for r in row['guest_udp']], [INITIAL.hex(), (INITIAL[:-1]+b'y').hex()])
        self.assertTrue(all(r['ip_checksum_valid'] and r['udp_checksum_valid'] for r in row['guest_udp']))

    def test_real_peer_receive_ledger_matches_every_capture_datagram(self):
        with fixture() as (value, sender, action):
            data = [INITIAL, INITIAL[:-1]+b'y']
            for item in data:
                deliver(value, sender, item)
            wire = observe([frame(item) for item in data])
            raw = [e for e in value.events if e['event'] == 'udp-receive']
            self.assertEqual([(e['bytes'], e['sha256'], e['data_hex']) for e in raw],
                             [(e['bytes'], e['sha256'], e['data_hex']) for e in wire['guest_udp']])
            self.assertEqual(len(raw), wire['guest_udp_count'])
            action.assert_called_once_with()

    def test_missing_initial_or_any_peer_udp_refuses(self):
        for frames in ([], [arp(), arp(True)], [frame(INITIAL, False)],
                       [frame(INITIAL), frame(b'output', False)],
                       [frame(INITIAL), frame(INITIAL, False)]):
            with self.subTest(frames=len(frames)), self.assertRaises(WIRE.Refusal):
                observe(frames)

    def test_checksum_valid_wrong_version_type_or_size_refuses(self):
        variants = [INITIAL[:1199], INITIAL+b'x']
        variants += [INITIAL[:1]+v.to_bytes(4, 'big')+INITIAL[5:] for v in (0, 2, 0xffffffff)]
        variants += [bytes([v])+INITIAL[1:] for v in (0x40, 0x80, 0xd0, 0xe0, 0xf0)]
        for data in variants:
            with self.subTest(prefix=data[:5], size=len(data)), self.assertRaises(WIRE.Refusal):
                observe([frame(data)])

    def test_wrong_tuple_checksum_mac_and_extra_frame_refuse(self):
        good = frame(INITIAL)
        variants = [[frame(INITIAL, sport=7822)], [frame(INITIAL, False, sport=4444)],
                    [good[:-1]+bytes([good[-1]^1])], [good[:6]+b'\x02\x00\x00\x00\x00\x03'+good[12:]],
                    [good, good[:12]+b'\x86\xdd'+good[14:]]]
        for frames in variants:
            with self.subTest(frames=len(frames)), self.assertRaises(WIRE.Refusal):
                observe(frames)

    def test_truncated_pcap_or_frame_is_never_trimmed_or_skipped(self):
        raw = pcap([frame(INITIAL)])
        for data in (raw[:23], raw[:-1], raw+b'x', raw[:24]+struct.pack('<IIII', 1, 0, 1200, 1242)+raw[40:]):
            with self.subTest(size=len(data)), self.assertRaises(WIRE.Refusal):
                WIRE.observe(data, CASES['Q24'], GM, PM)

    def test_finite_initial_count_boundary(self):
        row = observe([frame(INITIAL)]*256)
        self.assertEqual((row['guest_udp_count'], row['guest_udp_bytes']), (256, 307200))
        with self.assertRaises(WIRE.Refusal):
            observe([frame(INITIAL)]*257)

    def test_q24_selector_does_not_change_other_direction_or_marker_contracts(self):
        with self.assertRaises(WIRE.Refusal):
            observe([frame(INITIAL, case_id='Q01')], 'Q01')
        self.assertEqual(observe([frame(INITIAL, case_id='Q01'), frame(b'reply', False, 'Q01')], 'Q01')['guest_udp_count'], 1)
        marker = b'\x00ABSD-QUIC-Q23-INITIAL-OBSERVED'
        self.assertEqual(observe([frame(INITIAL, case_id='Q23'), frame(marker, False, 'Q23')], 'Q23')['guest_udp_count'], 1)
        for case_id in ('Q29', 'Q30'):
            self.assertEqual(observe([], case_id)['udp_count'], 0)
            with self.assertRaises(WIRE.Refusal):
                observe([frame(INITIAL, case_id=case_id)], case_id)


if __name__ == '__main__':
    unittest.main(verbosity=2)
