#!/usr/bin/env python3
"""Owned-host ICMP peer methods and full-capture refusal controls.

Real Linux UDP queues and the public aioquic header parser are exercised with
a controlled raw-frame socket. These controls do not establish AF_PACKET/TAP
emission, native feedback or authenticated QUIC; the guest run must do that.
"""
import copy
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import socket
import struct
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PEER = module('icmp_peer', 'native-quic-q01-peer.py')
WIRE = module('icmp_wire', 'native-quic-wire.py')
BASE = module('icmp_link_vectors', 'test-native-quic-link-peer.py')
CASES = {row['id']:row for row in json.loads((ROOT.parent/'quic/CASES.json').read_text())['native_occurrences']}
GM, PM = BASE.GM, BASE.PM
INITIAL = BASE.INITIAL


class RawSocket:
    """Deterministic raw transport with an observable call/result boundary."""
    def __init__(self, frames=(), outcome=None):
        self.frames, self.sent = list(frames), []
        self.outcome, self.closed = outcome, False
        self.address = ('fixture0', 0x0800, 0, 1, bytes.fromhex(PM.replace(':', '')))

    def recvfrom(self, size):
        return self.frames.pop(0), self.address

    def send(self, data):
        self.sent.append(bytes(data))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return len(data) if self.outcome is None else self.outcome

    def close(self):
        self.closed = True

    def bind(self, address):
        self.bound = address

    def getsockname(self):
        return self.address

    def setblocking(self, value):
        self.blocking = value


@contextmanager
def fixture(identity='Q25', outcome=None):
    # Reuse the existing real-UDP minimal Peer substrate; no existing control
    # method runs here. Only new actual ICMP methods are invoked explicitly.
    with BASE.fixture() as (old, sender, _):
        value = object.__new__(PEER.Peer)
        value.__dict__.update(old.__dict__)
        value.case, value.mode = copy.deepcopy(CASES[identity]), CASES[identity]['peer_mode']
        raw = RawSocket(outcome=outcome)
        value.__dict__.update(icmp_interface='fixture0', icmp_guest_mac=GM, icmp_peer_mac=PM,
            raw_socket=raw, raw_socket_closed=False, raw_rx_frames=0, raw_rx_bytes=0,
            icmp_guest_frames=[], icmp_socket_rows=[], icmp_send_attempted=False,
            icmp_send_completed=False, icmp_failed=False, icmp_send_result=None, icmp_trigger=None,
            thread=SimpleNamespace(is_alive=lambda:False, join=lambda **kwargs:None))
        try:
            yield value, sender, raw
        finally:
            value.close_icmp_socket()


def original(identity='Q25', data=INITIAL):
    return BASE.frame(data, case_id=identity)


def deliver_udp(value, sender, data=INITIAL, emit=True):
    assert sender.sendto(data, value.socket.getsockname()) == len(data)
    value.receive_icmp_udp(emit=emit)


def deliver_frame(value, raw, frame=None, emit=True):
    raw.frames.append(original(value.case['id']) if frame is None else frame)
    value.receive_icmp_frame(emit=emit)


def expected_error(frame, mtu):
    # Independent literal RFC792/1191 encoder, not Peer.icmp_frame.
    body = struct.pack('!BBHHH', 3, 4, 0, 0, mtu)+frame[14:42]
    body = body[:2]+struct.pack('!H', WIRE.checksum(body))+body[4:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 56, 0x5149, 0, 64, 1, 0,
                     socket.inet_aton('10.0.2.2'), socket.inet_aton('10.0.2.15'))
    ip = ip[:10]+struct.pack('!H', WIRE.checksum(ip))+ip[12:]
    return bytes.fromhex(GM.replace(':', ''))+bytes.fromhex(PM.replace(':', ''))+b'\x08\x00'+ip+body


def fix_error(frame):
    value = bytearray(frame)
    value[36:38] = b'\0\0'
    value[36:38] = struct.pack('!H', WIRE.checksum(bytes(value[34:])))
    value[24:26] = b'\0\0'
    value[24:26] = struct.pack('!H', WIRE.checksum(bytes(value[14:34])))
    return bytes(value)


def observe(frames, identity='Q25'):
    return WIRE.observe(BASE.pcap(frames), CASES[identity], GM, PM)


class PeerMethods(unittest.TestCase):
    def test_only_exact_three_canonical_profiles_are_enabled(self):
        for identity, profile in (('Q25','q25-icmp-576-development'), ('Q26','q26-icmp-1227-development'),
                                  ('Q28','q28-icmp-zero-development')):
            self.assertEqual(PEER.development_profile(CASES[identity]), profile)
            self.assertIsNone(PEER.load_peer_pki(CASES[identity], '/not-read'))
            with self.assertRaisesRegex(RuntimeError, 'IPv6'):
                PEER.development_profile(CASES[identity], 'ipv6')
        with self.assertRaises(RuntimeError):
            PEER.development_profile(dict(CASES['Q27'], peer_mode='icmp-1228', icmp_mtu=1228))

    def test_canonical_case_mutations_refuse(self):
        for identity in ('Q25', 'Q26', 'Q28'):
            for key, value in (('local_port',7800), ('icmp_mtu',1228), ('expected_outcome','Complete'),
                               ('grant_lifetime_ms',16000), ('missing_output',True), ('missing_time',True),
                               ('interrupt_phase','Handshake'), ('interrupt_delay_ms',1),
                               ('queue_control',True), ('suppress_reply',True), ('native_error_codes',[9])):
                with self.subTest(case=identity, key=key), self.assertRaises(RuntimeError):
                    PEER.development_profile(dict(CASES[identity], **{key:value}))
        for mtu in (False, 0.0, '0', None):
            changed=dict(CASES['Q28'],icmp_mtu=mtu)
            with self.subTest(mtu=mtu),self.assertRaises(RuntimeError):PEER.development_profile(changed)
            with self.subTest(wire_mtu=mtu),self.assertRaises(WIRE.Refusal):
                WIRE.observe(BASE.pcap([original('Q28'),expected_error(original('Q28'),0)]),changed,GM,PM)

    def test_exact_constructor_binds_owned_packet_interface_before_udp(self):
        raw, udp = RawSocket(), mock.Mock()
        udp.getsockname.return_value = ('10.0.2.2',4443)
        thread = mock.Mock()
        with mock.patch.object(PEER.socket, 'socket', side_effect=[udp, raw]) as opened, \
             mock.patch.object(PEER.threading, 'Thread', return_value=thread):
            value = PEER.Peer(CASES['Q25'], object(), '10.0.2.2',4443,('10.0.2.15',7824),
                icmp_interface='fixture0', icmp_guest_mac=GM, icmp_peer_mac=PM)
            self.assertEqual(opened.call_args_list[1], mock.call(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)))
            self.assertEqual(raw.bound, ('fixture0',0x0800))
            udp.bind.assert_called_once_with(('10.0.2.2',4443))
            self.assertIsNone(value.pki)
            thread.start.assert_called_once()
            value.close_icmp_socket()
            self.assertTrue(raw.closed)

    def test_constructor_rejects_invalid_authority_before_socket_creation(self):
        valid = dict(icmp_interface='fixture0', icmp_guest_mac=GM, icmp_peer_mac=PM)
        for changes in ({'icmp_interface':None}, {'icmp_interface':'bad/name'}, {'icmp_guest_mac':PM},
                        {'icmp_peer_mac':'ff:ff:ff:ff:ff:ff'}, {'icmp_guest_mac':'00:00:00:00:00:00'}):
            with mock.patch.object(PEER.socket, 'socket', side_effect=AssertionError('socket created')), \
                 self.subTest(changes=changes), self.assertRaises(RuntimeError):
                PEER.Peer(CASES['Q25'], None,'10.0.2.2',4443,('10.0.2.15',7824), **dict(valid, **changes))
        for bind, port, source in (('127.0.0.1',4443,('10.0.2.15',7824)),
                                   ('10.0.2.2',4444,('10.0.2.15',7824)),
                                   ('10.0.2.2',4443,('10.0.2.15',7800))):
            with mock.patch.object(PEER.socket, 'socket', side_effect=AssertionError('socket created')), \
                 self.subTest(bind=bind, port=port, source=source), self.assertRaises(RuntimeError):
                PEER.Peer(CASES['Q25'],None,bind,port,source,**valid)
        with self.assertRaisesRegex(RuntimeError, 'only available'):
            PEER.Peer(CASES['Q01'],None,'127.0.0.1',0,('127.0.0.1',1),**valid)

    def test_wrong_actual_interface_mac_closes_both_created_sockets(self):
        raw, udp = RawSocket(), mock.Mock()
        raw.address = ('fixture0',0x0800,0,1,b'\x02'*6)
        with mock.patch.object(PEER.socket,'socket',side_effect=[udp,raw]), \
             self.assertRaisesRegex(RuntimeError,'actual ICMP interface MAC differs'):
            PEER.Peer(CASES['Q25'],None,'10.0.2.2',4443,('10.0.2.15',7824),
                icmp_interface='fixture0',icmp_guest_mac=GM,icmp_peer_mac=PM)
        self.assertTrue(raw.closed)
        udp.close.assert_called_once()

    def test_actual_udp_then_actual_frame_emits_exactly_one_literal_quote(self):
        for identity in ('Q25','Q26','Q28'):
            with self.subTest(case=identity), fixture(identity) as (value,sender,raw):
                deliver_udp(value,sender)
                self.assertEqual(raw.sent,[])
                deliver_frame(value,raw)
                self.assertEqual(raw.sent,[expected_error(original(identity),CASES[identity]['icmp_mtu'])])
                self.assertEqual(value.icmp_trigger['data_hex'],INITIAL.hex())
                self.assertEqual(value.icmp_trigger['frame_hex'],original(identity).hex())
                self.assertEqual(value.icmp_trigger['quote_hex'],original(identity)[14:42].hex())
                self.assertEqual(value.icmp_trigger['receive_ordinal'],1)
                self.assertEqual(value.icmp_trigger['raw_frame_ordinal'],1)
                self.assertEqual(value.icmp_send_result['actual_sent_bytes'],70)
                self.assertTrue(value.icmp_send_attempted and value.icmp_send_completed)
                events=[row['event'] for row in value.events]
                self.assertLess(events.index('udp-receive'),events.index('initial-observed'))
                self.assertLess(events.index('icmp-frame-receive'),events.index('icmp-send-begin'))
                self.assertLess(events.index('icmp-send-begin'),events.index('icmp-send'))

    def test_raw_frame_before_udp_waits_for_actual_socket_and_public_parser(self):
        with fixture() as (value,sender,raw):
            deliver_frame(value,raw)
            self.assertEqual(raw.sent,[])
            deliver_udp(value,sender)
            self.assertEqual(len(raw.sent),1)
            self.assertEqual([row['event'] for row in value.events[:3]],
                             ['icmp-frame-receive','udp-receive','initial-observed'])

    def test_later_initials_and_method_reentry_cannot_send_again(self):
        with fixture() as (value,sender,raw):
            for _ in range(3):
                deliver_frame(value,raw)
                deliver_udp(value,sender)
                value.try_icmp_send()
            self.assertEqual((len(raw.sent),value.rx_packets,value.raw_rx_frames),(1,3,3))
            self.assertEqual(value.icmp_trigger['receive_ordinal'],1)

    def test_full_body_mismatch_with_valid_same_udp_checksum_cannot_quote(self):
        changed = bytearray(INITIAL)
        # Preserve the checksum sum while altering two complete 16-bit words.
        changed[-4:-2]=(int.from_bytes(changed[-4:-2],'big')+1).to_bytes(2,'big')
        changed[-2:]=(int.from_bytes(changed[-2:],'big')-1).to_bytes(2,'big')
        actual = original(data=bytes(changed))
        self.assertEqual(actual[14:42],original()[14:42])
        with fixture() as (value,sender,raw):
            deliver_frame(value,raw,actual)
            with self.assertRaisesRegex(RuntimeError,'raw frame and actual socket Initial differ'):
                deliver_udp(value,sender)
            self.assertTrue(value.icmp_failed)
            self.assertEqual(raw.sent,[])

    def test_wrong_actual_udp_source_is_recorded_then_refused(self):
        with fixture() as (value,sender,raw):
            value.expected_source=('127.0.0.2',sender.getsockname()[1])
            with self.assertRaisesRegex(RuntimeError,'exact source'):
                deliver_udp(value,sender)
            self.assertEqual((value.rx_packets,len(value.events),raw.sent),(1,1,[]))

    def test_public_header_parser_refuses_malformed_1200_byte_input(self):
        malformed=b'\xc0\0\0\0\1\xff'+b'\0'*1194
        with fixture() as (value,sender,raw):
            with self.assertRaises((ValueError,RuntimeError)):
                deliver_udp(value,sender,malformed)
            self.assertEqual(value.icmp_socket_rows,[])
            self.assertEqual(raw.sent,[])

    def test_actual_original_frame_checksums_tuple_flags_and_full_size_are_checked(self):
        for offset in (0,6,12,14,16,20,22,23,24,26,30,34,36,38,40,100):
            changed=bytearray(original());changed[offset]^=1
            with self.subTest(offset=offset), self.assertRaises(RuntimeError):
                PEER.icmp_original(bytes(changed),CASES['Q25'],GM,PM)
        for data in (original()[:-1],original()+b'\0'):
            with self.assertRaises(RuntimeError):PEER.icmp_original(data,CASES['Q25'],GM,PM)

    def test_every_raw_input_is_recorded_before_interface_or_parse_refusal(self):
        with fixture() as (value,sender,raw):
            raw.address=('other0',0x0800,0,1,raw.address[4])
            with self.assertRaisesRegex(RuntimeError,'another interface'):
                deliver_frame(value,raw)
            self.assertEqual((value.raw_rx_frames,value.raw_rx_bytes),(1,1242))
            self.assertEqual(value.events[0]['frame_hex'],original().hex())

    def test_local_outgoing_copy_is_accounted_but_never_reused_as_trigger(self):
        with fixture() as (value,sender,raw):
            deliver_frame(value,raw);deliver_udp(value,sender)
            raw.address=('fixture0',0x0800,4,1,raw.address[4])
            deliver_frame(value,raw,raw.sent[0])
            self.assertEqual((value.raw_rx_frames,len(value.icmp_guest_frames),len(raw.sent)),(2,1,1))
            self.assertEqual(value.events[-1]['packet_type'],4)

    def test_unrelated_raw_peer_frame_cannot_count_as_local_output_copy(self):
        with fixture() as (value,sender,raw):
            with self.assertRaisesRegex(RuntimeError,'exact emitted local copy'):
                deliver_frame(value,raw,expected_error(original(),576))
            self.assertEqual(raw.sent,[])

    def test_partial_raw_send_is_sticky_and_never_retried(self):
        with fixture(outcome=69) as (value,sender,raw):
            deliver_frame(value,raw)
            with self.assertRaisesRegex(RuntimeError,'partial ICMP'):
                deliver_udp(value,sender)
            self.assertTrue(value.icmp_send_attempted and value.icmp_failed)
            self.assertFalse(value.icmp_send_completed)
            raw.outcome=None
            with self.assertRaisesRegex(RuntimeError,'permanently refused'):
                value.try_icmp_send()
            self.assertEqual(len(raw.sent),1)
            self.assertFalse(any(row['event']=='icmp-send' for row in value.events))

    def test_ambiguous_raw_send_error_is_sticky_and_never_retried(self):
        with fixture(outcome=OSError('controlled send error')) as (value,sender,raw):
            deliver_udp(value,sender)
            with self.assertRaisesRegex(OSError,'controlled send error'):
                deliver_frame(value,raw)
            self.assertTrue(value.icmp_send_attempted and value.icmp_failed)
            self.assertIsNone(value.icmp_send_result)
            with self.assertRaisesRegex(RuntimeError,'permanently refused'):value.try_icmp_send()
            self.assertEqual(len(raw.sent),1)

    def test_deadline_or_stop_before_send_is_permanent_even_after_clock_extension(self):
        for stopped in (False,True):
            with self.subTest(stopped=stopped), fixture() as (value,sender,raw):
                deliver_udp(value,sender,emit=False);deliver_frame(value,raw,emit=False)
                if stopped:value.stop.set()
                else:value.deadline=time.monotonic()-1
                with self.assertRaisesRegex(RuntimeError,'after stop or deadline'):value.try_icmp_send()
                value.stop.clear();value.deadline=time.monotonic()+1
                with self.assertRaisesRegex(RuntimeError,'permanently refused'):value.try_icmp_send()
                self.assertEqual(raw.sent,[])

    def test_deadline_crossing_actual_send_retains_effect_and_permanently_refuses(self):
        with fixture() as (value,sender,raw):
            deliver_udp(value,sender,emit=False);deliver_frame(value,raw,emit=False)
            deadline=value.deadline
            with mock.patch.object(PEER.time,'monotonic',side_effect=[deadline-1,deadline-1,deadline+1]), \
                 self.assertRaisesRegex(RuntimeError,'actual effect retained'):
                value.try_icmp_send()
            self.assertTrue(value.icmp_send_completed and value.icmp_failed)
            self.assertEqual(value.icmp_send_result['actual_sent_bytes'],70)
            self.assertTrue(any(row['event']=='icmp-send' for row in value.events))
            with self.assertRaisesRegex(RuntimeError,'permanently refused'):value.try_icmp_send()
            self.assertEqual(len(raw.sent),1)

    def test_event_ceiling_refuses_before_consuming_actual_udp_or_raw_input(self):
        with fixture() as (value,sender,raw):
            value.events=[{}]*4089
            sender.sendto(INITIAL,value.socket.getsockname());raw.frames=[original()]
            with self.assertRaisesRegex(RuntimeError,'event ceiling'):value.receive_icmp_udp()
            with self.assertRaisesRegex(RuntimeError,'event ceiling'):value.receive_icmp_frame()
            self.assertEqual(value.socket.recvfrom(65536)[0],INITIAL)
            self.assertEqual(raw.frames,[original()])
            self.assertEqual((value.rx_packets,value.raw_rx_frames),(0,0))

    def test_receive_census_limits_precede_consumption(self):
        with fixture() as (value,sender,raw):
            value.rx_packets=256;value.raw_rx_frames=512
            sender.sendto(INITIAL,value.socket.getsockname());raw.frames=[original()]
            with self.assertRaisesRegex(RuntimeError,'receive ceiling'):value.receive_icmp_udp()
            with self.assertRaisesRegex(RuntimeError,'receive ceiling'):value.receive_icmp_frame()
            self.assertEqual(value.socket.recvfrom(65536)[0],INITIAL)
            self.assertEqual(raw.frames,[original()])

    def test_run_error_retires_raw_socket_and_preserves_actual_failure(self):
        with fixture() as (value,sender,raw):
            raw.frames=[b'wrong-frame']
            with mock.patch.object(PEER.select,'select',side_effect=[([raw],[],[]),([],[],[])]):
                value.run_icmp()
            self.assertTrue(raw.closed and value.raw_socket_closed and value.icmp_failed)
            self.assertTrue(value.errors)
            self.assertEqual(raw.sent,[])
            self.assertEqual(value.events[-1]['event'],'peer-ended')

    def test_stopped_run_drains_existing_queues_without_emission_then_closes(self):
        with fixture() as (value,sender,raw):
            value.stop.set();raw.frames=[original()]
            sender.sendto(INITIAL,value.socket.getsockname())
            with mock.patch.object(PEER.select,'select',side_effect=[([raw,value.socket],[],[]),([],[],[])]):
                value.run_icmp()
            self.assertTrue(raw.closed and value.raw_socket_closed)
            self.assertEqual((value.rx_packets,value.raw_rx_frames,raw.sent),(1,1,[]))
            self.assertEqual(value.errors,[])

    def test_actual_report_exposes_full_census_retirement_and_send_identity(self):
        with fixture() as (value,sender,raw):
            deliver_frame(value,raw);deliver_udp(value,sender);value.close()
            report=value.report()
            self.assertEqual(report['icmp_policy'],PEER.ICMP_POLICY)
            self.assertTrue(report['raw_socket_closed'] and report['icmp_send_completed'])
            self.assertFalse(report['engine_constructed'] or report['thread_alive'])
            self.assertEqual((report['raw_rx_frames'],report['raw_rx_bytes'],report['rx_datagrams'],report['rx_bytes']),
                             (1,1242,1,1200))
            self.assertEqual((report['tx_datagrams'],report['tx_bytes'],report['request_bytes'],report['echo_enqueued_bytes']),
                             (0,0,0,0))
            self.assertEqual(report['icmp_send_result']['sha256'],PEER.digest(raw.sent[0]))

    def test_engine_pki_udp_and_timer_routes_remain_unavailable(self):
        with fixture() as (value,sender,raw):
            for operation in (lambda:value.send(INITIAL), lambda:value.deliver_datagram(INITIAL,value.expected_source,0)):
                with self.assertRaisesRegex(RuntimeError,'ICMP'):operation()
            value.drive_timer(time.monotonic());value.flush()
            with self.assertRaisesRegex(RuntimeError,'cannot construct an engine'):
                PEER.configuration(None,client=True,case=CASES['Q25'])
            self.assertEqual(raw.sent,[])
            self.assertEqual(value.events,[])


class WireControls(unittest.TestCase):
    def test_full_capture_all_three_profiles_binds_original_and_exact_icmp(self):
        for identity in ('Q25','Q26','Q28'):
            initial=original(identity)
            error=expected_error(initial,CASES[identity]['icmp_mtu'])
            result=observe([initial,error],identity)
            self.assertEqual((result['frame_count'],result['udp_count'],len(result['icmp'])),(2,1,1))
            self.assertEqual(result['peer_udp'],[])
            self.assertEqual(result['guest_udp'][0]['data_hex'],INITIAL.hex())
            proof=result['icmp'][0]
            self.assertEqual(proof['quote_hex'],initial[14:42].hex())
            self.assertEqual(proof['submitted_frame_sha256'],PEER.digest(initial))
            self.assertEqual((proof['ordinal'],proof['quoted_frame_ordinal']),(2,1))

    def test_missing_duplicate_and_prior_icmp_refuse(self):
        initial=original();error=expected_error(initial,576)
        for frames in ([initial],[initial,error,error],[error,initial]):
            with self.subTest(count=len(frames)),self.assertRaises(WIRE.Refusal):observe(frames)

    def test_ordinary_echo_does_not_substitute_for_icmp(self):
        with self.assertRaises(WIRE.Refusal):observe([original(),BASE.frame(INITIAL,False,'Q25')])

    def test_wrong_mtu_unused_fields_type_and_code_refuse_with_valid_checksums(self):
        initial=original()
        for offset in (34,35,38,39,40,41):
            changed=bytearray(expected_error(initial,576));changed[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(WIRE.Refusal):observe([initial,fix_error(changed)])

    def test_checksum_and_outer_tuple_mutations_refuse(self):
        initial=original()
        for offset in (0,6,12,24,26,30,36,54,60,68):
            changed=bytearray(expected_error(initial,576));changed[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(WIRE.Refusal):observe([initial,bytes(changed)])

    def test_changed_inner_quote_refuses_even_with_recomputed_inner_outer_checksums(self):
        initial=original()
        for offset in (46,50,54,58,62,64,66,68):
            changed=bytearray(expected_error(initial,576));changed[offset]^=1
            changed[52:54]=b'\0\0'
            changed[52:54]=struct.pack('!H',WIRE.checksum(bytes(changed[42:62])))
            with self.subTest(offset=offset),self.assertRaises(WIRE.Refusal):observe([initial,fix_error(changed)])

    def test_wrong_selected_case_and_q27_stay_refused(self):
        initial=original();error=expected_error(initial,576)
        with self.assertRaises(WIRE.Refusal):observe([initial,error],'Q26')
        with self.assertRaises(WIRE.Refusal):observe([original('Q27'),expected_error(original('Q27'),1228)],'Q27')
        with self.assertRaises(WIRE.Refusal):
            WIRE.observe(BASE.pcap([BASE.frame(INITIAL,case_id='Q01'),error]),CASES['Q01'],GM,PM)

    def test_truncated_capture_unknown_frame_and_noninitial_guest_refuse(self):
        initial=original();error=expected_error(initial,576)
        with self.assertRaises(WIRE.Refusal):WIRE.observe(BASE.pcap([initial,error])[:-1],CASES['Q25'],GM,PM)
        changed=bytearray(initial);changed[6]^=1
        with self.assertRaises(WIRE.Refusal):observe([initial,error,bytes(changed)])
        bad=original(data=b'x'*1200)
        with self.assertRaises(WIRE.Refusal):observe([bad,expected_error(bad,576)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
