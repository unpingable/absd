#!/usr/bin/env python3
"""Finite Q06 source/correspondence controls; actual flow blocking is runtime-only."""
import copy
import importlib.util
from pathlib import Path
import threading
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('q06_base', ROOT / 'native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(BASE)
MATRIX, PEER, WIRE, MANIFEST = BASE.MATRIX, BASE.PEER_MODULE, BASE.WIRE, BASE.MANIFEST
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q06')
GUEST = bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e7d115b0011e120717569632d77697265000000000000000000')
PEER_PACKET = bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e7d0011e120717569632d77697265000000000000000000')


def line(prefix, row): return prefix + ' ' + ' '.join(key + '=' + str(value) for key, value in row.items())
def event(fixture, name):
    rows = [row for row in fixture['events'] if row['event'] == name]
    if len(rows) != 1: raise RuntimeError('one exact synthetic event required: ' + name)
    return rows[0]


def proof():
    output, fixture, wire = BASE.proof(); lines = []
    for text in output.splitlines():
        if text.startswith(('QUIC FIXTURE SEND ', 'QUIC FIXTURE RX ')): continue
        row = MATRIX.fields(text)
        if row.get('case') != 'Q01': lines.append(text); continue
        prefix = text.split(' case=', 1)[0]
        row['case'] = 'Q06'
        if 'local_port' in row: row['local_port'] = '7805'
        if prefix == 'QUIC RESULT':
            row.update(engine_transmits='2', send_calls='2', send_accepted='2', send_bytes='1300',
                       received='2', receive_bytes='2400', last_send_ms='25', fence_ms='400', end_ms='401')
        if prefix == 'QUIC FIXTURE NATIVE_COUNTS': row.update(send_requests='2', receive_delivered='2')
        lines.append(line(prefix, row))
    for ordinal, size, digest, at in ((1,1200,'a'*64,15),(2,100,'c'*64,25)):
        lines.append(line('QUIC FIXTURE SEND', dict(case='Q06', ordinal=ordinal, bytes=size, sha256=digest,
                                                   at_ms=at, peer_ip='10.0.2.2', peer_port=4443)))
    for ordinal, digest, at in ((1,'b'*64,18),(2,'d'*64,290)):
        lines.append(line('QUIC FIXTURE RX', dict(case='Q06', ordinal=ordinal, bytes=1200, sha256=digest,
                                                 at_ms=at, peer_ip='10.0.2.2', peer_port=4443)))
    lines += [
        'QUIC FLOW BLOCKED case=Q06 at_ms=20 sent_stream=1024 requested=512 authenticated=true max_data_received=0 max_stream_data_received=0',
        'QUIC FLOW TX case=Q06 engine_ordinal=2 native_request_ordinal=2 accepted_ordinal=2 bytes=100 sha256='+ 'c'*64 + ' data_blocked_before=0 data_blocked_after=1 authenticated=true',
        'QUIC FLOW CREDIT case=Q06 at_ms=290 receive_ordinal=2 bytes=1200 sha256='+ 'd'*64 + ' max_data_before=0 max_data_after=1 max_stream_data_before=0 max_stream_data_after=1',
        'QUIC FLOW RESUMED case=Q06 at_ms=291 sent_before=1024 written=512 max_data_received=1 max_stream_data_received=1']
    guest, peer = ['10.0.2.15',7805], ['10.0.2.2',4443]
    first = dict(event='udp-receive', bytes=1200, sha256='a'*64, source=list(guest))
    blocked = dict(event='udp-receive', bytes=100, sha256='c'*64, source=list(guest))
    handshake = dict(event='udp-send', bytes=1200, sha256='b'*64, source=list(peer), destination=list(guest))
    credit = dict(event='udp-send', bytes=1200, sha256='d'*64, source=list(peer), destination=list(guest))
    begin = 1_000_000_000
    fixture.update(mode='flow-pause', readiness_profile='q06-flow-pause-development', flow_released=True,
                   flow_started_ns=begin, flow_flushes=3, rx_datagrams=2, rx_bytes=1300, tx_datagrams=2, tx_bytes=2400)
    fixture['events'] = [dict(event='q06-configuration', max_data=1024, max_stream_data=1024, hold_ns=250_000_000),
        first, dict(event='initial-observed', bytes=1200, sha256='a'*64),
        dict(event='q06-public-flush', ordinal=1, request_bytes=0, released=False), handshake,
        dict(event='request-stream', stream_id=0, offset=0, bytes=1024, fin=False),
        dict(event='q06-pause-start', request_bytes=1024, request_fin=False, started_ns=begin,
             until_ns=begin+250_000_000, monotonic_ns=begin+1, tx_datagrams=1, tx_bytes=1200, public_flushes=1),
        blocked,
        dict(event='q06-pause-release', request_bytes=1024, request_fin=False, started_ns=begin,
             released_ns=begin+250_000_000, monotonic_ns=begin+250_000_001, tx_datagrams=1, tx_bytes=1200, public_flushes=1),
        dict(event='q06-public-flush', ordinal=2, request_bytes=1024, released=True), credit,
        dict(event='request-stream', stream_id=0, offset=1024, bytes=3072, fin=True),
        dict(event='q06-public-flush', ordinal=3, request_bytes=4096, released=True)]
    wire['guest_udp'] = [dict(bytes=row['bytes'], sha256=row['sha256'], source=list(guest), destination=list(peer)) for row in (first,blocked)]
    wire['peer_udp'] = [dict(bytes=row['bytes'], sha256=row['sha256'], source=list(peer), destination=list(guest)) for row in (handshake,credit)]
    return '\n'.join(lines), fixture, wire


def peer():
    value = object.__new__(PEER.Peer)
    value.mode, value.case, value.family = 'flow-pause', CASE, 'ipv4'
    value.flow_started_ns = value.flow_until_ns = None
    value.flow_released, value.flow_flushes = False, 0
    value.received, value.request_fin = bytearray(1024), False
    value.tx_packets, value.tx_bytes = 1, 1200
    value.lock, value.events = threading.Lock(), []
    return value


class PublicConnection:
    """Finite public API fixture; output construction is observable even empty."""
    def __init__(self): self.output_calls, self.timer_calls = [], []
    def datagrams_to_send(self, now): self.output_calls.append(now); return []
    def get_timer(self): return 0.0
    def handle_timer(self, now): self.timer_calls.append(now)


class FlowPauseControls(unittest.TestCase):
    def check(self, output, fixture, wire): return MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)

    def test_exact_case_joint_profile_port_and_standard_policy(self):
        self.assertEqual((CASE['peer_mode'],CASE['local_port'],CASE['expected_outcome']),('flow-pause',7805,'Complete'))
        self.assertEqual(MATRIX.development_profile(CASE),'q06-flow-pause-development')
        self.assertEqual(PEER.development_profile(CASE),'q06-flow-pause-development')
        self.assertEqual((PEER.peer_certificate(CASE),PEER.peer_terminal_codes(CASE),PEER.response_policy(CASE)),('valid',(0,),'standard'))

    def test_wrong_case_mode_port_and_ipv6_refuse(self):
        for case in (dict(CASE,id='Q01'),dict(CASE,peer_mode='echo'),dict(CASE,local_port=7800)):
            with self.subTest(case=case):
                with self.assertRaises(RuntimeError):MATRIX.development_profile(case)
                with self.assertRaises(RuntimeError):PEER.development_profile(case)
                with self.assertRaises(WIRE.Refusal):WIRE.observe(BASE.pcap([GUEST,PEER_PACKET]),case,'52:54:00:12:34:56','02:71:00:00:00:02')
        with self.assertRaises(RuntimeError):MATRIX.development_profile(CASE,'ipv6')
        with self.assertRaises(RuntimeError):PEER.development_profile(CASE,'ipv6')

    def test_literal7805_checksums_and_ordinary_port_refusal(self):
        result=WIRE.observe(BASE.pcap([BASE.ARP_BROADCAST,GUEST,PEER_PACKET]),CASE,'52:54:00:12:34:56','02:71:00:00:00:02')
        self.assertEqual(result['guest_udp'][0]['source'][1],7805)
        self.assertTrue(all(row['ip_checksum_valid']and row['udp_checksum_valid']for row in result['guest_udp']+result['peer_udp']))
        with self.assertRaises(WIRE.Refusal):WIRE.observe(BASE.pcap([BASE.GUEST,BASE.PEER]),CASE,'52:54:00:12:34:56','02:71:00:00:00:02')

    def test_actual_public_configuration_selects_only_q06_small_credit(self):
        class Config:
            def __init__(self, **values): self.__dict__.update(values)
            def load_cert_chain(self, certificate, key): self.loaded=(certificate,key)
        top, mid, module = (types.ModuleType(name) for name in ('aioquic','aioquic.quic','aioquic.quic.configuration'))
        top.__path__=[];mid.__path__=[];top.quic=mid;mid.configuration=module;module.QuicConfiguration=Config
        pki={'leaf_certificates':{'valid':{'path':'unused-public.pem'}},'leaf_private_key_path':'unused-private-fixture-path'}
        with mock.patch.dict('sys.modules',{'aioquic':top,'aioquic.quic':mid,'aioquic.quic.configuration':module}):
            selected=PEER.configuration(pki,case=CASE)
            original=PEER.configuration(pki,case=BASE.CASE)
        self.assertEqual((selected.max_data,selected.max_stream_data,selected.max_datagram_size),(1024,1024,1200))
        self.assertEqual((original.max_data,original.max_stream_data),(8192,8192))
        self.assertIsNone(selected.quic_logger);self.assertIsNone(selected.secrets_log_file)

    def test_actual_peer_starts_at_first_progress_above_half_credit(self):
        value=peer()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_000_000_000):value.flow_progress()
        self.assertEqual((value.flow_started_ns,value.flow_until_ns),(1_000_000_000,1_250_000_000))
        self.assertEqual(event({'events':value.events},'q06-pause-start')['request_bytes'],1024)
        for size in (513,768,900,1024):
            value=peer();value.received=bytearray(size)
            with self.subTest(size=size),mock.patch.object(PEER.time,'monotonic_ns',return_value=1_000_000_000):value.flow_progress()
            self.assertEqual(event({'events':value.events},'q06-pause-start')['request_bytes'],size)
        for size in (0,512):
            value=peer();value.received=bytearray(size);value.flow_progress();self.assertIsNone(value.flow_started_ns)
        for size in (1025,4096):
            value=peer();value.received=bytearray(size)
            with self.subTest(size=size),self.assertRaisesRegex(RuntimeError,'^NOT_ESTABLISHED: Q06 exact initial-credit boundary absent$'):value.flow_progress()

    def test_actual_peer_withholds_all_public_construction_then_releases(self):
        value=peer()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_000_000_000):value.flow_progress()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_249_999_999):self.assertFalse(value.flow_may_flush())
        self.assertEqual(value.flow_flushes,0)
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_250_000_000):self.assertTrue(value.flow_may_flush())
        self.assertTrue(value.flow_released);self.assertIsNone(value.flow_until_ns)
        self.assertEqual(value.flow_flushes,1)

    def test_actual_flush_never_constructs_output_during_hold_and_once_on_release(self):
        value=peer();value.one_response_flight=False;value.connection=PublicConnection()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_000_000_000):value.flow_progress()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_249_999_999):value.flush()
        self.assertEqual(value.connection.output_calls,[])
        self.assertEqual(value.flow_flushes,0)
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_250_000_000),mock.patch.object(PEER.time,'monotonic',return_value=1.25):value.flush()
        self.assertEqual(value.connection.output_calls,[1.25])
        self.assertTrue(value.flow_released);self.assertIsNone(value.flow_until_ns)
        self.assertEqual(value.flow_flushes,1)

    def test_actual_due_timer_preserves_output_hold_then_flushes_once_after_release(self):
        value=peer();value.one_response_flight=False;value.connection=PublicConnection()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_000_000_000):value.flow_progress()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_249_999_999):value.drive_timer(1.2)
        self.assertEqual(value.connection.timer_calls,[1.2])
        self.assertEqual(value.connection.output_calls,[])
        self.assertEqual(value.flow_flushes,0)
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_250_000_000),mock.patch.object(PEER.time,'monotonic',return_value=1.25):value.drive_timer(1.25)
        self.assertEqual(value.connection.timer_calls,[1.2,1.25])
        self.assertEqual(value.connection.output_calls,[1.25])
        self.assertTrue(value.flow_released);self.assertEqual(value.flow_flushes,1)

    def test_actual_early_credit_or_advanced_plateau_or_late_release_refuses(self):
        value=peer()
        with self.assertRaises(RuntimeError):value.flow_may_flush()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_000_000_000):value.flow_progress()
        value.received.extend(b'x')
        with self.assertRaises(RuntimeError):value.flow_may_flush()
        value.received=bytearray(1024)
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=2_000_000_001),self.assertRaises(RuntimeError):value.flow_may_flush()

    def test_actual_socket_send_cannot_bypass_active_hold(self):
        value=peer();value.one_response_flight=False
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_000_000_000):value.flow_progress()
        with self.assertRaisesRegex(RuntimeError,'cannot bypass'):value.send(b'frame')

    def test_synthetic_full_native_block_credit_resumption_calibrates(self):
        self.assertEqual(self.check(*proof())['actual_outcome'],'Complete')

    def test_weaker_linux_calibration_cannot_replace_native_observations(self):
        output,fixture,wire=proof()
        linux=copy.deepcopy(fixture)
        for row in linux['events']:
            if row['event']=='udp-send':row.update(source=['127.0.0.1',50002],destination=['127.0.0.1',50001])
            if row['event']=='udp-receive':row['source']=['127.0.0.1',50001]
        MATRIX.verify_flow_pause(CASE,linux)
        output='\n'.join(row for row in output.splitlines()if not row.startswith('QUIC FLOW '))
        with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):self.check(output,fixture,wire)

    def test_plateau_or_release_labels_without_construction_boundary_refuse(self):
        for name in ('q06-configuration','q06-pause-start','q06-pause-release','q06-public-flush'):
            output,fixture,wire=proof();fixture['events']=[row for row in fixture['events']if row['event']!=name]
            with self.subTest(event=name),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_changed_credit_hold_or_stationary_census_refuses(self):
        for name,key,value in [('q06-configuration','max_data',8192),('q06-configuration','max_stream_data',8192),
                               ('q06-configuration','hold_ns',249_000_000),('q06-pause-release','tx_datagrams',2),
                               ('q06-pause-release','request_bytes',1025),('q06-pause-release','released_ns',1_249_999_999)]:
            output,fixture,wire=proof();event(fixture,name)[key]=value
            with self.subTest(name=name,key=key),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_send_or_public_flush_during_hold_refuses(self):
        for name in ('udp-send','q06-public-flush'):
            output,fixture,wire=proof();row=next(row for row in fixture['events']if row['event']==name)
            fixture['events'].insert(fixture['events'].index(event(fixture,'q06-pause-release')),copy.deepcopy(row))
            with self.subTest(name=name),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_early_expansion_or_wrong_native_blocked_position_refuses(self):
        for before,after in [('sent_stream=1024 requested','sent_stream=1023 requested'),('requested=512','requested=0'),
                             ('authenticated=true max_data_received','authenticated=false max_data_received'),
                             ('max_data_received=0','max_data_received=1'),('max_stream_data_received=0','max_stream_data_received=1')]:
            output,fixture,wire=proof()
            with self.subTest(before=before),self.assertRaises(RuntimeError):self.check(output.replace(before,after),fixture,wire)

    def test_ack_or_unaccepted_send_cannot_supply_public_data_blocked(self):
        for before,after in [('data_blocked_after=1','data_blocked_after=0'),('accepted_ordinal=2','accepted_ordinal=1'),
                             ('native_request_ordinal=2','native_request_ordinal=1'),('data_blocked_before=0','data_blocked_before=1')]:
            output,fixture,wire=proof()
            with self.subTest(before=before),self.assertRaises(RuntimeError):self.check(output.replace(before,after),fixture,wire)

    def test_blocked_ciphertext_must_reach_peer_during_hold(self):
        output,fixture,wire=proof();row=fixture['events'].pop(7);fixture['events'].insert(8,row)
        with self.assertRaisesRegex(RuntimeError,'^NOT_ESTABLISHED: actual native DATA_BLOCKED did not reach peer during credit hold$'):self.check(output,fixture,wire)
        output,fixture,wire=proof();output=output.replace('bytes=100 sha256='+'c'*64+' data_blocked','bytes=100 sha256='+'e'*64+' data_blocked')
        with self.assertRaisesRegex(RuntimeError,'^Q06 positive public DATA_BLOCKED counter lacks exact accepted SEND/capture$'):self.check(output,fixture,wire)

    def test_never_blocks_refuses_at_missing_native_blocked_witness(self):
        output,fixture,wire=proof();output='\n'.join(row for row in output.splitlines()if not row.startswith('QUIC FLOW BLOCKED '))
        with self.assertRaisesRegex(RuntimeError,'^NOT_ESTABLISHED: Q06 actual native blocking/transmit/credit/resumption absent$'):self.check(output,fixture,wire)

    def test_never_resumes_refuses_at_missing_native_resumed_witness(self):
        output,fixture,wire=proof();output='\n'.join(row for row in output.splitlines()if not row.startswith('QUIC FLOW RESUMED '))
        with self.assertRaisesRegex(RuntimeError,'^NOT_ESTABLISHED: Q06 actual native blocking/transmit/credit/resumption absent$'):self.check(output,fixture,wire)

    def test_actual_intermediate_progress_holds_output_until_exact_credit_release(self):
        value=peer();value.received=bytearray(900);value.one_response_flight=False;value.connection=PublicConnection()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_000_000_000):value.flow_progress()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_100_000_000):value.flush()
        self.assertEqual(value.connection.output_calls,[])
        value.received.extend(b'x'*124)
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_200_000_000):value.flow_progress();value.flush()
        self.assertEqual(value.connection.output_calls,[])
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_250_000_000),mock.patch.object(PEER.time,'monotonic',return_value=1.25):value.flush()
        self.assertEqual(value.connection.output_calls,[1.25]);self.assertTrue(value.flow_released)

    def test_actual_incomplete_initial_credit_refuses_release_without_constructing_output(self):
        value=peer();value.received=bytearray(900);value.one_response_flight=False;value.connection=PublicConnection()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_000_000_000):value.flow_progress()
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=1_250_000_000),self.assertRaisesRegex(RuntimeError,'^NOT_ESTABLISHED: Q06 initial credit not reached before release$'):value.flush()
        self.assertEqual(value.connection.output_calls,[]);self.assertFalse(value.flow_released)

    def test_split_public_progress_calibrates_without_early_credit(self):
        output,fixture,wire=proof()
        request=next(row for row in fixture['events']if row['event']=='request-stream');request['bytes']=900
        event(fixture,'q06-pause-start')['request_bytes']=900
        fixture['events'].insert(7,dict(event='request-stream',stream_id=0,offset=900,bytes=124,fin=False))
        self.assertEqual(self.check(output,fixture,wire)['actual_outcome'],'Complete')

    def test_missing_or_earlier_credit_cannot_supply_resumed_progress(self):
        for before,after in [('max_data_after=1','max_data_after=0'),('receive_ordinal=2','receive_ordinal=1'),
                             ('sent_before=1024','sent_before=1023'),('written=512','written=0'),
                             ('max_data_received=1','max_data_received=0')]:
            output,fixture,wire=proof()
            with self.subTest(before=before),self.assertRaises(RuntimeError):self.check(output.replace(before,after),fixture,wire)

    def test_full_capture_and_native_input_order_remain_required(self):
        for direction in ('peer_udp','guest_udp'):
            output,fixture,wire=proof();wire[direction].reverse()
            with self.subTest(direction=direction),self.assertRaises(RuntimeError):self.check(output,fixture,wire)
        output,fixture,wire=proof();wire['guest_udp'].append(copy.deepcopy(wire['guest_udp'][-1]))
        with self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_json_census_fields_require_actual_nonnegative_integers(self):
        for name,key in [('q06-configuration','max_data'),('q06-pause-start','started_ns'),('q06-pause-release','tx_bytes')]:
            for value in (True,1.0,'1024',-1,None):
                output,fixture,wire=proof();event(fixture,name)[key]=value
                with self.subTest(name=name,key=key,value=value),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_original_full_consumer_cause_fence_resource_and_deadline_remain_required(self):
        for before,after in [('authenticated=true','authenticated=false'),('transport_error_code=none','transport_error_code=1'),
                             ('sent_stream=4096','sent_stream=4095'),('peer_fin=true','peer_fin=false'),
                             ('request_acked=true','request_acked=false'),('connection_drained=true','connection_drained=false'),
                             ('pipe_fenced=true','pipe_fenced=false'),('handles_after=1','handles_after=2'),
                             ('deadline_ms=10010','deadline_ms=10011'),('local_port=7805','local_port=7800')]:
            output,fixture,wire=proof()
            with self.subTest(before=before),self.assertRaises(RuntimeError):self.check(output.replace(before,after),fixture,wire)

    def test_original_q01_without_observations_still_calibrates(self):
        output,fixture,wire=BASE.proof()
        self.assertEqual(MATRIX.verify_native(BASE.CASE,output,fixture,wire,MANIFEST)['actual_outcome'],'Complete')


if __name__=='__main__':unittest.main()
