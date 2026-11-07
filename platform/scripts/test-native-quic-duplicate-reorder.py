#!/usr/bin/env python3
"""Finite Q05 held-output correspondence controls; protocol execution is separate."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('q05_base', ROOT / 'native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(BASE)
MATRIX, PEER, WIRE, MANIFEST = BASE.MATRIX, BASE.PEER_MODULE, BASE.WIRE, BASE.MANIFEST
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q05')
GUEST = bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e7c115b0011e121717569632d77697265000000000000000000')
PEER_PACKET = bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e7c0011e121717569632d77697265000000000000000000')
A, B = b'a'*1200, b'b'*1200
POLICY = 'q05-two-output-hold-v2'
START, SECOND, DEADLINE = 1_000_000_000, 1_200_000_000, 1_500_000_000


def digest(data):return hashlib.sha256(data).hexdigest()
def line(prefix, row):return prefix+' '+' '.join(key+'='+str(value)for key,value in row.items())
def event(fixture, name):
    rows=[row for row in fixture['events']if row['event']==name]
    if len(rows)!=1:raise RuntimeError('one exact synthetic event required: '+name)
    return rows[0]
def call(fixture, ordinal):
    rows=[row for row in fixture['events']if row['event']=='q05-public-call'and row['call_ordinal']==ordinal]
    if len(rows)!=1:raise RuntimeError('one exact synthetic call required')
    return rows[0]


def proof():
    output,fixture,wire=BASE.proof();lines=[]
    prefixes=('QUIC SERVICE SELECTOR','QUIC SERVICE DONE','QUIC SERVICE GRANT','QUIC RESULT',
              'QUIC BEGIN','QUIC CHILD EXIT','QUIC FIXTURE NATIVE_COUNTS','QUIC FIXTURE SEND','QUIC FIXTURE RX')
    for text in output.splitlines():
        prefix=next((name for name in prefixes if text.startswith(name+' ')),None)
        if prefix is None:lines.append(text);continue
        row=MATRIX.fields(text)
        if row.get('case')!='Q01':raise RuntimeError('exact original synthetic case required')
        row['case']='Q05'
        if 'local_port'in row:
            if row['local_port']!='7800':raise RuntimeError('exact original synthetic port required')
            row['local_port']='7804'
        if prefix=='QUIC RESULT':row.update(received='3',receive_bytes='3600',last_send_ms='21')
        if prefix=='QUIC FIXTURE NATIVE_COUNTS':row['receive_delivered']='3'
        if prefix=='QUIC FIXTURE RX':
            for ordinal,data in enumerate((B,A,A),1):lines.append(line(prefix,dict(row,ordinal=ordinal,at_ms=30+ordinal,sha256=digest(data))))
        else:lines.append(line(prefix,row))
    source,destination=['10.0.2.2',4443],['10.0.2.15',7804]
    def packet(data):return dict(bytes=len(data),sha256=digest(data),destination=list(destination))
    origins=[dict(source_call=1,source_index=0),dict(source_call=3,source_index=0)]
    originals=[dict(**origin,bytes=len(data),sha256=digest(data),data_hex=data.hex())for origin,data in zip(origins,(A,B))]
    events=[dict(event='udp-receive',bytes=1200,sha256='a'*64,source=list(destination)),
            dict(event='initial-observed',bytes=1200,sha256='a'*64),
            dict(event='q05-public-call',policy=POLICY,call_ordinal=1,batch_ordinal=1,observed_ns=START,initial_sha256='a'*64,datagrams=[packet(A)]),
            dict(event='q05-output-held',policy=POLICY,**origins[0],bytes=1200,sha256=digest(A),data_hex=A.hex(),started_ns=START,deadline_ns=DEADLINE,held_datagrams=1,held_bytes=1200),
            dict(event='q05-public-call',policy=POLICY,call_ordinal=2,batch_ordinal=None,observed_ns=START+1,initial_sha256='a'*64,datagrams=[]),
            dict(event='q05-public-call',policy=POLICY,call_ordinal=3,batch_ordinal=2,observed_ns=SECOND,initial_sha256='a'*64,datagrams=[packet(B)]),
            dict(event='q05-pair-ready',policy=POLICY,datagrams=originals,started_ns=START,ready_ns=SECOND,deadline_ns=DEADLINE,buffered_datagrams=2,buffered_bytes=2400,first_send_ordinal=1)]
    sent=[];order=[origins[1],origins[0],origins[0]]
    for ordinal,(data,origin)in enumerate(zip((B,A,A),order),1):
        row=dict(event='udp-send',bytes=1200,sha256=digest(data),source=list(source),destination=list(destination),send_ordinal=ordinal,monotonic_ns=SECOND+ordinal)
        events += [row,dict(event='q05-engine-datagram-sent',**origin,send_ordinal=ordinal,bytes=1200,sha256=digest(data))]
        sent.append({key:row[key]for key in ('bytes','sha256','source','destination')})
    events.append(dict(event='duplicate-reorder',policy=POLICY,source_origins=order,send_ordinals=[1,2,3],started_ns=START,released_ns=SECOND+4,deadline_ns=DEADLINE,held_bytes_after=0))
    fixture.update(readiness_profile='q05-duplicate-reorder-development',mode='duplicate-reorder',events=events,
                   tx_datagrams=3,tx_bytes=3600,reorder_policy=POLICY,reorder_hold_ns=500_000_000,reorder_calls=3,
                   reorder_batches=2,reorder_established=True,reorder_held_datagrams=0,reorder_abandoned=False)
    wire['peer_udp']=sent;wire['guest_udp'][0].update(source=list(destination),destination=list(source))
    return '\n'.join(lines),fixture,wire


def linux_proof():
    _,fixture,_=proof()
    for row in fixture['events']:
        if row['event']=='udp-receive':row['source']=['127.0.0.1',50001]
        if row['event']=='udp-send':row.update(source=['127.0.0.1',50002],destination=['127.0.0.1',50001])
        if row['event']=='q05-public-call':
            for packet in row['datagrams']:packet['destination']=['127.0.0.1',50001]
    consumed=[dict(ordinal=i,bytes=1200,sha256=digest(data),source=['127.0.0.1',50002],engine_delivered=True)for i,data in enumerate((B,A,A),1)]
    return fixture,consumed


class Engine:
    def __init__(self,batches):self.batches,self.calls=batches,0
    def datagrams_to_send(self,now):self.calls+=1;return self.batches.pop(0)if self.batches else []
class Socket:
    def __init__(self):self.sent=[]
    def getsockname(self):return ('10.0.2.2',4443)
    def sendto(self,data,destination):self.sent.append((bytes(data),destination));return len(data)


def peer(batches):
    value=object.__new__(PEER.Peer);value.case,value.mode,value.family=CASE,CASE['peer_mode'],'ipv4';value.expected_source=('10.0.2.15',7804)
    value.connection=Engine([[(data,value.expected_source)for data in batch]for batch in batches]);value.one_response_flight=value.response_flight_sealed=value.reorder_established=value.reorder_abandoned=False
    value.reorder_held=None;value.reorder_calls=value.reorder_batches=value.tx_packets=value.tx_bytes=0
    value.initial_sha256='a'*64;value.socket,value.lock,value.events=Socket(),threading.Lock(),[]
    return value


def flush_at(value,now):
    with mock.patch.object(PEER.time,'monotonic_ns',return_value=now):value.flush()


class DuplicateReorderControls(unittest.TestCase):
    def check(self,output,fixture,wire):return MATRIX.verify_native(CASE,output,fixture,wire,MANIFEST)

    def test_exact_case_joint_selectors_and_standard_certificate_calibrate(self):
        self.assertEqual((CASE['local_port'],CASE['peer_mode'],CASE['expected_outcome']),(7804,'duplicate-reorder','Complete'))
        self.assertEqual(MATRIX.development_profile(CASE),'q05-duplicate-reorder-development');self.assertEqual(PEER.development_profile(CASE),'q05-duplicate-reorder-development')
        self.assertEqual((PEER.peer_certificate(CASE),PEER.peer_terminal_codes(CASE),PEER.response_policy(CASE)),('valid',(0,),'standard'))
        self.assertEqual((PEER.Q05_HOLD_POLICY,PEER.Q05_HOLD_NS),(POLICY,500_000_000))

    def test_wrong_case_mode_port_and_ipv6_refuse(self):
        for changed in (dict(CASE,id='Q01'),dict(CASE,peer_mode='echo'),dict(CASE,local_port=7800)):
            with self.subTest(case=changed):
                with self.assertRaises(RuntimeError):MATRIX.development_profile(changed)
                with self.assertRaises(RuntimeError):PEER.development_profile(changed)
                with self.assertRaises(WIRE.Refusal):WIRE.observe(BASE.pcap([GUEST,PEER_PACKET]),changed,'52:54:00:12:34:56','02:71:00:00:00:02')
        with self.assertRaises(RuntimeError):MATRIX.development_profile(CASE,'ipv6')
        with self.assertRaises(RuntimeError):PEER.development_profile(CASE,'ipv6')

    def test_literal7804_checksum_valid_capture_and_old_port_refusal(self):
        value=WIRE.observe(BASE.pcap([BASE.ARP_BROADCAST,GUEST,PEER_PACKET]),CASE,'52:54:00:12:34:56','02:71:00:00:00:02')
        self.assertEqual(value['guest_udp'][0]['source'][1],7804)
        self.assertTrue(all(row['ip_checksum_valid']and row['udp_checksum_valid']for row in value['guest_udp']+value['peer_udp']))
        with self.assertRaises(WIRE.Refusal):WIRE.observe(BASE.pcap([BASE.GUEST,BASE.PEER]),CASE,'52:54:00:12:34:56','02:71:00:00:00:02')

    def test_actual_flush_swaps_two_distinct_inputs_and_duplicates_exact_first(self):
        for original in ([b'first',b'second'],[b'first',b'second',b'third',b'fourth']):
            value=peer([original]);flush_at(value,START)
            self.assertEqual([data for data,_ in value.socket.sent],[original[1],original[0],original[0],*original[2:]])
            self.assertEqual([row['send_ordinal']for row in value.events if row['event']=='udp-send'],list(range(1,len(original)+2)))
            selected=event({'events':value.events},'q05-pair-ready')['datagrams'];self.assertEqual([row['data_hex']for row in selected],[data.hex()for data in original[:2]])
            self.assertTrue(value.reorder_established);self.assertIsNone(value.reorder_held)

    def test_actual_flush_waits_for_first_eligible_batch_and_mutates_once(self):
        value=peer([[],[A],[],[B],[b'next',b'last']])
        for i in range(5):flush_at(value,START+i*10_000_000)
        self.assertEqual([data for data,_ in value.socket.sent],[B,A,A,b'next',b'last'])
        calls=[row for row in value.events if row['event']=='q05-public-call'];self.assertEqual([row['call_ordinal']for row in calls],[1,2,3,4,5]);self.assertEqual([row['batch_ordinal']for row in calls],[None,1,None,2,3])
        self.assertEqual(len([row for row in value.events if row['event']=='duplicate-reorder']),1)

    def test_actual_empty_batch_has_no_effect_and_bad_batch_refuses_before_send(self):
        value=peer([[]]);flush_at(value,START);self.assertEqual(value.socket.sent,[]);self.assertEqual(event({'events':value.events},'q05-public-call')['datagrams'],[])
        for batch in ([b''],[b'x'*1201],[b'x']*5):
            value=peer([batch])
            with self.subTest(batch=batch),self.assertRaises(RuntimeError):flush_at(value,START)
            self.assertEqual(value.socket.sent,[])
        value=peer([[b'a',b'b']]);value.connection.batches[0][1]=(b'b',('10.0.2.15',7800))
        with self.assertRaises(RuntimeError):flush_at(value,START)
        self.assertEqual(value.socket.sent,[])

    def test_synthetic_complete_native_input_correspondence_calibrates(self):
        self.assertEqual(self.check(*proof())['actual_outcome'],'Complete')

    def test_synthetic_linux_requires_actual_public_engine_consumed_order(self):
        fixture,consumed=linux_proof();MATRIX.verify_duplicate_reorder(CASE,fixture,client_datagrams=consumed)
        for mutation in ('missing','order','notdelivered'):
            fixture,consumed=linux_proof()
            if mutation=='missing':consumed.pop()
            elif mutation=='order':consumed[0]['sha256'],consumed[1]['sha256']=consumed[1]['sha256'],consumed[0]['sha256']
            else:consumed[0]['engine_delivered']=False
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):MATRIX.verify_duplicate_reorder(CASE,fixture,client_datagrams=consumed)

    def test_labels_without_full_public_batch_or_distinct_identity_refuse(self):
        for mutation in ('no_call','same','false','oldpolicy'):
            output,fixture,wire=proof()
            if mutation=='no_call':fixture['events']=[row for row in fixture['events']if row['event']!='q05-public-call']
            elif mutation=='same':call(fixture,3)['datagrams'][0]['sha256']=digest(A)
            elif mutation=='false':fixture['reorder_established']=False
            else:fixture['reorder_policy']='same-call-v1'
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_actual_send_order_duplicate_bytes_or_extra_send_cannot_be_substituted(self):
        for mutation in ('order','changed','extra'):
            output,fixture,wire=proof();sends=[row for row in fixture['events']if row['event']=='udp-send']
            if mutation=='order':sends[0]['sha256'],sends[1]['sha256']=sends[1]['sha256'],sends[0]['sha256']
            elif mutation=='changed':sends[2]['sha256']='d'*64
            else:fixture['events'].append(copy.deepcopy(sends[2]))
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_socket_and_full_capture_must_match_in_order_and_multiplicity(self):
        for mutation in ('missing','extra','order','guest'):
            output,fixture,wire=proof()
            if mutation=='missing':wire['peer_udp'].pop()
            elif mutation=='extra':wire['peer_udp'].append(copy.deepcopy(wire['peer_udp'][0]))
            elif mutation=='order':wire['peer_udp'][0],wire['peer_udp'][1]=wire['peer_udp'][1],wire['peer_udp'][0]
            else:wire['guest_udp'][0]['sha256']='f'*64
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_received_socket_tuple_representation_is_required(self):
        def with_receive(source):
            output,fixture,wire=proof()
            fixture['events'].append(dict(event='udp-receive',bytes=40,sha256='b'*64,source=source))
            fixture.update(rx_datagrams=fixture['rx_datagrams']+1,rx_bytes=fixture['rx_bytes']+40)
            wire['guest_udp'].append({**wire['guest_udp'][0],'bytes':40,'sha256':'b'*64,'source':source})
            return output,fixture,wire
        good=with_receive(['10.0.2.15',7804])
        MATRIX.verify_duplicate_reorder(CASE,good[1],good[2])
        for source in (['10.0.2.15',0],['10.0.2.15',65536],['10.0.2.15','7804'],['10.0.2.15',True],
                       [None,7804],['10.0.2.15',7804,0],('10.0.2.15',7804),None):
            output,fixture,wire=with_receive(source)
            with self.subTest(source=source),self.assertRaisesRegex(RuntimeError,'Q05 actual socket tuple representation differs'):
                MATRIX.verify_duplicate_reorder(CASE,fixture,wire)

    def test_missing_duplicate_native_dequeue_refuses_despite_complete_report(self):
        output,fixture,wire=proof();lines=[]
        for text in output.splitlines():
            if text.startswith('QUIC RESULT '):text=text.replace('received=3','received=2').replace('receive_bytes=3600','receive_bytes=2400')
            if text.startswith('QUIC FIXTURE NATIVE_COUNTS '):text=text.replace('receive_delivered=3','receive_delivered=2')
            if text.startswith('QUIC FIXTURE RX ')and 'ordinal=3 'in text:continue
            lines.append(text)
        with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):self.check('\n'.join(lines),fixture,wire)

    def test_native_reorder_or_later_identical_packet_cannot_supply_selected_input(self):
        output,fixture,wire=proof();output=output.replace('sha256='+digest(B),'sha256='+digest(A))
        with self.assertRaises(RuntimeError):self.check(output,fixture,wire)
        output,fixture,wire=proof();wire['peer_udp'].append(copy.deepcopy(wire['peer_udp'][1]))
        with self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_public_batch_and_postsend_action_causality_are_required(self):
        for mutation in ('initial','action','established','origin'):
            output,fixture,wire=proof()
            if mutation=='initial':fixture['events'][0],fixture['events'][2]=fixture['events'][2],fixture['events'][0]
            elif mutation=='action':fixture['events'][7],fixture['events'][8]=fixture['events'][8],fixture['events'][7]
            elif mutation=='established':fixture['events'].insert(7,fixture['events'].pop())
            else:event(fixture,'q05-pair-ready')['datagrams'][1]['source_call']=1
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_json_integer_fields_reject_bool_float_text_negative_and_missing(self):
        for target,key in [('call','call_ordinal'),('call','observed_ns'),('original','bytes'),('held','started_ns'),('held','held_bytes'),
                           ('pair','buffered_bytes'),('pair','ready_ns'),('action','source_index'),('release-origin','source_index'),('send','send_ordinal'),('send','monotonic_ns'),('fixture','reorder_calls'),('fixture','tx_bytes')]:
            for value in (True,False,1.0,'1',-1,None):
                output,fixture,wire=proof();row={'call':call(fixture,1),'original':call(fixture,1)['datagrams'][0],
                    'held':event(fixture,'q05-output-held'),'pair':event(fixture,'q05-pair-ready'),'release-origin':event(fixture,'duplicate-reorder')['source_origins'][0],'action':next(x for x in fixture['events']if x['event']=='q05-engine-datagram-sent'),
                    'send':next(x for x in fixture['events']if x['event']=='udp-send'),'fixture':fixture}[target];row[key]=value
                with self.subTest(target=target,key=key,value=value),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_original_auth_body_none_cause_fin_ack_drain_and_fence_remain_required(self):
        for before,after in [('authenticated=true','authenticated=false'),('transport_error_code=none','transport_error_code=1'),('sent_stream=4096','sent_stream=4095'),('peer_fin=true','peer_fin=false'),('request_acked=true','request_acked=false'),('connection_drained=true','connection_drained=false'),('pipe_fenced=true','pipe_fenced=false'),('handles_after=1','handles_after=2'),('deadline_ms=10010','deadline_ms=10011'),('local_port=7804','local_port=7800')]:
            output,fixture,wire=proof()
            with self.subTest(field=before),self.assertRaises(RuntimeError):self.check(output.replace(before,after),fixture,wire)

    def test_original_q01_without_fixture_still_calibrates(self):
        self.assertEqual(MATRIX.verify_native(BASE.CASE,*BASE.proof(),MANIFEST)['actual_outcome'],'Complete')

    def test_actual_first_singleton_is_held_and_next_distinct_call_releases(self):
        value=peer([[A],[B]]);flush_at(value,START);self.assertEqual(value.socket.sent,[]);self.assertEqual(value.reorder_held['data'],A)
        flush_at(value,SECOND);self.assertEqual([data for data,_ in value.socket.sent],[B,A,A]);self.assertIsNone(value.reorder_held)
        selected=event({'events':value.events},'q05-pair-ready');self.assertEqual([(row['source_call'],row['source_index'])for row in selected['datagrams']],[(1,0),(2,0)])

    def test_actual_missing_second_output_times_out_clears_and_never_calls_engine_late(self):
        value=peer([[A],[]]);flush_at(value,START);flush_at(value,DEADLINE)
        with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):flush_at(value,DEADLINE+1)
        self.assertIsNone(value.reorder_held);self.assertTrue(value.reorder_abandoned);self.assertEqual(value.connection.calls,2);self.assertEqual(value.socket.sent,[])
        self.assertEqual(event({'events':value.events},'q05-hold-refused')['held_bytes_after'],0)
        with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):flush_at(value,DEADLINE+2)
        self.assertEqual(value.connection.calls,2)

    def test_actual_call_returning_after_deadline_retains_its_public_identity_then_refuses(self):
        value=peer([[A],[B]]);flush_at(value,START);clock=[DEADLINE];original=value.connection.datagrams_to_send
        def delayed(now):clock[0]=DEADLINE+1;return original(now)
        value.connection.datagrams_to_send=delayed
        with mock.patch.object(PEER.time,'monotonic_ns',side_effect=lambda:clock[0]):
            with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):value.flush()
        calls=[row for row in value.events if row['event']=='q05-public-call'];self.assertEqual(calls[-1]['datagrams'][0]['sha256'],digest(B));self.assertEqual(len(calls),2)
        self.assertEqual(value.socket.sent,[]);self.assertIsNone(value.reorder_held)

    def test_actual_identical_second_output_refuses_and_clears_held_bytes(self):
        value=peer([[A],[A]]);flush_at(value,START)
        with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):flush_at(value,SECOND)
        self.assertIsNone(value.reorder_held);self.assertTrue(value.reorder_abandoned);self.assertEqual(value.socket.sent,[])
        self.assertEqual(event({'events':value.events},'q05-hold-refused')['reason'],'second-identical')

    def test_actual_bad_call_while_holding_clears_on_refusal(self):
        value=peer([[A],[b'']]);flush_at(value,START)
        with self.assertRaises(RuntimeError):flush_at(value,SECOND)
        self.assertIsNone(value.reorder_held);self.assertTrue(value.reorder_abandoned);self.assertEqual(value.socket.sent,[])

    def test_hold_deadline_release_time_and_completion_boundary_cannot_be_extended(self):
        for target,key,value in [('held','deadline_ns',DEADLINE+1),('held','started_ns',START+1),('pair','ready_ns',DEADLINE+1),('released','released_ns',DEADLINE+1),('send','monotonic_ns',DEADLINE+1),('fixture','reorder_hold_ns',500_000_001)]:
            output,fixture,wire=proof();row={'held':event(fixture,'q05-output-held'),'pair':event(fixture,'q05-pair-ready'),'released':event(fixture,'duplicate-reorder'),'send':next(x for x in fixture['events']if x['event']=='udp-send'),'fixture':fixture}[target];row[key]=value
            with self.subTest(target=target,key=key),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_empty_call_identity_hold_bytes_and_source_origins_cannot_be_substituted(self):
        for mutation in ('empty','hex','origin','pending','abandoned'):
            output,fixture,wire=proof()
            if mutation=='empty':call(fixture,2)['batch_ordinal']=1
            elif mutation=='hex':event(fixture,'q05-output-held')['data_hex']=B.hex()
            elif mutation=='origin':event(fixture,'duplicate-reorder')['source_origins'][0]['source_index']=1
            elif mutation=='pending':fixture['reorder_held_datagrams']=1
            else:fixture['reorder_abandoned']=True
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_pair_storage_and_exact_multiplicity_are_fixed(self):
        output,fixture,wire=proof();event(fixture,'q05-pair-ready')['buffered_bytes']=2401
        with self.assertRaises(RuntimeError):self.check(output,fixture,wire)
        value=peer([[A],[B,b'c'*1200,b'd'*1200,b'e'*1200]]);flush_at(value,START);flush_at(value,SECOND)
        self.assertEqual([data for data,_ in value.socket.sent],[B,A,A,b'c'*1200,b'd'*1200,b'e'*1200]);self.assertEqual(event({'events':value.events},'q05-pair-ready')['buffered_bytes'],2400)


    def test_actual_call_limit_refuses_before_an_unrecorded_engine_call(self):
        value=peer([[A],[B]]);flush_at(value,START);value.reorder_calls=1024
        with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):flush_at(value,SECOND)
        self.assertEqual(value.connection.calls,1);self.assertIsNone(value.reorder_held);self.assertTrue(value.reorder_abandoned)
        self.assertEqual(event({'events':value.events},'q05-hold-refused')['reason'],'call-limit')


    def assert_selected_emission_stays_abandoned(self,value,attempts,timer_calls):
        self.assertIsNone(value.reorder_held);self.assertTrue(value.reorder_abandoned);self.assertFalse(value.reorder_established)
        self.assertEqual(event({'events':value.events},'q05-hold-refused')['held_bytes_after'],0)
        self.assertFalse(any(row['event']=='duplicate-reorder'for row in value.events))
        before=(value.connection.calls,list(attempts),list(value.socket.sent),value.tx_packets,len(value.events))
        # Even an earlier subsequent clock observation cannot revive a refused hold.
        with mock.patch.object(PEER.time,'monotonic_ns',return_value=SECOND):
            for _ in range(2):
                with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):value.flush()
                with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):value.drive_timer(SECOND/1_000_000_000)
        self.assertEqual((value.connection.calls,list(attempts),list(value.socket.sent),value.tx_packets,len(value.events)),before)
        self.assertEqual(timer_calls,[])

    def test_actual_selected_second_or_third_socket_failure_clears_and_fences(self):
        for failure_ordinal in (2,3):
            with self.subTest(failure_ordinal=failure_ordinal):
                value=peer([[A],[B],[b'untouched']]);flush_at(value,START);attempts=[];timer_calls=[]
                original_send=value.socket.sendto
                def failing_send(data,destination):
                    attempts.append(bytes(data))
                    if len(attempts)==failure_ordinal:raise OSError('declared selected socket refusal')
                    return original_send(data,destination)
                value.socket.sendto=failing_send
                value.connection.get_timer=lambda:timer_calls.append('get_timer')or 0.0
                value.connection.handle_timer=lambda now:timer_calls.append('handle_timer')
                with self.assertRaisesRegex(OSError,'declared selected socket refusal'):flush_at(value,SECOND)
                self.assertEqual(attempts,[B,A,A][:failure_ordinal])
                self.assertEqual([data for data,_ in value.socket.sent],[B,A,A][:failure_ordinal-1])
                self.assertEqual(value.tx_packets,failure_ordinal-1)
                self.assertEqual(len([row for row in value.events if row['event']=='udp-send']),failure_ordinal-1)
                self.assertEqual(event({'events':value.events},'q05-hold-refused')['reason'],'call-refused')
                self.assert_selected_emission_stays_abandoned(value,attempts,timer_calls)

    def test_actual_deadline_crossed_during_selected_send_clears_and_fences(self):
        for crossing_ordinal in (1,2,3):
            with self.subTest(crossing_ordinal=crossing_ordinal):
                value=peer([[A],[B],[b'untouched']]);flush_at(value,START);attempts=[];timer_calls=[];clock=[SECOND]
                original_send=value.socket.sendto
                def crossing_send(data,destination):
                    attempts.append(bytes(data));count=original_send(data,destination)
                    if len(attempts)==crossing_ordinal:clock[0]=DEADLINE+1
                    return count
                value.socket.sendto=crossing_send
                value.connection.get_timer=lambda:timer_calls.append('get_timer')or 0.0
                value.connection.handle_timer=lambda now:timer_calls.append('handle_timer')
                with mock.patch.object(PEER.time,'monotonic_ns',side_effect=lambda:clock[0]):
                    with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):value.flush()
                self.assertEqual(attempts,[B,A,A][:crossing_ordinal])
                self.assertEqual([data for data,_ in value.socket.sent],[B,A,A][:crossing_ordinal])
                self.assertEqual(value.tx_packets,crossing_ordinal)
                sends=[row for row in value.events if row['event']=='udp-send']
                self.assertEqual(len(sends),crossing_ordinal);self.assertEqual(sends[-1]['monotonic_ns'],DEADLINE+1)
                self.assertEqual(event({'events':value.events},'q05-hold-refused')['reason'],'deadline')
                self.assert_selected_emission_stays_abandoned(value,attempts,timer_calls)


if __name__=='__main__':unittest.main()
