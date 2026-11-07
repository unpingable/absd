#!/usr/bin/env python3
"""Finite Q13 input and distinguishing STREAM-processing controls, not protocol runs."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('q13_base',ROOT/'native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(BASE)
MATRIX, PEER, WIRE, MANIFEST = BASE.MATRIX, BASE.PEER_MODULE, BASE.WIRE, BASE.MANIFEST
CASE = next(row for row in MANIFEST['native_occurrences']if row['id']=='Q13')
ORIGINAL = b'\x40' + bytes(range(1,64))
CHANGED = ORIGINAL[:-1] + bytes([ORIGINAL[-1]^1])

GUEST = bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e84115b0011e119717569632d77697265000000000000000000')
PEER_PACKET = bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e840011e119717569632d77697265000000000000000000')

def digest(data):return hashlib.sha256(data).hexdigest()
def line(prefix,row):return prefix+' '+' '.join(key+'='+str(value)for key,value in row.items())
def event(fixture,name):
    rows=[row for row in fixture['events']if row['event']==name]
    if len(rows)!=1:raise RuntimeError('one synthetic event required: '+name)
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
        row['case']='Q13'
        if 'local_port'in row:
            if row['local_port']!='7800':raise RuntimeError('exact original synthetic port required')
            row['local_port']='7812'
        if prefix=='QUIC RESULT':row.update(received='2',receive_bytes='128',last_send_ms='21')
        if prefix=='QUIC FIXTURE NATIVE_COUNTS':row['receive_delivered']='2'
        if prefix=='QUIC FIXTURE RX':
            for ordinal,data in enumerate((CHANGED,ORIGINAL),1):
                lines.append(line(prefix,dict(row,ordinal=ordinal,at_ms=30+ordinal,bytes=len(data),sha256=digest(data))))
        else:lines.append(line(prefix,row))
    source,destination=['10.0.2.2',4443],['10.0.2.15',7812]
    original=dict(bytes=64,sha256=digest(ORIGINAL),first_byte=64,destination=list(destination))
    mutation=dict(event='tag-mutation',policy='q13-tag-tail-xor1-v1',batch_ordinal=1,source_index=0,
                  first_send_ordinal=1,authenticated_before=True,bytes=64,tag_bytes=16,changed_offset=63,xor=1,
                  original_hex=ORIGINAL.hex(),changed_hex=CHANGED.hex(),original_sha256=digest(ORIGINAL),changed_sha256=digest(CHANGED))
    events=[dict(event='udp-receive',bytes=1200,sha256='a'*64,source=list(destination)),
            dict(event='initial-observed',bytes=1200,sha256='a'*64),
            dict(event='handshake',alpn='absd-echo/1',early_data=False,resumed=False),
            dict(event='echo-enqueue',offset=0,bytes=512),
            dict(event='q13-public-batch',batch_ordinal=1,selected_index=0,authenticated_before=True,echo_enqueued_before=512,
                 initial_sha256='a'*64,first_send_ordinal=1,datagrams=[original]),mutation]
    sent=[]
    for ordinal,data in enumerate((CHANGED,ORIGINAL),1):
        row=dict(event='udp-send',bytes=len(data),sha256=digest(data),source=list(source),destination=list(destination),send_ordinal=ordinal)
        events.append(row);sent.append({key:row[key]for key in ('bytes','sha256','source','destination')})
    events += [dict(event='tag-mutation-sent',batch_ordinal=1,source_index=0,send_ordinals=[1,2]),
               dict(event='q13-engine-datagram-sent',batch_ordinal=1,source_index=0,send_ordinal=2,bytes=64,sha256=digest(ORIGINAL))]
    fixture.update(readiness_profile='q13-invalid-tag-development',mode='invalid-tag',events=events,
                   tx_datagrams=2,tx_bytes=128,tag_batches=1,tag_mutations=1)
    wire['peer_udp']=sent;wire['guest_udp'][0].update(source=list(destination),destination=list(source))
    # Synthetic public counters belong only to this finite checker fixture;
    # an actual native proof must obtain them from the Q13-only engine hook.
    for ordinal,data in enumerate((CHANGED,ORIGINAL),1):
        lines.append(line('QUIC TAG RX',dict(case='Q13',at_ms=30+ordinal,receive_ordinal=ordinal,
            bytes=len(data),sha256=digest(data),stream_frames_before=0,stream_frames_after=ordinal-1,
            authenticated_before='true',target_handled='true')))
    return '\n'.join(lines),fixture,wire


def linux_proof():
    _,fixture,_=proof()
    for row in fixture['events']:
        if row['event']=='udp-receive':row['source']=['127.0.0.1',50001]
        if row['event']=='udp-send':row.update(source=['127.0.0.1',50002],destination=['127.0.0.1',50001])
        if row['event']=='q13-public-batch':
            for packet in row['datagrams']:packet['destination']=['127.0.0.1',50001]
    consumed=[dict(ordinal=i,bytes=64,sha256=digest(data),source=['127.0.0.1',50002],engine_delivered=True)
              for i,data in enumerate((CHANGED,ORIGINAL),1)]
    return fixture,consumed


class Engine:
    def __init__(self,batches):self.batches,self.calls=batches,0
    def datagrams_to_send(self,now):self.calls+=1;return self.batches.pop(0)if self.batches else []
class Socket:
    def __init__(self):self.sent=[]
    def getsockname(self):return ('10.0.2.2',4443)
    def sendto(self,data,destination):self.sent.append((bytes(data),destination));return len(data)


def peer(batches,authenticated=True,echoed=512):
    value=object.__new__(PEER.Peer);value.case,value.mode,value.family=CASE,CASE['peer_mode'],'ipv4'
    value.expected_source=('10.0.2.15',7812);value.connection=Engine([[(data,value.expected_source)for data in batch]for batch in batches])
    value.one_response_flight=value.response_flight_sealed=False;value.tag_batches=value.tag_mutations=value.tx_packets=value.tx_bytes=0
    value.initial_sha256='a'*64;value.authenticated=authenticated;value.echoed=echoed;value.socket,value.lock,value.events=Socket(),threading.Lock(),[]
    return value


class InvalidTagControls(unittest.TestCase):
    def check(self,output,fixture,wire):return MATRIX.verify_native(CASE,output,fixture,wire,MANIFEST)

    def test_exact_canonical_selectors_certificate_and_standard_policy(self):
        self.assertEqual((CASE['local_port'],CASE['peer_mode'],CASE['expected_outcome']),(7812,'invalid-tag','Complete'))
        self.assertEqual(MATRIX.development_profile(CASE),'q13-invalid-tag-development')
        self.assertEqual(PEER.development_profile(CASE),'q13-invalid-tag-development')
        self.assertEqual((PEER.peer_certificate(CASE),PEER.peer_terminal_codes(CASE),PEER.response_policy(CASE)),('valid',(0,),'standard'))

    def test_wrong_case_mode_port_and_family_refuse(self):
        for changed in (dict(CASE,id='Q01'),dict(CASE,peer_mode='echo'),dict(CASE,local_port=7800)):
            with self.subTest(case=changed):
                with self.assertRaises(RuntimeError):MATRIX.development_profile(changed)
                with self.assertRaises(RuntimeError):PEER.development_profile(changed)
                with self.assertRaises(WIRE.Refusal):WIRE.observe(BASE.pcap([BASE.GUEST,BASE.PEER]),changed,'52:54:00:12:34:56','02:71:00:00:00:02')
        with self.assertRaises(RuntimeError):MATRIX.development_profile(CASE,'ipv6')
        with self.assertRaises(RuntimeError):PEER.development_profile(CASE,'ipv6')

    def test_literal7812_complete_checksum_capture_calibrates(self):
        value=WIRE.observe(BASE.pcap([BASE.ARP_BROADCAST,GUEST,PEER_PACKET]),CASE,'52:54:00:12:34:56','02:71:00:00:00:02')
        self.assertEqual(value['guest_udp'][0]['source'][1],7812)
        self.assertTrue(all(row['ip_checksum_valid']and row['udp_checksum_valid']for row in value['guest_udp']+value['peer_udp']))
        with self.assertRaises(WIRE.Refusal):WIRE.observe(BASE.pcap([BASE.GUEST,BASE.PEER]),CASE,'52:54:00:12:34:56','02:71:00:00:00:02')

    def test_actual_public_flush_changes_only_last_bit_and_preserves_original(self):
        value=peer([[ORIGINAL]]);value.flush();self.assertEqual([data for data,_ in value.socket.sent],[CHANGED,ORIGINAL])
        mutation=event({'events':value.events},'tag-mutation');self.assertEqual((mutation['original_hex'],mutation['changed_hex']),(ORIGINAL.hex(),CHANGED.hex()))
        self.assertEqual((value.tag_mutations,value.tag_batches,value.tx_packets),(1,1,2))

    def test_actual_waits_for_authenticated_short42_and_mutates_once(self):
        too_short=b'\x40'+bytes(40);long=b'\xc0'+bytes(63)
        value=peer([[ORIGINAL],[long,too_short],[ORIGINAL],[ORIGINAL]],authenticated=False);value.flush();value.authenticated=True
        for _ in range(3):value.flush()
        self.assertEqual([data for data,_ in value.socket.sent],[ORIGINAL,long,too_short,CHANGED,ORIGINAL,ORIGINAL])
        self.assertEqual(len([row for row in value.events if row['event']=='tag-mutation']),1)

    def test_actual_selection_waits_for_enqueued_echo_stream_data(self):
        value=peer([[ORIGINAL],[ORIGINAL]],echoed=0);value.flush()
        self.assertEqual(value.tag_mutations,0);self.assertIsNone(event({'events':value.events},'q13-public-batch')['selected_index'])
        value.echoed=512;value.flush()
        self.assertEqual([data for data,_ in value.socket.sent],[ORIGINAL,CHANGED,ORIGINAL])
        self.assertEqual([row['echo_enqueued_before']for row in value.events if row['event']=='q13-public-batch'],[0,512])

    def test_selection_before_echo_or_unmatched_echo_census_refuses(self):
        output,fixture,wire=proof();self.check(output,fixture,wire)
        for mutation in ('no-echo','count','missing','bool'):
            output,fixture,wire=proof();batch=event(fixture,'q13-public-batch')
            if mutation=='no-echo':
                fixture['events']=[row for row in fixture['events']if row['event']!='echo-enqueue'];batch['echo_enqueued_before']=0
                message='Q13 first eligible actual short packet selection differs'
            elif mutation=='count':batch['echo_enqueued_before']=1024;message='Q13 complete original public batch shape'
            elif mutation=='missing':del batch['echo_enqueued_before'];message='echo_enqueued_before'
            else:batch['echo_enqueued_before']=True;message='echo_enqueued_before'
            with self.subTest(mutation=mutation),self.assertRaisesRegex(RuntimeError,message):self.check(output,fixture,wire)

    def test_42byte_boundary_preserves_every_permitted_hp_sample(self):
        for size in (42,43,1200):
            original=b'\x40'+bytes(size-1);changed=original[:-1]+bytes([original[-1]^1]);value=peer([[original]]);value.flush()
            self.assertEqual([data for data,_ in value.socket.sent],[changed,original])
            for cid_length in range(21):
                sample=1+cid_length+4;self.assertEqual(original[sample:sample+16],changed[sample:sample+16])
            self.assertEqual(original[:-16],changed[:-16]);self.assertNotEqual(original[-16:],changed[-16:])

    def test_actual_entire_public_batch_kept_in_order_around_extra_copy(self):
        first=b'\xc0'+bytes(63);last=b'\x41'+bytes(63);value=peer([[first,ORIGINAL,last]]);value.flush()
        self.assertEqual([data for data,_ in value.socket.sent],[first,CHANGED,ORIGINAL,last])
        batch=event({'events':value.events},'q13-public-batch');self.assertEqual(batch['selected_index'],1)
        self.assertEqual([row['sha256']for row in batch['datagrams']],[digest(first),digest(ORIGINAL),digest(last)])

    def test_empty_and_invalid_complete_batch_refuse_without_partial_send(self):
        value=peer([[]]);value.flush();self.assertEqual(value.events,[])
        for batch in ([b''],[b'x'*1201],[ORIGINAL]*5):
            value=peer([batch])
            with self.subTest(batch=batch),self.assertRaises(RuntimeError):value.flush()
            self.assertEqual(value.socket.sent,[])
        value=peer([[ORIGINAL,b'x']]);value.connection.batches[0][1]=(b'x',('10.0.2.15',7800))
        with self.assertRaises(RuntimeError):value.flush()
        self.assertEqual(value.socket.sent,[])

    def test_synthetic_complete_native_pair_calibrates(self):
        self.assertEqual(self.check(*proof())['actual_outcome'],'Complete')

    def test_synthetic_linux_actual_consumed_pair_required(self):
        fixture,consumed=linux_proof();MATRIX.verify_invalid_tag(CASE,fixture,client_datagrams=consumed)
        for mutation in ('missing','order','notdelivered'):
            fixture,consumed=linux_proof()
            if mutation=='missing':consumed.pop(0)
            elif mutation=='order':consumed[0],consumed[1]=consumed[1],consumed[0]
            else:consumed[0]['engine_delivered']=False
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):MATRIX.verify_invalid_tag(CASE,fixture,client_datagrams=consumed)

    def test_labels_without_actual_public_original_refuse(self):
        for mutation in ('batch','mutation','action','done','count'):
            output,fixture,wire=proof()
            if mutation=='count':fixture['tag_mutations']=0
            else:
                name={'batch':'q13-public-batch','mutation':'tag-mutation','action':'q13-engine-datagram-sent','done':'tag-mutation-sent'}[mutation]
                fixture['events']=[row for row in fixture['events']if row['event']!=name]
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_byte_relation_cannot_change_header_body_or_multiple_tag_bits(self):
        for index,xor in ((0,1),(20,1),(62,1),(63,2)):
            output,fixture,wire=proof();changed=bytearray(ORIGINAL);changed[index]^=xor;mutation=event(fixture,'tag-mutation')
            mutation.update(changed_hex=changed.hex(),changed_sha256=digest(changed))
            with self.subTest(index=index,xor=xor),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_tag_metadata_hash_and_canonical_hex_cannot_be_substituted(self):
        for key,value in [('original_sha256','f'*64),('tag_bytes',8),('xor',2),('changed_offset',62),('original_hex',ORIGINAL.hex().upper()),('policy','other')]:
            output,fixture,wire=proof();event(fixture,'tag-mutation')[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_initial_and_handshake_must_precede_actual_selected_batch(self):
        for mutation in ('handshake','batch','authentication','selection','alpn','resumed'):
            output,fixture,wire=proof();events=fixture['events']
            if mutation=='handshake':events.append(events.pop(2))
            elif mutation=='batch':events[0],events[3]=events[3],events[0]
            elif mutation=='authentication':event(fixture,'q13-public-batch')['authenticated_before']=False
            elif mutation=='selection':event(fixture,'q13-public-batch')['selected_index']=None
            elif mutation=='alpn':event(fixture,'handshake')['alpn']='other-echo/1'
            else:event(fixture,'handshake')['resumed']=True
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_changed_original_send_and_postsend_action_order_required(self):
        for mutation in ('send','done','action','extra'):
            output,fixture,wire=proof();events=fixture['events']
            if mutation=='send':events[5],events[6]=events[6],events[5]
            elif mutation=='done':events.insert(5,events.pop(7))
            elif mutation=='action':event(fixture,'q13-engine-datagram-sent')['sha256']='f'*64
            else:events.append(copy.deepcopy(events[5]))
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_full_capture_missing_extra_or_reordered_pair_refuses(self):
        for mutation in ('missing','extra','order','guest'):
            output,fixture,wire=proof()
            if mutation=='missing':wire['peer_udp'].pop(0)
            elif mutation=='extra':wire['peer_udp'].append(copy.deepcopy(wire['peer_udp'][0]))
            elif mutation=='order':wire['peer_udp'].reverse()
            else:wire['guest_udp'][0]['sha256']='f'*64
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_native_missing_changed_dequeue_refuses_despite_complete(self):
        output,fixture,wire=proof();lines=[]
        for text in output.splitlines():
            if text.startswith('QUIC RESULT '):text=text.replace('received=2','received=1').replace('receive_bytes=128','receive_bytes=64')
            if text.startswith('QUIC FIXTURE NATIVE_COUNTS '):text=text.replace('receive_delivered=2','receive_delivered=1')
            if text.startswith('QUIC FIXTURE RX '):
                if 'ordinal=1 'in text:continue
                text=text.replace('ordinal=2','ordinal=1')
            lines.append(text)
        with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):self.check('\n'.join(lines),fixture,wire)

    def test_json_integer_fields_refuse_bool_float_text_negative_none(self):
        for kind,key in [('mutation','bytes'),('mutation','tag_bytes'),('mutation','changed_offset'),('mutation','xor'),
                         ('batch','batch_ordinal'),('batch','first_send_ordinal'),('packet','first_byte'),('packet','bytes'),
                         ('action','source_index'),('send','send_ordinal'),('fixture','tag_batches'),('fixture','tag_mutations')]:
            for value in (True,1.0,'1',-1,None):
                output,fixture,wire=proof();row={'mutation':event(fixture,'tag-mutation'),'batch':event(fixture,'q13-public-batch'),
                    'packet':event(fixture,'q13-public-batch')['datagrams'][0],'action':event(fixture,'q13-engine-datagram-sent'),
                    'send':next(row for row in fixture['events']if row['event']=='udp-send'),'fixture':fixture}[kind];row[key]=value
                with self.subTest(kind=kind,key=key,value=value),self.assertRaises(RuntimeError):self.check(output,fixture,wire)

    def test_original_complete_auth_body_fin_ack_drain_timing_fence_census_remain(self):
        for before,after in [('authenticated=true','authenticated=false'),('sent_stream=4096','sent_stream=4095'),('transport_error_code=none','transport_error_code=1'),
                             ('peer_fin=true','peer_fin=false'),('request_acked=true','request_acked=false'),('connection_drained=true','connection_drained=false'),
                             ('pipe_fenced=true','pipe_fenced=false'),('handles_after=1','handles_after=2'),('deadline_ms=10010','deadline_ms=10011'),('local_port=7812','local_port=7800')]:
            output,fixture,wire=proof()
            with self.subTest(field=before),self.assertRaises(RuntimeError):self.check(output.replace(before,after),fixture,wire)

    def test_original_q01_without_q13_fixture_still_calibrates(self):
        self.assertEqual(MATRIX.verify_native(BASE.CASE,*BASE.proof(),MANIFEST)['actual_outcome'],'Complete')

    def test_native_both_inputs_must_already_be_authenticated(self):
        for ordinal in (1,2):
            output,fixture,wire=proof();lines=output.splitlines()
            index=next(i for i,text in enumerate(lines)if text.startswith('QUIC TAG RX ')and f'receive_ordinal={ordinal} 'in text)
            lines[index]=lines[index].replace('authenticated_before=true','authenticated_before=false')
            with self.subTest(ordinal=ordinal),self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):
                self.check('\n'.join(lines),fixture,wire)

    def test_native_both_inputs_require_exact_target_connection_handler(self):
        for ordinal in (1,2):
            output,fixture,wire=proof();lines=output.splitlines()
            index=next(i for i,text in enumerate(lines)if text.startswith('QUIC TAG RX ')and f'receive_ordinal={ordinal} 'in text)
            lines[index]=lines[index].replace('target_handled=true','target_handled=false')
            with self.subTest(ordinal=ordinal),self.assertRaises(RuntimeError):self.check('\n'.join(lines),fixture,wire)

    def test_skip_verification_process_changed_then_duplicate_original_refuses(self):
        output,fixture,wire=proof();lines=[]
        for text in output.splitlines():
            if text.startswith('QUIC TAG RX '):
                row=MATRIX.fields(text);row.update(stream_frames_before='0'if row['receive_ordinal']=='1'else'1',stream_frames_after='1')
                text=line('QUIC TAG RX',row)
            lines.append(text)
        with self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):self.check('\n'.join(lines),fixture,wire)

    def test_changed_processing_or_streamless_original_cannot_qualify(self):
        for counters in (((0,1),(1,2)),((0,0),(0,0))):
            output,fixture,wire=proof();lines=[]
            for text in output.splitlines():
                if text.startswith('QUIC TAG RX '):
                    row=MATRIX.fields(text);before,after=counters[int(row['receive_ordinal'])-1]
                    row.update(stream_frames_before=str(before),stream_frames_after=str(after));text=line('QUIC TAG RX',row)
                lines.append(text)
            with self.subTest(counters=counters),self.assertRaisesRegex(RuntimeError,'NOT_ESTABLISHED'):
                self.check('\n'.join(lines),fixture,wire)

    def test_complete_native_observations_missing_extra_order_or_case_refuse(self):
        for mutation in ('missing','extra','order','case'):
            output,fixture,wire=proof();lines=output.splitlines();indices=[i for i,text in enumerate(lines)if text.startswith('QUIC TAG RX ')]
            if mutation=='missing':lines.pop(indices[0])
            elif mutation=='extra':lines.append(lines[indices[0]])
            elif mutation=='order':lines[indices[0]],lines[indices[1]]=lines[indices[1]],lines[indices[0]]
            else:lines[indices[0]]=lines[indices[0]].replace('case=Q13','case=Q01')
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):self.check('\n'.join(lines),fixture,wire)

    def test_native_observation_exact_identity_lifetime_and_canonical_flags(self):
        for key,value in [('receive_ordinal','2'),('bytes','63'),('sha256','f'*64),('at_ms','9'),('at_ms','101'),
                          ('authenticated_before','True'),('target_handled','1')]:
            output,fixture,wire=proof();lines=output.splitlines();index=next(i for i,text in enumerate(lines)if text.startswith('QUIC TAG RX '))
            row=MATRIX.fields(lines[index]);row[key]=value;lines[index]=line('QUIC TAG RX',row)
            with self.subTest(key=key,value=value),self.assertRaises(RuntimeError):self.check('\n'.join(lines),fixture,wire)

    def test_native_stream_counter_canonical_bound_rewind_and_continuity(self):
        for ordinal,key,value in [(1,'stream_frames_before','1'),(2,'stream_frames_before','1'),(2,'stream_frames_after','129'),
                                  (1,'stream_frames_after','65'),(2,'stream_frames_after','0')]+[
                (2,key,value)for key in ('stream_frames_before','stream_frames_after')for value in ('-1','True','1.0','01','none')]:
            output,fixture,wire=proof();lines=output.splitlines();index=next(i for i,text in enumerate(lines)if text.startswith('QUIC TAG RX ')and f'receive_ordinal={ordinal} 'in text)
            row=MATRIX.fields(lines[index]);row[key]=value;lines[index]=line('QUIC TAG RX',row)
            with self.subTest(ordinal=ordinal,key=key,value=value),self.assertRaises(RuntimeError):self.check('\n'.join(lines),fixture,wire)

    def test_multiple_original_stream_frames_can_supply_positive_control(self):
        output,fixture,wire=proof();lines=[]
        for text in output.splitlines():
            if text.startswith('QUIC TAG RX ')and 'receive_ordinal=2 'in text:text=text.replace('stream_frames_after=1','stream_frames_after=2')
            lines.append(text)
        self.assertEqual(self.check('\n'.join(lines),fixture,wire)['actual_outcome'],'Complete')


if __name__=='__main__':unittest.main()
