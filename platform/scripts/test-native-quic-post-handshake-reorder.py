#!/usr/bin/env python3
"""Bounded post-handshake Q05 construction/oracle controls, not runtime proof."""
import copy,hashlib,importlib.util,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('q05_initial',ROOT/'test-native-quic-duplicate-reorder.py');BASE=importlib.util.module_from_spec(sp);sp.loader.exec_module(BASE)
MATRIX,PEER,CASE=BASE.MATRIX,BASE.PEER,BASE.CASE
POLICY='q05-post-handshake-two-output-hold-v2'
PREFIX=b'\xc0handshake-prefix'
def proof():
 output,f,wire=BASE.proof();events=f['events'];base=copy.deepcopy(events[2:])
 for row in base:
  if 'policy' in row:row['policy']=POLICY
  if 'source_call' in row:row['source_call']+=1
  if row['event']=='q05-public-call':row['call_ordinal']+=1;row['batch_ordinal']=row['batch_ordinal']+1 if row['batch_ordinal'] is not None else None
  if 'send_ordinal' in row:row['send_ordinal']+=1
  if row['event']=='q05-pair-ready':
   row['first_send_ordinal']=2
   for d in row['datagrams']:d['source_call']+=1
  if row['event']=='duplicate-reorder':
   row['send_ordinals']=[2,3,4]
   row['source_origins']=[dict(d,source_call=d['source_call']+1)for d in row['source_origins']]
 destination=['10.0.2.15',7804];source=['10.0.2.2',4443];digest=BASE.digest(PREFIX)
 prefix=[dict(event='q05-public-call',policy=POLICY,call_ordinal=1,batch_ordinal=1,observed_ns=BASE.START-10,initial_sha256='a'*64,datagrams=[dict(bytes=len(PREFIX),sha256=digest,destination=destination)]),
 dict(event='udp-send',bytes=len(PREFIX),sha256=digest,source=source,destination=destination,send_ordinal=1,monotonic_ns=BASE.START-9),
 dict(event='q05-engine-datagram-sent',source_call=1,source_index=0,send_ordinal=1,bytes=len(PREFIX),sha256=digest),
 dict(event='handshake',alpn='absd-echo/1',early_data=False,resumed=False),dict(event='request-stream',stream_id=0,offset=0,bytes=2048,fin=False),dict(event='q05-post-echo-release',policy=POLICY,required_request_bytes=2048,request_bytes=2048,echo_enqueued_before=0),dict(event='echo-enqueue',offset=0,bytes=2048),
 dict(event='q05-post-handshake-armed',policy=POLICY,first_source_call=2,authenticated=True,request_bytes=2048,echo_enqueued_bytes=2048,prior_tx_datagrams=1,observed_ns=BASE.START)]
 f['events']=events[:2]+prefix+base
 f.update(reorder_stage='post-handshake',reorder_policy=POLICY,reorder_calls=4,reorder_batches=3,tx_datagrams=4,tx_bytes=3600+len(PREFIX))
 wire['peer_udp'].insert(0,{k:prefix[1][k] for k in ('bytes','sha256','source','destination')})
 return f,wire

def check(f,wire):return MATRIX.verify_duplicate_reorder(CASE,f,wire=wire,reorder_stage='post-handshake')

class PostHandshakeControls(unittest.TestCase):
 def test_exact_prefix_and_later_pair(self):
  f,w=proof();self.assertEqual(check(f,w)['first_send_ordinal'],2)
  with self.assertRaises(RuntimeError):MATRIX.verify_duplicate_reorder(CASE,f,wire=w)
  _,f,w=BASE.proof()
  with self.assertRaises(RuntimeError):check(f,w)
 def test_actual_peer_passes_handshake_then_holds_and_reorders_once(self):
  p=BASE.peer([[PREFIX],[BASE.A],[BASE.B],[b'next']]);p.reorder_stage='post-handshake';p.reorder_armed=False;p.authenticated=False;p.received=bytearray();p.echoed=0
  BASE.flush_at(p,BASE.START-10);self.assertEqual([d for d,_ in p.socket.sent],[PREFIX]);self.assertFalse(p.reorder_armed)
  p.authenticated=True;p.received=bytearray(b'x'*2048);p.echoed=2048;p.reorder_echo_released=True
  BASE.flush_at(p,BASE.START);self.assertEqual([d for d,_ in p.socket.sent],[PREFIX]);self.assertIsNotNone(p.reorder_held)
  BASE.flush_at(p,BASE.SECOND);BASE.flush_at(p,BASE.SECOND+10)
  self.assertEqual([d for d,_ in p.socket.sent],[PREFIX,BASE.B,BASE.A,BASE.A,b'next']);self.assertEqual(len([r for r in p.events if r['event']=='q05-post-handshake-armed']),1)
 def test_linux_consumed_pair_requires_authentication_and_full_send_order(self):
  f,w=proof()
  for row in f['events']:
   if row['event']=='udp-receive':row['source']=['127.0.0.1',50001]
   if row['event']=='udp-send':row.update(source=['127.0.0.1',50002],destination=['127.0.0.1',50001])
   if row['event']=='q05-public-call':
    for d in row['datagrams']:d['destination']=['127.0.0.1',50001]
  ledger=[dict(ordinal=i,bytes=len(d),sha256=BASE.digest(d),source=['127.0.0.1',50002],engine_delivered=True,authenticated_before=i>1)for i,d in enumerate((PREFIX,BASE.B,BASE.A,BASE.A),1)]
  MATRIX.verify_duplicate_reorder(CASE,f,client_datagrams=ledger,reorder_stage='post-handshake')
  for index in (1,2,3):
   changed=copy.deepcopy(ledger);changed[index]['authenticated_before']=False
   with self.subTest(index=index),self.assertRaises(RuntimeError):MATRIX.verify_duplicate_reorder(CASE,f,client_datagrams=changed,reorder_stage='post-handshake')
 def test_full_native_scope_retains_original_authority_and_success_checks(self):
  output,_,_=BASE.proof();f,w=proof();lines=[];traces=[]
  for text in output.splitlines():
   if text.startswith('QUIC RESULT '):
    row=MATRIX.fields(text);row.update(received='4',receive_bytes=str(3600+len(PREFIX)));text=BASE.line('QUIC RESULT',row)
   elif text.startswith('QUIC FIXTURE NATIVE_COUNTS '):
    row=MATRIX.fields(text);row['receive_delivered']='4';text=BASE.line('QUIC FIXTURE NATIVE_COUNTS',row)
   elif text.startswith('QUIC FIXTURE RX '):
    row=MATRIX.fields(text);ordinal=int(row['ordinal'])
    if ordinal==1:
     prefix=dict(row,ordinal='1',at_ms='30',bytes=str(len(PREFIX)),sha256=BASE.digest(PREFIX));lines.append(BASE.line('QUIC FIXTURE RX',prefix))
     traces.append(dict(prefix,receive_ordinal='1',stream_frames_before='0',stream_frames_after='0',authenticated_before='false',target_handled='true'))
    row['ordinal']=str(ordinal+1);text=BASE.line('QUIC FIXTURE RX',row)
    traces.append(dict(row,receive_ordinal=str(ordinal+1),stream_frames_before=str(min(ordinal-1,2)),stream_frames_after=str(min(ordinal,2)),authenticated_before='true',target_handled='true'))
   lines.append(text)
  lines.extend(BASE.line('QUIC REORDER RX',r)for r in traces);output='\n'.join(lines)
  self.assertEqual(MATRIX.verify_native(CASE,output,f,w,BASE.MANIFEST,reorder_stage='post-handshake')['actual_outcome'],'Complete')
  for before,after in [('authenticated=true','authenticated=false'),('status=0','status=1'),('end_ms=101','end_ms=10011')]:
   with self.subTest(before=before),self.assertRaises(RuntimeError):MATRIX.verify_native(CASE,output.replace(before,after),f,w,BASE.MANIFEST,reorder_stage='post-handshake')
 def test_no_arm_without_each_actual_gate(self):
  for field,value in [('authenticated',False),('received',bytearray()),('echoed',0)]:
   p=BASE.peer([[BASE.A]]);p.reorder_stage='post-handshake';p.reorder_armed=False;p.authenticated=True;p.received=bytearray(b'x');p.echoed=1;setattr(p,field,value)
   BASE.flush_at(p,BASE.START);self.assertFalse(p.reorder_armed);self.assertEqual(len(p.socket.sent),1)
 def test_actual_echo_waits_for2048_then_releases_once_without_changing_initial_stage(self):
  class Stream:
   def __init__(self):self.writes=[]
   def send_stream_data(self,stream_id,data,end_stream):self.writes.append((stream_id,bytes(data),end_stream))
  p=BASE.peer([]);p.connection=Stream();p.reorder_stage='post-handshake';p.reorder_echo_released=False;p.echoed=0;p.request_fin=p.echo_fin=False
  p.received=bytearray(PEER.pattern(1024));p.echo();self.assertEqual(p.connection.writes,[])
  p.received=bytearray(PEER.pattern(2048));p.echo();self.assertEqual(b''.join(r[1]for r in p.connection.writes),PEER.pattern(2048));self.assertEqual(p.echoed,2048)
  p.received=bytearray(PEER.pattern(2560));p.echo();self.assertEqual(len([r for r in p.events if r['event']=='q05-post-echo-release']),1)
  p=BASE.peer([]);p.connection=Stream();p.reorder_stage='initial';p.received=bytearray(PEER.pattern(512));p.echoed=0;p.request_fin=p.echo_fin=False;p.echo();self.assertEqual(len(p.connection.writes),1)
 def test_gate_receipt_missing_early_late_or_changed_cannot_establish_pair(self):
  for mutation in ['missing','duplicate','threshold','short','nonzeroecho','afterecho','notfirstcrossing']:
   f,w=proof();g=next(r for r in f['events']if r['event']=='q05-post-echo-release')
   if mutation=='missing':f['events'].remove(g)
   elif mutation=='duplicate':f['events'].append(copy.deepcopy(g))
   elif mutation=='threshold':g['required_request_bytes']=1024
   elif mutation=='short':g['request_bytes']=2047
   elif mutation=='nonzeroecho':g['echo_enqueued_before']=512
   elif mutation=='afterecho':f['events'].remove(g);f['events'].append(g)
   else:
    index=f['events'].index(g);f['events'].insert(index,dict(event='request-stream',stream_id=0,offset=2048,bytes=1,fin=False));g['request_bytes']=2049
   with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):check(f,w)
 def test_arming_and_prefix_substitutions_refuse(self):
  for mutation in ['absent','duplicate','early','wrongcall','txcount','request','echo','auth','policy','prefixbytes','prefixorigin','longheader']:
   f,w=proof();a=next(r for r in f['events']if r['event']=='q05-post-handshake-armed')
   if mutation=='absent':f['events'].remove(a)
   elif mutation=='duplicate':f['events'].append(copy.deepcopy(a))
   elif mutation=='early':f['events'].remove(a);f['events'].insert(2,a)
   elif mutation=='wrongcall':a['first_source_call']=1
   elif mutation=='txcount':a['prior_tx_datagrams']=0
   elif mutation=='request':a['request_bytes']=513
   elif mutation=='echo':a['echo_enqueued_bytes']=511
   elif mutation=='auth':a['authenticated']=False
   elif mutation=='policy':a['policy']='q05-two-output-hold-v2'
   elif mutation=='prefixbytes':next(r for r in f['events']if r['event']=='udp-send')['sha256']='f'*64
   elif mutation=='prefixorigin':next(r for r in f['events']if r['event']=='q05-engine-datagram-sent')['source_call']=2
   else:next(r for r in f['events']if r['event']=='q05-pair-ready')['datagrams'][0]['data_hex']='c0'+BASE.A[1:].hex()
   with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):check(f,w)
 def test_native_processing_requires_positive_originals_zero_duplicate_and_authentication(self):
  delivered=[dict(ordinal=i,bytes=1200,sha256=BASE.digest(d),source=['10.0.2.2',4443])for i,d in enumerate((BASE.B,BASE.A,BASE.A),1)]
  rows=[dict(case='Q05',at_ms=20+i,receive_ordinal=i,bytes=1200,sha256=d['sha256'],stream_frames_before=b,stream_frames_after=a,authenticated_before='true',target_handled='true')for i,d,b,a in zip(range(1,4),delivered,(0,1,2),(1,2,2))]
  output='\n'.join(BASE.line('QUIC REORDER RX',r)for r in rows);report=dict(received='3',receive_bytes='3600',start_ms='1',fence_ms='100')
  MATRIX.verify_post_handshake_processing(CASE,output,report,delivered,1)
  # Keep the counter sequence coherent: a zero-STREAM B must fail the
  # positive-original predicate itself, not a later continuity check.
  changed=copy.deepcopy(rows)
  for row,before,after in zip(changed,(0,0,1),(0,1,1)):row.update(stream_frames_before=before,stream_frames_after=after)
  with self.assertRaisesRegex(RuntimeError,'positive/duplicate'):
   MATRIX.verify_post_handshake_processing(CASE,'\n'.join(BASE.line('QUIC REORDER RX',r)for r in changed),report,delivered,1)
  for field,value,index in [('authenticated_before','false',0),('target_handled','false',1),('stream_frames_after',0,0),('stream_frames_after',3,2),('sha256','f'*64,1),('receive_ordinal',4,1),('at_ms',101,2)]:
   changed=copy.deepcopy(rows);changed[index][field]=value
   with self.subTest(field=field,index=index),self.assertRaises(RuntimeError):MATRIX.verify_post_handshake_processing(CASE,'\n'.join(BASE.line('QUIC REORDER RX',r)for r in changed),report,delivered,1)

if __name__=='__main__':unittest.main()
