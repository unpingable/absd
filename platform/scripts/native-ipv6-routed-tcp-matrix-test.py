#!/usr/bin/env python3
"""Finite routed TCP proof substitution controls; run only on admitted Linux VM."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE = Path(__file__).resolve().parent
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
m = load('paired_route_matrix', 'native-ipv6-routed-tcp-matrix.py')
old = load('unchanged_udp_controls', 'native-ipv6-route-matrix-test.py')

def packet(link, answer, transport, body):
    source, destination = (m.PEER,m.GUEST) if answer else (m.GUEST,m.PEER)
    if link=='guest':sm,dm = (m.ROUTER_MAC,m.GUEST_MAC) if answer else (m.GUEST_MAC,m.ROUTER_MAC)
    else:sm,dm = (m.PEER_MAC,m.UPLINK_MAC) if answer else (m.UPLINK_MAC,m.PEER_MAC)
    hop = (63 if answer else 64) if link=='guest' else (64 if answer else 63)
    body=bytearray(body);at=16 if transport==6 else 6;body[at:at+2]=bytes(2)
    body[at:at+2]=old.wire_sum(source+destination+struct.pack('!I3xB',len(body),transport)+body).to_bytes(2,'big')
    return dm+sm+bytes.fromhex('86dd60000000')+struct.pack('!HBB',len(body),transport,hop)+source+destination+body

def udp(link, answer, kind):
    q=old.query(kind);body=m.truncated(q) if answer else q;ports=(42010,7002) if answer else (7002,42010)
    return packet(link,answer,17,struct.pack('!HHHH',*ports,len(body)+8,0)+body)

def tcp(link, answer, flags, sequence, acknowledgement, data=b'', mss=1440):
    options=b'\x02\x04'+struct.pack('!H',mss) if flags&2 else b''
    ports=(42010,7003) if answer else (7003,42010)
    body=struct.pack('!HHIIBBHHH',*ports,sequence,acknowledgement,((20+len(options))//4)<<4,flags,65535,0,0)+options+data
    return packet(link,answer,6,body)

def streams():
    queries=[old.query(k) for k in (1,28)];answers=[m.dns.answer(q)for q in queries]
    framed=lambda b:len(b).to_bytes(2,'big')+b
    return queries,answers,[framed(q)for q in queries],[framed(a)for a in answers]

def peer():
    qs,ans,query,answer=streams();records=[];events=[]
    def event(name,**kw):events.append({'event':name,'monotonic_ns':len(events)+1,'realtime_ns':len(events)+1,**kw})
    for at,kind in enumerate((1,28)):
        name=m.dns.question(qs[at])[0]
        for transport,source,a in [('UDP',7002,m.truncated(qs[at])),('TCP',7003,ans[at])]:
            records.append({'transport':transport,'name':name,'kind':kind,'port':42010,'source':[m.GUEST_IP,source,0,0],'query_hex':qs[at].hex(),'answer_hex':a.hex(),'monotonic_ns':len(records)+1,'realtime_ns':len(records)+1})
        event('udp-recv',source=[m.GUEST_IP,7002,0,0],port=42010,flags=0,hex=qs[at].hex())
        tc=m.truncated(qs[at]);event('udp-send',destination=[m.GUEST_IP,7002,0,0],port=42010,requested=len(tc),count=len(tc),hex=tc.hex())
        if at==0:event('tcp-accept',source=[m.GUEST_IP,7003,0,0],port=42010)
        event('tcp-recv',count=len(query[at]),hex=query[at].hex())
        event('tcp-send',requested=len(answer[at]),count=len(answer[at]),hex=answer[at].hex())
    event('tcp-recv',count=0,hex='');event('tcp-write-shutdown');event('tcp-close')
    received,sent=b''.join(query),b''.join(answer)
    return {'schema_version':1,'disposition':'PASS','errors':[],'pid':123,'bind':m.PEER_IP,'port':42010,'forbidden_port':42011,'codec_sha256':m.DNS_HASH,'stop_reason':'PEER-STOP','records':records,'io':events,
            'limits':{'dns_bytes':1232,'stream_bytes':4096,'io_events':128},'tcp':{'source':[m.GUEST_IP,7003,0,0],'connections':1,'read_eof':True,'write_shutdown':True,'closed':True,'pending_hex':'','unsent_hex':'','received_hex':received.hex(),'sent_hex':sent.hex(),'received_sha256':m.digest(received)['sha256'],'sent_sha256':m.digest(sent)['sha256'],'received_frames':[q.hex()for q in qs],'sent_frames':[a.hex()for a in ans]}}

def frames(link):
    qs,ans,q,a=streams();c,s=1001,2001
    first=[tcp(link,False,2,1000,0),tcp(link,True,0x12,2000,c),tcp(link,False,0x10,c,s),tcp(link,False,0x18,c,s,q[0]),tcp(link,True,0x18,s,c+len(q[0]),a[0])]
    c+=len(q[0]);s+=len(a[0]);first.append(tcp(link,False,0x10,c,s))
    second=[tcp(link,False,0x18,c,s,q[1]),tcp(link,True,0x18,s,c+len(q[1]),a[1])]
    c+=len(q[1]);s+=len(a[1]);second += [tcp(link,False,0x10,c,s),tcp(link,False,0x11,c,s),tcp(link,True,0x10,s,c+1),tcp(link,True,0x11,s,c+1),tcp(link,False,0x10,c+1,s+1)]
    return old.nd(link)+[udp(link,False,1),udp(link,True,1)]+first+[udp(link,False,28),udp(link,True,28)]+second

def output():
    text=old.output().replace('ROUTE6 ','ROUTE6TCP ')
    text=text.replace('ROUTE6TCP API BOUNDARIES','ROUTE6 API BOUNDARIES').replace('ROUTE6TCP PIPE BOUNDARIES','ROUTE6 PIPE BOUNDARIES')
    text=text.replace('NO-ROUTE REFUSAL PASS bind=denied','NO-ROUTE REFUSAL PASS udp=denied tcp=denied')
    text=text.replace('SERVICE READY scope=1 local-port=7002','SERVICE READY scope=1 udp-local-port=7002 tcp-local-port=7003 path-mtu=1500')
    text=text.replace('framed-denied=3','udp-denied=3 tcp-denied=3')
    return text.replace('ROUTE6TCP RETIRE sockets=0','ROUTE6TCP DNS CLOSE PASS\nROUTE6TCP CLOSE DRAIN observed-ms=1000\nROUTE6TCP RETIRE sockets=0')

class RoutedTcpControls(unittest.TestCase):
    def inspect(self,g=None,p=None,r=None):
        r=peer()if r is None else r
        observed=m.peer_result(json.dumps(r).encode())
        return m.inspect(old.capture(frames('guest')if g is None else g),old.capture(frames('peer')if p is None else p),observed)
    def test_complete_two_link_udp_tc_tcp_stream_and_fin_ack_correspondence(self):self.assertEqual(self.inspect()['connections'],1)
    def test_exact_source_full_tuple_and_wrong_destination_port_refuse(self):
        for at in (22,38,54,56):
            f=bytearray(frames('guest')[7]);f[at]^=1
            self.assertEqual(m.classify({'frame':bytes(f),'index':0,'timestamp':1},'guest')['kind'],'unexplained')
    def test_tcp_checksum_truncation_reserved_bits_and_padding_refuse(self):
        f=frames('guest')[7]
        for changed in (f[:-1],f+b'\0',f[:70]+bytes([f[70]^1])+f[71:],f[:66]+bytes([f[66]|1])+f[67:]):
            self.assertEqual(m.classify({'frame':changed,'index':0,'timestamp':1},'guest')['kind'],'unexplained')
    def test_guest_mss1440_is_required_for_explicit1500_path(self):
        with self.assertRaises(AssertionError):m.classify({'frame':tcp('guest',False,2,1000,0,mss=1220),'index':0,'timestamp':1},'guest')
    def test_udp_tc_replaced_by_untruncated_answer_refuses(self):
        g=frames('guest');g[3]=old.udp('guest',True,1)
        with self.assertRaises(AssertionError):self.inspect(g=g)
    def test_missing_one_hop_packet_refuses(self):
        p=frames('peer');del p[7]
        with self.assertRaises(AssertionError):self.inspect(p=p)
    def test_missing_second_tc_before_tcp_question_refuses(self):
        g=frames('guest');g[11],g[12]=g[12],g[11]
        with self.assertRaises(AssertionError):self.inspect(g=g)
    def test_tcp_contact_before_first_tc_refuses(self):
        g=frames('guest');g[3],g[4]=g[4],g[3]
        with self.assertRaises(AssertionError):self.inspect(g=g)
    def test_gapped_or_conflicting_tcp_stream_refuses(self):
        for delta in (1,99):
            g=frames('guest');q=streams()[2][0];g[7]=tcp('guest',False,0x18,1001+delta,2001,q)
            with self.assertRaises(AssertionError):self.inspect(g=g)
    def test_missing_or_wrong_fin_position_refuses(self):
        for index in (-4,-2):
            g=frames('guest');del g[index]
            with self.assertRaises(AssertionError):self.inspect(g=g)
    def test_second_connection_and_missing_fin_ack_refuse(self):
        g=frames('guest');g.insert(8,tcp('guest',False,2,3000,0))
        with self.assertRaises(AssertionError):self.inspect(g=g)
        g=frames('guest');del g[-1]
        with self.assertRaises(AssertionError):self.inspect(g=g)
    def test_premature_final_ack_in_both_link_domains_refuses(self):
        for a,b,message in [(-1,-2,'client never ACKed observed peer FIN'),(-4,-2,'peer never ACKed observed client FIN')]:
            g,p=frames('guest'),frames('peer');g[a],g[b]=g[b],g[a];p[a],p[b]=p[b],p[a]
            with self.assertRaisesRegex(AssertionError,message):self.inspect(g=g,p=p)
    def test_client_data_before_observed_synack_refuses(self):
        g,p=frames('guest'),frames('peer');g[5],g[7]=g[7],g[5];p[5],p[7]=p[7],p[5]
        with self.assertRaisesRegex(AssertionError,'SYNACK|handshake'):self.inspect(g=g,p=p)
    def test_socket_wrong_source_port_order_id_and_stream_refuse(self):
        for mutate in (lambda r:r['records'][1]['source'].__setitem__(1,7004),lambda r:r['records'].reverse(),lambda r:r['records'][1].__setitem__('query_hex','00'+r['records'][1]['query_hex'][2:]),lambda r:r['tcp'].__setitem__('received_hex','00')):
            r=peer();mutate(r)
            with self.assertRaises(AssertionError):self.inspect(r=r)
    def test_intended_answers_without_actual_udp_or_tcp_send_refuse(self):
        for event in ('udp-send','tcp-send'):
            r=peer();r['io']=[x for x in r['io']if x['event']!=event]
            with self.assertRaises(AssertionError):self.inspect(r=r)
    def test_unknown_io_short_send_forbidden_destination_and_second_accept_refuse(self):
        for mutate in (lambda r:r['io'][0].__setitem__('event','unparsed'),lambda r:r['io'][1].__setitem__('count',0),lambda r:r['io'][0].__setitem__('port',42011),lambda r:r['tcp'].__setitem__('connections',2)):
            r=peer();mutate(r)
            with self.assertRaises(AssertionError):self.inspect(r=r)
    def test_partial_stream_pending_bytes_missing_eof_and_shutdown_refuse(self):
        for key,value in [('pending_hex','00'),('unsent_hex','00'),('read_eof',False),('write_shutdown',False),('closed',False)]:
            r=peer();r['tcp'][key]=value
            with self.assertRaises(AssertionError):self.inspect(r=r)
    def test_exact_new_native_authority_close_and_resource_output(self):self.assertEqual(m.native_output(old.serial(output()),3)['census_after'][:4],[2,13,2,1])
    def test_native_missing_tcp_denial_close_marker_or_short_drain_refuses(self):
        for a,b in [('tcp-denied=3','tcp-denied=2'),('ROUTE6TCP DNS CLOSE PASS\n',''),('observed-ms=1000','observed-ms=999')]:
            with self.assertRaises(AssertionError):m.native_output(old.serial(output().replace(a,b)),3)
    def test_build_source_manifest_command_and_nested_outputs_are_exact(self):
        r,b=old.build_fixture();r['schema']='absd-native-ipv6-routed-tcp-build/1';r['platform'].update(revision=m.PRODUCT,tree=m.PRODUCT_TREE,archive={'bytes':m.PRODUCT_BYTES,'sha256':m.PRODUCT_ARCHIVE});r['commands'][0]=['sh','scripts/build-native-ipv6-routed-tcp.sh'];m.build_binding(r,b)
        for mutate in (lambda q:q['platform'].__setitem__('clean',False),lambda q:q['commands'].__setitem__(0,['sh','scripts/build-native-ipv6-route.sh']),lambda q:q['outputs']['parent'].__setitem__('sha256','0'*64)):
            bad=copy.deepcopy(r);mutate(bad)
            with self.assertRaises(AssertionError):m.build_binding(bad,b)
    def test_actual_iso_extents_and_exact1500_linux_topology(self):
        kernel=old.elf(b'kernel');cfg=b'boot';m.iso_binding(old.iso(kernel,cfg),kernel,cfg)
        state=old.topology();state['transport']='Linux kernel IPv6 forwarding and AF_INET6 UDP/TCP; application DNS answers are controlled fixtures';m.validate_topology(state)
        state['namespaces']['router']['links'][1]['mtu']=1280
        with self.assertRaises(AssertionError):m.validate_topology(state)

if __name__=='__main__':unittest.main()
