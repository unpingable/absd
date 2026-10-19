#!/usr/bin/env python3
"""Authored artifact controls; execute only on the separately admitted host."""
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
from pathlib import Path
import signal
import struct
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('dad_matrix',Path(__file__).with_name('native-ipv6-dad-matrix.py'))
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def checksum(data):
    total=0
    for at in range(0,len(data),2):
        total+=(data[at]<<8)+(data[at+1] if at+1<len(data) else 0)
        total=(total&65535)+(total>>16)
    return total^65535


def frame(src,dst,payload,protocol,outgoing,dstmac=None,hop=255):
    srcmac=m.GUEST_MAC if outgoing else m.HOST_MAC
    dstmac=dstmac or (m.HOST_MAC if outgoing else m.GUEST_MAC)
    payload=bytearray(payload);offset=2 if protocol==58 else 6;payload[offset:offset+2]=bytes(2)
    value=checksum(src+dst+struct.pack('!I3xB',len(payload),protocol)+payload)
    payload[offset:offset+2]=(value or 65535).to_bytes(2,'big')
    return dstmac+srcmac+b'\x86\xdd\x60\0\0\0'+struct.pack('!HBB',len(payload),protocol,hop)+src+dst+payload


def dad(outgoing=True):
    return frame(bytes(16),m.SOL,b'\x87\0'+bytes(6)+m.GUEST,58,outgoing,b'\x33\x33\xff\0\0\x15')


def defense(outgoing=True):
    mac=m.GUEST_MAC if outgoing else m.HOST_MAC
    return frame(m.GUEST,m.ALL,b'\x88\0'+bytes(2)+b'\x20\0\0\0'+m.GUEST+b'\x02\x01'+mac,58,outgoing,b'\x33\x33\0\0\0\x01')


def normal_nd():
    sol=m.original.solicited(m.HOST)
    ns=frame(m.GUEST,sol,b'\x87\0'+bytes(6)+m.HOST+b'\x01\x01'+m.GUEST_MAC,58,True,b'\x33\x33\xff\0\0\x02')
    na=frame(m.HOST,m.GUEST,b'\x88\0'+bytes(2)+b'\x60\0\0\0'+m.HOST+b'\x02\x01'+m.HOST_MAC,58,False)
    return [ns,na]


def question(kind):
    name=b'\x01a\x07example\0' if kind==1 else b'\x04aaaa\x07example\0'
    return struct.pack('!HHHHHH',kind,0x100,1,0,0,0)+name+struct.pack('!HH',kind,1)


def udp(payload,outgoing=True):
    src,dst=(m.GUEST,m.HOST) if outgoing else (m.HOST,m.GUEST)
    ports=(7002,42010) if outgoing else (42010,7002)
    return frame(src,dst,struct.pack('!HHHH',*ports,8+len(payload),0)+payload,17,outgoing,hop=64)


def capture(frames):
    raw=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65536,1)
    for i,f in enumerate(frames):raw+=struct.pack('<IIII',1,i,len(f),len(f))+f
    return raw


def interface_fixture():
    # Literal iproute2 6.1.0 loopback shapes from native2c3226ba readback.
    # Only the named fixture role fields below are substituted for the TAP;
    # these are not snapshots of the already deleted failed-case TAP.
    addresses=m.json.loads('[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"qdisc":"noqueue","operstate":"UNKNOWN","group":"default","txqlen":1000,"addr_info":[{"family":"inet6","local":"::1","prefixlen":128,"scope":"host","noprefixroute":true,"valid_life_time":4294967295,"preferred_life_time":4294967295}]}]')
    links=m.json.loads('[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"qdisc":"noqueue","operstate":"UNKNOWN","linkmode":"DEFAULT","group":"default","txqlen":1000,"link_type":"loopback","address":"00:00:00:00:00:00","broadcast":"00:00:00:00:00:00"}]')
    for row in (addresses[0],links[0]):row.update(ifindex=7,ifname='dad-tap0',mtu=1500)
    addresses[0]['addr_info'][0].update(local=m.HOST_IP,prefixlen=64,scope='global')
    links[0]['address']=m.HOST_MAC.hex(':')
    return addresses,links


def artifacts(case='unused'):
    frames=[dad()];peer={'transport':'Linux AF_INET6 SOCK_DGRAM','normal_exit':True,'errors':[],'records':[]};action={}
    if case=='duplicate':
        frames.append(defense(False));action={'assigned_before_launch':[{'addr_info':[{'local':m.GUEST_IP}]}]}
    elif case=='simultaneous':
        prefix=capture(frames);action={'trigger':'captured guest tentative NS','add_result':0,'capture_prefix':m.digest(prefix),'complete_records':1}
        frames.append(dad(False))
    else:
        frames.extend(normal_nd())
        for kind in (1,28):
            q=question(kind);answer=m.peer_fixture.answer(q);frames.append(udp(q))
            if case=='active-defense' and kind==1:
                frames.extend([dad(False),defense()])
                action={'trigger':'Linux socket received first A query','query_hex':q.hex(),'add_result':0,'delete_result':0,
                        'dad_snapshots':[[{'addr_info':[{'local':m.GUEST_IP,'tentative':True,'dadfailed':True}]}]],
                        'after_delete':[{'addr_info':[{'local':m.HOST_IP}]}],'add_start_monotonic_ns':2,
                        'dadfailed_observed_monotonic_ns':3,'delete_complete_monotonic_ns':4}
            frames.append(udp(answer,False))
            peer['records'].append({'source':[m.GUEST_IP,7002,0,1],'destination_port':42010,'query_hex':q.hex(),
                                    'answer_hex':answer.hex(),'received_monotonic_ns':1,'sent_monotonic_ns':5})
    peer['action']=copy.deepcopy(action)
    return frames,{'positive':case in ('unused','active-defense')},peer,action


def serial(case='unused'):
    positive=case in ('unused','active-defense')
    if positive:
        text=('IPV6 DAD CLEAR local=fd00:ab5d::15 scope=1 auth=none uniqueness=unproven\n'
              'IPV6 DAD SERVICE READY scope=1 udp=7002 peer-port=42010\n'
              'IPV6 DAD CLIENT AUTHORITY PASS scope-and-peer-refused no-nic\n'
              'IPV6 DAD DNS A PASS address=192.0.2.9\n'
              'IPV6 DAD DNS AAAA PASS address=2001:db8::9\n'
              'IPV6 DAD SERVICE PASS child=exited sockets=0 probes=1 defenses='+('1' if case=='active-defense' else '0')+' received=5 malformed=0\n').encode()
    else:text=b'IPV6 DAD SERVICE ERROR DAD acquisition refused Conflict\n'
    raw=(b'NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n'
         b'EXTERNAL OUTPUT CHUNK offset=0000000000000000 data='+text.hex().encode()+b'\n')
    if positive:
        value=0x811c9dc5
        for b in text:value=((value^b)*0x01000193)&0xffffffff
        raw+=(b'SPAWN OK pid=3 parent=2 program=image\nUSER EXIT pid=3 status=0\nUSER EXIT pid=2 status=0\n'
              b'EXTERNAL OUTPUT END bytes='+str(len(text)).encode()+b' digest='+f'{value:08x}'.encode()+b'\n')
    else:
        raw+=(b'USER EXIT pid=2 status=1\nDURABLE WORKER OUTCOME generation=1 pid=2 status=1\n'
              b'init: FAILED at durable worker outcome\n')
    raw+=b'DURABLE status='+ (b'0' if positive else b'99') +b' frames=0 processes=0 cells=0 pipes=0 ticks=2000\n'
    raw+=b'NIC STATS rx_frames=2 tx_frames=1 rx_refused=0 rx_missed=0 tx_refused=0 tx_errors=0 flags=1\n'
    raw+=b'DURABLE WORKLOAD OK\nABSD BOOT OK\n' if positive else b'DURABLE WORKLOAD FAILED\n'
    return raw


class ArtifactControls(unittest.TestCase):
    def inspect(self,case='unused',change=None):
        frames,obs,peer,action=artifacts(case)
        if change:change(frames,obs,peer,action)
        return m.inspect(capture(frames),obs,peer,action,case)

    def refuse(self,case,change):
        with self.assertRaises((AssertionError,ValueError,KeyError)):
            self.inspect(case,change)

    def test_unused_requires_real_dad_nd_and_both_dns_families(self):
        r=self.inspect();self.assertEqual(len(r['queries']),2);self.assertEqual(r['by_kind']['guest-dad-ns'],[1])

    def test_preassigned_duplicate_requires_actual_linux_multicast_na(self):
        r=self.inspect('duplicate');self.assertEqual(r['by_kind']['linux-duplicate-na'],[2]);self.assertFalse(r['queries'])

    def test_simultaneous_requires_kernel_ns_after_captured_probe(self):
        self.assertEqual(self.inspect('simultaneous')['by_kind']['linux-dad-ns'],[2])

    def test_active_kernel_dadfailed_and_fixed_defense_gate_a_reply(self):
        r=self.inspect('active-defense');self.assertEqual(r['by_kind']['guest-dad-na'],[6])

    def test_unknown_capture_frame_is_never_omitted(self):
        self.refuse('unused',lambda f,o,p,a:f.append(bytes(60)))

    def test_truncated_capture_refuses(self):
        f,o,p,a=artifacts()
        with self.assertRaises(AssertionError):m.inspect(capture(f)[:-1],o,p,a,'unused')

    def test_dad_checksum_corruption_refuses(self):
        def mutate(f,o,p,a):
            x=bytearray(f[0]);x[56]^=1;f[0]=bytes(x)
        self.refuse('unused',mutate)

    def test_wrong_candidate_even_with_valid_checksum_refuses(self):
        def mutate(f,o,p,a):
            wrong=bytearray(m.GUEST);wrong[-1]^=1
            f[0]=frame(bytes(16),m.SOL,b'\x87\0'+bytes(6)+bytes(wrong),58,True,b'\x33\x33\xff\0\0\x15')
        self.refuse('unused',mutate)

    def test_wrong_source_and_slla_are_not_kernel_dad_witnesses(self):
        for src,option in [(m.GUEST,b''),(bytes(16),b'\x01\x01'+m.GUEST_MAC)]:
            self.refuse('unused',lambda f,o,p,a:f.__setitem__(0,frame(src,m.SOL,b'\x87\0'+bytes(6)+m.GUEST+option,58,True,b'\x33\x33\xff\0\0\x15')))

    def test_fixed_defense_flags_cannot_be_solicited(self):
        def mutate(f,o,p,a):
            f[5]=frame(m.GUEST,m.ALL,b'\x88\0'+bytes(2)+b'\x60\0\0\0'+m.GUEST+b'\x02\x01'+m.GUEST_MAC,58,True,b'\x33\x33\0\0\0\x01')
        self.refuse('active-defense',mutate)

    def test_duplicate_with_no_actual_na_is_not_established(self):
        self.refuse('duplicate',lambda f,o,p,a:f.pop())

    def test_duplicate_assignment_must_already_be_usable(self):
        self.refuse('duplicate',lambda f,o,p,a:a['assigned_before_launch'][0]['addr_info'][0].update(tentative=True))

    def test_refused_acquisition_cannot_have_application_traffic(self):
        self.refuse('duplicate',lambda f,o,p,a:f.append(udp(question(1))))

    def test_simultaneous_without_ns_is_not_established(self):
        self.refuse('simultaneous',lambda f,o,p,a:f.pop())

    def test_simultaneous_action_prefix_is_exact(self):
        self.refuse('simultaneous',lambda f,o,p,a:a['capture_prefix'].update(sha256='0'*64))

    def test_active_without_linux_dadfailed_is_not_established(self):
        self.refuse('active-defense',lambda f,o,p,a:a['dad_snapshots'][0][0]['addr_info'][0].update(dadfailed=False))

    def test_active_answer_before_guest_na_is_not_established(self):
        def mutate(f,o,p,a):f[5],f[6]=f[6],f[5]
        self.refuse('active-defense',mutate)

    def test_failed_candidate_must_be_removed_before_dns_send(self):
        self.refuse('active-defense',lambda f,o,p,a:a.update(after_delete=[{'addr_info':[{'local':m.GUEST_IP}]}]))
        self.refuse('active-defense',lambda f,o,p,a:a.update(delete_complete_monotonic_ns=6))

    def test_socket_receive_and_wire_counts_must_agree(self):
        self.refuse('unused',lambda f,o,p,a:p['records'].pop())

    def test_socket_answer_bytes_are_not_an_oracle_for_wrong_answer(self):
        def mutate(f,o,p,a):
            wrong=bytearray.fromhex(p['records'][0]['answer_hex']);wrong[-1]^=1
            p['records'][0]['answer_hex']=wrong.hex();f[4]=udp(wrong,False)
        self.refuse('unused',mutate)

    def test_more_identical_answers_than_prior_query_copies_refuse(self):
        def mutate(f,o,p,a):
            f[5:5]=[f[4],f[3]];p['records'].insert(1,copy.deepcopy(p['records'][0]))
        self.refuse('unused',mutate)

    def test_missing_aaaa_cannot_pass_from_a_marker(self):
        self.refuse('unused',lambda f,o,p,a:(f.pop(),f.pop(),p['records'].pop()))

    def test_normal_nd_must_precede_dns(self):
        self.refuse('unused',lambda f,o,p,a:f.__delitem__(slice(1,3)))

    def test_positive_native_boot_digest_and_markers(self):
        r=m.native_output(serial(),3,'unused');self.assertTrue(r['positive']);self.assertIn('not exported',r['phase_time_limit'])

    def test_expected_negative_is_exact_refusal_not_generic_failure(self):
        self.assertFalse(m.native_output(serial('duplicate'),7,'duplicate')['positive'])
        with self.assertRaises(AssertionError):m.native_output(serial('duplicate').replace(b'Conflict'.hex().encode(),b'Link'.hex().encode()),7,'duplicate')

    def test_negative_must_not_spawn_a_child(self):
        with self.assertRaises(AssertionError):m.native_output(serial('duplicate')+b'SPAWN OK pid=3 parent=2 program=image\n',7,'duplicate')

    def test_native_resource_residue_wrong_exit_or_digest_refuses(self):
        with self.assertRaises(AssertionError):m.native_output(serial().replace(b'processes=0',b'processes=1'),3,'unused')
        with self.assertRaises(AssertionError):m.native_output(serial(),7,'unused')
        with self.assertRaises(AssertionError):m.native_output(serial().replace(b'digest=',b'digest=0'),3,'unused')

    def test_active_defense_marker_cannot_replace_wire_or_state(self):
        with self.assertRaises(AssertionError):m.native_output(serial(),3,'active-defense')

    def test_exact_build_source_archive_and_output_binding(self):
        child=b'\x7fELFchild';parent=b'\x7fELFparent'+child;kernel=b'\x7fELFkernel'+parent;buffers=dict(child=child,parent=parent,kernel=kernel)
        receipt={'schema':'absd-native-ipv6-dad-build/1','platform':{'revision':m.PRODUCT,'tree':m.PRODUCT_TREE,'clean':True,'archive':{'bytes':1,'sha256':m.PRODUCT_ARCHIVE}},
                 'kernel':{'revision':m.KERNEL,'tree':m.KERNEL_TREE,'clean':True,'archive':{'bytes':1,'sha256':m.KERNEL_ARCHIVE}},
                 'commands':[['scripts/build-native-ipv6-dad.sh'],['EXTERNAL_USER_ELF=parent']],
                 'logs':[{'bytes':1,'sha256':'1'*64}],'toolchain_receipt':{'bytes':1,'sha256':'2'*64},'outputs':{k:m.digest(v) for k,v in buffers.items()}}
        m.build_binding(receipt,buffers)
        for path in [('platform','revision'),('platform','archive','sha256'),('kernel','tree'),('outputs','child','sha256')]:
            bad=copy.deepcopy(receipt);at=bad
            for key in path[:-1]:at=at[key]
            at[path[-1]]='0'*64
            with self.assertRaises(AssertionError):m.build_binding(bad,buffers)
        bad=dict(buffers);bad['kernel']+=parent
        receipt['outputs']['kernel']=m.digest(bad['kernel'])
        with self.assertRaises(AssertionError):m.build_binding(receipt,bad)

    def test_owned_group_cleanup_runs_even_after_leader_exit(self):
        class Process:
            pid=12345
            def poll(self):return 0
        live=[True];signals=[]
        def killpg(pid,sig):
            self.assertEqual(pid,12345)
            if sig==0:
                if not live[0]:raise ProcessLookupError()
            else:signals.append(sig);live[0]=False
        with patch.object(m.os,'killpg',side_effect=killpg):
            result=m.stop_owned(Process())
        self.assertEqual(signals,[signal.SIGTERM]);self.assertTrue(result['group_absent']);self.assertFalse(result['forced'])

    def semantic_artifacts(self, directory, case):
        frames,obs,peer,action=artifacts(case)
        raw_capture=capture(frames)
        m.inspect(raw_capture,obs,peer,action,case)
        facts={'PEER-RESULT.json':peer,'CASE-ACTION.json':action,
               'LINUX-SETUP.json':{'action':action if case=='duplicate' else {},'namespace':'fixture'},
               'LINUX-LISTENERS.json':{'ports':[42010,42011]},
               'PEER-READY.json':{'pid':123,'namespace_inode':456},
               'LAUNCH.json':{'case':case,'peer_ready':{'pid':123,'namespace_inode':456}}}
        if case=='active-defense':facts['ACTIVE-DAD.json']=action
        if case=='simultaneous':facts['SIMULTANEOUS-DAD.json']=action
        evaluated={}
        for name,value in facts.items():
            data=m.write(directory/name,value)
            self.assertEqual(m.json.loads(data),value)
            evaluated[name]=m.identity(directory/name,data)
        (directory/'native-ipv6-dad.pcap').write_bytes(raw_capture)
        evaluated['native-ipv6-dad.pcap']=m.identity(directory/'native-ipv6-dad.pcap',raw_capture)
        return {'evaluated_build_inputs':{},'evaluated_artifacts':evaluated},facts

    def test_unmutated_evaluated_semantic_buffers_seal_exactly(self):
        for case in m.CASES:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);result,facts=self.semantic_artifacts(root,case)
                sealed=m.seal_artifacts(root,result)
                self.assertEqual(set(sealed),set(facts)|{'native-ipv6-dad.pcap'})
                for name in facts:self.assertEqual(sealed[name],result['evaluated_artifacts'][name])

    def test_semantic_content_mutation_after_evaluation_is_not_sealed(self):
        for case in m.CASES:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);result,facts=self.semantic_artifacts(root,case)
                for name,value in facts.items():
                    path=root/name;original=path.read_bytes()
                    changed=copy.deepcopy(value)
                    changed['post_evaluation_change']=True
                    path.write_text(m.json.dumps(changed)+'\n')
                    with self.subTest(file=name),self.assertRaises(AssertionError):
                        m.seal_artifacts(root,result)
                    path.write_bytes(original)
                capture_path=root/'native-ipv6-dad.pcap';original_capture=capture_path.read_bytes()
                capture_path.write_bytes(original_capture+b'\0')
                with self.assertRaises(AssertionError):m.seal_artifacts(root,result)
                capture_path.write_bytes(original_capture)
                m.seal_artifacts(root,result)

    def test_active_peer_action_must_equal_separate_action_evidence(self):
        def mutate(f,o,p,a):p['action']['query_hex']='0000'
        self.refuse('active-defense',mutate)

    def test_refused_acquisition_cannot_have_ordinary_candidate_nd(self):
        def mutate(f,o,p,a):f[1:1]=normal_nd()
        self.refuse('duplicate',mutate)

    def test_positive_ordinary_nd_cannot_precede_tentative_probe(self):
        def mutate(f,o,p,a):f[:3]=f[1:3]+f[:1]
        self.refuse('unused',mutate)

    def test_returned_cleanup_fact_is_bound_before_final_seal(self):
        # Exercise the actual return/finally path. External effects are local
        # fixtures; the original packet inspector and final seal still run.
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);work=root/'work';work.mkdir()
            child=b'\x7fELFchild';parent=b'\x7fELFparent'+child;kernel=b'\x7fELFkernel'+parent
            inputs={}
            for name,data in [('child',child),('parent',parent),('kernel',kernel),('source',b'source'),('log',b'log')]:
                path=root/name;path.write_bytes(data);inputs[name]=path
            source=m.identity(inputs['source'],b'source');log=m.identity(inputs['log'],b'log')
            receipt=root/'build.json'
            m.write(receipt,{'platform':{'archive':source},'kernel':{'archive':source},'logs':[log],'toolchain_receipt':log})
            args=m.argparse.Namespace(work=work,case='unused',timeout=120,lease=m.time.time()+3600,
                                      lease_end='fixture lease',client_elf=inputs['child'],elf=inputs['parent'],
                                      kernel_elf=inputs['kernel'],build_receipt=receipt)
            frames,_,peer,_=artifacts();raw_capture=capture(frames);raw_serial=serial()
            namespace=[];settings={};listener_reads=[0];processes=[]
            class Process:
                returncode=0
                def __init__(self):self.pid=12340+len(processes);processes.append(self)
                def poll(self):return self.returncode
            class Marker:
                def __init__(self,*args):pass
                def poll(self,**kwargs):pass
                def seal(self,*args):pass
            real_stat=m.os.stat
            def fixture_stat(path,*args,**kwargs):
                if str(path).startswith('/run/netns/'):return m.argparse.Namespace(st_ino=456)
                return real_stat(path,*args,**kwargs)
            def command(argv,*args):
                if argv[:3]==['ip','netns','list']:return ''.join(name+'\n' for name in namespace)
                if argv[:3]==['ip','netns','add']:namespace.append(argv[3]);return ''
                if argv[:3]==['ip','netns','pids']:return ''
                if argv[:3]==['ip','netns','del']:namespace.remove(argv[3]);return ''
                if argv[:3]!=['ip','netns','exec']:return ''
                inner=argv[4:]
                if inner[:2]==[m.sys.executable,'-c']:
                    return m.json.dumps({path:'present' for path in inner[3:]})
                if inner[:2]==['sysctl','-qw']:
                    key,value=inner[2].split('=',1);settings[key]=value;return ''
                if inner[:2]==['sysctl','-n']:return settings[inner[2]]+'\n'
                if inner[:4]==['ip','-j','-6','address']:
                    return m.json.dumps(interface_fixture()[0])
                if inner[:3]==['ip','-j','link']:return m.json.dumps(interface_fixture()[1])
                if inner[:4]==['ip','-j','-6','route']:
                    return m.json.dumps([{'dst':'fd00:ab5d::/64','dev':'dad-tap0'}])
                if inner[0]=='ss':
                    listener_reads[0]+=1
                    return ''.join(f'UNCONN 0 0 [{m.HOST_IP}]:{port} [::]:*\n' for port in (42010,42011)) if listener_reads[0]==1 else ''
                raise AssertionError('unexpected fixture command: '+repr(argv))
            def popen(argv,**kwargs):
                process=Process()
                if argv[0]=='grub-mkrescue':(work/'native-ipv6-dad.iso').write_bytes(b'ISO'+kernel)
                elif '--peer-worker' in argv:
                    m.write(work/'PEER-READY.json',{'pid':process.pid,'namespace_inode':456})
                    m.write(work/'PEER-RESULT.json',peer)
                else:
                    process.returncode=3
                    (work/'native-ipv6-dad.pcap').write_bytes(raw_capture)
                    (work/'native-ipv6-dad.serial.log').write_bytes(raw_serial)
                return process
            def reason(*args):
                sidecar=b'fixture annotation';(work/'NIC-READY-CAPTURE.json').write_bytes(sidecar)
                value={'capture_sha256':m.digest(raw_capture)['sha256'],'serial_sha256':m.digest(raw_serial)['sha256'],
                       'annotation_sha256':m.digest(sidecar)['sha256']}
                m.write(work/'NIC-REASON-ACCOUNTING.json',value);return value
            with ExitStack() as stack:
                for obj,name,value in [(m.os,'geteuid',lambda:0),(m.os,'stat',fixture_stat),(m,'command',command),
                                       (m.subprocess,'Popen',popen),(m.shutil,'which',lambda _: '/fixture/qemu'),
                                       (m.original,'ReadyMarker',Marker),(m.reasons,'evaluate',reason),
                                       (m,'build_binding',lambda *_:None),
                                       (m,'stop_owned',lambda _: {'status':0,'group_absent':True,'forced':False})]:
                    stack.enter_context(patch.object(obj,name,value))
                result=m.run(args)
            self.assertFalse(namespace)
            cleanup=work/'LOCAL-CLEANUP.json';original=cleanup.read_bytes()
            self.assertEqual(m.json.loads(original)['disposition'],'PASS')
            self.assertEqual(result['evaluated_artifacts']['LOCAL-CLEANUP.json'],m.identity(cleanup,original))
            m.seal_artifacts(work,result)
            changed=m.json.loads(original);changed['disposition']='FAIL';changed['errors']=['post-evaluation fixture change']
            cleanup.write_text(m.json.dumps(changed)+'\n')
            with self.assertRaisesRegex(AssertionError,'LOCAL-CLEANUP.json'):m.seal_artifacts(work,result)
            cleanup.write_bytes(original);m.seal_artifacts(work,result)

    def optimistic_fixture(self,presence='present',readback='0'):
        calls=[]
        def net(argv):
            calls.append(argv)
            if argv[:2]==[m.sys.executable,'-c']:
                return m.json.dumps({path:presence for path in argv[3:]})
            if argv[:2]==['sysctl','-qw']:return ''
            if argv[:2]==['sysctl','-n']:return readback+'\n'
            raise AssertionError('unexpected optimistic DAD fixture command: '+repr(argv))
        return net,calls

    def test_optimistic_dad_present_disables_and_reads_all_and_tap(self):
        net,calls=self.optimistic_fixture()
        with patch.object(m,'bounded',side_effect=AssertionError('config must not be needed')):
            values,policy,raw=m.configure_optimistic_dad(net,'dad-tap0')
        expected={'net.ipv6.conf.all.optimistic_dad':'0','net.ipv6.conf.dad-tap0.optimistic_dad':'0'}
        self.assertEqual(values,expected);self.assertIsNone(raw)
        self.assertEqual([a for a in calls if a[:2]==['sysctl','-qw']],
                         [['sysctl','-qw',key+'=0'] for key in expected])
        self.assertEqual([a for a in calls if a[:2]==['sysctl','-n']],
                         [['sysctl','-n',key] for key in expected])
        self.assertEqual(policy['mechanism'],'all-and-interface-sysctls')
        self.assertIsNone(policy['kernel_configuration']);self.assertTrue(policy['effective_disabled'])

    def test_optimistic_dad_compiled_out_requires_exact_config_and_absence(self):
        net,calls=self.optimistic_fixture('absent')
        raw=b'CONFIG_IPV6=y\n# CONFIG_IPV6_OPTIMISTIC_DAD is not set\n'
        with patch.object(m.os,'uname',return_value=m.argparse.Namespace(release='6.8.0-fixture')), \
             patch.object(m,'bounded',return_value=raw) as read:
            values,policy,retained=m.configure_optimistic_dad(net,'dad-tap0')
        read.assert_called_once_with(Path('/boot/config-6.8.0-fixture'),1024*1024)
        self.assertEqual(values,{});self.assertEqual(retained,raw)
        self.assertEqual(policy['kernel_configuration']['input'],m.identity('/boot/config-6.8.0-fixture',raw))
        self.assertEqual(policy['mechanism'],'compiled-out-with-namespace-absence')
        self.assertTrue(policy['effective_disabled'])
        self.assertEqual(len(calls),2)
        self.assertTrue(all(value=='absent' for value in policy['namespace_presence_after'].values()))

    def test_optimistic_dad_missing_duplicate_or_contradictory_config_refuses(self):
        configs=[b'CONFIG_IPV6=y\n',b'CONFIG_IPV6=y\nCONFIG_IPV6_OPTIMISTIC_DAD=y\n',
                 b'CONFIG_IPV6=y\nCONFIG_IPV6_OPTIMISTIC_DAD=m\n',
                 b'CONFIG_IPV6=y\n# CONFIG_IPV6_OPTIMISTIC_DAD is not set\nCONFIG_IPV6_OPTIMISTIC_DAD=y\n',
                 b'CONFIG_IPV6=y\n'+b'# CONFIG_IPV6_OPTIMISTIC_DAD is not set\n'*2,
                 b'CONFIG_IPV6=n\n# CONFIG_IPV6_OPTIMISTIC_DAD is not set\n',
                 b'CONFIG_IPV6=y\nCONFIG_IPV6=n\n# CONFIG_IPV6_OPTIMISTIC_DAD is not set\n']
        for raw in configs:
            net,_=self.optimistic_fixture('absent')
            with self.subTest(raw=raw),patch.object(m,'bounded',return_value=raw),self.assertRaises(AssertionError):
                m.configure_optimistic_dad(net,'dad-tap0')

    def test_optimistic_dad_mixed_unknown_or_changed_presence_refuses(self):
        for variant in ('mixed','unknown','changed','missing-key'):
            calls=[0]
            def net(argv):
                if argv[:2]==[m.sys.executable,'-c']:
                    calls[0]+=1;values={path:'present' for path in argv[3:]}
                    if variant=='mixed':values[argv[3]]='absent'
                    if variant=='unknown':values[argv[3]]='unknown'
                    if variant=='changed' and calls[0]>1:values[argv[3]]='absent'
                    if variant=='missing-key':del values[argv[3]]
                    return m.json.dumps(values)
                return '0\n'
            with self.subTest(variant=variant),self.assertRaises(AssertionError):
                m.configure_optimistic_dad(net,'dad-tap0')

    def test_optimistic_dad_unavailable_config_or_control_refuses(self):
        for error in (FileNotFoundError('config'),PermissionError('config'),AssertionError('config size')):
            net,_=self.optimistic_fixture('absent')
            with self.subTest(error=error),patch.object(m,'bounded',side_effect=error),self.assertRaises(type(error)):
                m.configure_optimistic_dad(net,'dad-tap0')
        for failed in ('probe','write','read'):
            ordinary,_=self.optimistic_fixture()
            def net(argv):
                if (failed=='probe' and argv[0]==m.sys.executable or
                    failed=='write' and argv[:2]==['sysctl','-qw'] or
                    failed=='read' and argv[:2]==['sysctl','-n']):raise PermissionError(failed)
                return ordinary(argv)
            with self.subTest(failed=failed),self.assertRaises(PermissionError):
                m.configure_optimistic_dad(net,'dad-tap0')

    def test_optimistic_dad_nonzero_or_malformed_value_refuses(self):
        for value in ('1','','0\n1','unknown'):
            net,_=self.optimistic_fixture(readback=value)
            with self.subTest(value=value),self.assertRaises(AssertionError):
                m.configure_optimistic_dad(net,'dad-tap0')

    def test_actual_separate_address_and_link_shapes_validate(self):
        addresses,links=interface_fixture()
        self.assertNotIn('address',addresses[0]);self.assertIn('address',links[0])
        m.validate_interface(addresses,links,'dad-tap0')

    def test_setup_wrong_mac_or_mtu_refuses(self):
        for field,value in [('address','52:55:00:00:02:03'),('mtu',1499)]:
            addresses,links=interface_fixture();links[0][field]=value
            with self.subTest(field=field),self.assertRaises(AssertionError):
                m.validate_interface(addresses,links,'dad-tap0')

    def test_setup_wrong_or_ambiguous_interface_refuses(self):
        for target,field,value in [(0,'ifname','another-tap'),(1,'ifname','another-tap'),
                                   (0,'ifindex',8),(1,'ifindex',8),(0,'ifindex',False)]:
            addresses,links=interface_fixture();(addresses,links)[target][0][field]=value
            with self.subTest(target=target,field=field),self.assertRaises(AssertionError):
                m.validate_interface(addresses,links,'dad-tap0')
        for target in (0,1):
            addresses,links=interface_fixture();(addresses,links)[target].append(copy.deepcopy((addresses,links)[target][0]))
            with self.subTest(extra_row=target),self.assertRaises(AssertionError):
                m.validate_interface(addresses,links,'dad-tap0')


if __name__=='__main__':unittest.main()
