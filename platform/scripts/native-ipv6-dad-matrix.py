#!/usr/bin/env python3
"""One bounded DAD case against an owned Linux namespace and prebuilt ABSD ELFs.

ND is produced by the Linux kernel. DNS answers are the unchanged application
fixture. This runner builds an ISO only; no compiler, key or provider action.
"""
import argparse
from collections import Counter
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from served_ram import served_qemu

if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
    raise SystemExit('native-ipv6-dad-matrix: optimized Python refused')
ROOT = Path(__file__).resolve().parent.parent
PRODUCT = '150270fe3cefff7f83eefd3290813608eab6eaee'
PRODUCT_TREE = 'eb3f47a528845023f7f32265c06a0151466dc85d'
PRODUCT_ARCHIVE = '775d457a4bd6e3913f4f615490b6a70fba3de56cfc321cafc616f6d28242a0f2'
KERNEL = 'ed6a15ea7c7c999422e1e294e139b6119619b06c'
KERNEL_TREE = '5c3834dcdb8cf393c86bc0e436ae62c7cda67af5'
KERNEL_ARCHIVE = '568ac7c029d9d8e6e101519b1341c2e860300cb7dded1e65ea526efaa731212e'
HELPERS = {'native-ipv6-accounting.py':'22d5f091c23c0d436be538d3695b43b3ed52b48ec5b4b30668be215a08001ad3',
           'native-ipv6-reason-accounting.py':'8155af1e25c73b1eb67636955a8e350c881cdd869c6cc73e70038bca06e0a827',
           'native-ipv6-peer.py':'c72d3146d9eb26850208ce5cd85744209ee41af140fa878b523da73b4d90da37'}
CASES = ('unused','duplicate','simultaneous','active-defense')
GUEST_IP, HOST_IP = 'fd00:ab5d::15', 'fd00:ab5d::2'
GUEST, HOST = (ipaddress.IPv6Address(x).packed for x in (GUEST_IP,HOST_IP))
GUEST_MAC, HOST_MAC = bytes.fromhex('525400ab5d15'), bytes.fromhex('525500000202')
ALL = ipaddress.IPv6Address('ff02::1').packed
SOL = ipaddress.IPv6Address('ff02::1:ff00:15').packed
MAX_ELF, MAX_LOG, MAX_CAPTURE = 64*1024*1024, 8*1024*1024, 2*1024*1024
UNRUN = ['native malformed/unknown/reserved options, rate/total/frame/call exhaustion',
         'native uncertain I/O, partial pipes, interruption, clock/health/missed-counter faults',
         'MLD-snooping links, enhanced DAD, extension/fragment ND, routed IPv6 and uniqueness/authentication',
         'independent internal boot-domain phase timestamps, physical clock accuracy, hardware/live transfer']


def bounded(path, maximum):
    with Path(path).open('rb') as stream:
        data = stream.read(maximum+1)
    assert len(data)<=maximum, 'input/output byte bound: '+str(path)
    return data


def digest(data):
    return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}


def identity(path, data):
    return {'path':str(Path(path).resolve()),**digest(data)}


def write(path, value):
    data=(json.dumps(value,indent=2)+'\n').encode('utf-8')
    with Path(path).open('xb') as stream:
        stream.write(data)
    return data


def module(name, filename):
    path=ROOT/'scripts'/filename
    assert hashlib.sha256(bounded(path,MAX_LOG)).hexdigest()==HELPERS[filename], 'changed accepted helper: '+filename
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


for _file,_hash in HELPERS.items():
    assert hashlib.sha256(bounded(ROOT/'scripts'/_file,MAX_LOG)).hexdigest()==_hash, 'changed accepted helper: '+_file
reasons=module('dad_private_reasons','native-ipv6-reason-accounting.py')
original=reasons.original
assert hashlib.sha256(bounded(ROOT/'scripts/native-ipv6-accounting.py',MAX_LOG)).hexdigest()==HELPERS['native-ipv6-accounting.py']
peer_fixture=module('dad_linux_dns_fixture','native-ipv6-peer.py')
base_classify=original.classify
PROFILE=original.PROFILES['udp']


def classify(record, guest_mac, host_mac, profile):
    row=base_classify(record,guest_mac,host_mac,profile)
    if row['kind']!='unexplained' or profile!=PROFILE:
        return row
    f=record['frame']
    if (len(f)<78 or f[12:15]!=b'\x86\xdd\x60' or f[20:22]!=b'\x3a\xff'
            or len(f)!=54+int.from_bytes(f[18:20],'big') or f[54] not in (135,136)):
        return row
    outgoing=f[6:12]==guest_mac
    if not outgoing and f[6:12]!=host_mac:
        return row
    src,dst,payload=f[22:38],f[38:54],f[54:]
    row['protocol_peer']=payload[8:24]==GUEST
    if payload[1]!=0 or original.checksum(src+dst+struct.pack('!I3xB',len(payload),58)+payload)!=0:
        return row
    if (payload==b'\x87\0'+payload[2:4]+bytes(4)+GUEST and src==bytes(16)
            and dst==SOL and f[:6]==b'\x33\x33\xff\0\0\x15'):
        kind='guest-dad-ns' if outgoing else 'linux-dad-ns'
    elif (len(payload)==32 and payload[:2]==b'\x88\0' and payload[4:8]==b'\x20\0\0\0'
          and payload[8:24]==GUEST and src==GUEST and dst==ALL
          and f[:6]==b'\x33\x33\0\0\0\x01'
          and payload[24:]==b'\x02\x01'+f[6:12]):
        kind='guest-dad-na' if outgoing else 'linux-duplicate-na'
    else:
        return row
    row.update(kind=kind,source_ip=str(ipaddress.IPv6Address(src)),destination_ip=str(ipaddress.IPv6Address(dst)))
    return row


# Only this fresh private helper instance sees the explicit new ND forms.
# The accepted first-four evaluator, sidecar/R1 checks and policy stay intact.
original.classify=classify


def lease_left(lease):
    remaining=lease-time.time()
    assert remaining>0, 'original absolute resource lease expired'
    return remaining


def build_binding(receipt, buffers):
    assert receipt['schema']=='absd-native-ipv6-dad-build/1'
    for key,rev,tree,archive in [('platform',PRODUCT,PRODUCT_TREE,PRODUCT_ARCHIVE),('kernel',KERNEL,KERNEL_TREE,KERNEL_ARCHIVE)]:
        item=receipt[key]
        assert item['revision']==rev and item['tree']==tree and item['clean'] is True
        assert item['archive']['sha256']==archive and 0<item['archive']['bytes']<=MAX_ELF
    assert receipt['commands'] and all(isinstance(c,list) and c and all(isinstance(x,str) for x in c) for c in receipt['commands'])
    assert any(any(x.endswith('scripts/build-native-ipv6-dad.sh') for x in c) for c in receipt['commands'])
    assert any(any(x.startswith('EXTERNAL_USER_ELF=') for x in c) for c in receipt['commands'])
    assert 1<=len(receipt['logs'])<=8
    for item in [receipt['toolchain_receipt'],*receipt['logs']]:
        assert 0<item['bytes']<=MAX_LOG and re.fullmatch('[0-9a-f]{64}',item['sha256'])
    for key,data in buffers.items():
        assert data[:4]==b'\x7fELF' and receipt['outputs'][key]==digest(data), 'exact build output: '+key
    assert buffers['parent'].count(buffers['child'])==buffers['kernel'].count(buffers['parent'])==buffers['kernel'].count(buffers['child'])==1


def native_output(raw, exit_status, case):
    positive=case in ('unused','active-defense')
    assert exit_status==(3 if positive else 7), 'unexpected QEMU status'
    assert not any(x in raw for x in (b'PANIC',b'KERNEL FAULT',b'NIC DISABLED'))
    assert raw.count(b'NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n')==1
    chunks=list(re.finditer(rb'EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)\n',raw))
    assert len(chunks)==raw.count(b'EXTERNAL OUTPUT CHUNK')
    output=bytearray()
    for c in chunks:
        assert int(c[1],16)==len(output)
        output.extend(bytes.fromhex(c[2].decode()))
        assert len(output)<=16384
    text=output.decode('utf-8');assert text.endswith('\n')
    stats=re.findall(rb'(?m)^NIC STATS ([^\n]+)\n',raw)
    durable=re.findall(rb'(?m)^DURABLE status=(-?\d+) frames=0 processes=0 cells=0 pipes=0 ([^\n]+)\n',raw)
    assert len(stats)==len(durable)==1
    assert int(durable[0][0])==(0 if positive else 99)
    counters=dict(p.split('=',1) for p in stats[0].decode().split())
    assert int(counters['rx_frames'])>0 and int(counters['tx_frames'])>0
    assert int(counters['flags'])==1
    ticks=re.search(rb'(?:^| )ticks=(\d+)(?: |$)',durable[0][1]);assert ticks
    if positive:
        markers=['IPV6 DAD CLEAR local=fd00:ab5d::15 scope=1 auth=none uniqueness=unproven',
                 'IPV6 DAD SERVICE READY scope=1 udp=7002 peer-port=42010',
                 'IPV6 DAD CLIENT AUTHORITY PASS scope-and-peer-refused no-nic',
                 'IPV6 DAD DNS A PASS address=192.0.2.9',
                 'IPV6 DAD DNS AAAA PASS address=2001:db8::9']
        lines=text.splitlines();assert lines[:5]==markers and len(lines)==6
        terminal=re.fullmatch(r'IPV6 DAD SERVICE PASS child=exited sockets=0 probes=1 defenses=(\d+) received=(\d+) malformed=0',lines[5]);assert terminal
        assert int(terminal[1])==(1 if case=='active-defense' else 0)
        assert 1<=int(terminal[2])<=128
        assert b'\nDURABLE WORKLOAD OK\nABSD BOOT OK\n' in raw and b'init: FAILED' not in raw
        assert re.search(rb'(?m)^SPAWN OK pid=(\d+) parent=2 program=image\n',raw)
        assert b'USER EXIT pid=3 status=0\n' in raw and b'USER EXIT pid=2 status=0\n' in raw
        ends=re.findall(rb'(?m)^EXTERNAL OUTPUT END bytes=(\d+) digest=([0-9a-f]{8})\n',raw);assert len(ends)==1
        value=0x811c9dc5
        for byte in output:value=((value^byte)*0x01000193)&0xffffffff
        assert int(ends[0][0])==len(output) and int(ends[0][1],16)==value
    else:
        assert text=='IPV6 DAD SERVICE ERROR DAD acquisition refused Conflict\n'
        assert b'USER EXIT pid=2 status=1\n' in raw
        assert b'DURABLE WORKER OUTCOME generation=1 pid=2 status=1\n' in raw
        assert b'init: FAILED at durable worker outcome\n' in raw
        assert b'DURABLE WORKLOAD FAILED\n' in raw and b'ABSD BOOT OK' not in raw
        assert b'EXTERNAL OUTPUT END' not in raw
        assert not re.search(rb'(?m)^SPAWN OK pid=\d+ parent=2 program=',raw), 'child created on acquisition refusal'
    return {'output':text,'positive':positive,'NIC_counters':counters,'terminal_ticks':int(ticks[1]),
            'phase_time_limit':'Internal DAD/start/activation instants are not exported. Bounds follow exact source guards; capture and host action time are not boot time.'}


def flag(info, name):
    return info.get(name) is True or name in info.get('flags',[])


def candidate(rows):
    found=[a for row in rows for a in row.get('addr_info',[]) if a.get('local')==GUEST_IP]
    assert len(found)<=1
    return found[0] if found else None


def inspect(capture, observation, peer, action, case):
    records,_=original.capture_records(capture)
    census=[classify(r,GUEST_MAC,HOST_MAC,PROFILE) for r in records]
    allowed={'linux-mldv2','peer-nd','peer-udp-dns','guest-dad-ns','linux-dad-ns','guest-dad-na','linux-duplicate-na'}
    assert all(r['kind'] in allowed for r in census), 'unexplained whole capture frame'
    bykind={k:[r['index'] for r in census if r['kind']==k] for k in allowed}
    assert len(bykind['guest-dad-ns'])==1, 'one actual candidate probe required'
    assert not peer['errors'] and peer['normal_exit'] and peer['transport']=='Linux AF_INET6 SOCK_DGRAM'
    candidate_nd=[r['index'] for r in census if r['kind']=='peer-nd' and r['direction']=='outgoing' and r['source_ip']==GUEST_IP]
    if case in ('duplicate','simultaneous'):
        assert not candidate_nd, 'candidate-source ordinary ND on refused acquisition'
    else:
        assert all(bykind['guest-dad-ns'][0]<index for index in candidate_nd), 'ordinary candidate ND preceded tentative probe'
    if case=='duplicate':
        assert len(bykind['linux-duplicate-na'])==1 and not bykind['linux-dad-ns'] and not bykind['guest-dad-na']
        assert bykind['guest-dad-ns'][0]<bykind['linux-duplicate-na'][0]
        assigned=candidate(action['assigned_before_launch']);assert assigned and not flag(assigned,'tentative') and not flag(assigned,'dadfailed')
    elif case=='simultaneous':
        assert len(bykind['linux-dad-ns'])==1 and not bykind['linux-duplicate-na'] and not bykind['guest-dad-na']
        assert bykind['guest-dad-ns'][0]<bykind['linux-dad-ns'][0]
        assert action['trigger']=='captured guest tentative NS' and action['add_result']==0
        prefix=action['capture_prefix'];assert digest(capture[:prefix['bytes']])==prefix
        prefix_records,_=original.capture_records(capture[:prefix['bytes']],partial=True)
        assert action['complete_records']==len(prefix_records)>=bykind['guest-dad-ns'][0]
        assert action['complete_records']<bykind['linux-dad-ns'][0]
    elif case=='active-defense':
        assert peer['action']==action, 'peer action differs from separately evaluated active DAD evidence'
        assert len(bykind['linux-dad-ns'])==len(bykind['guest-dad-na'])==1 and not bykind['linux-duplicate-na']
        assert action['trigger']=='Linux socket received first A query' and action['add_result']==0
        assert any(flag(candidate(s) or {},'dadfailed') for s in action['dad_snapshots']), 'actual Linux dadfailed required'
        assert candidate(action['after_delete']) is None and action['delete_result']==0
    else:
        assert not any(bykind[k] for k in ('linux-dad-ns','guest-dad-na','linux-duplicate-na'))
    queries=[];responses=[];response_counts=Counter();af_records=peer['records']
    for record,row in zip(records,census):
        if row['kind']!='peer-udp-dns':continue
        body=record['frame'][62:]
        if row['direction']=='outgoing':
            name,typ=peer_fixture.question(body)
            queries.append({'index':record['index'],'name':name,'type':typ,'query_hex':body.hex()})
        else:
            prior=[q for q in queries if peer_fixture.answer(bytes.fromhex(q['query_hex']))==body]
            assert prior, 'DNS response without exact earlier query'
            key=prior[0]['query_hex'];response_counts[key]+=1
            assert response_counts[key]<=len(prior), 'more answers than prior copies of exact query'
            responses.append({'index':record['index'],'answer_hex':body.hex(),'compatible_query_indices':[q['index'] for q in prior]})
    if observation['positive']:
        assert {q['name'] for q in queries}=={'a.example','aaaa.example'}
        for name in ('a.example','aaaa.example'):
            group=[q for q in queries if q['name']==name]
            assert 1<=len(group)<=4 and len({q['query_hex'] for q in group})==1
        assert queries[0]['name']=='a.example' and any(r['answer_hex']==peer_fixture.answer(bytes.fromhex(q['query_hex'])).hex() for q in queries for r in responses if q['name']=='aaaa.example')
        assert bykind['guest-dad-ns'][0]<queries[0]['index']
        nd=[(r['index'],r['direction'],records[r['index']-1]['frame'][54]) for r in census if r['kind']=='peer-nd']
        assert any(a[1:] == ('outgoing',135) and any(b[1:] == ('incoming',136) and a[0]<b[0]<queries[0]['index'] for b in nd) for a in nd), 'ordinary guest NS/Linux NA before DNS required'
        assert Counter(q['query_hex'] for q in queries)==Counter(r['query_hex'] for r in af_records), 'wire queries differ from actual Linux socket receives'
        assert Counter(r['answer_hex'] for r in responses)==Counter(r['answer_hex'] for r in af_records), 'wire answers differ from actual Linux socket sends'
        assert all(r['source'][0]==GUEST_IP and r['source'][1]==7002 and r['destination_port']==42010
                   and r['answer_hex']==peer_fixture.answer(bytes.fromhex(r['query_hex'])).hex() for r in af_records)
        if case=='active-defense':
            assert action['query_hex']==queries[0]['query_hex']
            assert af_records[0]['received_monotonic_ns']<=action['add_start_monotonic_ns']<=action['dadfailed_observed_monotonic_ns']<=action['delete_complete_monotonic_ns']<=af_records[0]['sent_monotonic_ns']
            first_a=min(r['index'] for r in responses if bytes.fromhex(r['answer_hex'])[2:4]==b'\x81\x80')
            assert queries[0]['index']<bykind['linux-dad-ns'][0]<bykind['guest-dad-na'][0]<first_a
    else:
        assert not queries and not responses and not af_records, 'application traffic on refused candidate'
    return {'capture':digest(capture),'census':census,'by_kind':bykind,'queries':queries,'responses':responses,
            'scope_limit':'Full captured packet order only. Source-bound phase output distinguishes acquisition refusal from activation; no synchronized wire/boot clock, uniqueness or authenticated ND claim.'}


def command(argv, timeout=5):
    result=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
    assert len(result.stdout)+len(result.stderr)<=65536, 'control output bound'
    assert result.returncode==0, 'control failed: '+repr((argv,result.returncode,result.stderr))
    return result.stdout


def dad_sysctls(tap):
    return {f'net.ipv6.conf.{tap}.accept_dad':'1',f'net.ipv6.conf.{tap}.dad_transmits':'1',
            f'net.ipv6.conf.{tap}.router_solicitation_delay':'0',f'net.ipv6.conf.{tap}.enhanced_dad':'0',
            'net.ipv6.conf.all.enhanced_dad':'0',
            f'net.ipv6.neigh.{tap}.retrans_time_ms':'100'}


def configure_optimistic_dad(net,tap):
    # Probe inside the owned namespace. Only ENOENT at an accessible existing
    # conf directory means absent; permission/control/parse errors propagate.
    keys=['net.ipv6.conf.'+name+'.optimistic_dad' for name in ('all',tap)]
    paths=['/proc/sys/'+key.replace('.','/') for key in keys]
    probe=('import json,os,stat,sys\nresult={}\n'
           'for path in sys.argv[1:]:\n'
           ' if not stat.S_ISDIR(os.stat(os.path.dirname(path)).st_mode): raise RuntimeError("conf directory")\n'
           ' try:\n'
           '  entry=os.stat(path)\n'
           '  if not stat.S_ISREG(entry.st_mode): raise RuntimeError("sysctl file type")\n'
           '  result[path]="present"\n'
           ' except FileNotFoundError: result[path]="absent"\n'
           'print(json.dumps(result,sort_keys=True))\n')
    def presence():
        value=json.loads(net([sys.executable,'-c',probe,*paths]))
        assert set(value)==set(paths) and all(v in ('present','absent') for v in value.values()), 'unknown optimistic DAD presence'
        return value
    before=presence();observed={};configuration=None;config_bytes=None
    release=os.uname().release
    assert re.fullmatch('[A-Za-z0-9_.+-]{1,128}',release), 'running kernel release'
    if all(value=='present' for value in before.values()):
        for key in keys:net(['sysctl','-qw',key+'=0'])
        for key in keys:
            observed[key]=net(['sysctl','-n',key]).strip()
            assert observed[key]=='0', 'optimistic DAD not disabled: '+key
        mechanism='all-and-interface-sysctls'
    else:
        assert all(value=='absent' for value in before.values()), 'mixed optimistic DAD presence'
        path=Path('/boot')/('config-'+release)
        config_bytes=bounded(path,1024*1024)
        lines=config_bytes.decode('ascii').splitlines()
        ipv6=[line for line in lines if re.match(r'(?:# )?CONFIG_IPV6(?:=|\s|$)',line)]
        optimistic=[line for line in lines if 'CONFIG_IPV6_OPTIMISTIC_DAD' in line]
        assert ipv6==['CONFIG_IPV6=y'], 'unknown/contradictory IPv6 configuration'
        assert optimistic==['# CONFIG_IPV6_OPTIMISTIC_DAD is not set'], 'optimistic DAD not proven compiled out'
        configuration={'input':identity(path,config_bytes),'relevant_lines':ipv6+optimistic}
        mechanism='compiled-out-with-namespace-absence'
    after=presence()
    assert after==before, 'optimistic DAD presence changed during setup'
    return observed,{'kernel_release':release,'mechanism':mechanism,'effective_disabled':True,
                     'namespace_presence_before':before,'namespace_presence_after':after,
                     'kernel_configuration':configuration},config_bytes


def validate_interface(addresses,links,tap):
    assert isinstance(addresses,list) and len(addresses)==1, 'one IPv6 interface row required'
    assert isinstance(links,list) and len(links)==1, 'one link interface row required'
    address,link=addresses[0],links[0]
    assert address['ifname']==link['ifname']==tap, 'setup interface name mismatch'
    assert type(address['ifindex']) is int and address['ifindex']>0, 'setup address ifindex'
    assert type(link['ifindex']) is int and link['ifindex']==address['ifindex'], 'setup ifindex mismatch'
    assert link['mtu']==1500 and address['mtu']==link['mtu'], 'setup MTU mismatch'
    assert link['address']==HOST_MAC.hex(':'), 'setup MAC mismatch'
    assert [a['local'] for a in address['addr_info']]==[HOST_IP]


def perform_dad(tap, lease, trigger, query_hex=None):
    action={'trigger':trigger,'query_hex':query_hex,'add_start_monotonic_ns':time.monotonic_ns(),
            'add_start_realtime_ns':time.time_ns(),'dad_snapshots':[]}
    lease_left(lease)
    command(['ip','-6','addr','add',GUEST_IP+'/64','dev',tap])
    action['add_result']=0
    until=time.monotonic()+2
    while time.monotonic()<until:
        lease_left(lease)
        rows=json.loads(command(['ip','-j','-6','address','show','dev',tap],timeout=1))
        action['dad_snapshots'].append(rows)
        assert len(action['dad_snapshots'])<=128
        info=candidate(rows)
        if info and flag(info,'dadfailed'):
            action['dadfailed_observed_monotonic_ns']=time.monotonic_ns()
            break
        assert info is None or flag(info,'tentative'), 'Linux candidate became usable instead of dadfailed'
        time.sleep(0.01)
    else:
        raise AssertionError('NOT_ESTABLISHED: Linux dadfailed not observed within2s')
    command(['ip','-6','addr','del',GUEST_IP+'/64','dev',tap])
    action['delete_result']=0
    action['after_delete']=json.loads(command(['ip','-j','-6','address','show','dev',tap]))
    assert candidate(action['after_delete']) is None
    action['delete_complete_monotonic_ns']=time.monotonic_ns()
    return action


def peer_worker(args):
    work=args.work
    deadline=min(time.monotonic()+args.timeout,time.monotonic()+lease_left(args.lease))
    sockets=[];records=[];errors=[];action={};normal=False
    try:
        for port in (42010,42011):
            sock=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            sock.bind((HOST_IP,port));sockets.append(sock)
        assert not (work/'PEER-READY.json').exists()
        peer_fixture.write_json(work/'PEER-READY.json',{'pid':os.getpid(),'namespace_inode':os.stat('/proc/self/ns/net').st_ino,
                                                     'kernel':list(os.uname()),'ports':[42010,42011]})
        while True:
            assert time.monotonic()<deadline and lease_left(args.lease)>0, 'peer absolute bound'
            ready,_,_=select.select(sockets,[],[],0.01)
            if not ready and (work/'PEER-STOP').exists():break
            for sock in ready:
                query,_,flags,source=sock.recvmsg(1233)
                received=time.monotonic_ns()
                assert len(records)<8 and sock is sockets[0] and not flags&socket.MSG_TRUNC
                assert source[0]==GUEST_IP and source[1]==7002 and len(query)<=1232
                name,kind=peer_fixture.question(query)
                if args.case=='active-defense' and not records:
                    assert name=='a.example'
                    action=perform_dad(args.tap,args.lease,'Linux socket received first A query',query.hex())
                    write(work/'ACTIVE-DAD.json',action)
                answer=peer_fixture.answer(query)
                assert sock.sendto(answer,source)==len(answer)
                records.append({'source':list(source),'destination_port':42010,'query_hex':query.hex(),
                                'answer_hex':answer.hex(),'name':name,'kind':kind,'received_monotonic_ns':received,'sent_monotonic_ns':time.monotonic_ns()})
        normal=True
    except BaseException as error:
        errors.append(repr(error))
    finally:
        for sock in sockets:sock.close()
        write(work/'PEER-RESULT.json',{'transport':'Linux AF_INET6 SOCK_DGRAM','records':records,'errors':errors,
                                     'normal_exit':normal,'action':action})
    return 0 if normal else 1


def group_live(process):
    try:os.killpg(process.pid,0);return True
    except ProcessLookupError:return False


def stop_owned(process):
    if process is None:return {'status':None,'group_absent':True,'forced':False}
    forced=False
    if group_live(process):
        try:os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        end=time.monotonic()+3
        while (process.poll() is None or group_live(process)) and time.monotonic()<end:time.sleep(0.02)
        if process.poll() is None or group_live(process):
            forced=True
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            end=time.monotonic()+3
            while (process.poll() is None or group_live(process)) and time.monotonic()<end:time.sleep(0.02)
    return {'status':process.poll(),'group_absent':not group_live(process),'forced':forced}


def run(args):
    assert os.geteuid()==0, 'owned disposable VM root required'
    assert args.timeout+45<lease_left(args.lease)<=4*3600, 'finite original lease margin'
    work=args.work;deadline=time.monotonic()+args.timeout
    namespace='absdv6dad-'+uuid.uuid4().hex;tap='dad-tap0'
    processes={};logs=[];bounds={};attempted=False;created=False;cleanup_errors=[];action={}
    evaluated={};simultaneous_bytes=None
    def fact(name,value):
        data=write(work/name,value)
        assert json.loads(data)==value, 'canonical fact differs from evaluated object: '+name
        evaluated[name]=identity(work/name,data)
        return data
    env={k:v for k,v in os.environ.items() if k not in ('LISTEN_PID','LISTEN_FDS','LISTEN_FDNAMES','NOTIFY_SOCKET')}
    def left(maximum):
        for p,b in bounds.items():assert not p.exists() or p.stat().st_size<=b, 'output bound: '+p.name
        remaining=min(deadline-time.monotonic(),lease_left(args.lease)-45)
        assert remaining>0, 'absolute case/lease bound'
        return min(maximum,remaining)
    def checked(argv):return command(argv,left(5))
    def net(argv):return checked(['ip','netns','exec',namespace,*argv])
    def start(name,argv,process_env=None):
        log=(work/(name+'.log')).open('xb');logs.append(log);bounds[work/(name+'.log')]=MAX_LOG
        processes[name]=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=env if process_env is None else process_env)
        return processes[name]
    try:
        buffers={name:bounded(path,MAX_ELF) for name,path in [('child',args.client_elf),('parent',args.elf),('kernel',args.kernel_elf)]}
        receipt_bytes=bounded(args.build_receipt,MAX_LOG);receipt=json.loads(receipt_bytes);build_binding(receipt,buffers)
        retained={}
        for name,data in buffers.items():
            path=work/(name+'.elf');path.write_bytes(data);retained[path.name]=identity(path,data)
        for name,item in [('platform-source.tar',receipt['platform']['archive']),('kernel-source.tar',receipt['kernel']['archive']),
                          ('build-input-0.log',receipt['toolchain_receipt']),*[(f'build-input-{i+1}.log',v) for i,v in enumerate(receipt['logs'])]]:
            data=bounded(item['path'],MAX_ELF if name.endswith('.tar') else MAX_LOG)
            assert digest(data)=={k:item[k] for k in ('bytes','sha256')}
            path=work/name;path.write_bytes(data);retained[name]=identity(path,data)
        (work/'BUILD-RECEIPT.json').write_bytes(receipt_bytes);retained['BUILD-RECEIPT.json']=identity(work/'BUILD-RECEIPT.json',receipt_bytes)
        tree=work/'iso-tree/boot/grub';tree.mkdir(parents=True)
        (tree.parent/'absd-kernel').write_bytes(buffers['kernel'])
        boot=b'insmod all_video\nset timeout=0\nmenuentry "ABSD IPv6 DAD" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n'
        (tree/'grub.cfg').write_bytes(boot)
        iso=work/'native-ipv6-dad.iso';disk=work/'native-ipv6-dad.img';bounds[iso]=128*1024*1024;bounds[disk]=2*1024*1024
        temporary=work/'iso-tmp';temporary.mkdir()
        builder=start('iso-build',['grub-mkrescue','-o',str(iso),str(tree.parent.parent)],dict(env,TMPDIR=str(temporary)))
        build_until=time.monotonic()+left(60)
        while builder.poll() is None:
            left(60);assert time.monotonic()<build_until, 'ISO construction bound';time.sleep(0.02)
        assert builder.returncode==0
        iso_bytes=bounded(iso,bounds[iso]);assert iso_bytes.count(buffers['kernel'])==1
        with disk.open('xb') as stream:stream.truncate(2*1024*1024)
        assert namespace not in [line.split()[0] for line in checked(['ip','netns','list']).splitlines()]
        attempted=True;checked(['ip','netns','add',namespace]);created=True
        for setting in ['all.disable_ipv6=0','default.disable_ipv6=0','all.accept_ra=0','default.accept_ra=0',
                        'default.autoconf=0','default.dad_transmits=0','all.enhanced_dad=0','default.enhanced_dad=0']:
            net(['sysctl','-qw','net.ipv6.conf.'+setting])
        for argv in [['link','set','lo','up'],['tuntap','add','dev',tap,'mode','tap'],['link','set',tap,'address',HOST_MAC.hex(':')],
                     ['link','set',tap,'mtu','1500'],['link','set',tap,'addrgenmode','none'],['link','set',tap,'up'],
                     ['-6','addr','add',HOST_IP+'/64','dev',tap,'nodad']]:
            checked(['ip','-n',namespace,*argv])
        settings=dad_sysctls(tap);observed={}
        for key,value in settings.items():net(['sysctl','-qw',key+'='+value])
        for key,value in settings.items():
            observed[key]=net(['sysctl','-n',key]).strip();assert observed[key]==value
        optimistic_values,optimistic_policy,config_bytes=configure_optimistic_dad(net,tap)
        observed.update(optimistic_values)
        if config_bytes is not None:
            path=work/'linux-kernel.config';path.write_bytes(config_bytes)
            evaluated[path.name]=identity(path,config_bytes)
        address_json=net(['ip','-j','-6','address','show','dev',tap]);link_json=net(['ip','-j','link','show','dev',tap])
        addresses=json.loads(address_json);links=json.loads(link_json);validate_interface(addresses,links,tap)
        routes=json.loads(net(['ip','-j','-6','route','show']))
        assert any(r['dst']=='fd00:ab5d::/64' for r in routes) and all(r['dst']=='fd00:ab5d::/64' and 'gateway' not in r and r['dev']==tap for r in routes)
        if args.case=='duplicate':
            net(['ip','-6','addr','add',GUEST_IP+'/64','dev',tap,'nodad'])
            action={'assigned_before_launch':json.loads(net(['ip','-j','-6','address','show','dev',tap]))}
        setup_bytes=fact('LINUX-SETUP.json',{'kernel':list(os.uname()),'namespace':namespace,'namespace_inode':os.stat('/run/netns/'+namespace).st_ino,
                                     'tap':tap,'sysctls':observed,'optimistic_dad':optimistic_policy,
                                     'address_json':address_json,'link_json':link_json,
                                     'addresses':addresses,'links':links,'routes':routes,'action':action})
        serial=work/'native-ipv6-dad.serial.log';capture=work/'native-ipv6-dad.pcap';bounds[serial]=MAX_LOG;bounds[capture]=MAX_CAPTURE
        marker=original.ReadyMarker(serial,capture);marker.poll(running=False)
        peer=start('peer',['ip','netns','exec',namespace,sys.executable,str(Path(__file__).resolve()),str(work),'--peer-worker',
                           '--case',args.case,'--tap',tap,'--lease-end',args.lease_end,'--timeout',str(args.timeout)])
        ready_until=time.monotonic()+left(5)
        while not (work/'PEER-READY.json').exists():
            assert time.monotonic()<ready_until, 'peer readiness bound'
            assert peer.poll() is None, 'peer setup failed'
            left(5);time.sleep(0.01)
        peer_ready_bytes=bounded(work/'PEER-READY.json',65536)
        peer_ready=json.loads(peer_ready_bytes)
        evaluated['PEER-READY.json']=identity(work/'PEER-READY.json',peer_ready_bytes)
        assert peer_ready['pid']==peer.pid and peer_ready['namespace_inode']==os.stat('/run/netns/'+namespace).st_ino
        listeners=net(['ss','-H','-6','-u','-l','-n'])
        local=[]
        for line in listeners.splitlines():
            fields=line.split();assert len(fields)==5
            address,port=fields[3].rsplit(':',1)
            assert ipaddress.IPv6Address(address.strip('[]'))==ipaddress.IPv6Address(HOST_IP)
            local.append(int(port))
        assert sorted(local)==[42010,42011]
        fact('LINUX-LISTENERS.json',{'before_guest':listeners,'ports':local})
        qemu=shutil.which(os.environ.get('ABSD_QEMU','qemu-system-x86_64'));assert qemu
        argv=served_qemu(['ip','netns','exec',namespace,str(Path(qemu).resolve()),'-accel','tcg,thread=single','-cpu','max,vendor=GenuineIntel,+rdrand',
              '-smp','1','-m','256M','-cdrom',str(iso),'-drive',f'file={disk},format=raw,if=ide,index=0','-display','none',
              '-serial',f'file:{serial}','-no-reboot','-no-shutdown','-device','isa-debug-exit,iobase=0xf4,iosize=0x04',
              '-device',f'e1000,netdev=n0,mac={GUEST_MAC.hex(":")}','-netdev',f'tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off',
              '-object',f'filter-dump,id=cap0,netdev=n0,file={capture}'])
        q=start('qemu',argv)
        fact('LAUNCH.json',{'case':args.case,'argv':argv,'qemu_pid_pgid':q.pid,'peer_pid_pgid':peer.pid,'builder_pid_pgid':builder.pid,
                                  'lease_end':args.lease_end,'timeout':args.timeout,'ISO':identity(iso,iso_bytes),'inputs':{n:digest(d) for n,d in buffers.items()},
                                  'runner':identity(__file__,bounded(__file__,MAX_LOG)),'helpers':HELPERS,'sysctls':observed,'peer_ready':peer_ready})
        while q.poll() is None:
            marker.poll(running=q.poll() is None);left(args.timeout)
            assert peer.poll() is None, 'peer ended before guest'
            if args.case=='simultaneous' and not action:
                raw=original.bounded(capture,MAX_CAPTURE);records,complete=original.capture_records(raw,partial=True)
                if any(classify(r,GUEST_MAC,HOST_MAC,PROFILE)['kind']=='guest-dad-ns' for r in records):
                    action={'trigger':'captured guest tentative NS','capture_prefix':digest(raw),'complete_records':len(records),
                            'trigger_monotonic_ns':time.monotonic_ns(),'trigger_realtime_ns':time.time_ns()}
                    net(['ip','-6','addr','add',GUEST_IP+'/64','dev',tap]);action['add_result']=0
                    action['after_add']=json.loads(net(['ip','-j','-6','address','show','dev',tap]))
                    simultaneous_bytes=fact('SIMULTANEOUS-DAD.json',action)
            time.sleep(0.005)
        marker.poll(running=False);marker.seal(work)
        (work/'PEER-STOP').touch(exist_ok=False)
        stop_until=time.monotonic()+left(3)
        while peer.poll() is None:
            left(3);assert time.monotonic()<stop_until, 'peer stop bound';time.sleep(0.01)
        assert peer.returncode==0
        assert not net(['ss','-H','-6','-u','-l','-n']).strip(), 'owned UDP sockets did not retire'
        peer_result_bytes=bounded(work/'PEER-RESULT.json',MAX_LOG)
        peer_result=json.loads(peer_result_bytes)
        evaluated['PEER-RESULT.json']=identity(work/'PEER-RESULT.json',peer_result_bytes)
        if args.case=='active-defense':
            active_bytes=bounded(work/'ACTIVE-DAD.json',MAX_LOG)
            action=json.loads(active_bytes)
            evaluated['ACTIVE-DAD.json']=identity(work/'ACTIVE-DAD.json',active_bytes)
        elif args.case=='simultaneous':
            assert simultaneous_bytes is not None, 'NOT_ESTABLISHED: no captured-probe action'
            assert json.loads(simultaneous_bytes)==action, 'simultaneous action copy differs'
        elif args.case=='duplicate':
            assert json.loads(setup_bytes)['action']==action, 'preassigned action copy differs'

        fact('CASE-ACTION.json',action)
        raw_serial=bounded(serial,MAX_LOG);observation=native_output(raw_serial,q.returncode,args.case)
        raw_capture=bounded(capture,MAX_CAPTURE)
        captured=inspect(raw_capture,observation,peer_result,action,args.case)
        reason=reasons.evaluate(work,marker,observation['NIC_counters'],GUEST_MAC.hex(':'),HOST_MAC.hex(':'),'udp')
        assert reason['capture_sha256']==captured['capture']['sha256'] and reason['serial_sha256']==digest(raw_serial)['sha256']
        reason_bytes=bounded(work/'NIC-REASON-ACCOUNTING.json',MAX_LOG);sidecar=bounded(work/'NIC-READY-CAPTURE.json',65536)
        assert json.loads(reason_bytes)==reason and digest(sidecar)['sha256']==reason['annotation_sha256']
        left(1)
        evaluated.update({
                    'iso-tree/boot/absd-kernel':identity(tree.parent/'absd-kernel',buffers['kernel']),
                    'iso-tree/boot/grub/grub.cfg':identity(tree/'grub.cfg',boot),
                    'native-ipv6-dad.iso':identity(iso,iso_bytes),'native-ipv6-dad.serial.log':identity(serial,raw_serial),
                    'native-ipv6-dad.pcap':identity(capture,raw_capture),
                    'NIC-READY-CAPTURE.json':identity(work/'NIC-READY-CAPTURE.json',sidecar),
                    'NIC-REASON-ACCOUNTING.json':identity(work/'NIC-REASON-ACCOUNTING.json',reason_bytes)})
        return {'disposition':'PASS','case':args.case,'observation':observation,'capture_result':captured,'peer':peer_result,'action':action,
                'reason_accounting':reason,'evaluated_build_inputs':retained,'evaluated_artifacts':evaluated,
                'unrun':UNRUN,'limits':'One exact source-bound Linux packet/state case. Original strict post-ready counter case is not requalified. Internal boot-phase timing, uniqueness, authentication and post-effect recall remain unproved.'}
    finally:
        terminals={}
        for name in ('qemu','peer','iso-build'):
            try:
                row=stop_owned(processes.get(name));terminals[name]=row
                if row['forced'] or not row['group_absent'] or (processes.get(name) is not None and row['status'] is None):cleanup_errors.append(name+' not terminal/clean')
            except BaseException as error:
                terminals[name]={'unknown':repr(error)};cleanup_errors.append(name+' '+repr(error))
        for log in logs:log.close()
        absent=False
        if attempted:
            try:
                listing=command(['ip','netns','list'])
                if namespace in [line.split()[0] for line in listing.splitlines()]:
                    assert not command(['ip','netns','pids',namespace]).strip(), 'owned namespace retains processes'
                    command(['ip','netns','del',namespace])
                absent=namespace not in [line.split()[0] for line in command(['ip','netns','list']).splitlines()]
                assert absent
            except BaseException as error:cleanup_errors.append('namespace '+repr(error))
        for path,bound in bounds.items():
            if path.exists() and path.stat().st_size>bound:cleanup_errors.append('output bound '+path.name)
        fact('LOCAL-CLEANUP.json',{'creation_attempted':attempted,'created':created,'namespace':namespace,'namespace_absent':absent,
                                        'processes':terminals,'errors':cleanup_errors,'disposition':'FAIL' if cleanup_errors else 'PASS'})
        if cleanup_errors:raise RuntimeError(cleanup_errors)


def seal_artifacts(work, result):
    artifacts={}
    for path in work.rglob('*'):
        if path.is_file():
            limit=128*1024*1024 if path.suffix=='.iso' else MAX_ELF
            artifacts[str(path.relative_to(work))]=identity(path,bounded(path,limit))
    for collection in ('evaluated_build_inputs','evaluated_artifacts'):
        for name,expected in result[collection].items():
            assert all(artifacts[name][k]==expected[k] for k in ('bytes','sha256')), 'evaluated buffer changed before final seal: '+name
    return artifacts


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('work',type=Path);p.add_argument('--case',choices=CASES,required=True)
    p.add_argument('--kernel-elf',type=Path);p.add_argument('--elf',type=Path);p.add_argument('--client-elf',type=Path);p.add_argument('--build-receipt',type=Path)
    p.add_argument('--lease-end',required=True,help='existing absolute UTC lease, ISO8601 with timezone')
    p.add_argument('--timeout',type=int,default=120);p.add_argument('--peer-worker',action='store_true',help=argparse.SUPPRESS);p.add_argument('--tap',default='dad-tap0',help=argparse.SUPPRESS)
    args=p.parse_args();stamp=datetime.datetime.fromisoformat(args.lease_end.replace('Z','+00:00'))
    if stamp.tzinfo is None or not 10<=args.timeout<=180:p.error('timezone and10..180s timeout required')
    args.lease=stamp.timestamp();args.work=args.work.resolve()
    if args.peer_worker:
        assert args.work.is_dir() and re.fullmatch('[A-Za-z0-9_.-]{1,15}',args.tap)
        return peer_worker(args)
    if any(getattr(args,k) is None for k in ('kernel_elf','elf','client_elf','build_receipt')):p.error('all prebuilt inputs required')
    args.work.mkdir(parents=True,mode=0o700,exist_ok=False)
    def stopped(_signum,_frame):raise KeyboardInterrupt('runner interrupted')
    signal.signal(signal.SIGTERM,stopped);signal.signal(signal.SIGINT,stopped)
    try:
        result=run(args)
        result['artifacts']=seal_artifacts(args.work,result)
    except BaseException as error:
        write(args.work/'RESULT.json',{'disposition':'FAIL','case':args.case,'error':repr(error),'unrun':UNRUN})
        raise
    write(args.work/'RESULT.json',result)
    print('NATIVE IPV6 DAD PROOF PASS case='+args.case)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
