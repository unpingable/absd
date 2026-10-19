#!/usr/bin/env python3
"""Independent Linux DNS fixtures, dig controls, and admitted native guest.
Uses the existing net-matrix boot/accounting helpers without altering them.
Guest invocation requires an exact steward slot. --linux needs no guest.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import threading
import time

spec = importlib.util.spec_from_file_location('net_matrix', Path(__file__).with_name('net-matrix.py'))
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)


def wire(name):
    return b''.join(bytes([len(label)])+label.encode('ascii') for label in name.split('.'))+b'\0'


def question(packet):
    # Fixture accepts only this client's ordinary uncompressed IN A query.
    if len(packet)<17 or packet[2:12]!=b'\x01\x00\x00\x01'+b'\0'*6:
        raise ValueError('unexpected query header')
    at=12;labels=[]
    while True:
        size=packet[at];at+=1
        if size==0:break
        if size>63 or at+size>len(packet):raise ValueError('query label')
        labels.append(packet[at:at+size].decode('ascii'));at+=size
    if packet[at:]!=b'\0\x01\0\x01':raise ValueError('query suffix')
    return '.'.join(labels),at+4


def rr(owner,kind,data):
    return owner+struct.pack('!HHIH',kind,1,60,len(data))+data


def response(query,records=(),rcode=0,tc=False):
    _,end=question(query)
    return query[:2]+struct.pack('!HHHHH',0x8180|rcode|(0x200 if tc else 0),1,len(records),0,0)+query[12:end]+b''.join(records)


def answers(query):
    owner=b'\xc0\x0c'
    return response(query,[rr(owner,1,bytes([192,0,2,9]))])


class Fixture:
    def __init__(self,ports=(42010,42011,42013)):
        self.udp=[];self.tcp=[];self.records=[];self.errors=[];self.counts={};self.saved={};self.tcp_accepts=0
        self.stop=threading.Event()
        try:
            for port in ports:
                udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',port));self.udp.append(udp)
                tcp=socket.socket();tcp.bind(('127.0.0.1',udp.getsockname()[1]));tcp.listen(4);self.tcp.append(tcp)
            self.thread=threading.Thread(target=self.serve);self.thread.start()
        except BaseException:
            for sock in self.udp+self.tcp:sock.close()
            raise
    def serve(self):
        while not self.stop.is_set():
            readable,_,_=select.select(self.udp+self.tcp,[],[],0.05)
            for sock in readable:
                try:
                    if sock in self.tcp:
                        stream,source=sock.accept();self.tcp_accepts+=1
                        with stream:
                            stream.settimeout(1)
                            prefix=receive_exact(stream,2);length=int.from_bytes(prefix,'big')
                            query=receive_exact(stream,length);data=answers(query)
                            stream.sendall(len(data).to_bytes(2,'big')+data)
                        continue
                    query,source=sock.recvfrom(65535)
                    name,_=question(query);port=sock.getsockname()[1]
                    key=(port,source,name);count=self.counts.get(key,0)+1;self.counts[key]=count
                    self.records.append({'port':port,'source':source,'name':name,'id':int.from_bytes(query[:2],'big'),'bytes':query.hex(),'ordinal':count})
                    owner=b'\xc0\x0c'
                    if name in ('absent.example','interrupt.example'):
                        self.saved[port]=answers(query);continue
                    if name=='retry.example' and count==1:continue
                    if name=='cname.example':data=response(query,[rr(owner,5,wire('target.example'))])
                    elif name=='order.example':data=response(query,[rr(wire('target.example'),1,bytes([192,0,2,9])),rr(wire('other.example'),1,b'\x09'*4),rr(owner,5,wire('target.example'))])
                    elif name=='loop.example':data=response(query,[rr(owner,5,wire('loop.example'))])
                    elif name in ('nx.example','fail.example','refused.example','empty.example'):
                        data=response(query,rcode={'nx.example':3,'fail.example':2,'refused.example':5,'empty.example':0}[name])
                    elif name=='tc.example':data=response(query,tc=True)
                    elif name=='bad.example':data=response(query,[rr(owner,5,b'\xff\xff')])
                    else:data=answers(query)
                    if name=='match.example':
                        wrong=bytes([query[0]^1])+data[1:];sock.sendto(wrong,source)
                        altered=bytearray(data);altered[13]^=1;sock.sendto(altered,source)
                    if name=='after.example' and port in self.saved:sock.sendto(self.saved[port],source)
                    sock.sendto(data,source)
                except BaseException as error:self.errors.append(repr(error))
    def close(self):
        self.stop.set();self.thread.join(timeout=3)
        if self.thread.is_alive():raise AssertionError('fixture did not stop')
        for sock in self.udp+self.tcp:sock.close()
        if self.errors:raise AssertionError(self.errors)


def receive_exact(stream,size):
    end=time.monotonic()+2;data=b''
    while len(data)<size:
        remaining=end-time.monotonic()
        if remaining<=0:raise TimeoutError('fixture stream deadline')
        stream.settimeout(remaining);chunk=stream.recv(size-len(data))
        if not chunk:raise EOFError('fixture short TCP frame')
        data+=chunk
    return data


def linux_control():
    fixture=Fixture((0,));port=fixture.udp[0].getsockname()[1];results=[]
    try:
        for name,expected,options in [('a.example','192.0.2.9',[]),('order.example','192.0.2.9',[]),('nx.example','NXDOMAIN',[]),('empty.example','NOERROR',[]),('refused.example','REFUSED',[]),('tc.example','Truncated',['+ignore']),('tc.example','192.0.2.9',['+tcp'])]:
            command=['dig','@127.0.0.1','-p',str(port),name,'A','+noedns','+noadflag','+time=1','+tries=1']+options
            completed=subprocess.run(command,capture_output=True,text=True,timeout=4)
            text=completed.stdout
            if expected=='Truncated':assert 'flags: qr tc rd ra' in text,text
            else:assert expected in text,text
            assert completed.returncode==0,(completed.returncode,text,completed.stderr)
            results.append({'name':name,'options':options,'stdout':text,'returncode':completed.returncode})
        assert fixture.tcp_accepts==1
    finally:fixture.close()
    return {'case':'independent-linux-dig','results':results,'tcp_positive_control':True}


def guest(kernel,elf,work):
    fixture=Fixture();qemu=None
    try:
        iso,image=n.build_iso(kernel,elf,str(work),1)
        port=n.free_ports(1)[0];log=str(work/'dns.serial.log')
        qemu=n.start_qemu(iso,image,log,['-netdev',f'user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:7000'])
        n.wait_output(log,rb'DNS SERVICE READY',qemu,timeout=90)
        with socket.create_connection(('127.0.0.1',port),timeout=5) as tcp:
            data=b'independent Linux TCP alongside native DNS\n';tcp.sendall(data)
            assert receive_exact(tcp,len(data))==data
        done,counters=n.finish_boot(qemu,log,rb'DNS SERVICE DONE native=3 partial=1 interrupted=1 fresh=1 tcp_bytes=\d+ sockets=0')
        output=n.stdout_of(log).decode('utf-8')
        assert output.count('DNS LOOKUP name=')==29,output
        assert output.count('name=tc.example result=Err(Truncated)')==2
        assert fixture.tcp_accepts==0,'native client unexpectedly used TCP DNS'
        assert output.count('DNS TIMEOUT FENCED fresh-channel-required')==2
        assert 'DNS FRESH GRANT AFTER TIMEOUT local=7006' in output
        assert 'DNS CLIENT DONE mode=3 kind=3 status=0' in output
        assert 'DNS CLIENT DONE mode=4 kind=1 status=0' in output
        expected={'a.example','cname.example','target.example','order.example','nx.example','empty.example','fail.example','refused.example','tc.example','bad.example','loop.example','match.example','after.example','retry.example','absent.example'}
        for p in (42010,42011):
            records=[r for r in fixture.records if r['port']==p]
            sources={tuple(r['source']) for r in records}
            assert len(sources)==(2 if p==42010 else 1),(p,sources)
            for source in sources:
                own=[r for r in records if tuple(r['source'])==source]
                names={r['name'] for r in own}
                suite='a.example' in names
                assert names==(expected if suite else {'after.example'}),(p,source,names)
                for name in names:
                    copies=[r for r in own if r['name']==name]
                    # The product contract permits at most two identical sends
                    # per queried name; ARP/startup delay can use that retry.
                    assert 1<=len(copies)<=2,(p,source,name,copies)
                    assert len({r['bytes'] for r in copies})==1,(p,source,name,copies)
                    if name in ('retry.example','absent.example'):assert len(copies)==2
                ids={name:next(r['id'] for r in own if r['name']==name) for name in names}
                assert len(set(ids.values()))==len(ids),(p,source,ids)
        return {'case':'native-linux-peer','queries':fixture.records,'dns_tcp_accepts':fixture.tcp_accepts,'tcp_echo':True,'counters':counters,'output':output}
    finally:
        try:fixture.close()
        finally:
            (work/'FIXTURE.json').write_text(json.dumps({'queries':fixture.records,'errors':fixture.errors,'tcp_accepts':fixture.tcp_accepts},indent=2)+'\n')
            if qemu is not None and qemu.poll() is None:qemu.terminate();qemu.wait(timeout=10)


def main():
    def terminate(signum,frame):raise KeyboardInterrupt('driver terminated')
    signal.signal(signal.SIGTERM,terminate)
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('work',type=Path);p.add_argument('--linux',action='store_true');p.add_argument('--kernel');p.add_argument('--elf')
    a=p.parse_args();a.work.mkdir(parents=True,exist_ok=True);results=[]
    try:
        results.append(linux_control())
        if not a.linux:
            if not a.kernel or not a.elf:p.error('guest needs --kernel and --elf')
            results.append(guest(a.kernel,a.elf,a.work))
    except BaseException as error:
        (a.work/'RESULT.json').write_text(json.dumps({'disposition':'FAIL','results':results,'error':repr(error)},indent=2)+'\n');raise
    (a.work/'RESULT.json').write_text(json.dumps({'disposition':'PASS','results':results},indent=2)+'\n')
    print('NATIVE DNS MATRIX OK cases='+str(len(results)))

if __name__=='__main__':main()
