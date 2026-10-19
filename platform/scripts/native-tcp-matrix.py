#!/usr/bin/env python3
"""Independent Linux stream/DNS fixtures and admitted native capability guest.
--linux needs no compiler or guest. Guest mode requires an exact steward go.
--tap uses an existing isolated TAP with host 10.0.2.2/24; Linux's kernel is
then the TCP wire peer. Default QEMU user networking proxies TCP via libslirp.
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

if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
    raise SystemExit('native-tcp-matrix: optimized Python is refused; oracle assertions are required')

spec=importlib.util.spec_from_file_location('dns_fixture',Path(__file__).with_name('native-dns-matrix.py'))
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d);n=d.n


def exact(stream,size,deadline):
    data=bytearray()
    while len(data)<size:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('absolute stream deadline')
        stream.settimeout(remaining);part=stream.recv(size-len(data))
        if not part:raise EOFError('short stream')
        data.extend(part)
    return bytes(data)


def echo_pattern():
    return bytes((((i+round*997)*131)^(i>>7))&255 for round in range(32) for i in range(997))


class Fixture:
    def __init__(self,fixed=False,bind='127.0.0.1'):
        self.stop=threading.Event();self.listeners={};self.udp={};self.records=[];self.errors=[];self.threads=[];self.streams=[]
        self.ports={};self.lock=threading.Lock()
        try:
            for mode in [0,1,2,4,5,6,7,8,9,11]:
                listener=socket.socket();listener.bind((bind,42100+mode if fixed else 0));listener.listen(4)
                self.listeners[listener]=mode;port=listener.getsockname()[1];self.ports[mode]=port
                if 4<=mode<=9:
                    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind((bind,port));self.udp[udp]=mode
            self.thread=threading.Thread(target=self.serve);self.thread.start()
        except BaseException:
            for sock in list(self.listeners)+list(self.udp):sock.close()
            raise
    def record(self,value):
        with self.lock:self.records.append(value)
    def serve(self):
        while not self.stop.is_set():
            ready,_,_=select.select(list(self.listeners)+list(self.udp),[],[],0.05)
            for sock in ready:
                try:
                    if sock in self.udp:
                        query,source=sock.recvfrom(65535);name,_=d.question(query);mode=self.udp[sock]
                        self.record({'transport':'udp','mode':mode,'source':source,'name':name,'bytes':query.hex()})
                        sock.sendto(d.answers(query) if name=='a.example' else d.response(query,tc=True),source)
                    else:
                        stream,source=sock.accept();mode=self.listeners[sock];self.streams.append(stream)
                        self.record({'transport':'accept','mode':mode,'source':source})
                        thread=threading.Thread(target=self.tcp,args=(stream,mode,source));self.threads.append(thread);thread.start()
                except BaseException as error:self.errors.append(repr(error))
    def tcp(self,stream,mode,source):
        try:
            with stream:
                stream.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);deadline=time.monotonic()+15
                if mode==2:
                    stream.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));return
                if mode==0:
                    received=bytearray()
                    while True:
                        stream.settimeout(max(0.01,deadline-time.monotonic()));part=stream.recv(137)
                        if not part:break
                        received.extend(part);stream.sendall(part[:1]);stream.sendall(part[1:])
                        if len(received)>len(echo_pattern()):raise AssertionError('echo bytes exceed bound')
                    assert bytes(received)==echo_pattern(),'independent echo bytes'
                    self.record({'transport':'echo','mode':mode,'bytes':len(received),'sha256':hashlib.sha256(received).hexdigest()});return
                if mode==1:
                    received=bytearray()
                    while True:
                        stream.settimeout(max(0.01,deadline-time.monotonic()));part=stream.recv(100)
                        if not part:break
                        received.extend(part)
                        assert len(received)<=7
                    assert received==b'request';stream.sendall(b'after-fin');self.record({'transport':'half-close','mode':mode,'reply_after_fin':True});return
                if mode==11:
                    stream.settimeout(3)
                    try:received=stream.recv(100)
                    except (ConnectionResetError,socket.timeout):received=b''
                    self.record({'transport':'interrupted','mode':mode,'bytes':received.hex()});return
                while not self.stop.is_set():
                    try:prefix=exact(stream,2,deadline)
                    except EOFError:return
                    query=exact(stream,int.from_bytes(prefix,'big'),deadline);name,_=d.question(query)
                    self.record({'transport':'tcp-dns','mode':mode,'source':source,'name':name,'bytes':query.hex()})
                    if mode==5:stream.sendall(b'\0\1\0');return
                    if mode==6:stream.sendall((4097).to_bytes(2,'big'));return
                    if mode==7:stream.sendall(b'\0\x64short');return
                    if mode==9:
                        while not self.stop.is_set() and time.monotonic()<deadline:
                            stream.settimeout(0.1)
                            try:
                                if not stream.recv(1):break
                            except socket.timeout:continue
                        return
                    answer=d.answers(query)
                    if name=='tcpbig.example':
                        txt=b''.join(bytes([200])+b'x'*200 for _ in range(3))
                        answer=d.response(query,[d.rr(b'\xc0\x0c',1,bytes([192,0,2,9])),d.rr(b'\xc0\x0c',16,txt)])
                        assert len(answer)>512
                    if mode==8:
                        wrong=bytes([answer[0]^1])+answer[1:]
                        other=bytearray(answer);other[13]^=1
                        for frame in [wrong,bytes(other)]:stream.sendall(len(frame).to_bytes(2,'big')+frame)
                    # Deliberate short writes; the native reader must join them.
                    frame=len(answer).to_bytes(2,'big')+answer
                    for at in range(0,len(frame),17):stream.sendall(frame[at:at+17])
        except (ConnectionResetError,BrokenPipeError):
            if mode not in [5,6,7,9,11]:self.errors.append('unexpected stream reset mode='+str(mode))
        except BaseException as error:
            if not self.stop.is_set():self.errors.append('mode='+str(mode)+' '+repr(error))
    def close(self):
        self.stop.set();self.thread.join(timeout=2)
        for stream in self.streams:
            try:stream.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        for thread in self.threads:thread.join(timeout=3)
        for sock in list(self.listeners)+list(self.udp):sock.close()
        if self.thread.is_alive() or any(t.is_alive() for t in self.threads):raise AssertionError('fixture thread did not stop')
        if self.errors:raise AssertionError(self.errors)


def linux_control():
    fixture=Fixture();results=[]
    try:
        with socket.create_connection(('127.0.0.1',fixture.ports[0]),timeout=2) as stream:
            data=echo_pattern();stream.sendall(data);stream.shutdown(socket.SHUT_WR)
            assert exact(stream,len(data),time.monotonic()+5)==data;assert stream.recv(1)==b''
            results.append({'case':'stream-short-io-echo','bytes':len(data)})
        with socket.create_connection(('127.0.0.1',fixture.ports[1]),timeout=2) as stream:
            stream.sendall(b'request');stream.shutdown(socket.SHUT_WR);assert exact(stream,9,time.monotonic()+2)==b'after-fin';assert stream.recv(1)==b''
            results.append({'case':'half-close','reply_after_fin':True})
        with socket.create_connection(('127.0.0.1',fixture.ports[2]),timeout=2) as stream:
            try:stream.recv(1)
            except ConnectionResetError:results.append({'case':'reset','observed':True})
            else:raise AssertionError('reset fixture returned orderly EOF')
        for name in ['tc.example','tcpbig.example']:
            command=['dig','@127.0.0.1','-p',str(fixture.ports[4]),name,'A','+tcp','+noedns','+noadflag','+time=2','+tries=1']
            result=subprocess.run(command,capture_output=True,text=True,timeout=5);assert result.returncode==0 and '192.0.2.9' in result.stdout,(result.stdout,result.stderr)
            results.append({'case':'dig-tcp','name':name,'stdout':result.stdout})
        query=b'\x23\x45\x01\x00\x00\x01'+b'\0'*6+d.wire('negative.example')+b'\0\x01\0\x01'
        for mode,expected in [(5,b'\0\1\0'),(6,(4097).to_bytes(2,'big')),(7,b'\0\x64short')]:
            with socket.create_connection(('127.0.0.1',fixture.ports[mode]),timeout=2) as stream:
                stream.sendall(len(query).to_bytes(2,'big')+query);assert exact(stream,len(expected),time.monotonic()+2)==expected;assert stream.recv(1)==b''
                results.append({'case':'negative-framing-control','mode':mode,'bytes':expected.hex()})
    finally:fixture.close()
    return {'case':'independent-linux','results':results}


def guest(kernel,elf,work,tap=None):
    fixture=Fixture(fixed=True,bind='10.0.2.2' if tap else '127.0.0.1');qemu=None
    try:
        iso,image=n.build_iso(kernel,elf,str(work),1);port=n.free_ports(1)[0];log=str(work/'tcp.serial.log')
        netdev=f'tap,id=n0,ifname={tap},script=no,downscript=no' if tap else f'user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:7000'
        qemu=n.start_qemu(iso,image,log,['-netdev',netdev])
        n.wait_output(log,rb'TCP SERVICE READY',qemu,timeout=90)
        with socket.create_connection(('10.0.2.15',7000) if tap else ('127.0.0.1',port),timeout=5) as stream:
            data=b'independent TCP alongside native stream capabilities\n';stream.sendall(data);assert exact(stream,len(data),time.monotonic()+5)==data
        _,counters=n.finish_boot(qemu,log,rb'TCP SERVICE DONE streams=4 dns=6 partial=1 interrupted=1 tcp_bytes=\d+ sockets=0')
        out=n.stdout_of(log).decode();assert out.count('TCP DNS LOOKUP')==8,out
        assert 'TCP CHILD DONE mode=12 kind=3 status=0' in out
        assert 'TCP CLIENT OK mode=0' in out and 'TCP CLIENT OK mode=1' in out
        assert 'TCP REFUSED result=Err(Closed)' in out and 'TCP RESET result=Err(Closed)' in out
        for mode in [0,1,2,4,5,6,7,8,9]:assert len([r for r in fixture.records if r['transport']=='accept' and r['mode']==mode])==1,(mode,fixture.records)
        # One TCP query per fallback, no fallback for a.example; UDP may
        # legitimately transmit twice with the same question under its bound.
        tcp_queries=[r for r in fixture.records if r['transport']=='tcp-dns'];assert len(tcp_queries)==7,tcp_queries
        assert not any(r['name']=='a.example' for r in tcp_queries)
        assert any(r['transport']=='echo' and r['bytes']==31904 for r in fixture.records)
        assert any(r['transport']=='half-close' for r in fixture.records)
        return {'case':'native-linux-peer','network':'linux-kernel-tap' if tap else 'qemu-user-libslirp','tap':tap,'counters':counters,'output':out,'fixture':fixture.records}
    finally:
        try:fixture.close()
        finally:
            (work/'FIXTURE.json').write_text(json.dumps({'records':fixture.records,'errors':fixture.errors},indent=2)+'\n')
            if qemu is not None and qemu.poll() is None:qemu.terminate();qemu.wait(timeout=10)


def main():
    def terminate(signum,frame):raise KeyboardInterrupt('driver terminated')
    signal.signal(signal.SIGTERM,terminate)
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('work',type=Path);p.add_argument('--linux',action='store_true');p.add_argument('--kernel');p.add_argument('--elf');p.add_argument('--tap',help='existing isolated TAP, host 10.0.2.2/24');a=p.parse_args();a.work.mkdir(parents=True,exist_ok=True);results=[]
    if a.tap and (a.linux or len(a.tap)>15 or not all(c.isascii() and (c.isalnum() or c in '_.-') for c in a.tap)):p.error('--tap needs guest mode and a Linux interface name of at most 15 characters')
    try:
        results.append(linux_control())
        if not a.linux:
            if not a.kernel or not a.elf:p.error('guest needs --kernel and --elf')
            results.append(guest(a.kernel,a.elf,a.work,a.tap))
    except BaseException as error:(a.work/'RESULT.json').write_text(json.dumps({'disposition':'FAIL','results':results,'error':repr(error)},indent=2)+'\n');raise
    (a.work/'RESULT.json').write_text(json.dumps({'disposition':'PASS','results':results},indent=2)+'\n');print('NATIVE TCP MATRIX OK cases='+str(len(results)))
if __name__=='__main__':main()
