#!/usr/bin/env python3
"""Independent Linux UDP peers and bounded native guest lifecycle cases.

Uses the existing net-matrix boot/accounting helpers without changing its
qualification contract. Requires an isolated disposable kernel checkout.
No acceptance/U1 resource is acquired by this program: obtain steward slot
admission before invoking guest cases. Logs and receipts survive failures.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import signal
import threading
import time

spec=importlib.util.spec_from_file_location('net_matrix',Path(__file__).with_name('net-matrix.py'))
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)


def pattern(size):
    return bytes(((i*131)^(i>>7))&255 for i in range(size))


def receive_exact(stream, length, timeout_s=5, clock=time.monotonic):
    end=clock()+timeout_s
    reply=bytearray()
    while len(reply)<length:
        remaining=end-clock()
        if remaining<=0:raise TimeoutError('TCP exchange deadline')
        stream.settimeout(remaining)
        chunk=stream.recv(length-len(reply))
        if not chunk:raise EOFError('TCP peer closed before complete reply')
        reply.extend(chunk)
    return bytes(reply)


def driver_controls():
    class Stream:
        def __init__(self,chunks):self.chunks=iter(chunks);self.reads=0
        def settimeout(self,value):assert value>0
        def recv(self,length):self.reads+=1;return next(self.chunks)
    for chunks in [[b''],[b'partial',b'']]:
        try:receive_exact(Stream(chunks),20)
        except EOFError:pass
        else:raise AssertionError('EOF control accepted')
    ticks=iter([0,0.4,0.8,1.2]);stream=Stream([b'x']*3)
    try:receive_exact(stream,20,timeout_s=1,clock=lambda:next(ticks))
    except TimeoutError:assert stream.reads==2
    else:raise AssertionError('partial progress renewed deadline')
    assert receive_exact(Stream([b'a',b'bc']),3)==b'abc'
    with tempfile.TemporaryDirectory(prefix='absd-udp-',dir='/tmp') as short:
        assert len(os.fsencode(os.path.join(short,'qmp.sock')))<100
    return {'case':'driver-bounds','early_eof':True,'trickle_deadline':True,'short_qmp_path':True}


def run_linux_control():
    """Conventional Linux semantics, independently of the ABSD engine."""
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver:
        sender.bind(('127.0.0.1',0));receiver.bind(('127.0.0.1',0))
        sender.settimeout(1);receiver.settimeout(0.05)
        lengths=[0,1,512,1472]
        for size in lengths:
            sender.sendto(pattern(size),receiver.getsockname())
        observed=[]
        for size in lengths:
            data,source=receiver.recvfrom(65535)
            assert data==pattern(size) and source==sender.getsockname()
            observed.append(len(data))
        sender.sendto(pattern(1472),receiver.getsockname())
        needed,ancillary,flags,source=receiver.recvmsg_into([bytearray(1)],0,socket.MSG_PEEK|socket.MSG_TRUNC)
        assert needed==1472 and flags&socket.MSG_TRUNC
        assert receiver.recvfrom(65535)[0]==pattern(1472)
        try:
            receiver.recvfrom(65535)
            raise AssertionError('empty Linux queue did not time out')
        except socket.timeout:pass
    return {'case':'linux-semantic-control','lengths':observed,'source_match':True,'short_peek_preserved':True,'timeout':True}


def run_peer(kernel,elf,work):
    # Conventional Linux UDP peer; no ABSD codec or smoltcp used here.
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1',42000));udp.settimeout(0.1)
    second=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    second.bind(('127.0.0.1',42001));second.settimeout(0.1)
    stop=threading.Event();seen=[];errors=[]
    def echo(peer):
        while not stop.is_set():
            try:data,source=peer.recvfrom(65535)
            except socket.timeout:continue
            if data!=pattern(len(data)) or len(data) not in [0,1,512,1472]:
                errors.append('unexpected UDP bytes')
            seen.append({'peer_port':peer.getsockname()[1],'source':source,'length':len(data),'sha256':hashlib.sha256(data).hexdigest()})
            peer.sendto(data,source)
    threads=[threading.Thread(target=echo,args=(peer,)) for peer in [udp,second]]
    for thread in threads:thread.start()
    qemu=None
    try:
        iso,image=n.build_iso(kernel,elf,work,1)
        port=n.free_ports(1)[0]
        log=os.path.join(work,'peer.serial.log')
        qemu=n.start_qemu(iso,image,log,['-netdev',f'user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:7000'])
        n.wait_output(log,rb'UDP SERVICE READY',qemu,timeout=90)
        # TCP and UDP share the actual stack, proving protocol coexistence.
        with socket.create_connection(('127.0.0.1',port),timeout=5) as tcp:
            data=b'independent Linux TCP alongside native UDP\n';tcp.sendall(data)
            reply=receive_exact(tcp,len(data))
            if reply!=data:raise AssertionError('TCP mismatch')
        n.wait_output(log,rb'UDP SERVICE DONE',qemu,timeout=45)
        done,counters=n.finish_boot(qemu,log,rb'UDP SERVICE DONE native=2 partial=1 interrupted=1 tcp_bytes=\d+ sockets=0')
        sizes=sorted(x['length'] for x in seen)
        if sizes!=sorted([0,1,512,1472]*2):raise AssertionError(f'Linux datagram boundaries/count {sizes}')
        for port in [42000,42001]:
            assert sorted(x['length'] for x in seen if x['peer_port']==port)==[0,1,512,1472]
        assert len({tuple(x['source']) for x in seen})==2
        if errors:raise AssertionError(errors)
        return {'case':'linux-peer','datagrams':seen,'tcp':True,'ungranted_destination':'silent','counters':counters}
    finally:
        stop.set()
        for thread in threads:thread.join(timeout=2)
        udp.close();second.close()
        if qemu is not None and qemu.poll() is None:qemu.terminate();qemu.wait(timeout=10)


def run_link(kernel,elf,work,step):
    options='net' if step==2 else 'net nic-ring-fault'
    iso,image=n.build_iso(kernel,elf,work,step,options=options)
    log=os.path.join(work,f'link-{step}.serial.log')
    # AF_UNIX socket names must be short even when evidence paths are long.
    with tempfile.TemporaryDirectory(prefix='absd-udp-',dir='/tmp') as short:
        qmp=os.path.join(short,'qmp.sock') if step==2 else None
        qemu=None
        try:
            qemu=n.start_qemu(iso,image,log,['-netdev','user,id=n0'],stopped_with_qmp=qmp)
            if qmp:
                monitor=n.Qmp(qmp,qemu)
                try:
                    monitor.set_link(False);monitor.execute('cont')
                    n.wait_output(log,rb'UDP LINK DOWN FENCED',qemu,timeout=90)
                    monitor.set_link(True)
                finally:
                    monitor.lines.close();monitor.close()
                result,counters=n.finish_boot(qemu,log,rb'UDP LINK UP FRESH GRANT ONLY sockets=0',link_line=rb'NIC LINK DOWN AT PROBE')
            else:
                result,counters=n.finish_boot(qemu,log,rb'UDP DEVICE FAILED FENCED passes=\d+ sockets=0',disabled_line=rb'NIC DISABLED reason=rx-head-outside-ring')
            return {'case':'carrier-regrant' if step==2 else 'device-failure','counters':counters}
        finally:
            if qemu is not None and qemu.poll() is None:qemu.terminate();qemu.wait(timeout=10)


def main():
    def terminate(signum,frame):raise KeyboardInterrupt("driver terminated")
    signal.signal(signal.SIGTERM,terminate)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('kernel',nargs='?');p.add_argument('elf',nargs='?');p.add_argument('work')
    p.add_argument('--only',choices=['linux','peer','link','dead','all'],default='all')
    a=p.parse_args();Path(a.work).mkdir(parents=True,exist_ok=True)
    results=[driver_controls()]
    if a.only!='linux' and (not a.kernel or not a.elf):p.error('guest cases need kernel and ELF')
    try:
        if a.only in ['all','linux']:results.append(run_linux_control())
        if a.only in ['all','peer']:results.append(run_peer(a.kernel,a.elf,a.work))
        if a.only in ['all','link']:results.append(run_link(a.kernel,a.elf,a.work,2))
        if a.only in ['all','dead']:results.append(run_link(a.kernel,a.elf,a.work,3))
    except BaseException as error:
        Path(a.work,'RESULT.json').write_text(json.dumps({'disposition':'FAIL','results':results,'error':str(error)},indent=2)+'\n')
        raise
    Path(a.work,'RESULT.json').write_text(json.dumps({'disposition':'PASS','results':results},indent=2)+'\n')
    print('NATIVE UDP MATRIX OK cases='+str(len(results)))

if __name__=='__main__':main()
