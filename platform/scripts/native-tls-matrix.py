#!/usr/bin/env python3
"""Independent OpenSSL/Linux TLS fixture and explicit admitted native cases.

Source-only until exact --admission permits execution. Linux controls qualify
the peer, never ABSD. Private fixture material is not archived by this runner.
"""
from pathlib import Path
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from served_ram import served_qemu

if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
    raise SystemExit('native-tls-matrix: optimized Python is refused')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def seal(path, value):
    with Path(path).open('x') as out:
        json.dump(value, out, indent=2);out.write('\n');out.flush();os.fsync(out.fileno())


def body_bytes(length):
    return bytes(97 + (i % 26) for i in range(length))


def response(case):
    mode = case['peer_mode'];n = case.get('response_body_length', case['expected_body'])
    value = str(n)
    headers = [b'Content-Length: ' + value.encode()]
    status = b'HTTP/1.1 200 OK'
    if mode == 'length-duplicate':headers.append(headers[0])
    if mode == 'length-conflicting':headers.append(b'Content-Length: ' + str(n + 1).encode())
    if mode == 'length-nondecimal':headers = [b'Content-Length: +2048']
    if mode == 'length-overflow':headers = [b'Content-Length: ' + b'9' * 100]
    if mode == 'transfer-encoding':headers.append(b'Transfer-Encoding: chunked')
    if mode == 'content-encoding':headers.append(b'Content-Encoding: gzip')
    if mode == 'redirect':status = b'HTTP/1.1 302 Found';headers.append(b'Location: https://other.absd-fixture.test/')
    base = status + b'\r\n' + b'\r\n'.join(headers) + b'\r\n\r\n'
    if mode in ['header-max', 'header-over']:
        target = 4096 if mode == 'header-max' else 4097
        remaining = target - len(base);count = (remaining + 1023) // 1024
        require(count + len(headers) <= 32, 'fixture header-field bound')
        for left in range(count, 0, -1):
            width = min(1024, remaining - 9 * (left - 1))
            require(width >= 9, 'fixture header padding')
            headers.append(b'X-Pad: ' + b'x' * (width - 9));remaining -= width
        base = status + b'\r\n' + b'\r\n'.join(headers) + b'\r\n\r\n'
        require(len(base) == target and all(len(x) + 2 <= 1024 for x in headers), 'exact header-boundary fixture')
    data = body_bytes(n)
    if mode == 'short-http-body':data = data[:-1]
    if mode == 'interim':base = b'HTTP/1.1 100 Continue\r\n\r\n' + base
    return base + data


def record_frames(data):
    result = [];at = 0
    while at < len(data):
        require(len(data) - at >= 5, 'OpenSSL emitted partial record header')
        length = int.from_bytes(data[at + 3:at + 5], 'big')
        require(at + 5 + length <= len(data), 'OpenSSL emitted partial record body')
        result.append((at, bytes(data[at:at + 5 + length])));at += 5 + length
    return result


def http_profile(data, expected):
    """Independent finite HTTP profile oracle for Linux fixture controls."""
    end = data.find(b'\r\n\r\n')
    require(end >= 0 and end + 4 <= 4096, 'header bound or missing delimiter')
    lines = data[:end].split(b'\r\n')
    require(lines[0].startswith(b'HTTP/1.1 200 ') and len(lines[0]) + 2 <= 1024, 'status')
    require(len(lines) - 1 <= 32 and all(len(x) + 2 <= 1024 for x in lines), 'line/field bound')
    lengths = []
    for line in lines[1:]:
        name, separator, value = line.partition(b':')
        require(separator and name and name.strip() == name, 'field framing')
        key = name.lower();value = value.strip(b' \t')
        require(key != b'transfer-encoding', 'unsupported transfer encoding')
        require(key != b'content-encoding' or value.lower() == b'identity', 'unsupported content encoding')
        if key == b'content-length':lengths.append(value)
    require(len(lengths) == 1 and re.fullmatch(rb'0|[1-9][0-9]*', lengths[0]) is not None, 'canonical length')
    require(len(lengths[0]) <= 5, 'length overflow')
    length = int(lengths[0]);require(length <= 16384 and length == expected, 'body length profile')
    require(data[end + 4:] == body_bytes(length), 'body framing or byte pattern')
    return {'header_bytes': end + 4, 'body_bytes': length, 'body_sha256': hashlib.sha256(body_bytes(length)).hexdigest()}


class Peer:
    def __init__(self, case, pki, bind='10.0.2.2', port=4443, native=True, timeout=180):
        self.case=case;self.pki=pki;self.bind=bind;self.native=native;self.timeout=timeout
        self.events=[];self.errors=[];self.stop=threading.Event();self.sockets=[];self.threads=[]
        self.listeners=[];self.lock=threading.Lock();self.accepts=0;self.guard_accepts=0
        self.request=b'';self.client_close_notify=False;self.server_close_notify=False
        self.authenticated=False;self.mutated=False
        try:
            for role,number in [('tls',port),('guard',4444 if native else 0)]:
                listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                listener.bind((bind,number));listener.listen(4);self.listeners.append((listener,role))
            self.port=self.listeners[0][0].getsockname()[1]
            self.guard_port=self.listeners[1][0].getsockname()[1]
            self.thread=threading.Thread(target=self.serve,name='tls-peer-'+case['id']);self.thread.start()
        except BaseException:
            for listener,_ in self.listeners:listener.close()
            raise

    def event(self, kind, **values):
        with self.lock:self.events.append({'event':kind,'time':now(),'wall_time_ns':time.time_ns(),
                                          'monotonic_ns':time.monotonic_ns(),**values})

    def serve(self):
        while not self.stop.is_set():
            ready,_,_=select.select([x[0] for x in self.listeners],[],[],0.05)
            for listener in ready:
                conn,source=listener.accept();self.sockets.append(conn)
                role=next(role for sock,role in self.listeners if sock==listener)
                self.event('accept',role=role,source=list(source))
                if role=='guard':self.guard_accepts+=1;conn.close();continue
                self.accepts+=1
                if self.native and source!=('10.0.2.15',self.case['local_port']):
                    self.errors.append('unexpected native source');conn.close();continue
                if self.accepts>1:self.errors.append('unexpected extra connection');conn.close();continue
                worker=threading.Thread(target=self.connection,args=(conn,),name='tls-peer-connection')
                self.threads.append(worker);worker.start()

    def receive(self, conn, deadline):
        while not self.stop.is_set():
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('absolute peer deadline')
            conn.settimeout(min(remaining,0.2))
            try:
                data=conn.recv(4096)
                self.event('tcp-read',bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
                return data
            except socket.timeout:continue
        raise InterruptedError('fixture ended after producer reconciliation')

    def send(self, conn, data):
        lengths=[1,2,5,17,1024];at=0;index=0
        while at<len(data):
            if self.stop.is_set():raise InterruptedError('fixture stopped during send')
            part=data[at:at+lengths[index%len(lengths)]]
            conn.sendall(part);self.event('tcp-write',bytes=len(part),stream_offset=at)
            at+=len(part);index+=1

    def connection(self, conn):
        mode=self.case['peer_mode'];deadline=time.monotonic()+self.timeout
        try:
            with conn:
                conn.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                if mode in ['no-connect','guard','grant-exhaustion']:
                    raise RuntimeError('case made an unauthorized connection')
                if mode in ['silent-handshake','interrupt-handshake']:
                    while self.receive(conn,deadline):pass
                    self.event('peer-eof',phase='handshake');return
                if mode=='bad-record':
                    require(self.receive(conn,deadline),'ClientHello absent')
                    data=b'\xff\x03\x03\0\0';self.send(conn,data)
                    self.event('raw-record',bytes_hex=data.hex(),phase='handshake')
                    while self.receive(conn,deadline):pass
                    return
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version=context.maximum_version=(ssl.TLSVersion.TLSv1_2 if mode=='tls12-only' else ssl.TLSVersion.TLSv1_3)
                context.num_tickets=0
                context.set_alpn_protocols([] if mode=='no-alpn' else ['h2'] if mode=='h2-only' else ['http/1.1'])
                leaf=mode if mode in ['untrusted','signature-failure','wrong-name','expired','future'] else 'valid'
                context.load_cert_chain(self.pki['leaf_certificates'][leaf]['path'],self.pki['leaf_private_key_path'])
                incoming=ssl.MemoryBIO();outgoing=ssl.MemoryBIO();engine=context.wrap_bio(incoming,outgoing,server_side=True)
                def flush(phase):
                    data=outgoing.read()
                    if not data:return 0
                    for offset,record in record_frames(data):
                        if not self.mutated and record[0]==23 and (
                            (mode=='bad-handshake-tag' and phase=='handshake') or
                            (mode=='bad-response-tag' and phase=='response')):
                            changed=record[:-1]+bytes([record[-1]^1]);self.mutated=True
                            self.event('record-mutation',phase=phase,offset=offset+len(record)-1,
                                original_sha256=hashlib.sha256(record).hexdigest(),
                                changed_sha256=hashlib.sha256(changed).hexdigest(),changed_hex=changed.hex())
                            record=changed
                        self.send(conn,record)
                    return len(data)
                def feed():
                    data=self.receive(conn,deadline)
                    if data:incoming.write(data)
                    else:incoming.write_eof()
                    return data
                while True:
                    try:engine.do_handshake();flush('handshake');break
                    except ssl.SSLWantReadError:flush('handshake');feed()
                    except ssl.SSLWantWriteError:flush('handshake')
                    except ssl.SSLError:
                        flush('handshake')
                        self.event('handshake-failure-alert-drained')
                        raise
                self.authenticated=True
                self.event('tls-handshake-complete',version=engine.version(),cipher=engine.cipher(),
                           alpn=engine.selected_alpn_protocol(),session_reused=engine.session_reused)
                while b'\r\n\r\n' not in self.request:
                    try:
                        part=engine.read(1024)
                        if not part:
                            self.event('peer-tls-close-before-request')
                            require(self.case.get('expect_http') is False,'TLS EOF before complete request')
                            return
                        self.request+=part;require(len(self.request)<=256,'peer request bound')
                    except ssl.SSLWantReadError:flush('handshake');feed()
                self.event('http-request',bytes=len(self.request),sha256=hashlib.sha256(self.request).hexdigest(),
                           request_hex=self.request.hex())
                expected=b'GET /native-network HTTP/1.1\r\nHost: absd-fixture.test:4443\r\nConnection: close\r\n\r\n'
                require(self.request==expected,'independent request bytes differ')
                if mode in ['silent-response','interrupt-authenticated']:
                    while self.receive(conn,deadline):pass
                    self.event('peer-eof',phase='response');return
                if mode=='oversize-record':
                    data=b'\x17\x03\x03\x41\x01';self.send(conn,data)
                    self.event('raw-record',bytes_hex=data.hex(),phase='response')
                    while self.receive(conn,deadline):pass
                    return
                plain=response(self.case)
                self.event('http-response',bytes=len(plain),sha256=hashlib.sha256(plain).hexdigest())
                if mode in ['eof-header1','eof-header4','eof-body','reset-record']:
                    require(engine.write(plain[:1024])>0,'no response accepted by OpenSSL')
                    encrypted=outgoing.read();require(encrypted,'no response record')
                    size=1 if mode=='eof-header1' else 4 if mode=='eof-header4' else max(6,len(encrypted)//2)
                    self.send(conn,encrypted[:size]);self.event('record-truncation',mode=mode,
                        sent_bytes=size,original_bytes=len(encrypted),sent_hex=encrypted[:size].hex())
                    if mode=='reset-record':
                        conn.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
                        linger=struct.unpack('ii',conn.getsockopt(socket.SOL_SOCKET,socket.SO_LINGER,8))
                        require(linger==(1,0),'reset linger setting differs')
                        self.event('tcp-reset-configured',linger=list(linger),
                                   source=list(conn.getsockname()),destination=list(conn.getpeername()))
                        return
                    conn.shutdown(socket.SHUT_WR)
                    while self.receive(conn,deadline):pass
                    return
                for at in range(0,len(plain),1024):
                    accepted=engine.write(plain[at:at+1024]);require(accepted>0,'zero OpenSSL write')
                    require(accepted==len(plain[at:at+1024]),'fixture must explicitly handle short plaintext acceptance')
                    flush('response')
                if mode=='no-close-notify':
                    self.event('intentional-raw-fin',server_close_notify=False)
                    conn.shutdown(socket.SHUT_WR)
                    while self.receive(conn,deadline):pass
                    return
                # unwrap sends our close_notify and waits for the client's. FIN
                # must not precede the successful observation on positive cases.
                while True:
                    try:
                        engine.unwrap();sent=flush('closing');self.client_close_notify=True
                        self.server_close_notify=self.server_close_notify or sent>0
                        self.event('client-close-notify-received');break
                    except ssl.SSLWantReadError:
                        sent=flush('closing');self.server_close_notify=self.server_close_notify or sent>0
                        if sent:self.event('server-close-notify-drained',ciphertext_bytes=sent)
                        feed()
                    except ssl.SSLWantWriteError:flush('closing')
                conn.shutdown(socket.SHUT_WR);self.event('peer-fin-after-tls-close')
        except (ssl.SSLError,ConnectionError,TimeoutError,InterruptedError,OSError) as error:
            self.event('connection-ended',error_type=type(error).__name__,reason=str(error),
                       verify_code=getattr(error,'verify_code',None))
            if self.case['expected_class']=='Success' and not self.stop.is_set():self.errors.append(repr(error))
        except BaseException as error:
            self.errors.append(repr(error));self.event('fixture-error',error=repr(error))

    def close(self):
        self.stop.set()
        for conn in self.sockets:
            try:conn.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        self.thread.join(timeout=3)
        for worker in self.threads:worker.join(timeout=3)
        for listener,_ in self.listeners:listener.close()
        for conn in self.sockets:conn.close()
        require(not self.thread.is_alive() and not any(t.is_alive() for t in self.threads),'fixture thread remains live')

    def report(self):
        return {'case':self.case,'events':self.events,'errors':self.errors,'accepts':self.accepts,
            'guard_accepts':self.guard_accepts,'request_bytes':len(self.request),
            'request_sha256':hashlib.sha256(self.request).hexdigest(),
            'server_handshake_complete':self.authenticated,'client_close_notify_received':self.client_close_notify,
            'server_close_notify_drained':self.server_close_notify,'record_mutation_observed':self.mutated,
            'engine':'Python ssl / OpenSSL','python_openssl_version':ssl.OPENSSL_VERSION}


def pcap_windows(path, case):
    data=Path(path).read_bytes();require(len(data)>=24,'missing PCAP header')
    shapes={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),
            b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
    require(data[:4] in shapes,'unknown PCAP shape');endian,scale=shapes[data[:4]]
    require(struct.unpack(endian+'I',data[20:24])[0]==1,'PCAP must contain Ethernet')
    at=24;windows=[]
    while at<len(data):
        require(at+16<=len(data),'short PCAP record')
        sec,fraction,size,original=struct.unpack(endian+'IIII',data[at:at+16]);at+=16
        require(at+size<=len(data),'short captured packet');frame=data[at:at+size];at+=size
        if len(frame)<54 or frame[12:14]!=b'\x08\0':continue
        ip=frame[14:];ihl=(ip[0]&15)*4;total=int.from_bytes(ip[2:4],'big')
        if ip[0]>>4!=4 or ihl<20 or total<ihl+20 or len(ip)<total or ip[9]!=6:continue
        if int.from_bytes(ip[6:8],'big')&0x3fff:continue
        if ip[12:16]!=bytes([10,0,2,15]) or ip[16:20]!=bytes([10,0,2,2]):continue
        tcp=ip[ihl:total];tcp_header=(tcp[12]>>4)*4
        if tcp_header<20 or len(tcp)<tcp_header or not tcp[13]&0x10 or tcp[13]&0x04:continue
        if int.from_bytes(tcp[:2],'big')!=case['local_port'] or int.from_bytes(tcp[2:4],'big')!=4443:continue
        windows.append({'wall_time_ns':sec*1000000000+fraction*scale,
                        'window':int.from_bytes(tcp[14:16],'big'),'flags':tcp[13]})
    zero=[r for r in windows if r['window']==0]
    reopened=[r for r in windows if zero and r['wall_time_ns']>zero[0]['wall_time_ns'] and r['window']>0]
    return {'guest_tcp_windows':windows,'zero_window_observed':bool(zero),
            'reopened_after_zero':bool(reopened),
            'limit':'PCAP wall time is not native PIT time. Zero-window-before-kill requires the separately measured fixture-local outbound ACK observer and kill timestamps; no numeric queue occupancy is inferred.'}


def fields(line):
    return dict(re.findall(r'(?<!\S)([a-zA-Z_][a-zA-Z0-9_]*)=([^\s]+)',line))


def classify_report(report):
    outcome=report['outcome']
    if outcome=='TLS' and report.get('tls_error_code')=='Some("ENTROPY_UNAVAILABLE")':return 'EntropyUnavailable'
    if outcome=='TLS' and report.get('tls_error_code')=='Some("ALPN_UNAVAILABLE")':return 'AlpnRejected'
    if outcome=='NATIVE':return 'Denied' if report.get('native_error') in ['Denied','Some(Denied)'] else 'Transport'
    table={'SUCCESS':'Success','CERTIFICATE':'CertificateRejected','TIME':'TimeUnavailable',
        'TLS':'TlsRejected','TIMEOUT':'Deadline','HTTP':'HttpRejected',
        'HTTP_INCOMPLETE':'HttpIncomplete','TRUNCATED':'Truncated','CLOSE_INCOMPLETE':'CloseIncomplete'}
    require(outcome in table,'unexpected actual native Outcome: '+outcome)
    return table[outcome]


def linux_control(case, pki, observation_path=None):
    """Ordinary Linux OpenSSL client against independently bounded peer mode."""
    expected=case.get('reference_expected_class',case['expected_class'])
    peer=Peer(case,pki,bind='127.0.0.1',port=0,native=False,timeout=20)
    received=bytearray();clean=False;failure=None;verify_code=None;profile=None;failure_detail=None
    try:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
        context.check_hostname=True;context.verify_mode=ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(Path(pki['root_der']['path']).read_bytes()))
        context.set_alpn_protocols(['http/1.1'])
        with socket.create_connection(('127.0.0.1',peer.port),timeout=3) as raw:
            if case['peer_mode']=='backpressure':raw.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
            with context.wrap_socket(raw,server_hostname='absd-fixture.test',suppress_ragged_eofs=False) as client:
                require(client.version()=='TLSv1.3','control TLS version')
                if client.selected_alpn_protocol()!='http/1.1':
                    failure='AlpnRejected'
                else:
                    client.sendall(b'GET /native-network HTTP/1.1\r\nHost: absd-fixture.test:4443\r\nConnection: close\r\n\r\n')
                    if case['peer_mode']=='backpressure':time.sleep(1)
                    client.settimeout(2 if expected=='Deadline' else 10)
                    while True:
                        part=client.recv(137)
                        if not part:clean=True;break
                        received.extend(part);require(len(received)<=32768,'control response bound')
                    client.unwrap()
    except ssl.SSLCertVerificationError as error:
        failure='CertificateRejected';verify_code=error.verify_code
    except ssl.SSLEOFError as error:
        failure='Truncated';failure_detail={'type':type(error).__name__,'errno':error.errno,
            'reason':getattr(error,'reason',None),'message':str(error)}
    except ssl.SSLError as error:
        failure='AlpnRejected' if getattr(error,'reason',None)=='TLSV1_ALERT_NO_APPLICATION_PROTOCOL' else 'TlsRejected'
    except (socket.timeout,TimeoutError):failure='Deadline'
    except ConnectionError as error:
        failure='Transport';failure_detail={'type':type(error).__name__,'errno':error.errno,'message':str(error)}
    finally:
        # The positive peer waits for our close_notify before return; join it
        # before setting stop so cleanup cannot manufacture its close event.
        for thread in peer.threads:thread.join(timeout=2)
        peer.close()
        # Preserve the observation before verdict checks, including a failed
        # reference case whose exception prevents a normal result return.
        if observation_path is not None:
            seal(observation_path,{'case':case['id'],'ABSD_execution':False,
                'expected_native_class':case['expected_class'],'observed_failure':failure,
                'expected_reference_class':expected,
                'failure_detail':failure_detail,'tls_clean_close':clean,
                'certificate_verify_code':verify_code,'response_bytes':len(received),
                'response_sha256':hashlib.sha256(received).hexdigest(),'fixture':peer.report()})
    if expected=='CertificateRejected':
        codes={'untrusted':20,'signature-failure':7,'wrong-name':62,'expired':10,'future':9}
        require(failure==expected and verify_code==codes[case['peer_mode']], 'wrong independent certificate reason')
    elif expected=='Success':
        require(failure is None and clean,'positive Linux TLS control failed')
        profile=http_profile(bytes(received),case['expected_body'])
        require(peer.client_close_notify and peer.server_close_notify and not peer.errors,'control close exchange/fixture')
    elif expected in ['HttpRejected','HttpIncomplete']:
        require(failure is None and clean,'HTTP fixture did not use clean TLS')
        try:http_profile(bytes(received),case['expected_body'])
        except RuntimeError:pass
        else:raise RuntimeError('negative HTTP fixture passed independent profile')
    elif expected=='CloseIncomplete':
        require(failure=='Truncated','raw FIN control did not expose missing close_notify')
        profile=http_profile(bytes(received),case['expected_body'])
    elif case['peer_mode']=='reset-record':
        # OpenSSL can translate a TCP reset during a partial TLS record into
        # SSLEOFError. This reference-library mapping does not change the
        # native W06 Transport predicate. Exact RST/exception correspondence
        # was separately captured and independently inspected before adoption.
        require(expected=='Transport' and failure in ['Transport','Truncated'] and not clean,
                'reset control did not refuse incomplete TLS')
        require(not peer.errors and any(event.get('event')=='tcp-reset-configured' and
                event.get('linger')==[1,0] for event in peer.events),
                'reset control lacks measured socket configuration')
    else:
        allowed={'Transport':{'Transport'},'Truncated':{'Truncated'},'TlsRejected':{'TlsRejected'},'AlpnRejected':{'AlpnRejected'},'Deadline':{'Deadline'}}
        require(failure in allowed.get(expected,set()),'unexpected Linux negative control outcome: '+str(failure))
    return {'case':case['id'],'ABSD_execution':False,'expected_class':expected,'observed_failure':failure,
            'failure_detail':failure_detail,
            'certificate_verify_code':verify_code,'tls_clean_close':clean,'profile':profile,
            'response_bytes':len(received),'response_sha256':hashlib.sha256(received).hexdigest(),'fixture':peer.report()}


def verify_native(case, output, fixture, windows, validation_unix_time):
    selectors=[fields(line) for line in output.splitlines() if line.startswith('TLS SERVICE SELECTOR ')]
    require(len(selectors)==1 and selectors[0].get('case')==case['id'],'actual service selector absent')
    for field,key in [('local_port','local_port'),('expected_body','expected_body'),
                      ('grant_lifetime_ms','grant_lifetime_ms'),('connect_timeout_ms','connect_deadline_ms')]:
        require(selectors[0].get(field)==str(case[key]),'actual service selector differs: '+field)
    require(selectors[0].get('unix_seconds')==str(validation_unix_time),
            'actual fixture time selector differs from the sealed PKI anchor')
    cpu=None
    if not case['flags']['grant_exhaustion']:
        records=[fields(line) for line in output.splitlines() if line.startswith('TLS CPU ')]
        require(len(records)==1,'actual child CPUID observation absent')
        cpu=records[0]
        require(cpu.get('vendor')=='GenuineIntel' and all(re.fullmatch(r'0|[1-9][0-9]*',cpu.get(key,''))
                for key in ['family','model','leaf1_eax','leaf1_ecx','rdrand']),'actual CPUID fields absent/noncanonical')
        eax=int(cpu['leaf1_eax']);ecx=int(cpu['leaf1_ecx']);base_family=(eax>>8)&15
        family=base_family+(((eax>>20)&255) if base_family==15 else 0)
        model=((eax>>4)&15)|((((eax>>16)&15)<<4) if base_family in [6,15] else 0)
        bit=0 if case['id']=='P10' else 1
        require(family==int(cpu['family'])==6 and model==int(cpu['model'])==60 and
                (ecx>>30)&1==int(cpu['rdrand'])==bit,'measured CPU/RDRAND differs from selected Haswell variant')
    ready='TLS SERVICE CASE READY id='+case['id']+' local_port='+str(case['local_port'])
    require(ready in output,'selected native case/port was not measured')
    done=[fields(line) for line in output.splitlines() if line.startswith('TLS SERVICE DONE ')]
    require(len(done)==1 and done[0].get('id')==case['id'] and done[0].get('sockets')=='0','service resource terminal')
    for name in ['processes','handles','pipes','cells']:
        before=done[0].get(name+'_before','');after=done[0].get(name+'_after','')
        require(re.fullmatch(r'0|[1-9][0-9]*',before) is not None and
                re.fullmatch(r'0|[1-9][0-9]*',after) is not None and before==after,
                'missing/noncanonical service resource count or delta: '+name)
    require(fixture['accepts']==case['expected_accepts'] and fixture['guard_accepts']==0,'accept/retry/guard count')
    require(not fixture['errors'],'independent fixture error')
    if case['expected_class']=='Interrupted':
        require('TLS CHILD DONE id='+case['id']+' class=Interrupted' in output,'child was not interrupted')
        returned=[fields(line) for line in output.splitlines() if line.startswith('TLS CHILD INTERRUPT RETURN id='+case['id']+' ')]
        exits=[fields(line) for line in output.splitlines() if line.startswith('TLS CHILD EXIT id='+case['id']+' ')]
        require(len(returned)==1 and re.fullmatch(r'0|[1-9][0-9]*',returned[0].get('result','')) is not None,
                'successful measured interruption action absent')
        require(len(exits)==1 and exits[0].get('kind')=='3' and exits[0].get('killed')=='true',
                'interrupted child exit was not measured')
        actual='Interrupted';report=None
    elif case['expected_class']=='Exhausted':
        require('TLS GRANT CONTROL id='+case['id']+' result=Err(Exhausted)' in output,'typed service exhaustion absent')
        actual='Exhausted';report=None
    else:
        reports=[fields(line) for line in output.splitlines() if line.startswith('TLS RESULT case='+case['id']+' ')]
        require(len(reports)==1,'one actual typed consumer result required');report=reports[0]
        actual=classify_report(report)
        if case['id']=='W02':
            require(case.get('criteria_amendment')=='W02-20261016-UPSTREAM-RUSTLS' and
                    case.get('allowed_native_classes')==['Deadline','Truncated'] and
                    case.get('reference_expected_class')=='TlsRejected',
                    'W02 dated upstream criteria amendment absent')
            require(actual in case['allowed_native_classes'],'amended W02 native outcome differs: '+actual)
            require(report.get('http_body')=='0','W02 delivered response body plaintext')
            require(report.get('connect_calls')=='1','W02 made another CONNECT attempt')
        else:
            require(actual==case['expected_class'],'actual native outcome differs: '+actual)
        require(report.get('preauth_http_emitted')=='0','pre-authentication HTTP emission not measured zero')
        if actual!='Denied':
            require(report.get('pipe_fenced')=='true','consumer pipe retirement was not measured')
            expected_deadline=min(int(report['start_ms'])+10000,int(report['grant_expiry_ms']))
            require(int(report['deadline_ms'])==expected_deadline,'deadline extended grant/operation authority')
        if actual=='Success':
            require(report.get('protocol_version')=='Some("TLSv1_3")','actual native TLS1.3 version absent')
            for field in ['authenticated','peer_closed','local_close_drained','native_close_accepted']:
                require(report.get(field)=='true','success predicate missing: '+field)
            require(int(report['http_body'])==case['expected_body'],'native body count')
            require(fixture['client_close_notify_received'] and fixture['server_close_notify_drained'],
                    'independent close_notify exchange absent')
        if actual=='CertificateRejected':
            codes={'P02':'UNKNOWN_ISSUER','P02b':'BAD_SIGNATURE','P03':'WRONG_NAME','P04':'EXPIRED','P05':'NOT_YET_VALID'}
            require(report.get('tls_error_code')=='Some("'+codes[case['group']]+'")','wrong native certificate reason')
        if actual=='HttpIncomplete':
            require(report.get('authenticated')=='true' and report.get('peer_closed')=='true',
                    'H04 did not observe clean peer TLS closure')
            if report.get('native_close_accepted')=='true' and report.get('local_close_drained')=='true':
                require(fixture['client_close_notify_received'] and fixture['server_close_notify_drained'],
                        'H04 claimed cleanup lacks independently received client close_notify')
            else:
                require(report.get('cleanup_error') not in [None,'None'],
                        'H04 incomplete cleanup lacks its separate error')
        if actual=='Denied':
            denial=[re.fullmatch(r'TLS DENIAL reply_bytes=12 header=\[([0-9, ]+)\]',line)
                    for line in output.splitlines() if line.startswith('TLS DENIAL ')]
            require(len(denial)==1 and denial[0] is not None and
                    [int(n.strip()) for n in denial[0].group(1).split(',')]==[1,16,2,0,10,0,2,2,17,91,0,0] and
                    report.get('denied_connect_requests')=='1' and report.get('actor')=='authority-control',
                    'actual denied CONNECT reply or request count absent')
    events=fixture.get('events',[]);mode=case['peer_mode']
    if mode in ['bad-handshake-tag','bad-response-tag']:
        phase='handshake' if mode=='bad-handshake-tag' else 'response'
        require(fixture['record_mutation_observed'] and any(event.get('event')=='record-mutation' and
                event.get('phase')==phase and event.get('original_sha256')!=event.get('changed_sha256')
                for event in events),'independent encrypted record mutation absent')
    if mode in ['bad-record','oversize-record']:
        expected='ff03030000' if mode=='bad-record' else '1703034101'
        require(any(event.get('event')=='raw-record' and event.get('bytes_hex')==expected for event in events),
                'independent malformed record write absent')
        if mode=='oversize-record':
            require(not any(event.get('event')=='http-response' for event in events),
                    'W02 peer sent response plaintext instead of header-only fixture')
    if mode in ['eof-header1','eof-header4','eof-body','reset-record']:
        require(any(event.get('event')=='record-truncation' and event.get('mode')==mode and
                0<event.get('sent_bytes',0)<event.get('original_bytes',0) for event in events),
                'independent record truncation absent')
    if case.get('expect_http') is False:
        require(fixture['request_bytes']==0,'HTTP observed in pre-authentication/refusal case')
        if report is not None:require(report.get('http_emitted')=='0','native HTTP emitted in refusal case')
    if case.get('wire_zero_window_required') and not case.get('require_zero_window_before_interrupt'):
        final=[fields(line) for line in output.splitlines() if line.startswith('TLS WINDOW SNAPSHOT ') and
               'id='+case['id']+' ' in line and 'stage=final ' in line]
        require(len(final)==1 and int(final[0].get('zero_events','0'))>0 and
                int(final[0].get('reopen_events','0'))>0 and final[0].get('clock_refused')=='false' and
                final[0].get('counters_saturated')=='false','native zero/reopening observation absent')
        require(windows['zero_window_observed'] and windows['reopened_after_zero'],
                'NOT_ESTABLISHED: receiver zero-window and reopening not captured')
    if case.get('require_zero_window_before_interrupt'):
        snapshots=[fields(line) for line in output.splitlines() if line.startswith('TLS WINDOW SNAPSHOT ') and 'id='+case['id']+' ' in line and 'stage=pre_interrupt ' in line]
        require(len(snapshots)==1,'NOT_ESTABLISHED: interruption window snapshot absent')
        observed=snapshots[0]
        returned=[fields(line) for line in output.splitlines() if line.startswith('TLS CHILD INTERRUPT RETURN id='+case['id']+' ')]
        timestamp=re.fullmatch(r'Some\((\d+)\)',observed.get('last_zero_ms',''))
        ack_time=re.fullmatch(r'Some\((\d+)\)',observed.get('last_ack_ms',''))
        pauses=[fields(line) for line in output.splitlines() if line.startswith('TLS READ PAUSE ')]
        starts=[fields(line) for line in output.splitlines() if line.startswith('TLS CHILD INTERRUPT OBSERVED id='+case['id']+' ')]
        requests=[fields(line) for line in output.splitlines() if line.startswith('TLS CHILD INTERRUPT REQUEST id='+case['id']+' ')]
        require(len(pauses)==len(starts)==len(requests)==1 and
                pauses[0].get('milliseconds')==str(case['flags']['pause_before_response_ms']) and
                starts[0].get('delay_ms')==str(case['flags']['interrupt_delay_ms']) and
                int(pauses[0]['at_ms'])<=int(starts[0]['observed_ms']) and
                requests[0].get('observed_ms')==starts[0]['observed_ms'] and
                int(requests[0]['requested_ms'])>=int(starts[0]['observed_ms'])+case['flags']['interrupt_delay_ms'] and
                len(returned)==1 and int(requests[0]['requested_ms'])<=int(returned[0]['end_ms'])<
                int(pauses[0]['at_ms'])+case['flags']['pause_before_response_ms'],
                'NOT_ESTABLISHED: interruption was not measured during the response READ pause')
        require(observed.get('latest_window')=='Some(0)' and int(observed.get('zero_events','0'))>0 and
                observed.get('clock_refused')=='false' and observed.get('counters_saturated')=='false' and
                timestamp and ack_time and int(timestamp.group(1))<=int(ack_time.group(1))<=int(observed['at_ms']) and
                len(returned)==1 and returned[0].get('zero_window_established')=='true' and
                int(observed['at_ms'])<=int(returned[0]['end_ms']) and
                windows['zero_window_observed'],'NOT_ESTABLISHED: zero-window-before-kill relation absent')
    return {'actual_class':actual,'typed_report':report,'measured_cpu':cpu,'fixture':fixture,'window_observations':windows}


def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module


def native_case(case, args, admission, pki, measure, helpers):
    work=args.work/case['id'].replace('/','_');work.mkdir(exist_ok=False)
    measured={key:measure.git_identity(value['path'],value['revision'],value['tree'])
              for key,value in admission['sources'].items()}
    root=pki['root_der'];require(sha(root['path'])==root['sha256'],'public root changed')
    child=Path(admission['client_elf']);require(sha(child)==admission['client_sha256'],'root-pinned child differs')
    require(Path(root['path']).read_bytes() in child.read_bytes(),'root DER absent from exact child ELF')
    build_env=measure.private_environment(admission['environment'])
    selectors={'ABSD_TLS_CASE':case['id'],'ABSD_TLS_UNIX_SECONDS':str(pki['validation_unix_time']),
               'ABSD_TLS_ROOT_DER':root['path'],'ABSD_TLS_ROOT_SHA256':root['sha256'],
               'ABSD_TLS_CLIENT_ELF':str(child),'ABSD_TLS_CLIENT_SHA256':admission['client_sha256']}
    build_env.update(selectors)
    seal(work/'CASE-INPUTS.json',{'time':now(),'selected_case':case,'build_environment':selectors,
        'root':root,'child_elf':measure.identity(child),'source':measured,
        'case_manifest_sha256':sha(Path(__file__).with_name('native-tls-cases.json'))})
    measure.capacity('/',admission['expected_new_per_case_bytes'])
    build_argv=[value.replace('{case_work}',str(work.resolve())) for value in admission['parent_build_argv']]
    require(all('{' not in value and '}' not in value for value in build_argv),'unresolved parent build template')
    require(build_argv.count('--receipt')==1 and
            Path(build_argv[build_argv.index('--receipt')+1])==work.resolve()/'NATIVE-BUILD.json',
            'parent build must write its new per-case receipt')
    build=measure.start_process(build_argv,args.source,work/'parent-build.log',
        build_env,work/'PARENT-BUILD-LAUNCH.json',{'selected_case':case,'selectors':selectors})
    measure.wait_process(build,work/'PARENT-BUILD-EXIT.json',admission['parent_build_timeout_seconds'])
    require(sha(child)==admission['client_sha256'],'parent builder changed the reused child bytes')
    parent=Path(admission['parent_elf']);require(child.read_bytes() in parent.read_bytes(),'parent does not embed exact child')
    # The canonical helper builds only; its CPU/vendor/default launch is never called.
    old_env=os.environ.copy()
    try:
        os.environ.clear();os.environ.update(build_env)
        iso,image=helpers.build_iso(str(args.kernel),str(parent),str(work),1)
    finally:
        os.environ.clear();os.environ.update(old_env)
    kernel=args.kernel/'build/external/target/debug/absd-kernel'
    boot=measure.iso_identity(iso,kernel,work/'boot-extracted',work/'BOOT-INPUTS.json',
                              embedded_elfs=[child,parent])
    serial=work/'tls.serial.log';wire=work/'tls.pcap'
    argv=[*served_qemu([admission['qemu'], '-m', '256M']),'-accel','tcg,thread=single','-cpu',
          'Haswell,-rdrand' if case['id']=='P10' else 'Haswell,+rdrand',
          '-smp','1','-cdrom',iso,'-drive','file='+image+',format=raw,if=ide,index=0',
          '-display','none','-serial','file:'+str(serial),'-no-reboot','-no-shutdown',
          '-device','isa-debug-exit,iobase=0xf4,iosize=0x04','-device','e1000,netdev=n0',
          '-netdev','tap,id=n0,ifname='+admission['tap']+',script=no,downscript=no',
          '-object','filter-dump,id=tlsdump,netdev=n0,file='+str(wire)]
    peer=Peer(case,pki,timeout=admission['peer_timeout_seconds']);producer=None
    try:
        measured={key:measure.git_identity(value['path'],value['revision'],value['tree'])
                  for key,value in admission['sources'].items()}
        producer=measure.start_qemu(argv,work,work/'qemu.log',build_env,work/'QEMU-LAUNCH.json',
                                    boot,measured,missing_rdrand=case['id']=='P10')
        measure.wait_process(producer,work/'QEMU-EXIT.json',admission['boot_timeout_seconds'],expected_returncode=3)
        helpers.finish_boot(producer,str(serial),re.escape(('TLS SERVICE DONE id='+case['id']+' sockets=0').encode()))
    finally:
        if producer is not None and producer.poll() is None:measure.stop_owned_group(producer)
        try:peer.close()
        finally:
            seal(work/'FIXTURE.json',peer.report())
            decoded=helpers.stdout_of(str(serial)).decode(errors='replace')
            (work/'native.stdout.log').write_text(decoded)
            seal(work/'CASE-END.json',{'time':now(),'case':case['id'],
                'qemu_wait_returncode':producer.returncode if producer is not None else None,
                'cpu_observation_present':any(line.startswith('TLS CPU ') for line in decoded.splitlines()),
                'consumer_begin_present':any(line.startswith('TLS BEGIN case='+case['id']+' ') for line in decoded.splitlines()),
                'serial_sha256':sha(serial) if serial.exists() else None,
                'pcap_sha256':sha(wire) if wire.exists() else None,'fixture_errors':peer.errors})
    output=helpers.stdout_of(str(serial)).decode(errors='replace')
    windows=pcap_windows(wire,case);seal(work/'WINDOWS.json',windows)
    result=verify_native(case,output,peer.report(),windows,pki['validation_unix_time'])
    result.update(case=case['id'],disposition='PASS',measured_qemu_exit=producer.returncode,boot_inputs=boot)
    seal(work/'RESULT.json',result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admission',type=Path,required=True);parser.add_argument('--pki',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True);parser.add_argument('--controls',action='store_true')
    parser.add_argument('--source',type=Path);parser.add_argument('--kernel',type=Path)
    parser.add_argument('--measure-tools',type=Path);parser.add_argument('--case',action='append',default=[])
    args=parser.parse_args();admission=json.loads(args.admission.read_text())
    require(admission.get('disposition')=='GO' and admission.get('peer_source_sha256')==sha(__file__),
            'exact peer/source admission is held')
    require(os.geteuid()==0 and socket.gethostname()==admission.get('host_name') and
            re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',admission.get('run','')) is not None and
            socket.gethostname()=='absd-s2-tls-'+admission['run'][:8],
            'only the exact fresh isolated VM/run is admitted')
    manifest_path=Path(__file__).with_name('native-tls-cases.json');manifest=json.loads(manifest_path.read_text())
    require(sha(manifest_path)==admission.get('case_manifest_sha256') and manifest['group_count']==32,
            'reviewed case manifest differs')
    require(admission.get('review_records') and all(sha(item['path'])==item['sha256']
            for item in admission['review_records']),'exact reviewed source/closure records required')
    pki=json.loads(args.pki.read_text());require(pki['private_keys_in_evidence'] is False,'private material in evidence')
    for cert in [*pki['public_certificates'],*pki['leaf_certificates'].values(),pki['root_der']]:
        require(sha(cert['path'])==cert['sha256'],'public PKI changed')
    require(abs(time.time()-pki['validation_unix_time'])<14400,'fixture validation anchor outside admitted four-hour occurrence')
    require(admission.get('peer_controls_go' if args.controls else 'native_execution_go') is True,
            'controls/native execution remain held')
    all_cases=manifest['native_occurrences']+manifest['separate_native_occurrences']
    excluded={'TimeUnavailable','Denied','Exhausted','Interrupted'}
    selected=([c['id'] for c in manifest['native_occurrences'] if c['expected_class'] not in excluded]
              if args.controls else args.case or [c['id'] for c in manifest['native_occurrences']])
    require(not args.controls or not args.case,'controls use the explicit applicable peer list; no ignored selector')
    require(len(selected)==len(set(selected)) and set(selected)<={c['id'] for c in all_cases},
            'duplicate or unknown selected case')
    args.work.mkdir(exist_ok=False);results=[];attempted=[];disposition='FAIL';error=None
    seal(args.work/'ENVIRONMENT.json',{'time':now(),'PYTHONOPTIMIZE':os.environ.get('PYTHONOPTIMIZE'),
        'sys_flags_optimize':sys.flags.optimize,'SSLKEYLOGFILE_present':'SSLKEYLOGFILE' in os.environ,
        'python':sys.version,'openssl':ssl.OPENSSL_VERSION})
    require(not os.environ.get('SSLKEYLOGFILE'),'TLS key logging is refused')
    try:
        if args.controls:
            for identity in selected:
                case=next(c for c in all_cases if c['id']==identity)
                require(admission['absolute_deletion_deadline_epoch']-time.time()>=
                        admission['minimum_remaining_before_case_seconds'],'lease margin exhausted before control')
                attempted.append(case['id'])
                observation=args.work/(case['id'].replace('/','_')+'.observation.json')
                result=linux_control(case,pki,observation);results.append(result)
                seal(args.work/(case['id'].replace('/','_')+'.json'),result)
        else:
            require(args.source and args.kernel and args.measure_tools,'native source/kernel/measurement paths required')
            require(set(admission['sources'])=={'platform','kernel'} and
                    args.source.resolve()==Path(admission['sources']['platform']['path']).resolve() and
                    args.kernel.resolve()==Path(admission['sources']['kernel']['path']).resolve(),
                    'actual build/helper paths differ from the measured admitted source checkouts')
            require(sha(args.measure_tools)==admission['measure_sha256'],'measurement helper differs')
            measure=load_module('tls_measure',args.measure_tools)
            require(sha(args.source/'scripts/net-matrix.py')==admission['net_helper_sha256'],'canonical build helper differs')
            helpers=load_module('tls_net_helper',args.source/'scripts/net-matrix.py')
            for identity in selected:
                case=next(c for c in all_cases if c['id']==identity)
                remaining=admission['absolute_deletion_deadline_epoch']-time.time()
                if remaining<admission['minimum_remaining_before_case_seconds']:
                    disposition='INCOMPLETE';raise RuntimeError('lease margin exhausted; remaining cases NOT_RUN')
                attempted.append(identity)
                results.append(native_case(case,args,admission,pki,measure,helpers))
        disposition='PASS'
    except BaseException as caught:
        error={'type':type(caught).__name__,'message':str(caught)}
        (args.work/'ERROR.log').write_text(traceback.format_exc())
    finally:
        qemu_records=[]
        if not args.controls:
            for identity in attempted:
                record=args.work/identity.replace('/','_')/'CASE-END.json'
                if record.exists():qemu_records.append({**json.loads(record.read_text()),'record':str(record),'record_sha256':sha(record)})
        p10_record=next((row for row in qemu_records if row['case']=='P10'),None)
        p10_passed=not args.controls and any(row['case']=='P10' for row in results)
        p10_status=('PASS' if p10_passed else 'NOT_RUN' if 'P10' not in attempted or
                    (p10_record and p10_record['qemu_wait_returncode'] is not None and
                     not p10_record['cpu_observation_present'] and not p10_record['consumer_begin_present']) else 'FAIL')
        seal(args.work/'RESULT.json',{'schema_version':1,'time':now(),'disposition':disposition,
            'error':error,'results':results,'planned_case_groups':32,'ABSD_execution':not args.controls,
            'requested_case_ids':selected,'attempted_case_ids':attempted,
            'completed_case_ids':[row['case'] for row in results],
            'missing_requested_case_ids':[identity for identity in selected if identity not in {row['case'] for row in results}],
            'unattempted_case_ids':[identity for identity in selected if identity not in attempted],
            'passed_native_groups':sorted({next(c['group'] for c in all_cases if c['id']==row['case']) for row in results}) if not args.controls else [],
            'host_only_groups_not_claimed_as_native':['P06','P07','L06','L08'],
            'separate_P10_requested':not args.controls and 'P10' in selected,
            'separate_P10_completed':p10_passed,
            'conditional_P10_native_coverage':{'status':p10_status if not args.controls else 'NOT_ABSD_EXECUTION',
                'consumer_reached':bool(p10_record and (p10_record['cpu_observation_present'] or p10_record['consumer_begin_present'])),
                'qemu_record':p10_record,
                'limit':'Pre-consumer absence establishes no native entropy result or cause. Original boot/QEMU and matrix failure remain unchanged.'},
            'qemu_execution_case_ids':[row['case'] for row in qemu_records if row['qemu_wait_returncode'] is not None],
            'qemu_exit_records':qemu_records,
            'measured_qemu_wait_returncodes':[row['qemu_wait_returncode'] for row in qemu_records],
            'all_measured_qemu_exits_expected':bool(qemu_records) and
                all(row['qemu_wait_returncode']==3 for row in qemu_records),
            'private_material_included':False,'limits':['Host-only groups remain separately executed evidence.',
                'Ordinary Linux controls qualify the independent peer, never ABSD.',
                'Missing-RDRAND native result is not established if the platform cannot reach the consumer.',
                'A failed/not-established case is never relabelled by a later fixture/source correction.']})
    return 0 if disposition=='PASS' else 1


if __name__=='__main__':
    sys.exit(main())
