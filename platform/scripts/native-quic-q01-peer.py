#!/usr/bin/env python3
"""Bounded echo and authentication-refusal peer using unmodified aioquic 1.6.1.

Only the public caller-driven API is used. Explicit fixture trust, local send,
captured wire emission and authenticated application receipt remain separate.
These separate development profiles do not satisfy the original campaign prerequisites.
"""
from pathlib import Path
import argparse
import datetime
import hashlib
import importlib.metadata
import json
import os
import re
import select
import socket
import ssl
import stat
import sysconfig
import sys
import threading
import time
import traceback


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def seal(path, value):
    with Path(path).open('x') as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())


def pattern(length=4096):
    return bytes(97 + offset % 26 for offset in range(length))


def verify_runtime(closure_path, closure_sha256, site_packages):
    """Bind installed wheel files before importing any peer implementation."""
    require(not sys.flags.optimize and not os.environ.get('PYTHONOPTIMIZE'),
            'optimized Python is refused')
    require(not any(os.environ.get(key) for key in ('SSLKEYLOGFILE', 'QLOGDIR')),
            'traffic secret logging is refused')
    require(sys.version_info[:2] == (3, 12) and sys.flags.isolated == 1,
            'sealed peer closure requires isolated CPython 3.12 (-I)')
    require(sha(closure_path) == closure_sha256, 'peer closure identity differs')
    closure = json.loads(Path(closure_path).read_text())
    root = Path(site_packages).resolve(strict=True)
    require(root.is_dir(), 'private peer installation path absent')
    prefixes = ('aioquic','cryptography','OpenSSL','service_identity','pylsqpack','certifi',
                'attrs','attr','cffi','_cffi_backend','pycparser','typing_extensions')
    require(not any(name == prefix or name.startswith(prefix + '.') for name in sys.modules
                    for prefix in prefixes), 'peer dependency was imported before exact path binding')
    standard = {Path(sysconfig.get_path(name)).resolve() for name in ('stdlib','platstdlib')}
    kept = []
    for entry in sys.path:
        if not entry:
            continue
        resolved = Path(entry).resolve()
        if any(part in ('site-packages','dist-packages') for part in resolved.parts):
            continue
        if any(resolved == base or resolved.is_relative_to(base) or
               resolved == base.parent / ('python%d%d.zip' % sys.version_info[:2]) for base in standard):
            kept.append(str(resolved))
    require(kept, 'interpreter standard-library path unavailable')
    sys.path[:] = [str(root), *kept]
    expected = closure['packages']
    require(len(expected) == 10 and next(row for row in expected if row['name'] == 'aioquic')['version'] == '1.6.1',
            'unreviewed peer package set')
    files = 0
    for row in expected:
        dist = importlib.metadata.distribution(row['name'])
        require(dist.version == row['version'], 'installed peer package version differs: ' + row['name'])
        for member in row['wheel_files']:
            # Installers rewrite RECORD; all implementation and notice bytes remain exact.
            if member['path'].endswith('.dist-info/RECORD'):
                continue
            path = Path(dist.locate_file(member['path']))
            require(path.resolve(strict=True).is_relative_to(root), 'peer package escaped private installation')
            require(path.stat().st_size == member['bytes'] and sha(path) == member['sha256'],
                    'installed peer member differs: ' + member['path'])
            files += 1
    import aioquic
    from cryptography.hazmat.backends.openssl.backend import backend
    require(Path(aioquic.__file__).resolve().is_relative_to(root), 'ambient aioquic import')
    return {'time': now(), 'closure_sha256': closure_sha256,
            'python': {'path': sys.executable, 'sha256': sha(sys.executable), 'version': sys.version},
            'aioquic': aioquic.__version__, 'cryptography_openssl': backend.openssl_version_text(),
            'python_ssl_openssl': ssl.OPENSSL_VERSION, 'checked_wheel_files': files,
            'private_site_packages': str(root), 'effective_import_path':list(sys.path),
            'isolated_interpreter':True, 'preloaded_peer_dependencies':False,
            'ambient_trust_store_used': False}


def validate_pki(pki):
    require(pki['private_keys_in_evidence'] is False, 'private fixture keys in ordinary evidence')
    for row in [*pki['public_certificates'],*pki['leaf_certificates'].values(),pki['root_der']]:
        require(re.fullmatch(r'[0-9a-f]{64}',row['sha256']) is not None and sha(row['path'])==row['sha256'],
                'public fixture certificate identity differs')
        require(Path(row['path']).stat().st_size>0,'empty public fixture certificate')
    key=Path(pki['leaf_private_key_path'])
    value=key.lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_uid==os.geteuid() and stat.S_IMODE(value.st_mode)==0o600,
            'fixture private key custody differs')
    parent=key.parent.stat()
    require(parent.st_uid==os.geteuid() and stat.S_IMODE(parent.st_mode)==0o700,
            'fixture private key directory custody differs')


def development_profile(case, family="ipv4"):
    if family == "ipv6":
        expected = {"Q01":("echo", "q01-ipv6-development"), "Q08":("wrong-root", "q08-ipv6-development"), "Q17":("denied-destination", "q17-ipv6-development")}
        require(case["id"] in expected and case["peer_mode"] == expected[case["id"]][0], "only explicit IPv6 Q01/Q08/Q17 profiles are implemented")
        return expected[case["id"]][1]
    require(family == "ipv4", "unknown explicit socket family")
    expected = {'Q01':('echo', 'q01-development'),
                'Q03':('initial-loss', 'q03-initial-loss-development'),
                'Q08':('wrong-root', 'q08-wrong-root-development'),
                'Q09':('wrong-name', 'q09-wrong-name-development'),
                'Q10':('expired-certificate', 'q10-expired-development'),
                'Q11':('wrong-alpn', 'q11-wrong-alpn-development'),
                'Q19':('queue-exhausted', 'q19-queue-exhausted-development')}
    require(case['id'] in expected and case['peer_mode'] == expected[case['id']][0],
            'only explicit canonical Q01/Q03/Q08/Q09/Q10/Q11/Q19 development cases are implemented')
    return expected[case['id']][1]


def peer_certificate(case):
    development_profile(case)
    return {'Q01':'valid', 'Q03':'valid', 'Q08':'untrusted', 'Q09':'wrong-name', 'Q10':'expired', 'Q11':'valid', 'Q19':'valid'}[case['id']]


def peer_alpn(case):
    development_profile(case)
    return ['other-echo/1'] if case['id'] == 'Q11' else ['absd-echo/1']


def peer_terminal_codes(case):
    development_profile(case)
    return {'Q01':(0,), 'Q03':(0,), 'Q08':(298,304), 'Q09':(298,), 'Q10':(301,), 'Q11':(376,), 'Q19':(0,)}[case['id']]


def configuration(pki, client=False, case=None):
    from aioquic.quic.configuration import QuicConfiguration
    config = QuicConfiguration(is_client=client, alpn_protocols=['absd-echo/1'] if client else peer_alpn(case),
                               supported_versions=[1], idle_timeout=15.0,
                               max_data=8192, max_stream_data=8192,
                               max_datagram_size=1200, max_datagram_frame_size=None,
                               congestion_control_algorithm='reno', secrets_log_file=None,
                               quic_logger=None)
    if client:
        config.server_name = 'absd-fixture.test'
        config.verify_mode = ssl.CERT_REQUIRED
        root = pki['root_der']
        # Verify the exact bytes subsequently converted; the canonical receipt
        # lists DER certificates and supplies no root-A.pem path.
        der = Path(root['path']).read_bytes()
        require(der and digest(der) == root['sha256'], 'explicit fixture root DER changed')
        config.cadata = ssl.DER_cert_to_PEM_cert(der).encode('ascii')
        config.cafile = config.capath = None
        config.session_ticket = None
    else:
        config.load_cert_chain(pki['leaf_certificates'][peer_certificate(case)]['path'], pki['leaf_private_key_path'])
    return config


def queue_fixture_datagrams():
    # Exact existing native engine prefill bytes, not arbitrary invalid input.
    return [b'ABSD-QUEUE-00000'[:15] + bytes([ordinal]) for ordinal in range(4)]


def response_policy(case, family="ipv4"):
    """Only explicit authentication-refusal fixtures seal their first batch."""
    development_profile(case, family)
    if case['id'] == 'Q08':
        return 'q08-one-response-flight-v1'
    if case['id'] in ('Q09', 'Q10', 'Q11'):
        return 'auth-one-response-flight-v1'
    return 'standard'


def one_response_policy(case, family="ipv4"):
    return response_policy(case, family) != 'standard'


class Peer:
    def __init__(self, case, pki, bind, port, expected_source, timeout=20, startup_timeout=180, family="ipv4"):
        development_profile(case, family)
        self.family = family
        require(0 < timeout <= 30, 'peer deadline bound')
        require(0 < startup_timeout <= 180, 'peer initial-arrival deadline bound')
        self.case, self.pki, self.mode = case, pki, case['peer_mode']
        self.expected_source = tuple(expected_source)
        self.events, self.errors = [], []
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.deadline = self.started + startup_timeout
        self.operation_timeout = timeout
        self.started_io = False
        self.received = bytearray()
        self.echoed = 0
        self.request_fin = self.echo_fin = self.authenticated = False
        self.terminated = None
        self.rx_packets = self.tx_packets = self.rx_bytes = self.tx_bytes = 0
        self.connection = None
        self.initial_drops = 0
        self.queue_fills = 0
        self.response_policy = response_policy(case, family)
        self.one_response_flight = one_response_policy(case, family)
        self.response_flight_sealed = False
        self.initial_sha256 = None
        self.certificate_selection = None
        self.socket = socket.socket(socket.AF_INET6 if family == "ipv6" else socket.AF_INET, socket.SOCK_DGRAM)
        if family == "ipv6":
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            self.socket.bind((bind, port))
            self.socket.setblocking(False)
            self.port = self.socket.getsockname()[1]
            self.thread = threading.Thread(target=self.run, name='quic-peer-' + case['id'])
            self.thread.start()
        except BaseException:
            self.socket.close()
            raise

    def event(self, event_name, **values):
        with self.lock:
            require(len(self.events) < 4096, 'peer event ceiling')
            self.events.append({'event': event_name, 'time': now(), 'monotonic_ns': time.monotonic_ns(),
                                'wall_time_ns': time.time_ns(), **values})

    def send(self, data):
        require(not self.one_response_flight or not self.response_flight_sealed,
                'selected authentication response flight is fenced; no later UDP send')
        require(0 < len(data) <= 1200, 'peer datagram size ceiling')
        require(self.tx_packets < 512 and self.tx_bytes + len(data) <= 512 * 1200, 'peer transmit bound')
        count = self.socket.sendto(data, self.expected_source)
        require(count == len(data), 'partial Linux UDP send')
        self.tx_packets += 1
        self.tx_bytes += count
        self.event('udp-send', bytes=count, sha256=digest(data), source=list(self.socket.getsockname()[:2]),
                   destination=list(self.expected_source))

    def drop_initial(self, data):
        """One omission after public header validation, before engine delivery."""
        if self.mode != 'initial-loss' or self.initial_drops:
            return False
        require(self.connection is None and self.rx_packets == 1 and len(data) == 1200,
                'Initial omission must be the first validated received datagram')
        self.initial_drops = 1
        self.event('initial-drop', bytes=len(data), sha256=digest(data),
                   receive_ordinal=self.rx_packets, engine_delivered=False)
        return True

    def accept_queue_fixture(self, data):
        """Consume exactly four ordered native fixture datagrams before QUIC."""
        if self.mode != 'queue-exhausted':
            return False
        if self.queue_fills == 4:
            require(data not in queue_fixture_datagrams(), 'extra queue fixture after exact four')
            return False
        require(self.connection is None and self.rx_packets == self.queue_fills + 1,
                'queue prefill must precede engine construction and all other receipts')
        require(data == queue_fixture_datagrams()[self.queue_fills],
                'queue prefill count/order/bytes differ')
        ordinal = self.queue_fills
        self.queue_fills += 1
        self.event('queue-fixture-received', ordinal=ordinal, receive_ordinal=self.rx_packets,
                   bytes=len(data), sha256=digest(data), engine_delivered=False)
        return True

    def run(self):
        from aioquic.buffer import Buffer
        from aioquic.quic import events
        from aioquic.quic.connection import QuicConnection
        from aioquic.quic.packet import pull_quic_header, QuicPacketType
        try:
            while not self.stop.is_set() and time.monotonic() < self.deadline:
                current = time.monotonic()
                self.drive_timer(current)
                ready, _, _ = select.select([self.socket], [], [], 0.01)
                if not ready:
                    continue
                data, source = self.socket.recvfrom(65536)
                source = source[:2]
                current = time.monotonic()
                if not self.started_io:
                    self.started_io = True
                    self.deadline = min(self.deadline, current + self.operation_timeout)
                self.rx_packets += 1
                self.rx_bytes += len(data)
                require(self.rx_packets <= 512 and self.rx_bytes <= 512 * 1200, 'peer receive ceiling')
                self.event('udp-receive', bytes=len(data), sha256=digest(data), source=list(source))
                require(source == self.expected_source, 'unexpected source sent to owned fixture')
                require(0 < len(data) <= 1200, 'oversized client datagram')
                require(not (self.family == 'ipv6' and self.case['id'] == 'Q17'),
                        'denied native destination unexpectedly emitted UDP')
                if self.accept_queue_fixture(data):
                    continue
                if self.one_response_flight and self.response_flight_sealed:
                    self.event(('q08' if self.case['id'] == 'Q08' else 'auth')+'-after-flight-input', bytes=len(data), sha256=digest(data),
                               receive_ordinal=self.rx_packets, engine_delivered=False)
                    continue
                if self.connection is None:
                    if self.mode == 'queue-exhausted':
                        require(self.queue_fills == 4, 'four exact queue fixtures must precede Initial')
                    header = pull_quic_header(Buffer(data=data), host_cid_length=8)
                    require(header.packet_type == QuicPacketType.INITIAL and header.version == 1
                            and len(data) >= 1200, 'actual first QUICv1 Initial absent')
                    if self.drop_initial(data):
                        continue
                    self.initial_sha256 = digest(data)
                    self.certificate_selection = {'kind':peer_certificate(self.case),
                        'sha256':self.pki['leaf_certificates'][peer_certificate(self.case)]['sha256'],
                        'client_root_sha256':self.pki['root_der']['sha256'],
                        'configured_alpn':peer_alpn(self.case)}
                    self.event('certificate-selection', **self.certificate_selection)
                    self.connection = QuicConnection(configuration=configuration(self.pki, case=self.case),
                        original_destination_connection_id=header.destination_cid)
                    self.event('initial-observed', bytes=len(data), sha256=digest(data),
                               receive_ordinal=self.rx_packets)
                self.connection.receive_datagram(data, source, now=current)
                for _ in range(32):
                    event = self.connection.next_event()
                    if event is None:
                        break
                    if isinstance(event, events.HandshakeCompleted):
                        require(not self.authenticated and event.alpn_protocol == 'absd-echo/1'
                                and not event.early_data_accepted and not event.session_resumed,
                                'peer negotiated outside tranche')
                        self.authenticated = True
                        self.event('handshake', alpn=event.alpn_protocol, early_data=False, resumed=False)
                    elif isinstance(event, events.StreamDataReceived):
                        require(self.authenticated and event.stream_id == 0 and not self.request_fin,
                                'unexpected peer stream or data after FIN')
                        require(len(self.received) + len(event.data) <= 4096, 'request byte ceiling')
                        self.received.extend(event.data)
                        require(bytes(self.received) == pattern(len(self.received)), 'request bytes differ from independent pattern')
                        self.request_fin = event.end_stream
                        self.event('request-stream', stream_id=0, bytes=len(event.data),
                                   offset=len(self.received) - len(event.data), fin=event.end_stream)
                        self.echo()
                    elif isinstance(event, events.ConnectionTerminated):
                        self.terminated = {'error_code':event.error_code, 'frame_type':event.frame_type,
                                           'reason_phrase':event.reason_phrase}
                        self.event('connection-terminated', **self.terminated)
                        require(event.error_code in peer_terminal_codes(self.case),
                                'peer terminated with an unexpected error')
                    elif isinstance(event, (events.StreamReset, events.StopSendingReceived, events.DatagramFrameReceived)):
                        raise RuntimeError('unexpected stream reset/stop/application DATAGRAM')
                else:
                    raise RuntimeError('peer event-turn ceiling')
                self.flush()
        except BaseException as error:
            self.errors.append({'type':type(error).__name__, 'message':str(error), 'traceback':traceback.format_exc()})
        finally:
            self.event('peer-ended', stopped=self.stop.is_set(), deadline_reached=time.monotonic() >= self.deadline)

    def echo(self):
        while self.echoed < len(self.received):
            end = min(self.echoed + 512, len(self.received))
            self.connection.send_stream_data(0, bytes(self.received[self.echoed:end]), end_stream=False)
            self.event('echo-enqueue', offset=self.echoed, bytes=end - self.echoed)
            self.echoed = end
        if self.request_fin and not self.echo_fin:
            require(len(self.received) == 4096, 'request FIN before exact body')
            self.connection.send_stream_data(0, b'', end_stream=True)
            self.echo_fin = True
            self.event('echo-fin-enqueue', offset=self.echoed)

    def drive_timer(self, current):
        if self.connection is None or (self.one_response_flight and self.response_flight_sealed):
            return
        due = self.connection.get_timer()
        if due is not None and due <= current:
            self.connection.handle_timer(now=current)
        self.flush()

    def flush(self):
        if self.one_response_flight:
            if self.response_flight_sealed:
                return
            require(self.rx_packets == 1 and self.initial_sha256 is not None,
                    'selected authentication response must follow its first accepted Initial')
            # One complete public aioquic response batch, with no engine patch.
            # The fixture then observes input but performs no more engine work.
            batch = list(self.connection.datagrams_to_send(now=time.monotonic()))
            require(1 <= len(batch) <= 4, 'bounded selected authentication first response batch required')
            rows = [{'bytes':len(data), 'sha256':digest(data), 'destination':list(destination)}
                    for data, destination in batch]
            prefix = 'q08' if self.response_policy == 'q08-one-response-flight-v1' else 'auth'
            self.event(prefix+'-response-flight', policy=self.response_policy,
                       initial_sha256=self.initial_sha256, datagrams=rows)
            for data, destination in batch:
                require(tuple(destination) == self.expected_source, 'peer selected a new destination')
                self.send(data)
            self.response_flight_sealed = True
            self.event(prefix+'-response-flight-fenced', policy=self.response_policy,
                       tx_datagrams=self.tx_packets, tx_bytes=self.tx_bytes,
                       later_engine_work=False, later_send=False)
            return
        for data, destination in self.connection.datagrams_to_send(now=time.monotonic()):
            require(tuple(destination) == self.expected_source, 'peer selected a new destination')
            self.send(data)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            self.errors.append({'type':'FixtureCleanupError', 'message':'peer thread did not retire within3seconds'})
        self.socket.close()
        require(not self.thread.is_alive(), 'peer thread remains live')

    def report(self):
        with self.lock:
            return {'schema_version':1, 'case':self.case['id'], 'mode':self.mode,
                    'readiness_profile':development_profile(self.case, self.family), 'transport_family':self.family, 'canonical_campaign_acceptance':False,
                    'certificate_selection':self.certificate_selection, 'events':list(self.events), 'errors':list(self.errors),
                    'authenticated':self.authenticated, 'request_bytes':len(self.received),
                    'request_sha256':digest(self.received), 'request_fin':self.request_fin,
                    'echo_enqueued_bytes':self.echoed, 'echo_fin_enqueued':self.echo_fin,
                    'terminated':self.terminated, 'initial_drops':self.initial_drops,
                    'unique_queue_fixture_datagrams':self.queue_fills, 'rx_datagrams':self.rx_packets,
                    'tx_datagrams':self.tx_packets, 'rx_bytes':self.rx_bytes, 'tx_bytes':self.tx_bytes,
                    'thread_alive':self.thread.is_alive(), 'private_material_included':False,
                    'peer_policy':self.response_policy,
                    'response_flight_sealed':self.response_flight_sealed,
                    'limit':'Echo enqueue and UDP send establish local effects only; the native report and raw capture must independently establish received body/FIN and wire emission.'}


def linux_outcome(authenticated, fin, received_bytes, terminal):
    """Classify observed client state; terminal failure takes priority over FIN."""
    if terminal is not None and terminal['error_code'] != 0:
        if (terminal['error_code'] == 1 and terminal['frame_type'] == 0
                and terminal['reason_phrase'] == 'Idle timeout'):
            return 'Deadline'
        return 'Protocol'
    return 'Complete' if authenticated and fin and received_bytes == 4096 else 'Deadline'


def linux_control(case, pki, timeout=16, family="ipv4"):
    """Independent Linux client control; never native ABSD coverage."""
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import HandshakeCompleted, StreamDataReceived, ConnectionTerminated
    development_profile(case, family)
    require(case["id"] != "Q17", "Linux sockets cannot establish native denied-grant semantics")
    loopback = "::1" if family == "ipv6" else "127.0.0.1"
    require(0 < timeout <= 30, 'Linux control deadline bound')
    # Resolve exact trust before opening any socket or peer thread.
    config = configuration(pki, client=True)
    engine = QuicConnection(configuration=config)
    # Public API defaults suffice for positive stream0 echo. This reference
    # does not establish the native client's zero peer-stream refusal behavior.
    client = socket.socket(socket.AF_INET6 if family == "ipv6" else socket.AF_INET, socket.SOCK_DGRAM)
    if family == "ipv6":
        client.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    peer = None
    data = bytearray()
    authenticated = fin = started = False
    terminal = None
    deadline = time.monotonic() + timeout
    error = None
    unauthorized_filtered = 0
    try:
        client.bind((loopback, 0))
        client.setblocking(False)
        peer = Peer(case, pki, loopback, 0, client.getsockname()[:2], timeout=timeout, family=family)
        if case['id'] == 'Q19':
            for fixture in queue_fixture_datagrams():
                require(client.sendto(fixture, (loopback, peer.port)) == len(fixture),
                        'partial Linux queue fixture send')
        engine.connect((loopback, peer.port), now=time.monotonic())
        while time.monotonic() < deadline:
            current = time.monotonic()
            due = engine.get_timer()
            if due is not None and due <= current:
                engine.handle_timer(now=current)
            for wire, destination in engine.datagrams_to_send(now=current):
                require(destination == (loopback, peer.port), 'Linux control destination changed')
                require(client.sendto(wire, destination) == len(wire), 'partial Linux control UDP send')
            if select.select([client], [], [], 0.01)[0]:
                wire, source = client.recvfrom(65536)
                source = source[:2]
                if source != (loopback, peer.port):
                    unauthorized_filtered += 1
                    continue
                engine.receive_datagram(wire, source, now=time.monotonic())
            for _ in range(32):
                event = engine.next_event()
                if event is None:
                    break
                if isinstance(event, HandshakeCompleted):
                    require(event.alpn_protocol == 'absd-echo/1' and not event.early_data_accepted and not event.session_resumed,
                            'Linux control negotiation differs')
                    authenticated = True
                    if not started:
                        require(engine.get_next_available_stream_id(is_unidirectional=False) == 0, 'Linux control stream is not0')
                        engine.send_stream_data(0, pattern(), end_stream=True)
                        started = True
                elif isinstance(event, StreamDataReceived):
                    require(event.stream_id == 0 and not fin, 'Linux control unexpected stream')
                    data.extend(event.data)
                    require(len(data) <= 4096 and bytes(data) == pattern(len(data)), 'Linux control echo bytes differ')
                    fin = event.end_stream
                elif isinstance(event, ConnectionTerminated):
                    terminal = {'error_code':event.error_code, 'frame_type':event.frame_type, 'reason_phrase':event.reason_phrase}
            else:
                raise RuntimeError('Linux control event ceiling')
            if fin or terminal is not None:
                # Flush final ACK before closing the independent fixture.
                for wire, destination in engine.datagrams_to_send(now=time.monotonic()):
                    require(destination == (loopback, peer.port), 'Linux control final destination changed')
                    require(client.sendto(wire, destination) == len(wire), 'partial Linux control final UDP send')
                break
    except BaseException as caught:
        error = {'type':type(caught).__name__, 'message':str(caught), 'traceback':traceback.format_exc()}
    finally:
        client.close()
        if peer is not None:
            peer.close()
    actual = linux_outcome(authenticated, fin, len(data), terminal)
    return {'schema_version':1, 'case':case['id'], 'ABSD_execution':False,
            'readiness_profile':development_profile(case, family), 'transport_family':family, 'canonical_campaign_acceptance':False, 'actual_outcome':actual,
            'authenticated':authenticated, 'received_bytes':len(data), 'received_sha256':digest(data),
            'peer_fin':fin, 'terminal':terminal, 'error':error,
            'unauthorized_source_filtered':unauthorized_filtered,
            'fixture':peer.report() if peer is not None else None,
            'reference_clock':'Linux wall time, exact native fixture root DER; not native fixture-time evidence.',
            'peer_stream_limit_scope':'aioquic public defaults; no native zero-peer-stream refusal coverage.',
            'queue_control_scope':'Q19 Linux sends four exact prelude datagrams before normal engine Initial; this does not exercise native queue exhaustion or retained Quinn transmit state.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admission', type=Path, required=True)
    parser.add_argument('--case-json', type=Path, required=True)
    parser.add_argument('--pki', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    admission = json.loads(args.admission.read_text())
    require(admission.get('disposition') == 'GO' and admission.get('standalone_peer_go') is True
            and admission.get('readiness_profile') in ('q01-development', 'q03-initial-loss-development', 'q08-wrong-root-development', 'q09-wrong-name-development', 'q10-expired-development', 'q11-wrong-alpn-development', 'q19-queue-exhausted-development'),
            'standalone peer execution is held')
    require(admission['peer_source_sha256'] == sha(__file__) and sha(sys.executable)==admission['python_sha256'] and
            socket.gethostname() == admission['host_name'],
            'standalone exact peer/host identity differs')
    require(Path('/etc/machine-id').read_text().strip() == admission['machine_id'], 'peer host machine identity differs')
    require(admission['absolute_deletion_deadline_epoch'] - time.time() >= admission['minimum_remaining_before_case_seconds'],
            'standalone peer lease margin')
    args.work.mkdir(exist_ok=False)
    runtime = verify_runtime(admission['peer_closure_path'], admission['peer_closure_sha256'], admission['peer_site_packages'])
    seal(args.work/'RUNTIME.json', runtime)
    case = json.loads(args.case_json.read_text())
    pki = json.loads(args.pki.read_text())
    validate_pki(pki)
    manifest_path=Path(admission['case_manifest_path'])
    require(sha(manifest_path)==admission['case_manifest_sha256'],'standalone case manifest differs')
    canonical=json.loads(manifest_path.read_text())['native_occurrences']
    require(case in canonical and development_profile(case) == admission['readiness_profile'],
            'canonical case and explicit development profile differ')
    peer = Peer(case, pki, admission['bind_address'], admission['port'],
                admission['expected_source'], timeout=admission['peer_timeout_seconds'])
    try:
        while peer.thread.is_alive():
            peer.thread.join(timeout=0.1)
    finally:
        peer.close()
        seal(args.work/'FIXTURE.json', peer.report())
    return 1 if peer.errors else 0


if __name__ == '__main__':
    sys.exit(main())
