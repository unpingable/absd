#!/usr/bin/env python3
"""Bounded QUIC peers and engine-free native advisory fixtures.

Q15 alone uses a version-pinned frame-writing hook to exercise a zero stream
limit; other protocol peers use the public caller-driven API. Explicit fixture trust, local send,
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
import struct
import sysconfig
import sys
import threading
import time
import traceback


Q05_HOLD_POLICY = 'q05-two-output-hold-v2'
Q05_POST_HANDSHAKE_POLICY = 'q05-post-handshake-two-output-hold-v2'
Q05_POST_ECHO_BYTES = 2048
Q05_HOLD_NS = 500_000_000
Q21_SILENT_POLICY = 'q21-engine-free-silent-v1'
Q22_OUTPUT_POLICY = 'q22-stream-output-fence-v1'
AUTHORITY_POLICIES = {'Q23':'q23-owner-expiry-v1',
                      'Q29':'q29-missing-output-v1', 'Q30':'q30-missing-time-v1', 'Q31':'q31-absent-rdrand-v1'}
Q23_MARKER = b'\x00ABSD-QUIC-Q23-INITIAL-OBSERVED'
Q24_LINK_POLICY = 'q24-link-failure-v1'
ICMP_CASES = {'Q25':576, 'Q26':1227, 'Q27':1200, 'Q28':0}
ICMP_POLICY = 'q25-q26-q28-literal-quote-v1'
Q17_IPV4_POLICY = 'q17-ipv4-denied-destination-v1'


def ipv4_denied(case, family):
    return family == 'ipv4' and case.get('id') == 'Q17'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def icmp_checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack('!'+'H'*(len(data)//2), data))
    while total >> 16:
        total = (total & 65535)+(total >> 16)
    return (~total) & 65535


def icmp_mac(text):
    require(isinstance(text, str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', text),
            'explicit canonical ICMP MAC required')
    value = bytes.fromhex(text.replace(':', ''))
    require(value != b'\0'*6 and not value[0] & 1, 'ICMP MAC must be nonzero unicast')
    return value


def icmp_original(frame, case, guest_mac, peer_mac):
    """Validate actual full Ethernet bytes, never reconstruct a quote from UDP."""
    development_profile(case)
    require(case['id'] in ICMP_CASES and len(frame) == 1242
            and frame[:14] == icmp_mac(peer_mac)+icmp_mac(guest_mac)+b'\x08\x00',
            'ICMP original Ethernet size or identities differ')
    ip = frame[14:]
    require(ip[0] == 0x45 and ip[1] & 3 == 0 and ip[2:4] == b'\x04\xcc'
            and ip[6:8] == b'\x40\x00' and ip[8] > 0 and ip[9] == 17
            and ip[12:20] == socket.inet_aton('10.0.2.15')+socket.inet_aton('10.0.2.2')
            and icmp_checksum(ip[:20]) == 0, 'ICMP original IPv4 header differs')
    sport, dport, length, check = struct.unpack('!HHHH', ip[20:28])
    require((sport, dport, length) == (case['local_port'], 4443, 1208) and check != 0
            and icmp_checksum(ip[12:20]+b'\x00\x11'+struct.pack('!H', length)+ip[20:]) == 0,
            'ICMP original UDP tuple, length or checksum differs')
    return ip[28:]


def icmp_frame(original, case, guest_mac, peer_mac):
    icmp_original(original, case, guest_mac, peer_mac)
    quote = original[14:42]  # Literal original 20-byte IP header plus 8-byte UDP header.
    body = struct.pack('!BBHHH', 3, 4, 0, 0, ICMP_CASES[case['id']])+quote
    body = body[:2]+struct.pack('!H', icmp_checksum(body))+body[4:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 56, 0x5149, 0, 64, 1, 0,
                     socket.inet_aton('10.0.2.2'), socket.inet_aton('10.0.2.15'))
    ip = ip[:10]+struct.pack('!H', icmp_checksum(ip))+ip[12:]
    return icmp_mac(guest_mac)+icmp_mac(peer_mac)+b'\x08\x00'+ip+body


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
                'Q02':('partial-io', 'q02-partial-ipc-development'),
                'Q12':('truncated-header', 'q12-truncated-header-development'),
                'Q13':('invalid-tag', 'q13-invalid-tag-development'),
                'Q14':('long-retry', 'q14-long-retry-development'),
                'Q15':('stream-limit', 'q15-stream-limit-development'),
                'Q16':('unknown-cid', 'q16-unknown-cid-development'),
                'Q17':('denied-destination', 'q17-denied-destination-development'),
                'Q18':('unauthorized-source', 'q18-unauthorized-source-development'),
                'Q03':('initial-loss', 'q03-initial-loss-development'),
                'Q04':('stream-loss', 'q04-stream-loss-development'),
                'Q05':('duplicate-reorder', 'q05-duplicate-reorder-development'),
                'Q06':('flow-pause', 'q06-flow-pause-development'),
                'Q07':('silent', 'q07-silent-development'),
                'Q08':('wrong-root', 'q08-wrong-root-development'),
                'Q09':('wrong-name', 'q09-wrong-name-development'),
                'Q10':('expired-certificate', 'q10-expired-development'),
                'Q11':('wrong-alpn', 'q11-wrong-alpn-development'),
                'Q20':('unknown-send', 'q20-unknown-send-development'),
                'Q21':('silent', 'q21-interrupt-handshake-development'),
                'Q22':('interrupt-stream', 'q22-interrupt-stream-development'),
                'Q23':('owner-expiry', 'q23-owner-expiry-development'),
                'Q24':('link-failure', 'q24-link-failure-development'),
                'Q25':('icmp-576', 'q25-icmp-576-development'),
                'Q26':('icmp-1227', 'q26-icmp-1227-development'),
                'Q27':('icmp-1200', 'q27-icmp-1200-development'),
                'Q28':('icmp-zero', 'q28-icmp-zero-development'),
                'Q29':('missing-output', 'q29-missing-output-development'),
                'Q30':('missing-time', 'q30-missing-time-development'),
                'Q31':('absent-rdrand', 'q31-absent-rdrand-development'),
                'Q19':('queue-exhausted', 'q19-queue-exhausted-development')}
    require(case['id'] in expected and case['peer_mode'] == expected[case['id']][0],
            'only explicit canonical Q01/Q02/Q03/Q04/Q05/Q06/Q07/Q08/Q09/Q10/Q11/Q12/Q14/Q16/Q18/Q19/Q21/Q22/Q23/Q24/Q29/Q30/Q31 development cases are implemented')
    if case['id'] == 'Q17':
        require(type(case.get('local_port')) is int and case['local_port'] == 7816
                and case.get('expected_outcome') == 'Native' and case.get('native_error_codes') == [2]
                and case.get('grant_lifetime_ms') == 15000 and case.get('interrupt_phase') is None
                and case.get('interrupt_delay_ms') == 0 and all(case.get(key) is False for key in
                    ('queue_control', 'suppress_reply', 'missing_output', 'missing_time'))
                and case.get('requires') == ['send_accepted=0', 'no_unauthorized_wire_send', 'authenticated=false'],
                'exact IPv4 denied-destination selector differs')
    if case['id'] in ICMP_CASES:
        require(type(case.get('icmp_mtu')) is int and
                (case.get('local_port'), case.get('icmp_mtu'), case.get('expected_outcome'),
                 case.get('grant_lifetime_ms'), case.get('missing_output'), case.get('missing_time'),
                 case.get('interrupt_phase'), case.get('interrupt_delay_ms'), case.get('queue_control'),
                 case.get('suppress_reply'), case.get('native_error_codes')) ==
                (7799+int(case['id'][1:]), ICMP_CASES[case['id']], 'Native', 15000, False, False,
                 None, 0, False, False, [14] if case['id'] in ('Q27', 'Q28') else [14,15]),
                'exact canonical ICMP profile differs')
    if case['id'] == 'Q24':
        require((case.get('local_port'), case.get('peer_mode'), case.get('expected_outcome'),
                 case.get('grant_lifetime_ms'), case.get('missing_output'), case.get('missing_time'),
                 case.get('interrupt_phase'), case.get('interrupt_delay_ms'), case.get('queue_control'),
                 case.get('suppress_reply'), case.get('native_error_codes')) ==
                (7823, 'link-failure', 'Native', 15000, False, False, None, 0, False, False, [9, 10, 11]),
                'exact canonical Q24 link profile differs')
    if case['id'] in AUTHORITY_POLICIES:
        require((case.get('local_port'), case.get('expected_outcome'),
                 case.get('grant_lifetime_ms'), case.get('missing_output'),
                 case.get('missing_time'), case.get('interrupt_phase'),
                 case.get('interrupt_delay_ms'), case.get('queue_control'),
                 case.get('suppress_reply')) == {
                    'Q23':(7822, 'Native', 3000, False, False, None, 0, False, False),
                    'Q29':(7828, 'Config', 15000, True, False, None, 0, False, False),
                    'Q30':(7829, 'Time', 15000, False, True, None, 0, False, False),
                    'Q31':(7830, 'Entropy', 15000, False, False, None, 0, False, False)}[case['id']],
                'exact canonical authority profile differs')
        require(case['id'] != 'Q31' or case.get('requires') == ['consumer_reached', 'no_SEND'],
                'canonical conditional entropy requirements differ')
        require(case['id'] != 'Q23' or case.get('observation_marker_hex') == Q23_MARKER.hex(),
                'canonical Q23 observation marker differs')
    if case['id'] in ('Q21', 'Q22'):
        require((case.get('local_port'), case.get('interrupt_phase'), case.get('interrupt_delay_ms'),
                 case.get('expected_outcome'), case.get('grant_lifetime_ms')) ==
                {'Q21':(7820, 'Handshake', 1000, 'Interrupted', 15000),
                 'Q22':(7821, 'Stream', 300, 'Interrupted', 15000)}[case['id']],
                'Q21/Q22 exact canonical interruption profile differs')
    require(case['id'] != 'Q16' or case.get('local_port') == 7815, 'Q16 exact local port differs')
    require(case['id'] != 'Q18' or case.get('local_port') == 7817, 'Q18 exact local port differs')
    require(case['id'] != 'Q15' or case.get('local_port') == 7814, 'Q15 exact local port differs')
    require(case['id'] != 'Q07' or case.get('local_port') == 7806, 'Q07 exact local port differs')
    require(case['id'] != 'Q14' or case.get('local_port') == 7813, 'Q14 exact local port differs')
    require(case['id'] != 'Q02' or case.get('local_port') == 7801, 'Q02 exact local port differs')
    require(case['id'] != 'Q04' or case.get('local_port') == 7803, 'Q04 exact local port differs')
    require(case['id'] != 'Q05' or case.get('local_port') == 7804, 'Q05 exact local port differs')
    require(case['id'] != 'Q06' or case.get('local_port') == 7805, 'Q06 exact local port differs')
    require(case['id'] != 'Q12' or case.get('local_port') == 7811, 'Q12 exact local port differs')
    require(case['id'] != 'Q13' or case.get('local_port') == 7812, 'Q13 exact local port differs')
    require(case['id'] != 'Q20' or case.get('local_port') == 7819, 'Q20 exact local port differs')
    return expected[case['id']][1]


def peer_certificate(case):
    development_profile(case)
    return {'Q01':'valid', 'Q12':'valid', 'Q13':'valid', 'Q02':'valid', 'Q03':'valid', 'Q04':'valid', 'Q05':'valid', 'Q06':'valid', 'Q07':'valid', 'Q08':'untrusted', 'Q14':'valid', 'Q15':'valid', 'Q16':'valid', 'Q18':'valid', 'Q09':'wrong-name', 'Q10':'expired', 'Q11':'valid', 'Q19':'valid', 'Q21':'valid', 'Q22':'valid'}[case['id']]


def peer_alpn(case):
    development_profile(case)
    return ['other-echo/1'] if case['id'] == 'Q11' else ['absd-echo/1']


def peer_terminal_codes(case):
    development_profile(case)
    return {'Q01':(0,), 'Q12':(0,), 'Q13':(0,), 'Q02':(0,), 'Q03':(0,), 'Q04':(0,), 'Q05':(0,), 'Q06':(0,), 'Q07':(0,), 'Q14':(0,), 'Q15':(4,), 'Q16':(0,), 'Q18':(0,), 'Q08':(298,304), 'Q09':(298,), 'Q10':(301,), 'Q11':(376,), 'Q19':(0,), 'Q21':(0,), 'Q22':(0,)}[case['id']]


def configuration(pki, client=False, case=None):
    require(case is None or case.get('id') not in ICMP_CASES, 'ICMP fixture cannot construct an engine')
    require(case is None or case.get('id') != 'Q24', 'Q24 cannot construct a peer or Linux client engine')
    from aioquic.quic.configuration import QuicConfiguration
    require(client or case['id'] not in AUTHORITY_POLICIES, 'authority peer cannot construct a server engine or use PKI')
    config = QuicConfiguration(is_client=client, alpn_protocols=['absd-echo/1'] if client else peer_alpn(case),
                               supported_versions=[1], idle_timeout=15.0,
                               max_data=1024 if not client and case['id'] == 'Q06' else 8192,
                               max_stream_data=1024 if not client and case['id'] == 'Q06' else 8192,
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


def load_peer_pki(case, path, family="ipv4"):
    development_profile(case, family)
    if case['id'] in AUTHORITY_POLICIES or case['id'] == 'Q24' or case['id'] in ICMP_CASES or ipv4_denied(case, family):
        return None  # Engine-free peers never read fixture certificates or keys.
    require(path is not None, 'server fixture PKI is required for this profile')
    pki = json.loads(Path(path).read_text())
    validate_pki(pki)
    return pki


def unknown_cid_datagram():
    # A 1-RTT-shaped short header (fixed bit set) to an 8-byte DCID the native
    # client never issued, padded past every header-protection sample.
    return bytes([0x40]) + b'ABSDQ16!' + bytes(range(64))


def truncated_header_datagram():
    # QUICv1 Initial prefix declares 8 DCID bytes, but none are present.
    return bytes.fromhex('c00000000108')


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


def stream_limit_connection(base):
    """Q15-only aioquic 1.6.1 hook; never reads or logs traffic keys.

    The normal engine owns packet numbers, protection, pacing and congestion
    control. This one-shot hook writes the RFC 9000 MAX_STREAM_DATA frame for
    server-initiated stream 1 after the handshake, despite the measured zero
    peer limit. Public send_stream_data correctly cannot create this input.
    """
    class StreamLimitConnection(base):
        q15_frame = None

        def _write_stream_limits(self, builder, space, stream):
            super()._write_stream_limits(builder, space, stream)
            if (self.q15_frame is not None or not self._handshake_complete
                    or not self._handshake_confirmed or stream.stream_id != 0):
                return
            require(self._remote_max_streams_bidi == 0,
                    'NOT_ESTABLISHED: Q15 peer did not advertise zero bidirectional streams')
            # One-byte type, one-byte stream id, two-byte maximum. Capacity
            # seventeen also bounds both possible eight-byte varints.
            frame = builder.start_frame(0x11, capacity=17)
            frame.push_uint_var(1)
            frame.push_uint_var(8192)
            self.q15_frame = {'frame_type':17, 'stream_id':1, 'maximum':8192,
                             'native_peer_bidi_limit':self._remote_max_streams_bidi,
                             'packet_number':builder.packet_number,
                             'handshake_complete':True, 'handshake_confirmed':True}

    return StreamLimitConnection


class Peer:
    def __init__(self, case, pki, bind, port, expected_source, timeout=20, startup_timeout=180, family="ipv4", *, reorder_stage='initial', link_action=None, icmp_interface=None,
                 icmp_guest_mac=None, icmp_peer_mac=None):
        development_profile(case, family)
        require(reorder_stage in ('initial', 'post-handshake') and
                (reorder_stage == 'initial' or case['id'] == 'Q05' and family == 'ipv4'),
                'post-handshake reorder requires the exact Q05 IPv4 case')
        self.reorder_stage, self.reorder_armed = reorder_stage, False
        self.reorder_echo_released = False
        require(callable(link_action) if case['id'] == 'Q24' else link_action is None,
                'Q24 requires a callable link_action; other profiles cannot carry a callback')
        is_icmp = case['id'] in ICMP_CASES
        require(is_icmp or (icmp_interface is icmp_guest_mac is icmp_peer_mac is None),
                'ICMP frame authority is only available to explicit ICMP profiles')
        if is_icmp:
            require(family == 'ipv4' and bind == '10.0.2.2' and port == 4443
                    and tuple(expected_source) == ('10.0.2.15', case['local_port']), 'exact ICMP endpoint differs')
            require(isinstance(icmp_interface, str) and re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', icmp_interface),
                    'explicit ICMP interface required')
            require(icmp_mac(icmp_guest_mac) != icmp_mac(icmp_peer_mac), 'distinct ICMP MACs required')
        self.family = family
        require(0 < timeout <= 30, 'peer deadline bound')
        require(0 < startup_timeout <= 180, 'peer initial-arrival deadline bound')
        self.case, self.pki, self.mode = case, None if case['id'] in AUTHORITY_POLICIES or case['id'] == 'Q24' or is_icmp or ipv4_denied(case, family) else pki, case['peer_mode']
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
        self.stream_drops = 0
        self.tag_batches = self.tag_mutations = 0
        self.reorder_calls = 0
        self.reorder_held = None
        self.reorder_abandoned = False
        self.reorder_batches = 0
        self.reorder_established = False
        self.flow_started_ns = self.flow_until_ns = None
        self.flow_released = False
        self.flow_flushes = 0
        self.queue_fills = 0
        self.response_policy = response_policy(case, family)
        self.one_response_flight = one_response_policy(case, family)
        self.response_flight_sealed = False
        self.initial_sha256 = None
        self.retry_bytes = None
        self.certificate_selection = None
        self.interrupt_stream_fenced = False
        self.interrupt_stream_trigger = None
        self.marker_sent = False
        self.marker_trigger = None
        self.passive_receive_count = 0
        self.icmp_interface, self.icmp_guest_mac, self.icmp_peer_mac = icmp_interface, icmp_guest_mac, icmp_peer_mac
        self.raw_socket = None
        self.raw_socket_closed = True
        self.raw_rx_frames = self.raw_rx_bytes = 0
        self.icmp_guest_frames, self.icmp_socket_rows = [], []
        self.icmp_send_attempted = self.icmp_send_completed = self.icmp_failed = False
        self.icmp_send_result = self.icmp_trigger = None
        self.link_action = link_action
        self.link_action_attempted = False
        self.link_action_result = None
        self.link_trigger = None
        self.socket = socket.socket(socket.AF_INET6 if family == "ipv6" else socket.AF_INET, socket.SOCK_DGRAM)
        if family == "ipv6":
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            if is_icmp:
                self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
                self.raw_socket_closed = False
                self.raw_socket.bind((icmp_interface, 0x0800))
                bound = self.raw_socket.getsockname()
                require(bound[0] == icmp_interface and bytes(bound[4]) == icmp_mac(icmp_peer_mac),
                        'actual ICMP interface MAC differs')
                self.raw_socket.setblocking(False)
            self.socket.bind((bind, port))
            self.socket.setblocking(False)
            self.port = self.socket.getsockname()[1]
            self.thread = threading.Thread(target=self.run, name='quic-peer-' + case['id'])
            self.thread.start()
        except BaseException:
            self.close_icmp_socket()
            self.socket.close()
            raise

    def event(self, event_name, **values):
        with self.lock:
            require(len(self.events) < 4096, 'peer event ceiling')
            self.events.append({'event': event_name, 'time': now(), 'monotonic_ns': time.monotonic_ns(),
                                'wall_time_ns': time.time_ns(), **values})

    def send(self, data, fixture=None):
        require(getattr(self, 'case', {}).get('id') not in ICMP_CASES, 'ICMP fixture cannot send UDP')
        require(getattr(self, 'case', {}).get('id') != 'Q24', 'Q24 engine-free peer cannot send UDP')
        if getattr(self, 'case', {}).get('id') in AUTHORITY_POLICIES or ipv4_denied(getattr(self, 'case', {}), getattr(self, 'family', None)):
            self.send_authority_marker(data, fixture)
            return
        require(getattr(self, 'case', {}).get('id') != 'Q21', 'Q21 silent peer cannot send UDP')
        require(not (getattr(self, 'mode', None) == 'interrupt-stream'
                     and getattr(self, 'interrupt_stream_fenced', False)),
                'Q22 stream output is fenced; no later UDP send')
        require(not self.one_response_flight or not self.response_flight_sealed,
                'selected authentication response flight is fenced; no later UDP send')
        require(0 < len(data) <= 1200, 'peer datagram size ceiling')
        require(self.tx_packets < 512 and self.tx_bytes + len(data) <= 512 * 1200, 'peer transmit bound')
        if fixture is not None:
            limits = [row for row in self.events if row['event'] == 'stream-limit-frame-built']
            require((fixture == 'truncated-header' and self.case['id'] == 'Q12'
                     and self.mode == 'truncated-header' and data == truncated_header_datagram())
                    or (fixture == 'long-retry' and self.case['id'] == 'Q14' and self.mode == 'long-retry'
                        and self.tx_packets == 0 and data == getattr(self, 'retry_bytes', None))
                    or (fixture == 'unknown-cid' and self.case['id'] == 'Q16' and self.mode == 'unknown-cid'
                        and data == unknown_cid_datagram() and not getattr(self, 'unknown_cid_sent', False))
                    or (fixture == 'stream-limit' and self.case['id'] == 'Q15' and self.mode == 'stream-limit'
                        and len(limits) == 1 and limits[0]['sha256'] == digest(data)
                        and limits[0]['bytes'] == len(data)
                        and limits[0]['send_ordinal_next'] == self.tx_packets + 1),
                    'fixture tag requires its exact selected case, bytes and one-shot send boundary')
        require(getattr(self, 'mode', None) != 'flow-pause' or self.flow_until_ns is None,
                'Q06 output cannot bypass the active credit hold')
        count = self.socket.sendto(data, self.expected_source)
        require(count == len(data), 'partial Linux UDP send')
        self.tx_packets += 1
        self.tx_bytes += count
        self.event('udp-send', bytes=count, sha256=digest(data), source=list(self.socket.getsockname()[:2]),
                   destination=list(self.expected_source),
                   **({'send_ordinal':self.tx_packets} if getattr(self, 'mode', None) in ('duplicate-reorder', 'invalid-tag') else {}),
                   **({'fixture':fixture} if fixture is not None else {}))

    def authority_guard(self):
        development_profile(self.case, self.family)
        require((self.case['id'] in AUTHORITY_POLICIES or ipv4_denied(self.case, self.family)) and self.family == 'ipv4'
                and self.connection is None and self.pki is None
                and not self.authenticated and not self.received and self.echoed == 0
                and not self.request_fin and not self.echo_fin and self.certificate_selection is None,
                'authority peer must remain engine-free, PKI-free and application-free')
        require(self.tx_packets <= (1 if self.case['id'] == 'Q23' else 0),
                'authority peer output ceiling')

    def authority_event_space(self):
        # This private loop is the sole event writer. Reserve enough space for
        # its entire receive -> marker-send transition and terminal/error event
        # BEFORE either socket operation; exhaustion never consumes hidden I/O.
        with self.lock:
            require(len(self.events) + 8 <= 4096, 'authority peer event ceiling before I/O')

    def send_authority_marker(self, data, fixture):
        self.authority_guard()
        require(self.case['id'] == 'Q23' and fixture == 'owner-expiry-marker'
                and data == Q23_MARKER and not self.marker_sent and self.tx_packets == 0
                and self.marker_trigger is not None and self.rx_packets >= 1
                and self.initial_sha256 == self.marker_trigger['sha256']
                and self.marker_trigger['receive_ordinal'] == self.rx_packets,
                'only one canonical Q23 marker after its real Initial receipt may be sent')
        self.authority_event_space()
        count = self.socket.sendto(data, self.expected_source)
        # Record the actual local result before refusing a short send.
        self.tx_packets += 1
        self.tx_bytes += count
        self.event('udp-send', bytes=count, sha256=digest(data[:count]), data_hex=data[:count].hex(),
                   source=list(self.socket.getsockname()[:2]), destination=list(self.expected_source),
                   send_ordinal=self.tx_packets, fixture=fixture)
        self.marker_sent = True
        require(count == len(data), 'partial Q23 marker UDP send')
        self.event('expiry-observation-marker', initial_sha256=self.initial_sha256,
                   case_port=self.case['local_port'], marker_sha256=digest(data),
                   marker_hex=data.hex(), send_ordinal=self.tx_packets,
                   destination=list(self.expected_source))

    def record_owner_initial(self, data):
        """Public header validation, not decryption/authentication of the Initial."""
        self.authority_guard()
        require(self.case['id'] == 'Q23' and self.rx_packets >= 1
                and len(data) == 1200 and data[0] & 0xf0 == 0xc0,
                'Q23 requires an exact 1200-byte QUICv1 Initial')
        from aioquic.buffer import Buffer
        from aioquic.quic.packet import pull_quic_header, QuicPacketType
        header = pull_quic_header(Buffer(data=data), host_cid_length=8)
        require(header.packet_type == QuicPacketType.INITIAL and header.version == 1,
                'Q23 requires an exact 1200-byte QUICv1 Initial')
        if self.initial_sha256 is None:
            self.initial_sha256 = digest(data)
            self.marker_trigger = {'receive_ordinal':self.rx_packets, 'bytes':len(data),
                'sha256':digest(data), 'marker_hex':Q23_MARKER.hex(),
                'marker_sha256':digest(Q23_MARKER), 'destination':list(self.expected_source)}
            self.event('initial-observed', receive_ordinal=self.rx_packets,
                       bytes=len(data), sha256=digest(data))
        self.event('owner-expiry-input', receive_ordinal=self.rx_packets,
                   bytes=len(data), sha256=digest(data), engine_delivered=False,
                   dcid_hex=bytes(header.destination_cid).hex(), scid_hex=bytes(header.source_cid).hex(),
                   token_bytes=len(header.token))
        if not self.marker_sent:
            self.send(Q23_MARKER, fixture='owner-expiry-marker')

    def receive_authority(self):
        self.authority_guard()
        self.authority_event_space()
        require(self.rx_packets < 512 and self.rx_bytes < 512 * 1200,
                'authority peer receive ceiling before I/O')
        data, source = self.socket.recvfrom(65536)
        source = source[:2]
        current = time.monotonic()
        if not self.started_io:
            self.started_io = True
            self.deadline = min(self.deadline, current + self.operation_timeout)
        self.rx_packets += 1
        self.rx_bytes += len(data)
        self.event('udp-receive', receive_ordinal=self.rx_packets, bytes=len(data),
                   sha256=digest(data), data_hex=data.hex(), source=list(source),
                   destination=list(self.socket.getsockname()[:2]))
        require(source == self.expected_source, 'unexpected source sent to owned authority fixture')
        require(0 < len(data) <= 1200 and self.rx_bytes <= 512 * 1200,
                'authority peer datagram/byte ceiling')
        if self.case['id'] == 'Q23':
            self.record_owner_initial(data)
        else:
            self.passive_receive_count += 1
            self.event('passive-input', receive_ordinal=self.rx_packets, bytes=len(data),
                       sha256=digest(data), engine_delivered=False)
            raise RuntimeError('Q17 passive fixture unexpectedly received UDP' if ipv4_denied(self.case, self.family)
                               else 'Q29/Q30/Q31 passive fixture unexpectedly received UDP')

    def run_authority(self):
        try:
            self.authority_guard()
            while not self.stop.is_set() and time.monotonic() < self.deadline:
                self.drive_timer(time.monotonic())
                if select.select([self.socket], [], [], 0.01)[0]:
                    self.receive_authority()
        except BaseException as error:
            self.errors.append({'type':type(error).__name__, 'message':str(error),
                                'traceback':traceback.format_exc()})
        finally:
            self.event('peer-ended', stopped=self.stop.is_set(),
                       deadline_reached=time.monotonic() >= self.deadline)

    def link_guard(self):
        development_profile(self.case, self.family)
        require(self.case['id'] == 'Q24' and self.family == 'ipv4' and callable(self.link_action)
                and self.connection is None and self.pki is None and self.tx_packets == self.tx_bytes == 0
                and not self.authenticated and not self.received and self.echoed == 0
                and not self.request_fin and not self.echo_fin and self.certificate_selection is None,
                'Q24 must remain callback-bound, engine-free, PKI-free and output-free')

    def link_event_space(self, slots=8):
        # Sole-writer loop reserves its complete receive/parse/callback/error
        # transition before consuming a socket datagram or invoking the callback.
        with self.lock:
            require(len(self.events) + slots <= 4096, 'Q24 event ceiling before I/O or callback')

    def perform_link_action(self):
        self.link_guard()
        require(not self.link_action_attempted and self.link_action_result is None
                and self.link_trigger is not None and self.rx_packets >= 1
                and self.initial_sha256 == self.link_trigger['sha256']
                and self.link_trigger['receive_ordinal'] == self.rx_packets
                and self.link_trigger['bytes'] == 1200,
                'Q24 link action requires its first parsed Initial and may be attempted only once')
        self.link_event_space(slots=3)
        # Sticky before invocation: a failed or ambiguous callback is never retried.
        self.link_action_attempted = True
        self.event('link-action-begin', trigger_receive_ordinal=self.link_trigger['receive_ordinal'],
                   trigger_sha256=self.link_trigger['sha256'])
        try:
            result = self.link_action()
            require(isinstance(result, dict) and result.get('qmp_acknowledged') is True
                    and isinstance(result.get('qmp_receipt'), str) and 0 < len(result['qmp_receipt']) <= 4096
                    and isinstance(result.get('qmp_receipt_sha256'), str)
                    and re.fullmatch(r'[0-9a-f]{64}', result['qmp_receipt_sha256']) is not None
                    and type(result.get('exact_qemu_pid')) is int and result['exact_qemu_pid'] > 0
                    and result.get('device_id') == 'quicnic',
                    'Q24 callback did not return an exact acknowledged QMP receipt binding')
            self.link_action_result = {key:result[key] for key in (
                'qmp_acknowledged', 'qmp_receipt', 'qmp_receipt_sha256', 'exact_qemu_pid', 'device_id')}
            self.event('link-action', **self.link_action_result,
                       trigger_receive_ordinal=self.link_trigger['receive_ordinal'],
                       trigger_sha256=self.link_trigger['sha256'])
        except BaseException as error:
            self.event('link-action-failed', error_type=type(error).__name__, message=str(error)[:1024],
                       trigger_receive_ordinal=self.link_trigger['receive_ordinal'],
                       trigger_sha256=self.link_trigger['sha256'])
            raise

    def receive_link(self):
        self.link_guard()
        self.link_event_space()
        require(self.rx_packets < 512 and self.rx_bytes < 512 * 1200,
                'Q24 receive ceiling before I/O')
        data, source = self.socket.recvfrom(65536)
        source = source[:2]
        current = time.monotonic()
        if not self.started_io:
            self.started_io = True
            self.deadline = min(self.deadline, current + self.operation_timeout)
        self.rx_packets += 1
        self.rx_bytes += len(data)
        self.event('udp-receive', receive_ordinal=self.rx_packets, bytes=len(data), sha256=digest(data),
                   data_hex=data.hex(), source=list(source), destination=list(self.socket.getsockname()[:2]),
                   engine_delivered=False)
        require(source == self.expected_source, 'unexpected source sent to owned Q24 fixture')
        require(len(data) == 1200 and self.rx_bytes <= 512 * 1200 and data[0] & 0xf0 == 0xc0,
                'Q24 requires an exact 1200-byte QUICv1 Initial')
        from aioquic.buffer import Buffer
        from aioquic.quic.packet import pull_quic_header, QuicPacketType
        header = pull_quic_header(Buffer(data=data), host_cid_length=8)
        require(header.packet_type == QuicPacketType.INITIAL and header.version == 1,
                'Q24 requires an exact 1200-byte QUICv1 Initial')
        first = self.initial_sha256 is None
        if first:
            self.initial_sha256 = digest(data)
            self.link_trigger = {'receive_ordinal':self.rx_packets, 'bytes':len(data), 'sha256':digest(data),
                                 'source':list(source), 'destination':list(self.socket.getsockname()[:2])}
            self.event('initial-observed', receive_ordinal=self.rx_packets, bytes=len(data), sha256=digest(data))
        self.event('link-failure-input', receive_ordinal=self.rx_packets, bytes=len(data), sha256=digest(data),
                   engine_delivered=False, dcid_hex=bytes(header.destination_cid).hex(),
                   scid_hex=bytes(header.source_cid).hex(), token_bytes=len(header.token))
        if first:
            self.perform_link_action()

    def run_link(self):
        try:
            self.link_guard()
            while not self.stop.is_set() and time.monotonic() < self.deadline:
                self.drive_timer(time.monotonic())
                if select.select([self.socket], [], [], 0.01)[0]:
                    self.receive_link()
        except BaseException as error:
            self.errors.append({'type':type(error).__name__, 'message':str(error),
                                'traceback':traceback.format_exc()})
        finally:
            self.event('peer-ended', stopped=self.stop.is_set(),
                       deadline_reached=time.monotonic() >= self.deadline)

    def icmp_guard(self):
        development_profile(self.case, self.family)
        require(self.case['id'] in ICMP_CASES and self.family == 'ipv4'
                and self.connection is None and self.pki is None and self.certificate_selection is None
                and self.tx_packets == self.tx_bytes == 0 and not self.authenticated
                and not self.received and not self.request_fin and self.echoed == 0 and not self.echo_fin,
                'ICMP fixture must remain engine-free, PKI-free and UDP-output-free')

    def icmp_event_space(self, slots=8):
        with self.lock:
            require(len(self.events)+slots <= 4096, 'ICMP event ceiling before I/O')

    def close_icmp_socket(self):
        raw = getattr(self, 'raw_socket', None)
        if raw is not None:
            raw.close()
            self.raw_socket = None
        self.raw_socket_closed = True

    def receive_icmp_udp(self, emit=True):
        self.icmp_guard()
        self.icmp_event_space()
        require(self.rx_packets < 256, 'ICMP UDP receive ceiling before I/O')
        data, source = self.socket.recvfrom(65536)
        source = source[:2]
        current = time.monotonic()
        if not self.started_io:
            self.started_io = True
            self.deadline = min(self.deadline, current+self.operation_timeout)
        self.rx_packets += 1
        self.rx_bytes += len(data)
        row = dict(receive_ordinal=self.rx_packets, bytes=len(data), sha256=digest(data),
                   data_hex=data.hex(), source=list(source), destination=list(self.socket.getsockname()[:2]))
        self.event('udp-receive', **row, engine_delivered=False)
        require(source == self.expected_source and len(data) == 1200 and data[0] & 0xf0 == 0xc0,
                'ICMP requires exact source and 1200-byte QUICv1 Initial')
        from aioquic.buffer import Buffer
        from aioquic.quic.packet import pull_quic_header, QuicPacketType
        header = pull_quic_header(Buffer(data=data), host_cid_length=8)
        require(header.packet_type == QuicPacketType.INITIAL and header.version == 1,
                'ICMP public parser did not observe a QUICv1 Initial')
        self.icmp_socket_rows.append(row)
        if self.initial_sha256 is None:
            self.initial_sha256 = row['sha256']
            self.event('initial-observed', **row)
        self.event('icmp-input', **row, engine_delivered=False)
        if emit:
            self.try_icmp_send()

    def receive_icmp_frame(self, emit=True):
        self.icmp_guard()
        self.icmp_event_space()
        require(self.raw_rx_frames < 512, 'ICMP raw receive ceiling before I/O')
        frame, address = self.raw_socket.recvfrom(65536)
        self.raw_rx_frames += 1
        self.raw_rx_bytes += len(frame)
        row = dict(raw_frame_ordinal=self.raw_rx_frames, bytes=len(frame), sha256=digest(frame),
                   frame_hex=frame.hex(), interface=address[0], packet_type=address[2])
        self.event('icmp-frame-receive', **row)
        require(address[0] == self.icmp_interface, 'ICMP raw frame arrived on another interface')
        if frame[:6] == icmp_mac(self.icmp_guest_mac):
            # Some packet-socket configurations observe the local outgoing copy.
            require(self.icmp_send_result is not None and frame.hex() == self.icmp_send_result['frame_hex'],
                    'ICMP raw peer frame is not the exact emitted local copy')
        else:
            data = icmp_original(frame, self.case, self.icmp_guest_mac, self.icmp_peer_mac)
            self.icmp_guest_frames.append(dict(row, data_hex=data.hex(), data_sha256=digest(data), quote_hex=frame[14:42].hex()))
        if emit:
            self.try_icmp_send()

    def try_icmp_send(self):
        try:
            return self._try_icmp_send()
        except BaseException:
            self.icmp_failed = True
            raise

    def _try_icmp_send(self):
        self.icmp_guard()
        require(not self.icmp_failed, 'ICMP output is permanently refused after failure')
        if self.icmp_send_attempted or not self.icmp_guest_frames or not self.icmp_socket_rows:
            return
        self.icmp_event_space()
        require(not self.stop.is_set() and self.raw_socket is not None
                and time.monotonic() < self.deadline, 'ICMP output after stop or deadline')
        raw, received = self.icmp_guest_frames[0], self.icmp_socket_rows[0]
        require(raw['data_hex'] == received['data_hex'] and raw['data_sha256'] == received['sha256'],
                'ICMP first raw frame and actual socket Initial differ')
        original = bytes.fromhex(raw['frame_hex'])
        frame = icmp_frame(original, self.case, self.icmp_guest_mac, self.icmp_peer_mac)
        self.icmp_trigger = dict(received, raw_frame_ordinal=raw['raw_frame_ordinal'],
            submitted_frame_sha256=raw['sha256'], frame_hex=raw['frame_hex'], quote_hex=raw['quote_hex'])
        result = dict(bytes=len(frame), sha256=digest(frame), frame_hex=frame.hex(),
            icmp_hex=frame[34:].hex(), mtu=ICMP_CASES[self.case['id']], quote_hex=raw['quote_hex'],
            submitted_frame_sha256=raw['sha256'], trigger_receive_ordinal=received['receive_ordinal'],
            trigger_raw_frame_ordinal=raw['raw_frame_ordinal'], trigger_sha256=received['sha256'])
        # Set before the actual send: partial return or ambiguous error cannot retry.
        self.icmp_send_attempted = True
        self.event('icmp-send-begin', **result)
        try:
            require(not self.stop.is_set() and time.monotonic() < self.deadline,
                    'ICMP deadline before raw send')
            count = self.raw_socket.send(frame)
            require(count == len(frame), 'partial ICMP raw frame send')
            self.icmp_send_result = dict(result, actual_sent_bytes=count)
            self.icmp_send_completed = True
            self.event('icmp-send', **self.icmp_send_result)
            require(not self.stop.is_set() and time.monotonic() < self.deadline,
                    'ICMP deadline or stop after raw send; actual effect retained')
        except BaseException as error:
            self.icmp_failed = True
            self.event('icmp-send-failed', error_type=type(error).__name__, message=str(error)[:1024])
            raise

    def run_icmp(self):
        try:
            self.icmp_guard()
            while not self.stop.is_set() and time.monotonic() < self.deadline:
                ready = select.select([self.raw_socket, self.socket], [], [], 0.01)[0]
                for sock in ready:
                    if sock is self.raw_socket:
                        self.receive_icmp_frame()
                    else:
                        self.receive_icmp_udp()
        except BaseException as error:
            self.icmp_failed = True
            self.errors.append({'type':type(error).__name__, 'message':str(error), 'traceback':traceback.format_exc()})
        finally:
            try:
                # Observe already queued input without any emission after stop/error.
                for _ in range(512):
                    ready = select.select([self.raw_socket, self.socket], [], [], 0)[0]
                    if not ready:
                        break
                    for sock in ready:
                        if sock is self.raw_socket:
                            self.receive_icmp_frame(emit=False)
                        else:
                            self.receive_icmp_udp(emit=False)
                else:
                    raise RuntimeError('ICMP cleanup receive bound')
            except BaseException as error:
                self.icmp_failed = True
                self.errors.append({'type':type(error).__name__, 'message':str(error)})
            finally:
                self.close_icmp_socket()
                self.event('peer-ended', stopped=self.stop.is_set(), deadline_reached=time.monotonic() >= self.deadline)

    def send_truncated_header(self):
        require(self.case['id'] == 'Q12' and self.mode == 'truncated-header' and self.family == 'ipv4'
                and self.connection is not None and self.initial_sha256 is not None and self.tx_packets == 0,
                'Q12 injection must be the first peer send after an accepted Initial')
        self.send(truncated_header_datagram(), fixture='truncated-header')

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

    def drop_stream_datagram(self, data):
        """Select one post-handshake short datagram; native proof is separate."""
        if self.mode != 'stream-loss' or self.stream_drops or not self.authenticated:
            return False
        require(0 < len(data) <= 1200, 'Q04 datagram size differs')
        if data[0] & 0xc0 != 0x40:
            return False
        if self.request_fin or len(self.received) == 4096:
            return False
        require(self.connection is not None and self.rx_packets > 1,
                'Q04 omission precedes real handshake/Initial delivery')
        self.stream_drops = 1
        self.event('stream-datagram-drop', bytes=len(data), sha256=digest(data),
                   receive_ordinal=self.rx_packets, first_byte=data[0],
                   authenticated_before=True, request_bytes_before=len(self.received),
                   request_fin_before=self.request_fin, engine_delivered=False,
                   frame_proof='requires-native-public-counter')
        return True

    def deliver_datagram(self, data, source, current):
        require(getattr(self, 'case', {}).get('id') not in ICMP_CASES, 'ICMP input cannot reach an engine')
        require(getattr(self, 'case', {}).get('id') != 'Q24',
                'Q24 never delivers socket input to an engine')
        require(not (self.mode == 'interrupt-stream' and self.interrupt_stream_fenced),
                'Q22 engine input is fenced; retain later socket input only')
        if self.drop_stream_datagram(data):
            return False
        self.connection.receive_datagram(data, source, now=current)
        if self.mode in ('stream-loss', 'interrupt-stream'):
            self.event('engine-delivered', bytes=len(data), sha256=digest(data),
                       receive_ordinal=self.rx_packets, source=list(source))
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

    def accept_unknown_initial(self, data):
        """Retain one parsed Initial without constructing a peer connection.

        The native service loses only the SEND completion reply. No peer reply
        or timer is needed to observe the already possible datagram effect.
        A second datagram is a failed fixture, including an identical retry.
        """
        if self.case['id'] != 'Q20':
            return False
        require(self.connection is None and self.initial_sha256 is None
                and self.rx_packets == 1 and len(data) == 1200
                and data[0] & 0xf0 == 0xc0 and data[1:5] == b'\0\0\0\1',
                'Q20 requires exactly one Initial before peer engine construction')
        self.initial_sha256 = digest(data)
        self.event('initial-observed', bytes=len(data), sha256=self.initial_sha256,
                   receive_ordinal=self.rx_packets, quic_version=1, engine_delivered=False)
        self.event('q20-initial-sink', policy='q20-one-initial-sink-v1',
                   bytes=len(data), sha256=self.initial_sha256, engine_constructed=False,
                   response_datagrams=0)
        return True

    def run(self):
        if self.case['id'] in ICMP_CASES:
            self.run_icmp()
            return
        if self.case['id'] == 'Q24':
            self.run_link()
            return
        if self.case['id'] in AUTHORITY_POLICIES or ipv4_denied(self.case, self.family):
            self.run_authority()
            return
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
                self.event('udp-receive', bytes=len(data), sha256=digest(data), source=list(source),
                           **({'receive_ordinal':self.rx_packets, 'first_byte':data[0] if data else None}
                              if self.mode in ('stream-loss', 'interrupt-stream') else {}))
                require(source == self.expected_source, 'unexpected source sent to owned fixture')
                require(0 < len(data) <= 1200, 'oversized client datagram')
                require(not (self.family == 'ipv6' and self.case['id'] == 'Q17'),
                        'denied native destination unexpectedly emitted UDP')
                if self.mode in ('silent', 'long-retry'):
                    # Q07/Q21/Q14: record every Initial; never construct an engine.
                    # Q14 answers the first one with exactly one overlong-SCID Retry.
                    header = pull_quic_header(Buffer(data=data), host_cid_length=8)
                    self.record_silent(data, header.packet_type == QuicPacketType.INITIAL and header.version == 1,
                                       header.destination_cid, header.source_cid, header.token)
                    if self.mode == 'long-retry' and self.tx_packets == 0:
                        self.send_long_retry(header.destination_cid, header.source_cid)
                    continue
                if self.mode == 'interrupt-stream' and self.interrupt_stream_fenced:
                    self.event('q22-after-fence-input', receive_ordinal=self.rx_packets,
                               bytes=len(data), sha256=digest(data), source=list(source),
                               engine_delivered=False)
                    continue
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
                    if self.accept_unknown_initial(data):
                        continue
                    self.initial_sha256 = digest(data)
                    self.certificate_selection = {'kind':peer_certificate(self.case),
                        'sha256':self.pki['leaf_certificates'][peer_certificate(self.case)]['sha256'],
                        'client_root_sha256':self.pki['root_der']['sha256'],
                        'configured_alpn':peer_alpn(self.case)}
                    self.event('certificate-selection', **self.certificate_selection)
                    config = configuration(self.pki, case=self.case)
                    if self.mode == 'flow-pause':
                        self.event('q06-configuration', max_data=config.max_data,
                                   max_stream_data=config.max_stream_data,
                                   hold_ns=250_000_000)
                    connection_type = stream_limit_connection(QuicConnection) if self.mode == 'stream-limit' else QuicConnection
                    self.connection = connection_type(configuration=config,
                        original_destination_connection_id=header.destination_cid)
                    self.event('initial-observed', bytes=len(data), sha256=digest(data),
                               receive_ordinal=self.rx_packets)
                    if self.mode == 'truncated-header':
                        self.send_truncated_header()
                if not self.deliver_datagram(data, source, current):
                    continue
                for _ in range(32):
                    event = self.connection.next_event()
                    if event is None:
                        break
                    if isinstance(event, events.HandshakeCompleted):
                        require(not self.authenticated and event.alpn_protocol == 'absd-echo/1'
                                and not event.early_data_accepted and not event.session_resumed,
                                'peer negotiated outside tranche')
                        self.authenticated = True
                        self.event('handshake', alpn=event.alpn_protocol, early_data=False, resumed=False,
                                   **({'receive_ordinal':self.rx_packets}
                                      if self.mode in ('stream-loss', 'interrupt-stream') else {}))
                    elif isinstance(event, events.StreamDataReceived):
                        require(self.authenticated and event.stream_id == 0 and not self.request_fin,
                                'unexpected peer stream or data after FIN')
                        require(len(self.received) + len(event.data) <= 4096, 'request byte ceiling')
                        self.received.extend(event.data)
                        require(bytes(self.received) == pattern(len(self.received)), 'request bytes differ from independent pattern')
                        self.request_fin = event.end_stream
                        self.event('request-stream', stream_id=0, bytes=len(event.data),
                                   offset=len(self.received) - len(event.data), fin=event.end_stream,
                                   **({'receive_ordinal':self.rx_packets} if self.mode == 'interrupt-stream' else {}))
                        if self.fence_interrupt_stream(data):
                            # Do not poll another queued engine event after the
                            # first real request prefix. Later socket input is
                            # retained above without further engine delivery.
                            break
                        self.flow_progress()
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
            if self.mode == 'duplicate-reorder' and self.reorder_held is not None:
                self.clear_reorder_hold('peer-ended')
            self.event('peer-ended', stopped=self.stop.is_set(), deadline_reached=time.monotonic() >= self.deadline)

    def record_silent(self, data, initial_v1, dcid=b'', scid=b'', token=b''):
        """Q07/Q21/Q14: header-validated Initial receipt; no engine or decryption claim."""
        if self.case['id'] == 'Q21':
            development_profile(self.case, self.family)
        require(((self.case['id'] in ('Q07', 'Q21') and self.mode == 'silent' and self.tx_packets == 0)
                 or (self.case['id'] == 'Q14' and self.mode == 'long-retry'
                     and self.tx_packets == (0 if self.initial_sha256 is None else 1)))
                and self.connection is None, 'Q07 silent receipt requires the selected engine-free peer')
        # RFC 9000 14.1 sets the 1200-byte Initial minimum and this fixture's
        # datagram ceiling is 1200, so exactly 1200 is the only admissible size.
        require(initial_v1 and len(data) == 1200, 'Q07 silent peer received a non-Initial datagram')
        if self.initial_sha256 is None:
            self.initial_sha256 = digest(data)
            self.event('initial-observed', bytes=len(data), sha256=digest(data), receive_ordinal=self.rx_packets)
        self.event('silent-input', receive_ordinal=self.rx_packets, bytes=len(data),
                   sha256=digest(data), engine_delivered=False, dcid_hex=bytes(dcid).hex(),
                   scid_hex=bytes(scid).hex(), token_bytes=len(token))

    def fence_interrupt_stream(self, data):
        """Q22: retain one real authenticated prefix, then stop all engine work/output."""
        if self.mode != 'interrupt-stream':
            return False
        development_profile(self.case, self.family)
        require(self.case['id'] == 'Q22' and self.family == 'ipv4'
                and self.connection is not None and self.authenticated
                and self.initial_sha256 is not None and self.rx_packets > 1
                and 0 < len(data) <= 1200 and 0 < len(self.received) <= 4096
                and bytes(self.received) == pattern(len(self.received))
                and self.echoed == 0 and not self.echo_fin,
                'NOT_ESTABLISHED: Q22 authenticated request prefix or zero-echo boundary absent')
        if not self.interrupt_stream_fenced:
            self.interrupt_stream_fenced = True
            self.interrupt_stream_trigger = {
                'receive_ordinal':self.rx_packets, 'bytes':len(data), 'sha256':digest(data),
                'request_bytes':len(self.received), 'request_sha256':digest(self.received),
                'request_fin':self.request_fin, 'authenticated_before':self.authenticated,
                'tx_datagrams':self.tx_packets, 'tx_bytes':self.tx_bytes}
            self.event('q22-stream-output-fenced', policy=Q22_OUTPUT_POLICY,
                       **self.interrupt_stream_trigger, later_engine_work=False, later_send=False)
        return True

    def send_long_retry(self, original_dcid, client_scid):
        """Q14: one Retry whose 21-byte SCID exceeds the 20-byte CID limit, with a valid tag."""
        from aioquic.quic.packet import encode_quic_retry, get_retry_integrity_tag
        require(self.case['id'] == 'Q14' and self.mode == 'long-retry' and self.tx_packets == 0
                and self.retry_bytes is None, 'one Q14 Retry only')
        retry_scid = bytes(range(0xa0, 0xa0 + 21))
        data = encode_quic_retry(1, retry_scid, client_scid, original_dcid, b'absd-q14-retry-token')
        verified = get_retry_integrity_tag(data[:-16], original_dcid, 1) == data[-16:]
        require(verified and len(retry_scid) == 21, 'Q14 Retry integrity or SCID construction differs')
        self.retry_bytes = data
        self.event('retry-fixture', source_cid_bytes=len(retry_scid), integrity_verified=verified,
                   bytes=len(data), sha256=digest(data), data_hex=data.hex(),
                   original_destination_cid_hex=bytes(original_dcid).hex(),
                   destination_cid_hex=bytes(client_scid).hex(), source_cid_hex=retry_scid.hex())
        self.send(data, fixture='long-retry')

    def flow_progress(self):
        if getattr(self, 'mode', None) != 'flow-pause' or self.flow_released:
            return
        if self.flow_started_ns is not None:
            require(512 < len(self.received) <= 1024 and not self.request_fin,
                    'NOT_ESTABLISHED: Q06 progress exceeded initial credit during hold')
            return
        if len(self.received) > 512:
            require(len(self.received) <= 1024 and not self.request_fin,
                    'NOT_ESTABLISHED: Q06 exact initial-credit boundary absent')
            self.flow_started_ns = time.monotonic_ns()
            self.flow_until_ns = self.flow_started_ns + 250_000_000
            self.event('q06-pause-start', request_bytes=len(self.received), request_fin=self.request_fin,
                       started_ns=self.flow_started_ns, until_ns=self.flow_until_ns,
                       tx_datagrams=self.tx_packets, tx_bytes=self.tx_bytes,
                       public_flushes=self.flow_flushes)

    def flow_may_flush(self):
        if getattr(self, 'mode', None) != 'flow-pause':
            return True
        if self.flow_until_ns is not None:
            require(512 < len(self.received) <= 1024 and not self.request_fin,
                    'NOT_ESTABLISHED: Q06 initial-credit plateau changed')
            current = time.monotonic_ns()
            if current < self.flow_until_ns:
                return False
            require(len(self.received) == 1024,
                    'NOT_ESTABLISHED: Q06 initial credit not reached before release')
            require(current - self.flow_started_ns <= 1_000_000_000,
                    'NOT_ESTABLISHED: Q06 bounded release observation missed')
            self.event('q06-pause-release', request_bytes=len(self.received), request_fin=self.request_fin,
                       started_ns=self.flow_started_ns, released_ns=current,
                       tx_datagrams=self.tx_packets, tx_bytes=self.tx_bytes,
                       public_flushes=self.flow_flushes)
            self.flow_until_ns = None
            self.flow_released = True
        require(self.flow_released or len(self.received) <= 512,
                'NOT_ESTABLISHED: Q06 early output construction could raise initial credit')
        self.flow_flushes += 1
        self.event('q06-public-flush', ordinal=self.flow_flushes, request_bytes=len(self.received),
                   released=self.flow_released)
        return True

    def echo(self):
        if getattr(self, 'mode', None) == 'interrupt-stream':
            require(self.interrupt_stream_fenced, 'Q22 must fence before echo enqueue')
            return
        if getattr(self, 'mode', None) == 'stream-limit':
            # Preserve the request observation, but do not let an ordinary
            # complete echo substitute for the selected refusal fixture.
            return
        if (self.mode == 'duplicate-reorder' and getattr(self, 'reorder_stage', 'initial') == 'post-handshake'
                and not getattr(self, 'reorder_echo_released', False)):
            require(self.echoed == 0, 'Q05 initial echo bypassed its preparation gate')
            if len(self.received) < Q05_POST_ECHO_BYTES:
                return
            self.reorder_echo_released = True
            self.event('q05-post-echo-release', policy=self.reorder_policy(),
                       required_request_bytes=Q05_POST_ECHO_BYTES,
                       request_bytes=len(self.received), echo_enqueued_before=0)
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
        if getattr(self, 'case', {}).get('id') in ICMP_CASES:
            self.icmp_guard()
            return
        if getattr(self, 'case', {}).get('id') == 'Q24':
            self.link_guard()
            return
        if getattr(self, 'case', {}).get('id') in AUTHORITY_POLICIES or ipv4_denied(getattr(self, 'case', {}), getattr(self, 'family', None)):
            self.authority_guard()
            return
        if (self.connection is None or (self.one_response_flight and self.response_flight_sealed)
                or (getattr(self, 'mode', None) == 'interrupt-stream' and self.interrupt_stream_fenced)):
            return
        if getattr(self, 'mode', None) == 'duplicate-reorder':
            self.check_reorder_deadline()
        due = self.connection.get_timer()
        if due is not None and due <= current:
            self.connection.handle_timer(now=current)
        self.flush()

    def flush(self):
        if getattr(self, 'case', {}).get('id') in ICMP_CASES:
            self.icmp_guard()
            return
        if getattr(self, 'case', {}).get('id') == 'Q24':
            self.link_guard()
            return
        if getattr(self, 'case', {}).get('id') in AUTHORITY_POLICIES or ipv4_denied(getattr(self, 'case', {}), getattr(self, 'family', None)):
            self.authority_guard()
            return
        if getattr(self, 'case', {}).get('id') == 'Q21':
            require(self.connection is None and self.tx_packets == 0, 'Q21 silent peer constructed an engine or sent')
            return
        if getattr(self, 'mode', None) == 'interrupt-stream' and self.interrupt_stream_fenced:
            return
        if not self.flow_may_flush():
            return
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
        if getattr(self, 'mode', None) == 'invalid-tag':
            self.flush_tag_batch(list(self.connection.datagrams_to_send(now=time.monotonic())))
            return
        if getattr(self, 'mode', None) == 'duplicate-reorder':
            self.check_reorder_deadline()
            if self.reorder_calls >= 1024:
                if self.reorder_held is not None:
                    self.clear_reorder_hold('call-limit')
                raise RuntimeError('NOT_ESTABLISHED: Q05 public call bound reached')
            self.flush_reorder_batch(list(self.connection.datagrams_to_send(now=time.monotonic())))
            return
        if getattr(self, 'mode', None) == 'stream-limit':
            before = self.connection.q15_frame
            batch = list(self.connection.datagrams_to_send(now=time.monotonic()))
            if before is None and self.connection.q15_frame is not None:
                require(self.authenticated and len(self.received) > 0 and len(batch) == 1,
                        'NOT_ESTABLISHED: Q15 frame must have one authenticated request/output datagram')
                data, destination = batch[0]
                require(tuple(destination) == self.expected_source and 0 < len(data) <= 1200
                        and data[0] & 0xc0 == 0x40, 'Q15 selected output is not bounded 1-RTT')
                self.event('stream-limit-frame-built', **self.connection.q15_frame,
                           bytes=len(data), sha256=digest(data), request_bytes=len(self.received),
                           send_ordinal_next=self.tx_packets + 1)
                self.send(data, fixture='stream-limit')
                return
            for data, destination in batch:
                require(tuple(destination) == self.expected_source, 'peer selected a new destination')
                self.send(data)
            return
        for data, destination in self.connection.datagrams_to_send(now=time.monotonic()):
            require(tuple(destination) == self.expected_source, 'peer selected a new destination')
            if (getattr(self, 'mode', None) == 'unauthorized-source' and not getattr(self, 'probe_sent', False)
                    and self.authenticated and self.echoed > 0 and len(data) >= 42 and data[0] & 0xc0 == 0x40):
                self.send_unauthorized_probe(data)
                continue
            self.send(data)
        if getattr(self, 'mode', None) == 'unknown-cid':
            self.maybe_send_unknown_cid()

    def send_unauthorized_probe(self, data):
        """Q18: the engine's actual next short-header datagram, sent only from a second, unauthorized local port."""
        require(self.case['id'] == 'Q18' and self.mode == 'unauthorized-source'
                and not getattr(self, 'probe_sent', False), 'one Q18 probe only')
        bound = self.socket.getsockname()[:2]
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind((bound[0], 0))
            source = list(probe.getsockname()[:2])
            require(source[0] == bound[0] and source[1] != bound[1], 'Q18 probe tuple is not distinct')
            count = probe.sendto(data, self.expected_source)
            require(count == len(data), 'partial Q18 probe send')
        finally:
            probe.close()
        self.probe_sent = True
        self.event('unauthorized-probe', bytes=len(data), sha256=digest(data), source=source,
                   destination=list(self.expected_source), authorized_source=list(bound),
                   authorized_copy_sent=False, echo_enqueued_before=self.echoed, first_byte=data[0])

    def maybe_send_unknown_cid(self):
        """Q16: once, after the first echo data was flushed, one datagram to an unissued CID."""
        if getattr(self, 'unknown_cid_sent', False) or not self.authenticated or self.echoed == 0:
            return
        data = unknown_cid_datagram()
        self.event('unknown-cid-fixture', bytes=len(data), sha256=digest(data), dcid_hex=data[1:9].hex(),
                   echo_enqueued_before=self.echoed, send_ordinal_next=self.tx_packets + 1)
        self.send(data, fixture='unknown-cid')
        self.unknown_cid_sent = True

    def flush_tag_batch(self, batch):
        """One public 1-RTT tag-tail copy; all original datagrams remain emitted."""
        require(self.case['id'] == 'Q13' and self.mode == 'invalid-tag' and self.family == 'ipv4'
                and self.connection is not None and self.initial_sha256 is not None,
                'Q13 batch requires the actual selected peer')
        if not batch:
            return
        require(1 <= len(batch) <= 4 and all(isinstance(data, bytes) and 0 < len(data) <= 1200
                and tuple(destination) == self.expected_source for data, destination in batch),
                'Q13 complete public batch shape/destination differs')
        selected = next((index for index, (data, _) in enumerate(batch)
                         if not self.tag_mutations and self.authenticated and self.echoed > 0
                         and len(data) >= 42 and data[0] & 0xc0 == 0x40), None)
        self.tag_batches += 1
        self.event('q13-public-batch', batch_ordinal=self.tag_batches, selected_index=selected,
                   authenticated_before=self.authenticated, echo_enqueued_before=self.echoed,
                   initial_sha256=self.initial_sha256, first_send_ordinal=self.tx_packets + 1,
                   datagrams=[{'bytes':len(data), 'sha256':digest(data), 'first_byte':data[0],
                               'destination':list(destination)} for data, destination in batch])
        for index, (data, _) in enumerate(batch):
            if index == selected:
                # RFC9001: 16-byte tag is the packet tail. >=42 keeps this byte
                # beyond HP sample even with maximum20-byte destination CID.
                changed = data[:-1] + bytes([data[-1] ^ 1])
                first = self.tx_packets + 1
                self.event('tag-mutation', policy='q13-tag-tail-xor1-v1',
                           batch_ordinal=self.tag_batches, source_index=index,
                           first_send_ordinal=first, authenticated_before=True,
                           bytes=len(data), tag_bytes=16, changed_offset=len(data)-1, xor=1,
                           original_hex=data.hex(), changed_hex=changed.hex(),
                           original_sha256=digest(data), changed_sha256=digest(changed))
                self.send(changed)
                self.send(data)
                self.tag_mutations = 1
                self.event('tag-mutation-sent', batch_ordinal=self.tag_batches, source_index=index,
                           send_ordinals=[first, first + 1])
            else:
                self.send(data)
            self.event('q13-engine-datagram-sent', batch_ordinal=self.tag_batches,
                       source_index=index, send_ordinal=self.tx_packets, bytes=len(data), sha256=digest(data))

    def clear_reorder_hold(self, reason):
        held = self.reorder_held
        self.reorder_held = None
        self.reorder_abandoned = True
        self.event('q05-hold-refused', policy=self.reorder_policy(), reason=reason,
                   **({'source_call':held['source_call'], 'source_index':held['source_index'],
                       'bytes':len(held['data']), 'sha256':digest(held['data']),
                       'started_ns':held['started_ns'], 'deadline_ns':held['deadline_ns']}
                      if held is not None else {}),
                   refused_ns=time.monotonic_ns(), held_bytes_after=0)

    def check_reorder_deadline(self):
        require(not self.reorder_abandoned, 'NOT_ESTABLISHED: Q05 held output was already abandoned')
        if self.reorder_held is not None and time.monotonic_ns() > self.reorder_held['deadline_ns']:
            self.clear_reorder_hold('deadline')
            raise RuntimeError('NOT_ESTABLISHED: Q05 second output or release exceeded500ms hold')

    def flush_reorder_batch(self, batch):
        try:
            self.collect_reorder_batch(batch)
        except BaseException:
            if self.reorder_held is not None:
                self.clear_reorder_hold('call-refused')
            raise

    def reorder_policy(self):
        return (Q05_POST_HANDSHAKE_POLICY if getattr(self, 'reorder_stage', 'initial') == 'post-handshake'
                else Q05_HOLD_POLICY)

    def collect_reorder_batch(self, batch):
        """Bounded first two distinct public outputs, including successive calls."""
        require(self.case['id'] == 'Q05' and self.mode == 'duplicate-reorder' and self.family == 'ipv4'
                and self.connection is not None and self.initial_sha256 is not None,
                'Q05 batch requires its actual live selected peer')
        require(not self.reorder_abandoned, 'NOT_ESTABLISHED: Q05 refused hold cannot resume')
        require(isinstance(batch, list) and len(batch) <= 4 and all(isinstance(data, bytes)
                and 0 < len(data) <= 1200 and tuple(destination) == self.expected_source
                for data, destination in batch), 'Q05 complete public call shape/destination differs')
        require(self.reorder_calls < 1024, 'Q05 public call bound')
        self.reorder_calls += 1
        self.reorder_batches += bool(batch)
        observed = time.monotonic_ns()
        post = getattr(self, 'reorder_stage', 'initial') == 'post-handshake'
        if post and not self.reorder_armed and batch and self.authenticated and self.received and self.echoed > 0:
            require(getattr(self, 'reorder_echo_released', False) and self.echoed >= Q05_POST_ECHO_BYTES,
                    'NOT_ESTABLISHED: Q05 post-handshake echo preparation absent')
            self.reorder_armed = True
            self.event('q05-post-handshake-armed', policy=self.reorder_policy(),
                       first_source_call=self.reorder_calls, authenticated=True,
                       request_bytes=len(self.received), echo_enqueued_bytes=self.echoed,
                       prior_tx_datagrams=self.tx_packets, observed_ns=observed)
        self.event('q05-public-call', policy=self.reorder_policy(), call_ordinal=self.reorder_calls,
                   batch_ordinal=self.reorder_batches if batch else None, observed_ns=observed,
                   initial_sha256=self.initial_sha256,
                   datagrams=[{'bytes':len(data), 'sha256':digest(data), 'destination':list(destination)}
                              for data, destination in batch])
        # Preserve even an actual call that returns too late, then refuse before
        # sending its output. No further engine call occurs after refusal.
        self.check_reorder_deadline()
        for index, (data, _) in enumerate(batch):
            origin = {'source_call':self.reorder_calls, 'source_index':index}
            if self.reorder_established or post and not self.reorder_armed:
                self.send(data)
                self.event('q05-engine-datagram-sent', **origin, send_ordinal=self.tx_packets,
                           bytes=len(data), sha256=digest(data))
                continue
            if post:
                require(data[0] & 0xc0 == 0x40,
                        'NOT_ESTABLISHED: post-handshake Q05 selected output is not short-header 1-RTT')
            if self.reorder_held is None:
                self.reorder_held = {**origin, 'data':data, 'started_ns':observed,
                                     'deadline_ns':observed + Q05_HOLD_NS}
                self.event('q05-output-held', policy=self.reorder_policy(), **origin,
                           bytes=len(data), sha256=digest(data), data_hex=data.hex(),
                           started_ns=observed, deadline_ns=observed + Q05_HOLD_NS,
                           held_datagrams=1, held_bytes=len(data))
                continue
            held = self.reorder_held
            if data == held['data']:
                self.clear_reorder_hold('second-identical')
                raise RuntimeError('NOT_ESTABLISHED: Q05 first two public outputs are not distinct')
            self.check_reorder_deadline()
            ready = time.monotonic_ns()
            require(ready <= held['deadline_ns'], 'NOT_ESTABLISHED: Q05 pair readiness exceeded500ms')
            originals = [{'source_call':held['source_call'], 'source_index':held['source_index'],
                          'bytes':len(held['data']), 'sha256':digest(held['data']), 'data_hex':held['data'].hex()},
                         {**origin, 'bytes':len(data), 'sha256':digest(data), 'data_hex':data.hex()}]
            require(sum(row['bytes'] for row in originals) <= 2400, 'Q05 selected pair storage bound')
            self.event('q05-pair-ready', policy=self.reorder_policy(), datagrams=originals,
                       started_ns=held['started_ns'], ready_ns=ready, deadline_ns=held['deadline_ns'],
                       buffered_datagrams=2, buffered_bytes=sum(row['bytes'] for row in originals),
                       first_send_ordinal=self.tx_packets + 1)
            first = self.tx_packets + 1
            order = [(data, origin), (held['data'], {key:held[key] for key in origin}),
                     (held['data'], {key:held[key] for key in origin})]
            for wire, source in order:
                self.check_reorder_deadline()
                self.send(wire)
                self.event('q05-engine-datagram-sent', **source, send_ordinal=self.tx_packets,
                           bytes=len(wire), sha256=digest(wire))
                self.check_reorder_deadline()
            released = time.monotonic_ns()
            require(released <= held['deadline_ns'], 'NOT_ESTABLISHED: Q05 release exceeded500ms')
            self.reorder_held = None
            self.reorder_established = True
            self.event('duplicate-reorder', policy=self.reorder_policy(), source_origins=[source for _,source in order],
                       send_ordinals=[first, first + 1, first + 2], started_ns=held['started_ns'],
                       released_ns=released, deadline_ns=held['deadline_ns'], held_bytes_after=0)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            self.errors.append({'type':'FixtureCleanupError', 'message':'peer thread did not retire within3seconds'})
        self.close_icmp_socket()
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
                    **({'denied_policy':Q17_IPV4_POLICY, 'engine_constructed':self.connection is not None,
                        'passive_receive_count':self.passive_receive_count}
                       if ipv4_denied(self.case, self.family) else {}),
                    **({'icmp_policy':'q27-literal-quote-v1' if self.case['id'] == 'Q27' else ICMP_POLICY, 'engine_constructed':self.connection is not None,
                        'icmp_interface':self.icmp_interface, 'icmp_guest_mac':self.icmp_guest_mac,
                        'icmp_peer_mac':self.icmp_peer_mac, 'raw_socket_closed':self.raw_socket_closed,
                        'raw_rx_frames':self.raw_rx_frames, 'raw_rx_bytes':self.raw_rx_bytes,
                        'icmp_send_attempted':self.icmp_send_attempted,
                        'icmp_send_completed':self.icmp_send_completed, 'icmp_failed':self.icmp_failed,
                        'icmp_send_result':self.icmp_send_result, 'icmp_trigger':self.icmp_trigger}
                       if self.case['id'] in ICMP_CASES else {}),
                    **({'link_policy':Q24_LINK_POLICY, 'engine_constructed':self.connection is not None,
                        'link_action_attempted':self.link_action_attempted,
                        'link_action_completed':self.link_action_result is not None,
                        'link_action_result':self.link_action_result, 'link_trigger':self.link_trigger}
                       if self.case['id'] == 'Q24' else {}),
                    **({'authority_policy':AUTHORITY_POLICIES[self.case['id']],
                        'engine_constructed':self.connection is not None, 'marker_sent':self.marker_sent,
                        'marker_trigger':self.marker_trigger, 'passive_receive_count':self.passive_receive_count}
                       if self.case['id'] in AUTHORITY_POLICIES else {}),
                    **({'interruption_policy':Q21_SILENT_POLICY,
                        'engine_constructed':self.connection is not None} if self.case['id'] == 'Q21' else {}),
                    **({'interruption_policy':Q22_OUTPUT_POLICY,
                        'stream_output_fenced':self.interrupt_stream_fenced,
                        'stream_output_trigger':self.interrupt_stream_trigger}
                       if self.mode == 'interrupt-stream' else {}),
                    **({'stream_drops':self.stream_drops} if self.mode == 'stream-loss' else {}),
                    **({'tag_batches':self.tag_batches, 'tag_mutations':self.tag_mutations}
                       if self.mode == 'invalid-tag' else {}),
                    **({'reorder_batches':self.reorder_batches, 'reorder_calls':self.reorder_calls,
                        'reorder_established':self.reorder_established, 'reorder_policy':self.reorder_policy(),
                        'reorder_stage':getattr(self, 'reorder_stage', 'initial'),
                        'reorder_hold_ns':Q05_HOLD_NS, 'reorder_held_datagrams':int(self.reorder_held is not None),
                        'reorder_abandoned':self.reorder_abandoned}
                       if self.mode == 'duplicate-reorder' else {}),
                    **({'flow_started_ns':self.flow_started_ns, 'flow_released':self.flow_released,
                        'flow_flushes':self.flow_flushes} if self.mode == 'flow-pause' else {}),
                    'unique_queue_fixture_datagrams':self.queue_fills, 'rx_datagrams':self.rx_packets,
                    'tx_datagrams':self.tx_packets, 'rx_bytes':self.rx_bytes, 'tx_bytes':self.tx_bytes,
                    'thread_alive':self.thread.is_alive(), 'private_material_included':False,
                    'peer_policy':self.response_policy,
                    'response_flight_sealed':self.response_flight_sealed,
                    **({'completion_policy':'q20-one-initial-sink-v1',
                        'engine_constructed':self.connection is not None} if self.case['id'] == 'Q20' else {}),
                    'limit':'Echo enqueue and UDP send establish local effects only; the native report and raw capture must independently establish received body/FIN and wire emission.'}


def linux_outcome(authenticated, fin, received_bytes, terminal):
    """Classify observed client state; terminal failure takes priority over FIN."""
    if terminal is not None and terminal['error_code'] != 0:
        if (terminal['error_code'] == 1 and terminal['frame_type'] == 0
                and terminal['reason_phrase'] == 'Idle timeout'):
            return 'Deadline'
        return 'Protocol'
    return 'Complete' if authenticated and fin and received_bytes == 4096 else 'Deadline'


def linux_control(case, pki, timeout=16, family="ipv4", reorder_stage='initial'):
    """Independent Linux client control; never native ABSD coverage."""
    development_profile(case, family)
    require(not ipv4_denied(case, family), 'Q17 native capability denial requires separate Linux Q01 calibration')
    require(case['id'] not in ICMP_CASES, 'native ICMP fixture requires separate Linux Q01 calibration')
    require(case['id'] != 'Q24', 'Q24 native QEMU link action requires separate Linux Q01 calibration')
    require(case['id'] not in ('Q29', 'Q30'),
            'Q29/Q30 startup-role/time refusals have no Linux socket equivalent')
    require(case['id'] != 'Q31', 'Q31 native absent-RDRAND refusal requires separate Linux Q01 calibration')
    require(case['id'] != 'Q20', 'Q20 completion loss is native IPC; use the same-source Linux Q01 control')
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import HandshakeCompleted, StreamDataReceived, ConnectionTerminated
    require(case["id"] != "Q17", "Linux sockets cannot establish native denied-grant semantics")
    loopback = "::1" if family == "ipv6" else "127.0.0.1"
    require(0 < timeout <= 30, 'Linux control deadline bound')
    # Resolve exact trust before opening any socket or peer thread.
    config = configuration(pki, client=True)
    engine = QuicConnection(configuration=config)
    if case['id'] == 'Q15':
        # Fixture-only Linux calibration of the native zero-peer-stream
        # policy. aioquic exposes no public configuration for these limits.
        # The real native engine keeps its existing TransportConfig unchanged.
        engine._local_max_streams_bidi.value = 0
        engine._local_max_streams_uni.value = 0
        engine._local_max_streams_bidi.sent = 0
        engine._local_max_streams_uni.sent = 0
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
    filtered_datagrams = []
    client_datagrams = []
    try:
        client.bind((loopback, 0))
        client.setblocking(False)
        peer = Peer(case, pki, loopback, 0, client.getsockname()[:2], timeout=timeout, family=family,
                    reorder_stage=reorder_stage)
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
                    if len(filtered_datagrams) < 16:
                        filtered_datagrams.append({'bytes':len(wire), 'sha256':digest(wire), 'source':list(source)})
                    continue
                engine.receive_datagram(wire, source, now=time.monotonic())
                if case['id'] in ('Q05', 'Q13', 'Q15', 'Q21', 'Q22', 'Q23'):
                    require(len(client_datagrams) < 512, 'Q05 Linux consumed-input bound')
                    client_datagrams.append({'ordinal':len(client_datagrams) + 1, 'bytes':len(wire),
                                             'sha256':digest(wire), 'source':list(source), 'engine_delivered':True,
                                             **({'data_hex':wire.hex()} if case['id'] == 'Q23' else {}),
                                             **({'authenticated_before':authenticated} if case['id'] in ('Q05', 'Q15') else {})})
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
            'unauthorized_source_filtered':unauthorized_filtered, 'unauthorized_filtered_datagrams':filtered_datagrams,
            **({'client_datagrams':client_datagrams,
                'duplicate_reorder_scope':'Actual authorized Linux socket inputs passed to public receive_datagram; no native authority, dequeue or deadline claim.'}
               if case['id'] == 'Q05' else {}),
            **({'client_datagrams':client_datagrams,
                'invalid_tag_control_scope':'Actual corrupted-tag/original socket input passed to public receive_datagram; no independent internal decryption trace.'}
               if case['id'] == 'Q13' else {}),
            **({'client_datagrams':client_datagrams,
                'interruption_control_scope':'Linux exercises the selected silent or authenticated zero-echo fixture and expects Deadline. It does not establish native phase observation, process interruption, reap, grant retirement or resource restoration.'}
               if case['id'] in ('Q21', 'Q22') else {}),
            **({'client_datagrams':client_datagrams,
                'owner_expiry_control_scope':'Linux exercises the engine-free Q23 marker peer and expects Deadline with actual marker receipt; no native authority, grant expiry or clock claim.'}
               if case['id'] == 'Q23' else {}),
            **({'client_datagrams':client_datagrams} if case['id'] == 'Q15' else {}),
            'fixture':peer.report() if peer is not None else None,
            'reference_clock':'Linux wall time, exact native fixture root DER; not native fixture-time evidence.',
            'peer_stream_limit_scope':('Q15 calibration advertises zero bidirectional/unidirectional peer streams through version-pinned aioquic limit fields; native policy is unchanged.' if case['id'] == 'Q15' else 'aioquic public defaults; no native zero-peer-stream refusal coverage.'),
            **({'stream_loss_control_scope':'Linux establishes one post-handshake header-selected omission and echo recovery; actual omitted STREAM-frame identity requires native Quinn counter/SEND/capture proof.'} if case['id'] == 'Q04' else {}),
            **({'partial_ipc_control_scope':'Q02 Linux is ordinary authenticated4096-byte echo/FIN only; no native pipe, seven-byte chunk or partial-IPC counter coverage.'} if case['id'] == 'Q02' else {}),
            'queue_control_scope':'Q19 Linux sends four exact prelude datagrams before normal engine Initial; this does not exercise native queue exhaustion or retained Quinn transmit state.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admission', type=Path, required=True)
    parser.add_argument('--case-json', type=Path, required=True)
    parser.add_argument('--pki', type=Path)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--reorder-stage', choices=('initial', 'post-handshake'), default='initial')
    args = parser.parse_args()
    admission = json.loads(args.admission.read_text())
    require(admission.get('reorder_stage', 'initial') == args.reorder_stage,
            'standalone explicit Q05 reorder stage differs')
    require(admission.get('disposition') == 'GO' and admission.get('standalone_peer_go') is True
            and admission.get('readiness_profile') in ('q01-development', 'q12-truncated-header-development', 'q03-initial-loss-development', 'q04-stream-loss-development', 'q05-duplicate-reorder-development', 'q06-flow-pause-development', 'q08-wrong-root-development', 'q09-wrong-name-development', 'q10-expired-development', 'q11-wrong-alpn-development', 'q19-queue-exhausted-development', 'q20-unknown-send-development', 'q21-interrupt-handshake-development', 'q22-interrupt-stream-development', 'q23-owner-expiry-development', 'q29-missing-output-development', 'q30-missing-time-development'),
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
    manifest_path=Path(admission['case_manifest_path'])
    require(sha(manifest_path)==admission['case_manifest_sha256'],'standalone case manifest differs')
    canonical=json.loads(manifest_path.read_text())['native_occurrences']
    require(case in canonical and development_profile(case) == admission['readiness_profile'],
            'canonical case and explicit development profile differ')
    pki = load_peer_pki(case, args.pki)
    peer = Peer(case, pki, admission['bind_address'], admission['port'],
                admission['expected_source'], timeout=admission['peer_timeout_seconds'], reorder_stage=args.reorder_stage)
    try:
        while peer.thread.is_alive():
            peer.thread.join(timeout=0.1)
    finally:
        peer.close()
        seal(args.work/'FIXTURE.json', peer.report())
    return 1 if peer.errors else 0


if __name__ == '__main__':
    sys.exit(main())
