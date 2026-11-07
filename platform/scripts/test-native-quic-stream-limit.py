#!/usr/bin/env python3
"""Q15 construction and artifact controls; no cryptographic/runtime verdict."""
import copy
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import threading
import struct
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('q15_base', ROOT/'native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(BASE)
MATRIX, PEER, MANIFEST = BASE.MATRIX, BASE.PEER_MODULE, BASE.MANIFEST
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q15')
PACKET = b'\x41' + bytes(range(1, 64))
HASH = hashlib.sha256(PACKET).hexdigest()


def proof():
    output, fixture, wire = BASE.proof()
    mark = dict(event='stream-limit-frame-built', frame_type=17, stream_id=1, maximum=8192,
                native_peer_bidi_limit=0, packet_number=3, handshake_complete=True,
                handshake_confirmed=True, request_bytes=512, bytes=len(PACKET), sha256=HASH,
                send_ordinal_next=1)
    sent = dict(event='udp-send', bytes=len(PACKET), sha256=HASH,
                source=['10.0.2.2', 4443], destination=['10.0.2.15', 7814], fixture='stream-limit')
    received = dict(event='udp-receive', bytes=1200, sha256='a'*64, source=['10.0.2.15', 7814])
    fixture.update(mode='stream-limit', readiness_profile='q15-stream-limit-development',
                   request_bytes=512, echo_enqueued_bytes=0, echo_fin_enqueued=False,
                   request_sha256=hashlib.sha256(bytes(97 + i % 26 for i in range(512))).hexdigest(),
                   request_fin=False, tx_datagrams=1, tx_bytes=len(PACKET), rx_datagrams=1,
                   rx_bytes=1200, events=[received, dict(event='initial-observed', sha256='a'*64),
                       dict(event='handshake'), dict(event='request-stream', stream_id=0, bytes=512), mark, sent])
    wire.update(guest_udp=[dict(received, ordinal=1, first_byte=0xc0, destination=['10.0.2.2',4443])],
                peer_udp=[dict(sent, first_byte=PACKET[0])], guest_udp_count=1)
    prefixes = ('QUIC SERVICE SELECTOR','QUIC SERVICE DONE','QUIC SERVICE GRANT','QUIC RESULT',
                'QUIC BEGIN','QUIC CHILD EXIT','QUIC FIXTURE NATIVE_COUNTS','QUIC FIXTURE SEND','QUIC FIXTURE RX')
    lines = []
    for text in output.splitlines():
        prefix = next((p for p in prefixes if text.startswith(p+' ')), None)
        if prefix is None: lines.append(text); continue
        row = MATRIX.fields(text); row['case'] = 'Q15'
        if 'local_port' in row: row['local_port'] = '7814'
        if prefix == 'QUIC RESULT':
            row.update(outcome='Protocol', authenticated='true', sent_stream='512', received_stream='0',
                       request_fin='false', peer_fin='false', request_acked='false', connection_drained='false',
                       transport_error_code='4', transport_close_origin='local', receive_bytes=str(len(PACKET)))
        if prefix == 'QUIC FIXTURE RX': row.update(bytes=str(len(PACKET)), sha256=HASH)
        lines.append(prefix+' '+' '.join(k+'='+str(v) for k,v in row.items()))
    return '\n'.join(lines), fixture, wire


class Frame:
    def __init__(self): self.values = []
    def push_uint_var(self, value): self.values.append(value)


class Builder:
    packet_number = 3
    def __init__(self): self.frames = []
    def start_frame(self, kind, capacity):
        frame = Frame(); self.frames.append((kind, capacity, frame)); return frame


class Connection:
    _handshake_complete = _handshake_confirmed = True
    _remote_max_streams_bidi = 0
    def _write_stream_limits(self, builder, space, stream): pass


class StreamLimitControls(unittest.TestCase):
    def test_canonical_case_and_native_proof(self):
        self.assertEqual(MATRIX.development_profile(CASE), 'q15-stream-limit-development')
        self.assertEqual(PEER.development_profile(CASE), 'q15-stream-limit-development')
        self.assertEqual(PEER.peer_certificate(CASE), 'valid')
        self.assertEqual(PEER.peer_alpn(CASE), ['absd-echo/1'])
        self.assertEqual(PEER.peer_terminal_codes(CASE), (4,))
        MATRIX.verify_native(CASE, *proof(), MANIFEST)

    def test_hook_writes_exact_frame_once(self):
        connection = PEER.stream_limit_connection(Connection)(); builder = Builder()
        for _ in range(2): connection._write_stream_limits(builder, None, SimpleNamespace(stream_id=0))
        self.assertEqual(len(builder.frames), 1)
        kind, capacity, frame = builder.frames[0]
        self.assertEqual((kind, capacity, frame.values), (17, 17, [1, 8192]))
        self.assertEqual(connection.q15_frame['native_peer_bidi_limit'], 0)

    def test_wire_classifier_accepts_only_exact_q15_mode_and_port(self):
        frames = []
        for original, offset in ((BASE.GUEST, 34), (BASE.PEER, 36)):
            frame = bytearray(original); frame[offset:offset+2] = (7814).to_bytes(2, 'big')
            length = struct.unpack('!H', frame[38:40])[0]; frame[40:42] = b'\0\0'
            pseudo = bytes(frame[26:34]) + b'\0\x11' + bytes(frame[38:40])
            checksum = BASE.WIRE.checksum(pseudo + bytes(frame[34:34+length])) or 65535
            frame[40:42] = checksum.to_bytes(2, 'big'); frames.append(bytes(frame))
        raw = BASE.pcap(frames)
        observed = BASE.WIRE.observe(raw, CASE, '52:54:00:12:34:56', '02:71:00:00:00:02')
        self.assertEqual(observed['guest_udp'][0]['source'][1], 7814)
        self.assertTrue(all(row['ip_checksum_valid'] and row['udp_checksum_valid']
                            for row in observed['guest_udp'] + observed['peer_udp']))
        for changed in (dict(CASE, local_port=7813), dict(CASE, peer_mode='echo')):
            with self.subTest(case=changed), self.assertRaises(BASE.WIRE.Refusal):
                BASE.WIRE.observe(raw, changed, '52:54:00:12:34:56', '02:71:00:00:00:02')

    def test_final_certificate_selection_binds_actual_leaf_and_root(self):
        selected = dict(kind='valid', sha256='a'*64, client_root_sha256='b'*64)
        fixture = dict(certificate_selection=selected)
        pki = dict(leaf_certificates={'valid':{'sha256':'a'*64}}, root_der={'sha256':'b'*64})
        MATRIX.verify_certificate_selection(CASE, fixture, pki)
        for field, value in [('kind','untrusted'), ('sha256','c'*64), ('client_root_sha256','c'*64)]:
            changed = copy.deepcopy(fixture); changed['certificate_selection'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                MATRIX.verify_certificate_selection(CASE, changed, pki)

    def test_actual_flush_sends_selected_frame_once_and_rejects_tag_substitution(self):
        class Output:
            q15_frame = None
            def datagrams_to_send(self, now):
                self.q15_frame = dict(frame_type=17, stream_id=1, maximum=8192,
                    native_peer_bidi_limit=0, packet_number=3,
                    handshake_complete=True, handshake_confirmed=True)
                return [(PACKET, ('10.0.2.15', 7814))]
        class Socket:
            def __init__(self): self.sent = []
            def getsockname(self): return ('10.0.2.2', 4443)
            def sendto(self, data, destination): self.sent.append((data, destination)); return len(data)
        peer = object.__new__(PEER.Peer)
        peer.case, peer.mode, peer.family = CASE, 'stream-limit', 'ipv4'
        peer.connection, peer.socket, peer.lock, peer.events = Output(), Socket(), threading.Lock(), []
        peer.authenticated, peer.received = True, bytearray(PEER.pattern(512))
        peer.one_response_flight = peer.response_flight_sealed = False
        peer.expected_source, peer.tx_packets, peer.tx_bytes = ('10.0.2.15', 7814), 0, 0
        with self.assertRaises(RuntimeError): peer.send(PACKET, fixture='stream-limit')
        peer.flush()
        self.assertEqual(peer.socket.sent, [(PACKET, peer.expected_source)])
        self.assertEqual([r['fixture'] for r in peer.events if r['event'] == 'udp-send'], ['stream-limit'])
        for data in (PACKET, PACKET[:-1] + b'!'):
            with self.subTest(data=data), self.assertRaises(RuntimeError): peer.send(data, fixture='stream-limit')

    def test_hook_does_not_inject_before_confirmed_handshake_or_on_other_stream(self):
        for field in ('_handshake_complete','_handshake_confirmed'):
            with self.subTest(field=field):
                connection = PEER.stream_limit_connection(Connection)(); setattr(connection, field, False)
                builder = Builder(); connection._write_stream_limits(builder, None, SimpleNamespace(stream_id=0))
                self.assertEqual(builder.frames, [])
        connection = PEER.stream_limit_connection(Connection)(); builder = Builder()
        connection._write_stream_limits(builder, None, SimpleNamespace(stream_id=4))
        self.assertEqual(builder.frames, [])

    def test_nonzero_advertised_limit_cannot_establish_fixture(self):
        connection = PEER.stream_limit_connection(Connection)(); connection._remote_max_streams_bidi = 1
        with self.assertRaisesRegex(RuntimeError, 'NOT_ESTABLISHED'):
            connection._write_stream_limits(Builder(), None, SimpleNamespace(stream_id=0))

    def test_missing_or_duplicate_selected_frame_refused(self):
        for event in ('stream-limit-frame-built','udp-send'):
            for duplicate in (False, True):
                output, fixture, wire = proof(); mark = next(r for r in fixture['events'] if r['event'] == event)
                if duplicate: fixture['events'].append(copy.deepcopy(mark))
                else: fixture['events'].remove(mark)
                with self.subTest(event=event, duplicate=duplicate), self.assertRaises(RuntimeError):
                    MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)

    def test_each_boundary_and_output_binding_is_effective(self):
        changes = dict(frame_type=16, stream_id=0, maximum=8191, native_peer_bidi_limit=1,
                       handshake_complete=False, handshake_confirmed=False, request_bytes=0,
                       send_ordinal_next=2, bytes=1201, sha256='f'*64, packet_number=-1)
        for key, value in changes.items():
            output, fixture, wire = proof()
            next(r for r in fixture['events'] if r['event'] == 'stream-limit-frame-built')[key] = value
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)

    def test_before_authentication_or_before_request_refused(self):
        for event in ('handshake','request-stream'):
            output, fixture, wire = proof(); row = next(r for r in fixture['events'] if r['event'] == event)
            fixture['events'].remove(row); fixture['events'].append(row)
            with self.subTest(event=event), self.assertRaises(RuntimeError):
                MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)

    def test_wire_or_native_dequeue_substitution_refused(self):
        output, fixture, wire = proof(); wire['peer_udp'][0]['sha256'] = 'f'*64
        with self.assertRaises(RuntimeError): MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)
        output, fixture, wire = proof(); output = output.replace('sha256='+HASH, 'sha256='+'f'*64)
        with self.assertRaises(RuntimeError): MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)

    def test_peer_close_timeout_or_child_failure_cannot_pass(self):
        changes = [('transport_close_origin=local','transport_close_origin=peer'),
                   ('transport_error_code=4','transport_error_code=5'),
                   ('outcome=Protocol','outcome=Native'), ('authenticated=true','authenticated=false'),
                   ('status=0','status=1'), ('killed=false','killed=true'), ('end_ms=101','end_ms=10011')]
        for before, after in changes:
            output, fixture, wire = proof()
            with self.subTest(change=before), self.assertRaises(RuntimeError):
                MATRIX.verify_native(CASE, output.replace(before, after), fixture, wire, MANIFEST)

    def test_linux_requires_actual_authenticated_delivery(self):
        _, fixture, _ = proof()
        ledger = [dict(ordinal=1, bytes=len(PACKET), sha256=HASH, source=['10.0.2.2',4443],
                       engine_delivered=True, authenticated_before=True)]
        MATRIX.verify_stream_limit(fixture, client_datagrams=ledger)
        for key in ('engine_delivered','authenticated_before'):
            changed = copy.deepcopy(ledger); changed[0][key] = False
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                MATRIX.verify_stream_limit(fixture, client_datagrams=changed)

    def test_fixture_label_alone_is_not_coverage(self):
        _, fixture, wire = proof()
        with self.assertRaisesRegex(RuntimeError, 'witness required'): MATRIX.verify_stream_limit(fixture)
        with self.assertRaisesRegex(RuntimeError, 'witness required'):
            MATRIX.verify_stream_limit(fixture, wire=wire, client_datagrams=[])


if __name__ == '__main__': unittest.main()
