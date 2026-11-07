#!/usr/bin/env python3
"""Finite Q18 unauthorized-source controls: probe tuple/capture census and native non-delivery, not protocol runs."""
import hashlib
import importlib.util
from pathlib import Path
import socket
import threading
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('q18_base', ROOT/'native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(BASE)
MATRIX, PEER, MANIFEST, WIRE = BASE.MATRIX, BASE.PEER_MODULE, BASE.MANIFEST, BASE.WIRE
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q18')
PROBE = b'\x45' + bytes(range(1, 200))
ECHO = b'\x41' + bytes(range(1, 64))
GUEST, AUTH, BAD = ['10.0.2.15', 7817], ['10.0.2.2', 4443], ['10.0.2.2', 40001]

def digest(data): return hashlib.sha256(data).hexdigest()
def line(prefix, row): return prefix + ' ' + ' '.join(key + '=' + str(value) for key, value in row.items())


def proof():
    output, fixture, wire = BASE.proof(); lines = []
    prefixes = ('QUIC SERVICE SELECTOR', 'QUIC SERVICE DONE', 'QUIC SERVICE GRANT', 'QUIC RESULT', 'QUIC BEGIN', 'QUIC CHILD EXIT',
                'QUIC FIXTURE NATIVE_COUNTS', 'QUIC FIXTURE SEND', 'QUIC FIXTURE RX')
    for text in output.splitlines():
        prefix = next((name for name in prefixes if text.startswith(name + ' ')), None)
        if prefix is None: lines.append(text); continue
        row = MATRIX.fields(text); row['case'] = 'Q18'
        if 'local_port' in row: row['local_port'] = '7817'
        if prefix == 'QUIC RESULT': row.update(received='1', receive_bytes=str(len(ECHO)), engine_transmits='2', send_calls='2', last_send_ms='60',
                                               send_accepted='2', send_bytes='1241')
        if prefix == 'QUIC FIXTURE NATIVE_COUNTS': row['send_requests'] = '2'
        if prefix == 'QUIC FIXTURE RX': row.update(bytes=str(len(ECHO)), sha256=digest(ECHO))
        lines.append(line(prefix, row))
        if prefix == 'QUIC FIXTURE SEND': lines.append(line(prefix, dict(row, ordinal='2', at_ms='60', bytes='41')))
    events = [dict(event='initial-observed', sha256='a' * 64), dict(event='udp-receive', bytes=1200, source=list(GUEST)),
              dict(event='handshake', alpn='absd-echo/1', early_data=False, resumed=False),
              dict(event='echo-enqueue', offset=0, bytes=512),
              dict(event='unauthorized-probe', bytes=len(PROBE), sha256=digest(PROBE), source=list(BAD), destination=list(GUEST),
                   authorized_source=list(AUTH), authorized_copy_sent=False, echo_enqueued_before=512, first_byte=PROBE[0]),
              dict(event='udp-send', bytes=len(ECHO), sha256=digest(ECHO), source=list(AUTH), destination=list(GUEST))]
    fixture.update(readiness_profile='q18-unauthorized-source-development', mode='unauthorized-source', events=events,
                   rx_datagrams=1, rx_bytes=1200, tx_datagrams=1, tx_bytes=len(ECHO))
    wire['guest_udp'] = [dict(sha256='a' * 64, bytes=1200, source=list(GUEST), timestamp=1.0),
                         dict(sha256='d' * 64, bytes=41, source=list(GUEST), timestamp=3.0)]
    wire['peer_udp'] = [dict(sha256=digest(ECHO), bytes=len(ECHO), source=list(AUTH), destination=list(GUEST), timestamp=2.5)]
    wire['unauthorized_peer_udp'] = [dict(sha256=digest(PROBE), bytes=len(PROBE), source=list(BAD), destination=list(GUEST), timestamp=2.0)]
    # The old shared synthetic proof appends owner packet records at the end.
    # Put Q18's records inside the actual parent observation interval.
    traffic = [text for text in lines if text.startswith(('QUIC FIXTURE SEND ', 'QUIC FIXTURE RX '))]
    traffic.sort(key=lambda text: int(MATRIX.fields(text)['at_ms']))
    output = []
    for text in lines:
        if text in traffic:
            continue
        if text.startswith('QUIC CHILD EXIT '):
            output.extend(traffic)
        output.append(text)
        if text.startswith('QUIC SERVICE GRANT '):
            output.append('QUIC SERVICE UDP_FILTER case=Q18 phase=begin dropped=0 at_ms=2')
        if text.startswith('QUIC CHILD EXIT '):
            output.append('QUIC SERVICE UDP_FILTER case=Q18 phase=end dropped=1 at_ms=110')
    return '\n'.join(output), fixture, wire


class Socket:
    def __init__(self): self.sent = []
    def getsockname(self): return ('127.0.0.1', 4443)
    def sendto(self, data, destination): self.sent.append(data); return len(data)


class UnauthorizedSourceControls(unittest.TestCase):
    def check(self, output, fixture, wire): return MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)

    def test_exact_selector_port_and_tables(self):
        self.assertEqual(PEER.development_profile(CASE), 'q18-unauthorized-source-development')
        self.assertEqual(MATRIX.development_profile(CASE), 'q18-unauthorized-source-development')
        with self.assertRaises(RuntimeError): PEER.development_profile(dict(CASE, local_port=7800))
        source = (ROOT / 'native-quic-q01.py').read_text()
        self.assertIn("'q18-unauthorized-source-development'", source[source.index("parser.add_argument('--profile'"):][:1600])
        self.assertEqual(MATRIX.select_development_cases({CASE['id']: CASE}, 'q18-unauthorized-source-development', 'ipv4', False, []),
                         (['Q18'], ['Q18'], 'q18-unauthorized-source-development'))
        self.assertIn("'Q18':'unauthorized-probe'", source[source.index('required_event = {'):][:800])

    def test_actual_probe_leaves_from_a_distinct_local_port_only(self):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); receiver.bind(('127.0.0.1', 0)); receiver.settimeout(2)
        own = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); own.bind(('127.0.0.1', 0))
        try:
            value = object.__new__(PEER.Peer); value.case, value.mode, value.family = CASE, CASE['peer_mode'], 'ipv4'
            value.socket, value.lock, value.events, value.echoed = own, threading.Lock(), [], 512
            value.expected_source = receiver.getsockname()[:2]
            value.send_unauthorized_probe(PROBE)
            data, source = receiver.recvfrom(2048)
            self.assertEqual(data, PROBE); self.assertNotEqual(source[1], own.getsockname()[1])
            event = value.events[-1]; self.assertEqual((event['source'][1], event['authorized_copy_sent']), (source[1], False))
            with self.assertRaisesRegex(RuntimeError, 'one Q18 probe only'): value.send_unauthorized_probe(PROBE)
        finally:
            receiver.close(); own.close()

    def test_synthetic_complete_with_filtered_probe_calibrates(self):
        self.assertEqual(self.check(*proof())['actual_outcome'], 'Complete')

    def test_owner_filter_witness_is_required_and_scoped(self):
        output, fixture, wire = proof()
        begin = 'QUIC SERVICE UDP_FILTER case=Q18 phase=begin dropped=0 at_ms=2'
        end = 'QUIC SERVICE UDP_FILTER case=Q18 phase=end dropped=1 at_ms=110'
        mutations = {
            'missing-begin': output.replace(begin, ''),
            'missing-end': output.replace(end, ''),
            'not-dequeued': output.replace(end, end.replace('dropped=1', 'dropped=0')),
            'two-discards': output.replace(end, end.replace('dropped=1', 'dropped=2')),
            'old-stack-count': output.replace(begin, begin.replace('dropped=0', 'dropped=1')),
            'wrong-case': output.replace(end, end.replace('case=Q18', 'case=Q01')),
            'duplicate-end': output + '\n' + end,
            'reversed': output.replace(begin, '@').replace(end, begin).replace('@', end),
            'noncanonical-count': output.replace(end, end.replace('dropped=1', 'dropped=01')),
            'clock-rewind': output.replace(end, end.replace('at_ms=110', 'at_ms=1')),
            'clock-overflow': output.replace(end, end.replace('at_ms=110', 'at_ms=18446744073709551616')),
            'starts-before-construction': output.replace(begin, begin.replace('at_ms=2', 'at_ms=1')),
            'ends-before-consumer': output.replace(end, end.replace('at_ms=110', 'at_ms=100')),
            'traffic-before-window': output.replace('phase=begin dropped=0 at_ms=2', 'phase=begin dropped=0 at_ms=22'),
            'late-receive': output.replace('ordinal=1 at_ms=50', 'ordinal=1 at_ms=111'),
            'end-before-child-exit': output.replace(end, '').replace('QUIC CHILD EXIT ', end + '\nQUIC CHILD EXIT ', 1),
        }
        for name, changed in mutations.items():
            with self.subTest(mutation=name), self.assertRaises(RuntimeError):
                self.check(changed, fixture, wire)

    def test_probe_delivery_capture_and_census_refuse(self):
        def rx_has_probe(o, f, w): return o.replace('sha256=' + digest(ECHO), 'sha256=' + digest(PROBE), 1)
        mutations = {
            'delivered-to-native': ('output', rx_has_probe),
            'authorized-copy': ('fixture', lambda f, w: (f['events'].append(dict(event='udp-send', bytes=len(PROBE), sha256=digest(PROBE), source=list(AUTH), destination=list(GUEST))),
                                                         f.update(tx_datagrams=2, tx_bytes=len(ECHO) + len(PROBE)),
                                                         w['peer_udp'].append(dict(sha256=digest(PROBE), bytes=len(PROBE), source=list(AUTH), destination=list(GUEST), timestamp=2.6)))),
            'not-captured': ('fixture', lambda f, w: w.update(unauthorized_peer_udp=[])),
            'captured-twice': ('fixture', lambda f, w: w['unauthorized_peer_udp'].append(dict(w['unauthorized_peer_udp'][0]))),
            'same-port': ('fixture', lambda f, w: next(r for r in f['events'] if r['event'] == 'unauthorized-probe').update(source=list(AUTH))),
            'before-echo': ('fixture', lambda f, w: f['events'].insert(2, f['events'].pop(4))),
            'after-exchange': ('fixture', lambda f, w: w['unauthorized_peer_udp'][0].update(timestamp=9.0)),
            'copy-flag': ('fixture', lambda f, w: next(r for r in f['events'] if r['event'] == 'unauthorized-probe').update(authorized_copy_sent=True)),
            'long-header': ('fixture', lambda f, w: next(r for r in f['events'] if r['event'] == 'unauthorized-probe').update(first_byte=0xc0)),
        }
        for name, (kind, mutate) in mutations.items():
            output, fixture, wire = proof()
            if kind == 'output': output = mutate(output, fixture, wire)
            else: mutate(fixture, wire)
            with self.subTest(mutation=name), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_wire_classifier_keeps_wrong_port_frames_apart_for_q18_only(self):
        from importlib import util
        spec = util.spec_from_file_location('q07_frames', ROOT / 'test-native-quic-silent.py'); frames = util.module_from_spec(spec); spec.loader.exec_module(frames)
        g, p = frames.GUEST_MAC, frames.PEER_MAC
        guest = frames.udp_frame(g, p, '10.0.2.15', '10.0.2.2', 7817, 4443, b'\xc7' + bytes(1199))
        reply = frames.udp_frame(p, g, '10.0.2.2', '10.0.2.15', 4443, 7817, ECHO)
        stray = frames.udp_frame(p, g, '10.0.2.2', '10.0.2.15', 40001, 7817, PROBE)
        observed = WIRE.observe(BASE.pcap([guest, stray, reply]), CASE, g, p)
        self.assertEqual([r['sha256'] for r in observed['peer_udp']], [digest(ECHO)])
        self.assertEqual([(r['sha256'], r['source'][1]) for r in observed['unauthorized_peer_udp']], [(digest(PROBE), 40001)])
        q16 = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q16')
        with self.assertRaises(WIRE.Refusal):
            WIRE.observe(BASE.pcap([frames.udp_frame(g, p, '10.0.2.15', '10.0.2.2', 7815, 4443, b'\xc7' + bytes(1199)),
                                    frames.udp_frame(p, g, '10.0.2.2', '10.0.2.15', 40001, 7815, PROBE)]), q16, g, p)

    def test_linux_filtered_probe_is_matched_by_hash(self):
        source = (ROOT / 'native-quic-q01.py').read_text()
        block = source[source.index("if identity == 'Q18':"):][:900]
        self.assertIn("filtered[0]['sha256'] == probe['sha256']", block)
        self.assertIn("observed.get('unauthorized_source_filtered') == len(filtered) == 1", block)

    def test_linux_control_uses_the_same_peer_predicate(self):
        _, fixture, _ = proof(); self.assertEqual(MATRIX.verify_unauthorized_source(fixture)['sha256'], digest(PROBE))


if __name__ == '__main__':
    unittest.main()
