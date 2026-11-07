#!/usr/bin/env python3
"""Finite Q16 unknown-CID controls: peer datagram census and native per-input routing evidence, not protocol runs."""
import hashlib
import importlib.util
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('q16_base', ROOT/'native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(BASE)
MATRIX, PEER, MANIFEST, WIRE = BASE.MATRIX, BASE.PEER_MODULE, BASE.MANIFEST, BASE.WIRE
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q16')
STRAY = bytes([0x40]) + b'ABSDQ16!' + bytes(range(64))
ECHO = b'\x41' + bytes(range(1, 64))

def digest(data): return hashlib.sha256(data).hexdigest()
def line(prefix, row): return prefix + ' ' + ' '.join(key + '=' + str(value) for key, value in row.items())


def proof():
    output, fixture, wire = BASE.proof(); lines = []
    prefixes = ('QUIC SERVICE SELECTOR', 'QUIC SERVICE DONE', 'QUIC SERVICE GRANT', 'QUIC RESULT', 'QUIC BEGIN', 'QUIC CHILD EXIT',
                'QUIC FIXTURE NATIVE_COUNTS', 'QUIC FIXTURE SEND', 'QUIC FIXTURE RX')
    for text in output.splitlines():
        prefix = next((name for name in prefixes if text.startswith(name + ' ')), None)
        if prefix is None: lines.append(text); continue
        row = MATRIX.fields(text); row['case'] = 'Q16'
        if 'local_port' in row: row['local_port'] = '7815'
        if prefix == 'QUIC RESULT': row.update(received='2', receive_bytes=str(len(ECHO) + len(STRAY)), endpoint_responses_discarded='1')
        if prefix == 'QUIC FIXTURE NATIVE_COUNTS': row['receive_delivered'] = '2'
        if prefix == 'QUIC FIXTURE RX':
            for ordinal, data in enumerate((ECHO, STRAY), 1):
                lines.append(line(prefix, dict(row, ordinal=ordinal, at_ms=30 + ordinal, bytes=len(data), sha256=digest(data))))
                lines.append(line('QUIC ROUTE RX', dict(case='Q16', at_ms=30 + ordinal, receive_ordinal=ordinal, bytes=len(data),
                    sha256=digest(data), stream_frames_before=1 if ordinal == 2 else 0, stream_frames_after=1,
                    authenticated_before='true', target_handled='true' if ordinal == 1 else 'false')))
        else: lines.append(line(prefix, row))
    source, destination = ['10.0.2.2', 4443], ['10.0.2.15', 7815]
    events = [dict(event='initial-observed', sha256='a' * 64), dict(event='udp-receive', bytes=1200),
              dict(event='handshake', alpn='absd-echo/1', early_data=False, resumed=False),
              dict(event='echo-enqueue', offset=0, bytes=512)]
    sent = []
    for data, tag in ((ECHO, None), (STRAY, 'unknown-cid')):
        if tag:
            events.append(dict(event='unknown-cid-fixture', bytes=len(STRAY), sha256=digest(STRAY), dcid_hex=STRAY[1:9].hex(),
                               echo_enqueued_before=512, send_ordinal_next=2))
        row = dict(event='udp-send', bytes=len(data), sha256=digest(data), source=list(source), destination=list(destination),
                   **({'fixture': tag} if tag else {}))
        events.append(row); sent.append({k: row[k] for k in ('bytes', 'sha256', 'source', 'destination')})
    fixture.update(readiness_profile='q16-unknown-cid-development', mode='unknown-cid', events=events,
                   tx_datagrams=2, tx_bytes=len(ECHO) + len(STRAY))
    wire['peer_udp'] = sent
    return '\n'.join(lines), fixture, wire


class Socket:
    def __init__(self): self.sent = []
    def getsockname(self): return ('10.0.2.2', 4443)
    def sendto(self, data, destination): self.sent.append(data); return len(data)


def peer(authenticated=True, echoed=512):
    value = object.__new__(PEER.Peer); value.case, value.mode, value.family = CASE, CASE['peer_mode'], 'ipv4'
    value.authenticated, value.echoed, value.tx_packets, value.tx_bytes = authenticated, echoed, 0, 0
    value.one_response_flight = value.response_flight_sealed = False; value.expected_source = ('10.0.2.15', 7815)
    value.socket, value.lock, value.events = Socket(), threading.Lock(), []
    return value


class UnknownCidControls(unittest.TestCase):
    def check(self, output, fixture, wire): return MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)

    def test_exact_selector_port_and_tables(self):
        self.assertEqual(PEER.development_profile(CASE), 'q16-unknown-cid-development')
        self.assertEqual(MATRIX.development_profile(CASE), 'q16-unknown-cid-development')
        with self.assertRaises(RuntimeError): PEER.development_profile(dict(CASE, local_port=7800))
        source = (ROOT / 'native-quic-q01.py').read_text()
        self.assertIn("'q16-unknown-cid-development'", source[source.index("parser.add_argument('--profile'"):][:1500])
        self.assertEqual(MATRIX.select_development_cases({CASE['id']: CASE}, 'q16-unknown-cid-development', 'ipv4', False, []),
                         (['Q16'], ['Q16'], 'q16-unknown-cid-development'))
        self.assertIn("'Q16':'unknown-cid-fixture'", source[source.index('required_event = {'):][:800])
        echo = (ROOT.parent / 'quic/src/bin/quic_echo.rs').read_text()
        self.assertIn('Family::Ipv4 if args.case == "Q16" => {', echo); self.assertIn('QUIC ROUTE RX case=Q16', echo)

    def test_actual_peer_sends_once_only_after_authenticated_echo(self):
        for authenticated, echoed in ((False, 512), (True, 0)):
            value = peer(authenticated, echoed); value.maybe_send_unknown_cid(); self.assertEqual(value.socket.sent, [])
        value = peer(); value.maybe_send_unknown_cid(); value.maybe_send_unknown_cid()
        self.assertEqual(value.socket.sent, [STRAY]); self.assertEqual(sum(r['event'] == 'unknown-cid-fixture' for r in value.events), 1)
        value = peer()
        with self.assertRaisesRegex(RuntimeError, 'fixture tag'): value.send(STRAY + b'x', fixture='unknown-cid')

    def test_synthetic_complete_with_unrouted_stray_calibrates(self):
        self.assertEqual(self.check(*proof())['actual_outcome'], 'Complete')

    def test_routing_evidence_refuses(self):
        stray_route = 'receive_ordinal=2 bytes=73 sha256=' + digest(STRAY)
        cases = {'stray-routed': ('target_handled=false', 'target_handled=true'),
                 'echo-unrouted': ('target_handled=true', 'target_handled=false'),
                 'stray-stream': ('stream_frames_before=1 stream_frames_after=1 authenticated_before=true target_handled=false',
                                  'stream_frames_before=1 stream_frames_after=2 authenticated_before=true target_handled=false'),
                 'stray-before-auth': ('authenticated_before=true target_handled=false', 'authenticated_before=false target_handled=false'),
                 'responses': ('endpoint_responses_discarded=1', 'endpoint_responses_discarded=2')}
        for name, (old, new) in cases.items():
            output, fixture, wire = proof(); self.assertIn(old, output); output = output.replace(old, new, 1)
            with self.subTest(mutation=name), self.assertRaises(RuntimeError): self.check(output, fixture, wire)
        output, fixture, wire = proof(); self.assertIn(stray_route, output)
        output = '\n'.join(r for r in output.split('\n') if not (r.startswith('QUIC ROUTE RX') and stray_route in r))
        with self.assertRaisesRegex(RuntimeError, 'routing observations absent'): self.check(output, fixture, wire)

    def test_peer_datagram_census_refuses(self):
        for name in ('untagged', 'before-echo', 'wrong-bytes', 'twice-on-wire', 'missing-mark'):
            output, fixture, wire = proof(); ev = fixture['events']
            mark = next(r for r in ev if r['event'] == 'unknown-cid-fixture')
            if name == 'untagged': next(r for r in ev if r.get('fixture') == 'unknown-cid').pop('fixture')
            elif name == 'before-echo': ev.remove(mark); ev.insert(2, mark)
            elif name == 'wrong-bytes': mark['sha256'] = 'c' * 64
            elif name == 'twice-on-wire': wire['peer_udp'].append(dict(wire['peer_udp'][-1]))
            else: ev.remove(mark)
            with self.subTest(mutation=name), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_linux_control_uses_the_same_peer_predicate(self):
        _, fixture, _ = proof(); self.assertEqual(MATRIX.verify_unknown_cid(fixture)['sha256'], digest(STRAY))


if __name__ == '__main__':
    unittest.main()
