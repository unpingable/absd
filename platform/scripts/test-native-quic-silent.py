#!/usr/bin/env python3
"""Finite Q07 silent-peer controls: peer receipt census and native deadline evidence, not protocol runs."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('q07_base', ROOT/'native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(BASE)
MATRIX, PEER, MANIFEST, WIRE = BASE.MATRIX, BASE.PEER_MODULE, BASE.MANIFEST, BASE.WIRE
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q07')
INITIALS = [bytes([0xc7]) + bytes([i]) * 1199 for i in range(1, 5)]
GUEST, PEER_TUPLE = ['10.0.2.15', 7806], ['10.0.2.2', 4443]

def digest(data): return hashlib.sha256(data).hexdigest()


def udp_frame(src_mac, dst_mac, src, dst, sport, dport, payload):
    import socket, struct
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = s + d + struct.pack('!BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('!H', WIRE.checksum(pseudo + udp) or 0xffff) + udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0, s, d)
    ip = ip[:10] + struct.pack('!H', WIRE.checksum(ip)) + ip[12:]
    return bytes.fromhex(dst_mac.replace(':', '')) + bytes.fromhex(src_mac.replace(':', '')) + b'\x08\x00' + ip + udp


GUEST_MAC, PEER_MAC = '52:54:00:12:34:56', '02:71:00:00:00:02'
def guest_initial(data): return udp_frame(GUEST_MAC, PEER_MAC, '10.0.2.15', '10.0.2.2', 7806, 4443, data)
def peer_reply(data): return udp_frame(PEER_MAC, GUEST_MAC, '10.0.2.2', '10.0.2.15', 4443, 7806, data)
def line(prefix, row): return prefix + ' ' + ' '.join(key + '=' + str(value) for key, value in row.items())


def proof(count=4):
    report = {field: '0' for field in MANIFEST['report']['fields']}
    report.update(case='Q07', outcome='Native', authenticated='false', sent_stream='0', received_stream='0',
        request_fin='false', peer_fin='false', request_acked='false', connection_drained='false',
        close_accepted='true', pipe_fenced='true', unknown_send='false', native_failure_kind='Deadline',
        native_error_code='none', native_error_detail='none', transport_error_code='none',
        transport_close_origin='none', entropy_attempts='1', engine_transmits=str(count), send_calls=str(count),
        send_accepted=str(count), send_bytes=str(1200 * count), received='0', receive_bytes='0',
        last_send_ms='8000', fence_ms='10011', start_ms='10', end_ms='10011', deadline_ms='10010', grant_expiry_ms='15001')
    rows = [line('QUIC SERVICE SELECTOR', dict(case='Q07', local_port=7806)),
            line('QUIC SERVICE DONE', dict(case='Q07', sockets=0, **{n + '_' + w: 1 for n in ('processes', 'handles', 'pipes', 'cells') for w in ('before', 'after')})),
            line('QUIC SERVICE GRANT', dict(case='Q07', before_ms=1, constructed_ms=2, owner_expiry_ms=15001, local_port=7806, peer_port=4443)),
            line('QUIC CPU', dict(vendor='GenuineIntel', leaf1_eax=0x306c0, leaf1_ecx=1 << 30, family=6, model=60, rdrand=1)),
            line('QUIC RESULT', report),
            line('QUIC BEGIN', dict(case='Q07', start_ms=10, deadline_ms=10010, grant_expiry_ms=15001)),
            line('QUIC CHILD EXIT', dict(case='Q07', kind=1, status=0, killed='false'))]
    for ordinal, data in enumerate(INITIALS[:count], 1):
        rows.append(line('QUIC FIXTURE SEND', dict(case='Q07', ordinal=ordinal, at_ms=20 + 1000 * ordinal, bytes=1200,
                                                   peer_ip='10.0.2.2', peer_port=4443)))
    events = []
    for ordinal, data in enumerate(INITIALS[:count], 1):
        events.append(dict(event='udp-receive', bytes=1200, sha256=digest(data), source=list(GUEST)))
        if ordinal == 1:
            events.append(dict(event='initial-observed', bytes=1200, sha256=digest(data), receive_ordinal=1))
        events.append(dict(event='silent-input', receive_ordinal=ordinal, bytes=1200, sha256=digest(data), engine_delivered=False))
    fixture = dict(case='Q07', mode='silent', readiness_profile='q07-silent-development', canonical_campaign_acceptance=False,
                   authenticated=False, request_bytes=0, echo_enqueued_bytes=0, request_fin=False, echo_fin_enqueued=False,
                   terminated=None, errors=[], thread_alive=False, rx_datagrams=count, tx_datagrams=0,
                   rx_bytes=1200 * count, tx_bytes=0, events=events, certificate_selection=None)
    wire = dict(guest_udp=[dict(ordinal=i, bytes=1200, sha256=digest(d), source=list(GUEST), destination=list(PEER_TUPLE), first_byte=d[0])
                           for i, d in enumerate(INITIALS[:count], 1)], peer_udp=[], guest_udp_count=count)
    return '\n'.join(rows), fixture, wire


class Socket:
    def __init__(self): self.sent = []
    def getsockname(self): return ('10.0.2.2', 4443)
    def sendto(self, data, destination): self.sent.append(data); return len(data)


def peer():
    value = object.__new__(PEER.Peer); value.case, value.mode, value.family = CASE, CASE['peer_mode'], 'ipv4'
    value.connection = value.initial_sha256 = None; value.tx_packets = value.rx_packets = 0
    value.socket, value.lock, value.events = Socket(), threading.Lock(), []
    return value


class SilentControls(unittest.TestCase):
    def check(self, output, fixture, wire): return MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)

    def test_exact_selector_and_port(self):
        self.assertEqual(PEER.development_profile(CASE), 'q07-silent-development')
        self.assertEqual(MATRIX.development_profile(CASE), 'q07-silent-development')
        wrong = dict(CASE, local_port=7800)
        with self.assertRaises(RuntimeError): PEER.development_profile(wrong)

    def test_actual_peer_records_initials_and_never_sends(self):
        value = peer()
        for data in INITIALS[:3]:
            value.rx_packets += 1; value.record_silent(data, True)
        self.assertEqual(value.socket.sent, [])
        self.assertEqual([row['event'] for row in value.events], ['initial-observed', 'silent-input', 'silent-input', 'silent-input'])
        self.assertEqual(value.initial_sha256, digest(INITIALS[0]))

    def test_actual_peer_refuses_non_initial_short_or_engine(self):
        for data, initial in ((INITIALS[0], False), (INITIALS[0][:1199], True), (INITIALS[0] + b'\x00', True)):
            with self.subTest(initial=initial, size=len(data)), self.assertRaisesRegex(RuntimeError, 'non-Initial'):
                value = peer(); value.rx_packets = 1; value.record_silent(data, initial)
        value = peer(); value.connection = object()
        with self.assertRaisesRegex(RuntimeError, 'engine-free'): value.record_silent(INITIALS[0], True)

    def test_synthetic_native_deadline_calibrates(self):
        result = self.check(*proof())
        self.assertEqual(result['actual_outcome'], 'Native')

    def test_peer_send_or_engine_event_refuses(self):
        for mutation in ('send-event', 'tx-count', 'handshake', 'wire-peer', 'terminated', 'certificate', 'authenticated'):
            output, fixture, wire = proof()
            if mutation == 'send-event':
                fixture['events'].append(dict(event='udp-send', bytes=41, sha256='b' * 64, source=list(PEER_TUPLE), destination=list(GUEST)))
            elif mutation == 'tx-count': fixture.update(tx_datagrams=1, tx_bytes=41)
            elif mutation == 'handshake': fixture['events'].append(dict(event='handshake'))
            elif mutation == 'wire-peer':
                wire['peer_udp'].append(dict(bytes=41, sha256='b' * 64, source=list(PEER_TUPLE), destination=list(GUEST)))
            elif mutation == 'terminated': fixture['terminated'] = {'error_code': 0}
            elif mutation == 'certificate': fixture['certificate_selection'] = {'kind': 'valid'}
            else: fixture['authenticated'] = True
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_receipt_census_capture_and_initial_identity_refuse(self):
        for mutation in ('missing-silent', 'ordinal', 'delivered', 'initial-hash', 'capture-hash', 'capture-extra', 'short-header', 'rx-count'):
            output, fixture, wire = proof()
            silent = [row for row in fixture['events'] if row['event'] == 'silent-input']
            if mutation == 'missing-silent': fixture['events'].remove(silent[-1])
            elif mutation == 'ordinal': silent[1]['receive_ordinal'] = 3
            elif mutation == 'delivered': silent[0]['engine_delivered'] = True
            elif mutation == 'initial-hash': next(r for r in fixture['events'] if r['event'] == 'initial-observed')['sha256'] = 'c' * 64
            elif mutation == 'capture-hash': wire['guest_udp'][2]['sha256'] = 'c' * 64
            elif mutation == 'capture-extra': wire['guest_udp'].append(copy.deepcopy(wire['guest_udp'][0]))
            elif mutation == 'short-header': wire['guest_udp'][1]['first_byte'] = 0x47
            else: fixture['rx_datagrams'] = 3
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_native_deadline_transport_input_and_send_ledger_refuse(self):
        cases = {'idle-close': ('transport_error_code=none transport_close_origin=none', 'transport_error_code=1 transport_close_origin=local'),
                 'early-end': ('end_ms=10011', 'end_ms=10009'),
                 'late-end': ('end_ms=10011', 'end_ms=11011'),
                 'other-deadline': ('start_ms=10 deadline_ms=10010 grant_expiry_ms=15001\nQUIC BEGIN', 'start_ms=10 deadline_ms=9000 grant_expiry_ms=15001\nQUIC BEGIN'),
                 'received': ('received=0 receive_bytes=0', 'received=1 receive_bytes=41'),
                 'other-kind': ('native_failure_kind=Deadline', 'native_failure_kind=Cancelled'),
                 'complete': ('outcome=Native', 'outcome=Complete'),
                 'accepted-count': ('send_accepted=4 ', 'send_accepted=5 ')}
        for name, (old, new) in cases.items():
            output, fixture, wire = proof(); self.assertIn(old, output); output = output.replace(old, new, 1)
            with self.subTest(mutation=name), self.assertRaises(RuntimeError): self.check(output, fixture, wire)
        output, fixture, wire = proof()
        output += '\n' + line('QUIC FIXTURE RX', dict(case='Q07', ordinal=1, at_ms=50, bytes=41, peer_ip='10.0.2.2', peer_port=4443, sha256='b' * 64))
        with self.assertRaisesRegex(RuntimeError, 'Q07 native silence'): self.check(output, fixture, wire)
        for mutation in ('bytes', 'missing', 'hash'):
            output, fixture, wire = proof(); rows = output.split('\n')
            index = max(i for i, row in enumerate(rows) if row.startswith('QUIC FIXTURE SEND'))
            if mutation == 'bytes': rows[index] = rows[index].replace('bytes=1200', 'bytes=1199')
            elif mutation == 'missing': del rows[index]
            else: rows[index] += ' sha256=' + 'd' * 64
            with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError, 'Q07 native Initial SEND ledger'):
                self.check('\n'.join(rows), fixture, wire)

    def test_idle_timeout_shaped_report_refuses(self):
        # engine.rs maps Quinn ConnectionLost (including idle TimedOut) to
        # Outcome::Protocol, never to native failure kind Deadline.
        output, fixture, wire = proof()
        output = output.replace('outcome=Native', 'outcome=Protocol', 1).replace('native_failure_kind=Deadline', 'native_failure_kind=none', 1)
        output = output.replace('end_ms=10011', 'end_ms=10050', 1)
        with self.assertRaisesRegex(RuntimeError, 'actual native outcome differs'): self.check(output, fixture, wire)
        output, fixture, wire = proof(); output = output.replace('end_ms=10011', 'end_ms=11011', 1)
        with self.assertRaisesRegex(RuntimeError, 'Q07 native silence'): self.check(output, fixture, wire)
        output, fixture, wire = proof(); output = output.replace('end_ms=10011', 'end_ms=11010', 1); self.check(output, fixture, wire)

    def test_runner_tables_admit_q07(self):
        # The runner's argparse choices and profile-to-case map, and the Linux
        # fault-establishment event, must all name Q07 (two earlier VM
        # attempts refused at these tables before any Q07 execution).
        source = (ROOT / 'native-quic-q01.py').read_text()
        self.assertIn("'q07-silent-development'", source[source.index("parser.add_argument('--profile'"):][:1200])
        self.assertEqual(MATRIX.select_development_cases({CASE['id']: CASE}, 'q07-silent-development', 'ipv4', False, []),
                         (['Q07'], ['Q07'], 'q07-silent-development'))
        self.assertIn("'Q07':'silent-input'", source[source.index('required_event = {'):][:600])
        self.assertIn("if case['id'] not in ('Q17', 'Q07', 'Q14', 'Q21', 'Q23', 'Q24', 'Q25', 'Q26', 'Q27', 'Q28', 'Q29', 'Q30', 'Q31'):\n        verify_certificate_selection", source)
        self.assertEqual(PEER.peer_certificate(CASE), 'valid')

    def test_wire_classifier_admits_q07_only_with_an_empty_peer_direction(self):
        observed = WIRE.observe(BASE.pcap([guest_initial(INITIALS[0]), guest_initial(INITIALS[1])]), CASE, GUEST_MAC, PEER_MAC)
        self.assertEqual((len(observed['guest_udp']), observed['peer_udp']), (2, []))
        self.assertEqual(observed['guest_udp'][0]['sha256'], digest(INITIALS[0]))
        with self.assertRaises(WIRE.Refusal):
            WIRE.observe(BASE.pcap([guest_initial(INITIALS[0]), peer_reply(b'\x40' + bytes(40))]), CASE, GUEST_MAC, PEER_MAC)
        with self.assertRaises(WIRE.Refusal):
            WIRE.observe(BASE.pcap([guest_initial(INITIALS[0])]), dict(CASE, local_port=7800), GUEST_MAC, PEER_MAC)
        q01 = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q01')
        with self.assertRaises(WIRE.Refusal):
            WIRE.observe(BASE.pcap([udp_frame(GUEST_MAC, PEER_MAC, '10.0.2.15', '10.0.2.2', 7800, 4443, INITIALS[0])]), q01, GUEST_MAC, PEER_MAC)

    def test_child_must_exit_normally(self):
        for old, new in (('kind=1 status=0', 'kind=1 status=1'), ('killed=false', 'killed=true'), ('kind=1 status=0', 'kind=3 status=0')):
            output, fixture, wire = proof(); output = output.replace(old, new, 1)
            with self.subTest(change=new), self.assertRaisesRegex(RuntimeError, 'Q07 child did not exit normally'): self.check(output, fixture, wire)
        output, fixture, wire = proof(); output = '\n'.join(r for r in output.split('\n') if not r.startswith('QUIC CHILD EXIT'))
        with self.assertRaisesRegex(RuntimeError, 'Q07 child did not exit normally'): self.check(output, fixture, wire)

    def test_linux_control_census_uses_the_same_peer_predicate(self):
        _, fixture, _ = proof(); self.assertEqual(len(MATRIX.verify_silent(fixture)), 4)
        fixture['events'].append(dict(event='udp-send', bytes=41, sha256='b' * 64))
        with self.assertRaises(RuntimeError): MATRIX.verify_silent(fixture)


if __name__ == '__main__':
    unittest.main()
