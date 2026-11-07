#!/usr/bin/env python3
"""Finite Q14 overlong-Retry controls: peer Retry/receipt census and native deadline evidence, not protocol runs."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('q14_base', ROOT/'native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(BASE)
MATRIX, PEER, MANIFEST, WIRE = BASE.MATRIX, BASE.PEER_MODULE, BASE.MANIFEST, BASE.WIRE
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q14')
GUEST, PEER_TUPLE = ['10.0.2.15', 7813], ['10.0.2.2', 4443]
ODCID, CSCID, RSCID = bytes(range(1, 9)), bytes(range(0x30, 0x38)), bytes(range(0xa0, 0xb5))
INITIALS = [bytes([0xc7]) + bytes([i]) * 1199 for i in range(1, 6)]
# Structure only: the peer's actual aioquic encoder computes and verifies the real tag.
RETRY = b'\xf0\x00\x00\x00\x01' + bytes([len(CSCID)]) + CSCID + bytes([21]) + RSCID + b'absd-q14-retry-token' + b'\x77' * 16

def digest(data): return hashlib.sha256(data).hexdigest()
def line(prefix, row): return prefix + ' ' + ' '.join(key + '=' + str(value) for key, value in row.items())


def proof(count=5):
    report = {field: '0' for field in MANIFEST['report']['fields']}
    report.update(case='Q14', outcome='Native', authenticated='false', sent_stream='0', received_stream='0',
        request_fin='false', peer_fin='false', request_acked='false', connection_drained='false',
        close_accepted='true', pipe_fenced='true', unknown_send='false', native_failure_kind='Deadline',
        native_error_code='none', native_error_detail='none', transport_error_code='none',
        transport_close_origin='none', entropy_attempts='1', engine_transmits=str(count), send_calls=str(count),
        send_accepted=str(count), send_bytes=str(1200 * count), received='1', receive_bytes=str(len(RETRY)),
        last_send_ms='8000', fence_ms='10011', start_ms='10', end_ms='10011', deadline_ms='10010', grant_expiry_ms='15001')
    rows = [line('QUIC SERVICE SELECTOR', dict(case='Q14', local_port=7813)),
            line('QUIC SERVICE DONE', dict(case='Q14', sockets=0, **{n + '_' + w: 1 for n in ('processes', 'handles', 'pipes', 'cells') for w in ('before', 'after')})),
            line('QUIC SERVICE GRANT', dict(case='Q14', before_ms=1, constructed_ms=2, owner_expiry_ms=15001, local_port=7813, peer_port=4443)),
            line('QUIC CPU', dict(vendor='GenuineIntel', leaf1_eax=0x306c0, leaf1_ecx=1 << 30, family=6, model=60, rdrand=1)),
            line('QUIC RESULT', report),
            line('QUIC BEGIN', dict(case='Q14', start_ms=10, deadline_ms=10010, grant_expiry_ms=15001)),
            line('QUIC CHILD EXIT', dict(case='Q14', kind=1, status=0, killed='false')),
            line('QUIC FIXTURE RX', dict(case='Q14', ordinal=1, at_ms=40, bytes=len(RETRY), peer_ip='10.0.2.2', peer_port=4443, sha256=digest(RETRY)))]
    for ordinal in range(1, count + 1):
        rows.append(line('QUIC FIXTURE SEND', dict(case='Q14', ordinal=ordinal, at_ms=20 + 1000 * ordinal, bytes=1200, peer_ip='10.0.2.2', peer_port=4443)))
    events = []
    for ordinal, data in enumerate(INITIALS[:count], 1):
        events.append(dict(event='udp-receive', bytes=1200, sha256=digest(data), source=list(GUEST)))
        if ordinal == 1:
            events.append(dict(event='initial-observed', bytes=1200, sha256=digest(data), receive_ordinal=1))
        events.append(dict(event='silent-input', receive_ordinal=ordinal, bytes=1200, sha256=digest(data), engine_delivered=False,
                           dcid_hex=ODCID.hex(), scid_hex=CSCID.hex(), token_bytes=0))
        if ordinal == 1:
            events.append(dict(event='retry-fixture', source_cid_bytes=21, integrity_verified=True, bytes=len(RETRY), sha256=digest(RETRY),
                               data_hex=RETRY.hex(), original_destination_cid_hex=ODCID.hex(), destination_cid_hex=CSCID.hex(),
                               source_cid_hex=RSCID.hex()))
            events.append(dict(event='udp-send', bytes=len(RETRY), sha256=digest(RETRY), source=list(PEER_TUPLE),
                               destination=list(GUEST), fixture='long-retry'))
    fixture = dict(case='Q14', mode='long-retry', readiness_profile='q14-long-retry-development', canonical_campaign_acceptance=False,
                   authenticated=False, request_bytes=0, echo_enqueued_bytes=0, request_fin=False, echo_fin_enqueued=False,
                   terminated=None, errors=[], thread_alive=False, rx_datagrams=count, tx_datagrams=1,
                   rx_bytes=1200 * count, tx_bytes=len(RETRY), events=events, certificate_selection=None)
    wire = dict(guest_udp=[dict(ordinal=i, bytes=1200, sha256=digest(d), source=list(GUEST), destination=list(PEER_TUPLE), first_byte=d[0])
                           for i, d in enumerate(INITIALS[:count], 1)],
                peer_udp=[dict(bytes=len(RETRY), sha256=digest(RETRY), source=list(PEER_TUPLE), destination=list(GUEST), first_byte=RETRY[0])],
                guest_udp_count=count)
    return '\n'.join(rows), fixture, wire


class Socket:
    def __init__(self): self.sent = []
    def getsockname(self): return ('10.0.2.2', 4443)
    def sendto(self, data, destination): self.sent.append(data); return len(data)


def peer():
    value = object.__new__(PEER.Peer); value.case, value.mode, value.family = CASE, CASE['peer_mode'], 'ipv4'
    value.connection = value.initial_sha256 = value.retry_bytes = None; value.tx_packets = value.rx_packets = value.tx_bytes = 0
    value.one_response_flight = value.response_flight_sealed = False; value.expected_source = tuple(GUEST)
    value.socket, value.lock, value.events = Socket(), threading.Lock(), []
    return value


TAG = {'value': RETRY[-16:]}
MATRIX.retry_integrity_tag = lambda packet, odcid: TAG['value'] if (packet, odcid) == (RETRY[:-16], ODCID) else b'\0' * 16


class LongRetryControls(unittest.TestCase):
    def check(self, output, fixture, wire): return MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)

    def test_recomputed_integrity_tag_decides_not_the_peer_flag(self):
        try:
            TAG['value'] = b'\x55' * 16
            with self.assertRaisesRegex(RuntimeError, 'recomputed integrity tag'): self.check(*proof())
        finally:
            TAG['value'] = RETRY[-16:]
        output, fixture, wire = proof()
        next(r for r in fixture['events'] if r['event'] == 'retry-fixture')['original_destination_cid_hex'] = 'ff' * 8
        with self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_child_must_exit_normally(self):
        for old, new in (('kind=1 status=0', 'kind=1 status=1'), ('killed=false', 'killed=true'), ('kind=1 status=0', 'kind=3 status=0')):
            output, fixture, wire = proof(); output = output.replace(old, new, 1)
            with self.subTest(change=new), self.assertRaisesRegex(RuntimeError, 'Q14 child did not exit normally'): self.check(output, fixture, wire)

    def test_a_later_initial_queued_before_the_retry_receipt_does_not_count(self):
        # Every native SEND precedes the Retry RX: a crash on the Retry would look like this.
        output, fixture, wire = proof()
        output = output.replace('QUIC FIXTURE RX case=Q14 ordinal=1 at_ms=40', 'QUIC FIXTURE RX case=Q14 ordinal=1 at_ms=9000', 1)
        with self.assertRaisesRegex(RuntimeError, 'no native Initial SEND after the native Retry receipt'): self.check(output, fixture, wire)
        output, fixture, wire = proof()
        output = output.replace('QUIC FIXTURE RX case=Q14 ordinal=1 at_ms=40', 'QUIC FIXTURE RX case=Q14 ordinal=1 at_ms=4019', 1); self.check(output, fixture, wire)

    def test_exact_selector_port_and_tables(self):
        self.assertEqual(PEER.development_profile(CASE), 'q14-long-retry-development')
        self.assertEqual(MATRIX.development_profile(CASE), 'q14-long-retry-development')
        with self.assertRaises(RuntimeError): PEER.development_profile(dict(CASE, local_port=7800))
        source = (ROOT / 'native-quic-q01.py').read_text()
        self.assertIn("'q14-long-retry-development'", source[source.index("parser.add_argument('--profile'"):][:1400])
        self.assertEqual(MATRIX.select_development_cases({CASE['id']: CASE}, 'q14-long-retry-development', 'ipv4', False, []),
                         (['Q14'], ['Q14'], 'q14-long-retry-development'))
        self.assertIn("'Q14':'retry-fixture'", source[source.index('required_event = {'):][:700])
        self.assertIn("if case['id'] not in ('Q17', 'Q07', 'Q14', 'Q21', 'Q23', 'Q24', 'Q25', 'Q26', 'Q27', 'Q28', 'Q29', 'Q30', 'Q31'):", source)

    def test_synthetic_native_deadline_after_ignored_retry_calibrates(self):
        self.assertEqual(self.check(*proof())['actual_outcome'], 'Native')

    def test_peer_send_fixture_tag_admits_only_the_recorded_retry(self):
        value = peer(); value.retry_bytes = RETRY; value.send(RETRY, fixture='long-retry')
        self.assertEqual(value.socket.sent, [RETRY])
        for other in (RETRY + b'x', INITIALS[0][:100]):
            value = peer(); value.retry_bytes = RETRY
            with self.subTest(size=len(other)), self.assertRaisesRegex(RuntimeError, 'fixture tag'): value.send(other, fixture='long-retry')
        value = peer(); value.retry_bytes = RETRY; value.tx_packets = 1
        with self.assertRaisesRegex(RuntimeError, 'fixture tag'): value.send(RETRY, fixture='long-retry')

    def test_peer_receipt_records_cids_and_allows_one_retry_only(self):
        value = peer(); value.rx_packets = 1
        value.record_silent(INITIALS[0], True, ODCID, CSCID, b'')
        value.tx_packets = 1; value.rx_packets = 2
        value.record_silent(INITIALS[1], True, ODCID, CSCID, b'')
        rows = [row for row in value.events if row['event'] == 'silent-input']
        self.assertEqual([(r['dcid_hex'], r['scid_hex'], r['token_bytes']) for r in rows], [(ODCID.hex(), CSCID.hex(), 0)] * 2)
        value.tx_packets = 2
        with self.assertRaisesRegex(RuntimeError, 'engine-free'): value.record_silent(INITIALS[2], True, ODCID, CSCID, b'')

    def test_retry_structure_and_identity_refuse(self):
        def retry_event(f): return next(r for r in f['events'] if r['event'] == 'retry-fixture')
        def set_retry(f, w, data):
            r = retry_event(f); r.update(data_hex=data.hex(), bytes=len(data), sha256=digest(data))
            s = next(x for x in f['events'] if x['event'] == 'udp-send'); s.update(bytes=len(data), sha256=digest(data))
            f['tx_bytes'] = len(data); w['peer_udp'][0].update(bytes=len(data), sha256=digest(data))
        mutations = {
            'scid-20': lambda f, w: set_retry(f, w, RETRY[:15] + bytes([20]) + RSCID[:20] + RETRY[37:]),
            'not-retry-type': lambda f, w: set_retry(f, w, b'\xe0' + RETRY[1:]),
            'version-2': lambda f, w: set_retry(f, w, RETRY[:4] + b'\x02' + RETRY[5:]),
            'wrong-dcid': lambda f, w: retry_event(f).update(destination_cid_hex='00' * 8),
            'wrong-odcid': lambda f, w: retry_event(f).update(original_destination_cid_hex='00' * 8),
            'integrity-false': lambda f, w: retry_event(f).update(integrity_verified=False),
            'no-tag-room': lambda f, w: set_retry(f, w, RETRY[:37]),
            'untagged-send': lambda f, w: next(x for x in f['events'] if x['event'] == 'udp-send').pop('fixture'),
            'two-retries': lambda f, w: f['events'].append(copy.deepcopy(retry_event(f))),
            'wire-extra-peer': lambda f, w: w['peer_udp'].append(copy.deepcopy(w['peer_udp'][0])),
            'no-later-initial': lambda f, w: None,
        }
        for name, mutate in mutations.items():
            output, fixture, wire = proof(1 if name == 'no-later-initial' else 5)
            mutate(fixture, wire)
            with self.subTest(mutation=name), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_client_that_follows_the_retry_refuses(self):
        for change in ({'dcid_hex': RSCID.hex()}, {'token_bytes': 20}, {'scid_hex': '11' * 8}):
            output, fixture, wire = proof()
            later = [r for r in fixture['events'] if r['event'] == 'silent-input'][2]; later.update(change)
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'keep its original Initial'): self.check(output, fixture, wire)

    def test_native_retry_receipt_deadline_and_send_ledger_refuse(self):
        cases = {'no-rx': ('received=1 receive_bytes=', 'received=0 receive_bytes='),
                 'idle-close': ('transport_error_code=none transport_close_origin=none', 'transport_error_code=1 transport_close_origin=local'),
                 'late-end': ('end_ms=10011', 'end_ms=11011'), 'early-end': ('end_ms=10011', 'end_ms=10009'),
                 'protocol': ('outcome=Native', 'outcome=Protocol'),
                 'rx-hash': ('sha256=' + digest(RETRY), 'sha256=' + 'e' * 64),
                 'accepted': ('send_accepted=5 ', 'send_accepted=6 ')}
        for name, (old, new) in cases.items():
            output, fixture, wire = proof(); self.assertIn(old, output); output = output.replace(old, new, 1)
            with self.subTest(mutation=name), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_wire_classifier_admits_q14_with_the_retry_direction(self):
        from importlib import util
        spec = util.spec_from_file_location('q07_frames', ROOT / 'test-native-quic-silent.py'); frames = util.module_from_spec(spec); spec.loader.exec_module(frames)
        guest = frames.udp_frame(frames.GUEST_MAC, frames.PEER_MAC, '10.0.2.15', '10.0.2.2', 7813, 4443, INITIALS[0])
        reply = frames.udp_frame(frames.PEER_MAC, frames.GUEST_MAC, '10.0.2.2', '10.0.2.15', 4443, 7813, RETRY)
        observed = WIRE.observe(BASE.pcap([guest, reply]), CASE, frames.GUEST_MAC, frames.PEER_MAC)
        self.assertEqual([r['sha256'] for r in observed['peer_udp']], [digest(RETRY)])
        with self.assertRaises(WIRE.Refusal): WIRE.observe(BASE.pcap([guest]), CASE, frames.GUEST_MAC, frames.PEER_MAC)

    def test_linux_control_uses_the_same_peer_predicate(self):
        _, fixture, _ = proof(); self.assertEqual(MATRIX.verify_long_retry(fixture), RETRY)


if __name__ == '__main__':
    unittest.main()
