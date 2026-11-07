#!/usr/bin/env python3
"""Synthetic Q25/Q26/Q28 inputs for the actual peer and native checkers.

Run only on the owned test host with the pinned peer closure. The independent
literal Ethernet/IP/UDP/ICMP vectors exercise full artifact correspondence;
the serial records exercise the real runner oracle. They are not native
execution, ICMP origin authentication, or a shared host/guest clock witness.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import unittest

ROOT = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


MATRIX = module('icmp_artifact_matrix', 'native-quic-q01.py')
WIRE = module('icmp_artifact_wire', 'native-quic-wire.py')
MANIFEST = json.loads((ROOT.parent / 'quic/CASES.json').read_text())
CASES = {row['id']: row for row in MANIFEST['native_occurrences']}
IDENTITIES = ('Q25', 'Q26', 'Q28')
GM, PM = '52:54:00:12:34:56', '02:71:00:00:00:02'
# Header-parser-valid QUICv1 Initial, with no ciphertext validity claim.
PREFIX = b'\xc0\x00\x00\x00\x01\x08DCIDICMP\x08SCIDICMP\x00\x44\x96'
INITIAL = PREFIX + b'i' * (1200 - len(PREFIX))


def digest(value):
    return hashlib.sha256(value).hexdigest()


def checksum(value):
    """Independent Internet checksum; do not use the peer's frame encoder."""
    if len(value) % 2:
        value += b'\0'
    total = sum(int.from_bytes(value[i:i + 2], 'big') for i in range(0, len(value), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def original(identity, data=INITIAL, identification=1):
    source, destination = socket.inet_aton('10.0.2.15'), socket.inet_aton('10.0.2.2')
    udp = struct.pack('!HHHH', CASES[identity]['local_port'], 4443, len(data) + 8, 0) + data
    value = checksum(source + destination + b'\0\x11' + struct.pack('!H', len(udp)) + udp) or 65535
    udp = udp[:6] + struct.pack('!H', value) + udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp) + 20, identification,
                     0x4000, 64, 17, 0, source, destination)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex(PM.replace(':', '')) + bytes.fromhex(GM.replace(':', '')) + b'\x08\x00' + ip + udp


def advice(quoted, mtu):
    body = struct.pack('!BBHHH', 3, 4, 0, 0, mtu) + quoted[14:42]
    body = body[:2] + struct.pack('!H', checksum(body)) + body[4:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 56, 0x5149, 0, 64, 1, 0,
                     socket.inet_aton('10.0.2.2'), socket.inet_aton('10.0.2.15'))
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex(GM.replace(':', '')) + bytes.fromhex(PM.replace(':', '')) + b'\x08\x00' + ip + body


def pcap(frames):
    result = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        result += struct.pack('<IIII', 1, index, len(frame), len(frame)) + frame
    return result


def line(prefix, **values):
    return prefix + ' ' + ' '.join(key + '=' + str(value) for key, value in values.items())


def change(output, prefix, index=0, **values):
    rows = output.splitlines()
    selected = [i for i, row in enumerate(rows) if row.startswith(prefix + ' case=')]
    record = MATRIX.fields(rows[selected[index]])
    record.update({key: str(value) for key, value in values.items()})
    rows[selected[index]] = line(prefix, **record)
    return '\n'.join(rows)


def event(fixture, name):
    rows = [row for row in fixture['events'] if row['event'] == name]
    assert len(rows) == 1
    return rows[0]


def proof(identity='Q25', code=14, outgoing_copy=True, raw_first=False):
    """Complete synthetic witness, built independently of the peer methods."""
    case = CASES[identity]
    submitted = original(identity)
    emitted = advice(submitted, case['icmp_mtu'])
    packet = dict(receive_ordinal=1, bytes=1200, sha256=digest(INITIAL), data_hex=INITIAL.hex(),
                  source=['10.0.2.15', case['local_port']], destination=['10.0.2.2', 4443])
    raw = dict(raw_frame_ordinal=1, bytes=len(submitted), sha256=digest(submitted),
               frame_hex=submitted.hex(), interface='fixture0', packet_type=0)
    trigger = dict(packet, raw_frame_ordinal=1, submitted_frame_sha256=digest(submitted),
                   frame_hex=submitted.hex(), quote_hex=submitted[14:42].hex())
    result = dict(bytes=70, sha256=digest(emitted), frame_hex=emitted.hex(),
                  icmp_hex=emitted[34:].hex(), mtu=case['icmp_mtu'], quote_hex=submitted[14:42].hex(),
                  submitted_frame_sha256=digest(submitted), trigger_receive_ordinal=1,
                  trigger_raw_frame_ordinal=1, trigger_sha256=digest(INITIAL))
    events = [dict(packet, event='udp-receive', engine_delivered=False),
              dict(packet, event='initial-observed'),
              dict(packet, event='icmp-input', engine_delivered=False),
              dict(raw, event='icmp-frame-receive'),
              dict(result, event='icmp-send-begin'),
              dict(result, event='icmp-send', actual_sent_bytes=70)]
    if raw_first:
        events.insert(0, events.pop(3))
    if outgoing_copy:
        events.append(dict(event='icmp-frame-receive', raw_frame_ordinal=2,
                           bytes=70, sha256=digest(emitted), frame_hex=emitted.hex(),
                           interface='fixture0', packet_type=4))
    events.append(dict(event='peer-ended', stopped=True, deadline_reached=False))
    # Host event clocks are intentionally unrelated to guest milliseconds.
    for index, row in enumerate(events):
        row.update(monotonic_ns=9_000_000_000 + index * 1000,
                   wall_time_ns=1_800_000_000_000_000_000 + index * 1000, time=index / 1000)
    fixture = dict(schema_version=1, case=identity, mode=case['peer_mode'], transport_family='ipv4',
        readiness_profile=MATRIX.development_profile(case), canonical_campaign_acceptance=False,
        icmp_policy='q25-q26-q28-literal-quote-v1', engine_constructed=False,
        icmp_interface='fixture0', icmp_guest_mac=GM, icmp_peer_mac=PM, raw_socket_closed=True,
        raw_rx_frames=2 if outgoing_copy else 1, raw_rx_bytes=1312 if outgoing_copy else 1242,
        icmp_send_attempted=True, icmp_send_completed=True, icmp_failed=False,
        icmp_send_result=dict(result, actual_sent_bytes=70), icmp_trigger=trigger,
        errors=[], thread_alive=False, certificate_selection=None, authenticated=False,
        request_bytes=0, request_sha256=digest(b''), request_fin=False,
        echo_enqueued_bytes=0, echo_fin_enqueued=False, terminated=None,
        rx_datagrams=1, rx_bytes=1200, tx_datagrams=0, tx_bytes=0,
        initial_drops=0, private_material_included=False, peer_policy='standard',
        response_flight_sealed=False, events=events)
    wire = WIRE.observe(pcap([submitted, emitted]), case, GM, PM)
    sends = 2 if code == 15 else 1
    detail = case['icmp_mtu'] - 28 if code == 15 else case['icmp_mtu']
    report = {key: '0' for key in MANIFEST['report']['fields']}
    report.update(case=identity, outcome='Native', phase='Fenced',
        **{key: 'false' for key in ('authenticated', 'request_fin', 'peer_fin', 'request_acked',
                                   'connection_drained', 'close_accepted', 'unknown_send')},
        pipe_fenced='true', no_native_pair='false', native_failure_kind='Native',
        native_error_code=str(code), native_error_detail=str(detail), transport_error_code='none',
        transport_close_origin='none', engine_transmits=str(sends), send_calls=str(sends),
        send_accepted='1', send_bytes='1200', receive_calls='2', close_calls='0', entropy_attempts='1',
        pending_exhausted_sha256='none', pending_retry_sha256='none',
        start_ms='10', end_ms='80', deadline_ms='10010', grant_expiry_ms='15001',
        last_send_ms='52' if code == 15 else '32', fence_ms='75',
        partial_pipe_reads='0', partial_pipe_writes='0')
    rows = [line('QUIC SERVICE SELECTOR', case=identity, local_port=case['local_port']),
            line('QUIC SERVICE GRANT', case=identity, before_ms=1, constructed_ms=2,
                 owner_expiry_ms=15001, local_port=case['local_port'], peer_port=4443),
            line('QUIC FIXTURE SEND', case=identity, ordinal=1, at_ms=30, bytes=1200,
                 sha256=digest(INITIAL), peer_ip='10.0.2.2', peer_port=4443)]
    if code == 15:
        # A complete request is observed before native SEND fails; it is not
        # another captured datagram, accepted completion, or wire receipt.
        rows.append(line('QUIC FIXTURE SEND', case=identity, ordinal=2, at_ms=50, bytes=1200,
                         sha256=digest(INITIAL), peer_ip='10.0.2.2', peer_port=4443))
    rows += [line('QUIC FIXTURE NATIVE_COUNTS', case=identity, at_ms=85, send_requests=sends,
                  receive_delivered=0, sends_after_owner_expiry=0, partial_request_bytes=0, partial_reply_bytes=0),
             line('QUIC CHILD AUTHORITY RETIRED', case=identity, reaped_ms=90, retired_ms=91,
                  process_handle_live='false', pipe_live='false', grant_live='false', sockets=0,
                  result_eof='true', owner_expired='false'),
             line('QUIC CHILD EXIT', case=identity, kind=1, status=0, killed='false'),
             'QUIC CONSUMER case=' + identity + ' begin',
             line('QUIC CPU', vendor='GenuineIntel', family=6, model=60, leaf1_eax=0x306c0,
                  leaf1_ecx=1 << 30, rdrand=1),
             line('QUIC BEGIN', case=identity, start_ms=10, deadline_ms=10010,
                  grant_expiry_ms=15001, unix_time='Some(1792282393)', native_pair='true', body_len=4096),
             line('QUIC PHASE', case=identity, phase='Init', at_ms=10),
             line('QUIC PHASE', case=identity, phase='Handshake', at_ms=20),
             line('QUIC PHASE', case=identity, phase='Fenced', at_ms=76),
             line('QUIC RESULT', **report),
             'QUIC CONSUMER case=' + identity + ' end',
             line('QUIC SERVICE RETIRE', case=identity, sockets_before_fence=0, sockets_after_fence=0),
             line('QUIC SERVICE DONE', case=identity, sockets=0,
                  **{name + '_' + when: 1 for name in ('processes', 'handles', 'pipes', 'cells')
                     for when in ('before', 'after')})]
    return '\n'.join(rows), fixture, wire


def later_initial(output, fixture, identity='Q25'):
    """Retain a second socket/frame input, without a second ICMP action."""
    changed = copy.deepcopy(fixture)
    data = INITIAL[:-1] + b'j'
    frame = original(identity, data, identification=2)
    packet = dict(receive_ordinal=2, bytes=1200, sha256=digest(data), data_hex=data.hex(),
                  source=['10.0.2.15', CASES[identity]['local_port']], destination=['10.0.2.2', 4443])
    additions = [dict(packet, event='udp-receive', engine_delivered=False),
                 dict(packet, event='icmp-input', engine_delivered=False),
                 dict(event='icmp-frame-receive', raw_frame_ordinal=changed['raw_rx_frames'] + 1,
                      bytes=len(frame), sha256=digest(frame), frame_hex=frame.hex(),
                      interface='fixture0', packet_type=0)]
    changed['events'][-1:-1] = additions
    for index, row in enumerate(changed['events']):
        row.update(monotonic_ns=9_000_000_000 + index * 1000,
                   wall_time_ns=1_800_000_000_000_000_000 + index * 1000, time=index / 1000)
    changed.update(rx_datagrams=2, rx_bytes=2400, raw_rx_frames=changed['raw_rx_frames'] + 1,
                   raw_rx_bytes=changed['raw_rx_bytes'] + len(frame))
    rows = output.splitlines()
    index = next(i for i, row in enumerate(rows) if row.startswith('QUIC FIXTURE NATIVE_COUNTS '))
    rows.insert(index, line('QUIC FIXTURE SEND', case=identity, ordinal=2, at_ms=50, bytes=1200,
                            sha256=digest(data), peer_ip='10.0.2.2', peer_port=4443))
    output = change('\n'.join(rows), 'QUIC FIXTURE NATIVE_COUNTS', send_requests=2)
    output = change(output, 'QUIC RESULT', engine_transmits=2, send_calls=2,
                    send_accepted=2, send_bytes=2400, last_send_ms=52)
    wire = WIRE.observe(pcap([original(identity), advice(original(identity), CASES[identity]['icmp_mtu']), frame]),
                        CASES[identity], GM, PM)
    return output, changed, wire


class ICMPArtifactControls(unittest.TestCase):
    def check(self, output, fixture, wire, identity='Q25'):
        return MATRIX.verify_native(CASES[identity], output, fixture, wire, MANIFEST)

    def refused(self, output, fixture, wire, identity='Q25'):
        with self.assertRaises(RuntimeError):
            self.check(output, fixture, wire, identity)

    def test_complete_literal_peer_and_native14_for_all_selected_cases(self):
        for identity in IDENTITIES:
            for outgoing in (False, True):
                for raw_first in (False, True):
                    with self.subTest(case=identity, outgoing_copy=outgoing, raw_first=raw_first):
                        output, fixture, wire = proof(identity, outgoing_copy=outgoing, raw_first=raw_first)
                        observed = self.check(output, fixture, wire, identity)
                        self.assertEqual(observed['actual_outcome'], 'Native')
                        self.assertEqual(observed['typed_report']['native_error_code'], '14')
                        self.assertEqual(MATRIX.verify_icmp_peer(CASES[identity], fixture, wire)['mtu'],
                                         CASES[identity]['icmp_mtu'])

    def test_later_initial_remains_fully_accounted_without_repeating_icmp(self):
        for identity in IDENTITIES:
            output, fixture, _ = proof(identity)
            output, fixture, wire = later_initial(output, fixture, identity)
            with self.subTest(case=identity):
                self.assertEqual(self.check(output, fixture, wire, identity)['actual_outcome'], 'Native')
                self.assertEqual(len(wire['guest_udp']), 2)
                self.assertEqual(len(wire['icmp']), 1)
                self.assertEqual(fixture['icmp_trigger']['receive_ordinal'], 1)

    def test_complete_send_order_is_bound_to_distinct_captured_initials(self):
        output, fixture, _ = proof()
        output, fixture, wire = later_initial(output, fixture)
        first, second = [MATRIX.fields(row) for row in output.splitlines()
                         if row.startswith('QUIC FIXTURE SEND ')]
        changed = change(output, 'QUIC FIXTURE SEND', 0, sha256=second['sha256'])
        changed = change(changed, 'QUIC FIXTURE SEND', 1, sha256=first['sha256'])
        self.refused(changed, fixture, wire)
        changed = copy.deepcopy(fixture)
        changed['events'][-2]['frame_hex'] = original('Q25').hex()
        changed['events'][-2]['sha256'] = digest(original('Q25'))
        self.refused(output, changed, wire)

    def test_complete_failed_send15_uses_mtu_minus28_without_another_wire_packet(self):
        for identity, maximum in (('Q25', 548), ('Q26', 1199)):
            with self.subTest(case=identity):
                output, fixture, wire = proof(identity, code=15)
                result = self.check(output, fixture, wire, identity)
                self.assertEqual(result['typed_report']['native_error_detail'], str(maximum))
                self.assertEqual(result['typed_report']['send_accepted'], '1')
                self.assertEqual(len(wire['guest_udp']), 1)

    def test_exact_profiles_and_no_q27_or_ipv6_selection(self):
        for identity, profile in zip(IDENTITIES, ('q25-icmp-576-development',
                'q26-icmp-1227-development', 'q28-icmp-zero-development')):
            self.assertEqual(MATRIX.development_profile(CASES[identity]), profile)
            self.assertEqual(MATRIX.peer_control_cases(CASES[identity]), ['Q01'])
            with self.assertRaises(RuntimeError):
                MATRIX.development_profile(CASES[identity], 'ipv6')
        with self.assertRaises(RuntimeError):
            MATRIX.development_profile(dict(CASES['Q27'], peer_mode='icmp-1228', icmp_mtu=1228))

    def test_selected_case_object_mutations_refuse(self):
        for identity in IDENTITIES:
            case = CASES[identity]
            for key, value in (('local_port', 7800), ('icmp_mtu', 1228), ('peer_mode', 'echo'),
                    ('expected_outcome', 'Complete'), ('grant_lifetime_ms', 15001),
                    ('interrupt_phase', 'Handshake'), ('interrupt_delay_ms', 1),
                    ('queue_control', True), ('suppress_reply', True),
                    ('missing_output', True), ('missing_time', True), ('native_error_codes', [8, 14])):
                with self.subTest(case=identity, field=key), self.assertRaises(RuntimeError):
                    MATRIX.development_profile(dict(case, **{key: value}))

    def test_peer_policy_completion_closure_and_engine_flags_are_required(self):
        output, fixture, wire = proof()
        for key, value in (('case', 'Q26'), ('mode', 'echo'), ('readiness_profile', 'q01-development'),
                ('transport_family', 'ipv6'), ('icmp_policy', 'label-only'),
                ('canonical_campaign_acceptance', True), ('engine_constructed', True),
                ('raw_socket_closed', False), ('icmp_send_attempted', False),
                ('icmp_send_completed', False), ('icmp_failed', True), ('thread_alive', True),
                ('errors', ['fixture failure']), ('certificate_selection', {}),
                ('terminated', {'error_code': 0}), ('private_material_included', True)):
            changed = copy.deepcopy(fixture)
            changed[key] = value
            with self.subTest(field=key):
                self.refused(output, changed, wire)

    def test_peer_authentication_application_or_udp_output_refuses(self):
        output, fixture, wire = proof()
        for key, value in (('authenticated', True), ('request_bytes', 1), ('request_fin', True),
                ('echo_enqueued_bytes', 1), ('echo_fin_enqueued', True),
                ('tx_datagrams', 1), ('tx_bytes', 1200)):
            changed = copy.deepcopy(fixture)
            changed[key] = value
            with self.subTest(field=key):
                self.refused(output, changed, wire)

    def test_missing_action_trigger_result_or_literal_quote_refuses(self):
        output, fixture, wire = proof()
        for container, key in ((None, 'icmp_trigger'), (None, 'icmp_send_result'),
                ('icmp_trigger', 'quote_hex'), ('icmp_trigger', 'frame_hex'),
                ('icmp_send_result', 'quote_hex'), ('icmp_send_result', 'frame_hex'),
                ('icmp_send_result', 'icmp_hex')):
            changed = copy.deepcopy(fixture)
            target = changed if container is None else changed[container]
            target.pop(key)
            with self.subTest(container=container, field=key):
                self.refused(output, changed, wire)

    def test_literal_full_frame_and_action_identity_cannot_be_substituted(self):
        output, fixture, wire = proof()
        for container, key, value in (
                ('icmp_trigger', 'submitted_frame_sha256', 'f' * 64),
                ('icmp_trigger', 'raw_frame_ordinal', 2), ('icmp_trigger', 'receive_ordinal', 2),
                ('icmp_trigger', 'sha256', 'f' * 64), ('icmp_trigger', 'data_hex', b'x'.hex()),
                ('icmp_send_result', 'sha256', 'f' * 64), ('icmp_send_result', 'mtu', 1227),
                ('icmp_send_result', 'actual_sent_bytes', 69), ('icmp_send_result', 'bytes', 69),
                ('icmp_send_result', 'trigger_receive_ordinal', 2),
                ('icmp_send_result', 'trigger_raw_frame_ordinal', 2),
                ('icmp_send_result', 'trigger_sha256', 'f' * 64),
                ('icmp_send_result', 'quote_hex', '00' * 28)):
            changed = copy.deepcopy(fixture)
            changed[container][key] = value
            with self.subTest(container=container, field=key):
                self.refused(output, changed, wire)

    def test_self_consistent_checksum_valid_altered_quote_or_reserved_word_refuses(self):
        _, fixture, _ = proof()
        for kind in ('quote', 'reserved'):
            changed = copy.deepcopy(fixture)
            frame = bytearray.fromhex(changed['icmp_send_result']['frame_hex'])
            if kind == 'quote':
                # Change quoted IPv4 ID and repair its checksum; the quote is
                # still internally valid, but not the literal submitted one.
                frame[46:48] = b'\0\x02'
                frame[52:54] = b'\0\0'
                frame[52:54] = struct.pack('!H', checksum(bytes(frame[42:62])))
            else:
                frame[38:40] = b'\0\x01'
            frame[36:38] = b'\0\0'
            frame[36:38] = struct.pack('!H', checksum(bytes(frame[34:])))
            result = changed['icmp_send_result']
            result.update(frame_hex=bytes(frame).hex(), sha256=digest(frame),
                          icmp_hex=bytes(frame[34:]).hex(), quote_hex=bytes(frame[42:]).hex())
            for name in ('icmp-send-begin', 'icmp-send'):
                row = event(changed, name)
                row.update({key: value for key, value in result.items()
                            if key != 'actual_sent_bytes' or name == 'icmp-send'})
            raw = next(row for row in changed['events'] if row.get('packet_type') == 4)
            raw.update(frame_hex=result['frame_hex'], sha256=result['sha256'])
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                MATRIX.verify_icmp_peer(CASES['Q25'], changed)

    def test_checksum_valid_same_quote_full_payload_substitution_refuses(self):
        output, fixture, wire = proof()
        # Two 16-bit substitutions preserve the UDP checksum and literal quote.
        changed = bytearray(INITIAL)
        changed[-4:-2] = (int.from_bytes(changed[-4:-2], 'big') + 1).to_bytes(2, 'big')
        changed[-2:] = (int.from_bytes(changed[-2:], 'big') - 1).to_bytes(2, 'big')
        frame = original('Q25', bytes(changed))
        self.assertEqual(frame[14:42], original('Q25')[14:42])
        rewritten = copy.deepcopy(fixture)
        raw = next(row for row in rewritten['events'] if row['event'] == 'icmp-frame-receive')
        raw.update(frame_hex=frame.hex(), sha256=digest(frame))
        rewritten['icmp_trigger'].update(frame_hex=frame.hex(), submitted_frame_sha256=digest(frame))
        self.refused(output, rewritten, wire)

    def test_event_names_cardinality_and_action_order_are_not_labels(self):
        output, fixture, wire = proof()
        for name in ('udp-receive', 'initial-observed', 'icmp-input', 'icmp-frame-receive',
                     'icmp-send-begin', 'icmp-send', 'peer-ended'):
            index = next(i for i, row in enumerate(fixture['events']) if row['event'] == name)
            for duplicate in (False, True):
                changed = copy.deepcopy(fixture)
                if duplicate:
                    changed['events'].insert(index, copy.deepcopy(changed['events'][index]))
                else:
                    changed['events'].pop(index)
                with self.subTest(event=name, duplicate=duplicate):
                    self.refused(output, changed, wire)
        for a, b in ((0, 1), (1, 2), (3, 4), (4, 5), (5, 6)):
            changed = copy.deepcopy(fixture)
            changed['events'][a], changed['events'][b] = changed['events'][b], changed['events'][a]
            # Reassign increasing clocks so order predicates, not clock rewind,
            # must distinguish the changed transition history.
            for index, row in enumerate(changed['events']):
                row['monotonic_ns'] = 9_000_000_000 + index * 1000
            with self.subTest(swap=(a, b)):
                self.refused(output, changed, wire)

    def test_top_level_and_event_action_result_must_agree(self):
        output, fixture, wire = proof()
        for name, key, value in (('initial-observed', 'sha256', 'f' * 64),
                ('icmp-input', 'engine_delivered', True), ('icmp-input', 'receive_ordinal', 2),
                ('icmp-send-begin', 'trigger_sha256', 'f' * 64),
                ('icmp-send', 'actual_sent_bytes', 69), ('peer-ended', 'stopped', False),
                ('peer-ended', 'deadline_reached', True)):
            changed = copy.deepcopy(fixture)
            event(changed, name)[key] = value
            with self.subTest(event=name, field=key):
                self.refused(output, changed, wire)

    def test_unrecorded_engine_timer_udp_or_failed_send_events_refuse(self):
        output, fixture, wire = proof()
        for name in ('certificate-selection', 'handshake-completed', 'udp-send',
                     'icmp-send-failed', 'timer-fired'):
            changed = copy.deepcopy(fixture)
            changed['events'].insert(-1, dict(event=name, monotonic_ns=9_000_006_000,
                                              wall_time_ns=1_800_000_000_000_006_000))
            with self.subTest(event=name):
                self.refused(output, changed, wire)

    def test_exact_raw_socket_census_identity_and_clocks_refuse_mutations(self):
        output, fixture, wire = proof()
        for key, value in (('rx_datagrams', 2), ('rx_bytes', 1199), ('raw_rx_frames', 1),
                           ('raw_rx_bytes', 1242), ('icmp_interface', 'other0'),
                           ('icmp_guest_mac', PM), ('icmp_peer_mac', 'ff:ff:ff:ff:ff:ff')):
            changed = copy.deepcopy(fixture)
            changed[key] = value
            with self.subTest(field=key):
                self.refused(output, changed, wire)
        for index, key, value in ((0, 'engine_delivered', True), (0, 'receive_ordinal', 2),
                (0, 'source', ['10.0.2.15', 7800]), (0, 'destination', ['10.0.2.2', 4444]),
                (0, 'sha256', 'f' * 64), (3, 'interface', 'other0'), (3, 'packet_type', 256),
                (3, 'raw_frame_ordinal', 2), (3, 'bytes', 1241), (3, 'sha256', 'f' * 64),
                (5, 'monotonic_ns', 1), (5, 'wall_time_ns', -1)):
            changed = copy.deepcopy(fixture)
            changed['events'][index][key] = value
            with self.subTest(event_index=index, field=key):
                self.refused(output, changed, wire)

    def test_capture_missing_extra_or_tampered_packets_and_quote_refuse(self):
        output, fixture, wire = proof()
        for key, value in (('guest_udp', []), ('icmp', []), ('peer_udp', [copy.deepcopy(wire['guest_udp'][0])]),
                           ('unexpected_frames', 1), ('guest_udp_count', 2), ('guest_udp_bytes', 1199)):
            changed = copy.deepcopy(wire)
            changed[key] = value
            with self.subTest(field=key):
                self.refused(output, fixture, changed)
        for group, key, value in (('guest_udp', 'sha256', 'f' * 64),
                ('guest_udp', 'frame_sha256', 'f' * 64), ('guest_udp', 'data_hex', '00' * 1200),
                ('guest_udp', 'source', ['10.0.2.15', 7800]),
                ('icmp', 'quote_hex', '00' * 28), ('icmp', 'submitted_frame_sha256', 'f' * 64),
                ('icmp', 'frame_sha256', 'f' * 64), ('icmp', 'icmp_checksum_valid', False),
                ('icmp', 'quoted_frame_ordinal', 2), ('icmp', 'ordinal', 0), ('icmp', 'mtu', 0)):
            changed = copy.deepcopy(wire)
            changed[group][0][key] = value
            with self.subTest(group=group, field=key):
                self.refused(output, fixture, changed)
        for group in ('guest_udp', 'icmp'):
            changed = copy.deepcopy(wire)
            changed[group].append(copy.deepcopy(changed[group][0]))
            with self.subTest(extra=group):
                self.refused(output, fixture, changed)

    def test_peer_json_counters_require_integers_not_boolean_float_or_text(self):
        output, fixture, wire = proof()
        for key in ('rx_datagrams', 'rx_bytes', 'raw_rx_frames', 'raw_rx_bytes', 'tx_datagrams'):
            for value in (True, float(fixture[key]), str(fixture[key]), -1, None):
                changed = copy.deepcopy(fixture)
                changed[key] = value
                with self.subTest(field=key, value=value):
                    self.refused(output, changed, wire)

    def test_exact_trigger_result_schema_and_json_numbers_refuse(self):
        output, fixture, wire = proof()
        for container in ('icmp_trigger', 'icmp_send_result'):
            changed = copy.deepcopy(fixture)
            changed[container]['unrecorded_field'] = 1
            with self.subTest(extra=container):
                self.refused(output, changed, wire)
        for container, key in (('icmp_trigger', 'receive_ordinal'), ('icmp_trigger', 'raw_frame_ordinal'),
                ('icmp_send_result', 'bytes'), ('icmp_send_result', 'actual_sent_bytes'),
                ('icmp_send_result', 'mtu'), ('icmp_send_result', 'trigger_receive_ordinal')):
            for value in (True, float(fixture[container][key]), str(fixture[container][key]), -1, None):
                changed = copy.deepcopy(fixture)
                changed[container][key] = value
                with self.subTest(container=container, field=key, value=value):
                    self.refused(output, changed, wire)

    def test_required_native_records_are_present_and_unique(self):
        output, fixture, wire = proof()
        for prefix in ('QUIC SERVICE SELECTOR', 'QUIC SERVICE GRANT', 'QUIC BEGIN',
                'QUIC FIXTURE NATIVE_COUNTS', 'QUIC CHILD AUTHORITY RETIRED',
                'QUIC CHILD EXIT', 'QUIC RESULT', 'QUIC SERVICE RETIRE', 'QUIC SERVICE DONE'):
            rows = output.splitlines()
            index = next(i for i, row in enumerate(rows) if row.startswith(prefix + ' case='))
            for changed in ('\n'.join(rows[:index] + rows[index + 1:]), output + '\n' + rows[index]):
                with self.subTest(prefix=prefix):
                    self.refused(changed, fixture, wire)
        rows = output.splitlines()
        for marker in ('QUIC CONSUMER case=Q25 begin', 'QUIC CONSUMER case=Q25 end',
                       next(row for row in rows if row.startswith('QUIC CPU '))):
            for changed in ('\n'.join(row for row in rows if row != marker), output + '\n' + marker):
                with self.subTest(marker=marker):
                    self.refused(changed, fixture, wire)

    def test_other_native_error_causes_or_unknown_completion_cannot_substitute(self):
        output, fixture, wire = proof()
        for values in ({'native_error_code': 8}, {'native_error_code': 9}, {'native_error_code': 10},
                {'native_error_code': 11}, {'native_error_code': 15}, {'native_error_detail': 0},
                {'native_error_detail': 1227}, {'native_failure_kind': 'Deadline'},
                {'native_failure_kind': 'Unknown'}, {'unknown_send': 'true'},
                {'transport_error_code': 0, 'transport_close_origin': 'peer'}, {'outcome': 'Complete'}):
            with self.subTest(values=values):
                self.refused(change(output, 'QUIC RESULT', **values), fixture, wire)
        output, fixture, wire = proof('Q28')
        self.refused(change(output, 'QUIC RESULT', native_error_code=15, native_error_detail=548), fixture, wire, 'Q28')

    def test_send15_requires_failed_complete_send_and_exact_unaccepted_maximum(self):
        for identity, maximum in (('Q25', 548), ('Q26', 1199)):
            output, fixture, wire = proof(identity, code=15)
            for values in ({'native_error_detail': 0}, {'native_error_detail': maximum - 1},
                    {'native_error_detail': maximum + 1}, {'native_error_detail': 1200},
                    {'send_accepted': 2}, {'send_bytes': 2400}, {'send_calls': 1}, {'engine_transmits': 1}):
                with self.subTest(case=identity, values=values):
                    self.refused(change(output, 'QUIC RESULT', **values), fixture, wire, identity)
            rows = [row for row in output.splitlines() if not row.startswith(
                'QUIC FIXTURE SEND case=' + identity + ' ordinal=2 ')]
            self.refused('\n'.join(rows), fixture, wire, identity)

    def test_native_auth_application_receive_close_and_entropy_substitutions_refuse(self):
        output, fixture, wire = proof()
        for field, value in (('authenticated', 'true'), ('request_fin', 'true'), ('peer_fin', 'true'),
                ('request_acked', 'true'), ('connection_drained', 'true'), ('close_accepted', 'true'),
                ('sent_stream', 1), ('received_stream', 1), ('received', 1), ('receive_bytes', 1200),
                ('close_calls', 1), ('entropy_attempts', 0), ('entropy_attempts', 2),
                ('unexpected_rng_draws', 1), ('pipe_fenced', 'false'), ('no_native_pair', 'true'),
                ('sends_after_fence', 1)):
            with self.subTest(field=field, value=value):
                self.refused(change(output, 'QUIC RESULT', **{field: value}), fixture, wire)

    def test_normal_reap_true_eof_and_absent_authority_are_required(self):
        output, fixture, wire = proof()
        for prefix, values in (
                ('QUIC CHILD EXIT', {'kind': 3}), ('QUIC CHILD EXIT', {'status': 1}),
                ('QUIC CHILD EXIT', {'killed': 'true'}),
                ('QUIC CHILD AUTHORITY RETIRED', {'result_eof': 'false'}),
                ('QUIC CHILD AUTHORITY RETIRED', {'process_handle_live': 'true'}),
                ('QUIC CHILD AUTHORITY RETIRED', {'pipe_live': 'true'}),
                ('QUIC CHILD AUTHORITY RETIRED', {'grant_live': 'true'}),
                ('QUIC CHILD AUTHORITY RETIRED', {'owner_expired': 'true'}),
                ('QUIC CHILD AUTHORITY RETIRED', {'sockets': 1}),
                ('QUIC SERVICE RETIRE', {'sockets_before_fence': 1}),
                ('QUIC SERVICE RETIRE', {'sockets_after_fence': 1}), ('QUIC SERVICE DONE', {'sockets': 1})):
            with self.subTest(prefix=prefix, values=values):
                self.refused(change(output, prefix, **values), fixture, wire)
        for kind in ('processes', 'handles', 'pipes', 'cells'):
            with self.subTest(object=kind):
                self.refused(change(output, 'QUIC SERVICE DONE', **{kind + '_after': 2}), fixture, wire)

    def test_original_clock_grant_deadline_and_retirement_order_are_required(self):
        output, fixture, wire = proof()
        for prefix, values in (
                ('QUIC SERVICE GRANT', {'constructed_ms': 11}),
                ('QUIC SERVICE GRANT', {'owner_expiry_ms': 15002}),
                ('QUIC BEGIN', {'start_ms': 11}), ('QUIC BEGIN', {'deadline_ms': 10011}),
                ('QUIC BEGIN', {'grant_expiry_ms': 15002}), ('QUIC BEGIN', {'native_pair': 'false'}),
                ('QUIC BEGIN', {'unix_time': 'None'}), ('QUIC RESULT', {'start_ms': 11}),
                ('QUIC RESULT', {'deadline_ms': 10011}), ('QUIC RESULT', {'grant_expiry_ms': 15002}),
                ('QUIC RESULT', {'end_ms': 10010}), ('QUIC RESULT', {'fence_ms': 81}),
                ('QUIC RESULT', {'last_send_ms': 76}),
                ('QUIC CHILD AUTHORITY RETIRED', {'reaped_ms': 79}),
                ('QUIC CHILD AUTHORITY RETIRED', {'retired_ms': 89}),
                ('QUIC FIXTURE NATIVE_COUNTS', {'at_ms': 9}),
                ('QUIC FIXTURE NATIVE_COUNTS', {'at_ms': 74}),
                ('QUIC FIXTURE NATIVE_COUNTS', {'at_ms': 92})):
            with self.subTest(prefix=prefix, values=values):
                self.refused(change(output, prefix, **values), fixture, wire)

    def test_host_clock_shift_is_not_a_guest_latency_measurement(self):
        output, fixture, wire = proof()
        for row in fixture['events']:
            row['monotonic_ns'] += 10 ** 18
            row['wall_time_ns'] += 10 ** 18
        result = self.check(output, fixture, wire)
        self.assertEqual(result['typed_report']['native_error_code'], '14')

    def test_bounded_partial_framing_retirement_is_not_claimed_as_complete_delivery(self):
        output, fixture, wire = proof()
        output = change(output, 'QUIC FIXTURE NATIVE_COUNTS', partial_request_bytes=1, partial_reply_bytes=1)
        observed = self.check(output, fixture, wire)
        self.assertEqual(observed['icmp']['partial_request_bytes_retired'], 1)
        self.assertEqual(observed['icmp']['partial_reply_bytes_retired'], 1)
        self.assertEqual(observed['typed_report']['received'], '0')

    def test_native_integer_and_boolean_serial_forms_are_canonical(self):
        output, fixture, wire = proof()
        for field in ('send_calls', 'native_error_detail', 'start_ms', 'fence_ms'):
            for value in ('01', '-1', '1.0', 'true', 'none'):
                with self.subTest(field=field, value=value):
                    self.refused(change(output, 'QUIC RESULT', **{field: value}), fixture, wire)
        for field in ('pipe_fenced', 'unknown_send'):
            for value in ('True', 'False', '0', '1', 'none'):
                with self.subTest(field=field, value=value):
                    self.refused(change(output, 'QUIC RESULT', **{field: value}), fixture, wire)

    def test_native_framing_census_send_tuple_hash_and_request_order_refuse(self):
        output, fixture, wire = proof()
        for values in ({'send_requests': 0}, {'send_requests': 2}, {'receive_delivered': 1},
                {'sends_after_owner_expiry': 1}, {'partial_request_bytes': 1486}, {'partial_reply_bytes': 1486}):
            with self.subTest(counts=values):
                self.refused(change(output, 'QUIC FIXTURE NATIVE_COUNTS', **values), fixture, wire)
        for values in ({'ordinal': 2}, {'bytes': 1199}, {'bytes': 1201}, {'sha256': 'f' * 64},
                {'sha256': 'F' * 64}, {'peer_ip': '10.0.2.3'}, {'peer_port': 4444},
                {'case': 'Q26'}, {'at_ms': 9}, {'at_ms': 86}):
            with self.subTest(send=values):
                self.refused(change(output, 'QUIC FIXTURE SEND', **values), fixture, wire)
        for values in ({'send_calls': 0}, {'send_accepted': 0}, {'send_bytes': 1199},
                       {'send_bytes': 1201}, {'engine_transmits': 0}):
            with self.subTest(report=values):
                self.refused(change(output, 'QUIC RESULT', **values), fixture, wire)

    def test_native_receive_expiry_interruption_or_partial_publication_refuses(self):
        output, fixture, wire = proof()
        for extra in (
                line('QUIC FIXTURE RX', case='Q25', ordinal=1, at_ms=40, bytes=1200,
                     sha256=digest(INITIAL), peer_ip='10.0.2.2', peer_port=4443),
                line('QUIC SERVICE GRANT EXPIRED', case='Q25', observed_ms=15001),
                line('QUIC CHILD INTERRUPT REQUEST', case='Q25', requested_ms=40),
                line('QUIC CONSUMER PARTIAL', case='Q25', bytes=1)):
            with self.subTest(extra=extra):
                self.refused(output + '\n' + extra, fixture, wire)

    def test_buffered_publication_phases_and_native_record_order_are_exact(self):
        output, fixture, wire = proof()
        for a, b in (('QUIC FIXTURE NATIVE_COUNTS', 'QUIC CHILD AUTHORITY RETIRED'),
                     ('QUIC CHILD AUTHORITY RETIRED', 'QUIC CHILD EXIT'),
                     ('QUIC SERVICE RETIRE', 'QUIC SERVICE DONE')):
            rows = output.splitlines()
            ai, bi = (next(i for i, row in enumerate(rows) if row.startswith(p + ' case=')) for p in (a, b))
            rows[ai], rows[bi] = rows[bi], rows[ai]
            with self.subTest(swap=(a, b)):
                self.refused('\n'.join(rows), fixture, wire)
        for index, values in ((0, {'phase': 'Authenticated'}), (1, {'phase': 'Stream'}),
                              (1, {'at_ms': 9}), (2, {'at_ms': 81})):
            with self.subTest(phase=index, values=values):
                self.refused(change(output, 'QUIC PHASE', index, **values), fixture, wire)


if __name__ == '__main__':
    unittest.main()
