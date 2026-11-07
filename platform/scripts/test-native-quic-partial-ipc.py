#!/usr/bin/env python3
"""Finite Q02 profile/oracle controls; run only on the declared execution host."""
from pathlib import Path
import importlib.util
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('quic_partial_base', ROOT / 'scripts/native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
MATRIX, PEER, WIRE = BASE.MATRIX, BASE.PEER_MODULE, BASE.WIRE
MANIFEST = json.loads((ROOT / 'quic/CASES.json').read_text())
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q02')
# Literal checksum-valid IPv4/UDP vectors with exact Q02 local port7801.
GUEST = bytes.fromhex('02710000000252540012345608004500002500014000401122b70a00020f0a0002021e79115b0011e124717569632d77697265000000000000000000')
PEER_PACKET = bytes.fromhex('52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e790011e124717569632d77697265000000000000000000')


def one_event(fixture, name):
    rows = [row for row in fixture['events'] if row['event'] == name]
    if len(rows) != 1:
        raise RuntimeError('one exact fixture event required: ' + name)
    return rows[0]


def retag_base_output(output):
    prefixes = ('QUIC SERVICE SELECTOR', 'QUIC SERVICE DONE', 'QUIC SERVICE GRANT',
                'QUIC RESULT', 'QUIC BEGIN', 'QUIC CHILD EXIT',
                'QUIC FIXTURE NATIVE_COUNTS', 'QUIC FIXTURE SEND', 'QUIC FIXTURE RX')
    lines = []
    for line in output.splitlines():
        prefix = next((p for p in prefixes if line.startswith(p + ' ')
                       and all('=' in part for part in line[len(p) + 1:].split())), None)
        if prefix is None:
            lines.append(line)
            continue
        parts = line[len(prefix) + 1:].split()
        fields = MATRIX.fields(line)
        if fields.get('case') != 'Q01':
            lines.append(line)
            continue
        parts = ['case=Q02' if part == 'case=Q01' else part for part in parts]
        if prefix in ('QUIC SERVICE SELECTOR', 'QUIC SERVICE GRANT'):
            if fields.get('local_port') != '7800':
                raise RuntimeError('exact original Q01 local port required')
            parts = ['local_port=7801' if part == 'local_port=7800' else part for part in parts]
        lines.append(prefix + ' ' + ' '.join(parts))
    return '\n'.join(lines)


def partial_counter(output, key, value):
    if key not in ('partial_pipe_reads', 'partial_pipe_writes'):
        raise RuntimeError('exact partial counter key required')
    lines = output.splitlines()
    rows = [index for index, line in enumerate(lines)
            if line.startswith('QUIC RESULT ') and MATRIX.fields(line).get('case') == 'Q02']
    if len(rows) != 1:
        raise RuntimeError('one exact Q02 synthetic report required')
    parts = lines[rows[0]].split()
    positions = [i for i, part in enumerate(parts) if part.startswith(key + '=')]
    if len(positions) != 1:
        raise RuntimeError('one exact synthetic partial counter required')
    if value is None:
        parts.pop(positions[0])
    else:
        parts[positions[0]] = key + '=' + value
    lines[rows[0]] = ' '.join(parts)
    return '\n'.join(lines)


def proof():
    output, fixture, wire = BASE.proof()
    output = retag_base_output(output)
    lines = output.splitlines()
    reports = [index for index, line in enumerate(lines) if line.startswith('QUIC RESULT ')]
    if len(reports) != 1 or any(key + '=' in lines[reports[0]] for key in ('partial_pipe_reads', 'partial_pipe_writes')):
        raise RuntimeError('one base report without optional partial counters required')
    # Literal boundary: ceil(1200/7) - one payload-bearing message =171.
    lines[reports[0]] += ' partial_pipe_reads=171 partial_pipe_writes=171'
    output = '\n'.join(lines)
    fixture['readiness_profile'] = 'q02-partial-ipc-development'
    one_event(fixture, 'udp-send')['destination'][1] = 7801
    wire['peer_udp'][0]['destination'][1] = 7801
    return output, fixture, wire


class PartialIPCControls(unittest.TestCase):
    def check(self, output, fixture, wire):
        return MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)

    def test_exact_joint_profile_and_ordinary_peer_calibrates(self):
        self.assertEqual((CASE['peer_mode'], CASE['local_port'], CASE['expected_outcome']), ('partial-io', 7801, 'Complete'))
        self.assertEqual(PEER.development_profile(CASE), 'q02-partial-ipc-development')
        self.assertEqual(MATRIX.development_profile(CASE), 'q02-partial-ipc-development')
        self.assertEqual(PEER.peer_certificate(CASE), 'valid')
        self.assertEqual(PEER.peer_alpn(CASE), ['absd-echo/1'])
        self.assertEqual(PEER.peer_terminal_codes(CASE), (0,))
        self.assertEqual(PEER.response_policy(CASE), 'standard')
        self.assertFalse(PEER.one_response_policy(CASE))

    def test_exact_valid_leaf_and_root_selection_calibrates(self):
        pki = {'root_der': {'sha256': 'e' * 64}, 'leaf_certificates': {'valid': {'sha256': 'd' * 64}}}
        fixture = {'certificate_selection': {'kind': 'valid', 'sha256': 'd' * 64, 'client_root_sha256': 'e' * 64}}
        MATRIX.verify_certificate_selection(CASE, fixture, pki)
        for key, value in (('kind', 'untrusted'), ('sha256', 'c' * 64), ('client_root_sha256', 'c' * 64)):
            changed = {'certificate_selection': dict(fixture['certificate_selection'], **{key: value})}
            with self.subTest(field=key), self.assertRaises(RuntimeError): MATRIX.verify_certificate_selection(CASE, changed, pki)

    def test_case_mode_port_substitutions_refuse(self):
        for changed in (dict(CASE, id='Q01'), dict(CASE, peer_mode='echo'), dict(CASE, local_port=7800)):
            with self.subTest(case=changed):
                with self.assertRaises(RuntimeError): PEER.development_profile(changed)
                with self.assertRaises(RuntimeError): MATRIX.development_profile(changed)
                with self.assertRaises(WIRE.Refusal): WIRE.observe(BASE.pcap([GUEST, PEER_PACKET]), changed, '52:54:00:12:34:56', '02:71:00:00:00:02')

    def test_ipv6_partial_profile_is_not_admitted(self):
        with self.assertRaises(RuntimeError): PEER.development_profile(CASE, 'ipv6')
        with self.assertRaises(RuntimeError): MATRIX.development_profile(CASE, 'ipv6')

    def test_exact_port7801_capture_calibrates(self):
        observed = WIRE.observe(BASE.pcap([BASE.ARP_BROADCAST, GUEST, PEER_PACKET]), CASE, '52:54:00:12:34:56', '02:71:00:00:00:02')
        self.assertEqual((observed['frame_count'], observed['arp_count'], observed['udp_count']), (3, 1, 2))
        self.assertEqual(observed['guest_udp'][0]['source'], ['10.0.2.15', 7801])
        self.assertEqual(observed['peer_udp'][0]['destination'], ['10.0.2.15', 7801])
        self.assertTrue(all(row['ip_checksum_valid'] and row['udp_checksum_valid'] for row in observed['guest_udp'] + observed['peer_udp']))

    def test_q01_capture_cannot_qualify_partial_profile(self):
        with self.assertRaises(WIRE.Refusal): WIRE.observe(BASE.pcap([BASE.GUEST, BASE.PEER]), CASE, '52:54:00:12:34:56', '02:71:00:00:00:02')

    def test_complete_capture_keeps_checksum_and_frame_refusals(self):
        changed = bytearray(GUEST); changed[42] ^= 1
        for frames in ([bytes(changed), PEER_PACKET], [GUEST], [GUEST, PEER_PACKET, bytes(60)]):
            with self.subTest(frames=frames), self.assertRaises(WIRE.Refusal):
                WIRE.observe(BASE.pcap(frames), CASE, '52:54:00:12:34:56', '02:71:00:00:00:02')

    def test_synthetic_partial_counter_proof_calibrates(self):
        observed = self.check(*proof())
        self.assertEqual(observed['actual_outcome'], 'Complete')
        self.assertEqual((observed['typed_report']['partial_pipe_reads'], observed['typed_report']['partial_pipe_writes']), ('171', '171'))

    def test_zero_missing_or_noncanonical_partial_counters_refuse(self):
        for key in ('partial_pipe_reads', 'partial_pipe_writes'):
            for replacement in ('0', None, '-1', '01'):
                output, fixture, wire = proof()
                with self.subTest(field=key, replacement=replacement), self.assertRaises(RuntimeError):
                    self.check(partial_counter(output, key, replacement), fixture, wire)

    def test_exact_bound_and_one_more_calibrate_but_one_less_refuses(self):
        for key in ('partial_pipe_reads', 'partial_pipe_writes'):
            for value in ('171', '172'):
                output, fixture, wire = proof()
                with self.subTest(field=key, value=value): self.check(partial_counter(output, key, value), fixture, wire)
            output, fixture, wire = proof()
            with self.subTest(field=key), self.assertRaisesRegex(RuntimeError, '7-byte payload bound'):
                self.check(partial_counter(output, key, '170'), fixture, wire)

    def test_a_cap_applied_only_once_cannot_qualify_either_direction(self):
        for key in ('partial_pipe_reads', 'partial_pipe_writes'):
            output, fixture, wire = proof()
            with self.subTest(field=key), self.assertRaisesRegex(RuntimeError, '7-byte payload bound'):
                self.check(partial_counter(output, key, '1'), fixture, wire)

    def test_payload_message_bound_rounding_and_conservative_floor(self):
        for payload, messages, expected in ((0, 0, 1), (7, 1, 1), (8, 1, 1), (14, 1, 1),
                                             (15, 1, 2), (14, 2, 1), (1200, 1, 171),
                                             (7100, 13, 1002), (6445, 13, 908)):
            row = {'receive_bytes':str(payload), 'received':str(messages),
                   'send_bytes':str(payload), 'send_accepted':str(messages)}
            with self.subTest(payload=payload, messages=messages):
                self.assertEqual(MATRIX.partial_ipc_bounds(row), {'partial_pipe_reads':expected, 'partial_pipe_writes':expected})

    def test_bound_inputs_require_canonical_integers(self):
        for key in ('receive_bytes', 'received', 'send_bytes', 'send_accepted'):
            for value in (None, '-1', '01', '+1', '1.0', '1e3', ' 1', 'true'):
                row = {'receive_bytes':'1200', 'received':'1', 'send_bytes':'1200', 'send_accepted':'1'}
                if value is None: row.pop(key)
                else: row[key] = value
                with self.subTest(field=key, value=value), self.assertRaises(RuntimeError): MATRIX.partial_ipc_bounds(row)

    def test_framing_progress_model_has_at_most_one_uncounted_body_finish(self):
        for payloads in ((0,), (1,), (7,), (1200,), (3, 8, 13), (1200, 500, 1472)):
            for kernel_cap in (1, 3, 7):
                partial = 0
                for payload in payloads:
                    remaining, uncounted = 12 + payload, 0
                    while remaining:
                        requested = min(remaining, 256)
                        transferred = min(requested, 7, kernel_cap)
                        partial += transferred < requested
                        uncounted += transferred == requested
                        remaining -= transferred
                    self.assertLessEqual(uncounted, 1)
                # Prefix calls and all other transactions were omitted from
                # this bounded model; neither can decrease these counters.
                report = {'receive_bytes':str(sum(payloads)), 'received':str(len(payloads)),
                          'send_bytes':str(sum(payloads)), 'send_accepted':str(len(payloads))}
                with self.subTest(payloads=payloads, kernel_cap=kernel_cap):
                    self.assertGreaterEqual(partial, MATRIX.partial_ipc_bounds(report)['partial_pipe_reads'])

    def test_counter_integer_forms_are_checked_before_bound(self):
        for key in ('partial_pipe_reads', 'partial_pipe_writes'):
            for value in ('0171', '+171', '171.0', '1e3', 'true'):
                output, fixture, wire = proof()
                with self.subTest(field=key, value=value), self.assertRaises(RuntimeError):
                    self.check(partial_counter(output, key, value), fixture, wire)

    def test_structural_retag_preserves_unrelated_case_text_and_values(self):
        output, _, _ = BASE.proof()
        diagnostic = 'QUIC DIAGNOSTIC case=Q01 note=Q01 local_port=7800'
        output += '\n' + diagnostic
        output = output.replace('QUIC RESULT case=Q01 ', 'QUIC RESULT case=Q01 diagnostic=Q01 source_name=Q01-buffer ')
        result = retag_base_output(output)
        self.assertIn(diagnostic, result.splitlines())
        report = next(row for row in result.splitlines() if row.startswith('QUIC RESULT '))
        self.assertEqual((MATRIX.fields(report)['case'], MATRIX.fields(report)['diagnostic'], MATRIX.fields(report)['source_name']),
                         ('Q02', 'Q01', 'Q01-buffer'))
        self.assertEqual(MATRIX.fields(next(row for row in result.splitlines() if row.startswith('QUIC SERVICE GRANT ')))['local_port'], '7801')

    def test_structural_retag_refuses_port_substitution_and_keeps_other_case(self):
        output, _, _ = BASE.proof()
        with self.assertRaises(RuntimeError): retag_base_output(output.replace('local_port=7800', 'local_port=7802'))
        other = 'QUIC BEGIN case=Q03 diagnostic=Q01 local_port=7800'
        self.assertEqual(retag_base_output(other), other)

    def test_partial_counts_cannot_replace_auth_body_fin_ack_drain(self):
        for before, after in (('authenticated=true', 'authenticated=false'), ('sent_stream=4096', 'sent_stream=4095'),
                              ('received_stream=4096', 'received_stream=4095'), ('request_fin=true', 'request_fin=false'),
                              ('peer_fin=true', 'peer_fin=false'), ('request_acked=true', 'request_acked=false'),
                              ('connection_drained=true', 'connection_drained=false')):
            output, fixture, wire = proof()
            with self.subTest(field=before), self.assertRaises(RuntimeError): self.check(output.replace(before, after), fixture, wire)

    def test_peer_body_or_error_terminal_refuses(self):
        for mutation in ('body', 'terminal'):
            output, fixture, wire = proof()
            if mutation == 'body': fixture['request_sha256'] = 'c' * 64
            else: fixture['terminated'] = {'error_code': 1}
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_complete_peer_census_and_every_send_capture_refuse_substitution(self):
        for mutation in ('census', 'send', 'capture'):
            output, fixture, wire = proof()
            if mutation == 'census': fixture['tx_datagrams'] += 1
            elif mutation == 'send': one_event(fixture, 'udp-send')['sha256'] = 'c' * 64
            else: wire['peer_udp'].clear()
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): self.check(output, fixture, wire)

    def test_native_census_resource_or_fence_substitution_refuses(self):
        for before, after in (('send_requests=1', 'send_requests=2'), ('receive_delivered=1', 'receive_delivered=2'),
                              ('handles_after=1', 'handles_after=2'), ('pipe_fenced=true', 'pipe_fenced=false'),
                              ('sends_after_fence=0', 'sends_after_fence=1'), ('partial_request_bytes=0', 'partial_request_bytes=1'),
                              ('status=0 killed=false', 'status=1 killed=false')):
            output, fixture, wire = proof()
            with self.subTest(field=before), self.assertRaises(RuntimeError): self.check(output.replace(before, after), fixture, wire)

    def test_original_grant_deadline_and_tuple_substitution_refuse(self):
        for before, after in (('deadline_ms=10010', 'deadline_ms=10011'), ('owner_expiry_ms=15001', 'owner_expiry_ms=15002'),
                              ('local_port=7801', 'local_port=7800'), ('peer_port=4443', 'peer_port=4444'), ('end_ms=101', 'end_ms=10011')):
            output, fixture, wire = proof()
            with self.subTest(field=before), self.assertRaises(RuntimeError): self.check(output.replace(before, after), fixture, wire)

    def test_original_q01_zero_partial_counters_still_calibrates(self):
        output, fixture, wire = BASE.proof()
        lines = output.splitlines()
        reports = [index for index, line in enumerate(lines) if line.startswith('QUIC RESULT ')]
        self.assertEqual(len(reports), 1)
        lines[reports[0]] += ' partial_pipe_reads=0 partial_pipe_writes=0'
        observed = MATRIX.verify_native(BASE.CASE, '\n'.join(lines), fixture, wire, MANIFEST)
        self.assertEqual(observed['actual_outcome'], 'Complete')


if __name__ == '__main__':
    unittest.main()
