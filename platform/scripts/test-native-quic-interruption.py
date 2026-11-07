#!/usr/bin/env python3
"""Finite parent/packet witness controls, not native interruption execution."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('interruption_base', ROOT / 'native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
MATRIX, MANIFEST = BASE.MATRIX, BASE.MANIFEST
CASES = {row['id']:row for row in MANIFEST['native_occurrences']}
INITIAL, STREAM, REPLY = b'\xc7' + b'i' * 1199, b'\x40' + b's' * 127, b'\xc1' + b'r' * 1199


def digest(data): return hashlib.sha256(data).hexdigest()
def line(prefix, **values): return prefix + ' ' + ' '.join(key + '=' + str(value) for key, value in values.items())
def record(output, prefix):
    rows = [MATRIX.fields(row) for row in output.splitlines() if row.startswith(prefix + ' ')]
    if len(rows) != 1: raise RuntimeError('one synthetic record required: ' + prefix)
    return rows[0]
def change(output, prefix, **values):
    result = []
    for text in output.splitlines():
        if text.startswith(prefix + ' '):
            fields = MATRIX.fields(text)
            fields.update({key:str(value) for key, value in values.items()})
            text = line(prefix, **fields)
        result.append(text)
    return '\n'.join(result)


def proof(identity='Q21'):
    case = CASES[identity]
    active = identity == 'Q22'
    requested = 400 if active else 1100
    guest, peer = ['10.0.2.15', case['local_port']], ['10.0.2.2', 4443]
    packets = [INITIAL, STREAM] if active else [INITIAL]
    received = [dict(event='udp-receive', receive_ordinal=i, bytes=len(data), sha256=digest(data), source=list(guest))
                for i, data in enumerate(packets, 1)]
    initial = dict(event='initial-observed', bytes=1200, sha256=digest(INITIAL), receive_ordinal=1)
    events = [received[0], initial]
    fixture = dict(mode=case['peer_mode'], readiness_profile=MATRIX.development_profile(case),
                   canonical_campaign_acceptance=False, errors=[], thread_alive=False,
                   authenticated=active, request_bytes=64 if active else 0, request_fin=False,
                   echo_enqueued_bytes=0, echo_fin_enqueued=False, terminated=None,
                   certificate_selection={'kind':'valid'} if active else None,
                   rx_datagrams=len(received), rx_bytes=sum(row['bytes'] for row in received),
                   tx_datagrams=1 if active else 0, tx_bytes=1200 if active else 0)
    if active:
        sent = dict(event='udp-send', bytes=1200, sha256=digest(REPLY), source=list(peer), destination=list(guest))
        prefix_hash = digest(bytes(97 + i % 26 for i in range(64)))
        trigger = dict(receive_ordinal=2, bytes=len(STREAM), sha256=digest(STREAM), request_bytes=64,
                       request_sha256=prefix_hash, request_fin=False, authenticated_before=True,
                       tx_datagrams=1, tx_bytes=1200)
        events += [sent, received[1], dict(event='handshake', receive_ordinal=2),
                   dict(event='request-stream', stream_id=0, offset=0, bytes=64, fin=False, receive_ordinal=2),
                   dict(event='q22-stream-output-fenced', policy='q22-stream-output-fence-v1',
                        later_engine_work=False, later_send=False, **trigger), dict(event='peer-ended')]
        fixture.update(interruption_policy='q22-stream-output-fence-v1', stream_output_fenced=True,
                       stream_output_trigger=trigger, request_sha256=prefix_hash)
        peer_packets = [{key:sent[key] for key in ('bytes','sha256','source','destination')}]
    else:
        events += [dict(event='silent-input', receive_ordinal=1, bytes=1200, sha256=digest(INITIAL),
                        engine_delivered=False), dict(event='peer-ended')]
        fixture.update(interruption_policy='q21-engine-free-silent-v1', engine_constructed=False)
        peer_packets = []
    fixture['events'] = events
    wire = dict(guest_udp=[dict(bytes=len(data), sha256=digest(data), source=list(guest), destination=list(peer))
                           for data in packets], peer_udp=peer_packets)
    rows = [line('QUIC SERVICE SELECTOR', case=identity, local_port=case['local_port']),
            line('QUIC SERVICE GRANT', case=identity, before_ms=1, constructed_ms=2,
                 owner_expiry_ms=15001, local_port=case['local_port'], peer_port=4443)]
    for ordinal, data in enumerate(packets, 1):
        rows.append(line('QUIC FIXTURE SEND', case=identity, ordinal=ordinal, at_ms=20 + ordinal * 10,
                         bytes=len(data), sha256=digest(data), peer_ip='10.0.2.2', peer_port=4443))
    if active:
        rows.append(line('QUIC FIXTURE RX', case=identity, ordinal=1, at_ms=50,
                         bytes=1200, sha256=digest(REPLY), peer_ip='10.0.2.2', peer_port=4443))
    rows += [line('QUIC CHILD INTERRUPT OBSERVED', case=identity, phase=case['interrupt_phase'],
                  observed_ms=100, delay_ms=case['interrupt_delay_ms']),
             line('QUIC CHILD INTERRUPT REQUEST', case=identity, requested_ms=requested, observed_ms=100),
             line('QUIC CHILD INTERRUPT RETURN', case=identity, result=0, end_ms=requested + 1),
             line('QUIC FIXTURE NATIVE_COUNTS', case=identity, at_ms=requested + 2,
                  send_requests=len(packets), receive_delivered=int(active), sends_after_owner_expiry=0,
                  partial_request_bytes=0, partial_reply_bytes=0),
             line('QUIC CHILD INTERRUPT RETIRED', case=identity, reaped_ms=requested + 2, retired_ms=requested + 3,
                  process_handle_live='false', pipe_live='false', grant_live='false', sockets=0, result_eof='true'),
             line('QUIC CHILD EXIT', case=identity, kind=3, status=0, killed='true'),
             'QUIC CONSUMER case=' + identity + ' begin',
             line('QUIC CPU', vendor='GenuineIntel', leaf1_eax=0x306c0, leaf1_ecx=1 << 30, family=6, model=60, rdrand=1),
             line('QUIC BEGIN', case=identity, start_ms=10, deadline_ms=10010, grant_expiry_ms=15001),
             line('QUIC PHASE', case=identity, phase='Init', at_ms=10),
             line('QUIC PHASE', case=identity, phase='Handshake', at_ms=20)]
    if active:
        rows += [line('QUIC PHASE', case=identity, phase='Authenticated', at_ms=50),
                 line('QUIC PHASE', case=identity, phase='Stream', at_ms=60)]
    rows += ['QUIC CONSUMER case=' + identity + ' end',
             line('QUIC SERVICE RETIRE', case=identity, sockets_before_fence=0, sockets_after_fence=0),
             line('QUIC SERVICE DONE', case=identity, sockets=0,
                  **{name + '_' + when:1 for name in ('processes','handles','pipes','cells') for when in ('before','after')})]
    return '\n'.join(rows), fixture, wire


class InterruptionControls(unittest.TestCase):
    def check(self, identity, output, fixture, wire):
        return MATRIX.verify_native(CASES[identity], output, fixture, wire, MANIFEST)

    def test_exact_canonical_profiles_and_original_clocks(self):
        for identity, port, phase, delay in (('Q21',7820,'Handshake',1000), ('Q22',7821,'Stream',300)):
            case = CASES[identity]
            self.assertEqual((case['local_port'],case['interrupt_phase'],case['interrupt_delay_ms'],case['grant_lifetime_ms']),
                             (port,phase,delay,15000))
            for key, value in (('local_port',7800),('interrupt_phase','Closing'),('interrupt_delay_ms',delay+1),
                               ('grant_lifetime_ms',15001),('expected_outcome','Complete'),('peer_mode','echo')):
                with self.subTest(identity=identity,key=key), self.assertRaises(RuntimeError):
                    MATRIX.development_profile(dict(case, **{key:value}))

    def test_real_argparse_accepts_only_declared_profile_names(self):
        for identity in ('Q21','Q22'):
            result = subprocess.run([sys.executable, MATRIX.__file__, '--profile', MATRIX.development_profile(CASES[identity]), '--help'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([sys.executable, MATRIX.__file__, '--profile', 'q21-invented', '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)

    def test_synthetic_phase_reap_and_retirement_calibrate(self):
        for identity in ('Q21','Q22'):
            result = self.check(identity, *proof(identity))
            self.assertEqual(result['actual_outcome'], 'Interrupted')
            self.assertTrue(result['interruption']['result_eof'])
            self.assertIsNone(result['typed_report'])

    def test_missing_required_parent_or_child_records_refuse(self):
        for prefix in ('QUIC BEGIN','QUIC CHILD INTERRUPT OBSERVED','QUIC CHILD INTERRUPT REQUEST',
                       'QUIC CHILD INTERRUPT RETURN','QUIC CHILD INTERRUPT RETIRED','QUIC CHILD EXIT',
                       'QUIC FIXTURE NATIVE_COUNTS','QUIC SERVICE RETIRE','QUIC SERVICE DONE'):
            output,fixture,wire = proof()
            output = '\n'.join(row for row in output.splitlines() if not row.startswith(prefix + ' '))
            with self.subTest(prefix=prefix), self.assertRaises(RuntimeError): self.check('Q21',output,fixture,wire)

    def test_control_record_order_is_required_despite_equal_fields(self):
        for a,b in (('OBSERVED','REQUEST'),('REQUEST','RETURN'),('RETURN','RETIRED')):
            output,fixture,wire = proof(); rows = output.splitlines()
            ia,ib = (next(i for i,row in enumerate(rows) if row.startswith('QUIC CHILD INTERRUPT ' + name + ' ')) for name in (a,b))
            rows[ia],rows[ib] = rows[ib],rows[ia]
            with self.subTest(pair=(a,b)), self.assertRaisesRegex(RuntimeError,'publication order'):
                self.check('Q21','\n'.join(rows),fixture,wire)

    def test_buffered_phase_time_is_bound_to_parent_observation(self):
        output,fixture,wire = proof('Q22')
        output = output.replace('phase=Stream at_ms=60','phase=Stream at_ms=101')
        with self.assertRaisesRegex(RuntimeError,'active selected phase'): self.check('Q22',output,fixture,wire)
        output,fixture,wire = proof()
        output = '\n'.join(row for row in output.splitlines() if 'QUIC PHASE case=Q21 phase=Handshake ' not in row)
        with self.assertRaisesRegex(RuntimeError,'active selected phase'): self.check('Q21',output,fixture,wire)
        output,fixture,wire = proof('Q22')
        output = output.replace('phase=Handshake at_ms=20','phase=Handshake at_ms=90')
        with self.assertRaisesRegex(RuntimeError,'clock moved backwards'): self.check('Q22',output,fixture,wire)

    def test_late_closing_fenced_or_normal_result_cannot_replace_interruption(self):
        for extra in ('QUIC RESULT case=Q22 outcome=Complete', 'QUIC PHASE case=Q22 phase=Closing at_ms=70',
                      'QUIC PHASE case=Q22 phase=Fenced at_ms=70'):
            output,fixture,wire = proof('Q22')
            output = output.replace('QUIC CONSUMER case=Q22 end',extra+'\nQUIC CONSUMER case=Q22 end')
            with self.subTest(extra=extra), self.assertRaises(RuntimeError): self.check('Q22',output,fixture,wire)

    def test_original_grant_and_operation_expiry_cannot_be_extended(self):
        for prefix,values in [('QUIC SERVICE GRANT',dict(owner_expiry_ms=15002)),
                              ('QUIC BEGIN',dict(deadline_ms=10011)),('QUIC BEGIN',dict(grant_expiry_ms=15002)),
                              ('QUIC CHILD INTERRUPT RETIRED',dict(retired_ms=10010))]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaisesRegex(RuntimeError,'lifetime'):
                self.check('Q21',change(output,prefix,**values),fixture,wire)

    def test_parent_observation_delay_cannot_be_shortened_or_substituted(self):
        for prefix,values in [('QUIC CHILD INTERRUPT REQUEST',dict(requested_ms=1099)),
                              ('QUIC CHILD INTERRUPT REQUEST',dict(observed_ms=99)),
                              ('QUIC CHILD INTERRUPT OBSERVED',dict(delay_ms=999)),
                              ('QUIC CHILD INTERRUPT OBSERVED',dict(phase='Stream'))]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                self.check('Q21',change(output,prefix,**values),fixture,wire)

    def test_exact_kill_zero_and_killed_reap_record_required(self):
        for prefix,values in [('QUIC CHILD INTERRUPT RETURN',dict(result=1)),('QUIC CHILD EXIT',dict(kind=1)),
                              ('QUIC CHILD EXIT',dict(status=1)),('QUIC CHILD EXIT',dict(killed='false'))]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaisesRegex(RuntimeError,'killed-child reap'):
                self.check('Q21',change(output,prefix,**values),fixture,wire)

    def test_timeout_is_not_result_end_and_live_authority_refuses(self):
        for values in [dict(result_eof='false'),dict(process_handle_live='true'),dict(pipe_live='true'),
                       dict(grant_live='true'),dict(sockets=1)]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaisesRegex(RuntimeError,'retirement absent'):
                self.check('Q21',change(output,'QUIC CHILD INTERRUPT RETIRED',**values),fixture,wire)

    def test_final_socket_and_all_parent_resource_counts_are_required(self):
        for prefix,values in [('QUIC SERVICE RETIRE',dict(sockets_before_fence=1)),
                              ('QUIC SERVICE RETIRE',dict(sockets_after_fence=1))]+[
                              ('QUIC SERVICE DONE',{name+'_after':2}) for name in ('processes','handles','pipes','cells')]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                self.check('Q21',change(output,prefix,**values),fixture,wire)

    def test_complete_native_census_is_not_optional_after_child_interruption(self):
        for prefix,values in [('QUIC FIXTURE NATIVE_COUNTS',dict(send_requests=2)),
                              ('QUIC FIXTURE NATIVE_COUNTS',dict(receive_delivered=1)),
                              ('QUIC FIXTURE NATIVE_COUNTS',dict(sends_after_owner_expiry=1))]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                self.check('Q21',change(output,prefix,**values),fixture,wire)
        output,fixture,wire = proof('Q22')
        output = '\n'.join(row for row in output.splitlines() if not row.startswith('QUIC FIXTURE RX '))
        output = change(output,'QUIC FIXTURE NATIVE_COUNTS',receive_delivered=0)
        with self.assertRaisesRegex(RuntimeError,'no complete native RECEIVE'):
            self.check('Q22',output,fixture,wire)

    def test_native_packet_identity_and_retirement_time_are_required(self):
        for values in [dict(sha256='f'*64),dict(bytes=1199),dict(peer_port=4444),dict(at_ms=1104)]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                self.check('Q21',change(output,'QUIC FIXTURE SEND',**values),fixture,wire)

    def test_complete_native_send_cannot_appear_after_pipe_retirement(self):
        output,fixture,wire = proof(); rows = output.splitlines()
        index = next(i for i,row in enumerate(rows) if row.startswith('QUIC FIXTURE SEND '))
        rows.append(rows.pop(index))
        with self.assertRaisesRegex(RuntimeError,'crossed retirement'): self.check('Q21','\n'.join(rows),fixture,wire)
        output,fixture,wire = proof(); rows = output.splitlines()
        index = next(i for i,row in enumerate(rows) if row.startswith('QUIC FIXTURE NATIVE_COUNTS '))
        before_kill = next(i for i,row in enumerate(rows) if row.startswith('QUIC CHILD INTERRUPT REQUEST '))
        rows.insert(before_kill,rows.pop(index))
        with self.assertRaisesRegex(RuntimeError,'publication order'):
            self.check('Q21','\n'.join(rows),fixture,wire)
        output,fixture,wire = proof()
        with self.assertRaisesRegex(RuntimeError,'framing retirement'):
            self.check('Q21',change(output,'QUIC FIXTURE NATIVE_COUNTS',at_ms=1101),fixture,wire)

    def test_partial_ipc_is_explicitly_retired_within_original_frame_bound(self):
        for size in (0,7,1485):
            output,fixture,wire = proof()
            output = change(output,'QUIC FIXTURE NATIVE_COUNTS',partial_request_bytes=size,partial_reply_bytes=size)
            result = self.check('Q21',output,fixture,wire)
            self.assertEqual(result['interruption']['partial_request_bytes_retired'],size)
        for key in ('partial_request_bytes','partial_reply_bytes'):
            output,fixture,wire = proof()
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError,'framing retirement'):
                self.check('Q21',change(output,'QUIC FIXTURE NATIVE_COUNTS',**{key:1486}),fixture,wire)

    def test_queued_request_is_distinguished_from_wire_emission(self):
        output,fixture,wire = proof()
        extra = line('QUIC FIXTURE SEND',case='Q21',ordinal=2,at_ms=40,bytes=len(STREAM),
                     sha256=digest(STREAM),peer_ip='10.0.2.2',peer_port=4443)
        output = output.replace('QUIC CHILD INTERRUPT OBSERVED ',extra+'\nQUIC CHILD INTERRUPT OBSERVED ')
        output = change(output,'QUIC FIXTURE NATIVE_COUNTS',send_requests=2)
        result = self.check('Q21',output,fixture,wire)['interruption']
        self.assertEqual((result['complete_send_requests'],result['captured_guest_udp']),(2,1))

    def test_q21_requires_real_initial_silence_and_no_engine(self):
        for key,value in [('engine_constructed',True),('authenticated',True),('certificate_selection',{'kind':'valid'}),
                          ('tx_datagrams',1),('request_bytes',1)]:
            output,fixture,wire = proof();fixture[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): self.check('Q21',output,fixture,wire)

    def test_q22_requires_authentication_and_exact_positive_request_prefix(self):
        for key,value in [('authenticated',False),('request_bytes',0),('request_sha256','f'*64),
                          ('echo_enqueued_bytes',1),('echo_fin_enqueued',True),('stream_output_fenced',False),
                          ('terminated',{'error_code':0}),('request_fin',True)]:
            output,fixture,wire = proof('Q22');fixture[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): self.check('Q22',output,fixture,wire)

    def test_q22_fence_label_cannot_replace_triggering_socket_input(self):
        for key,value in [('receive_ordinal',1),('sha256','f'*64),('bytes',127),('authenticated_before',False)]:
            output,fixture,wire = proof('Q22')
            row = next(row for row in fixture['events'] if row['event']=='q22-stream-output-fenced')
            row[key] = value;fixture['stream_output_trigger'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): self.check('Q22',output,fixture,wire)

    def test_q22_engine_or_output_after_stream_fence_refuses(self):
        for name in ('engine-delivered','timer-fired','engine-polled'):
            output,fixture,wire = proof('Q22')
            fixture['events'].append(dict(event=name,receive_ordinal=2,bytes=len(STREAM),
                                          sha256=digest(STREAM),source=['10.0.2.15',7821]))
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError,'engine/output work crossed'):
                self.check('Q22',output,fixture,wire)
        output,fixture,wire = proof('Q22')
        sent = copy.deepcopy(next(row for row in fixture['events'] if row['event']=='udp-send'))
        fixture['events'].append(sent)
        fixture['tx_datagrams'] += 1; fixture['tx_bytes'] += sent['bytes']
        wire['peer_udp'].append({key:sent[key] for key in ('bytes','sha256','source','destination')})
        fence = next(row for row in fixture['events'] if row['event']=='q22-stream-output-fenced')
        for key in ('tx_datagrams','tx_bytes'):
            fence[key] = fixture[key];fixture['stream_output_trigger'][key] = fixture[key]
        with self.assertRaisesRegex(RuntimeError,'stable output census'):
            self.check('Q22',output,fixture,wire)

    def test_false_canonical_flags_or_noncanonical_numbers_refuse(self):
        for prefix,values in [('QUIC CHILD INTERRUPT RETIRED',dict(result_eof='True')),
                              ('QUIC CHILD INTERRUPT REQUEST',dict(requested_ms='01100')),
                              ('QUIC FIXTURE NATIVE_COUNTS',dict(partial_request_bytes='-1'))]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                self.check('Q21',change(output,prefix,**values),fixture,wire)

    def test_original_q01_still_uses_its_normal_result_path(self):
        self.assertEqual(MATRIX.verify_native(BASE.CASE,*BASE.proof(),MANIFEST)['actual_outcome'],'Complete')


if __name__ == '__main__': unittest.main()
