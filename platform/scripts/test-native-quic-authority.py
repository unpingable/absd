#!/usr/bin/env python3
"""Finite Q23/Q29/Q30 evidence controls; execute only on the owned test host.

Synthetic records exercise the actual source oracle. They do not establish
native expiry, child reaping, kernel EOF, or protocol behavior. Q29/Q30 have
only a positive Linux Q01 prerequisite, never simulated Linux startup refusal.
"""
import copy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('authority_base', ROOT/'native-quic-q01-source-controls.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
MATRIX, MANIFEST = BASE.MATRIX, BASE.MANIFEST
CASES = {row['id']:row for row in MANIFEST['native_occurrences']}
# Public parser-shaped Initial headers, not authenticated or encrypted packets.
PREFIX = b'\xc0\x00\x00\x00\x01\x08DCIDQ23!\x08SCIDQ23!\x00\x44\x96'
INITIALS = [PREFIX + byte*(1200-len(PREFIX)) for byte in (b'i', b'j')]
MARKER = b'\x00ABSD-QUIC-Q23-INITIAL-OBSERVED'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def line(prefix, **values):
    return prefix+' '+' '.join(key+'='+str(value) for key,value in values.items())


def indices(output, prefix):
    # GRANT must not also select GRANT EXPIRED.
    return [i for i,row in enumerate(output.splitlines()) if row.startswith(prefix+' case=')]


def change(output, prefix, record_index=0, **values):
    rows = output.splitlines()
    index = indices(output, prefix)[record_index]
    fields = MATRIX.fields(rows[index])
    fields.update({key:str(value) for key,value in values.items()})
    rows[index] = line(prefix, **fields)
    return '\n'.join(rows)


def without(output, prefix):
    rows = output.splitlines()
    remove = set(indices(output, prefix))
    return '\n'.join(row for i,row in enumerate(rows) if i not in remove)


def move_before(output, source, destination):
    rows = output.splitlines()
    value = rows.pop(indices(output, source)[0])
    output = '\n'.join(rows)
    rows.insert(indices(output, destination)[0], value)
    return '\n'.join(rows)


def peer_proof(identity='Q23', linux=False):
    case = CASES[identity]
    guest = ['127.0.0.1', 53123] if linux else ['10.0.2.15', case['local_port']]
    peer = ['127.0.0.1', 51970] if linux else ['10.0.2.2', 4443]
    fixture = dict(mode=case['peer_mode'], readiness_profile=MATRIX.development_profile(case),
        canonical_campaign_acceptance=False, authority_policy={
            'Q23':'q23-owner-expiry-v1', 'Q29':'q29-missing-output-v1', 'Q30':'q30-missing-time-v1'}[identity],
        errors=[], thread_alive=False, engine_constructed=False, certificate_selection=None,
        authenticated=False, request_bytes=0, request_fin=False, echo_enqueued_bytes=0,
        echo_fin_enqueued=False, terminated=None, passive_receive_count=0,
        rx_datagrams=0, rx_bytes=0, tx_datagrams=0, tx_bytes=0, events=[])
    wire = dict(guest_udp=[], peer_udp=[], guest_udp_count=0)
    if identity != 'Q23':
        return fixture, wire
    received = [dict(event='udp-receive', receive_ordinal=i, bytes=len(data), sha256=digest(data),
                     data_hex=data.hex(), source=list(guest)) for i,data in enumerate(INITIALS, 1)]
    sent = dict(event='udp-send', send_ordinal=1, bytes=len(MARKER), sha256=digest(MARKER),
                data_hex=MARKER.hex(), source=list(peer), destination=list(guest))
    inputs = [dict(event='owner-expiry-input', receive_ordinal=i, bytes=len(data), sha256=digest(data),
                   engine_delivered=False) for i,data in enumerate(INITIALS, 1)]
    marker = dict(event='expiry-observation-marker', initial_sha256=digest(INITIALS[0]),
                  marker_hex=MARKER.hex(), marker_sha256=digest(MARKER), case_port=case['local_port'], send_ordinal=1)
    trigger = dict(receive_ordinal=1, bytes=1200, sha256=digest(INITIALS[0]), marker_hex=MARKER.hex(),
                   marker_sha256=digest(MARKER), destination=list(guest))
    fixture.update(marker_sent=True, marker_trigger=trigger, rx_datagrams=2, rx_bytes=2400,
        tx_datagrams=1, tx_bytes=len(MARKER), events=[received[0],
            dict(event='initial-observed', receive_ordinal=1, bytes=1200, sha256=digest(INITIALS[0])),
            inputs[0], sent, marker, received[1], inputs[1], dict(event='peer-ended')])
    wire['guest_udp'] = [dict(bytes=row['bytes'], sha256=row['sha256'], source=list(guest), destination=list(peer))
                         for row in received]
    wire['peer_udp'] = [{key:sent[key] for key in ('bytes','sha256','source','destination')}]
    wire['guest_udp_count'] = 2
    return fixture, wire


def proof(identity='Q23'):
    case = CASES[identity]
    active = identity == 'Q23'
    expiry, deadline = 1+case['grant_lifetime_ms'], 3001 if active else 10010
    end, reaped, counted, retired = (3004,3005,3002,3006) if active else (12,14,15,16)
    phase = 'Fenced' if identity != 'Q30' else 'Init'
    report = {field:'0' for field in MANIFEST['report']['fields']}
    report.update(case=identity, outcome=case['expected_outcome'], phase=phase,
        **{key:'false' for key in ('authenticated','request_fin','peer_fin','request_acked',
            'connection_drained','close_accepted','unknown_send')},
        pipe_fenced='false' if identity == 'Q29' else 'true',
        no_native_pair='true' if identity == 'Q29' else 'false',
        native_failure_kind='Deadline' if active else 'none', native_error_code='none', native_error_detail='none',
        transport_error_code='none', transport_close_origin='none', receive_calls='1' if active else '0',
        close_calls='0', entropy_attempts='1' if active else '0', engine_transmits='2' if active else '0',
        send_calls='2' if active else '0', send_accepted='2' if active else '0', send_bytes='2400' if active else '0',
        received='1' if active else '0', receive_bytes=str(len(MARKER)) if active else '0',
        last_send_ms='2000' if active else '0', fence_ms=str(end) if active else '0',
        start_ms='10', end_ms=str(end), deadline_ms=str(deadline), grant_expiry_ms=str(expiry))
    rows = [line('QUIC SERVICE SELECTOR', case=identity, local_port=case['local_port']),
            line('QUIC SERVICE GRANT', case=identity, before_ms=1, constructed_ms=2,
                 owner_expiry_ms=expiry, local_port=case['local_port'], peer_port=4443)]
    if active:
        rows += [line('QUIC FIXTURE SEND', case=identity, ordinal=1, at_ms=30,
                      bytes=1200, sha256=digest(INITIALS[0]), peer_ip='10.0.2.2', peer_port=4443),
                 line('QUIC FIXTURE RX', case=identity, ordinal=1, at_ms=50,
                      bytes=len(MARKER), sha256=digest(MARKER), peer_ip='10.0.2.2', peer_port=4443),
                 line('QUIC FIXTURE SEND', case=identity, ordinal=2, at_ms=2000,
                      bytes=1200, sha256=digest(INITIALS[1]), peer_ip='10.0.2.2', peer_port=4443)]
    rows += [line('QUIC FIXTURE NATIVE_COUNTS', case=identity, at_ms=counted,
                  send_requests=2 if active else 0, receive_delivered=1 if active else 0,
                  sends_after_owner_expiry=0, partial_request_bytes=0, partial_reply_bytes=0)]
    if active:
        rows += [line('QUIC SERVICE GRANT EXPIRED', case=identity, observed_ms=3001, owner_expiry_ms=expiry,
                      revoked_ms=3003, pipe_live='false', grant_live='false', sockets=0)]
    rows += [line('QUIC CHILD AUTHORITY RETIRED', case=identity, reaped_ms=reaped, retired_ms=retired,
                  process_handle_live='false', pipe_live='false', grant_live='false', sockets=0,
                  result_eof='true', owner_expired='true' if active else 'false'),
             line('QUIC CHILD EXIT', case=identity, kind=1, status=0, killed='false'),
             'QUIC CONSUMER case='+identity+' begin',
             line('QUIC CPU', vendor='GenuineIntel', leaf1_eax=0x306c0, leaf1_ecx=1<<30, family=6, model=60, rdrand=1),
             line('QUIC BEGIN', case=identity, start_ms=10, deadline_ms=deadline, grant_expiry_ms=expiry,
                  unix_time='None' if identity == 'Q30' else 'Some(1792279191)',
                  native_pair='false' if identity == 'Q29' else 'true')]
    if active:
        rows += [line('QUIC PHASE', case=identity, phase='Init', at_ms=10),
                 line('QUIC PHASE', case=identity, phase='Handshake', at_ms=20),
                 line('QUIC PHASE', case=identity, phase='Fenced', at_ms=end)]
    else:
        rows += [line('QUIC PHASE', case=identity, phase=phase, at_ms=10)]
    rows += [line('QUIC RESULT', **report), 'QUIC CONSUMER case='+identity+' end',
             line('QUIC SERVICE RETIRE', case=identity, sockets_before_fence=0, sockets_after_fence=0),
             line('QUIC SERVICE DONE', case=identity, sockets=0,
                  **{name+'_'+when:1 for name in ('processes','handles','pipes','cells') for when in ('before','after')})]
    fixture,wire = peer_proof(identity)
    return '\n'.join(rows),fixture,wire


def linux_proof():
    fixture,_ = peer_proof(linux=True)
    sent = next(row for row in fixture['events'] if row['event'] == 'udp-send')
    return dict(fixture=fixture, actual_outcome='Deadline', authenticated=False, received_bytes=0, peer_fin=False,
                client_datagrams=[dict(ordinal=1, engine_delivered=True,
                    **{key:sent[key] for key in ('bytes','sha256','source','data_hex')})])


class AuthorityControls(unittest.TestCase):
    def check(self, identity, output, fixture, wire):
        return MATRIX.verify_native(CASES[identity], output, fixture, wire, MANIFEST)

    def test_selected_canonical_authority_profiles_and_flags(self):
        for identity,port,lifetime,outcome in (('Q23',7822,3000,'Native'),('Q29',7828,15000,'Config'),('Q30',7829,15000,'Time')):
            case = CASES[identity]
            self.assertEqual((case['local_port'],case['grant_lifetime_ms'],case['expected_outcome']), (port,lifetime,outcome))
            for key,value in [('local_port',7800),('grant_lifetime_ms',lifetime+1),('expected_outcome','Complete'),
                              ('peer_mode','echo'),('interrupt_phase','Handshake'),('interrupt_delay_ms',1),
                              ('missing_output',not case['missing_output']),('missing_time',not case['missing_time']),
                              ('queue_control',True),('suppress_reply',True)]:
                with self.subTest(case=identity,key=key), self.assertRaises(RuntimeError):
                    MATRIX.development_profile(dict(case, **{key:value}))
        for key,value in [('observation_marker_hex','00'),('native_failure_kinds',['Deadline'])]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                MATRIX.development_profile(dict(CASES['Q23'], **{key:value}))

    def test_real_argparse_admits_only_the_exact_new_names(self):
        for identity in ('Q23','Q29','Q30'):
            result = subprocess.run([sys.executable,MATRIX.__file__,'--profile',MATRIX.development_profile(CASES[identity]),'--help'],
                                    capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
        for name in ('q23-invented','q29-development','q30-time'):
            result = subprocess.run([sys.executable,MATRIX.__file__,'--profile',name,'--help'],
                                    capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0)

    def test_linux_prerequisite_is_positive_q01_for_native_startup_refusals(self):
        self.assertEqual(MATRIX.peer_control_cases(CASES['Q23']), ['Q23'])
        for identity in ('Q29','Q30'):
            self.assertEqual(MATRIX.peer_control_cases(CASES[identity]), ['Q01'])
            with self.subTest(case=identity), self.assertRaises(RuntimeError):
                MATRIX.verify_linux_owner_expiry(CASES[identity],linux_proof())

    def test_complete_positive_fixtures_exercise_all_three_native_paths(self):
        for identity in ('Q23','Q29','Q30'):
            result = self.check(identity,*proof(identity))
            self.assertEqual(result['actual_outcome'],CASES[identity]['expected_outcome'])
            self.assertTrue(result['authority']['result_eof'])
        # Q29 has no constructed native transport; do not invent a CLOSE/fence.
        self.assertEqual(self.check('Q29',*proof('Q29'))['typed_report']['pipe_fenced'],'false')

    def test_q23_unknown_and_late_parent_wait_preserve_original_deadline(self):
        output,fixture,wire = proof()
        output = change(output,'QUIC RESULT',native_failure_kind='Unknown',native_error_detail='32')
        output = change(output,'QUIC CHILD AUTHORITY RETIRED',reaped_ms=3100,retired_ms=3103)
        output = change(output,'QUIC FIXTURE NATIVE_COUNTS',at_ms=3101)
        output = change(output,'QUIC SERVICE GRANT EXPIRED',observed_ms=3101,revoked_ms=3102)
        result = self.check('Q23',output,fixture,wire)
        self.assertEqual(result['authority']['owner_expiry_ms'],3001)
        self.assertEqual(result['authority']['reaped_ms'],3100)

    def test_missing_output_pipe_can_retire_before_child_begin(self):
        output,fixture,wire = proof('Q29')
        output = change(output,'QUIC FIXTURE NATIVE_COUNTS',at_ms=2)
        result = self.check('Q29',output,fixture,wire)
        self.assertEqual(result['actual_outcome'],'Config')
        self.assertTrue(result['authority']['result_eof'])
        with self.assertRaisesRegex(RuntimeError,'lifetime'):
            self.check('Q29',change(output,'QUIC FIXTURE NATIVE_COUNTS',at_ms=1),fixture,wire)
        for identity in ('Q23','Q30'):
            output,fixture,wire = proof(identity)
            with self.subTest(case=identity), self.assertRaisesRegex(RuntimeError,'lifetime'):
                self.check(identity,change(output,'QUIC FIXTURE NATIVE_COUNTS',at_ms=2),fixture,wire)

    def test_required_records_cannot_be_missing_or_duplicated(self):
        prefixes = ('QUIC SERVICE GRANT','QUIC BEGIN','QUIC CHILD AUTHORITY RETIRED','QUIC CHILD EXIT',
                    'QUIC FIXTURE NATIVE_COUNTS','QUIC RESULT','QUIC SERVICE RETIRE','QUIC SERVICE DONE')
        for identity in ('Q23','Q29','Q30'):
            for prefix in prefixes:
                output,fixture,wire = proof(identity)
                for changed in (without(output,prefix), output+'\n'+output.splitlines()[indices(output,prefix)[0]]):
                    with self.subTest(case=identity,prefix=prefix), self.assertRaises(RuntimeError):
                        self.check(identity,changed,fixture,wire)

    def test_parent_retirement_and_buffered_publication_order_is_required(self):
        for source,destination in [('QUIC CHILD AUTHORITY RETIRED','QUIC FIXTURE NATIVE_COUNTS'),
                                   ('QUIC CHILD EXIT','QUIC CHILD AUTHORITY RETIRED'),
                                   ('QUIC RESULT','QUIC BEGIN'),('QUIC SERVICE DONE','QUIC SERVICE RETIRE')]:
            output,fixture,wire = proof()
            with self.subTest(source=source), self.assertRaisesRegex(RuntimeError,'publication order'):
                self.check('Q23',move_before(output,source,destination),fixture,wire)
        for extra in ('QUIC CONSUMER PARTIAL case=Q23 begin','QUIC CHILD INTERRUPT REQUEST case=Q23 requested_ms=3001'):
            output,fixture,wire = proof()
            with self.subTest(extra=extra), self.assertRaisesRegex(RuntimeError,'publication order'):
                self.check('Q23',output+'\n'+extra,fixture,wire)

    def test_normal_reap_true_eof_and_no_live_authority_are_required(self):
        for identity in ('Q23','Q29','Q30'):
            for prefix,values in [('QUIC CHILD EXIT',dict(kind=3)),('QUIC CHILD EXIT',dict(status=1)),
                                  ('QUIC CHILD EXIT',dict(killed='true'))]+[
                    ('QUIC CHILD AUTHORITY RETIRED',{key:'true'}) for key in ('process_handle_live','pipe_live','grant_live')]+[
                    ('QUIC CHILD AUTHORITY RETIRED',dict(result_eof='false')),
                    ('QUIC CHILD AUTHORITY RETIRED',dict(sockets=1))]:
                output,fixture,wire = proof(identity)
                with self.subTest(case=identity,values=values), self.assertRaisesRegex(RuntimeError,'normal child reap'):
                    self.check(identity,change(output,prefix,**values),fixture,wire)

    def test_socket_and_parent_resource_censuses_cannot_hide_live_objects(self):
        for prefix,values in [('QUIC SERVICE RETIRE',dict(sockets_before_fence=1)),
                              ('QUIC SERVICE RETIRE',dict(sockets_after_fence=1)),('QUIC SERVICE DONE',dict(sockets=1))]+[
                              ('QUIC SERVICE DONE',{key+'_after':2}) for key in ('processes','handles','pipes','cells')]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                self.check('Q23',change(output,prefix,**values),fixture,wire)

    def test_original_expiry_and_child_budget_cannot_be_rebased_or_extended(self):
        for prefix,values in [('QUIC SERVICE GRANT',dict(before_ms=2)),('QUIC SERVICE GRANT',dict(owner_expiry_ms=3002)),
                              ('QUIC BEGIN',dict(deadline_ms=10010)),('QUIC BEGIN',dict(grant_expiry_ms=3002)),
                              ('QUIC RESULT',dict(start_ms=11)),('QUIC RESULT',dict(deadline_ms=3002)),
                              ('QUIC RESULT',dict(grant_expiry_ms=3002)),
                              ('QUIC CHILD AUTHORITY RETIRED',dict(retired_ms=5001))]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaisesRegex(RuntimeError,'lifetime|operation or grant'):
                self.check('Q23',change(output,prefix,**values),fixture,wire)

    def test_an_early_unknown_cannot_be_qualified_by_later_owner_expiry(self):
        output,fixture,wire = proof()
        output = change(output,'QUIC RESULT',native_failure_kind='Unknown',native_error_detail='32',end_ms=3000,fence_ms=3000)
        output = change(output,'QUIC PHASE',record_index=2,at_ms=3000)
        with self.assertRaisesRegex(RuntimeError,'actual original owner expiry'):
            self.check('Q23',output,fixture,wire)

    def test_expired_record_requires_actual_revocation_states_and_clock(self):
        for values in [dict(observed_ms=3000),dict(revoked_ms=3000),dict(owner_expiry_ms=3002),
                       dict(pipe_live='true'),dict(grant_live='true'),dict(sockets=1)]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaisesRegex(RuntimeError,'actual original owner expiry'):
                self.check('Q23',change(output,'QUIC SERVICE GRANT EXPIRED',**values),fixture,wire)
        output,fixture,wire = proof()
        with self.assertRaisesRegex(RuntimeError,'actual original owner expiry'):
            self.check('Q23',change(output,'QUIC CHILD AUTHORITY RETIRED',owner_expired='false'),fixture,wire)
        with self.assertRaisesRegex(RuntimeError,'owner expiry record absent'):
            self.check('Q23',without(output,'QUIC SERVICE GRANT EXPIRED'),fixture,wire)

    def test_complete_native_ledger_ordinals_hashes_tuples_and_times_are_bound(self):
        for prefix,values in [('QUIC FIXTURE SEND',dict(ordinal=2)),('QUIC FIXTURE SEND',dict(sha256='f'*64)),
                              ('QUIC FIXTURE SEND',dict(peer_port=4444)),('QUIC FIXTURE SEND',dict(peer_ip='10.0.2.3')),
                              ('QUIC FIXTURE SEND',dict(at_ms=3001)),('QUIC FIXTURE RX',dict(at_ms=3001)),
                              ('QUIC FIXTURE RX',dict(bytes=1)),('QUIC FIXTURE RX',dict(sha256='f'*64)),
                              ('QUIC FIXTURE NATIVE_COUNTS',dict(send_requests=1)),
                              ('QUIC FIXTURE NATIVE_COUNTS',dict(receive_delivered=0)),
                              ('QUIC FIXTURE NATIVE_COUNTS',dict(sends_after_owner_expiry=1))]:
            output,fixture,wire = proof()
            with self.subTest(prefix=prefix,values=values), self.assertRaises(RuntimeError):
                self.check('Q23',change(output,prefix,**values),fixture,wire)

    def test_a_send_published_after_retirement_is_not_a_preexpiry_dispatch(self):
        output,fixture,wire = proof()
        rows = output.splitlines()
        rows.append(rows.pop(indices(output,'QUIC FIXTURE SEND')[0]))
        with self.assertRaisesRegex(RuntimeError,'native ledger identity'):
            self.check('Q23','\n'.join(rows),fixture,wire)

    def test_marker_requires_literal_bytes_not_an_echo_or_declared_hex_label(self):
        for key,value in [('marker_hex','00'),('marker_sha256','f'*64),('initial_sha256','f'*64),
                          ('case_port',7800),('send_ordinal',2)]:
            output,fixture,wire = proof()
            marker = next(row for row in fixture['events'] if row['event']=='expiry-observation-marker')
            marker[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError,'exact literal marker'):
                self.check('Q23',output,fixture,wire)
        output,fixture,wire = proof()
        sent = next(row for row in fixture['events'] if row['event']=='udp-send')
        sent.update(bytes=4096,sha256=digest(b'e'*4096),data_hex=(b'e'*4096).hex())
        wire['peer_udp'][0].update(bytes=sent['bytes'],sha256=sent['sha256'])
        fixture['tx_bytes'] = 4096
        with self.assertRaisesRegex(RuntimeError,'exact literal marker'):
            self.check('Q23',output,fixture,wire)

    def test_marker_requires_actual_native_delivery_before_original_expiry(self):
        output,fixture,wire = proof()
        output = without(output,'QUIC FIXTURE RX')
        output = change(output,'QUIC FIXTURE NATIVE_COUNTS',receive_delivered=0)
        with self.assertRaisesRegex(RuntimeError,'complete or interrupted framing'):
            self.check('Q23',output,fixture,wire)
        output,fixture,wire = proof()
        with self.assertRaisesRegex(RuntimeError,'native ledger identity'):
            self.check('Q23',change(output,'QUIC FIXTURE RX',at_ms=3001),fixture,wire)

    def test_marker_and_initial_must_have_the_actual_causal_event_order(self):
        for source,destination in [('udp-send','initial-observed'),('expiry-observation-marker','udp-send'),
                                   ('owner-expiry-input','udp-receive')]:
            output,fixture,wire = proof()
            ev = fixture['events']
            value = next(row for row in ev if row['event']==source)
            ev.remove(value)
            ev.insert(next(i for i,row in enumerate(ev) if row['event']==destination),value)
            with self.subTest(source=source), self.assertRaises(RuntimeError): self.check('Q23',output,fixture,wire)

    def test_full_socket_capture_census_rejects_omission_duplication_and_reorder(self):
        for direction in ('guest_udp','peer_udp'):
            for mutation in ('missing','extra','hash'):
                output,fixture,wire = proof()
                if mutation=='missing': wire[direction].pop()
                elif mutation=='extra': wire[direction].append(copy.deepcopy(wire[direction][0]))
                else: wire[direction][0]['sha256'] = 'f'*64
                with self.subTest(direction=direction,mutation=mutation), self.assertRaisesRegex(RuntimeError,'socket/capture'):
                    self.check('Q23',output,fixture,wire)
        output,fixture,wire = proof()
        wire['guest_udp'].reverse()
        with self.assertRaisesRegex(RuntimeError,'socket/capture'): self.check('Q23',output,fixture,wire)

    def test_packet_tuple_and_initial_data_are_not_only_event_names(self):
        for mutation in ('source','destination','initial-hex','initial-version','delivered'):
            output,fixture,wire = proof()
            receive = next(row for row in fixture['events'] if row['event']=='udp-receive')
            sent = next(row for row in fixture['events'] if row['event']=='udp-send')
            if mutation=='source':
                sent['source'] = ['10.0.2.3',4443];wire['peer_udp'][0]['source'] = list(sent['source'])
            elif mutation=='destination':
                sent['destination'][1] = 7800;wire['peer_udp'][0]['destination'] = list(sent['destination'])
            elif mutation=='initial-hex': receive['data_hex'] = '00'*1200
            elif mutation=='initial-version': receive['data_hex'] = receive['data_hex'][:2]+'00000002'+receive['data_hex'][10:]
            else: next(row for row in fixture['events'] if row['event']=='owner-expiry-input')['engine_delivered'] = True
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): self.check('Q23',output,fixture,wire)

    def test_socket_json_counters_reject_boolean_text_float_and_negative(self):
        for value in (True,'2',2.0,-1,None):
            for key in ('rx_datagrams','rx_bytes','tx_datagrams','tx_bytes'):
                output,fixture,wire = proof()
                fixture[key] = value
                with self.subTest(key=key,value=value), self.assertRaises(RuntimeError): self.check('Q23',output,fixture,wire)

    def test_startup_refusal_has_zero_engine_entropy_and_native_io(self):
        for identity in ('Q29','Q30'):
            for key in ('send_calls','send_accepted','send_bytes','receive_calls','received','receive_bytes',
                        'engine_transmits','entropy_attempts'):
                output,fixture,wire = proof(identity)
                with self.subTest(case=identity,key=key), self.assertRaisesRegex(RuntimeError,'startup requirement refusal|pre-SEND refusal|refusal emitted UDP|missing fixture time'):
                    self.check(identity,change(output,'QUIC RESULT',**{key:1}),fixture,wire)

    def test_missing_named_output_and_missing_unix_time_are_distinct_shapes(self):
        for identity,prefix,values in [('Q29','QUIC BEGIN',dict(native_pair='true')),
                                      ('Q29','QUIC RESULT',dict(no_native_pair='false')),
                                      ('Q29','QUIC BEGIN',dict(unix_time='None')),
                                      ('Q30','QUIC BEGIN',dict(native_pair='false')),
                                      ('Q30','QUIC RESULT',dict(no_native_pair='true')),
                                      ('Q30','QUIC BEGIN',dict(unix_time='Some(1792279191)')),
                                      ('Q30','QUIC RESULT',dict(pipe_fenced='false'))]:
            output,fixture,wire = proof(identity)
            with self.subTest(case=identity,values=values), self.assertRaises(RuntimeError):
                self.check(identity,change(output,prefix,**values),fixture,wire)

    def test_startup_phase_and_owner_retirement_cannot_be_substituted(self):
        for identity in ('Q29','Q30'):
            for prefix,values in [('QUIC CHILD AUTHORITY RETIRED',dict(owner_expired='true')),
                                  ('QUIC CHILD AUTHORITY RETIRED',dict(retired_ms=10010)),
                                  ('QUIC RESULT',dict(phase='Handshake')),('QUIC RESULT',dict(unknown_send='true')),
                                  ('QUIC FIXTURE NATIVE_COUNTS',dict(partial_request_bytes=1))]:
                output,fixture,wire = proof(identity)
                with self.subTest(case=identity,values=values), self.assertRaises(RuntimeError):
                    self.check(identity,change(output,prefix,**values),fixture,wire)

    def test_startup_passive_peer_refuses_even_local_datagram_activity(self):
        for identity in ('Q29','Q30'):
            output,fixture,wire = proof(identity)
            fixture['passive_receive_count'] = 1
            with self.subTest(case=identity), self.assertRaisesRegex(RuntimeError,'passive peer'):
                self.check(identity,output,fixture,wire)
            output,fixture,wire = proof(identity)
            wire['guest_udp'].append(dict(bytes=1200,sha256=digest(INITIALS[0]),source=['10.0.2.15',CASES[identity]['local_port']]))
            with self.subTest(case=identity), self.assertRaisesRegex(RuntimeError,'socket/capture'):
                self.check(identity,output,fixture,wire)

    def test_buffered_phase_clocks_must_be_monotone_and_inside_child_lifetime(self):
        for values in [dict(at_ms=9),dict(at_ms=3005),dict(case='Q29')]:
            output,fixture,wire = proof()
            with self.subTest(values=values), self.assertRaisesRegex(RuntimeError,'buffered phase identity or clock'):
                self.check('Q23',change(output,'QUIC PHASE',record_index=1,**values),fixture,wire)
        output,fixture,wire = proof()
        output = change(output,'QUIC PHASE',record_index=0,at_ms=21)
        with self.assertRaisesRegex(RuntimeError,'buffered phase identity or clock'):
            self.check('Q23',output,fixture,wire)

    def test_partial_framing_is_bounded_and_startup_refusal_never_transacts(self):
        output,fixture,wire = proof()
        self.check('Q23',change(output,'QUIC FIXTURE NATIVE_COUNTS',partial_request_bytes=7,partial_reply_bytes=7),fixture,wire)
        for key in ('partial_request_bytes','partial_reply_bytes'):
            output,fixture,wire = proof()
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError,'complete framing retirement'):
                self.check('Q23',change(output,'QUIC FIXTURE NATIVE_COUNTS',**{key:1486}),fixture,wire)

    def test_unrelated_failure_or_authenticated_completion_cannot_qualify(self):
        for key,value in [('authenticated','true'),('sent_stream','1'),('received_stream','1'),('request_fin','true'),
                          ('peer_fin','true'),('request_acked','true'),('connection_drained','true'),('close_accepted','true'),
                          ('close_calls','1'),('transport_error_code','1'),('native_error_code','1'),
                          ('native_failure_kind','Cancelled'),('entropy_attempts','0')]:
            output,fixture,wire = proof()
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.check('Q23',change(output,'QUIC RESULT',**{key:value}),fixture,wire)

    def test_linux_marker_calibrates_delivery_but_never_native_expiry(self):
        observed = linux_proof()
        MATRIX.verify_linux_owner_expiry(CASES['Q23'],observed)
        for key,value in [('actual_outcome','Native'),('authenticated',True),('received_bytes',1),('peer_fin',True)]:
            observed = linux_proof();observed[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError,'Linux owner expiry marker calibration'):
                MATRIX.verify_linux_owner_expiry(CASES['Q23'],observed)
        for mutation in ('missing','extra','hash','raw-bytes','not-delivered','source','ordinal'):
            observed = linux_proof();delivered = observed['client_datagrams']
            if mutation=='missing': delivered.clear()
            elif mutation=='extra': delivered.append(copy.deepcopy(delivered[0]))
            elif mutation=='hash': delivered[0]['sha256'] = 'f'*64
            elif mutation=='raw-bytes': delivered[0]['data_hex'] = '00'
            elif mutation=='not-delivered': delivered[0]['engine_delivered'] = False
            elif mutation=='source': delivered[0]['source'] = ['127.0.0.1',1]
            else: delivered[0]['ordinal'] = 2
            with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError,'exact marker was not delivered'):
                MATRIX.verify_linux_owner_expiry(CASES['Q23'],observed)


if __name__ == '__main__':
    unittest.main()
