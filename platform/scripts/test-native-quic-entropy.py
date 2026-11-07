#!/usr/bin/env python3
"""Execution-host controls for conditional Q31; authored, not run on build_host.

Synthetic serial/receipt fixtures exercise real selection and oracle code.
Temporary ordinary-case records are explicitly local substitution controls,
never reviewed eligibility, native PASS evidence or a campaign contributor.
No control invokes QEMU or claims that Haswell,-rdrand reaches the consumer.
"""
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


ART = module('entropy_authority_vectors', 'test-native-quic-authority.py')
METHODS = module('entropy_peer_vectors', 'test-native-quic-authority-peer.py')
SELECTION = module('entropy_selection_vectors', 'test-native-quic-control-selection.py')
MATRIX, PEER, WIRE, MANIFEST = ART.MATRIX, METHODS.PEER, METHODS.WIRE, ART.MANIFEST
CASE = MANIFEST['conditional_native_occurrences'][0]
PROFILE = 'q31-absent-rdrand-development'
ORDINARY = MANIFEST['native_occurrences']


def proof():
    output, fixture, wire = ART.proof('Q30')
    output = output.replace('case=Q30', 'case=Q31')
    output = ART.change(output, 'QUIC SERVICE SELECTOR', local_port=7830)
    output = ART.change(output, 'QUIC SERVICE GRANT', local_port=7830)
    output = ART.change(output, 'QUIC BEGIN', unix_time='Some(1792279191)')
    # CPU has no case field. Keep the actual measurement line in the child
    # buffer, before BEGIN, while selecting only the absent-RDRAND variant.
    output = output.replace('leaf1_ecx=1073741824', 'leaf1_ecx=0').replace('rdrand=1', 'rdrand=0')
    output = ART.change(output, 'QUIC RESULT', outcome='Entropy', entropy_attempts=1,
        partial_pipe_reads=0, partial_pipe_writes=0,
        last_send_ms='none', fence_ms='none', pending_exhausted_sha256='none', pending_retry_sha256='none')
    fixture.update(mode='absent-rdrand', readiness_profile=PROFILE,
                   authority_policy='q31-absent-rdrand-v1', marker_sent=False, marker_trigger=None)
    wire['udp_count'] = 0
    return output, fixture, wire


def check(output, fixture, wire):
    return MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)


@contextmanager
def eligibility_fixture():
    """Finite local parser controls, with OS unit inspection explicitly mocked.

    These files are NEVER emitted outside this temporary directory and NEVER
    passed to native_case. Their synthetic provenance is not real eligibility.
    """
    with tempfile.TemporaryDirectory(prefix='q31-synthetic-gate-control-') as temporary:
        registry = Path(temporary)
        run = '11111111-1111-4111-8111-111111111111'
        invocation = 'a'*32
        source = dict(revision='synthetic-source-only', tree='synthetic-tree-only')
        admission = dict(ordinary_registry=str(registry), case_manifest_sha256='b'*64,
                         client_sha256='c'*64, sources=dict(platform=source))
        def seal(path, value):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))
            return hashlib.sha256(path.read_bytes()).hexdigest()
        identity = registry/run/'evidence/UNIT.json'
        identity_sha = seal(identity, dict(invocation_id=invocation, synthetic_control=True))
        receipt = dict(synthetic_control=True, occurrences=[dict(run=run,
            unit='absd-s2-quic-validate-'+run[:8]+'.service', invocation_id=invocation,
            unit_identity_path=str(identity), unit_identity_sha256=identity_sha)], rows=[])
        for case in ORDINARY:
            directory = registry/run/'evidence/native-matrix'/case['id']
            result, inputs = directory/'RESULT.json', directory/'CASE-INPUTS.json'
            result_sha = seal(result, dict(case=case['id'], disposition='PASS', ABSD_execution=True,
                                          synthetic_control=True))
            inputs_sha = seal(inputs, dict(selected_case=case, case_manifest_sha256='b'*64,
                client_elf=dict(sha256='c'*64), source=dict(platform=dict(source, dirty_state='', clean_required=True))))
            receipt['rows'].append(dict(case=case['id'], run=run, result_path=str(result),
                result_sha256=result_sha, inputs_path=str(inputs), inputs_sha256=inputs_sha))
        receipt_path = registry/'synthetic-control-eligibility.json'
        def bind():
            admission['conditional_ordinary_eligibility'] = dict(path=str(receipt_path), sha256=seal(receipt_path, receipt))
        bind()
        def invoke(properties=None):
            bind()
            current = dict(MainPID='0', ControlPID='0', InvocationID=invocation, ActiveState='inactive', LoadState='loaded')
            current.update(properties or {})
            result = SimpleNamespace(stdout='\n'.join(key+'='+value for key,value in current.items()))
            with mock.patch.object(MATRIX.subprocess, 'run', return_value=result) as inspected:
                value = MATRIX.conditional_prerequisite(admission, ORDINARY)
                assert inspected.call_args.args[0][:2] == ['/usr/bin/systemctl', 'show']
                return value
        def change_document(row, kind, **changes):
            path = Path(row[kind+'_path'])
            value = json.loads(path.read_text())
            value.update(changes)
            row[kind+'_sha256'] = seal(path, value)
        yield admission, receipt, invoke, change_document


class EntropyControls(unittest.TestCase):
    def test_exact_conditional_profile_without_manifest_change(self):
        self.assertEqual((CASE['id'],CASE['ordinal'],CASE['local_port'],CASE['expected_outcome']),
                         ('Q31',30,7830,'Entropy'))
        self.assertEqual(hashlib.sha256((ROOT.parent/'quic/CASES.json').read_bytes()).hexdigest(),
                         'a1cd3276a017ac4e2507f919d0c1c362391b4125a72df74f1786e60bbffb6b57')
        self.assertEqual(MATRIX.development_profile(CASE),PROFILE)
        self.assertEqual(PEER.development_profile(CASE),PROFILE)
        for parser in (MATRIX.development_profile,PEER.development_profile):
            with self.assertRaisesRegex(RuntimeError,'IPv6'):
                parser(CASE,'ipv6')

    def test_exact_profile_refuses_changed_preconditions(self):
        for key,value in (('peer_mode','echo'),('local_port',7800),('expected_outcome','Complete'),
                ('grant_lifetime_ms',15001),('missing_time',True),('missing_output',True),
                ('queue_control',True),('suppress_reply',True),('interrupt_phase','Init'),
                ('interrupt_delay_ms',1),('requires',['no_SEND'])):
            for parser in (MATRIX.development_profile,PEER.development_profile):
                with self.subTest(key=key,parser=parser.__name__),self.assertRaises(RuntimeError):
                    parser(dict(CASE,**{key:value}))

    def test_actual_linux_selection_is_q01_and_native_selection_separate_q31(self):
        for requested in ([],['Q01']):
            self.assertEqual(MATRIX.select_development_cases(SELECTION.CASES,PROFILE,'ipv4',True,requested),
                             (['Q01'],['Q01'],'q01-development'))
        for requested in ([],['Q31']):
            self.assertEqual(MATRIX.select_development_cases(SELECTION.CASES,PROFILE,'ipv4',False,requested),
                             (['Q31'],['Q01'],PROFILE))
        for controls,requested in ((True,['Q31']),(False,['Q01']),(False,['Q01','Q31']),
                                  (False,['Q31','Q31'])):
            with self.subTest(controls=controls,requested=requested),self.assertRaises(RuntimeError):
                MATRIX.select_development_cases(SELECTION.CASES,PROFILE,'ipv4',controls,requested)

    def test_real_argparse_admits_only_explicit_profile(self):
        for profile,expected in ((PROFILE,0),('q31-development',2),('q31-no-rng',2)):
            result = subprocess.run([sys.executable,MATRIX.__file__,'--profile',profile,'--help'],
                                    capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,expected,result.stderr)

    def test_real_main_labels_linux_q01_and_refuses_native_without_ordinary30(self):
        with SELECTION.runner_fixture(PROFILE) as invoke:
            code,receipt,cases,calls,native_calls = invoke()
            self.assertEqual((code,calls,native_calls),(0,[('Q01',dict(timeout=1))],0))
            for record in (receipt,cases['Q01']):
                self.assertEqual(record['readiness_profile'],'q01-development')
                self.assertEqual(record['requested_readiness_profile'],PROFILE)
                self.assertFalse(record['ABSD_execution'])
            for key in ('requested_case_ids','attempted_case_ids','completed_case_ids'):
                self.assertEqual(receipt[key],['Q01'])
            code,result,_,calls,native_calls = invoke(controls=False,control_receipt=receipt)
            self.assertEqual((code,native_calls,calls),(1,0,[]))
            self.assertEqual(result['conditional_Q31_status'],'NOT_RUN')
            self.assertEqual(result['attempted_case_ids'],[])
            self.assertIn('conditional_ordinary_eligibility',result['error']['message'])

    def test_linux_cannot_emulate_missing_native_entropy(self):
        with self.assertRaisesRegex(RuntimeError,'separate Linux Q01'):
            PEER.linux_control(CASE,None)
        self.assertIsNone(PEER.load_peer_pki(CASE,Path('/nonexistent-Q31-private-key')))

    def test_complete_local_init_fixture_and_no_fabricated_fenced_time(self):
        result = check(*proof())
        self.assertEqual(result['actual_outcome'],'Entropy')
        self.assertTrue(result['entropy']['consumer_reached'])
        self.assertTrue(result['entropy']['result_eof'])
        self.assertEqual((result['typed_report']['phase'],result['typed_report']['fence_ms']),('Init','none'))

    def test_unsupported_preconsumer_boot_and_missing_begin_never_pass(self):
        output,fixture,wire = proof()
        for changed in ('unsupported CPU before consumer',ART.without(output,'QUIC BEGIN'),
                        '\n'.join(row for row in output.splitlines() if not row.startswith('QUIC CPU '))):
            with self.subTest(changed=changed[:30]),self.assertRaises(RuntimeError):
                check(changed,fixture,wire)

    def test_actual_cpu_measurement_must_show_absent_rdrand(self):
        output,fixture,wire = proof()
        for changed in (output.replace('rdrand=0','rdrand=1'),
                        output.replace('leaf1_ecx=0','leaf1_ecx=1073741824'),
                        output.replace('model=60','model=61')):
            with self.assertRaisesRegex(RuntimeError,'CPU'):
                check(changed,fixture,wire)

    def test_config_time_or_native_error_cannot_substitute_for_entropy(self):
        output,fixture,wire = proof()
        for outcome in ('Config','Time','Native','Interrupted','Complete'):
            with self.subTest(outcome=outcome),self.assertRaises(RuntimeError):
                check(ART.change(output,'QUIC RESULT',outcome=outcome),fixture,wire)
        for key,value in (('native_failure_kind','Unknown'),('native_error_code',14),
                          ('transport_error_code',298),('transport_close_origin','local')):
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                check(ART.change(output,'QUIC RESULT',**{key:value}),fixture,wire)

    def test_entropy_acquisition_is_exactly_one_and_no_ambient_draw(self):
        output,fixture,wire = proof()
        for key,value in (('entropy_attempts',0),('entropy_attempts',2),('unexpected_rng_draws',1)):
            with self.subTest(key=key,value=value),self.assertRaises(RuntimeError):
                check(ART.change(output,'QUIC RESULT',**{key:value}),fixture,wire)

    def test_fenced_callback_or_handshake_is_not_prepare_refusal(self):
        output,fixture,wire = proof()
        for phase in ('Handshake','Stream','Fenced'):
            for changed in (ART.change(output,'QUIC PHASE',phase=phase),
                            ART.change(output,'QUIC RESULT',phase=phase)):
                with self.subTest(phase=phase),self.assertRaises(RuntimeError):
                    check(changed,fixture,wire)
        for key,value in (('fence_ms',0),('last_send_ms',0),('pipe_fenced','false'),
                          ('no_native_pair','true')):
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                check(ART.change(output,'QUIC RESULT',**{key:value}),fixture,wire)

    def test_all_native_engine_application_and_partial_ipc_counters_zero(self):
        output,fixture,wire = proof()
        for key in ('send_calls','send_accepted','send_bytes','receive_calls','received','receive_bytes',
                    'engine_transmits','endpoint_responses_discarded','exhausted','close_calls',
                    'sent_stream','received_stream','sends_after_fence','queue_fills','queue_retry_accepted',
                    'partial_pipe_reads','partial_pipe_writes'):
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                check(ART.change(output,'QUIC RESULT',**{key:1}),fixture,wire)
        for key in ('authenticated','request_fin','peer_fin','request_acked','connection_drained',
                    'close_accepted','unknown_send'):
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                check(ART.change(output,'QUIC RESULT',**{key:'true'}),fixture,wire)

    def test_full_parent_native_census_and_no_hidden_ledger(self):
        output,fixture,wire = proof()
        for key in ('send_requests','receive_delivered','sends_after_owner_expiry',
                    'partial_request_bytes','partial_reply_bytes'):
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                check(ART.change(output,'QUIC FIXTURE NATIVE_COUNTS',**{key:1}),fixture,wire)
        for prefix in ('QUIC FIXTURE SEND','QUIC FIXTURE RX'):
            with self.assertRaisesRegex(RuntimeError,'I/O'):
                check(output+'\n'+ART.line(prefix,case='Q31',ordinal=1),fixture,wire)

    def test_original_clocks_cannot_be_renewed_or_retired_after_deadline(self):
        output,fixture,wire = proof()
        for prefix,key,value in (('QUIC BEGIN','deadline_ms',10011),('QUIC BEGIN','grant_expiry_ms',15002),
                ('QUIC SERVICE GRANT','before_ms',0),('QUIC RESULT','start_ms',9),
                ('QUIC RESULT','end_ms',17),('QUIC FIXTURE NATIVE_COUNTS','at_ms',9),
                ('QUIC CHILD AUTHORITY RETIRED','reaped_ms',11),
                ('QUIC CHILD AUTHORITY RETIRED','retired_ms',10010)):
            with self.subTest(prefix=prefix,key=key),self.assertRaises(RuntimeError):
                check(ART.change(output,prefix,**{key:value}),fixture,wire)

    def test_normal_reap_true_eof_and_absent_authority_are_required(self):
        output,fixture,wire = proof()
        for prefix,key,value in (('QUIC CHILD EXIT','kind',3),('QUIC CHILD EXIT','status',1),
                ('QUIC CHILD EXIT','killed','true'),('QUIC CHILD AUTHORITY RETIRED','result_eof','false'),
                ('QUIC CHILD AUTHORITY RETIRED','process_handle_live','true'),
                ('QUIC CHILD AUTHORITY RETIRED','pipe_live','true'),
                ('QUIC CHILD AUTHORITY RETIRED','grant_live','true'),
                ('QUIC CHILD AUTHORITY RETIRED','owner_expired','true'),
                ('QUIC CHILD AUTHORITY RETIRED','sockets',1),('QUIC SERVICE RETIRE','sockets_after_fence',1),
                ('QUIC SERVICE DONE','cells_after',2)):
            with self.subTest(prefix=prefix,key=key),self.assertRaises(RuntimeError):
                check(ART.change(output,prefix,**{key:value}),fixture,wire)

    def test_required_records_exactly_once_and_physical_order(self):
        output,fixture,wire = proof()
        for prefix in ('QUIC SERVICE GRANT','QUIC BEGIN','QUIC FIXTURE NATIVE_COUNTS',
                'QUIC CHILD AUTHORITY RETIRED','QUIC CHILD EXIT','QUIC RESULT','QUIC SERVICE RETIRE','QUIC SERVICE DONE'):
            for changed in (ART.without(output,prefix),
                            output+'\n'+output.splitlines()[ART.indices(output,prefix)[0]]):
                with self.subTest(prefix=prefix),self.assertRaises(RuntimeError):
                    check(changed,fixture,wire)
        with self.assertRaisesRegex(RuntimeError,'publication'):
            check(ART.move_before(output,'QUIC CHILD AUTHORITY RETIRED','QUIC FIXTURE NATIVE_COUNTS'),fixture,wire)

    def test_valid_native_pair_and_time_are_preconditions_not_entropy_coverage(self):
        output,fixture,wire = proof()
        for key,value in (('native_pair','false'),('unix_time','None')):
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                check(ART.change(output,'QUIC BEGIN',**{key:value}),fixture,wire)

    def test_peer_engine_auth_marker_or_socket_census_cannot_hide(self):
        output,fixture,wire = proof()
        for key,value in (('engine_constructed',True),('authenticated',True),('certificate_selection',{}),
                ('request_bytes',1),('rx_datagrams',1),('tx_datagrams',1),('rx_bytes',1),
                ('tx_bytes',1),('passive_receive_count',1),('marker_sent',True),('marker_trigger',{})):
            changed = copy.deepcopy(fixture); changed[key] = value
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                check(output,changed,wire)

    def test_full_capture_zero_udp_and_foreign_frame_refusal(self):
        captured = WIRE.observe(METHODS.pcap([]),CASE,METHODS.GM,METHODS.PM)
        self.assertEqual(captured['udp_count'],0)
        for guest in (True,False):
            # Construct the literal selected Q31 tuple, with correct checksums.
            cases = dict(METHODS.CASES,Q31=CASE)
            with mock.patch.object(METHODS,'CASES',cases):
                frame = METHODS.frame(b'x',case_id='Q31',guest=guest)
            with self.assertRaises(WIRE.Refusal):
                WIRE.observe(METHODS.pcap([frame]),CASE,METHODS.GM,METHODS.PM)
        with self.assertRaises(WIRE.Refusal):
            WIRE.observe(METHODS.pcap([b'foreign-frame']),CASE,METHODS.GM,METHODS.PM)

    def test_actual_passive_peer_never_constructs_engine_or_sends(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
            sender.bind(('127.0.0.1',0))
            sender.settimeout(0.1)
            peer = PEER.Peer(copy.deepcopy(CASE),pki={'public_control_sentinel':True},
                bind='127.0.0.1',port=0,expected_source=sender.getsockname(),
                timeout=0.5,startup_timeout=1)
            try:
                self.assertEqual(peer.case,CASE)
                self.assertEqual(peer.mode,'absent-rdrand')
                self.assertEqual(peer.report()['authority_policy'],'q31-absent-rdrand-v1')
                self.assertIsNone(peer.pki)
                self.assertIsNone(peer.connection)
                peer.authority_guard()
                for call in (lambda:peer.send(b'output'),
                             lambda:peer.send_authority_marker(METHODS.MARKER,'owner-expiry-marker')):
                    with self.assertRaises(RuntimeError): call()
                self.assertEqual((peer.tx_packets,peer.tx_bytes),(0,0))
                with self.assertRaises(socket.timeout): sender.recvfrom(65536)
            finally:
                peer.close()
            report = peer.report()
            self.assertTrue(peer.stop.is_set())
            self.assertFalse(peer.thread.is_alive())
            self.assertEqual(report['errors'],[])
            self.assertEqual(report['events'][-1]['event'],'peer-ended')
            self.assertTrue(report['events'][-1]['stopped'])
            self.assertFalse(report['engine_constructed'])
            self.assertEqual((report['rx_datagrams'],report['tx_datagrams']), (0,0))

    def test_actual_passive_receive_records_and_refuses_without_response(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
            sender.bind(('127.0.0.1',0))
            sender.settimeout(0.1)
            peer = PEER.Peer(copy.deepcopy(CASE),pki=None,
                bind='127.0.0.1',port=0,expected_source=sender.getsockname(),
                timeout=0.5,startup_timeout=1)
            data = b'unexpected-local-control-input'
            try:
                self.assertEqual(peer.case,CASE)
                self.assertEqual(peer.mode,'absent-rdrand')
                self.assertIsNone(peer.pki)
                self.assertIsNone(peer.connection)
                self.assertEqual(sender.sendto(data,peer.socket.getsockname()),len(data))
                peer.thread.join(timeout=1)
                self.assertFalse(peer.thread.is_alive())
                report = peer.report()
                self.assertEqual(report['authority_policy'],'q31-absent-rdrand-v1')
                self.assertEqual(len(report['errors']),1)
                self.assertEqual(report['errors'][0]['type'],'RuntimeError')
                self.assertEqual(report['errors'][0]['message'],
                                 'Q29/Q30/Q31 passive fixture unexpectedly received UDP')
                self.assertEqual([row['event'] for row in report['events']],
                                 ['udp-receive','passive-input','peer-ended'])
                received,refused,_ = report['events']
                self.assertEqual((received['receive_ordinal'],received['bytes'],received['data_hex']),
                                 (1,len(data),data.hex()))
                self.assertEqual(received['source'],list(sender.getsockname()))
                self.assertEqual(received['sha256'],hashlib.sha256(data).hexdigest())
                self.assertEqual((refused['receive_ordinal'],refused['bytes'],refused['sha256']),
                                 (1,len(data),received['sha256']))
                self.assertIs(refused['engine_delivered'],False)
                self.assertEqual((report['rx_datagrams'],report['rx_bytes'],report['passive_receive_count']),
                                 (1,len(data),1))
                self.assertEqual((report['tx_datagrams'],report['tx_bytes']), (0,0))
                self.assertFalse(report['engine_constructed'])
                self.assertIsNone(report['certificate_selection'])
                self.assertFalse(report['authenticated'])
                self.assertEqual((report['request_bytes'],report['echo_enqueued_bytes']), (0,0))
                with self.assertRaises(socket.timeout): sender.recvfrom(65536)
            finally:
                peer.close()
            self.assertTrue(peer.stop.is_set())
            self.assertFalse(peer.thread.is_alive())
            self.assertEqual(len(peer.report()['errors']),1)


class PrerequisiteControls(unittest.TestCase):
    def test_complete_synthetic_gate_fixture_exercises_unchanged_reader_only(self):
        with eligibility_fixture() as (_,receipt,invoke,_):
            result = invoke()
            self.assertEqual(result['ordinary_rows_checked'],30)
            self.assertEqual(result['ordinary_case_ids'],['Q%02d'%i for i in range(1,31)])
            self.assertEqual(result['ended_contributors'],[receipt['occurrences'][0]['run']])
            result = invoke(dict(InvocationID='',LoadState='not-found',ActiveState='inactive'))
            self.assertEqual(result['ordinary_rows_checked'],30)

    def test_missing_duplicate_or_unknown_ordinary_row_refuses(self):
        for mutation in ('missing','duplicate','unknown'):
            with eligibility_fixture() as (_,receipt,invoke,_):
                if mutation == 'missing': receipt['rows'].pop()
                elif mutation == 'duplicate': receipt['rows'][-1] = copy.deepcopy(receipt['rows'][0])
                else: receipt['rows'][-1]['case'] = 'Q31'
                with self.subTest(mutation=mutation),self.assertRaisesRegex(RuntimeError,'finite30'):
                    invoke()

    def test_live_replaced_or_indeterminate_contributor_refuses(self):
        for properties in (dict(MainPID='1'),dict(ControlPID='2'),dict(InvocationID='b'*32),
                dict(InvocationID='',LoadState='loaded'),dict(InvocationID='',LoadState='not-found',ActiveState='active')):
            with eligibility_fixture() as (_,_,invoke,_):
                with self.subTest(properties=properties),self.assertRaises(RuntimeError): invoke(properties)

    def test_actual_native_pass_required_and_linux_or_failed_receipt_refuses(self):
        for changes in (dict(ABSD_execution=False),dict(disposition='FAIL'),dict(case='Q02')):
            with eligibility_fixture() as (_,receipt,invoke,change):
                change(receipt['rows'][0],'result',**changes)
                with self.subTest(changes=changes),self.assertRaisesRegex(RuntimeError,'actual native PASS'): invoke()

    def test_mixed_client_manifest_case_or_source_refuses(self):
        for field in ('client','manifest','case','revision','tree','dirty','clean'):
            with eligibility_fixture() as (_,receipt,invoke,change):
                row = receipt['rows'][0]
                inputs = json.loads(Path(row['inputs_path']).read_text())
                if field == 'client': inputs['client_elf']['sha256'] = 'd'*64
                elif field == 'manifest': inputs['case_manifest_sha256'] = 'e'*64
                elif field == 'case': inputs['selected_case'] = ORDINARY[1]
                else:
                    source = inputs['source']['platform']
                    source[dict(revision='revision',tree='tree',dirty='dirty_state',clean='clean_required')[field]] = \
                        False if field == 'clean' else 'different'
                change(row,'inputs',**inputs)
                with self.subTest(field=field),self.assertRaises(RuntimeError): invoke()

    def test_missing_or_changed_original_unit_custody_refuses(self):
        for mutation in ('missing','hash','invocation'):
            with eligibility_fixture() as (_,receipt,invoke,_):
                occurrence = receipt['occurrences'][0]
                if mutation == 'missing': Path(occurrence['unit_identity_path']).unlink()
                elif mutation == 'hash': occurrence['unit_identity_sha256'] = 'f'*64
                else: occurrence['invocation_id'] = 'b'*32
                with self.subTest(mutation=mutation),self.assertRaises((RuntimeError,FileNotFoundError)): invoke()

    def test_rows_must_belong_to_connected_ended_contributors(self):
        with eligibility_fixture() as (_,receipt,invoke,_):
            receipt['rows'][0]['run'] = '22222222-2222-4222-8222-222222222222'
            with self.assertRaisesRegex(RuntimeError,'no ended ordinary contributor'): invoke()
        with eligibility_fixture() as (_,receipt,invoke,_):
            other = copy.deepcopy(receipt['occurrences'][0])
            other['run'] = '22222222-2222-4222-8222-222222222222'
            other['unit'] = 'absd-s2-quic-validate-'+other['run'][:8]+'.service'
            path = Path(other['unit_identity_path']).parents[2]/other['run']/'evidence/UNIT.json'
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(dict(invocation_id=other['invocation_id'])))
            other.update(unit_identity_path=str(path),unit_identity_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            receipt['occurrences'].append(other)
            with self.assertRaisesRegex(RuntimeError,'disconnected'): invoke()


if __name__ == '__main__':
    unittest.main()
