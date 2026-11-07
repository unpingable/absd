#!/usr/bin/env python3
"""Bounded Q24 QMP and evidence controls; run on the owned Linux test host.

The server is a local UNIX socket with real Linux peer credentials. These
controls establish command/receipt behavior, not a QEMU link transition,
native link feedback, packet delivery, or guest authority retirement.
Synthetic native records exercise the source oracle, not ABSD execution.
"""
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('quic_link_matrix', ROOT / 'native-quic-q01.py')
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)

HELLO = {'QMP': {'version': {'qemu': {'major': 9, 'minor': 2, 'micro': 0},
                              'package': 'local-control-fixture'}, 'capabilities': []}}
COMMANDS = [
    {'execute': 'qmp_capabilities', 'id': 'capabilities'},
    {'execute': 'set_link', 'arguments': {'name': 'quicnic', 'up': False}, 'id': 'drop-link'},
]
MANIFEST = json.loads((ROOT.parent / 'quic/CASES.json').read_text())
CASE = next(row for row in MANIFEST['native_occurrences'] if row['id'] == 'Q24')
# Structurally valid public Initial header, not authenticated QUIC ciphertext.
INITIAL_PREFIX = b'\xc0\x00\x00\x00\x01\x08DCIDQ24!\x08SCIDQ24!\x00\x44\x96'
INITIAL = INITIAL_PREFIX + b'i' * (1200 - len(INITIAL_PREFIX))


def digest(data):
    return hashlib.sha256(data).hexdigest()


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
    return next(row for row in fixture['events'] if row['event'] == name)


def qmp_receipt(socket_path='/fixture/quic.qmp', pid=4321):
    return {'schema_version': 1, 'socket': str(socket_path), 'expected_qemu_pid': pid,
            'device_id': 'quicnic', 'qmp_acknowledged': True,
            'socket_peer': {'pid': pid, 'uid': os.geteuid(), 'gid': os.getegid()},
            'greeting': copy.deepcopy(HELLO), 'acknowledged_monotonic_ns': 140,
            'exchanges': [{'command': copy.deepcopy(command),
                           'replies': [success(command['id'])]} for command in COMMANDS]}


def link_proof(receipt_path='/fixture/QMP-LINK.json', receipt_hash='a' * 64, pid=4321):
    """Complete synthetic oracle input; this is not a native execution trace."""
    packet = {'bytes': 1200, 'sha256': digest(INITIAL), 'data_hex': INITIAL.hex(),
              'source': ['10.0.2.15', 7823], 'destination': ['10.0.2.2', 4443]}
    action_result = {'qmp_acknowledged': True, 'qmp_receipt': str(receipt_path),
                     'qmp_receipt_sha256': receipt_hash, 'exact_qemu_pid': pid,
                     'device_id': 'quicnic'}
    trigger = {'receive_ordinal': 1, 'bytes': 1200, 'sha256': digest(INITIAL),
               'source': packet['source'], 'destination': packet['destination']}
    events = [
        dict(packet, event='udp-receive', receive_ordinal=1, engine_delivered=False, monotonic_ns=100),
        dict(event='initial-observed', receive_ordinal=1, bytes=1200, sha256=digest(INITIAL), monotonic_ns=110),
        dict(event='link-failure-input', receive_ordinal=1, bytes=1200, sha256=digest(INITIAL),
             engine_delivered=False, dcid_hex=b'DCIDQ24!'.hex(), scid_hex=b'SCIDQ24!'.hex(),
             token_bytes=0, monotonic_ns=120),
        dict(event='link-action-begin', trigger_receive_ordinal=1,
             trigger_sha256=digest(INITIAL), monotonic_ns=130),
        dict(action_result, event='link-action', trigger_receive_ordinal=1,
             trigger_sha256=digest(INITIAL), monotonic_ns=150),
        dict(event='peer-ended', monotonic_ns=160),
    ]
    fixture = dict(case='Q24', mode='link-failure', transport_family='ipv4',
        readiness_profile='q24-link-failure-development', canonical_campaign_acceptance=False,
        link_policy='q24-link-failure-v1', errors=[], thread_alive=False,
        engine_constructed=False, certificate_selection=None, authenticated=False,
        request_bytes=0, request_sha256=digest(b''), request_fin=False, echo_enqueued_bytes=0,
        echo_fin_enqueued=False, terminated=None, rx_datagrams=1, rx_bytes=1200,
        tx_datagrams=0, tx_bytes=0, events=events, link_action_attempted=True,
        link_action_completed=True, link_action_result=copy.deepcopy(action_result),
        link_trigger=copy.deepcopy(trigger))
    wire = dict(guest_udp=[dict(packet, ordinal=1, first_byte=INITIAL[0], timestamp=1.0)],
                peer_udp=[], guest_udp_count=1, peer_udp_count=0,
                guest_udp_bytes=1200, peer_udp_bytes=0)
    report = {field: '0' for field in MANIFEST['report']['fields']}
    report.update(case='Q24', outcome='Native', phase='Fenced',
        **{key: 'false' for key in ('authenticated', 'request_fin', 'peer_fin', 'request_acked',
                                   'connection_drained', 'close_accepted', 'unknown_send')},
        pipe_fenced='true', no_native_pair='false', native_failure_kind='Native',
        native_error_code='9', native_error_detail='none', transport_error_code='none',
        transport_close_origin='none', engine_transmits='1', send_calls='1', send_accepted='1',
        send_bytes='1200', receive_calls='2', close_calls='0', entropy_attempts='1',
        pending_exhausted_sha256='none', pending_retry_sha256='none',
        start_ms='10', end_ms='80', deadline_ms='10010', grant_expiry_ms='15001',
        last_send_ms='32', fence_ms='75', partial_pipe_reads='0', partial_pipe_writes='0')
    output = '\n'.join([
        line('QUIC SERVICE SELECTOR', case='Q24', local_port=7823),
        line('QUIC FIXTURE LINK', case='Q24', at_ms=1, present='true', link_up='true', disabled='false'),
        line('QUIC SERVICE GRANT', case='Q24', before_ms=1, constructed_ms=2,
             owner_expiry_ms=15001, local_port=7823, peer_port=4443),
        line('QUIC FIXTURE SEND', case='Q24', ordinal=1, at_ms=30, bytes=1200,
             sha256=digest(INITIAL), peer_ip='10.0.2.2', peer_port=4443),
        line('QUIC FIXTURE LINK', case='Q24', at_ms=50, present='true', link_up='false', disabled='false'),
        line('QUIC FIXTURE NATIVE_COUNTS', case='Q24', at_ms=85, send_requests=1,
             receive_delivered=0, sends_after_owner_expiry=0, partial_request_bytes=0, partial_reply_bytes=0),
        line('QUIC CHILD AUTHORITY RETIRED', case='Q24', reaped_ms=90, retired_ms=91,
             process_handle_live='false', pipe_live='false', grant_live='false',
             sockets=0, result_eof='true', owner_expired='false'),
        line('QUIC CHILD EXIT', case='Q24', kind=1, status=0, killed='false'),
        'QUIC CONSUMER case=Q24 begin',
        line('QUIC CPU', vendor='GenuineIntel', family=6, model=60, leaf1_eax=0x306c0,
             leaf1_ecx=1 << 30, rdrand=1),
        line('QUIC BEGIN', case='Q24', start_ms=10, deadline_ms=10010,
             grant_expiry_ms=15001, unix_time='Some(1792282393)', native_pair='true', body_len=4096),
        line('QUIC PHASE', case='Q24', phase='Init', at_ms=10),
        line('QUIC PHASE', case='Q24', phase='Handshake', at_ms=20),
        line('QUIC PHASE', case='Q24', phase='Fenced', at_ms=76),
        line('QUIC RESULT', **report),
        'QUIC CONSUMER case=Q24 end',
        line('QUIC SERVICE RETIRE', case='Q24', sockets_before_fence=0, sockets_after_fence=0),
        line('QUIC SERVICE DONE', case='Q24', sockets=0,
             **{name + '_' + when: 1 for name in ('processes', 'handles', 'pipes', 'cells')
                for when in ('before', 'after')}),
    ])
    return output, fixture, wire


def encoded(value):
    return value if isinstance(value, bytes) else (json.dumps(value) + '\r\n').encode()


def success(identity):
    return {'return': {}, 'id': identity}


class LocalQMP:
    """One bounded connection, at most two commands, no QEMU or subprocess."""
    def __init__(self, directory, greeting=HELLO, responses=None):
        self.path = Path(directory) / 'control.sock'
        self.receipt = Path(directory) / 'receipt.json'
        self.greeting = greeting
        self.responses = responses if responses is not None else [
            [success('capabilities')], [success('drop-link')]]
        self.commands, self.command_times, self.errors = [], [], []
        self.greeting_sent = False
        self.stop = threading.Event()
        self.connection = None
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.settimeout(0.1)
        self.listener.bind(str(self.path))
        self.path.chmod(0o600)
        self.listener.listen(1)
        self.thread = threading.Thread(target=self.serve, name='local-qmp-control')

    def serve(self):
        try:
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            self.connection = connection
            connection.settimeout(2.5)
            with connection, connection.makefile('rb') as source:
                greeting = encoded(self.greeting)
                connection.sendall(greeting)
                self.greeting_sent = True
                if not greeting.endswith(b'\n'):
                    return
                for responses in self.responses:
                    raw = source.readline(16385)
                    if not raw:
                        return
                    if not raw.endswith(b'\n') or len(raw) > 16384:
                        raise AssertionError('client command framing differs')
                    self.commands.append(json.loads(raw))
                    self.command_times.append(time.monotonic_ns())
                    if responses is None:
                        return
                    for response in responses:
                        raw = encoded(response)
                        connection.sendall(raw)
                        if not raw.endswith(b'\n'):
                            return
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            # Early client refusal is expected in the negative controls.
            pass
        except OSError as error:
            if not self.stop.is_set():
                self.errors.append(repr(error))
        except BaseException as error:
            self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.listener.close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise AssertionError('bounded local QMP server did not retire')
        if self.errors:
            raise AssertionError('local QMP server failed: ' + repr(self.errors))


@contextmanager
def server(**kwargs):
    with tempfile.TemporaryDirectory(prefix='absd-qmp-') as directory:
        value = LocalQMP(directory, **kwargs)
        value.thread.start()
        try:
            yield value
        finally:
            value.close()


class QMPLinkControls(unittest.TestCase):
    def call(self, value, expected_pid=None):
        return MATRIX.qmp_link_down(value.path,
                                    os.getpid() if expected_pid is None else expected_pid,
                                    value.receipt)

    def refused(self, value, commands, message=None, expected_pid=None):
        # Requiring an actual command prefix and peer-credential receipt keeps
        # an unrelated setup failure from satisfying a reply-boundary control.
        with self.assertRaises(Exception) as caught:
            self.call(value, expected_pid)
        if message is not None:
            self.assertIn(message, str(caught.exception))
        receipt = json.loads(value.receipt.read_text())
        self.assertIs(receipt['qmp_acknowledged'], False)
        self.assertIn('error', receipt)
        self.assertNotIn('acknowledged_monotonic_ns', receipt)
        self.assertEqual(value.commands, commands)
        if expected_pid is None:
            self.assertEqual(receipt['socket_peer']['pid'], os.getpid())
            self.assertEqual(receipt['socket_peer']['uid'], os.geteuid())
        return receipt

    def test_exact_commands_real_peer_and_hashed_receipt(self):
        with server() as value:
            before = time.monotonic_ns()
            result = self.call(value)
            after = time.monotonic_ns()
            self.assertEqual(value.commands, COMMANDS)
            receipt = json.loads(value.receipt.read_text())
            self.assertIs(receipt['qmp_acknowledged'], True)
            self.assertEqual(receipt['socket'], str(value.path))
            self.assertEqual(receipt['expected_qemu_pid'], os.getpid())
            self.assertEqual(receipt['socket_peer'],
                             {'pid': os.getpid(), 'uid': os.geteuid(), 'gid': os.getegid()})
            self.assertEqual(receipt['device_id'], 'quicnic')
            self.assertEqual(receipt['greeting'], HELLO)
            self.assertEqual([row['command'] for row in receipt['exchanges']], COMMANDS)
            self.assertEqual([row['replies'] for row in receipt['exchanges']],
                             [[success('capabilities')], [success('drop-link')]])
            self.assertLessEqual(before, receipt['acknowledged_monotonic_ns'])
            self.assertLessEqual(value.command_times[-1], receipt['acknowledged_monotonic_ns'])
            self.assertLessEqual(receipt['acknowledged_monotonic_ns'], after)
            self.assertNotIn('error', receipt)
            self.assertEqual(result, {
                'qmp_acknowledged': True, 'qmp_receipt': str(value.receipt),
                'qmp_receipt_sha256': hashlib.sha256(value.receipt.read_bytes()).hexdigest(),
                'exact_qemu_pid': os.getpid(), 'device_id': 'quicnic'})

    def test_wrong_guest_pid_refuses_before_commands(self):
        with server() as value:
            receipt = self.refused(value, [], 'peer differs', expected_pid=os.getpid() + 1)
            self.assertEqual(receipt['expected_qemu_pid'], os.getpid() + 1)
            self.assertNotIn('socket_peer', receipt)

    def test_missing_qmp_greeting_refuses_before_commands(self):
        with server(greeting={'event': 'RESET'}) as value:
            self.refused(value, [], 'greeting')

    def test_malformed_greeting_types_do_not_authorize_commands(self):
        for greeting in (None, [], 'QMP', {'QMP': None}, {'QMP': []}, {'QMP': 'version'}):
            with self.subTest(greeting=greeting), server(greeting=greeting) as value:
                self.refused(value, [])

    def test_greeting_version_and_capability_shapes_refuse(self):
        malformed = []
        for key in ('version', 'capabilities'):
            greeting = copy.deepcopy(HELLO)
            del greeting['QMP'][key]
            malformed.append((key + '-missing', greeting))
            for replacement in (None, 'fixture', True):
                greeting = copy.deepcopy(HELLO)
                greeting['QMP'][key] = replacement
                malformed.append((key + '-' + repr(replacement), greeting))
        for replacement in (None, [], 'qemu'):
            greeting = copy.deepcopy(HELLO)
            greeting['QMP']['version']['qemu'] = replacement
            malformed.append(('qemu-' + repr(replacement), greeting))
        greeting = copy.deepcopy(HELLO)
        del greeting['QMP']['version']['qemu']
        malformed.append(('qemu-missing', greeting))
        for key in ('major', 'minor', 'micro'):
            greeting = copy.deepcopy(HELLO)
            del greeting['QMP']['version']['qemu'][key]
            malformed.append((key + '-missing', greeting))
            for replacement in (None, True, 1.5, '1'):
                greeting = copy.deepcopy(HELLO)
                greeting['QMP']['version']['qemu'][key] = replacement
                malformed.append((key + '-' + repr(replacement), greeting))
        greeting = copy.deepcopy(HELLO)
        greeting['QMP']['capabilities'] = {}
        malformed.append(('capabilities-object', greeting))
        for label, greeting in malformed:
            with self.subTest(shape=label), server(greeting=greeting) as value:
                self.refused(value, [])

    def test_invalid_json_greeting_refuses_before_commands(self):
        with server(greeting=b'not JSON\n') as value:
            self.refused(value, [])

    def test_unterminated_greeting_refuses_before_commands(self):
        with server(greeting=b'{"QMP":{}}') as value:
            self.refused(value, [], 'framing')

    def test_overlong_greeting_refuses_before_commands(self):
        with server(greeting=b'x' * 16384 + b'\n') as value:
            self.refused(value, [], 'framing')

    def test_wrong_reply_id_cannot_acknowledge_either_command(self):
        for index in range(2):
            replies = [[success('capabilities')], [success('drop-link')]]
            replies[index] = [success('unrelated-id')]
            with self.subTest(command=index), server(responses=replies) as value:
                self.refused(value, COMMANDS[:index + 1])

    def test_qmp_error_stops_before_later_commands(self):
        for index, identity in enumerate(('capabilities', 'drop-link')):
            replies = [[success('capabilities')], [success('drop-link')]]
            replies[index] = [{'id': identity, 'error': {'class': 'GenericError', 'desc': 'fixture refusal'}}]
            with self.subTest(command=index), server(responses=replies) as value:
                self.refused(value, COMMANDS[:index + 1], 'command failed')

    def test_error_plus_return_is_not_success(self):
        for index, identity in enumerate(('capabilities', 'drop-link')):
            replies = [[success('capabilities')], [success('drop-link')]]
            replies[index] = [dict(success(identity), error={'class': 'GenericError'})]
            with self.subTest(command=index), server(responses=replies) as value:
                self.refused(value, COMMANDS[:index + 1], 'command failed')

    def test_matching_id_without_return_refuses(self):
        for index, identity in enumerate(('capabilities', 'drop-link')):
            replies = [[success('capabilities')], [success('drop-link')]]
            replies[index] = [{'id': identity}]
            with self.subTest(command=index), server(responses=replies) as value:
                self.refused(value, COMMANDS[:index + 1], 'command failed')

    def test_reply_must_be_an_object_with_object_return(self):
        for index, identity in enumerate(('capabilities', 'drop-link')):
            malformed = [None, [], 'QMP', True]
            malformed += [{'id': identity, 'return': value} for value in (None, [], 'ok', True)]
            for changed in malformed:
                replies = [[success('capabilities')], [success('drop-link')]]
                replies[index] = [changed]
                with self.subTest(command=index, reply=changed), server(responses=replies) as value:
                    self.refused(value, COMMANDS[:index + 1])

    def test_invalid_json_command_reply_refuses(self):
        for index in range(2):
            replies = [[success('capabilities')], [success('drop-link')]]
            replies[index] = [b'not JSON\n']
            with self.subTest(command=index), server(responses=replies) as value:
                self.refused(value, COMMANDS[:index + 1])

    def test_command_reply_framing_and_bound_refuse(self):
        for index in range(2):
            for raw in (b'{"return":{}}', b'x' * 16384 + b'\n'):
                replies = [[success('capabilities')], [success('drop-link')]]
                replies[index] = [raw]
                with self.subTest(command=index, size=len(raw)), server(responses=replies) as value:
                    self.refused(value, COMMANDS[:index + 1], 'framing')

    def test_closed_connection_is_not_command_acknowledgment(self):
        for index in range(2):
            replies = [[success('capabilities')], [success('drop-link')]]
            replies[index] = None
            with self.subTest(command=index), server(responses=replies) as value:
                self.refused(value, COMMANDS[:index + 1], 'framing')

    def test_thirty_second_reply_can_be_exact_acknowledgment(self):
        replies = [[{'event': 'FIXTURE', 'data': {'ordinal': n}} for n in range(31)]
                   + [success(identity)] for identity in ('capabilities', 'drop-link')]
        with server(responses=replies) as value:
            result = self.call(value)
            self.assertTrue(result['qmp_acknowledged'])
            self.assertEqual(value.commands, COMMANDS)
            receipt = json.loads(value.receipt.read_text())
            self.assertEqual([len(row['replies']) for row in receipt['exchanges']], [32, 32])
            self.assertEqual([row['replies'][-1] for row in receipt['exchanges']],
                             [success('capabilities'), success('drop-link')])

    def test_thirty_two_unrelated_replies_refuse_even_if_ack_follows(self):
        for index, identity in enumerate(('capabilities', 'drop-link')):
            replies = [[success('capabilities')], [success('drop-link')]]
            replies[index] = [success('unrelated-' + str(n)) for n in range(32)] + [success(identity)]
            with self.subTest(command=index), server(responses=replies) as value:
                self.refused(value, COMMANDS[:index + 1], 'reply ceiling')

    def test_absent_path_has_failure_receipt_and_no_ack(self):
        with tempfile.TemporaryDirectory(prefix='absd-qmp-') as directory:
            path, receipt = Path(directory) / 'absent.sock', Path(directory) / 'receipt.json'
            with self.assertRaises(FileNotFoundError):
                MATRIX.qmp_link_down(path, os.getpid(), receipt)
            result = json.loads(receipt.read_text())
            self.assertFalse(result['qmp_acknowledged'])
            self.assertEqual(result['exchanges'], [])
            self.assertIn('error', result)

    def test_regular_file_replacing_socket_is_not_contacted(self):
        with server() as value:
            value.path.unlink()
            value.path.write_text('replacement fixture\n')
            with self.assertRaisesRegex(RuntimeError, 'owned QMP socket'):
                self.call(value)
            self.assertEqual(value.commands, [])
            self.assertEqual(value.path.read_text(), 'replacement fixture\n')
            receipt = json.loads(value.receipt.read_text())
            self.assertFalse(receipt['qmp_acknowledged'])
            self.assertNotIn('socket_peer', receipt)

    def test_symlink_to_owned_socket_is_not_the_exact_socket_path(self):
        with server() as value:
            alias = value.path.parent / 'alias.sock'
            alias.symlink_to(value.path)
            with self.assertRaisesRegex(RuntimeError, 'owned QMP socket'):
                MATRIX.qmp_link_down(alias, os.getpid(), value.receipt)
            self.assertEqual(value.commands, [])
            receipt = json.loads(value.receipt.read_text())
            self.assertFalse(receipt['qmp_acknowledged'])
            self.assertNotIn('socket_peer', receipt)


class NativeLinkControls(unittest.TestCase):
    def check(self, output, fixture, wire, case=CASE):
        return MATRIX.verify_native(case, output, fixture, wire, MANIFEST)

    def test_complete_native_and_peer_link_fixture(self):
        output, fixture, wire = link_proof()
        result = self.check(output, fixture, wire)
        self.assertEqual(result['actual_outcome'], 'Native')
        self.assertEqual(result['typed_report']['native_error_code'], '9')
        self.assertEqual(result['link']['guest_link_down_ms'], 50)
        self.assertTrue(result['link']['result_eof'])
        self.assertEqual(result['link']['complete_send_requests'], 1)
        self.assertEqual(MATRIX.verify_link_peer(CASE, fixture, wire)['trigger_sha256'], digest(INITIAL))

    def test_exact_q24_selector_and_positive_linux_prerequisite(self):
        self.assertEqual(MATRIX.development_profile(CASE), 'q24-link-failure-development')
        self.assertEqual(MATRIX.peer_control_cases(CASE), ['Q01'])
        for key, value in [('local_port', 7800), ('grant_lifetime_ms', 15001),
                           ('expected_outcome', 'Complete'), ('peer_mode', 'echo'),
                           ('native_error_codes', [8, 9, 10, 11]), ('interrupt_phase', 'Handshake'),
                           ('interrupt_delay_ms', 1), ('queue_control', True),
                           ('suppress_reply', True), ('missing_output', True), ('missing_time', True)]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                MATRIX.development_profile(dict(CASE, **{key: value}))

    def test_required_native_records_are_unique_and_present(self):
        output, fixture, wire = link_proof()
        for prefix in ('QUIC SERVICE SELECTOR', 'QUIC SERVICE GRANT', 'QUIC BEGIN',
                       'QUIC FIXTURE NATIVE_COUNTS', 'QUIC CHILD AUTHORITY RETIRED',
                       'QUIC CHILD EXIT', 'QUIC RESULT', 'QUIC SERVICE RETIRE', 'QUIC SERVICE DONE'):
            rows = output.splitlines()
            index = next(i for i, row in enumerate(rows) if row.startswith(prefix + ' case='))
            for changed in ('\n'.join(rows[:index] + rows[index + 1:]), output + '\n' + rows[index]):
                with self.subTest(prefix=prefix), self.assertRaises(RuntimeError):
                    self.check(changed, fixture, wire)

    def test_stale_deadline_and_other_native_causes_cannot_replace_link_down(self):
        output, fixture, wire = link_proof()
        for values in ({'native_error_code': '8'}, {'native_error_code': '10'},
                       {'native_error_code': '11'}, {'native_failure_kind': 'Deadline', 'native_error_code': 'none'},
                       {'native_failure_kind': 'Unknown', 'native_error_code': 'none'},
                       {'native_error_detail': '110'}, {'transport_error_code': '0', 'transport_close_origin': 'peer'},
                       {'outcome': 'Complete'}):
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                self.check(change(output, 'QUIC RESULT', **values), fixture, wire)

    def test_two_actual_guest_link_readings_cannot_be_substituted(self):
        output, fixture, wire = link_proof()
        for index, values in [(0, {'present': 'false'}), (0, {'link_up': 'false'}),
                              (0, {'disabled': 'true'}), (0, {'at_ms': 3}),
                              (1, {'present': 'false'}), (1, {'link_up': 'true'}),
                              (1, {'disabled': 'true'}), (1, {'at_ms': 9}), (1, {'at_ms': 92})]:
            with self.subTest(index=index, values=values), self.assertRaises(RuntimeError):
                self.check(change(output, 'QUIC FIXTURE LINK', index, **values), fixture, wire)
        rows = output.splitlines()
        links = [i for i, row in enumerate(rows) if row.startswith('QUIC FIXTURE LINK ')]
        for changed in ('\n'.join(row for i, row in enumerate(rows) if i != links[1]),
                        output + '\n' + rows[links[1]]):
            with self.assertRaises(RuntimeError):
                self.check(changed, fixture, wire)

    def test_original_grant_and_child_clock_budget_are_not_extended(self):
        output, fixture, wire = link_proof()
        for prefix, values in [('QUIC SERVICE GRANT', {'owner_expiry_ms': 15002}),
                               ('QUIC SERVICE GRANT', {'constructed_ms': 11}),
                               ('QUIC BEGIN', {'deadline_ms': 10011}),
                               ('QUIC BEGIN', {'grant_expiry_ms': 15002}),
                               ('QUIC BEGIN', {'unix_time': 'None'}),
                               ('QUIC BEGIN', {'native_pair': 'false'}),
                               ('QUIC RESULT', {'end_ms': 10010}),
                               ('QUIC RESULT', {'deadline_ms': 10011}),
                               ('QUIC RESULT', {'start_ms': 11}),
                               ('QUIC RESULT', {'fence_ms': 81}),
                               ('QUIC RESULT', {'last_send_ms': 76}),
                               ('QUIC FIXTURE NATIVE_COUNTS', {'at_ms': 9}),
                               ('QUIC FIXTURE NATIVE_COUNTS', {'at_ms': 92})]:
            with self.subTest(prefix=prefix, values=values), self.assertRaises(RuntimeError):
                self.check(change(output, prefix, **values), fixture, wire)

    def test_normal_reap_true_eof_and_no_live_authority_are_required(self):
        output, fixture, wire = link_proof()
        for prefix, values in [('QUIC CHILD EXIT', {'kind': 3}), ('QUIC CHILD EXIT', {'status': 1}),
                               ('QUIC CHILD EXIT', {'killed': 'true'}),
                               *[('QUIC CHILD AUTHORITY RETIRED', {key: 'true'})
                                 for key in ('process_handle_live', 'pipe_live', 'grant_live', 'owner_expired')],
                               ('QUIC CHILD AUTHORITY RETIRED', {'result_eof': 'false'}),
                               ('QUIC CHILD AUTHORITY RETIRED', {'reaped_ms': 79}),
                               ('QUIC CHILD AUTHORITY RETIRED', {'retired_ms': 89}),
                               ('QUIC CHILD AUTHORITY RETIRED', {'sockets': 1})]:
            with self.subTest(prefix=prefix, values=values), self.assertRaises(RuntimeError):
                self.check(change(output, prefix, **values), fixture, wire)
        expired = line('QUIC SERVICE GRANT EXPIRED', case='Q24', observed_ms=15001,
                       owner_expiry_ms=15001, revoked_ms=15001, pipe_live='false', grant_live='false', sockets=0)
        with self.assertRaises(RuntimeError):
            self.check(output + '\n' + expired, fixture, wire)

    def test_parent_resource_counts_and_zero_sockets_are_required(self):
        output, fixture, wire = link_proof()
        for key in ('processes_after', 'handles_after', 'pipes_after', 'cells_after', 'sockets'):
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                self.check(change(output, 'QUIC SERVICE DONE', **{key: 2}), fixture, wire)
        for key in ('sockets_before_fence', 'sockets_after_fence'):
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                self.check(change(output, 'QUIC SERVICE RETIRE', **{key: 1}), fixture, wire)

    def test_no_authentication_application_or_post_fence_api_calls(self):
        output, fixture, wire = link_proof()
        for key, value in [('authenticated', 'true'), ('request_fin', 'true'), ('peer_fin', 'true'),
                           ('request_acked', 'true'), ('connection_drained', 'true'), ('close_accepted', 'true'),
                           ('unknown_send', 'true'), ('pipe_fenced', 'false'), ('no_native_pair', 'true'),
                           ('sent_stream', 1), ('received_stream', 1), ('close_calls', 1),
                           ('entropy_attempts', 0), ('unexpected_rng_draws', 1), ('sends_after_fence', 1)]:
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                self.check(change(output, 'QUIC RESULT', **{key: value}), fixture, wire)

    def test_buffered_child_phase_and_publication_order_are_checked(self):
        output, fixture, wire = link_proof()
        for index, values in [(0, {'phase': 'Closing'}), (1, {'phase': 'Stream'}),
                              (1, {'at_ms': 9}), (2, {'at_ms': 81})]:
            with self.subTest(index=index, values=values), self.assertRaises(RuntimeError):
                self.check(change(output, 'QUIC PHASE', index, **values), fixture, wire)
        rows = output.splitlines()
        census = rows.pop(next(i for i, row in enumerate(rows) if row.startswith('QUIC FIXTURE NATIVE_COUNTS ')))
        rows.append(census)
        with self.assertRaises(RuntimeError):
            self.check('\n'.join(rows), fixture, wire)

    def test_complete_native_send_ledger_requires_tuple_hash_order_and_census(self):
        output, fixture, wire = link_proof()
        for prefix, values in [('QUIC FIXTURE SEND', {'ordinal': 2}),
                               ('QUIC FIXTURE SEND', {'bytes': 1199}),
                               ('QUIC FIXTURE SEND', {'sha256': 'b' * 64}),
                               ('QUIC FIXTURE SEND', {'peer_ip': '10.0.2.3'}),
                               ('QUIC FIXTURE SEND', {'peer_port': 4444}),
                               ('QUIC FIXTURE SEND', {'at_ms': 86}),
                               ('QUIC FIXTURE SEND', {'at_ms': 51}),
                               ('QUIC FIXTURE NATIVE_COUNTS', {'send_requests': 0}),
                               ('QUIC FIXTURE NATIVE_COUNTS', {'sends_after_owner_expiry': 1}),
                               ('QUIC FIXTURE NATIVE_COUNTS', {'partial_request_bytes': 1486}),
                               ('QUIC FIXTURE NATIVE_COUNTS', {'partial_reply_bytes': 1486}),
                               ('QUIC RESULT', {'send_accepted': 0}),
                               ('QUIC RESULT', {'send_bytes': 1199})]:
            with self.subTest(prefix=prefix, values=values), self.assertRaises(RuntimeError):
                self.check(change(output, prefix, **values), fixture, wire)

    def test_native_receive_or_peer_output_is_not_the_selected_link_fixture(self):
        output, fixture, wire = link_proof()
        for prefix, values in [('QUIC FIXTURE NATIVE_COUNTS', {'receive_delivered': 1}),
                               ('QUIC RESULT', {'received': 1}), ('QUIC RESULT', {'receive_bytes': 1})]:
            with self.subTest(prefix=prefix), self.assertRaises(RuntimeError):
                self.check(change(output, prefix, **values), fixture, wire)
        changed = copy.deepcopy(wire)
        changed['peer_udp'] = [dict(changed['guest_udp'][0], source=['10.0.2.2', 4443])]
        with self.assertRaises(RuntimeError):
            self.check(output, fixture, changed)

    def test_peer_engine_output_and_application_substitutions_refuse(self):
        output, fixture, wire = link_proof()
        for key, value in [('mode', 'echo'), ('link_policy', 'invented'), ('canonical_campaign_acceptance', True),
                           ('engine_constructed', True), ('certificate_selection', {'kind': 'valid'}),
                           ('authenticated', True), ('request_bytes', 1), ('request_fin', True),
                           ('echo_enqueued_bytes', 1), ('echo_fin_enqueued', True),
                           ('terminated', {'error_code': 0}), ('tx_datagrams', 1), ('tx_bytes', 1),
                           ('thread_alive', True), ('errors', [{'message': 'fixture failure'}])]:
            changed = copy.deepcopy(fixture)
            changed[key] = value
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                self.check(output, changed, wire)

    def test_peer_callback_must_follow_the_first_actual_initial_once(self):
        output, fixture, wire = link_proof()
        for name in ('udp-receive', 'initial-observed', 'link-failure-input', 'link-action-begin', 'link-action'):
            changed = copy.deepcopy(fixture)
            changed['events'].remove(event(changed, name))
            with self.subTest(missing=name), self.assertRaises(RuntimeError):
                self.check(output, changed, wire)
        for field in ('link_action_attempted', 'link_action_completed'):
            changed = copy.deepcopy(fixture)
            changed[field] = False
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.check(output, changed, wire)
        changed = copy.deepcopy(fixture)
        begun = event(changed, 'link-action-begin')
        changed['events'].remove(begun)
        changed['events'].insert(0, begun)
        with self.assertRaises(RuntimeError):
            self.check(output, changed, wire)
        changed = copy.deepcopy(fixture)
        changed['events'].append(copy.deepcopy(event(changed, 'link-action')))
        with self.assertRaises(RuntimeError):
            self.check(output, changed, wire)

    def test_exact_initial_bytes_and_complete_socket_capture_census(self):
        output, fixture, wire = link_proof()
        for field, value in [('rx_datagrams', 0), ('rx_datagrams', True), ('rx_bytes', 1199)]:
            changed = copy.deepcopy(fixture)
            changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                self.check(output, changed, wire)
        for field, value in [('source', ['10.0.2.15', 7824]), ('data_hex', '00' * 1200),
                             ('destination', ['10.0.2.2', 4444]), ('engine_delivered', True),
                             ('sha256', 'b' * 64), ('bytes', 1199), ('receive_ordinal', 2)]:
            changed = copy.deepcopy(fixture)
            event(changed, 'udp-receive')[field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.check(output, changed, wire)
        for field, value in [('guest_udp_count', 0), ('guest_udp', []), ('guest_udp_bytes', 1201)]:
            changed = copy.deepcopy(wire)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.check(output, fixture, changed)

    def test_peer_trigger_and_callback_result_correspond_to_the_recorded_action(self):
        output, fixture, wire = link_proof()
        for field, value in [('trigger_receive_ordinal', 2), ('trigger_sha256', 'b' * 64),
                             ('qmp_acknowledged', False), ('device_id', 'othernic'),
                             ('exact_qemu_pid', True), ('qmp_receipt_sha256', 'bad')]:
            changed = copy.deepcopy(fixture)
            event(changed, 'link-action')[field] = value
            with self.subTest(action=field), self.assertRaises(RuntimeError):
                self.check(output, changed, wire)
        for target, field, value in [('link_trigger', 'receive_ordinal', 2),
                                     ('link_trigger', 'sha256', 'b' * 64),
                                     ('link_trigger', 'destination', ['10.0.2.2', 4444]),
                                     ('link_action_result', 'device_id', 'othernic')]:
            changed = copy.deepcopy(fixture)
            changed[target][field] = value
            with self.subTest(target=target, field=field), self.assertRaises(RuntimeError):
                self.check(output, changed, wire)
        changed = copy.deepcopy(fixture)
        event(changed, 'link-action-begin')['trigger_sha256'] = 'b' * 64
        with self.assertRaises(RuntimeError):
            self.check(output, changed, wire)
        for name, field, value in [('link-action-begin', 'trigger_receive_ordinal', 2),
                                   ('initial-observed', 'receive_ordinal', 2),
                                   ('link-action', 'monotonic_ns', 129),
                                   ('link-action', 'monotonic_ns', True)]:
            changed = copy.deepcopy(fixture)
            event(changed, name)[field] = value
            with self.subTest(event=name, field=field), self.assertRaises(RuntimeError):
                self.check(output, changed, wire)

    def test_ordinary_udp_cannot_replace_initial_with_matching_all_ledgers(self):
        output, fixture, wire = link_proof()
        ordinary = b'ordinary echo'.ljust(1200, b'x')
        checksum = digest(ordinary)
        received = event(fixture, 'udp-receive')
        received.update(data_hex=ordinary.hex(), sha256=checksum)
        for name in ('initial-observed', 'link-failure-input'):
            event(fixture, name)['sha256'] = checksum
        for name in ('link-action-begin', 'link-action'):
            event(fixture, name)['trigger_sha256'] = checksum
        fixture['link_trigger']['sha256'] = checksum
        wire['guest_udp'][0].update(data_hex=ordinary.hex(), sha256=checksum, first_byte=ordinary[0])
        output = change(output, 'QUIC FIXTURE SEND', sha256=checksum)
        with self.assertRaises(RuntimeError):
            self.check(output, fixture, wire)

    def test_peer_input_is_not_delivered_to_an_engine_and_later_engine_work_refuses(self):
        output, fixture, wire = link_proof()
        changed = copy.deepcopy(fixture)
        event(changed, 'link-failure-input')['engine_delivered'] = True
        with self.assertRaises(RuntimeError):
            self.check(output, changed, wire)
        for name in ('handshake', 'request-stream', 'udp-send', 'link-action-begin'):
            changed = copy.deepcopy(fixture)
            changed['events'].append({'event': name, 'monotonic_ns': 170})
            with self.subTest(event=name), self.assertRaises(RuntimeError):
                self.check(output, changed, wire)


class QMPReceiptControls(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix='absd-qmp-receipt-') as directory:
            path = Path(directory) / 'QMP-LINK.json'
            socket_path = Path(directory) / 'quic.qmp'
            receipt = qmp_receipt(socket_path)
            path.write_text(json.dumps(receipt))
            _, fixture, _ = link_proof(path, digest(path.read_bytes()))
            yield path, socket_path, receipt, fixture

    def rewrite(self, path, receipt, fixture):
        path.write_text(json.dumps(receipt))
        checksum = digest(path.read_bytes())
        event(fixture, 'link-action')['qmp_receipt_sha256'] = checksum
        fixture['link_action_result']['qmp_receipt_sha256'] = checksum

    def test_complete_qmp_receipt_matches_one_causal_action(self):
        with self.fixture() as (path, socket_path, receipt, fixture):
            result = MATRIX.verify_qmp_link_receipt(fixture, path, 4321, socket_path)
            self.assertEqual(result, {'path': str(path), 'sha256': digest(path.read_bytes()), 'exact_qemu_pid': 4321})
            output, native_fixture, wire = link_proof(path, digest(path.read_bytes()))
            self.assertEqual(native_fixture, fixture)
            self.assertEqual(MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)['link']['native_error_code'], 9)

    def test_actual_qmp_server_receipt_can_be_checked_against_its_action(self):
        with server() as value:
            before = time.monotonic_ns()
            result = MATRIX.qmp_link_down(value.path, os.getpid(), value.receipt)
            after = time.monotonic_ns()
            output, fixture, wire = link_proof(value.receipt, result['qmp_receipt_sha256'], os.getpid())
            for row, stamp in zip(fixture['events'], (before - 3, before - 2, before - 1, before, after, after + 1)):
                row['monotonic_ns'] = stamp
            checked = MATRIX.verify_qmp_link_receipt(fixture, value.receipt, os.getpid(), value.path)
            self.assertEqual(checked['sha256'], result['qmp_receipt_sha256'])
            self.assertEqual(value.commands, COMMANDS)
            self.assertEqual(MATRIX.verify_native(CASE, output, fixture, wire, MANIFEST)['link']['native_error_code'], 9)

    def test_receipt_hash_pid_path_and_socket_correspondence_refuse(self):
        with self.fixture() as (path, socket_path, receipt, fixture):
            for field, value in [('qmp_receipt_sha256', 'b' * 64), ('exact_qemu_pid', 4322),
                                 ('qmp_receipt', str(path) + '.other')]:
                changed = copy.deepcopy(fixture)
                event(changed, 'link-action')[field] = value
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    MATRIX.verify_qmp_link_receipt(changed, path, 4321, socket_path)
            with self.assertRaises(RuntimeError):
                MATRIX.verify_qmp_link_receipt(fixture, path, 4322, socket_path)
            with self.assertRaises(RuntimeError):
                MATRIX.verify_qmp_link_receipt(fixture, path, 4321, str(socket_path) + '.other')
            alias = path.parent / 'alias.json'
            alias.symlink_to(path)
            changed = copy.deepcopy(fixture)
            event(changed, 'link-action')['qmp_receipt'] = str(alias)
            with self.assertRaises(RuntimeError):
                MATRIX.verify_qmp_link_receipt(changed, alias, 4321, socket_path)

    def test_rehashed_receipt_cannot_change_original_identity_or_success(self):
        mutations = [('qmp_acknowledged', False), ('expected_qemu_pid', 4322),
                     ('expected_qemu_pid', 4321.0),
                     ('device_id', 'othernic'), ('socket', '/other/qmp.sock'),
                     ('error', {'message': 'earlier failure'})]
        for field, value in mutations:
            with self.subTest(field=field), self.fixture() as (path, socket_path, receipt, fixture):
                receipt[field] = value
                self.rewrite(path, receipt, fixture)
                with self.assertRaises(RuntimeError):
                    MATRIX.verify_qmp_link_receipt(fixture, path, 4321, socket_path)
        peer_mutations = [('pid', 4322), ('pid', 4321.0), ('uid', os.geteuid() + 1),
                          ('uid', float(os.geteuid()))]
        if os.geteuid() == 0:
            peer_mutations.append(('uid', False))
        for field, value in peer_mutations:
            with self.subTest(peer=field), self.fixture() as (path, socket_path, receipt, fixture):
                receipt['socket_peer'][field] = value
                self.rewrite(path, receipt, fixture)
                with self.assertRaises(RuntimeError):
                    MATRIX.verify_qmp_link_receipt(fixture, path, 4321, socket_path)

    def test_rehashed_receipt_commands_device_direction_and_reply_census(self):
        for index, field, value in [(0, 'id', 'other'), (0, 'execute', 'query-status'),
                                    (1, 'arguments', {'name': 'othernic', 'up': False}),
                                    (1, 'arguments', {'name': 'quicnic', 'up': True}),
                                    (1, 'arguments', {'name': 'quicnic', 'up': 0})]:
            with self.subTest(index=index, field=field, value=value), self.fixture() as (path, socket_path, receipt, fixture):
                receipt['exchanges'][index]['command'][field] = value
                self.rewrite(path, receipt, fixture)
                with self.assertRaises(RuntimeError):
                    MATRIX.verify_qmp_link_receipt(fixture, path, 4321, socket_path)
        for index, identity in enumerate(('capabilities', 'drop-link')):
            malformed = [[], [success('other')], [dict(success(identity), error={})],
                         [{'return': None, 'id': identity}], [success(identity), success(identity)],
                         [success('other')] * 32 + [success(identity)]]
            for replies in malformed:
                with self.subTest(index=index, replies=replies), self.fixture() as (path, socket_path, receipt, fixture):
                    receipt['exchanges'][index]['replies'] = replies
                    self.rewrite(path, receipt, fixture)
                    with self.assertRaises(RuntimeError):
                        MATRIX.verify_qmp_link_receipt(fixture, path, 4321, socket_path)

    def test_rehashed_receipt_greeting_and_same_host_ack_clock_are_not_fabricated(self):
        for field, value in [('greeting', None), ('greeting', {'QMP': None}),
                             ('acknowledged_monotonic_ns', True), ('acknowledged_monotonic_ns', 0),
                             ('acknowledged_monotonic_ns', 129), ('acknowledged_monotonic_ns', 151)]:
            with self.subTest(field=field, value=value), self.fixture() as (path, socket_path, receipt, fixture):
                receipt[field] = value
                self.rewrite(path, receipt, fixture)
                with self.assertRaises(RuntimeError):
                    MATRIX.verify_qmp_link_receipt(fixture, path, 4321, socket_path)

    def test_live_and_retained_greeting_package_capability_members_and_version(self):
        changed = []
        greeting = copy.deepcopy(HELLO)
        greeting['QMP']['version']['package'] = None
        changed.append(greeting)
        greeting = copy.deepcopy(HELLO)
        greeting['QMP']['capabilities'] = [False]
        changed.append(greeting)
        greeting = copy.deepcopy(HELLO)
        greeting['QMP']['version']['qemu']['major'] = -1
        changed.append(greeting)
        for greeting in changed:
            with self.subTest(greeting=greeting), server(greeting=greeting) as value:
                with self.assertRaises(RuntimeError):
                    MATRIX.qmp_link_down(value.path, os.getpid(), value.receipt)
                self.assertEqual(value.commands, [])
                self.assertFalse(json.loads(value.receipt.read_text())['qmp_acknowledged'])
            with self.subTest(retained=greeting), self.fixture() as (path, socket_path, receipt, fixture):
                receipt['greeting'] = greeting
                self.rewrite(path, receipt, fixture)
                with self.assertRaises(RuntimeError):
                    MATRIX.verify_qmp_link_receipt(fixture, path, 4321, socket_path)


if __name__ == '__main__':
    unittest.main()
