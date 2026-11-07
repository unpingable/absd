#!/usr/bin/env python3
"""Bounded echo and authentication-refusal milestones with a Linux peer.

Linux fixture controls never count as ABSD execution. Each native occurrence
retains exact boot bytes, raw packets and observations before its verdict.
Source readiness alone admits no host, compiler, guest or protocol execution.
This distinct milestone does not satisfy the original17-control prerequisite
or qualify any part of the original30+1 campaign for promotion.
"""
from pathlib import Path
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import socket
import stat
import subprocess
import struct
import sys
import threading
import time
import traceback

from served_ram import served_qemu


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def seal(path, value):
    with Path(path).open('x') as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def fields(line):
    result = {}
    for word in line.split():
        key, separator, value = word.partition('=')
        if separator:
            require(key not in result, 'duplicate report field: ' + key)
            result[key] = value
    return result


def records(output, prefix, case):
    rows = [fields(line) for line in output.splitlines() if line.startswith(prefix + ' ')]
    return [row for row in rows if row.get('case') == case['id']]


def number(row, name):
    value = row.get(name, '')
    require(re.fullmatch(r'0|[1-9][0-9]*', value) is not None, 'missing/noncanonical integer: ' + name)
    return int(value)


def boolean(row, name):
    value = row.get(name)
    require(value in ('true', 'false'), 'missing/noncanonical boolean: ' + name)
    return value == 'true'


def verify_udp_filter_witness(case, output):
    """Q18's parent observes actual IPv4 peer-filter dequeues, not all loss."""
    prefix = 'QUIC SERVICE UDP_FILTER'
    lines = output.splitlines()
    selected = [(i, fields(line)) for i, line in enumerate(lines) if line.startswith(prefix + ' ')]
    require(len(selected) == 2 and all(row.get('case') == case['id'] for _, row in selected),
            'NOT_ESTABLISHED: exact owner UDP filter witness absent')
    (begin_index, begin), (end_index, end) = selected
    require(begin.get('phase') == 'begin' and end.get('phase') == 'end',
            'NOT_ESTABLISHED: UDP filter witness phases')
    require(number(begin, 'dropped') == 0 and number(end, 'dropped') == 1,
            'NOT_ESTABLISHED: fresh stack did not observe exactly one grant-filter discard')
    start, stop = number(begin, 'at_ms'), number(end, 'at_ms')
    require(0 <= start <= stop <= (1 << 64) - 1, 'UDP filter witness clock')
    grant_lines = [i for i, line in enumerate(lines) if line.startswith('QUIC SERVICE GRANT ')]
    exit_lines = [i for i, line in enumerate(lines) if line.startswith('QUIC CHILD EXIT ')]
    require(len(grant_lines) == len(exit_lines) == 1 and
            grant_lines[0] < begin_index < exit_lines[0] < end_index,
            'NOT_ESTABLISHED: UDP filter witness outside owner lifecycle')
    grant = fields(lines[grant_lines[0]])
    reports = records(output, 'QUIC RESULT', case)
    require(number(grant, 'constructed_ms') <= start and len(reports) == 1 and
            number(reports[0], 'end_ms') <= stop,
            'NOT_ESTABLISHED: filter witness does not bracket grant and consumer')
    for name in ('QUIC FIXTURE SEND', 'QUIC FIXTURE RX'):
        for i, line in enumerate(lines):
            if line.startswith(name + ' '):
                row = fields(line)
                require(row.get('case') == case['id'] and begin_index < i < end_index and
                        start <= number(row, 'at_ms') <= stop,
                        'NOT_ESTABLISHED: native traffic outside filter witness interval')
    return {'begin': 0, 'end': 1, 'discarded': 1}


def partial_ipc_bounds(report):
    # Each completed payload-bearing frame body has at most one positive
    # non-partial final call under ChildPipe's 7-byte cap. Prefix/header and
    # other transactions can add counters; ignoring them is conservative.
    return {counter: max(1, (number(report, payload) + 6) // 7 - number(report, messages))
            for counter, payload, messages in (
                ('partial_pipe_reads', 'receive_bytes', 'received'),
                ('partial_pipe_writes', 'send_bytes', 'send_accepted'))}


def allocation(roots):
    """Measure only explicit owned roots, deduplicating aliases by inode."""
    seen = set()
    total = 0
    for root in roots:
        root = Path(root).resolve(strict=True)
        for current, directories, files in os.walk(root, followlinks=False):
            for path in [Path(current), *(Path(current) / name for name in files)]:
                stat = path.lstat()
                if (stat.st_dev, stat.st_ino) not in seen:
                    seen.add((stat.st_dev, stat.st_ino))
                    total += stat.st_blocks * 512
    return total


IPV6_PINS = {
    'native-quic-ipv6-wire.py': '68a6d5cfb85420896c6a22748d22c2a09ee04748f21fa145adf9970b0a15b776',
    'native-ipv6-accounting.py': '22d5f091c23c0d436be538d3695b43b3ed52b48ec5b4b30668be215a08001ad3',
    'native-ipv6-reason-accounting.py': '8155af1e25c73b1eb67636955a8e350c881cdd869c6cc73e70038bca06e0a827',
}


def ipv6_helper(name, filename):
    path = Path(__file__).with_name(filename)
    require(not path.is_symlink() and sha(path) == IPV6_PINS[filename], 'pinned IPv6 helper changed: ' + filename)
    return module(name, path)


def ipv6_accounting(case):
    development_profile(case, 'ipv6')
    path = Path(__file__).with_name('native-ipv6-accounting.py')
    require(not path.is_symlink() and sha(path) == IPV6_PINS[path.name], 'pinned IPv6 accounting changed')
    reasons = ipv6_helper('quic6_private_reasons', 'native-ipv6-reason-accounting.py')
    # Only this fresh private module instance receives the explicit tuple.
    # The classifier, source, sidecar guard and first-four policy are unchanged.
    require('quic6' not in reasons.original.PROFILES, 'private profile already occupied')
    reasons.original.PROFILES['quic6'] = {'guest': 'fd00:ab5d::15', 'host': 'fd00:ab5d::2',
                                        'udp': [case['local_port'], 4443], 'tcp': None}
    return reasons


def wire_observations(path, case, macs, family='ipv4'):
    require(family in ('ipv4', 'ipv6'), 'unknown transport family')
    wire = (ipv6_helper('native_quic6_wire', 'native-quic-ipv6-wire.py') if family == 'ipv6' else
            module('native_quic_wire', Path(__file__).with_name('native-quic-wire.py')))
    return wire.observe(Path(path).read_bytes(), case, macs['guest'], macs['peer'])


def development_profile(case, family='ipv4'):
    require(family in ('ipv4', 'ipv6'), 'unknown transport family')
    if family == 'ipv6':
        profiles = {'Q01': ('echo', 'q01-ipv6-development', 7800),
                    'Q08': ('wrong-root', 'q08-ipv6-development', 7807),
                    'Q17': ('denied-destination', 'q17-ipv6-development', 7816)}
        require(case.get('id') in profiles and
                (case.get('peer_mode'), case.get('local_port')) ==
                (profiles[case['id']][0], profiles[case['id']][2]), 'unsupported bounded IPv6 case')
        return profiles[case['id']][1]
    profiles = {'Q01':('echo', 'q01-development'),
                'Q02':('partial-io', 'q02-partial-ipc-development'),
                'Q12':('truncated-header', 'q12-truncated-header-development'),
                'Q13':('invalid-tag', 'q13-invalid-tag-development'),
                'Q14':('long-retry', 'q14-long-retry-development'),
                'Q15':('stream-limit', 'q15-stream-limit-development'),
                'Q16':('unknown-cid', 'q16-unknown-cid-development'),
                'Q17':('denied-destination', 'q17-denied-destination-development'),
                'Q18':('unauthorized-source', 'q18-unauthorized-source-development'),
                'Q03':('initial-loss', 'q03-initial-loss-development'),
                'Q04':('stream-loss', 'q04-stream-loss-development'),
                'Q05':('duplicate-reorder', 'q05-duplicate-reorder-development'),
                'Q06':('flow-pause', 'q06-flow-pause-development'),
                'Q07':('silent', 'q07-silent-development'),
                'Q08':('wrong-root', 'q08-wrong-root-development'),
                'Q09':('wrong-name', 'q09-wrong-name-development'),
                'Q10':('expired-certificate', 'q10-expired-development'),
                'Q11':('wrong-alpn', 'q11-wrong-alpn-development'),
                'Q19':('queue-exhausted', 'q19-queue-exhausted-development'),
                'Q20':('unknown-send', 'q20-unknown-send-development')}
    profiles.update({'Q21':('silent', 'q21-interrupt-handshake-development'),
                     'Q22':('interrupt-stream', 'q22-interrupt-stream-development'),
                     'Q23':('owner-expiry', 'q23-owner-expiry-development'),
                     'Q24':('link-failure', 'q24-link-failure-development'),
                     'Q25':('icmp-576', 'q25-icmp-576-development'),
                     'Q26':('icmp-1227', 'q26-icmp-1227-development'),
                     'Q27':('icmp-1200', 'q27-icmp-1200-development'),
                     'Q28':('icmp-zero', 'q28-icmp-zero-development'),
                     'Q29':('missing-output', 'q29-missing-output-development'),
                     'Q30':('missing-time', 'q30-missing-time-development'),
                     'Q31':('absent-rdrand', 'q31-absent-rdrand-development')})
    require(case['id'] in profiles and case['peer_mode'] == profiles[case['id']][0],
            'unsupported bounded development case')
    require(case['id'] != 'Q02' or case.get('local_port') == 7801, 'Q02 exact local port differs')
    require(case['id'] != 'Q04' or case.get('local_port') == 7803, 'Q04 exact local port differs')
    require(case['id'] != 'Q05' or case.get('local_port') == 7804, 'Q05 exact local port differs')
    require(case['id'] != 'Q06' or case.get('local_port') == 7805, 'Q06 exact local port differs')
    require(case['id'] != 'Q12' or case.get('local_port') == 7811, 'Q12 exact local port differs')
    require(case['id'] != 'Q13' or case.get('local_port') == 7812, 'Q13 exact local port differs')
    require(case['id'] != 'Q14' or case.get('local_port') == 7813, 'Q14 exact local port differs')
    require(case['id'] != 'Q15' or case.get('local_port') == 7814, 'Q15 exact local port differs')
    require(case['id'] != 'Q16' or case.get('local_port') == 7815, 'Q16 exact local port differs')
    require(case['id'] != 'Q15' or case.get('local_port') == 7814, 'Q15 exact local port differs')
    require(case['id'] != 'Q18' or case.get('local_port') == 7817, 'Q18 exact local port differs')
    if case['id'] == 'Q17':
        require(type(case.get('local_port')) is int and case['local_port'] == 7816
                and case.get('expected_outcome') == 'Native' and case.get('native_error_codes') == [2]
                and case.get('grant_lifetime_ms') == 15000 and case.get('interrupt_phase') is None
                and case.get('interrupt_delay_ms') == 0 and all(case.get(key) is False for key in
                    ('queue_control', 'suppress_reply', 'missing_output', 'missing_time'))
                and case.get('requires') == ['send_accepted=0', 'no_unauthorized_wire_send', 'authenticated=false'],
                'exact IPv4 denied-destination selector differs')
    if case['id'] in ('Q21', 'Q22'):
        phase, delay, port = {'Q21':('Handshake', 1000, 7820), 'Q22':('Stream', 300, 7821)}[case['id']]
        require(case.get('local_port') == port and case.get('interrupt_phase') == phase
                and case.get('interrupt_delay_ms') == delay and case.get('grant_lifetime_ms') == 15000
                and case.get('expected_outcome') == 'Interrupted', 'exact interruption selector differs')
    if case['id'] == 'Q24':
        require(case.get('local_port') == 7823 and case.get('grant_lifetime_ms') == 15000
                and case.get('expected_outcome') == 'Native' and case.get('native_error_codes') == [9,10,11]
                and case.get('interrupt_phase') is None and case.get('interrupt_delay_ms') == 0
                and all(case.get(key) is False for key in
                        ('queue_control','suppress_reply','missing_output','missing_time')),
                'exact link-failure selector differs')
    if case['id'] in ('Q25', 'Q26', 'Q27', 'Q28'):
        port, mtu, codes = {'Q25':(7824, 576, [14,15]), 'Q26':(7825, 1227, [14,15]),
                            'Q27':(7826, 1200, [14]),
                            'Q28':(7827, 0, [14])}[case['id']]
        require(case.get('local_port') == port and type(case.get('icmp_mtu')) is int and case.get('icmp_mtu') == mtu
                and case.get('native_error_codes') == codes and case.get('expected_outcome') == 'Native'
                and case.get('grant_lifetime_ms') == 15000 and case.get('interrupt_phase') is None
                and case.get('interrupt_delay_ms') == 0 and all(case.get(key) is False for key in
                        ('queue_control','suppress_reply','missing_output','missing_time')),
                'exact native ICMP advisory selector differs')
    if case['id'] in ('Q23', 'Q29', 'Q30'):
        port, lifetime, outcome = {'Q23':(7822, 3000, 'Native'), 'Q29':(7828, 15000, 'Config'),
                                   'Q30':(7829, 15000, 'Time')}[case['id']]
        require(case.get('local_port') == port and case.get('grant_lifetime_ms') == lifetime
                and case.get('expected_outcome') == outcome and case.get('interrupt_phase') is None
                and case.get('interrupt_delay_ms') == 0 and case.get('queue_control') is False
                and case.get('suppress_reply') is False
                and case.get('missing_output') is (case['id'] == 'Q29')
                and case.get('missing_time') is (case['id'] == 'Q30'), 'exact authority selector differs')
        if case['id'] == 'Q23':
            require(case.get('observation_marker_hex') == (b'\x00ABSD-QUIC-Q23-INITIAL-OBSERVED').hex()
                    and case.get('native_failure_kinds') == ['Deadline', 'Unknown'],
                    'exact owner expiry marker or refusal kinds differ')
    if case['id'] == 'Q31':
        require(case.get('local_port') == 7830 and case.get('grant_lifetime_ms') == 15000
                and case.get('expected_outcome') == 'Entropy'
                and case.get('requires') == ['consumer_reached', 'no_SEND']
                and case.get('interrupt_phase') is None and case.get('interrupt_delay_ms') == 0
                and all(case.get(key) is False for key in
                        ('queue_control', 'suppress_reply', 'missing_output', 'missing_time')),
                'exact conditional entropy selector differs')
    require(case['id'] != 'Q20' or case.get('local_port') == 7819, 'Q20 exact local port differs')
    return profiles[case['id']][1]


def peer_control_cases(case, family='ipv4'):
    development_profile(case, family)
    # Linux has no native startup-role or supplied-time construction. A real
    # positive Q01 echo calibrates the peer; only ABSD proves these refusals.
    return ['Q01' if case['id'] in ('Q17', 'Q20', 'Q24', 'Q25', 'Q26', 'Q27', 'Q28', 'Q29', 'Q30', 'Q31') else case['id']]


def select_development_cases(all_cases, profile, family, controls, case_ids):
    """Select actual execution without relabeling a Linux prerequisite as native."""
    profile_cases = {'q01-development':'Q01', 'q12-truncated-header-development':'Q12', 'q13-invalid-tag-development':'Q13', 'q02-partial-ipc-development':'Q02', 'q03-initial-loss-development':'Q03', 'q04-stream-loss-development':'Q04', 'q05-duplicate-reorder-development':'Q05', 'q06-flow-pause-development':'Q06', 'q07-silent-development':'Q07', 'q08-wrong-root-development':'Q08', 'q14-long-retry-development':'Q14', 'q15-stream-limit-development':'Q15', 'q16-unknown-cid-development':'Q16', 'q18-unauthorized-source-development':'Q18',
                      'q09-wrong-name-development':'Q09', 'q10-expired-development':'Q10',
                      'q11-wrong-alpn-development':'Q11', 'q19-queue-exhausted-development':'Q19', 'q20-unknown-send-development':'Q20', 'q01-ipv6-development':'Q01',
                      'q21-interrupt-handshake-development':'Q21', 'q22-interrupt-stream-development':'Q22',
                      'q23-owner-expiry-development':'Q23', 'q24-link-failure-development':'Q24', 'q29-missing-output-development':'Q29', 'q30-missing-time-development':'Q30', 'q31-absent-rdrand-development':'Q31',
                      'q25-icmp-576-development':'Q25', 'q26-icmp-1227-development':'Q26', 'q27-icmp-1200-development':'Q27', 'q28-icmp-zero-development':'Q28',
                      'q08-ipv6-development':'Q08', 'q17-ipv6-development':'Q17',
                      'q17-denied-destination-development':'Q17'}
    require(profile in profile_cases, 'unknown bounded development profile')
    profile_case = profile_cases[profile]
    require(development_profile(all_cases[profile_case], family) == profile,
            'only the exact case for the explicit bounded development profile is admitted')
    peer_controls = peer_control_cases(all_cases[profile_case], family)
    expected = peer_controls if controls else [profile_case]
    selected = list(case_ids or expected)
    require(selected and len(set(selected)) == len(selected) and set(selected) <= all_cases.keys(),
            'duplicate/unknown case selection')
    require(selected == expected,
            '--controls requires exactly the real Linux prerequisite ' + ','.join(peer_controls) + ' for ' + profile
            if controls else 'only the exact case for the explicit bounded development profile is admitted')
    return selected, peer_controls, development_profile(all_cases[selected[0]], family)


def verify_certificate_selection(case, fixture, pki):
    selected = fixture.get('certificate_selection')
    if case['id'] == 'Q20':
        require(selected is None and fixture.get('completion_policy') == 'q20-one-initial-sink-v1'
                and fixture.get('engine_constructed') is False,
                'Q20 must observe the Initial without a peer engine or certificate selection')
        return
    kind = {'Q01':'valid', 'Q12':'valid', 'Q13':'valid', 'Q02':'valid', 'Q03':'valid', 'Q04':'valid', 'Q05':'valid', 'Q06':'valid', 'Q07':'valid', 'Q08':'untrusted', 'Q14':'valid', 'Q15':'valid', 'Q16':'valid', 'Q18':'valid', 'Q09':'wrong-name', 'Q10':'expired', 'Q11':'valid', 'Q19':'valid', 'Q22':'valid'}[case['id']]
    require(selected is not None and selected.get('kind') == kind
            and selected.get('sha256') == pki['leaf_certificates'][kind]['sha256']
            and selected.get('client_root_sha256') == pki['root_der']['sha256'],
            'actual peer certificate and client trust selection differ')
    if case['id'] == 'Q11':
        require(selected.get('configured_alpn') == ['other-echo/1'],
                'actual wrong-ALPN peer configuration differs')


def verify_linux_auth_refusal(case, observed, pki, family="ipv4"):
    require(case['id'] in ('Q08','Q09','Q10','Q11'), 'authentication refusal case differs')
    fixture = observed['fixture']
    development_profile(case, family)
    if family == 'ipv6':
        require(case['id'] == 'Q08' and observed.get('transport_family') == 'ipv6'
                and fixture.get('transport_family') == 'ipv6'
                and fixture.get('readiness_profile') == development_profile(case, family),
                'Linux IPv6 authentication family or profile differs')
        verify_ipv6_response_flight(fixture)
    elif case['id'] == 'Q08':
        verify_q08_response_flight(fixture)
    elif case['id'] in ('Q09', 'Q10', 'Q11'):
        verify_auth_response_flight(case, fixture)
    verify_certificate_selection(case, fixture, pki)
    terminal = observed.get('terminal')
    # aioquic1.6.1 maps OpenSSL chain refusal to TLS bad_certificate(42),
    # hence QUIC298. Native rustls retains canonical Q08 unknown_ca/304.
    require(observed['actual_outcome'] == 'Protocol' and not observed['authenticated']
            and observed['received_bytes'] == 0 and not observed['peer_fin']
            and terminal is not None and terminal['error_code'] == {'Q08':298, 'Q09':298, 'Q10':301, 'Q11':376}[case['id']],
            'Linux authentication refusal is absent or has a different cause')
    require(not fixture['authenticated'] and fixture['request_bytes'] == 0
            and fixture['echo_enqueued_bytes'] == 0 and not fixture['request_fin']
            and not fixture['echo_fin_enqueued'] and fixture['rx_datagrams'] > 0
            and fixture['tx_datagrams'] > 0
            and any(row['event'] == 'initial-observed' for row in fixture['events'])
            and not fixture['errors'] and not fixture['thread_alive'],
            'Linux authentication fixture emitted application data or never exchanged Initial')


def verify_linux_wrong_root(case, observed, pki):
    # The existing focused Q08 controls remain a named caller of this helper.
    require(case['id'] == 'Q08', 'wrong-root control case differs')
    verify_linux_auth_refusal(case, observed, pki)


def verify_initial_loss(fixture):
    """Bind one omitted first receipt to a later accepted Initial, not echo alone."""
    events = fixture['events']
    dropped = [row for row in events if row['event'] == 'initial-drop']
    accepted = [row for row in events if row['event'] == 'initial-observed']
    received = [row for row in events if row['event'] == 'udp-receive']
    require(fixture.get('initial_drops') == 1 and len(dropped) == len(accepted) == 1
            and len(received) >= 2, 'one actual Initial omission and recovery required')
    drop, accept = dropped[0], accepted[0]
    ordinal = accept.get('receive_ordinal', 0)
    require(drop.get('receive_ordinal') == 1 and drop.get('engine_delivered') is False
            and drop['bytes'] == received[0]['bytes'] == 1200
            and drop['sha256'] == received[0]['sha256']
            and 2 <= ordinal <= len(received)
            and accept['bytes'] == received[ordinal-1]['bytes'] == 1200
            and accept['sha256'] == received[ordinal-1]['sha256']
            and events.index(drop) < events.index(accept),
            'Initial omission was not first, pre-engine, or followed by accepted retry')
    first_receipt = events.index(received[0])
    retry_receipt = events.index(received[ordinal-1])
    accepted_at = events.index(accept)
    require(first_receipt < events.index(drop) < retry_receipt < accepted_at
            and all(index > accepted_at for index, row in enumerate(events)
                    if row['event'] == 'udp-send'),
            'Initial receipt/drop/accept/first response event causality differs')
    return drop, accept



def verify_queue_prelude(fixture, wire=None):
    """Bind all four exact socket receipts, pre-engine events and captured bytes."""
    expected = [b'ABSD-QUEUE-00000'[:15] + bytes([ordinal]) for ordinal in range(4)]
    events = fixture['events']
    fills = [row for row in events if row['event'] == 'queue-fixture-received']
    received = [row for row in events if row['event'] == 'udp-receive']
    accepted = [row for row in events if row['event'] == 'initial-observed']
    require(fixture.get('unique_queue_fixture_datagrams') == 4 and len(fills) == 4
            and len(received) >= 5 and len(accepted) == 1,
            'four exact queue fixture receipts and one Initial required')
    previous = -1
    for ordinal, data in enumerate(expected):
        fill, receipt = fills[ordinal], received[ordinal]
        require(fill.get('ordinal') == ordinal and fill.get('receive_ordinal') == ordinal + 1
                and fill.get('engine_delivered') is False
                and fill['bytes'] == receipt['bytes'] == 16
                and fill['sha256'] == receipt['sha256'] == hashlib.sha256(data).hexdigest()
                and previous < events.index(receipt) < events.index(fill),
                'queue fixture count/order/bytes/event correspondence differs')
        previous = events.index(fill)
    initial = accepted[0]
    require(initial.get('receive_ordinal') == 5 and initial['bytes'] == received[4]['bytes'] == 1200
            and initial['sha256'] == received[4]['sha256']
            and previous < events.index(received[4]) < events.index(initial)
            and all(index > events.index(initial) for index, row in enumerate(events)
                    if row['event'] == 'udp-send'),
            'queue fixtures were not followed by accepted Initial before any peer response')
    if wire is not None:
        captured = wire['guest_udp']
        hashes = {hashlib.sha256(data).hexdigest() for data in expected}
        require(len([row for row in captured if row['bytes'] == 16]) == 4
                and len([row for row in captured if row['sha256'] in hashes]) == 4,
                'extra or substituted queue fixture in complete capture')
        require(len(captured) >= 5 and captured[4]['sha256'] == initial['sha256']
                and captured[4]['bytes'] == 1200 and captured[4]['first_byte'] & 0xf0 == 0xc0,
                'captured Initial is not the fifth guest datagram')
        for ordinal, data in enumerate(expected):
            row = captured[ordinal]
            require(row['bytes'] == 16 and row['sha256'] == hashlib.sha256(data).hexdigest()
                    and row['ordinal'] < captured[ordinal+1]['ordinal'],
                    'four exact ordered queue fixtures absent from complete capture')
    return initial

def verify_q08_response_flight(fixture):
    require(fixture.get('readiness_profile') == 'q08-wrong-root-development'
            and fixture.get('mode') == 'wrong-root'
            and fixture.get('peer_policy') == 'q08-one-response-flight-v1'
            and fixture.get('response_flight_sealed') is True,
            'explicit fenced Q08 one-response-flight policy absent')
    events = fixture['events']
    def positions(name): return [(i, row) for i, row in enumerate(events) if row['event'] == name]
    received, initial = positions('udp-receive'), positions('initial-observed')
    batch, fenced, sent = positions('q08-response-flight'), positions('q08-response-flight-fenced'), positions('udp-send')
    require(received and len(initial) == len(batch) == len(fenced) == 1 and 1 <= len(sent) <= 4,
            'Q08 first response batch/event count differs')
    (ri, first), (ii, accepted), (bi, planned), (fi, retired) = received[0], initial[0], batch[0], fenced[0]
    require(ri < ii < bi < sent[0][0] <= sent[-1][0] < fi
            and first['bytes'] == accepted['bytes'] == 1200
            and first['sha256'] == accepted['sha256'] == planned['initial_sha256']
            and planned['policy'] == retired['policy'] == 'q08-one-response-flight-v1'
            and planned['datagrams'] == [{key:row[key] for key in ('bytes','sha256','destination')} for _, row in sent]
            and retired['tx_datagrams'] == fixture['tx_datagrams'] == len(sent)
            and retired['tx_bytes'] == fixture['tx_bytes'] == sum(row['bytes'] for _, row in sent)
            and retired['later_engine_work'] is False and retired['later_send'] is False,
            'Q08 receipt/Initial/batch/SEND/fence correspondence differs')


def verify_auth_response_flight(case, fixture):
    require(case['id'] in ('Q09', 'Q10', 'Q11')
            and fixture.get('readiness_profile') == development_profile(case)
            and fixture.get('mode') == case['peer_mode']
            and fixture.get('peer_policy') == 'auth-one-response-flight-v1'
            and fixture.get('response_flight_sealed') is True,
            'explicit fenced selected authentication one-response-flight policy absent')
    events = fixture['events']
    def positions(name): return [(i, row) for i, row in enumerate(events) if row['event'] == name]
    received, initial = positions('udp-receive'), positions('initial-observed')
    batch, fenced, sent = positions('auth-response-flight'), positions('auth-response-flight-fenced'), positions('udp-send')
    require(received and len(initial) == len(batch) == len(fenced) == 1 and 1 <= len(sent) <= 4,
            'selected authentication first response batch/event count differs')
    (ri, first), (ii, accepted), (bi, planned), (fi, retired) = received[0], initial[0], batch[0], fenced[0]
    require(ri < ii < bi < sent[0][0] <= sent[-1][0] < fi
            and first['bytes'] == accepted['bytes'] == 1200
            and first['sha256'] == accepted['sha256'] == planned['initial_sha256']
            and planned['policy'] == retired['policy'] == 'auth-one-response-flight-v1'
            and planned['datagrams'] == [{key:row[key] for key in ('bytes','sha256','destination')} for _, row in sent]
            and retired['tx_datagrams'] == fixture['tx_datagrams'] == len(sent)
            and retired['tx_bytes'] == fixture['tx_bytes'] == sum(row['bytes'] for _, row in sent)
            and retired['later_engine_work'] is False and retired['later_send'] is False,
            'selected authentication receipt/Initial/batch/SEND/fence correspondence differs')




def verify_ipv6_response_flight(fixture):
    require(fixture.get('peer_policy') == 'q08-one-response-flight-v1'
            and fixture.get('response_flight_sealed') is True, 'bounded Q08 response policy absent')
    events = fixture['events']
    def selected(name): return [(i, row) for i, row in enumerate(events) if row['event'] == name]
    received, initial = selected('udp-receive'), selected('initial-observed')
    batch, fenced, sent = selected('q08-response-flight'), selected('q08-response-flight-fenced'), selected('udp-send')
    require(received and len(initial) == len(batch) == len(fenced) == 1 and 1 <= len(sent) <= 4,
            'bounded first response event census differs')
    (ri, first), (ii, accepted), (bi, planned), (fi, retired) = received[0], initial[0], batch[0], fenced[0]
    require(ri < ii < bi < sent[0][0] <= sent[-1][0] < fi
            and first['bytes'] == accepted['bytes'] == 1200
            and first['sha256'] == accepted['sha256'] == planned['initial_sha256']
            and planned['policy'] == retired['policy'] == 'q08-one-response-flight-v1'
            and planned['datagrams'] == [{key: row[key] for key in ('bytes', 'sha256', 'destination')} for _, row in sent]
            and retired['tx_datagrams'] == fixture['tx_datagrams'] == len(sent)
            and retired['tx_bytes'] == fixture['tx_bytes'] == sum(row['bytes'] for _, row in sent)
            and retired['later_engine_work'] is False and retired['later_send'] is False,
            'Initial, complete batch, every SEND and fence differ')


def json_integer(row, name):
    value = row.get(name)
    require(type(value) is int and value >= 0, 'missing/noncanonical JSON integer: ' + name)
    return value


def verify_stream_loss(fixture, wire=None):
    """One observed post-handshake omission; native STREAM content is separate."""
    require(fixture.get('mode') == 'stream-loss' and json_integer(fixture, 'stream_drops') == 1
            and json_integer(fixture, 'initial_drops') == 0, 'Q04 exact omission mode/count differs')
    events = fixture['events']
    def rows(name): return [(i, row) for i, row in enumerate(events) if row['event'] == name]
    received, delivered, drops, handshakes, initials = (rows(name) for name in
        ('udp-receive', 'engine-delivered', 'stream-datagram-drop', 'handshake', 'initial-observed'))
    require(len(drops) == len(handshakes) == len(initials) == 1 and len(received) >= 3
            and len(delivered) == len(received) - 1 and not rows('initial-drop'),
            'Q04 complete receive/delivery/omission census differs')
    (di, drop), (hi, handshake), (ii, initial) = drops[0], handshakes[0], initials[0]
    ordinal = json_integer(drop, 'receive_ordinal')
    require([json_integer(row, 'receive_ordinal') for _, row in received] == list(range(1, len(received) + 1))
            and json_integer(fixture, 'rx_datagrams') == len(received)
            and json_integer(fixture, 'rx_bytes') == sum(json_integer(row, 'bytes') for _, row in received),
            'Q04 socket receive ordinals/bytes differ')
    require(1 < ordinal <= len(received) and json_integer(initial, 'receive_ordinal') == 1
            and json_integer(initial, 'bytes') == 1200 and initial['sha256'] == received[0][1]['sha256']
            and received[0][0] < ii < hi < received[ordinal - 1][0] < di
            and json_integer(handshake, 'receive_ordinal') < ordinal
            and handshake.get('alpn') == 'absd-echo/1'
            and handshake.get('early_data') is False and handshake.get('resumed') is False,
            'Q04 omission was not after its actual accepted Initial/handshake')
    captured_drop = received[ordinal - 1][1]
    require(drop.get('authenticated_before') is True and drop.get('engine_delivered') is False
            and drop.get('frame_proof') == 'requires-native-public-counter'
            and drop.get('request_fin_before') is False
            and 0 <= json_integer(drop, 'request_bytes_before') < 4096
            and 0 < json_integer(drop, 'bytes') <= 1200 and json_integer(drop, 'first_byte') & 0xc0 == 0x40
            and all(drop[key] == captured_drop[key] for key in ('bytes', 'sha256', 'first_byte'))
            and drop['sha256'] != initial['sha256'],
            'Q04 omitted datagram identity/header/lifecycle differs')
    expected = [(index, row) for index, row in received if json_integer(row, 'receive_ordinal') != ordinal]
    for (ri, receive), (ei, delivery) in zip(expected, delivered):
        next_receive = next((index for index, _ in received if index > ri), len(events))
        require(ri < ei < next_receive
                and json_integer(delivery, 'bytes') == json_integer(receive, 'bytes')
                and all(delivery[key] == receive[key] for key in ('receive_ordinal', 'bytes', 'sha256', 'source')),
                'Q04 engine delivery is missing, reordered or includes the omitted datagram')
    next_receive = next((index for index, _ in received if index > received[ordinal - 1][0]), len(events))
    require(di < next_receive, 'Q04 drop record is not causal with its socket receipt')
    handshake_delivery = next((index for index, row in delivered
                               if json_integer(row, 'receive_ordinal') == json_integer(handshake, 'receive_ordinal')), None)
    require(handshake_delivery is not None and handshake_delivery < hi,
            'Q04 handshake lacks its actual successful engine delivery')
    if wire is not None:
        require([{key: row[key] for key in ('bytes', 'sha256', 'source')} for _, row in received]
                == [{key: row[key] for key in ('bytes', 'sha256', 'source')} for row in wire['guest_udp']],
                'Q04 full socket receive/capture correspondence differs')
        sent = [row for row in events if row['event'] == 'udp-send']
        require([{key: row[key] for key in ('bytes', 'sha256', 'source', 'destination')} for row in sent]
                == [{key: row[key] for key in ('bytes', 'sha256', 'source', 'destination')} for row in wire['peer_udp']],
                'Q04 full socket SEND/capture correspondence differs')
        require(json_integer(wire['guest_udp'][0], 'first_byte') & 0xf0 == 0xc0
                and wire['guest_udp'][ordinal - 1]['first_byte'] == drop['first_byte'],
                'Q04 Initial/omitted short header absent from full capture')
    return drop


def verify_native_stream_loss(case, output, report, fixture, wire):
    drop = verify_stream_loss(fixture, wire)
    observations = records(output, 'QUIC STREAM TX', case)
    require(observations and len(observations) <= 256
            and len(observations) == sum(line.startswith('QUIC STREAM TX ') for line in output.splitlines()),
            'Q04 actual native STREAM-transmit observations absent or different case')
    sends = records(output, 'QUIC FIXTURE SEND', case)
    captured = wire['guest_udp']
    require(len(captured) == number(report, 'send_accepted')
            and sum(packet['bytes'] for packet in captured) == number(report, 'send_bytes'),
            'Q04 complete accepted native SEND/capture census differs')
    cursor = 0
    for packet in captured:
        while cursor < len(sends) and (sends[cursor].get('sha256'), number(sends[cursor], 'bytes')) != (packet['sha256'], packet['bytes']):
            cursor += 1
        require(cursor < len(sends), 'Q04 captured datagram lacks ordered owner SEND correspondence')
        cursor += 1
    previous_engine = previous_request = previous_accepted = previous_frames = 0
    for row in observations:
        engine, request, accepted = (number(row, key) for key in
            ('engine_ordinal', 'native_request_ordinal', 'accepted_ordinal'))
        before, after = number(row, 'stream_frames_before'), number(row, 'stream_frames_after')
        require(previous_engine < engine <= number(report, 'engine_transmits')
                and previous_request < request <= len(sends)
                and previous_accepted < accepted <= number(report, 'send_accepted')
                and accepted == engine <= request and before >= previous_frames
                and before < after <= before + number(row, 'bytes')
                and boolean(row, 'authenticated'),
                'Q04 public STREAM counter/datagram/native ordinal relation differs')
        sent = sends[request - 1]
        require(number(sent, 'ordinal') == request and number(sent, 'bytes') == number(row, 'bytes')
                and sent.get('sha256') == row.get('sha256')
                and captured[accepted - 1]['sha256'] == row['sha256']
                and captured[accepted - 1]['bytes'] == number(row, 'bytes'),
                'Q04 annotated accepted SEND lacks exact owner/full-capture bytes')
        previous_engine, previous_request, previous_accepted, previous_frames = engine, request, accepted, after
    matching = [row for row in observations if row['sha256'] == drop['sha256']
                and number(row, 'bytes') == drop['bytes']
                and number(row, 'accepted_ordinal') == json_integer(drop, 'receive_ordinal')]
    require(len(matching) == 1, 'NOT_ESTABLISHED: omitted datagram lacks one positive public STREAM counter delta')

def verify_truncated_header(case, fixture, wire=None, linux_control=False):
    """Exact peer socket bytes; optional complete capture, never delivery by name."""
    require(case['id'] == 'Q12' and development_profile(case) == 'q12-truncated-header-development'
            and fixture.get('readiness_profile') == 'q12-truncated-header-development', 'Q12 profile differs')
    expected = bytes.fromhex('c00000000108')
    expected_hash = hashlib.sha256(expected).hexdigest()
    events = fixture['events']
    sends = [row for row in events if row['event'] == 'udp-send']
    received = [row for row in events if row['event'] == 'udp-receive']
    initial = [row for row in events if row['event'] == 'initial-observed']
    tagged = [row for row in sends if row.get('fixture') == 'truncated-header']
    require(len(tagged) == len(initial) == 1 and sends and sends[0] is tagged[0]
            and received and initial[0]['bytes'] == received[0]['bytes'] == 1200
            and initial[0]['sha256'] == received[0]['sha256']
            and events.index(received[0]) < events.index(initial[0]) < events.index(tagged[0]),
            'Q12 exact first peer injection after accepted Initial absent')
    malformed = tagged[0]
    require(malformed['bytes'] == len(expected) and malformed['sha256'] == expected_hash
            and sum(row['sha256'] == expected_hash for row in sends) == 1,
            'Q12 truncated bytes differ')
    if linux_control:
        require(wire is None and malformed['source'][0] == malformed['destination'][0] == '127.0.0.1'
                and all(type(row[1]) is int and 0 < row[1] <= 65535
                        for row in (malformed['source'], malformed['destination']))
                and malformed['source'] != malformed['destination']
                and received[0]['source'] == malformed['destination'],
                'Q12 Linux loopback socket tuple differs')
    else:
        require(malformed['source'] == ['10.0.2.2',4443] and malformed['destination'] == ['10.0.2.15',7811],
                'Q12 authorized native tuple differs')
    if wire is not None:
        peer = wire['peer_udp']
        require(len(peer) >= 2 and peer[0]['bytes'] == len(expected) and peer[0]['sha256'] == expected_hash
                and sum(row['sha256'] == expected_hash for row in peer) == 1,
                'Q12 exact malformed datagram absent or duplicated in complete capture')
        for observed, captured, keys in ((sends, peer, ('bytes','sha256','source','destination')),
                                         (received, wire['guest_udp'], ('bytes','sha256','source'))):
            require([{key:row[key] for key in keys} for row in observed] ==
                    [{key:row[key] for key in keys} for row in captured],
                    'Q12 complete socket/capture correspondence differs')
    return malformed


def reorder_consumed(selected, delivered, sent):
    """Actual consumed input, distinct from peer SEND or event labels."""
    require(delivered and [json_integer(row, 'ordinal') for row in delivered] == list(range(1, len(delivered) + 1)),
            'Q05 complete consumed-input ordinals differ')
    identity = lambda row: (json_integer(row, 'bytes'), row['sha256'])
    original = selected['datagrams']
    first, second = identity(original[0]), identity(original[1])
    expected = [second, first, first]
    values = [identity(row) for row in delivered]
    matches = [i for i in range(len(values) - 2) if values[i:i + 3] == expected]
    require(len(matches) == 1 and values.count(first) == 2 and values.count(second) == 1,
            'NOT_ESTABLISHED: Q05 distinct B,A,A input was not consumed consecutively exactly once')
    cursor = 0
    for row in delivered:
        while cursor < len(sent) and (identity(sent[cursor]), sent[cursor]['source']) != (identity(row), row['source']):
            cursor += 1
        require(cursor < len(sent), 'Q05 consumed input is not an ordered subset of complete peer SENDs')
        cursor += 1
    return matches[0] + 1


def verify_duplicate_reorder(case, fixture, wire=None, client_datagrams=None, reorder_stage='initial'):
    require(reorder_stage in ('initial', 'post-handshake'), 'Q05 reorder stage differs')
    post = reorder_stage == 'post-handshake'
    policy = 'q05-post-handshake-two-output-hold-v2' if post else 'q05-two-output-hold-v2'
    require(case['id'] == 'Q05' and development_profile(case) == 'q05-duplicate-reorder-development'
            and fixture.get('readiness_profile') == 'q05-duplicate-reorder-development'
            and fixture.get('mode') == 'duplicate-reorder'
            and fixture.get('reorder_policy') == policy
            and fixture.get('reorder_stage', 'initial') == reorder_stage, 'Q05 exact held-output profile differs')
    require(fixture.get('reorder_established') is True, 'NOT_ESTABLISHED: Q05 distinct held-output reorder absent')
    require((wire is None) != (client_datagrams is None), 'Q05 capture or actual Linux consumed-input witness required')
    require(json_integer(fixture, 'reorder_hold_ns') == 500_000_000
            and json_integer(fixture, 'reorder_held_datagrams') == 0
            and fixture.get('reorder_abandoned') is False, 'Q05 bounded hold was not released normally')
    events = fixture['events']
    def rows(name): return [(i,row) for i,row in enumerate(events) if row['event'] == name]
    calls, actions, sends, initial, received, held, paired, established = (rows(name) for name in
        ('q05-public-call','q05-engine-datagram-sent','udp-send','initial-observed','udp-receive',
         'q05-output-held','q05-pair-ready','duplicate-reorder'))
    require(0 < len(calls) <= 1024 and 0 < len(sends) <= 512 and 0 < len(received) <= 512
            and len(initial) == len(held) == len(paired) == len(established) == 1
            and not rows('q05-hold-refused') and len(actions) == len(sends)
            and json_integer(fixture,'reorder_calls') == len(calls)
            and json_integer(fixture,'reorder_batches') == sum(bool(row['datagrams'])for _,row in calls)
            and json_integer(fixture,'tx_datagrams') == len(sends)
            and json_integer(fixture,'tx_bytes') == sum(json_integer(row,'bytes')for _,row in sends) <= 512*1200
            and json_integer(fixture,'rx_datagrams') == len(received)
            and json_integer(fixture,'rx_bytes') == sum(json_integer(row,'bytes')for _,row in received) <= 512*1200
            and [json_integer(row,'send_ordinal')for _,row in sends] == list(range(1,len(sends)+1)),
            'Q05 complete public-call/socket/action census differs')
    require(received[0][0] < initial[0][0] < calls[0][0]
            and initial[0][1]['sha256'] == received[0][1]['sha256']
            and json_integer(initial[0][1],'bytes') == json_integer(received[0][1],'bytes') == 1200,
            'Q05 public output did not follow its actual accepted Initial')
    originals, batch_ordinal, previous_ns = [], 0, 0
    for ordinal, (ci,call) in enumerate(calls,1):
        datagrams = call['datagrams']
        batch_ordinal += bool(datagrams)
        observed = json_integer(call,'observed_ns')
        require(isinstance(datagrams,list) and len(datagrams) <= 4
                and 'batch_ordinal' in call and call.get('policy') == policy
                and json_integer(call,'call_ordinal') == ordinal and 0 < observed >= previous_ns
                and (call.get('batch_ordinal') is None if not datagrams else
                     json_integer(call,'batch_ordinal') == batch_ordinal)
                and call['initial_sha256'] == initial[0][1]['sha256'], 'Q05 original public call boundary/time differs')
        previous_ns = observed
        for index,packet in enumerate(datagrams):
            require(0 < json_integer(packet,'bytes') <= 1200 and isinstance(packet.get('sha256'),str)
                    and re.fullmatch('[0-9a-f]{64}',packet['sha256'])
                    and packet['destination'] == received[0][1]['source'], 'Q05 original public datagram identity differs')
            originals.append({**packet,'source_call':ordinal,'source_index':index,'event_index':ci,'observed_ns':observed})
    prefix = []
    arms = rows('q05-post-handshake-armed')
    gates = rows('q05-post-echo-release')
    if post:
        require(len(arms) == len(gates) == 1, 'NOT_ESTABLISHED: Q05 post-handshake arm/gate absent or duplicated')
        arm_index, arm = arms[0]
        gate_index, gate = gates[0]
        handshake, requests, echoes = rows('handshake'), rows('request-stream'), rows('echo-enqueue')
        require(len(handshake) == 1 and requests and echoes and fixture.get('authenticated') is True
                and handshake[0][0] < requests[0][0] < gate_index < echoes[0][0] < arm_index
                and handshake[0][1].get('alpn') == 'absd-echo/1'
                and handshake[0][1].get('early_data') is False and handshake[0][1].get('resumed') is False
                and arm.get('policy') == policy and arm.get('authenticated') is True,
                'Q05 arm precedes actual handshake, request or echo construction')
        prior_requests = [row for i,row in requests if i < gate_index]
        require(prior_requests and gate.get('policy') == policy
                and json_integer(gate, 'required_request_bytes') == 2048
                and json_integer(gate, 'echo_enqueued_before') == 0
                and 2048 <= json_integer(gate, 'request_bytes') == sum(json_integer(row, 'bytes') for row in prior_requests) <= 4096
                and sum(json_integer(row, 'bytes') for row in prior_requests[:-1]) < 2048
                and all(i > gate_index for i,_ in echoes),
                'Q05 echo gate did not release at the first actual2048-byte request boundary')
        first_call = json_integer(arm, 'first_source_call')
        prefix = [row for row in originals if row['source_call'] < first_call]
        eligible = [row for row in originals if row['source_call'] >= first_call]
        require(prefix and eligible and first_call == eligible[0]['source_call']
                and arm_index < eligible[0]['event_index']
                and json_integer(arm, 'observed_ns') == eligible[0]['observed_ns']
                and json_integer(arm, 'prior_tx_datagrams') == len(prefix)
                and 2048 <= json_integer(arm, 'echo_enqueued_bytes') <= json_integer(arm, 'request_bytes') <= 4096
                and json_integer(arm, 'request_bytes') == sum(json_integer(row, 'bytes') for i,row in requests if i < arm_index)
                and json_integer(arm, 'echo_enqueued_bytes') == sum(json_integer(row, 'bytes') for i,row in echoes if i < arm_index),
                'Q05 arm/request/output prefix boundary differs')
    else:
        require(not arms and not gates, 'initial Q05 cannot substitute a post-handshake arm/gate')
        eligible = originals
    require(len(eligible) >= 2 and eligible[0]['sha256'] != eligible[1]['sha256'],
            'NOT_ESTABLISHED: Q05 first two emitted outputs were not distinct')
    first,second = eligible[:2]
    first_send = len(prefix) + 1
    require(len(sends) >= first_send + 2, 'Q05 selected SEND interval absent')
    hi,hold = held[0]; pi,pair = paired[0]; ei,released = established[0]
    origin = lambda row: {key:json_integer(row,key) for key in ('source_call','source_index')}
    identity = lambda row: (json_integer(row,'bytes'),row['sha256'])
    started = json_integer(hold,'started_ns'); deadline = json_integer(hold,'deadline_ns')
    ready_ns = json_integer(pair,'ready_ns'); released_ns = json_integer(released,'released_ns')
    require(first['event_index'] < hi < pi < sends[first_send-1][0]
            and origin(hold) == origin(first) and hold.get('policy') == policy
            and identity(hold) == identity(first)
            and json_integer(hold,'held_datagrams') == 1 and json_integer(hold,'held_bytes') == first['bytes']
            and started == first['observed_ns'] and deadline == started+500_000_000
            and second['observed_ns'] <= ready_ns <= released_ns <= deadline
            and second['event_index'] < pi
            and (first['source_call'] == second['source_call'] or hi < second['event_index'])
            and all(ci > ei for ci,_ in calls if ci > pi), 'Q05 first hold/pair/release causality or500ms bound differs')
    released_origins = released.get('source_origins')
    require(isinstance(released_origins,list) and len(released_origins) == 3
            and all(isinstance(row,dict) for row in released_origins), 'Q05 release origin array differs')
    selected = pair['datagrams']
    require(isinstance(selected,list) and len(selected) == 2
            and pair.get('policy') == released.get('policy') == policy
            and json_integer(pair,'started_ns') == json_integer(released,'started_ns') == started
            and json_integer(pair,'deadline_ns') == json_integer(released,'deadline_ns') == deadline
            and json_integer(pair,'buffered_datagrams') == 2
            and json_integer(pair,'buffered_bytes') == first['bytes']+second['bytes'] <= 2400
            and json_integer(pair,'first_send_ordinal') == first_send
            and json_integer(released,'held_bytes_after') == 0
            and released.get('send_ordinals') == list(range(first_send, first_send+3))
            and all(type(value)is int for value in released['send_ordinals'])
            and [origin(row)for row in released_origins] == [origin(second),origin(first),origin(first)]
            and all(json_integer(row,'observed_ns') >= released_ns for ci,row in calls if ci > ei),
            'Q05 exact two-buffer policy/selected origin/release receipt differs')
    for selected_packet, public in zip(selected,(first,second)):
        encoded = selected_packet.get('data_hex')
        require(isinstance(encoded,str) and re.fullmatch(r'(?:[0-9a-f]{2}){1,1200}',encoded),
                'Q05 selected actual public bytes are not canonical')
        data = bytes.fromhex(encoded)
        if post:
            require(data[0] & 0xc0 == 0x40, 'Q05 post-handshake selected ciphertext is not short-header 1-RTT')
        require(origin(selected_packet) == origin(public) and identity(selected_packet) == identity(public)
                and len(data) == public['bytes'] and hashlib.sha256(data).hexdigest() == public['sha256'],
                'Q05 selected held/public ciphertext bytes differ')
    require(hold.get('data_hex') == selected[0]['data_hex'], 'Q05 held bytes substituted at pairing')
    expected = [*prefix,second,first,first,*eligible[2:]]
    require(len(sends) == len(expected), 'Q05 every original output and one duplicate must be accounted')
    for index,((si,sent),(ai,action),public) in enumerate(zip(sends,actions,expected),1):
        next_send = sends[index][0] if index < len(sends) else len(events)
        require(public['event_index'] < si < ai < next_send and identity(sent) == identity(public)
                and sent['destination'] == public['destination'] and origin(action) == origin(public)
                and json_integer(action,'send_ordinal') == index and identity(action) == identity(public),
                'Q05 actual output origin/SEND/post-SEND order or complete bytes differs')
        if first_send <= index < first_send+3:
            require(pi < si < ai < ei and ready_ns <= json_integer(sent,'monotonic_ns') <= deadline,
                    'Q05 selected actual SEND completion exceeded held-output window')
        elif index < first_send:
            require(ai < arm_index, 'Q05 handshake output crossed post-handshake arm')
        else:
            require(ei < si, 'Q05 later public output preceded selected release')
    for public,count in ((first,2),(second,1)):
        require(sum(identity(row) == identity(public)for _,row in sends) == count,
                'Q05 selected original identities reused outside exact B,A,A')
    sent = [row for _,row in sends]
    require(all(isinstance(row.get(key),list)and len(row[key])==2 and isinstance(row[key][0],str)
                and type(row[key][1])is int and 0<row[key][1]<=65535 for row in sent for key in ('source','destination'))
            and all(isinstance(row.get('source'),list)and len(row['source'])==2 and isinstance(row['source'][0],str)
                    and type(row['source'][1])is int and 0<row['source'][1]<=65535 for _,row in received),
            'Q05 actual socket tuple representation differs')
    if wire is not None:
        for observed,captured,keys in ((sent,wire['peer_udp'],('bytes','sha256','source','destination')),
                                      ([row for _,row in received],wire['guest_udp'],('bytes','sha256','source'))):
            require([{key:row[key]for key in keys}for row in observed] ==
                    [{key:row[key]for key in keys}for row in captured], 'Q05 full socket/capture correspondence differs')
    else:
        require(sent[0]['source'][0] == received[0][1]['source'][0] == '127.0.0.1'
                and sent[0]['source'] != received[0][1]['source']
                and all(row.get('engine_delivered')is True and row['source']==sent[0]['source']for row in client_datagrams),
                'Q05 actual Linux public-engine input differs')
        selected_ordinal = reorder_consumed(pair,client_datagrams,sent)
        if post:
            require(all(row.get('authenticated_before') is True
                        for row in client_datagrams[selected_ordinal-1:selected_ordinal+2]),
                    'Q05 Linux selected inputs were not already authenticated')
    return pair



def verify_post_handshake_processing(case, output, report, delivered, selected_ordinal):
    observations = records(output, 'QUIC REORDER RX', case)
    require(len(observations) == len(delivered) == number(report, 'received') <= 256
            and len(observations) == sum(line.startswith('QUIC REORDER RX ') for line in output.splitlines()),
            'NOT_ESTABLISHED: Q05 complete native processing observations absent or different case')
    previous = 0
    for ordinal, (observation, actual) in enumerate(zip(observations, delivered), 1):
        before, after = (number(observation, key) for key in ('stream_frames_before', 'stream_frames_after'))
        handled = boolean(observation, 'target_handled')
        boolean(observation, 'authenticated_before')
        require(number(observation, 'receive_ordinal') == ordinal == actual['ordinal']
                and number(observation, 'bytes') == actual['bytes']
                and observation.get('sha256') == actual['sha256']
                and number(report, 'start_ms') <= number(observation, 'at_ms') <= number(report, 'fence_ms')
                and before == previous <= after <= number(report, 'receive_bytes')
                and after-before <= actual['bytes'] and (handled or after == before),
                'Q05 processing observation input, time or STREAM counter sequence differs')
        previous = after
    selected = observations[selected_ordinal-1:selected_ordinal+2]
    require(len(selected) == 3 and all(boolean(row, 'authenticated_before') and boolean(row, 'target_handled')
                                      for row in selected),
            'NOT_ESTABLISHED: Q05 selected inputs were not handled by the already authenticated target')
    require(all(number(row, 'stream_frames_after') > number(row, 'stream_frames_before') for row in selected[:2])
            and number(selected[2], 'stream_frames_after') == number(selected[2], 'stream_frames_before'),
            'NOT_ESTABLISHED: Q05 B and A positive/duplicate A zero STREAM processing absent')


def verify_flow_pause(case, fixture, wire=None):
    """Peer calibration only; native blocking and credit receipt are separate."""
    require(case['id'] == 'Q06' and development_profile(case) == 'q06-flow-pause-development'
            and fixture.get('readiness_profile') == 'q06-flow-pause-development'
            and fixture.get('mode') == 'flow-pause' and fixture.get('flow_released') is True,
            'Q06 exact selected peer/profile/release absent')
    events = fixture['events']
    def rows(name): return [(i, row) for i, row in enumerate(events) if row['event'] == name]
    config, start, release = (rows(name) for name in ('q06-configuration', 'q06-pause-start', 'q06-pause-release'))
    require(len(config) == len(start) == len(release) == 1, 'Q06 exact configuration/pause/release census differs')
    ci, configured = config[0]; si, paused = start[0]; ei, released = release[0]
    require(ci < si < ei and json_integer(configured, 'max_data') == json_integer(configured, 'max_stream_data') == 1024
            and json_integer(configured, 'hold_ns') == 250_000_000,
            'Q06 initial connection/stream credit or timer differs')
    begun = json_integer(paused, 'started_ns'); ended = json_integer(released, 'released_ns')
    require(json_integer(paused, 'until_ns') == begun + 250_000_000
            and json_integer(released, 'started_ns') == json_integer(fixture, 'flow_started_ns') == begun
            and 250_000_000 <= ended - begun <= 1_000_000_000
            and begun <= json_integer(paused, 'monotonic_ns') < ended <= json_integer(released, 'monotonic_ns')
            and paused.get('request_fin') is released.get('request_fin') is False
            and 512 < json_integer(paused, 'request_bytes') <= 1024
            and json_integer(released, 'request_bytes') == 1024,
            'Q06 exact bounded initial-credit plateau absent')
    flushes = rows('q06-public-flush'); sent = rows('udp-send'); received = rows('udp-receive')
    require(flushes and sent and received and all(not si < i < ei for i, _ in flushes + sent)
            and [json_integer(row, 'ordinal') for _, row in flushes] == list(range(1, len(flushes) + 1))
            and json_integer(fixture, 'flow_flushes') == len(flushes),
            'Q06 output construction or SEND crossed its credit hold')
    before = [(i, row) for i, row in flushes if i < si]
    after = [(i, row) for i, row in flushes if i > ei]
    require(before and after and all(row.get('released') is False and json_integer(row, 'request_bytes') <= 512 for _, row in before)
            and all(row.get('released') is True for _, row in after)
            and json_integer(after[0][1], 'request_bytes') == 1024
            and json_integer(paused, 'public_flushes') == json_integer(released, 'public_flushes') == len(before),
            'Q06 early credit expansion or release construction boundary differs')
    for index, boundary in ((si, paused), (ei, released)):
        prior = [row for i, row in sent if i < index]
        require(json_integer(boundary, 'tx_datagrams') == len(prior)
                and json_integer(boundary, 'tx_bytes') == sum(json_integer(row, 'bytes') for row in prior),
                'Q06 stable peer SEND census during hold differs')
    requests = rows('request-stream'); total = 0; crossing = None
    for i, row in requests:
        require(json_integer(row, 'stream_id') == 0 and json_integer(row, 'offset') == total
                and 0 < json_integer(row, 'bytes') <= 4096 - total,
                'Q06 request progress is not complete and contiguous')
        total += json_integer(row, 'bytes')
        if crossing is None and total > 512:
            crossing = (i, total)
        require(type(row.get('fin')) is bool and (not row['fin'] or total == 4096),
                'Q06 request FIN or representation differs')
        if i < ei:
            require(total <= 1024 and not row['fin'],
                    'Q06 request exceeded initial credit before release')
        if total == 1024:
            require(i < ei and not row['fin'], 'Q06 release is not after exact initial-credit progress')
    for i, row in flushes:
        require(json_integer(row, 'request_bytes') == sum(json_integer(part, 'bytes') for j, part in requests if j < i),
                'Q06 public flush request progress differs from actual stream events')
    require(ci < flushes[0][0], 'Q06 public output preceded its declared initial credit')
    require(total == 4096 and requests and requests[-1][1]['fin'] is True
            and crossing is not None and crossing[0] < si and crossing[1] == json_integer(paused, 'request_bytes')
            and sum(json_integer(row, 'bytes') for i, row in requests if i < si) == json_integer(paused, 'request_bytes')
            and sum(json_integer(row, 'bytes') for i, row in requests if i < ei) == 1024,
            'Q06 exact pre-pause progress or final request body absent')
    require(json_integer(fixture, 'tx_datagrams') == len(sent) <= 512
            and json_integer(fixture, 'rx_datagrams') == len(received) <= 512
            and json_integer(fixture, 'tx_bytes') == sum(json_integer(row, 'bytes') for _, row in sent)
            and json_integer(fixture, 'rx_bytes') == sum(json_integer(row, 'bytes') for _, row in received),
            'Q06 full socket census differs')
    if wire is not None:
        for observed, captured, keys in ((sent, wire['peer_udp'], ('bytes', 'sha256', 'source', 'destination')),
                                        (received, wire['guest_udp'], ('bytes', 'sha256', 'source'))):
            require([{key:row[key] for key in keys} for _, row in observed] ==
                    [{key:row[key] for key in keys} for row in captured], 'Q06 full socket/capture correspondence differs')
    else:
        require(sent[0][1]['source'][0] == received[0][1]['source'][0] == '127.0.0.1'
                and sent[0][1]['source'] != received[0][1]['source'], 'Q06 Linux socket calibration tuple differs')
    return si, ei, sent, received


def verify_native_flow_pause(case, output, report, fixture, wire):
    si, ei, sent, received = verify_flow_pause(case, fixture, wire)
    lines = output.splitlines()
    def observations(prefix):
        result = [(i, fields(line)) for i, line in enumerate(lines) if line.startswith(prefix + ' ')]
        require(all(row.get('case') == 'Q06' for _, row in result), 'Q06 flow observation has different case')
        return result
    blocked, transmitted, credits, resumed = (observations(prefix) for prefix in
        ('QUIC FLOW BLOCKED', 'QUIC FLOW TX', 'QUIC FLOW CREDIT', 'QUIC FLOW RESUMED'))
    require(len(blocked) == len(resumed) == 1 and 0 < len(transmitted) <= 256 and 0 < len(credits) <= 256,
            'NOT_ESTABLISHED: Q06 actual native blocking/transmit/credit/resumption absent')
    bi, block = blocked[0]; ri, resume = resumed[0]
    require(boolean(block, 'authenticated') and number(block, 'sent_stream') == 1024
            and number(block, 'requested') == 512
            and number(block, 'max_data_received') == number(block, 'max_stream_data_received') == 0
            and number(report, 'start_ms') <= number(block, 'at_ms') < number(resume, 'at_ms') < number(report, 'deadline_ms'),
            'NOT_ESTABLISHED: Q06 native blocked attempt was not at untouched initial credit')
    require(bi < transmitted[0][0] < credits[0][0] < ri
            and number(resume, 'sent_before') == 1024 and 0 < number(resume, 'written') <= 512
            and number(resume, 'max_data_received') > 0 and number(resume, 'max_stream_data_received') > 0,
            'Q06 native accepted blocked frame/credit/resumed write order differs')
    native_sent = records(output, 'QUIC FIXTURE SEND', case)
    native_rx = records(output, 'QUIC FIXTURE RX', case)
    require(len(wire['guest_udp']) == number(report, 'send_accepted')
            and sum(row['bytes'] for row in wire['guest_udp']) == number(report, 'send_bytes'),
            'Q06 complete accepted SEND/full capture differs')
    previous = previous_counter = 0
    for ti, row in transmitted:
        engine, request, accepted = (number(row, key) for key in ('engine_ordinal', 'native_request_ordinal', 'accepted_ordinal'))
        require(previous < engine == accepted <= number(report, 'engine_transmits') and 1 <= request <= len(native_sent)
                and engine <= request and boolean(row, 'authenticated')
                and number(row, 'data_blocked_before') == previous_counter
                and previous_counter < number(row, 'data_blocked_after') <= previous_counter + number(row, 'bytes'),
                'Q06 accepted DATA_BLOCKED counter/ordinal relation differs')
        request_row, packet = native_sent[request - 1], wire['guest_udp'][accepted - 1]
        require(row['sha256'] == request_row.get('sha256') == packet['sha256']
                and number(row, 'bytes') == number(request_row, 'bytes') == packet['bytes'],
                'Q06 positive public DATA_BLOCKED counter lacks exact accepted SEND/capture')
        previous, previous_counter = engine, number(row, 'data_blocked_after')
    first = transmitted[0][1]; first_socket = received[number(first, 'accepted_ordinal') - 1]
    require(si < first_socket[0] < ei and number(first, 'data_blocked_before') == 0,
            'NOT_ESTABLISHED: actual native DATA_BLOCKED did not reach peer during credit hold')
    # Match all successful native inputs as an ordered subset of the full peer
    # capture, retaining multiplicity; a credit cannot reuse a pre-release packet.
    capture_indices = []; cursor = 0
    for row in native_rx:
        while cursor < len(wire['peer_udp']) and (wire['peer_udp'][cursor]['bytes'], wire['peer_udp'][cursor]['sha256']) != (number(row, 'bytes'), row['sha256']):
            cursor += 1
        require(cursor < len(wire['peer_udp']), 'Q06 native input lacks ordered full peer capture')
        capture_indices.append(cursor); cursor += 1
    previous_rx = data = stream = resume_data = resume_stream = 0
    for ci, row in credits:
        ordinal = number(row, 'receive_ordinal')
        require(previous_rx < ordinal <= len(native_rx)
                and number(row, 'max_data_before') == data and number(row, 'max_stream_data_before') == stream
                and number(row, 'max_data_after') >= data and number(row, 'max_stream_data_after') >= stream
                and (number(row, 'max_data_after'), number(row, 'max_stream_data_after')) != (data, stream),
                'Q06 complete ordered public credit counter sequence differs')
        actual = native_rx[ordinal - 1]
        require(row['sha256'] == actual['sha256'] and number(row, 'bytes') == number(actual, 'bytes')
                and number(block, 'at_ms') <= number(row, 'at_ms') < number(report, 'deadline_ms')
                and sent[capture_indices[ordinal - 1]][0] > ei,
                'Q06 credit observation lacks exact native input emitted after release')
        previous_rx, data, stream = ordinal, number(row, 'max_data_after'), number(row, 'max_stream_data_after')
        if ci < ri:
            require(number(row, 'at_ms') <= number(resume, 'at_ms'), 'Q06 credit time follows the resumed write')
            resume_data, resume_stream = data, stream
    require(resume_data > 0 and resume_stream > 0
            and number(resume, 'max_data_received') == resume_data and number(resume, 'max_stream_data_received') == resume_stream,
            'Q06 no MAX_DATA/MAX_STREAM_DATA receipt before resumption')


def tag_consumed(mutation, delivered, sent):
    require(delivered and [json_integer(row, 'ordinal') for row in delivered] == list(range(1, len(delivered)+1)),
            'Q13 complete consumed-input ordinals differ')
    identity = lambda row: (json_integer(row, 'bytes'), row['sha256'])
    pair = [(mutation['bytes'], mutation['changed_sha256']), (mutation['bytes'], mutation['original_sha256'])]
    actual = [identity(row) for row in delivered]
    require(sum(actual[i:i+2] == pair for i in range(len(actual)-1)) == 1
            and all(actual.count(value) == 1 for value in pair),
            'NOT_ESTABLISHED: Q13 corrupted-tag/original pair was not consumed once consecutively')
    cursor = 0
    for row in delivered:
        while cursor < len(sent) and (identity(sent[cursor]), sent[cursor]['source']) != (identity(row), row['source']):
            cursor += 1
        require(cursor < len(sent), 'Q13 consumed input is not an ordered subset of complete peer SENDs')
        cursor += 1


def verify_invalid_tag(case, fixture, wire=None, client_datagrams=None):
    require(case['id'] == 'Q13' and development_profile(case) == 'q13-invalid-tag-development'
            and fixture.get('readiness_profile') == 'q13-invalid-tag-development'
            and fixture.get('mode') == 'invalid-tag', 'Q13 exact selected profile differs')
    require((wire is None) != (client_datagrams is None), 'Q13 capture or actual Linux consumed input required')
    events = fixture['events']
    def rows(name): return [(i,row) for i,row in enumerate(events) if row['event'] == name]
    batches, sends, actions, changes, done, initial, received, handshake = (rows(name) for name in
        ('q13-public-batch','udp-send','q13-engine-datagram-sent','tag-mutation','tag-mutation-sent',
         'initial-observed','udp-receive','handshake'))
    require(len(changes) == len(done) == 1 and json_integer(fixture, 'tag_mutations') == 1,
            'NOT_ESTABLISHED: Q13 one actual tag mutation absent')
    ci, mutation = changes[0]
    encoded = [mutation.get(key) for key in ('original_hex','changed_hex')]
    require(all(isinstance(value,str) and re.fullmatch(r'(?:[0-9a-f]{2}){42,1200}',value) for value in encoded),
            'Q13 exact bounded public ciphertext encoding differs')
    original, changed = (bytes.fromhex(value) for value in encoded)
    require(original[0] & 0xc0 == 0x40 and changed == original[:-1] + bytes([original[-1] ^ 1])
            and json_integer(mutation, 'bytes') == len(original)
            and json_integer(mutation, 'tag_bytes') == 16 and json_integer(mutation, 'xor') == 1
            and json_integer(mutation, 'changed_offset') == len(original)-1 >= 41
            and mutation['original_sha256'] == hashlib.sha256(original).hexdigest()
            and mutation['changed_sha256'] == hashlib.sha256(changed).hexdigest()
            and mutation.get('policy') == 'q13-tag-tail-xor1-v1'
            and mutation.get('authenticated_before') is True,
            'Q13 exact tag-tail-only byte relation or HP-sample exclusion differs')
    require(batches and 0 < len(sends) <= 512 and 0 < len(received) <= 512
            and len(initial) == len(handshake) == 1
            and received[0][0] < initial[0][0] < handshake[0][0] < ci
            and handshake[0][1].get('alpn') == 'absd-echo/1'
            and handshake[0][1].get('early_data') is False and handshake[0][1].get('resumed') is False
            and json_integer(initial[0][1], 'bytes') == json_integer(received[0][1], 'bytes') == 1200
            and initial[0][1]['sha256'] == received[0][1]['sha256']
            and json_integer(fixture, 'tx_datagrams') == len(sends)
            and json_integer(fixture, 'rx_datagrams') == len(received)
            and json_integer(fixture, 'tx_bytes') == sum(json_integer(row,'bytes')for _,row in sends) <= 512*1200
            and json_integer(fixture, 'rx_bytes') == sum(json_integer(row,'bytes')for _,row in received) <= 512*1200
            and json_integer(fixture, 'tag_batches') == len(batches)
            and [json_integer(row,'send_ordinal')for _,row in sends] == list(range(1,len(sends)+1)),
            'Q13 actual Initial/handshake/full batch/socket census differs')
    cursor, action_cursor, selected = 0, 0, False
    for ordinal, (bi,batch) in enumerate(batches,1):
        originals = batch['datagrams']
        require(isinstance(originals,list) and 1 <= len(originals) <= 4
                and json_integer(batch,'batch_ordinal') == ordinal
                and initial[0][0] < bi
                and json_integer(batch,'first_send_ordinal') == cursor+1
                and batch['initial_sha256'] == initial[0][1]['sha256']
                and type(batch.get('authenticated_before')) is bool
                and batch['authenticated_before'] == (bi > handshake[0][0])
                and json_integer(batch,'echo_enqueued_before') == sum(
                    json_integer(row,'bytes') for i,row in enumerate(events) if i < bi and row['event'] == 'echo-enqueue')
                and all(0 < json_integer(row,'bytes') <= 1200 and 0 <= json_integer(row,'first_byte') <= 255
                        and isinstance(row.get('sha256'),str) and re.fullmatch('[0-9a-f]{64}',row['sha256'])
                        and row['destination'] == received[0][1]['source'] for row in originals),
                'Q13 complete original public batch shape/identity/auth order differs')
        # Only a packet flushed after echo STREAM data was enqueued is eligible,
        # so the unchanged original can carry the positive STREAM observation.
        eligible = next((i for i,row in enumerate(originals) if not selected and batch['authenticated_before']
                         and batch['echo_enqueued_before'] > 0 and row['bytes'] >= 42 and row['first_byte'] & 0xc0 == 0x40),None)
        require(batch.get('selected_index') == eligible
                and (batch['selected_index'] is None or type(batch['selected_index']) is int),
                'Q13 first eligible actual short packet selection differs')
        boundary = batches[ordinal][0] if ordinal < len(batches) else len(events)
        previous = bi
        for index, packet in enumerate(originals):
            count = 2 if index == eligible else 1
            require(cursor + count <= len(sends) and action_cursor < len(actions), 'Q13 public output SEND/action missing')
            if index == eligible:
                selected = True
                require(json_integer(mutation,'batch_ordinal') == ordinal and json_integer(mutation,'source_index') == index
                        and json_integer(mutation,'first_send_ordinal') == cursor+1
                        and packet['bytes'] == len(original) and packet['first_byte'] == original[0]
                        and packet['sha256'] == mutation['original_sha256']
                        and previous < ci < sends[cursor][0], 'Q13 changed copy lacks exact original public engine output')
            for position in range(count):
                si,sent = sends[cursor]
                expected_hash = mutation['changed_sha256'] if count == 2 and position == 0 else packet['sha256']
                require(previous < si < boundary and sent['bytes'] == packet['bytes']
                        and sent['sha256'] == expected_hash and sent['destination'] == packet['destination'],
                        'Q13 complete changed/original public SEND order or bytes differs')
                previous = si; cursor += 1
            if index == eligible:
                di, completed = done[0]
                require(previous < di < boundary and json_integer(completed,'batch_ordinal') == ordinal
                        and json_integer(completed,'source_index') == index
                        and completed.get('send_ordinals') == [cursor-1,cursor]
                        and all(type(value)is int for value in completed['send_ordinals']),
                        'Q13 changed/original pair completion event differs')
                previous = di
            ai, action = actions[action_cursor];action_cursor += 1
            require(previous < ai < boundary and json_integer(action,'batch_ordinal') == ordinal
                    and json_integer(action,'source_index') == index and json_integer(action,'send_ordinal') == cursor
                    and json_integer(action,'bytes') == packet['bytes'] and action['sha256'] == packet['sha256'],
                    'Q13 original engine datagram post-SEND action differs')
            previous = ai
    require(selected and cursor == len(sends) and action_cursor == len(actions),
            'NOT_ESTABLISHED: Q13 no selected original or unmatched public output')
    for digest in (mutation['changed_sha256'], mutation['original_sha256']):
        require(sum(row['sha256'] == digest for _,row in sends) == 1, 'Q13 selected ciphertext identity reused')
    sent = [row for _,row in sends]
    require(all(isinstance(row.get(key),list)and len(row[key])==2 and isinstance(row[key][0],str)
                and type(row[key][1])is int and 0<row[key][1]<=65535 for row in sent for key in ('source','destination')),
            'Q13 actual socket tuple representation differs')
    if wire is not None:
        for observed,captured,keys in ((sent,wire['peer_udp'],('bytes','sha256','source','destination')),
                                      ([row for _,row in received],wire['guest_udp'],('bytes','sha256','source'))):
            require([{key:row[key]for key in keys}for row in observed] ==
                    [{key:row[key]for key in keys}for row in captured], 'Q13 full socket/capture correspondence differs')
    else:
        require(sent[0]['source'][0] == received[0][1]['source'][0] == '127.0.0.1'
                and sent[0]['source'] != received[0][1]['source']
                and all(row.get('engine_delivered')is True and row['source']==sent[0]['source']for row in client_datagrams),
                'Q13 actual Linux public-engine input differs')
        tag_consumed(mutation,client_datagrams,sent)
    return mutation


def verify_native_tag_processing(case, output, report, fixture, wire):
    mutation = verify_invalid_tag(case, fixture, wire=wire)
    ledger = records(output, 'QUIC FIXTURE RX', case)
    delivered = [{'ordinal':number(row, 'ordinal'), 'bytes':number(row, 'bytes'), 'sha256':row['sha256'],
                  'source':[row['peer_ip'], number(row, 'peer_port')]}
                 for row in ledger]
    tag_consumed(mutation, delivered, wire['peer_udp'])
    observations = records(output, 'QUIC TAG RX', case)
    require(len(observations) == len(ledger) == number(report, 'received') <= 256
            and len(observations) == sum(line.startswith('QUIC TAG RX ') for line in output.splitlines()),
            'NOT_ESTABLISHED: Q13 complete actual native tag observations absent or different case')
    previous = 0
    for ordinal, (observation, actual) in enumerate(zip(observations, ledger), 1):
        before, after = (number(observation, key) for key in ('stream_frames_before', 'stream_frames_after'))
        handled = boolean(observation, 'target_handled')
        boolean(observation, 'authenticated_before')
        require(number(observation, 'receive_ordinal') == ordinal == number(actual, 'ordinal')
                and number(observation, 'bytes') == number(actual, 'bytes')
                and observation.get('sha256') == actual['sha256']
                and number(report, 'start_ms') <= number(observation, 'at_ms') <= number(report, 'fence_ms'),
                'Q13 tag processing observation lacks exact ordered native input/lifetime')
        require(before == previous <= after <= number(report, 'receive_bytes')
                and after - before <= number(actual, 'bytes') and (handled or after == before),
                'Q13 public STREAM receive counter sequence differs')
        previous = after
    # Full socket/capture/native-input checks above establish the one pair's
    # ordinal and ciphertext identity. These immediate per-input counters do
    # not claim an AEAD error signal or invariance of every connection field.
    changed = next(i for i, row in enumerate(delivered) if row['sha256'] == mutation['changed_sha256'])
    corrupt, original = observations[changed:changed + 2]
    require(all(boolean(row, 'authenticated_before') and boolean(row, 'target_handled')
                for row in (corrupt, original)),
            'NOT_ESTABLISHED: Q13 pair was not handled by the already authenticated target connection')
    require(number(corrupt, 'stream_frames_after') == number(corrupt, 'stream_frames_before')
            and number(original, 'stream_frames_after') > number(original, 'stream_frames_before'),
            'NOT_ESTABLISHED: Q13 changed-tag zero/original positive STREAM processing absent')
    require(len(wire['guest_udp']) == number(report, 'send_accepted')
            and sum(row['bytes'] for row in wire['guest_udp']) == number(report, 'send_bytes'),
            'Q13 complete native SEND/capture census differs')


# Q07 end-time slack past the engine's own deadline. The engine re-reads its
# clock every turn (1 ms pause); accepted TCG runs show turns of at most 145 ms.
Q07_DEADLINE_SLACK_MS = 1000


def verify_silent(fixture, wire=None):
    """Q07: the peer received only client Initials and never sent or built an engine."""
    events = fixture['events']
    received = [row for row in events if row['event'] == 'udp-receive']
    silent = [row for row in events if row['event'] == 'silent-input']
    initial = [row for row in events if row['event'] == 'initial-observed']
    require(fixture.get('mode') == 'silent' and fixture.get('readiness_profile') == 'q07-silent-development',
            'Q07 exact silent profile differs')
    require(received and len(silent) == len(received) and len(initial) == 1
            and [(row['bytes'], row['sha256']) for row in silent] == [(row['bytes'], row['sha256']) for row in received]
            and [json_integer(row, 'receive_ordinal') for row in silent] == list(range(1, len(received) + 1))
            and all(row.get('engine_delivered') is False and json_integer(row, 'bytes') == 1200 for row in silent)
            and (initial[0]['sha256'], initial[0]['bytes']) == (received[0]['sha256'], received[0]['bytes']),
            'NOT_ESTABLISHED: Q07 complete silent Initial receipt census differs')
    require(not any(row['event'] in ('udp-send', 'certificate-selection', 'handshake', 'request-stream',
                                     'echo-enqueue', 'connection-terminated') for row in events)
            and json_integer(fixture, 'tx_datagrams') == json_integer(fixture, 'tx_bytes') == 0
            and json_integer(fixture, 'rx_datagrams') == len(received)
            and json_integer(fixture, 'rx_bytes') == sum(json_integer(row, 'bytes') for row in received)
            and fixture.get('authenticated') is False and fixture.get('request_bytes') == 0
            and fixture.get('echo_enqueued_bytes') == 0 and fixture.get('terminated') is None
            and fixture.get('certificate_selection') is None,
            'Q07 silent peer census differs: a send, engine, certificate, application byte or count')
    if wire is not None:
        require(not wire['peer_udp'] and wire.get('peer_udp_count', 0) == 0, 'Q07 peer datagram captured on the wire')
        require([(row['bytes'], row['sha256'], row['source']) for row in wire['guest_udp']]
                == [(row['bytes'], row['sha256'], row['source']) for row in received]
                and all(row['first_byte'] & 0xf0 == 0xc0 for row in wire['guest_udp']),
                'Q07 guest Initial capture/peer receipt correspondence differs')
    return received


def retry_integrity_tag(packet_without_tag, original_destination_cid):
    """RFC 9001 5.8 Retry tag, recomputed with aioquic's public helper (the verified peer closure)."""
    from aioquic.quic.packet import get_retry_integrity_tag
    return get_retry_integrity_tag(packet_without_tag, original_destination_cid, 1)


def verify_long_retry(fixture, wire=None):
    """Q14: one valid-integrity Retry with a 21-byte SCID, ignored by the client, then silence."""
    events = fixture['events']
    received = [(i, row) for i, row in enumerate(events) if row['event'] == 'udp-receive']
    silent = [(i, row) for i, row in enumerate(events) if row['event'] == 'silent-input']
    initial = [(i, row) for i, row in enumerate(events) if row['event'] == 'initial-observed']
    retry = [(i, row) for i, row in enumerate(events) if row['event'] == 'retry-fixture']
    sent = [(i, row) for i, row in enumerate(events) if row['event'] == 'udp-send']
    require(fixture.get('mode') == 'long-retry' and fixture.get('readiness_profile') == 'q14-long-retry-development',
            'Q14 exact long-Retry profile differs')
    require(len(received) >= 2 and len(silent) == len(received) and len(initial) == len(retry) == len(sent) == 1
            and [(row['bytes'], row['sha256']) for _, row in silent] == [(row['bytes'], row['sha256']) for _, row in received]
            and [json_integer(row, 'receive_ordinal') for _, row in silent] == list(range(1, len(received) + 1))
            and all(row.get('engine_delivered') is False and json_integer(row, 'bytes') == 1200 for _, row in silent)
            and (initial[0][1]['sha256'], initial[0][1]['bytes']) == (received[0][1]['sha256'], received[0][1]['bytes'])
            and received[0][0] < initial[0][0] < silent[0][0] < retry[0][0] < sent[0][0] < received[1][0],
            'NOT_ESTABLISHED: Q14 Initial/Retry/later-Initial order or receipt census differs')
    first = silent[0][1]; hold = retry[0][1]; out = sent[0][1]
    encoded = hold.get('data_hex')
    require(isinstance(encoded, str) and re.fullmatch(r'(?:[0-9a-f]{2}){1,1200}', encoded) is not None,
            'Q14 Retry bytes are not canonical')
    data = bytes.fromhex(encoded)
    dcid = bytes.fromhex(first['dcid_hex']); scid = bytes.fromhex(first['scid_hex'])
    d_len = data[5] if len(data) > 5 else -1
    s_off = 6 + d_len
    require(data[0] & 0xf0 == 0xf0 and data[1:5] == b'\x00\x00\x00\x01'
            and data[6:6 + d_len] == scid and data[s_off] == 21
            and data[s_off + 1:s_off + 22].hex() == hold.get('source_cid_hex')
            and hold.get('source_cid_bytes') == 21 and hold.get('integrity_verified') is True
            and hold.get('original_destination_cid_hex') == dcid.hex() and hold.get('destination_cid_hex') == scid.hex()
            and len(data) > s_off + 22 + 16
            and retry_integrity_tag(data[:-16], dcid) == data[-16:]
            and json_integer(hold, 'bytes') == len(data) == json_integer(out, 'bytes')
            and hold['sha256'] == hashlib.sha256(data).hexdigest() == out['sha256'] and out.get('fixture') == 'long-retry',
            'Q14 Retry structure, 21-byte SCID, recomputed integrity tag or sent bytes differ')
    later = [row for _, row in silent[1:]]
    require(later and all(row['dcid_hex'] == first['dcid_hex'] and row['scid_hex'] == first['scid_hex']
                          and json_integer(row, 'token_bytes') == 0 for row in [first] + later),
            'NOT_ESTABLISHED: Q14 client did not keep its original Initial after the overlong Retry')
    require(not any(row['event'] in ('certificate-selection', 'handshake', 'request-stream', 'echo-enqueue',
                                     'connection-terminated') for row in events)
            and json_integer(fixture, 'tx_datagrams') == 1 and json_integer(fixture, 'tx_bytes') == len(data)
            and json_integer(fixture, 'rx_datagrams') == len(received)
            and json_integer(fixture, 'rx_bytes') == sum(json_integer(row, 'bytes') for _, row in received)
            and fixture.get('authenticated') is False and fixture.get('request_bytes') == 0
            and fixture.get('echo_enqueued_bytes') == 0 and fixture.get('terminated') is None
            and fixture.get('certificate_selection') is None,
            'Q14 peer census differs: an extra send, engine, certificate, application byte or count')
    if wire is not None:
        require([(row['bytes'], row['sha256']) for row in wire['peer_udp']] == [(len(data), hold['sha256'])]
                and wire['peer_udp'][0]['first_byte'] & 0xf0 == 0xf0, 'Q14 captured peer output is not exactly the Retry')
        require([(row['bytes'], row['sha256'], row['source']) for row in wire['guest_udp']]
                == [(row['bytes'], row['sha256'], row['source']) for _, row in received]
                and all(row['first_byte'] & 0xf0 == 0xc0 for row in wire['guest_udp']),
                'Q14 guest Initial capture/peer receipt correspondence differs')
    return data


def verify_unknown_cid(fixture, wire=None):
    """Q16: one short-header datagram to an unissued DCID, sent once after echo data, inside a normal echo."""
    events = fixture['events']
    marks = [(i, row) for i, row in enumerate(events) if row['event'] == 'unknown-cid-fixture']
    tagged = [(i, row) for i, row in enumerate(events) if row['event'] == 'udp-send' and row.get('fixture') == 'unknown-cid']
    handshake = [i for i, row in enumerate(events) if row['event'] == 'handshake']
    echo = [i for i, row in enumerate(events) if row['event'] == 'echo-enqueue']
    require(fixture.get('mode') == 'unknown-cid' and fixture.get('readiness_profile') == 'q16-unknown-cid-development'
            and len(marks) == len(tagged) == len(handshake) == 1 and echo,
            'NOT_ESTABLISHED: Q16 one unknown-CID datagram after authentication absent')
    (mi, mark), (si, sent) = marks[0], tagged[0]
    expected = bytes([0x40]) + b'ABSDQ16!' + bytes(range(64))
    require(handshake[0] < echo[0] < mi < si and json_integer(mark, 'echo_enqueued_before') > 0
            and mark.get('dcid_hex') == expected[1:9].hex()
            and json_integer(mark, 'bytes') == json_integer(sent, 'bytes') == len(expected)
            and mark['sha256'] == sent['sha256'] == hashlib.sha256(expected).hexdigest(),
            'Q16 unknown-CID datagram bytes, order or tag differ')
    if wire is not None:
        require(sum(row['sha256'] == sent['sha256'] for row in wire['peer_udp']) == 1,
                'Q16 unknown-CID datagram not captured exactly once')
    return sent


def verify_unauthorized_source(fixture, wire=None):
    """Q18: the peer's actual next short-header datagram, sent only from a second local port, after echo data."""
    events = fixture['events']
    probes = [(i, row) for i, row in enumerate(events) if row['event'] == 'unauthorized-probe']
    handshake = [i for i, row in enumerate(events) if row['event'] == 'handshake']
    echo = [i for i, row in enumerate(events) if row['event'] == 'echo-enqueue']
    require(fixture.get('mode') == 'unauthorized-source'
            and fixture.get('readiness_profile') == 'q18-unauthorized-source-development'
            and len(probes) == len(handshake) == 1 and echo,
            'NOT_ESTABLISHED: distinct bad-tuple encrypted probe absent')
    pi, probe = probes[0]
    sent = [row for row in events if row['event'] == 'udp-send']
    require(handshake[0] < echo[0] < pi and probe.get('authorized_copy_sent') is False
            and json_integer(probe, 'echo_enqueued_before') > 0 and 42 <= json_integer(probe, 'bytes') <= 1200
            and json_integer(probe, 'first_byte') & 0xc0 == 0x40
            and probe['source'][0] == probe['authorized_source'][0] and probe['source'][1] != probe['authorized_source'][1]
            and probe['destination'] == received_source(events)
            and all(row['sha256'] != probe['sha256'] for row in sent),
            'Q18 probe tuple, timing, shape or authorized-copy absence differs')
    if wire is not None:
        bad = [row for row in wire.get('unauthorized_peer_udp', []) if row['sha256'] == probe['sha256']]
        require(len(bad) == len(wire.get('unauthorized_peer_udp', [])) == 1 and bad[0]['source'][1] == probe['source'][1]
                and bad[0]['source'][1] != 4443 and bad[0]['destination'] == wire['guest_udp'][0]['source']
                and not any(row['sha256'] == probe['sha256'] for row in wire['peer_udp']),
                'NOT_ESTABLISHED: distinct wrong-tuple probe not captured exactly once')
    return probe


def received_source(events):
    first = next(row for row in events if row['event'] == 'udp-receive')
    return first['source']


def verify_interruption_peer(case, fixture, wire=None):
    """Calibrate the independent peer; this does not prove native interruption."""
    require(case['id'] in ('Q21', 'Q22') and not fixture['errors'] and not fixture['thread_alive']
            and fixture.get('readiness_profile') == development_profile(case)
            and fixture.get('canonical_campaign_acceptance') is False,
            'interruption peer profile or terminal state differs')
    events = fixture['events']
    def rows(name): return [(i, row) for i, row in enumerate(events) if row['event'] == name]
    received, sent, initial = (rows(name) for name in ('udp-receive', 'udp-send', 'initial-observed'))
    require(0 < len(received) <= 512 and len(sent) <= 512 and len(initial) == 1
            and json_integer(fixture, 'rx_datagrams') == len(received)
            and json_integer(fixture, 'tx_datagrams') == len(sent)
            and json_integer(fixture, 'rx_bytes') == sum(json_integer(row, 'bytes') for _, row in received)
            and json_integer(fixture, 'tx_bytes') == sum(json_integer(row, 'bytes') for _, row in sent),
            'interruption complete peer socket census differs')
    host = '10.0.2.15' if wire is not None else '127.0.0.1'
    source = received[0][1].get('source')
    require(isinstance(source, list) and len(source) == 2 and source[0] == host
            and type(source[1]) is int and 0 < source[1] <= 65535
            and (wire is None or source[1] == case['local_port']), 'interruption client tuple differs')
    for _, row in received:
        require(row.get('source') == source and 0 < json_integer(row, 'bytes') <= 1200
                and isinstance(row.get('sha256'), str) and re.fullmatch('[0-9a-f]{64}', row['sha256']),
                'interruption peer receipt identity differs')
    require(received[0][0] < initial[0][0] and json_integer(initial[0][1], 'bytes') == 1200
            and (initial[0][1]['bytes'], initial[0][1]['sha256']) ==
                (received[0][1]['bytes'], received[0][1]['sha256']),
            'NOT_ESTABLISHED: interruption peer never received the actual Initial')
    if wire is not None:
        for observed, captured, keys in ((received, wire['guest_udp'], ('bytes', 'sha256', 'source')),
                                         (sent, wire['peer_udp'], ('bytes', 'sha256', 'source', 'destination'))):
            require([{key:row[key] for key in keys} for _, row in observed] ==
                    [{key:row[key] for key in keys} for row in captured],
                    'interruption full peer socket/capture correspondence differs')
    require(fixture.get('echo_enqueued_bytes') == 0 and fixture.get('echo_fin_enqueued') is False
            and not rows('echo-enqueue') and not rows('echo-fin-enqueue'),
            'interruption fixture completed or enqueued an echo')
    if case['id'] == 'Q21':
        silent = rows('silent-input')
        require(fixture.get('mode') == 'silent'
                and fixture.get('interruption_policy') == 'q21-engine-free-silent-v1'
                and fixture.get('engine_constructed') is False and not sent
                and fixture.get('authenticated') is False and fixture.get('request_bytes') == 0
                and fixture.get('request_fin') is False and fixture.get('certificate_selection') is None
                and fixture.get('terminated') is None
                and not any(rows(name) for name in ('certificate-selection', 'handshake', 'request-stream', 'connection-terminated'))
                and len(silent) == len(received)
                and [json_integer(row, 'receive_ordinal') for _, row in silent] == list(range(1, len(received) + 1))
                and all(row.get('engine_delivered') is False and json_integer(row, 'bytes') == 1200
                        and (row['bytes'], row['sha256']) == (actual['bytes'], actual['sha256'])
                        for (_, row), (_, actual) in zip(silent, received)),
                'NOT_ESTABLISHED: Q21 actual engine-free silent Initial receipts absent')
        return None
    fenced, handshakes, requests = (rows(name) for name in ('q22-stream-output-fenced', 'handshake', 'request-stream'))
    require(fixture.get('mode') == 'interrupt-stream'
            and fixture.get('interruption_policy') == 'q22-stream-output-fence-v1'
            and fixture.get('stream_output_fenced') is True and fixture.get('authenticated') is True
            and fixture.get('terminated') is None and not rows('connection-terminated')
            and len(fenced) == len(handshakes) == 1 and requests,
            'NOT_ESTABLISHED: Q22 authenticated positive stream output fence absent')
    fi, fence = fenced[0]
    trigger_fields = ('receive_ordinal', 'bytes', 'sha256', 'request_bytes', 'request_sha256',
                      'request_fin', 'authenticated_before', 'tx_datagrams', 'tx_bytes')
    require(fixture.get('stream_output_trigger') == {key:fence.get(key) for key in trigger_fields}
            and handshakes[0][0] < requests[0][0] < fi
            and fence.get('policy') == 'q22-stream-output-fence-v1'
            and fence.get('authenticated_before') is True
            and fence.get('later_engine_work') is fence.get('later_send') is False,
            'Q22 selected stream fence identity or authentication differs')
    total = 0
    for index, row in requests:
        require(index < fi and json_integer(row, 'stream_id') == 0
                and json_integer(row, 'offset') == total and 0 < json_integer(row, 'bytes') <= 4096 - total
                and type(row.get('fin')) is bool
                and (index == requests[-1][0] or row['fin'] is False),
                'Q22 request prefix is not complete and contiguous')
        total += row['bytes']
    prefix_hash = hashlib.sha256(bytes(97 + i % 26 for i in range(total))).hexdigest()
    require(0 < total == json_integer(fixture, 'request_bytes') == json_integer(fence, 'request_bytes') <= 4096
            and fixture.get('request_sha256') == fence.get('request_sha256') == prefix_hash
            and type(fixture.get('request_fin')) is bool and fence.get('request_fin') is fixture['request_fin']
            and requests[-1][1]['fin'] is fixture['request_fin']
            and (not fixture['request_fin'] or total == 4096), 'Q22 actual request prefix/hash/FIN differs')
    trigger = json_integer(fence, 'receive_ordinal')
    require(1 <= trigger <= len(received)
            and all(json_integer(row, 'receive_ordinal') == trigger for _, row in requests)
            and [json_integer(row, 'receive_ordinal') for _, row in received] == list(range(1, len(received) + 1))
            and (fence['bytes'], fence['sha256']) == (received[trigger - 1][1]['bytes'], received[trigger - 1][1]['sha256'])
            and received[trigger - 1][0] < fi
            and json_integer(fence, 'tx_datagrams') == len(sent)
            and json_integer(fence, 'tx_bytes') == sum(row['bytes'] for _, row in sent)
            and all(index < fi for index, _ in sent), 'Q22 triggering input or stable output census differs')
    later = rows('q22-after-fence-input')
    require(len(later) == len(received) - trigger
            and [(json_integer(row, 'receive_ordinal'), row['bytes'], row['sha256'], row['source']) for _, row in later] ==
                [(ordinal, row['bytes'], row['sha256'], row['source']) for ordinal, (_, row) in enumerate(received, 1) if ordinal > trigger]
            and all(index > fi and row.get('engine_delivered') is False for index, row in later)
            and all(row['event'] in ('udp-receive', 'q22-after-fence-input', 'peer-ended') for row in events[fi + 1:]),
            'Q22 engine/output work crossed the selected stream fence')
    return fence


def verify_qmp_greeting(hello):
    require(isinstance(hello,dict) and isinstance(hello.get('QMP'),dict), 'QMP greeting absent')
    greeting = hello['QMP']
    version = greeting.get('version')
    qemu = version.get('qemu') if isinstance(version,dict) else None
    require(isinstance(qemu,dict) and all(type(qemu.get(key)) is int and qemu[key]>=0
                                         for key in ('major','minor','micro'))
            and isinstance(version.get('package'),str)
            and isinstance(greeting.get('capabilities'),list)
            and all(isinstance(item,str) for item in greeting['capabilities']), 'QMP greeting schema differs')


def verify_link_peer(case, fixture, wire=None):
    """A real Initial triggers one exact-QEMU action, with no server engine."""
    require(case['id'] == 'Q24' and development_profile(case) == 'q24-link-failure-development'
            and fixture.get('readiness_profile') == development_profile(case)
            and fixture.get('canonical_campaign_acceptance') is False
            and fixture.get('mode') == 'link-failure' and fixture.get('link_policy') == 'q24-link-failure-v1'
            and fixture.get('errors') == [] and fixture.get('thread_alive') is False,
            'link fixture failed, remains live or has a different profile')
    events = fixture['events']
    def rows(name): return [(i,row) for i,row in enumerate(events) if row['event'] == name]
    received, sent = rows('udp-receive'), rows('udp-send')
    initial, begun, actions = rows('initial-observed'), rows('link-action-begin'), rows('link-action')
    inputs = rows('link-failure-input')
    require(fixture.get('engine_constructed') is False and fixture.get('certificate_selection') is None
            and fixture.get('authenticated') is False and fixture.get('request_bytes') == 0
            and fixture.get('request_fin') is False and fixture.get('echo_enqueued_bytes') == 0
            and fixture.get('echo_fin_enqueued') is False and fixture.get('terminated') is None
            and not sent and fixture.get('tx_datagrams') == fixture.get('tx_bytes') == 0
            and not any(rows(name) for name in ('certificate-selection','handshake','request-stream',
                                               'echo-enqueue','echo-fin-enqueue','connection-terminated')),
            'link peer constructed an engine, sent UDP or reached authentication/application')
    require(0 < len(received) <= 256 and json_integer(fixture,'rx_datagrams') == len(received)
            and json_integer(fixture,'rx_bytes') == sum(json_integer(row,'bytes') for _,row in received)
            and [json_integer(row,'receive_ordinal') for _,row in received] == list(range(1,len(received)+1))
            and len(inputs) == len(received), 'link peer complete socket census differs')
    require(len(initial) == len(begun) == len(actions) == 1
            and received[0][0] < initial[0][0] < inputs[0][0] < begun[0][0] < actions[0][0]
            and fixture.get('link_action_attempted') is True and fixture.get('link_action_completed') is True,
            'NOT_ESTABLISHED: link action did not follow one actual Initial')
    source = ['10.0.2.15',case['local_port']]
    for (ri,row),(ii,delivery) in zip(received,inputs):
        raw = row.get('data_hex')
        require(isinstance(raw,str) and re.fullmatch('[0-9a-f]{2400}',raw)
                and json_integer(row,'bytes') == 1200 and hashlib.sha256(bytes.fromhex(raw)).hexdigest() == row.get('sha256')
                and int(raw[:2],16)&0xf0 == 0xc0 and raw[2:10] == '00000001' and row.get('source') == source
                and row.get('destination') == ['10.0.2.2',4443] and row.get('engine_delivered') is False
                and ri < ii and delivery.get('engine_delivered') is False
                and all(delivery.get(key) == row.get(key) for key in ('receive_ordinal','bytes','sha256')),
                'link input lacks exact parsed Initial bytes, tuple or engine-free receipt')
    first, action = received[0][1], actions[0][1]
    require(all(initial[0][1].get(key) == first[key] for key in ('receive_ordinal','bytes','sha256'))
            and json_integer(begun[0][1],'trigger_receive_ordinal') == 1
            and begun[0][1].get('trigger_sha256') == first['sha256']
            and json_integer(action,'trigger_receive_ordinal') == 1 and action.get('trigger_sha256') == first['sha256']
            and action.get('qmp_acknowledged') is True and action.get('device_id') == 'quicnic'
            and type(action.get('exact_qemu_pid')) is int and action['exact_qemu_pid'] > 0
            and isinstance(action.get('qmp_receipt'),str)
            and re.fullmatch('[0-9a-f]{64}',action.get('qmp_receipt_sha256','')),
            'link action lacks exact Initial trigger or owned QMP identity')
    keys = ('qmp_acknowledged','qmp_receipt','qmp_receipt_sha256','exact_qemu_pid','device_id')
    trigger = fixture.get('link_trigger')
    require(isinstance(trigger,dict)
            and all(trigger.get(key) == first[key] for key in ('receive_ordinal','bytes','sha256','source','destination'))
            and fixture.get('link_action_result') == {key:action[key] for key in keys}
            and all(json_integer(a,'monotonic_ns') <= json_integer(b,'monotonic_ns')
                    for a,b in zip(events,events[1:])), 'link retained trigger/result or host-clock ordering differs')
    require(all(row['event'] in ('udp-receive','link-failure-input','peer-ended')
                for row in events[actions[0][0]+1:]), 'link action was repeated or engine work followed it')
    if wire is not None:
        require(not wire['peer_udp'] and wire['guest_udp_count'] == len(received)
                and [{key:row[key] for key in ('bytes','sha256','source')} for _,row in received] ==
                    [{key:row[key] for key in ('bytes','sha256','source')} for row in wire['guest_udp']],
                'link peer complete socket/capture correspondence differs')
    return action


def verify_qmp_link_receipt(fixture, path, expected_pid, socket_path):
    actions = [row for row in fixture['events'] if row['event'] == 'link-action']
    require(len(actions) == 1, 'one QMP action receipt required')
    action = actions[0]
    require(type(expected_pid) is int and expected_pid > 0 and not path.is_symlink()
            and action.get('exact_qemu_pid') == expected_pid and action.get('qmp_receipt') == str(path)
            and sha(path) == action.get('qmp_receipt_sha256'), 'QMP action receipt or original guest differs')
    receipt = json.loads(path.read_text())
    verify_qmp_greeting(receipt.get('greeting'))
    peer = receipt.get('socket_peer',{})
    require(receipt.get('qmp_acknowledged') is True and 'error' not in receipt
            and json_integer(receipt,'expected_qemu_pid') == json_integer(peer,'pid') == expected_pid
            and json_integer(peer,'uid') == os.geteuid() and json_integer(peer,'gid') >= 0
            and receipt.get('socket') == str(socket_path)
            and receipt.get('device_id') == action.get('device_id') == 'quicnic'
            and type(receipt.get('acknowledged_monotonic_ns')) is int
            and receipt['acknowledged_monotonic_ns'] > 0,
            'QMP acknowledgment lacks exact original socket process or successful terminal')
    begun = [row for row in fixture['events'] if row['event'] == 'link-action-begin']
    require(len(begun) == 1 and json_integer(begun[0],'monotonic_ns') <=
            receipt['acknowledged_monotonic_ns'] <= json_integer(action,'monotonic_ns'),
            'QMP acknowledgment is outside its same-host callback interval')
    commands = [dict(execute='qmp_capabilities',id='capabilities'),
                dict(execute='set_link',arguments=dict(name='quicnic',up=False),id='drop-link')]
    exchanges = receipt.get('exchanges')
    require(isinstance(exchanges,list) and len(exchanges) == 2, 'QMP command census differs')
    for row,command in zip(exchanges,commands):
        replies = row.get('replies')
        require(row.get('command') == command and isinstance(replies,list) and 0 < len(replies) <= 32
                and all(isinstance(reply,dict) for reply in replies)
                and all(reply.get('id') != command['id'] for reply in replies[:-1])
                and replies[-1].get('id') == command['id'] and 'error' not in replies[-1]
                and isinstance(replies[-1].get('return'),dict), 'QMP exact command acknowledgment differs')
    require(exchanges[1]['command']['arguments']['up'] is False, 'QMP link action is not down')
    return {'path':str(path),'sha256':sha(path),'exact_qemu_pid':expected_pid}


def verify_authority_peer(case, fixture, wire=None):
    """A causal Q23 marker, or a passive native-only startup-refusal peer."""
    development_profile(case)
    require(case['id'] in ('Q23', 'Q29', 'Q30', 'Q31') and fixture.get('readiness_profile') == development_profile(case)
            and fixture.get('canonical_campaign_acceptance') is False
            and fixture.get('errors') == [] and fixture.get('thread_alive') is False,
            'authority fixture failed, remains live or has a different profile')
    policy = {'Q23':'q23-owner-expiry-v1', 'Q29':'q29-missing-output-v1', 'Q30':'q30-missing-time-v1', 'Q31':'q31-absent-rdrand-v1'}[case['id']]
    events = fixture['events']
    def rows(name): return [(i, row) for i, row in enumerate(events) if row['event'] == name]
    received, sent = rows('udp-receive'), rows('udp-send')
    require(fixture.get('mode') == case['peer_mode'] and fixture.get('authority_policy') == policy
            and fixture.get('engine_constructed') is False and fixture.get('certificate_selection') is None
            and fixture.get('authenticated') is False and fixture.get('request_bytes') == 0
            and fixture.get('request_fin') is False and fixture.get('echo_enqueued_bytes') == 0
            and fixture.get('echo_fin_enqueued') is False and fixture.get('terminated') is None
            and not any(rows(name) for name in ('certificate-selection', 'handshake', 'request-stream',
                                               'echo-enqueue', 'echo-fin-enqueue', 'connection-terminated')),
            'authority peer constructed an engine, authenticated or emitted application data')
    require(json_integer(fixture, 'rx_datagrams') == len(received)
            and json_integer(fixture, 'tx_datagrams') == len(sent)
            and json_integer(fixture, 'rx_bytes') == sum(json_integer(row, 'bytes') for _, row in received)
            and json_integer(fixture, 'tx_bytes') == sum(json_integer(row, 'bytes') for _, row in sent),
            'authority peer complete socket census differs')
    if wire is not None:
        for observed, captured, keys in ((received, wire['guest_udp'], ('bytes', 'sha256', 'source')),
                                         (sent, wire['peer_udp'], ('bytes', 'sha256', 'source', 'destination'))):
            require([{key:row[key] for key in keys} for _, row in observed] ==
                    [{key:row[key] for key in keys} for row in captured],
                    'authority peer complete socket/capture correspondence differs')
    if case['id'] != 'Q23':
        require(not received and not sent and not rows('initial-observed')
                and fixture.get('passive_receive_count') == 0,
                'native startup refusal reached the passive peer')
        return None
    initial, markers = rows('initial-observed'), rows('expiry-observation-marker')
    require(received and len(initial) == len(markers) == len(sent) == 1,
            'NOT_ESTABLISHED: owner expiry has no actual Initial and one causal marker')
    require([json_integer(row, 'receive_ordinal') for _, row in received] == list(range(1, len(received) + 1))
            and all(json_integer(row, 'bytes') == 1200 and isinstance(row.get('sha256'), str)
                    and re.fullmatch('[0-9a-f]{64}', row['sha256'])
                    and isinstance(row.get('data_hex'), str) and re.fullmatch('[0-9a-f]{2400}', row['data_hex'])
                    and hashlib.sha256(bytes.fromhex(row['data_hex'])).hexdigest() == row['sha256']
                    and int(row['data_hex'][:2], 16) & 0xf0 == 0xc0 and row['data_hex'][2:10] == '00000001'
                    for _, row in received),
            'owner expiry complete Initial receipt ledger differs')
    inputs = rows('owner-expiry-input')
    require(len(inputs) == len(received)
            and [(json_integer(row, 'receive_ordinal'), row.get('bytes'), row.get('sha256')) for _, row in inputs] ==
                [(json_integer(row, 'receive_ordinal'), row['bytes'], row['sha256']) for _, row in received]
            and all(receive_index < input_index and row.get('engine_delivered') is False
                    for (receive_index, _), (input_index, row) in zip(received, inputs)),
            'owner expiry input reached an engine or lacks its actual receipt')
    client = received[0][1].get('source')
    require(isinstance(client, list) and len(client) == 2
            and client[0] == ('10.0.2.15' if wire is not None else '127.0.0.1')
            and type(client[1]) is int and 0 < client[1] <= 65535
            and (wire is None or client[1] == case['local_port'])
            and all(row.get('source') == client for _, row in received), 'owner expiry client tuple differs')
    marker = markers[0][1]
    literal = b'\x00ABSD-QUIC-Q23-INITIAL-OBSERVED'
    marker_hash = hashlib.sha256(literal).hexdigest()
    require(received[0][0] < initial[0][0] < inputs[0][0] < sent[0][0] < markers[0][0]
            and (json_integer(initial[0][1], 'bytes'), initial[0][1].get('sha256')) ==
                (received[0][1]['bytes'], received[0][1]['sha256'])
            and marker.get('initial_sha256') == received[0][1]['sha256']
            and marker.get('marker_hex') == literal.hex() == case['observation_marker_hex']
            and marker.get('marker_sha256') == marker_hash
            and json_integer(marker, 'case_port') == case['local_port']
            and json_integer(marker, 'send_ordinal') == json_integer(sent[0][1], 'send_ordinal') == 1
            and (json_integer(sent[0][1], 'bytes'), sent[0][1].get('sha256')) == (len(literal), marker_hash)
            and sent[0][1].get('data_hex') == literal.hex()
            and sent[0][1].get('destination') == client
            and sent[0][1].get('source', [None, None])[0] == ('10.0.2.2' if wire is not None else '127.0.0.1')
            and (wire is None or sent[0][1]['source'][1] == 4443)
            and fixture.get('marker_sent') is True,
            'NOT_ESTABLISHED: exact literal marker was not sent after the actual Initial')
    trigger = fixture.get('marker_trigger')
    require(isinstance(trigger, dict) and json_integer(trigger, 'receive_ordinal') == 1
            and (trigger.get('bytes'), trigger.get('sha256')) == (1200, received[0][1]['sha256'])
            and trigger.get('marker_hex') == literal.hex() and trigger.get('marker_sha256') == marker_hash
            and trigger.get('destination') == client, 'owner expiry marker trigger differs')
    return marker


def verify_linux_owner_expiry(case, observed):
    require(case['id'] == 'Q23', 'Linux owner expiry calibration case differs')
    fixture = observed['fixture']
    verify_authority_peer(case, fixture)
    require(observed.get('actual_outcome') == 'Deadline' and observed.get('authenticated') is False
            and observed.get('received_bytes') == 0 and observed.get('peer_fin') is False,
            'Linux owner expiry marker calibration authenticated or received application data')
    sent = [row for row in fixture['events'] if row['event'] == 'udp-send']
    delivered = observed.get('client_datagrams')
    require(isinstance(delivered, list) and len(delivered) == len(sent) == 1
            and json_integer(delivered[0], 'ordinal') == 1 and delivered[0].get('engine_delivered') is True
            and delivered[0].get('data_hex') == (b'\x00ABSD-QUIC-Q23-INITIAL-OBSERVED').hex()
            and [(row.get('bytes'), row.get('sha256'), row.get('source')) for row in delivered] ==
                [(row['bytes'], row['sha256'], row['source']) for row in sent],
            'Linux owner expiry exact marker was not delivered to the independent client')


def verify_icmp_peer(case, fixture, wire=None):
    """Literal fixture correspondence, separate from native advisory matching."""
    development_profile(case)
    require(case['id'] in ('Q25', 'Q26', 'Q27', 'Q28')
            and fixture.get('case') == case['id'] and fixture.get('mode') == case['peer_mode']
            and fixture.get('readiness_profile') == development_profile(case)
            and fixture.get('transport_family') == 'ipv4'
            and fixture.get('icmp_policy') == ('q27-literal-quote-v1' if case['id'] == 'Q27' else 'q25-q26-q28-literal-quote-v1')
            and fixture.get('canonical_campaign_acceptance') is False
            and fixture.get('engine_constructed') is False and fixture.get('raw_socket_closed') is True
            and fixture.get('icmp_send_attempted') is True and fixture.get('icmp_send_completed') is True
            and fixture.get('icmp_failed') is False and fixture.get('thread_alive') is False
            and fixture.get('errors') == [] and fixture.get('certificate_selection') is None
            and fixture.get('terminated') is None and fixture.get('private_material_included') is False,
            'ICMP fixture lacks a completed engine-free, closed, exact-profile occurrence')
    require(all(fixture.get(key) is False for key in ('authenticated','request_fin','echo_fin_enqueued'))
            and all(json_integer(fixture,key) == 0 for key in
                    ('request_bytes','echo_enqueued_bytes','tx_datagrams','tx_bytes')),
            'ICMP fixture used an engine, application or UDP output')
    interface = fixture.get('icmp_interface')
    require(isinstance(interface,str) and re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',interface),
            'ICMP exact interface name absent')
    def octets(row,key,maximum):
        text = row.get(key)
        require(isinstance(text,str) and 0 < len(text) <= maximum*2
                and len(text)%2 == 0 and re.fullmatch('[0-9a-f]+',text), 'ICMP canonical bounded hex absent: '+key)
        return bytes.fromhex(text)
    def checksum(data):
        if len(data)%2: data += b'\0'
        total = sum(struct.unpack('!'+str(len(data)//2)+'H',data))
        while total >> 16: total = (total & 65535)+(total >> 16)
        return (~total)&65535
    def mac(key):
        value = fixture.get(key)
        require(isinstance(value,str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',value),
                'ICMP exact MAC absent')
        result = bytes.fromhex(value.replace(':',''))
        require(result != b'\0'*6 and not result[0]&1, 'ICMP nonzero unicast MAC required')
        return result
    gm,pm = mac('icmp_guest_mac'),mac('icmp_peer_mac')
    require(gm != pm, 'ICMP endpoint MACs coincide')
    def original(frame):
        require(len(frame) == 1242 and frame[:14] == pm+gm+b'\x08\x00', 'ICMP original Ethernet frame differs')
        ip = frame[14:]
        require(ip[0] == 0x45 and int.from_bytes(ip[2:4],'big') == 1228
                and ip[6:8] == b'\x40\x00' and ip[8] > 0 and ip[9] == 17
                and ip[12:20] == socket.inet_aton('10.0.2.15')+socket.inet_aton('10.0.2.2')
                and checksum(ip[:20]) == 0 and ip[1]&3 == 0, 'ICMP original IPv4 header differs')
        udp = ip[20:]
        require(struct.unpack('!HHH',udp[:6]) == (case['local_port'],4443,1208)
                and udp[6:8] != b'\0\0'
                and checksum(ip[12:20]+b'\0\x11'+udp[4:6]+udp) == 0,
                'ICMP original UDP header/checksum differs')
        data = udp[8:]
        require(data[0]&0xf0 == 0xc0 and data[1:5] == b'\0\0\0\x01', 'ICMP original is not a QUICv1 Initial')
        return data
    events = fixture.get('events')
    allowed = {'udp-receive','icmp-frame-receive','initial-observed','icmp-input',
               'icmp-send-begin','icmp-send','peer-ended'}
    require(isinstance(events,list) and 0 < len(events) <= 4096
            and all(isinstance(row,dict) and row.get('event') in allowed for row in events),
            'ICMP complete event census differs')
    times = [json_integer(row,'monotonic_ns') for row in events]
    require(all(a <= b for a,b in zip(times,times[1:])), 'ICMP host event clocks rewind')
    for row in events: json_integer(row,'wall_time_ns')
    rows = lambda name:[(i,row) for i,row in enumerate(events) if row['event'] == name]
    received,raw = rows('udp-receive'),rows('icmp-frame-receive')
    require(0 < len(received) <= 256 and 0 < len(raw) <= 512
            and [json_integer(row,'receive_ordinal') for _,row in received] == list(range(1,len(received)+1))
            and [json_integer(row,'raw_frame_ordinal') for _,row in raw] == list(range(1,len(raw)+1))
            and json_integer(fixture,'rx_datagrams') == len(received)
            and json_integer(fixture,'rx_bytes') == 1200*len(received)
            and json_integer(fixture,'raw_rx_frames') == len(raw)
            and json_integer(fixture,'raw_rx_bytes') == sum(json_integer(row,'bytes') for _,row in raw),
            'ICMP raw/socket ordinal or byte census differs')
    socket_keys = ('receive_ordinal','bytes','sha256','data_hex','source','destination')
    for _,row in received:
        data = octets(row,'data_hex',1200)
        require(len(data) == json_integer(row,'bytes') == 1200
                and hashlib.sha256(data).hexdigest() == row.get('sha256')
                and data[0]&0xf0 == 0xc0 and data[1:5] == b'\0\0\0\x01'
                and row.get('source') == ['10.0.2.15',case['local_port']]
                and row.get('destination') == ['10.0.2.2',4443]
                and row.get('engine_delivered') is False, 'ICMP actual socket Initial differs')
    inputs,initial,begun,sent,ended = (rows(name) for name in
            ('icmp-input','initial-observed','icmp-send-begin','icmp-send','peer-ended'))
    require(len(inputs) == len(received) and len(initial) == len(begun) == len(sent) == len(ended) == 1
            and ended[0][0] == len(events)-1 and ended[0][1].get('stopped') is True
            and ended[0][1].get('deadline_reached') is False,
            'ICMP one-shot action or actual peer termination absent')
    for (ri,rx),(ii,item) in zip(received,inputs):
        require(ri < ii and {k:rx[k] for k in socket_keys} == {k:item.get(k) for k in socket_keys}
                and item.get('engine_delivered') is False, 'ICMP input lacks exact socket receipt')
    trigger,result = fixture.get('icmp_trigger'),fixture.get('icmp_send_result')
    require(isinstance(trigger,dict) and isinstance(result,dict), 'ICMP actual trigger/result absent')
    require(set(trigger) == set(socket_keys)|{'raw_frame_ordinal','submitted_frame_sha256','frame_hex','quote_hex'}
            and set(result) == {'bytes','actual_sent_bytes','sha256','frame_hex','icmp_hex','mtu','quote_hex',
                               'submitted_frame_sha256','trigger_receive_ordinal','trigger_raw_frame_ordinal','trigger_sha256'},
            'ICMP trigger or result schema differs')
    require({k:trigger.get(k) for k in socket_keys} == {k:received[0][1][k] for k in socket_keys}
            and {k:initial[0][1].get(k) for k in socket_keys} == {k:trigger[k] for k in socket_keys}
            and received[0][0] < initial[0][0] < inputs[0][0] < begun[0][0] < sent[0][0],
            'ICMP first parsed Initial/action order differs')
    frame = octets(result,'frame_hex',70)
    quoted = octets(trigger,'frame_hex',1242)
    data = original(quoted)
    require(data.hex() == trigger['data_hex'] and len(frame) == json_integer(result,'bytes') ==
            json_integer(result,'actual_sent_bytes') == 70
            and frame[:14] == gm+pm+b'\x08\x00'
            and hashlib.sha256(frame).hexdigest() == result.get('sha256')
            and hashlib.sha256(quoted).hexdigest() == trigger.get('submitted_frame_sha256'),
            'ICMP actual frame/body identity differs')
    ip,icmp = frame[14:34],frame[34:]
    require(ip[0] == 0x45 and ip[2:4] == b'\0\x38' and ip[8] > 0 and ip[9] == 1
            and int.from_bytes(ip[6:8],'big')&0xbfff == 0 and checksum(ip) == checksum(icmp) == 0
            and ip[12:20] == socket.inet_aton('10.0.2.2')+socket.inet_aton('10.0.2.15')
            and icmp[:2] == b'\x03\x04' and icmp[4:6] == b'\0\0'
            and int.from_bytes(icmp[6:8],'big') == json_integer(result,'mtu') == case['icmp_mtu']
            and icmp[8:] == quoted[14:42] and result.get('icmp_hex') == icmp.hex()
            and result.get('quote_hex') == trigger.get('quote_hex') == quoted[14:42].hex(),
            'ICMP exact checksummed fragmentation-needed literal quote differs')
    require(result.get('submitted_frame_sha256') == trigger['submitted_frame_sha256']
            and json_integer(result,'trigger_receive_ordinal') == json_integer(trigger,'receive_ordinal') == 1
            and json_integer(result,'trigger_raw_frame_ordinal') == json_integer(trigger,'raw_frame_ordinal')
            and result.get('trigger_sha256') == trigger['sha256']
            and {k:begun[0][1].get(k) for k in result if k != 'actual_sent_bytes'} ==
                {k:v for k,v in result.items() if k != 'actual_sent_bytes'}
            and all(sent[0][1].get(k) == v for k,v in result.items()),
            'ICMP top-level result and actual single send events disagree')
    guest_raw = []
    for i,row in raw:
        raw_frame = octets(row,'frame_hex',1514)
        require(len(raw_frame) == json_integer(row,'bytes')
                and hashlib.sha256(raw_frame).hexdigest() == row.get('sha256')
                and row.get('interface') == interface and json_integer(row,'packet_type') <= 255,
                'ICMP raw receive identity differs')
        if raw_frame == frame:
            require(i > sent[0][0], 'ICMP local outgoing copy predates actual send')
        else:
            payload = original(raw_frame)
            guest_raw.append((i,row,payload))
    require(len(guest_raw) == len(received)
            and [payload.hex() for _,_,payload in guest_raw] == [row['data_hex'] for _,row in received]
            and guest_raw[0][0] < begun[0][0]
            and guest_raw[0][1]['raw_frame_ordinal'] == trigger['raw_frame_ordinal']
            and guest_raw[0][1]['frame_hex'] == trigger['frame_hex'],
            'ICMP complete original raw-frame/socket correspondence differs')
    if wire is not None:
        packets,advice = wire['guest_udp'],wire['icmp']
        require(len(packets) == len(received) and not wire['peer_udp'] and len(advice) == 1
                and wire.get('unexpected_frames') == 0
                and json_integer(wire,'guest_udp_count') == len(packets)
                and json_integer(wire,'guest_udp_bytes') == 1200*len(packets)
                and [row['frame_sha256'] for row in packets] == [row['sha256'] for _,row,_ in guest_raw]
                and [(row['bytes'],row['sha256'],row['data_hex'],row['source'],row['destination']) for row in packets] ==
                    [(row['bytes'],row['sha256'],row['data_hex'],row['source'],row['destination']) for _,row in received],
                'ICMP full capture/raw/socket census differs')
        observed = advice[0]
        require(observed.get('frame_hex') == result['frame_hex']
                and observed.get('frame_sha256') == result['sha256']
                and observed.get('icmp_hex') == result['icmp_hex']
                and observed.get('quote_hex') == result['quote_hex']
                and observed.get('submitted_frame_sha256') == trigger['submitted_frame_sha256']
                and json_integer(observed,'mtu') == case['icmp_mtu']
                and observed.get('icmp_checksum_valid') is True
                and json_integer(observed,'quoted_frame_ordinal') == json_integer(packets[0],'ordinal')
                and json_integer(packets[0],'ordinal') < json_integer(observed,'ordinal'),
                'ICMP exact captured quote/trigger/action correspondence differs')
    return {'trigger_sha256':trigger['sha256'],'submitted_frame_sha256':trigger['submitted_frame_sha256'],
            'icmp_frame_sha256':result['sha256'],'mtu':case['icmp_mtu'],
            'limit':'Full fixture identity is independent of native advisory header-key correlation; no shared clock or authenticated ICMP origin is claimed.'}


def verify_stream_limit(fixture, wire=None, client_datagrams=None):
    """One bound 1-RTT MAX_STREAM_DATA input after the actual handshake.

    Frame construction is observed in the pinned peer hook. Native local
    transport code 4 supplies the runtime refusal witness, not a peer label.
    No secret/decryption record or generalized stream-state proof is claimed.
    """
    require((wire is None) != (client_datagrams is None),
            'Q15 capture or actual Linux consumed-input witness required')
    events = fixture['events']
    marks = [(i, row) for i, row in enumerate(events) if row['event'] == 'stream-limit-frame-built']
    tagged = [(i, row) for i, row in enumerate(events)
              if row['event'] == 'udp-send' and row.get('fixture') == 'stream-limit']
    require(fixture.get('mode') == 'stream-limit'
            and fixture.get('readiness_profile') == 'q15-stream-limit-development'
            and fixture['authenticated'] is True and len(marks) == len(tagged) == 1,
            'NOT_ESTABLISHED: Q15 selected authenticated frame absent')
    pos, mark = marks[0]
    send_pos, sent = tagged[0]
    require(any(i < pos and row['event'] == 'handshake' for i, row in enumerate(events))
            and any(i < pos and row['event'] == 'request-stream' and row['stream_id'] == 0
                    and row['bytes'] > 0 for i, row in enumerate(events)),
            'Q15 frame did not follow the actual handshake and request')
    require(mark['frame_type'] == 17 and mark['stream_id'] == 1 and mark['maximum'] == 8192
            and mark['native_peer_bidi_limit'] == 0 and mark['handshake_complete'] is True
            and mark['handshake_confirmed'] is True
            and 0 < mark['request_bytes'] <= fixture['request_bytes'] <= 4096
            and isinstance(mark['packet_number'], int) and mark['packet_number'] >= 0
            and pos < send_pos and 0 < mark['bytes'] == sent['bytes'] <= 1200
            and mark['sha256'] == sent['sha256'], 'Q15 frame identity or encrypted output binding differs')
    sends = [row for row in events if row['event'] == 'udp-send']
    receives = [row for row in events if row['event'] == 'udp-receive']
    require(mark['send_ordinal_next'] == sends.index(sent) + 1
            and fixture['tx_datagrams'] == len(sends) and fixture['rx_datagrams'] == len(receives)
            and fixture['tx_bytes'] == sum(row['bytes'] for row in sends)
            and fixture['rx_bytes'] == sum(row['bytes'] for row in receives)
            and fixture['request_sha256'] == hashlib.sha256(
                bytes(97 + offset % 26 for offset in range(fixture['request_bytes']))).hexdigest()
            and fixture['echo_enqueued_bytes'] == 0 and not fixture['echo_fin_enqueued'],
            'Q15 complete socket census or no-echo fixture differs')
    if wire is not None:
        for rows, packets, keys in [(sends, wire['peer_udp'], ('bytes','sha256','source','destination')),
                                    (receives, wire['guest_udp'], ('bytes','sha256','source'))]:
            require([{key: row[key] for key in keys} for row in rows]
                    == [{key: row[key] for key in keys} for row in packets],
                    'Q15 ordered socket/capture correspondence differs')
        matched = [row for row in wire['peer_udp'] if row['sha256'] == mark['sha256']]
        require(len(matched) == 1 and matched[0]['first_byte'] & 0xc0 == 0x40,
                'Q15 selected 1-RTT output absent or duplicated in capture')
    if client_datagrams is not None:
        require([row['ordinal'] for row in client_datagrams] == list(range(1, len(client_datagrams) + 1))
                and all(row['engine_delivered'] is True for row in client_datagrams)
                and [{key: row[key] for key in ('bytes','sha256','source')} for row in client_datagrams]
                == [{key: row[key] for key in ('bytes','sha256','source')}
                    for row in sends[:len(client_datagrams)]],
                'Q15 ordered Linux socket/engine input correspondence differs')
        matched = [row for row in client_datagrams if row['sha256'] == mark['sha256']]
        require(len(matched) == 1 and matched[0]['bytes'] == mark['bytes']
                and matched[0]['engine_delivered'] is True and matched[0]['authenticated_before'] is True,
                'Q15 Linux selected input was not delivered after authentication')
    return mark


def verify_ipv4_denied_peer(case, fixture, wire):
    """A passive socket is only a zero-input witness, never native denial."""
    require(case['id'] == 'Q17' and development_profile(case) == 'q17-denied-destination-development',
            'explicit IPv4 Q17 required')
    require(fixture.get('case') == 'Q17' and fixture.get('mode') == 'denied-destination'
            and fixture.get('transport_family') == 'ipv4'
            and fixture.get('denied_policy') == 'q17-ipv4-denied-destination-v1'
            and fixture.get('readiness_profile') == 'q17-denied-destination-development'
            and fixture.get('canonical_campaign_acceptance') is False
            and fixture.get('engine_constructed') is False and fixture.get('certificate_selection') is None
            and not fixture['errors'] and not fixture['thread_alive']
            and not fixture['authenticated'] and not fixture['request_fin'] and not fixture['echo_fin_enqueued']
            and fixture.get('terminated') is None and fixture.get('private_material_included') is False,
            'IPv4 Q17 passive peer state differs')
    require(all(json_integer(fixture, key) == 0 for key in ('rx_datagrams', 'tx_datagrams', 'rx_bytes',
                'tx_bytes', 'request_bytes', 'echo_enqueued_bytes', 'passive_receive_count'))
            and not wire['guest_udp'] and not wire['peer_udp']
            and 'family' not in wire and 'scope' not in wire
            and not wire.get('unauthorized_peer_udp')
            and json_integer(wire, 'udp_count') == json_integer(wire, 'guest_udp_count') ==
                json_integer(wire, 'guest_udp_bytes') == json_integer(wire, 'unexpected_frames') == 0,
            'IPv4 Q17 had actual UDP or application input/output')
    events = fixture['events']
    require(len(events) == 1 and events[0].get('event') == 'peer-ended'
            and events[0].get('stopped') is True and events[0].get('deadline_reached') is False,
            'IPv4 Q17 peer did not stop normally without input')


def verify_native_ipv4_denied(case, output, report, fixture, wire):
    verify_ipv4_denied_peer(case, fixture, wire)
    lines = output.splitlines()
    def one(prefix):
        rows = [(i, fields(row)) for i, row in enumerate(lines) if row.startswith(prefix + ' ')]
        require(len(rows) == 1 and rows[0][1].get('case') == 'Q17',
                'IPv4 Q17 requires one exact record: ' + prefix)
        return rows[0]
    gi, grant = one('QUIC SERVICE GRANT')
    si, send = one('QUIC FIXTURE SEND')
    ci, counts = one('QUIC FIXTURE NATIVE_COUNTS')
    ri, retired = one('QUIC CHILD AUTHORITY RETIRED')
    ei, exited = one('QUIC CHILD EXIT')
    bi, begin = one('QUIC BEGIN')
    ti, typed = one('QUIC RESULT')
    fi, final = one('QUIC SERVICE RETIRE')
    di, done = one('QUIC SERVICE DONE')
    opened = [i for i, row in enumerate(lines) if row == 'QUIC CONSUMER case=Q17 begin']
    closed = [i for i, row in enumerate(lines) if row == 'QUIC CONSUMER case=Q17 end']
    require(typed == report and len(opened) == len(closed) == 1
            and gi < si < ci < ri < ei < opened[0] < bi < ti < closed[0] < fi < di
            and not any(row.startswith(('QUIC FIXTURE RX ', 'QUIC CHILD INTERRUPT ',
                'QUIC SERVICE GRANT EXPIRED ', 'QUIC CONSUMER PARTIAL ', 'QUIC TRANSPORT ',
                'QUIC SERVICE FAMILY ')) for row in lines), 'IPv4 Q17 publication or family differs')
    start, deadline, expiry = (number(begin, key) for key in ('start_ms', 'deadline_ms', 'grant_expiry_ms'))
    end, reaped, retired_at = number(report, 'end_ms'), number(retired, 'reaped_ms'), number(retired, 'retired_ms')
    require(number(grant, 'local_port') == 7816 and number(grant, 'peer_port') == 4443
            and number(grant, 'before_ms') <= number(grant, 'constructed_ms') <= start < deadline
            and expiry == number(grant, 'before_ms') + 15000 == number(grant, 'owner_expiry_ms')
            and deadline == min(start + 10000, expiry) == number(report, 'deadline_ms')
            and number(report, 'start_ms') == start and number(report, 'grant_expiry_ms') == expiry
            and re.fullmatch(r'Some\([1-9][0-9]*\)', begin.get('unix_time', ''))
            and boolean(begin, 'native_pair') and not boolean(report, 'no_native_pair')
            and start <= number(report, 'last_send_ms') <= number(send, 'at_ms') <= number(report, 'fence_ms')
                <= end <= reaped <= retired_at < deadline
            and number(report, 'fence_ms') <= number(counts, 'at_ms') <= retired_at,
            'IPv4 Q17 original grant, attempted SEND or fence clocks differ')
    require(report['outcome'] == report['native_failure_kind'] == 'Native'
            and report['native_error_code'] == '2' and report['phase'] == 'Fenced'
            and report['native_error_detail'] == report['transport_error_code'] == report['transport_close_origin'] == 'none'
            and boolean(report, 'pipe_fenced') and not boolean(report, 'unknown_send')
            and number(report, 'send_calls') == number(counts, 'send_requests') == 1,
            'IPv4 Q17 actual typed Denied/fence or one attempted operation absent')
    require(number(send, 'ordinal') == 1 and number(send, 'bytes') == len(b'ABSD_QUIC_DENIED')
            and send.get('sha256') == hashlib.sha256(b'ABSD_QUIC_DENIED').hexdigest()
            and send.get('peer_ip') == '10.0.2.2' and number(send, 'peer_port') == 4444
            and 'family' not in send and 'scope' not in send,
            'IPv4 Q17 attempted destination or complete request body differs')
    require(all(number(report, key) == 0 for key in ('send_accepted', 'send_bytes', 'receive_calls', 'received',
                'receive_bytes', 'engine_transmits', 'endpoint_responses_discarded', 'entropy_attempts',
                'unexpected_rng_draws', 'sent_stream', 'received_stream', 'close_calls', 'sends_after_fence',
                'queue_fills', 'queue_retry_accepted', 'exhausted'))
            and all(not boolean(report, key) for key in ('authenticated', 'request_fin', 'peer_fin',
                'request_acked', 'connection_drained', 'close_accepted'))
            and report['pending_exhausted_sha256'] == report['pending_retry_sha256'] == 'none'
            and all(number(counts, key) == 0 for key in ('receive_delivered', 'sends_after_owner_expiry',
                'partial_request_bytes', 'partial_reply_bytes')),
            'IPv4 Q17 progressed beyond one pre-engine denied SEND')
    phases = [(i, fields(row)) for i, row in enumerate(lines) if row.startswith('QUIC PHASE ')]
    require([row.get('phase') for _, row in phases] == ['Init', 'Fenced']
            and all(row.get('case') == 'Q17' and bi < i < ti and start <= number(row, 'at_ms') <= end
                    for i, row in phases)
            and number(phases[0][1], 'at_ms') <= number(phases[1][1], 'at_ms'),
            'IPv4 Q17 actual pre-engine phases differ')
    require(number(exited, 'kind') == 1 and number(exited, 'status') == 0 and not boolean(exited, 'killed')
            and boolean(retired, 'result_eof') and all(not boolean(retired, key) for key in
                ('process_handle_live', 'pipe_live', 'grant_live', 'owner_expired'))
            and number(retired, 'sockets') == number(final, 'sockets_before_fence') ==
                number(final, 'sockets_after_fence') == number(done, 'sockets') == 0,
            'IPv4 Q17 normal reap, true EOF or authority retirement absent')
    for key in ('processes', 'handles', 'pipes', 'cells'):
        require(number(done, key + '_before') == number(done, key + '_after'),
                'IPv4 Q17 parent object not restored: ' + key)
    return {'native_error_code':2, 'attempted_port':4444, 'allowed_port':4443,
            'complete_send_requests':1, 'result_eof':True, 'reaped_ms':reaped, 'retired_ms':retired_at,
            'limit':'One software grant denial and local retirement; no network echo, hardware transfer or full-memory claim.'}


def verify_fixture(case, fixture, wire, family="ipv4", reorder_stage='initial'):
    require(not fixture['errors'] and not fixture['thread_alive'], 'independent peer failed or remains live')
    require(fixture.get('readiness_profile') == development_profile(case, family)
            and fixture.get('canonical_campaign_acceptance') is False, 'limited peer profile differs')
    events = fixture['events']
    if family == 'ipv4' and case['id'] == 'Q17':
        verify_ipv4_denied_peer(case, fixture, wire)
        return
    if family == 'ipv6':
        require(fixture.get('transport_family') == 'ipv6' and wire.get('family') == 6 and wire.get('scope') == 1,
                'actual IPv6 fixture/wire family differs')
        if case['id'] == 'Q17':
            require(fixture['rx_datagrams'] == fixture['tx_datagrams'] == fixture['rx_bytes'] == fixture['tx_bytes'] == 0
                    and not fixture['authenticated'] and fixture['request_bytes'] == fixture['echo_enqueued_bytes'] == 0
                    and not fixture['request_fin'] and not fixture['echo_fin_enqueued']
                    and not wire['guest_udp'] and not wire['peer_udp'] and not wire['nd']
                    and all(row['event'] not in ('udp-send', 'udp-receive', 'initial-observed', 'certificate-selection') for row in events),
                    'native denied destination reached the peer or caused UDP/ND')
            return
        if case['id'] == 'Q08':
            verify_ipv6_response_flight(fixture)
        for event, packets, keys in [('udp-send', wire['peer_udp'], ('bytes', 'sha256', 'source', 'destination')),
                                      ('udp-receive', wire['guest_udp'], ('bytes', 'sha256', 'source'))]:
            observed = [row for row in events if row['event'] == event]
            require([{key: row[key] for key in keys} for row in observed] ==
                    [{key: row[key] for key in keys} for row in packets],
                    'complete IPv6 peer socket/capture datagram correspondence differs: ' + event)
    elif case['id'] == 'Q08':
        verify_q08_response_flight(fixture)
    elif case['id'] in ('Q09', 'Q10', 'Q11'):
        verify_auth_response_flight(case, fixture)
    mode = case.get('peer_mode','absent-rdrand')
    if case['id'] in ('Q21', 'Q22'):
        verify_interruption_peer(case, fixture, wire)
        return
    if case['id'] in ('Q23', 'Q29', 'Q30', 'Q31'):
        verify_authority_peer(case, fixture, wire)
        return
    if case['id'] == 'Q24':
        verify_link_peer(case, fixture, wire)
        return
    if case['id'] in ('Q25', 'Q26', 'Q27', 'Q28'):
        verify_icmp_peer(case, fixture, wire)
        return
    def event(kind):
        values = [row for row in events if row['event'] == kind]
        require(values, 'NOT_ESTABLISHED: independent fixture event missing: ' + kind)
        return values
    for sent in [row for row in events if row['event'] == 'udp-send']:
        require(any(row['sha256'] == sent['sha256'] and row['source'] == sent['source'] and
                    row['destination'] == sent['destination'] for row in wire['peer_udp']),
                'NOT_ESTABLISHED: independent UDP send absent from actual capture')
    if mode == 'truncated-header':
        verify_truncated_header(case, fixture, wire)
    elif mode == 'queue-exhausted':
        verify_queue_prelude(fixture, wire)
    elif mode == 'initial-loss':
        drop, accept = verify_initial_loss(fixture)
        lost = [row for row in wire['guest_udp'] if row['sha256'] == drop['sha256']]
        retried = [row for row in wire['guest_udp'] if row['sha256'] == accept['sha256']]
        require(lost and retried and wire['guest_udp_count'] >= 2
                and lost[0]['ordinal'] < retried[-1]['ordinal']
                and all(row['bytes'] == 1200 and row['first_byte'] & 0xf0 == 0xc0
                        for row in (lost[0], retried[-1])),
                'dropped Initial and subsequent Initial absent or out of order on wire')
    elif mode == 'stream-loss':
        verify_stream_loss(fixture, wire)
    elif mode == 'duplicate-reorder':
        verify_duplicate_reorder(case, fixture, wire, reorder_stage=reorder_stage)
    elif mode == 'flow-pause':
        verify_flow_pause(case, fixture, wire)
    elif mode == 'silent':
        verify_silent(fixture, wire)
    elif mode == 'unknown-cid':
        verify_unknown_cid(fixture, wire)
    elif mode == 'unauthorized-source':
        verify_unauthorized_source(fixture, wire)
    elif mode == 'invalid-tag':
        verify_invalid_tag(case, fixture, wire=wire)
    elif mode == 'long-retry':
        verify_long_retry(fixture, wire)
    elif mode == 'stream-limit':
        verify_stream_limit(fixture, wire=wire)
    if case['id'] in ('Q01', 'Q02', 'Q03', 'Q04', 'Q05', 'Q06', 'Q08', 'Q09', 'Q10', 'Q11', 'Q12', 'Q13', 'Q15', 'Q16', 'Q18', 'Q19'):
        require(case['expected_outcome'] != 'Complete' or fixture.get('terminated') is None or fixture['terminated']['error_code'] == 0,
                'Q01 independent peer terminated with nonzero error')
        sent = [row for row in events if row['event'] == 'udp-send']
        received = [row for row in events if row['event'] == 'udp-receive']
        require(sent and received and fixture['tx_datagrams'] == len(sent)
                and fixture['rx_datagrams'] == len(received)
                and fixture['tx_bytes'] == sum(row['bytes'] for row in sent)
                and fixture['rx_bytes'] == sum(row['bytes'] for row in received),
                'Q01 complete independent peer datagram census differs')
    if case['id'] in ('Q08','Q09','Q10','Q11'):
        require(isinstance(fixture.get('certificate_selection'), dict)
                and fixture['certificate_selection'].get('kind') == {'Q08':'untrusted','Q09':'wrong-name','Q10':'expired','Q11':'valid'}[case['id']]
                and not fixture['authenticated'] and fixture['request_bytes'] == 0
                and fixture['echo_enqueued_bytes'] == 0 and not fixture['request_fin']
                and not fixture['echo_fin_enqueued']
                and (fixture.get('terminated') is None or fixture['terminated']['error_code'] in case['transport_error_codes']),
                'wrong-root peer selection/no-application/terminal predicate differs')
    if case['id'] == 'Q11':
        require(fixture['certificate_selection'].get('configured_alpn') == ['other-echo/1'],
                'wrong-ALPN fixture was not established')
    if case['expected_outcome'] == 'Complete':
        body_hash = hashlib.sha256(bytes(97 + i % 26 for i in range(4096))).hexdigest()
        require(fixture['authenticated'] and fixture['request_bytes'] == fixture['echo_enqueued_bytes'] == 4096 and
                fixture['request_sha256'] == body_hash and fixture['request_fin'] and fixture['echo_fin_enqueued'],
                'independent authenticated4096-byte request/echo/FIN absent')


def verify_transport_close_origin(case, report):
    """Bind a transport code to the ConnectionError variant that supplied it."""
    origin = report.get('transport_close_origin')
    require(origin in ('none', 'local', 'peer'), 'transport close origin missing or invalid')
    code = report.get('transport_error_code')
    require((code == 'none') == (origin == 'none'), 'transport close code/origin pair differs')
    if code != 'none':
        number(report, 'transport_error_code')
    if case['expected_outcome'] == 'Complete':
        require(code == origin == 'none', 'Complete has a transport close cause')
    if case['id'] in ('Q08', 'Q09', 'Q10', 'Q11'):
        require(origin == ('peer' if case['id'] == 'Q11' else 'local'),
                'selected authentication refusal has a different transport close origin')


def verify_native_interruption(case, output, fixture, wire, cpu):
    """Bind the interrupted consumer to parent-owned reap and retirement."""
    require(case['id'] in ('Q21', 'Q22'), 'unsupported native interruption case')
    development_profile(case)
    lines = output.splitlines()
    def one(prefix):
        found = [(i, fields(line)) for i, line in enumerate(lines) if line.startswith(prefix + ' ')]
        require(len(found) == 1 and found[0][1].get('case') == case['id'],
                'interruption requires one exact record: ' + prefix)
        return found[0]
    gi, grant = one('QUIC SERVICE GRANT')
    bi, begin = one('QUIC BEGIN')
    oi, observed = one('QUIC CHILD INTERRUPT OBSERVED')
    qi, requested = one('QUIC CHILD INTERRUPT REQUEST')
    ki, returned = one('QUIC CHILD INTERRUPT RETURN')
    ri, retired = one('QUIC CHILD INTERRUPT RETIRED')
    ei, exited = one('QUIC CHILD EXIT')
    ci, counts = one('QUIC FIXTURE NATIVE_COUNTS')
    fi, final = one('QUIC SERVICE RETIRE')
    di, done = one('QUIC SERVICE DONE')
    opened = [i for i, line in enumerate(lines) if line == 'QUIC CONSUMER case=' + case['id'] + ' begin']
    closed = [i for i, line in enumerate(lines) if line == 'QUIC CONSUMER case=' + case['id'] + ' end']
    require(len(opened) == len(closed) == 1
            and gi < oi < qi < ki < ri < ei < opened[0] < bi < closed[0] < fi < di
            and ki < ci < ri,
            'interruption parent lifecycle or buffered publication order differs')
    require(not any(line.startswith(('QUIC RESULT ', 'QUIC CONSUMER PARTIAL ')) for line in lines),
            'interruption cannot substitute a normal result or partial publication')
    start, deadline, expiry = (number(begin, key) for key in ('start_ms', 'deadline_ms', 'grant_expiry_ms'))
    observed_at, requested_at, returned_at = (number(row, key) for row, key in
        ((observed, 'observed_ms'), (requested, 'requested_ms'), (returned, 'end_ms')))
    reaped_at, retired_at = (number(retired, key) for key in ('reaped_ms', 'retired_ms'))
    require(number(grant, 'before_ms') <= number(grant, 'constructed_ms') <= start
            and number(grant, 'owner_expiry_ms') == expiry == number(grant, 'before_ms') + 15000
            and start < deadline == min(start + 10000, expiry)
            and start <= observed_at <= requested_at <= returned_at <= reaped_at <= retired_at < deadline,
            'interruption original grant, operation or retirement lifetime differs')
    require(observed.get('phase') == case['interrupt_phase']
            and number(observed, 'delay_ms') == case['interrupt_delay_ms']
            and number(requested, 'observed_ms') == observed_at
            and requested_at >= observed_at + case['interrupt_delay_ms']
            and number(returned, 'result') == 0
            and number(exited, 'kind') == 3 and number(exited, 'status') == 0
            and boolean(exited, 'killed'),
            'NOT_ESTABLISHED: exact phase interruption and killed-child reap absent')
    require(all(not boolean(retired, key) for key in ('process_handle_live', 'pipe_live', 'grant_live'))
            and boolean(retired, 'result_eof') and number(retired, 'sockets') == 0
            and number(final, 'sockets_before_fence') == number(final, 'sockets_after_fence') == number(done, 'sockets') == 0,
            'interruption process, pipe End or grant retirement absent')
    phases = [(i, fields(line)) for i, line in enumerate(lines) if line.startswith('QUIC PHASE ')]
    require(phases and all(row.get('case') == case['id'] and opened[0] < i < closed[0]
                          and start <= number(row, 'at_ms') <= requested_at for i, row in phases),
            'interruption actual buffered phase identity or time differs')
    require(all(number(a, 'at_ms') <= number(b, 'at_ms')
                for (_, a), (_, b) in zip(phases, phases[1:])),
            'interruption buffered phase clock moved backwards')
    targets = [(i, row) for i, row in phases if row.get('phase') == case['interrupt_phase']]
    require(len(targets) == 1 and number(targets[0][1], 'at_ms') <= observed_at
            and not any(row.get('phase') in ('Closing', 'Fenced') for _, row in phases),
            'NOT_ESTABLISHED: active selected phase was not established before interruption')
    if case['id'] == 'Q21':
        require(not any(row.get('phase') in ('Authenticated', 'Stream') for _, row in phases),
                'Q21 interruption passed the handshake boundary')
    else:
        authenticated = [(i, row) for i, row in phases if row.get('phase') == 'Authenticated']
        require(len(authenticated) == 1 and authenticated[0][0] < targets[0][0]
                and number(authenticated[0][1], 'at_ms') <= number(targets[0][1], 'at_ms'),
                'Q22 actual authenticated stream phase absent')
    require(reaped_at <= number(counts, 'at_ms') <= retired_at
            and number(counts, 'sends_after_owner_expiry') == 0
            and number(counts, 'partial_request_bytes') < 1486
            and number(counts, 'partial_reply_bytes') < 1486,
            'interruption complete native framing retirement differs')
    def ledger(prefix, count_name):
        rows = [(i, fields(line)) for i, line in enumerate(lines) if line.startswith(prefix + ' ')]
        require(len(rows) == number(counts, count_name)
                and [number(row, 'ordinal') for _, row in rows] == list(range(1, len(rows) + 1)),
                'interruption complete native ledger census differs: ' + prefix)
        for index, row in rows:
            require(index < ci and row.get('case') == case['id']
                    and start <= number(row, 'at_ms') <= number(counts, 'at_ms') <= retired_at
                    and 0 < number(row, 'bytes') <= 1472
                    and row.get('peer_ip') == '10.0.2.2' and number(row, 'peer_port') == 4443
                    and isinstance(row.get('sha256'), str) and re.fullmatch('[0-9a-f]{64}', row['sha256']),
                    'interruption native input/request lacks exact identity or crossed retirement')
        return [row for _, row in rows]
    sends = ledger('QUIC FIXTURE SEND', 'send_requests')
    received = ledger('QUIC FIXTURE RX', 'receive_delivered')
    require(0 < len(sends) <= 4096 and len(received) <= 256 and wire['guest_udp'],
            'NOT_ESTABLISHED: interrupted consumer has no actual native output')
    require(case['id'] != 'Q22' or received,
            'NOT_ESTABLISHED: Q22 authentication has no complete native RECEIVE')
    def ordered_subset(actual, available, label):
        cursor = 0
        for identity in actual:
            while cursor < len(available) and available[cursor] != identity:
                cursor += 1
            require(cursor < len(available), 'interruption ordered packet correspondence differs: ' + label)
            cursor += 1
    # Requested SEND is not a wire receipt. Revocation can discard an earlier
    # queued output; retain the whole request and capture ledgers separately.
    ordered_subset([(json_integer(row, 'bytes'), row['sha256']) for row in wire['guest_udp']],
                   [(number(row, 'bytes'), row['sha256']) for row in sends],
                   'captured output versus complete SEND requests')
    ordered_subset([(number(row, 'bytes'), row['sha256']) for row in received],
                   [(json_integer(row, 'bytes'), row['sha256']) for row in wire['peer_udp']],
                   'complete pipe delivery versus captured peer output')
    for name in ('processes', 'handles', 'pipes', 'cells'):
        require(number(done, name + '_before') == number(done, name + '_after'),
                'interruption parent resource not restored: ' + name)
    return {'actual_outcome':'Interrupted', 'typed_report':None, 'measured_cpu':cpu,
            'interruption':{'phase':case['interrupt_phase'], 'observed_ms':observed_at,
                            'requested_ms':requested_at, 'returned_ms':returned_at,
                            'reaped_ms':reaped_at, 'retired_ms':retired_at, 'result_eof':True,
                            'complete_send_requests':len(sends), 'captured_guest_udp':len(wire['guest_udp']),
                            'complete_reply_deliveries':len(received), 'captured_peer_udp':len(wire['peer_udp']),
                            'partial_request_bytes_retired':number(counts, 'partial_request_bytes'),
                            'partial_reply_bytes_retired':number(counts, 'partial_reply_bytes')},
            'scope':'Exact parent-owned stop/reap and local grant retirement; earlier queued/wire effects are not retracted.'}


def verify_native_authority(case, output, report, wire):
    """Bind refusal/expiry to real child retirement and the original grant."""
    development_profile(case)
    lines = output.splitlines()
    def one(prefix):
        found = [(i, fields(line)) for i, line in enumerate(lines)
                 if line.startswith(prefix + ' ')
                 and (prefix != 'QUIC SERVICE GRANT' or 'constructed_ms' in fields(line))]
        require(len(found) == 1 and found[0][1].get('case') == case['id'],
                'authority case requires one exact record: ' + prefix)
        return found[0]
    gi, grant = one('QUIC SERVICE GRANT')
    bi, begin = one('QUIC BEGIN')
    ri, retired = one('QUIC CHILD AUTHORITY RETIRED')
    ei, exited = one('QUIC CHILD EXIT')
    ci, counts = one('QUIC FIXTURE NATIVE_COUNTS')
    ti, typed = one('QUIC RESULT')
    fi, final = one('QUIC SERVICE RETIRE')
    di, done = one('QUIC SERVICE DONE')
    opened = [i for i, row in enumerate(lines) if row == 'QUIC CONSUMER case=' + case['id'] + ' begin']
    closed = [i for i, row in enumerate(lines) if row == 'QUIC CONSUMER case=' + case['id'] + ' end']
    require(len(opened) == len(closed) == 1 and gi < ci < ri < ei < opened[0] < bi < ti < closed[0] < fi < di
            and not any(row.startswith(('QUIC CONSUMER PARTIAL ', 'QUIC CHILD INTERRUPT ')) for row in lines),
            'authority retirement or buffered child publication order differs')
    start, deadline, expiry = (number(begin, key) for key in ('start_ms', 'deadline_ms', 'grant_expiry_ms'))
    end, reaped, retired_at = number(report, 'end_ms'), number(retired, 'reaped_ms'), number(retired, 'retired_ms')
    # Q29 copies no protocol output writer. Its parent can therefore observe
    # request EOF before the child first runs; that zero-I/O census belongs
    # to the already constructed grant, not to the child's later BEGIN.
    census_start = number(grant, 'constructed_ms') if case['id'] == 'Q29' else start
    require(number(grant, 'before_ms') <= number(grant, 'constructed_ms') <= start < deadline
            and expiry == number(grant, 'before_ms') + case['grant_lifetime_ms'] == number(grant, 'owner_expiry_ms')
            and deadline == min(start + 10000, expiry) == number(report, 'deadline_ms')
            and number(report, 'start_ms') == start and number(report, 'grant_expiry_ms') == expiry
            and start <= end <= reaped <= retired_at < expiry + 2000
            and census_start <= number(counts, 'at_ms') <= retired_at,
            'authority original grant, child deadline or retirement lifetime differs')
    require(number(exited, 'kind') == 1 and number(exited, 'status') == 0 and not boolean(exited, 'killed')
            and all(not boolean(retired, key) for key in ('process_handle_live', 'pipe_live', 'grant_live'))
            and boolean(retired, 'result_eof')
            and number(retired, 'sockets') == number(final, 'sockets_before_fence') ==
                number(final, 'sockets_after_fence') == number(done, 'sockets') == 0,
            'authority normal child reap, actual EOF or local retirement absent')
    require(number(counts, 'sends_after_owner_expiry') == 0
            and number(counts, 'partial_request_bytes') < 1486 and number(counts, 'partial_reply_bytes') < 1486,
            'authority complete framing retirement differs')
    phases = [(i, fields(row)) for i, row in enumerate(lines) if row.startswith('QUIC PHASE ')]
    require(phases and all(row.get('case') == case['id'] and opened[0] < index < ti
                          and start <= number(row, 'at_ms') <= end for index, row in phases)
            and all(number(a, 'at_ms') <= number(b, 'at_ms') for (_, a), (_, b) in zip(phases, phases[1:])),
            'authority buffered phase identity or clock differs')
    def ledger(prefix, count_name):
        rows = [(i, fields(row)) for i, row in enumerate(lines) if row.startswith(prefix + ' ')]
        require(len(rows) == number(counts, count_name)
                and [number(row, 'ordinal') for _, row in rows] == list(range(1, len(rows) + 1))
                and all(index < ci and row.get('case') == case['id']
                        and start <= number(row, 'at_ms') < expiry
                        and row.get('peer_ip') == '10.0.2.2' and number(row, 'peer_port') == 4443
                        and 0 < number(row, 'bytes') <= 1472 and isinstance(row.get('sha256'), str)
                        and re.fullmatch('[0-9a-f]{64}', row['sha256']) for index, row in rows),
                'authority complete native ledger identity, census or lifetime differs: ' + prefix)
        return [row for _, row in rows]
    sends, received = ledger('QUIC FIXTURE SEND', 'send_requests'), ledger('QUIC FIXTURE RX', 'receive_delivered')
    require(not boolean(report, 'authenticated') and not boolean(report, 'request_fin')
            and not boolean(report, 'peer_fin') and not boolean(report, 'request_acked')
            and not boolean(report, 'connection_drained') and not boolean(report, 'close_accepted')
            and number(report, 'sent_stream') == number(report, 'received_stream') == number(report, 'close_calls') == 0
            and report.get('native_error_code') == report.get('transport_error_code') == report.get('transport_close_origin') == 'none',
            'authority refusal authenticated, emitted application data or hid another failure')
    expired_rows = [(i, fields(row)) for i, row in enumerate(lines) if row.startswith('QUIC SERVICE GRANT EXPIRED ')]
    if case['id'] != 'Q23':
        require(not expired_rows and not boolean(retired, 'owner_expired') and retired_at < deadline
                and not sends and not received and not wire['guest_udp'] and not wire['peer_udp']
                and number(counts, 'partial_request_bytes') == number(counts, 'partial_reply_bytes') == 0
                and all(number(report, key) == 0 for key in ('send_calls', 'send_accepted', 'send_bytes',
                    'receive_calls', 'received', 'receive_bytes', 'engine_transmits', 'entropy_attempts'))
                and not boolean(report, 'unknown_send') and report.get('native_failure_kind') == 'none'
                and report.get('native_error_detail') == 'none'
                and boolean(report, 'no_native_pair') is (case['id'] == 'Q29')
                and boolean(begin, 'native_pair') is (case['id'] == 'Q30'),
                'startup requirement refusal reached native I/O, entropy or a different startup shape')
        require((case['id'] == 'Q29' and report.get('phase') == 'Fenced'
                 and [row['phase'] for _, row in phases] == ['Fenced']
                 and re.fullmatch(r'Some\([1-9][0-9]*\)', begin.get('unix_time', '')))
                or (case['id'] == 'Q30' and report.get('phase') == 'Init'
                    and [row['phase'] for _, row in phases] == ['Init']
                    and begin.get('unix_time') == 'None' and boolean(report, 'pipe_fenced')),
                'startup requirement refusal has a different construction phase or time input')
        return {'kind':'startup-refusal', 'reaped_ms':reaped, 'retired_ms':retired_at, 'result_eof':True}
    require(len(expired_rows) == 1 and expired_rows[0][1].get('case') == 'Q23',
            'NOT_ESTABLISHED: actual owner expiry record absent')
    xi, expired = expired_rows[0]
    observed, revoked = number(expired, 'observed_ms'), number(expired, 'revoked_ms')
    require(ci < xi < ri and expiry == deadline == number(expired, 'owner_expiry_ms')
            and expiry <= observed <= revoked <= retired_at and expiry <= end
            and number(counts, 'at_ms') <= revoked and boolean(retired, 'owner_expired')
            and not boolean(expired, 'pipe_live') and not boolean(expired, 'grant_live')
            and number(expired, 'sockets') == 0,
            'NOT_ESTABLISHED: actual original owner expiry and local revocation absent')
    require(report.get('phase') == 'Fenced' and boolean(report, 'pipe_fenced')
            and not boolean(report, 'no_native_pair') and boolean(begin, 'native_pair')
            and re.fullmatch(r'Some\([1-9][0-9]*\)', begin.get('unix_time', ''))
            and [row['phase'] for _, row in phases] == ['Init', 'Handshake', 'Fenced']
            and expiry <= number(report, 'fence_ms') <= end
            and number(report, 'entropy_attempts') == 1
            and report.get('native_failure_kind') in ('Deadline', 'Unknown')
            and number(report, 'sends_after_fence') == 0
            and start <= number(report, 'last_send_ms') < expiry,
            'owner expiry has a different terminal cause, construction or fence')
    require(0 < len(sends) <= 4096 and 0 < len(received) <= 256
            and len(sends) <= number(report, 'send_calls') <= len(sends) + 1
            and 0 < number(report, 'send_accepted') <= len(sends)
            and number(report, 'send_bytes') <= sum(number(row, 'bytes') for row in sends)
            and number(report, 'received') <= len(received) <= number(report, 'received') + 1
            and number(report, 'receive_bytes') <= sum(number(row, 'bytes') for row in received),
            'owner expiry native counters exceed complete or interrupted framing')
    def ordered_subset(actual, available):
        cursor = 0
        for value in actual:
            while cursor < len(available) and available[cursor] != value: cursor += 1
            require(cursor < len(available), 'owner expiry ordered native/capture correspondence differs')
            cursor += 1
    ordered_subset([(row['bytes'], row['sha256']) for row in wire['guest_udp']],
                   [(number(row, 'bytes'), row['sha256']) for row in sends])
    ordered_subset([(number(row, 'bytes'), row['sha256']) for row in received],
                   [(row['bytes'], row['sha256']) for row in wire['peer_udp']])
    marker = b'\x00ABSD-QUIC-Q23-INITIAL-OBSERVED'
    witness = [row for row in received if row['sha256'] == hashlib.sha256(marker).hexdigest()
               and number(row, 'bytes') == len(marker)]
    require(len(witness) == 1 and start <= number(witness[0], 'at_ms') < expiry,
            'NOT_ESTABLISHED: causal Initial marker was not delivered before owner expiry')
    return {'kind':'owner-expiry', 'owner_expiry_ms':expiry, 'observed_ms':observed, 'revoked_ms':revoked,
            'reaped_ms':reaped, 'retired_ms':retired_at, 'result_eof':True,
            'marker_rx_ms':number(witness[0], 'at_ms'), 'complete_send_requests':len(sends),
            'partial_request_bytes_retired':number(counts, 'partial_request_bytes'),
            'partial_reply_bytes_retired':number(counts, 'partial_reply_bytes')}


def verify_native_entropy(case, output, report, fixture, wire):
    """Q31 reaches the actual consumer, then refuses before native I/O.

    The prepare error drops the real pipe while still in Init. It never
    constructs NativeTransport, so no Fenced callback or native fence time
    exists. The parent's normal reap and authority retirement are separate.
    """
    require(case['id'] == 'Q31', 'conditional entropy case differs')
    development_profile(case)
    verify_authority_peer(case, fixture, wire)
    require(fixture.get('marker_sent') is False and fixture.get('marker_trigger') is None,
            'conditional entropy passive peer produced a marker')
    lines = output.splitlines()
    def one(prefix):
        rows = [(i, fields(line)) for i, line in enumerate(lines) if line.startswith(prefix + ' ')]
        require(len(rows) == 1 and rows[0][1].get('case') == 'Q31',
                'conditional entropy requires one exact record: ' + prefix)
        return rows[0]
    gi, grant = one('QUIC SERVICE GRANT')
    bi, begin = one('QUIC BEGIN')
    ci, counts = one('QUIC FIXTURE NATIVE_COUNTS')
    ri, retired = one('QUIC CHILD AUTHORITY RETIRED')
    ei, exited = one('QUIC CHILD EXIT')
    ti, typed = one('QUIC RESULT')
    fi, final = one('QUIC SERVICE RETIRE')
    di, done = one('QUIC SERVICE DONE')
    opened = [i for i, row in enumerate(lines) if row == 'QUIC CONSUMER case=Q31 begin']
    closed = [i for i, row in enumerate(lines) if row == 'QUIC CONSUMER case=Q31 end']
    cpu = [i for i, row in enumerate(lines) if row.startswith('QUIC CPU ')]
    require(typed == report and len(opened) == len(closed) == len(cpu) == 1
            and gi < ci < ri < ei < opened[0] < cpu[0] < bi < ti < closed[0] < fi < di
            and not any(row.startswith(('QUIC SERVICE GRANT EXPIRED ', 'QUIC CHILD INTERRUPT ',
                                       'QUIC CONSUMER PARTIAL ')) for row in lines),
            'conditional entropy consumer reach or retirement publication differs')
    start, deadline, expiry = (number(begin, key) for key in ('start_ms', 'deadline_ms', 'grant_expiry_ms'))
    end, reaped, retired_at = number(report, 'end_ms'), number(retired, 'reaped_ms'), number(retired, 'retired_ms')
    require(number(grant, 'before_ms') <= number(grant, 'constructed_ms') <= start < deadline
            and expiry == number(grant, 'owner_expiry_ms') == number(grant, 'before_ms') + 15000
            and deadline == min(start + 10000, expiry) == number(report, 'deadline_ms')
            and number(report, 'start_ms') == start and number(report, 'grant_expiry_ms') == expiry
            and start <= end <= reaped <= retired_at < deadline
            and start <= number(counts, 'at_ms') <= retired_at,
            'conditional entropy original grant, deadline or retirement clock differs')
    require(number(exited, 'kind') == 1 and number(exited, 'status') == 0 and not boolean(exited, 'killed')
            and all(not boolean(retired, key) for key in ('process_handle_live', 'pipe_live', 'grant_live', 'owner_expired'))
            and boolean(retired, 'result_eof')
            and number(retired, 'sockets') == number(final, 'sockets_before_fence') ==
                number(final, 'sockets_after_fence') == number(done, 'sockets') == 0,
            'conditional entropy normal reap, true EOF or local authority retirement absent')
    require(report.get('outcome') == 'Entropy' and report.get('phase') == 'Init'
            and boolean(report, 'pipe_fenced') and not boolean(report, 'no_native_pair')
            and boolean(begin, 'native_pair')
            and re.fullmatch(r'Some\([1-9][0-9]*\)', begin.get('unix_time', ''))
            and number(report, 'entropy_attempts') == 1 and number(report, 'unexpected_rng_draws') == 0
            and all(report.get(key) == 'none' for key in ('native_failure_kind', 'native_error_code',
                'native_error_detail', 'transport_error_code', 'transport_close_origin', 'last_send_ms',
                'fence_ms', 'pending_exhausted_sha256', 'pending_retry_sha256')),
            'conditional entropy actual prepare refusal shape differs')
    phases = [(i, fields(row)) for i, row in enumerate(lines) if row.startswith('QUIC PHASE ')]
    require(len(phases) == 1 and phases[0][1].get('case') == 'Q31'
            and phases[0][1].get('phase') == 'Init' and bi < phases[0][0] < ti
            and start <= number(phases[0][1], 'at_ms') <= end,
            'conditional entropy entered an engine phase beyond Init')
    require(all(not boolean(report, key) for key in ('authenticated', 'request_fin', 'peer_fin',
                'request_acked', 'connection_drained', 'close_accepted', 'unknown_send'))
            and all(number(report, key) == 0 for key in ('sent_stream', 'received_stream',
                'engine_transmits', 'endpoint_responses_discarded', 'send_calls', 'send_accepted',
                'send_bytes', 'exhausted', 'receive_calls', 'received', 'receive_bytes', 'close_calls',
                'sends_after_fence', 'queue_fills', 'queue_retry_accepted', 'partial_pipe_reads', 'partial_pipe_writes'))
            and all(number(counts, key) == 0 for key in ('send_requests', 'receive_delivered',
                'sends_after_owner_expiry', 'partial_request_bytes', 'partial_reply_bytes'))
            and not any(row.startswith(('QUIC FIXTURE SEND ', 'QUIC FIXTURE RX ')) for row in lines)
            and not wire['guest_udp'] and not wire['peer_udp']
            and wire['guest_udp_count'] == wire['udp_count'] == 0,
            'conditional entropy refusal reached native, engine or application I/O')
    return {'consumer_reached':True, 'phase':'Init', 'entropy_attempts':1,
            'reaped_ms':reaped, 'retired_ms':retired_at, 'result_eof':True,
            'complete_native_send_requests':0, 'complete_native_receives':0, 'captured_udp':0}


def verify_native_link(case, output, report, fixture, wire):
    """Actual guest link-down, typed refusal and local retirement are distinct."""
    action = verify_link_peer(case,fixture,wire)
    lines = output.splitlines()
    def one(prefix):
        rows = [(i,fields(line)) for i,line in enumerate(lines) if line.startswith(prefix+' ')
                and (prefix != 'QUIC SERVICE GRANT' or 'constructed_ms' in fields(line))]
        require(len(rows) == 1 and rows[0][1].get('case') == 'Q24', 'one exact link record required: '+prefix)
        return rows[0]
    gi,grant = one('QUIC SERVICE GRANT')
    bi,begin = one('QUIC BEGIN')
    ci,counts = one('QUIC FIXTURE NATIVE_COUNTS')
    ri,retired = one('QUIC CHILD AUTHORITY RETIRED')
    ei,exited = one('QUIC CHILD EXIT')
    ti,typed = one('QUIC RESULT')
    fi,final = one('QUIC SERVICE RETIRE')
    di,done = one('QUIC SERVICE DONE')
    opened = [i for i,row in enumerate(lines) if row == 'QUIC CONSUMER case=Q24 begin']
    closed = [i for i,row in enumerate(lines) if row == 'QUIC CONSUMER case=Q24 end']
    require(typed == report and len(opened) == len(closed) == 1
            and gi < ci < ri < ei < opened[0] < bi < ti < closed[0] < fi < di
            and not any(row.startswith(('QUIC SERVICE GRANT EXPIRED ','QUIC CHILD INTERRUPT ',
                                       'QUIC CONSUMER PARTIAL ')) for row in lines),
            'link retirement or buffered publication differs')
    start,deadline,expiry = (number(begin,key) for key in ('start_ms','deadline_ms','grant_expiry_ms'))
    end,reaped,retired_at = number(report,'end_ms'),number(retired,'reaped_ms'),number(retired,'retired_ms')
    require(number(grant,'before_ms') <= number(grant,'constructed_ms') <= start < deadline
            and expiry == number(grant,'owner_expiry_ms') == number(grant,'before_ms')+15000
            and deadline == min(start+10000,expiry) == number(report,'deadline_ms')
            and number(report,'start_ms') == start and number(report,'grant_expiry_ms') == expiry
            and start <= end <= reaped <= retired_at < deadline
            and start <= number(counts,'at_ms') <= retired_at,
            'link original grant, child lifetime or retirement clock differs')
    links = [(i,fields(row)) for i,row in enumerate(lines) if row.startswith('QUIC FIXTURE LINK ')]
    require(len(links) == 2 and all(row.get('case') == 'Q24' for _,row in links)
            and links[0][0] < gi and links[0][0] < links[1][0] < ri
            and boolean(links[0][1],'present') and boolean(links[0][1],'link_up')
            and not boolean(links[0][1],'disabled')
            and boolean(links[1][1],'present') and not boolean(links[1][1],'link_up')
            and not boolean(links[1][1],'disabled')
            and number(links[0][1],'at_ms') <= number(grant,'constructed_ms')
            and start <= number(links[1][1],'at_ms') <= retired_at,
            'NOT_ESTABLISHED: actual guest up-to-down NIC reading absent')
    down_at = number(links[1][1],'at_ms')
    require(number(exited,'kind') == 1 and number(exited,'status') == 0 and not boolean(exited,'killed')
            and all(not boolean(retired,key) for key in ('process_handle_live','pipe_live','grant_live','owner_expired'))
            and boolean(retired,'result_eof')
            and number(retired,'sockets') == number(final,'sockets_before_fence') ==
                number(final,'sockets_after_fence') == number(done,'sockets') == 0,
            'link normal child reap, true EOF or absent local authority not established')
    for name in ('processes','handles','pipes','cells'):
        require(number(done,name+'_before') == number(done,name+'_after'), 'link resource not restored: '+name)
    require(report.get('outcome') == 'Native' and report.get('native_failure_kind') == 'Native'
            and number(report,'native_error_code') == 9 and report.get('native_error_detail') == 'none'
            and report.get('transport_error_code') == report.get('transport_close_origin') == 'none'
            and report.get('phase') == 'Fenced' and boolean(report,'pipe_fenced')
            and not boolean(report,'no_native_pair') and boolean(begin,'native_pair')
            and re.fullmatch(r'Some\([1-9][0-9]*\)',begin.get('unix_time',''))
            and number(report,'entropy_attempts') == 1 and number(report,'unexpected_rng_draws') == 0
            and start <= number(report,'fence_ms') <= end and number(report,'sends_after_fence') == 0
            and not boolean(report,'unknown_send'),
            'actual link-down was replaced by Stale, Deadline or another native cause')
    require(all(not boolean(report,key) for key in ('authenticated','request_fin','peer_fin',
                    'request_acked','connection_drained','close_accepted'))
            and all(number(report,key) == 0 for key in ('sent_stream','received_stream','received',
                                                       'receive_bytes','close_calls')),
            'link fixture reached authentication, application data or unrelated close')
    phases = [(i,fields(row)) for i,row in enumerate(lines) if row.startswith('QUIC PHASE ')]
    require([row.get('phase') for _,row in phases] == ['Init','Handshake','Fenced']
            and all(row.get('case') == 'Q24' and opened[0] < i < ti
                    and start <= number(row,'at_ms') <= end for i,row in phases)
            and all(number(a,'at_ms') <= number(b,'at_ms') for (_,a),(_,b) in zip(phases,phases[1:])),
            'link actual child phases or buffered clocks differ')
    sends = [(i,fields(row)) for i,row in enumerate(lines) if row.startswith('QUIC FIXTURE SEND ')]
    require(0 < len(sends) <= 4096 and len(sends) == number(counts,'send_requests')
            and [number(row,'ordinal') for _,row in sends] == list(range(1,len(sends)+1))
            and len(sends) <= number(report,'send_calls') <= len(sends)+1
            and 0 < number(report,'send_accepted') <= len(sends)
            and len(wire['guest_udp']) <= number(report,'send_accepted')
            and wire['guest_udp_bytes'] <= number(report,'send_bytes') <= sum(number(row,'bytes') for _,row in sends)
            and number(counts,'receive_delivered') == 0
            and not any(row.startswith('QUIC FIXTURE RX ') for row in lines)
            and number(counts,'sends_after_owner_expiry') == 0
            and number(counts,'partial_request_bytes') < 1486 and number(counts,'partial_reply_bytes') < 1486,
            'link complete native census, bytes or framing retirement differs')
    for i,row in sends:
        require(i < ci and row.get('case') == 'Q24' and row.get('peer_ip') == '10.0.2.2'
                and number(row,'peer_port') == 4443 and number(row,'bytes') == 1200
                and start <= number(row,'at_ms') <= number(counts,'at_ms')
                and re.fullmatch('[0-9a-f]{64}',row.get('sha256','')), 'link SEND lacks complete tuple/time/hash')
    eligible = [row for _,row in sends if number(row,'at_ms') <= down_at]
    cursor = 0
    for packet in wire['guest_udp']:
        while cursor < len(eligible) and (number(eligible[cursor],'bytes'),eligible[cursor]['sha256']) != (packet['bytes'],packet['sha256']):
            cursor += 1
        require(cursor < len(eligible), 'link capture lacks ordered pre-observed-loss native SEND')
        cursor += 1
    require(any(row['sha256'] == action['trigger_sha256'] for row in eligible)
            and start <= number(report,'last_send_ms') <= number(report,'fence_ms'),
            'link transition lacks causal native Initial before the guest loss observation')
    return {'guest_link_down_ms':down_at,'native_error_code':9,'reaped_ms':reaped,'retired_ms':retired_at,
            'result_eof':True,'qmp_receipt_sha256':action['qmp_receipt_sha256'],
            'complete_send_requests':len(sends),'captured_guest_udp':len(wire['guest_udp']),
            'partial_request_bytes_retired':number(counts,'partial_request_bytes'),
            'partial_reply_bytes_retired':number(counts,'partial_reply_bytes'),
            'limit':'Typed software link feedback and local authority retirement; prior wire effects are not retracted.'}


def verify_native_icmp(case, output, report, fixture, wire):
    """Bind actual advisory feedback to the consumer and local retirement."""
    action = verify_icmp_peer(case,fixture,wire)
    identity = case['id']
    lines = output.splitlines()
    def one(prefix):
        rows = [(i,fields(line)) for i,line in enumerate(lines) if line.startswith(prefix+' ')
                and (prefix != 'QUIC SERVICE GRANT' or 'constructed_ms' in fields(line))]
        require(len(rows) == 1 and rows[0][1].get('case') == identity, 'one exact ICMP record required: '+prefix)
        return rows[0]
    gi,grant = one('QUIC SERVICE GRANT')
    bi,begin = one('QUIC BEGIN')
    ci,counts = one('QUIC FIXTURE NATIVE_COUNTS')
    ri,retired = one('QUIC CHILD AUTHORITY RETIRED')
    ei,exited = one('QUIC CHILD EXIT')
    ti,typed = one('QUIC RESULT')
    fi,final = one('QUIC SERVICE RETIRE')
    di,done = one('QUIC SERVICE DONE')
    opened = [i for i,row in enumerate(lines) if row == 'QUIC CONSUMER case='+identity+' begin']
    closed = [i for i,row in enumerate(lines) if row == 'QUIC CONSUMER case='+identity+' end']
    require(typed == report and len(opened) == len(closed) == 1
            and gi < ci < ri < ei < opened[0] < bi < ti < closed[0] < fi < di
            and not any(row.startswith(('QUIC SERVICE GRANT EXPIRED ','QUIC CHILD INTERRUPT ',
                                       'QUIC CONSUMER PARTIAL ','QUIC FIXTURE LINK ')) for row in lines),
            'ICMP retirement or buffered publication differs')
    start,deadline,expiry = (number(begin,key) for key in ('start_ms','deadline_ms','grant_expiry_ms'))
    end,reaped,retired_at = number(report,'end_ms'),number(retired,'reaped_ms'),number(retired,'retired_ms')
    require(number(grant,'before_ms') <= number(grant,'constructed_ms') <= start < deadline
            and expiry == number(grant,'owner_expiry_ms') == number(grant,'before_ms')+15000
            and deadline == min(start+10000,expiry) == number(report,'deadline_ms')
            and number(report,'start_ms') == start and number(report,'grant_expiry_ms') == expiry
            and start <= end <= reaped <= retired_at < deadline
            and start <= number(counts,'at_ms') <= retired_at,
            'ICMP original grant, child lifetime or retirement clock differs')
    require(number(exited,'kind') == 1 and number(exited,'status') == 0 and not boolean(exited,'killed')
            and all(not boolean(retired,key) for key in ('process_handle_live','pipe_live','grant_live','owner_expired'))
            and boolean(retired,'result_eof')
            and number(retired,'sockets') == number(final,'sockets_before_fence') ==
                number(final,'sockets_after_fence') == number(done,'sockets') == 0,
            'ICMP normal child reap, true EOF or absent local authority not established')
    for name in ('processes','handles','pipes','cells'):
        require(number(done,name+'_before') == number(done,name+'_after'), 'ICMP resource not restored: '+name)
    code,detail = number(report,'native_error_code'),number(report,'native_error_detail')
    require(code in case['native_error_codes'] and detail == (case['icmp_mtu'] if code == 14 else case['icmp_mtu']-28)
            and report.get('outcome') == 'Native' and report.get('native_failure_kind') == 'Native'
            and report.get('transport_error_code') == report.get('transport_close_origin') == 'none'
            and report.get('phase') == 'Fenced' and boolean(report,'pipe_fenced')
            and not boolean(report,'no_native_pair') and boolean(begin,'native_pair')
            and re.fullmatch(r'Some\([1-9][0-9]*\)',begin.get('unix_time',''))
            and number(report,'entropy_attempts') == 1 and number(report,'unexpected_rng_draws') == 0
            and start <= number(report,'fence_ms') <= end and number(report,'sends_after_fence') == 0
            and not boolean(report,'unknown_send'),
            'ICMP selected native code/detail or actual pipe fencing differs')
    require(number(report,'fence_ms') <= number(counts,'at_ms')
            and number(report,'engine_transmits') >= (2 if code == 15 else 1)
            and number(report,'send_bytes') == 1200*number(report,'send_accepted'),
            'ICMP production, accepted-byte total or final census clock differs')
    require(all(not boolean(report,key) for key in ('authenticated','request_fin','peer_fin',
                    'request_acked','connection_drained','close_accepted'))
            and all(number(report,key) == 0 for key in ('sent_stream','received_stream','received',
                                                       'receive_bytes','close_calls')),
            'ICMP fixture reached authentication, application data or unrelated close')
    phases = [(i,fields(row)) for i,row in enumerate(lines) if row.startswith('QUIC PHASE ')]
    require([row.get('phase') for _,row in phases] == ['Init','Handshake','Fenced']
            and all(row.get('case') == identity and opened[0] < i < ti
                    and start <= number(row,'at_ms') <= end for i,row in phases)
            and all(number(a,'at_ms') <= number(b,'at_ms') for (_,a),(_,b) in zip(phases,phases[1:])),
            'ICMP actual child phases or buffered clocks differ')
    sends = [(i,fields(row)) for i,row in enumerate(lines) if row.startswith('QUIC FIXTURE SEND ')]
    require(0 < len(sends) <= 4096 and len(sends) == number(counts,'send_requests')
            and [number(row,'ordinal') for _,row in sends] == list(range(1,len(sends)+1))
            and len(sends) <= number(report,'send_calls') <= len(sends)+1
            and 0 < number(report,'send_accepted') <= len(sends)
            and len(wire['guest_udp']) <= number(report,'send_accepted')
            and wire['guest_udp_bytes'] <= number(report,'send_bytes') <= sum(number(row,'bytes') for _,row in sends)
            and number(counts,'receive_delivered') == 0
            and not any(row.startswith('QUIC FIXTURE RX ') for row in lines)
            and number(counts,'sends_after_owner_expiry') == 0
            and number(counts,'partial_request_bytes') < 1486 and number(counts,'partial_reply_bytes') < 1486,
            'ICMP complete native census, bytes or framing retirement differs')
    for i,row in sends:
        require(i < ci and row.get('case') == identity and row.get('peer_ip') == '10.0.2.2'
                and number(row,'peer_port') == 4443 and number(row,'bytes') == 1200
                and start <= number(row,'at_ms') <= min(number(report,'fence_ms'),number(counts,'at_ms'))
                and re.fullmatch('[0-9a-f]{64}',row.get('sha256','')), 'ICMP SEND lacks complete tuple/time/hash')
    cursor = 0
    for packet in wire['guest_udp']:
        while cursor < len(sends) and (number(sends[cursor][1],'bytes'),sends[cursor][1]['sha256']) != (packet['bytes'],packet['sha256']):
            cursor += 1
        require(cursor < len(sends), 'ICMP capture lacks ordered complete native SEND')
        cursor += 1
    require(any(row['sha256'] == action['trigger_sha256'] for _,row in sends)
            and start <= number(report,'last_send_ms') <= number(report,'fence_ms'),
            'ICMP literal trigger lacks an actual native Initial request')
    if code == 15:
        # The unchanged IPv4 codec admits status15 only as a failed SEND with
        # maximum < request bytes. A socket receipt is never application RX.
        require(number(report,'send_accepted') < len(sends) and detail < number(sends[-1][1],'bytes'),
                'ICMP path-MTU status lacks a complete SEND refused before enqueue')
    return {**action,'native_error_code':code,'native_error_detail':detail,'reaped_ms':reaped,
            'retired_ms':retired_at,'result_eof':True,'complete_send_requests':len(sends),
            'captured_guest_udp':len(wire['guest_udp']),
            'partial_request_bytes_retired':number(counts,'partial_request_bytes'),
            'partial_reply_bytes_retired':number(counts,'partial_reply_bytes'),
            'limit':'Current native advisory-to-fence policy only; no PMTU discovery, boundary continuation, authenticated ICMP origin or retraction of prior wire effects.'}


def verify_native(case, output, fixture, wire, manifest, family='ipv4', reorder_stage='initial'):
    selected = records(output, 'QUIC SERVICE SELECTOR', case)
    done = records(output, 'QUIC SERVICE DONE', case)
    grants = [row for row in records(output,'QUIC SERVICE GRANT',case) if 'constructed_ms' in row]
    require(len(selected) == len(done) == len(grants) == 1, 'one actual parent selector/grant/terminal required')
    require(number(selected[0], 'local_port') == case['local_port'] and number(done[0], 'sockets') == 0,
            'selected tuple or native UDP resource terminal differs')
    require(number(grants[0], 'local_port') == case['local_port']
            and number(grants[0], 'peer_port') == 4443,
            'selected grant tuple differs')
    for name in ('processes','handles','pipes','cells'):
        require(number(done[0], name + '_before') == number(done[0], name + '_after'), 'parent resource not restored: ' + name)
    cpu = [fields(line) for line in output.splitlines() if line.startswith('QUIC CPU ')]
    require(len(cpu) == 1 and cpu[0].get('vendor') == 'GenuineIntel', 'actual selected CPU evidence absent')
    eax, ecx = number(cpu[0], 'leaf1_eax'), number(cpu[0], 'leaf1_ecx')
    cpu_family = (eax >> 8) & 15
    cpu_family += ((eax >> 20) & 255) if cpu_family == 15 else 0
    model = ((eax >> 4) & 15) | ((((eax >> 16) & 15) << 4) if cpu_family in (6,15) else 0)
    bit = 0 if case['id'] == 'Q31' else 1
    require(cpu_family == number(cpu[0], 'family') == 6 and model == number(cpu[0], 'model') == 60 and
            (ecx >> 30) & 1 == number(cpu[0], 'rdrand') == bit, 'actual CPU differs from selected Haswell variant')
    verify_fixture(case, fixture, wire, family, reorder_stage=reorder_stage)
    if case['id'] in ('Q08', 'Q09', 'Q10', 'Q11'):
        after = 'q08-after-flight-input' if case['id'] == 'Q08' else 'auth-after-flight-input'
        require(not any(row['event'] == after for row in fixture['events']),
                ('native Q08 received input after the response flight; ' if family == 'ipv6' else '')
                + 'native authentication input was discarded after the response flight')
    if case['expected_outcome'] == 'Interrupted':
        return verify_native_interruption(case, output, fixture, wire, cpu[0])
    reports = records(output, manifest['report']['prefix'], case)
    require(len(reports) == 1, 'one typed native result required')
    report = reports[0]
    require(all(name in report for name in manifest['report']['fields']), 'typed native result schema incomplete')
    verify_transport_close_origin(case, report)
    require(report['outcome'] == case['expected_outcome'], 'actual native outcome differs: ' + report['outcome'])
    require(number(report, 'unexpected_rng_draws') == 0, 'ambient entropy backend was reached')
    require(number(report,'engine_transmits')<=256 and number(report,'received')<=256 and
            number(report,'receive_bytes')<=376832 and number(report,'send_accepted')<=260 and
            number(report,'send_bytes')<=307200+4*16, 'native packet/byte budget exceeded')
    for requirement in case['requires']:
        match=re.fullmatch(r'([a-zA-Z_][a-zA-Z_0-9]*)(>=|=)([a-zA-Z_0-9]+)',requirement)
        if match and match[1] in report:
            name,operation,value=match.groups()
            if value in report:
                require(operation=='=' and report[name]==report[value], 'manifest field correspondence differs: '+requirement)
            elif value in ('true','false'):
                require(operation=='=' and boolean(report,name)==(value=='true'), 'manifest boolean differs: '+requirement)
            else:
                require(value.isdecimal() and (number(report,name)>=int(value) if operation=='>=' else number(report,name)==int(value)),
                        'manifest numeric requirement differs: '+requirement)
        elif requirement in report:
            require(boolean(report,requirement),'manifest boolean absent: '+requirement)
        elif requirement=='peer_app_bytes=0':
            require(fixture['request_bytes']==0,'pre-authentication application bytes reached independent peer')
    if case['expected_outcome'] not in ('Config','Time','Entropy'):
        require(number(report,'sends_after_fence')==0,'SEND API reached after native pipe retirement')
    if case.get('native_failure_kinds'):
        require(report['native_failure_kind'] in case['native_failure_kinds'], 'native failure kind differs')
    for field, values in [('native_error_code', case.get('native_error_codes')),
                          ('transport_error_code', case.get('transport_error_codes'))]:
        if values:
            require(number(report, field) in values, 'typed native error differs: ' + field)
    if case['expected_outcome'] not in ('Config','Time','Entropy'):
        require(boolean(report, 'pipe_fenced'), 'owned native pipe retirement absent')
    if case['expected_outcome'] == 'Complete':
        for field in ('authenticated','request_fin','peer_fin','request_acked','connection_drained','close_accepted','pipe_fenced'):
            require(boolean(report, field), 'success predicate absent: ' + field)
        require(number(report, 'sent_stream') == number(report, 'received_stream') == 4096, 'native exact stream byte count differs')
    begins = records(output, 'QUIC BEGIN', case)
    if case['expected_outcome'] not in ('Config','Time','Entropy'):
        require(len(begins) == 1, 'original operation deadline absent')
        start, deadline, expiry = (number(begins[0], name) for name in ('start_ms','deadline_ms','grant_expiry_ms'))
        require(deadline == min(start + 10000, expiry), 'operation or grant deadline was extended')
        if case['expected_outcome'] == 'Complete':
            require(number(report, 'end_ms') <= deadline, 'success reached after original deadline')
    if case['id'] in ('Q07','Q08','Q09','Q10','Q11','Q14'):
        require(not boolean(report,'authenticated') and number(report,'sent_stream')==0 and
                fixture['request_bytes']==0,'refusal authenticated or emitted application data')
    if case['id'] in ('Q08','Q09','Q10','Q11'):
        require(number(report, 'received_stream') == 0 and not boolean(report, 'request_fin')
                and not boolean(report, 'peer_fin') and number(report, 'sends_after_fence') == 0,
                'wrong-root native emitted/received application data or sent after fence')
    if case['id'] == 'Q02':
        require(all(number(report, counter) >= minimum
                    for counter, minimum in partial_ipc_bounds(report).items()),
                'actual partial native IPC reads/writes below 7-byte payload bound')
    if case['id'] == 'Q19':
        released = records(output, 'QUIC FIXTURE QUEUE RELEASE', case)
        full = [row for row in records(output, 'QUIC PHASE', case) if row.get('phase') == 'QueueFull']
        require(len(full) == len(released) == 1 and released[0].get('trigger') == 'real_Initial_Exhausted'
                and number(full[0], 'at_ms') <= number(released[0], 'at_ms') <= number(report, 'last_send_ms'),
                'actual QueueFull phase and owner release correspondence absent')
        initial = verify_queue_prelude(fixture, wire)
        require(number(report, 'queue_fills') == 4 and number(report, 'exhausted') >= 1 and
                number(report, 'queue_retry_accepted') == 1 and len(released) == 1 and
                fixture['unique_queue_fixture_datagrams'] == 4 and
                report['pending_exhausted_sha256'] == report['pending_retry_sha256'] and
                report['pending_retry_sha256'] == initial['sha256'] and
                re.fullmatch(r'[0-9a-f]{64}',report['pending_retry_sha256']) is not None and
                any(row['sha256'] == report['pending_retry_sha256'] for row in wire['guest_udp']),
                'known-not-queued exact datagram retry was not established')
    if case['id'] == 'Q20':
        verify_unknown_completion(case, output, fixture, wire, report, grants[0], begins[0])
    if case['id'] == 'Q18':
        verify_udp_filter_witness(case, output)
        probes = [row for row in fixture['events'] if row['event'] == 'unauthorized-probe']
        ledger = records(output, 'QUIC FIXTURE RX', case)
        native_counts=records(output,'QUIC FIXTURE NATIVE_COUNTS',case)
        require(len(probes) == 1 and probes[0]['authorized_copy_sent'] is False,
                'NOT_ESTABLISHED: distinct bad-tuple encrypted probe absent')
        verify_unauthorized_source(fixture, wire)
        bad = wire['unauthorized_peer_udp'][0]
        require(any(row['timestamp'] > bad['timestamp'] for row in wire['guest_udp'])
                and any(row['timestamp'] > bad['timestamp'] for row in wire['peer_udp']),
                'NOT_ESTABLISHED: Q18 probe did not arrive while the connection was still exchanging')
        require(len(native_counts)==1 and number(native_counts[0],'receive_delivered')==len(ledger) and
                len(ledger) == number(report, 'received') and len(ledger) <= 256 and
                [number(row, 'ordinal') for row in ledger] == list(range(1,len(ledger)+1)),
                'NOT_ESTABLISHED: complete native successful RECEIVE ledger absent')
        require(not any(packet['sha256']==probes[0]['sha256'] and packet['source']==['10.0.2.2',4443]
                        for packet in wire['peer_udp']), 'probe bytes were sent from authorized tuple')
        require(all(row.get('sha256') != probes[0]['sha256'] for row in ledger) and
                any(row['sha256'] != probes[0]['sha256'] for row in ledger),
                'unauthorized ciphertext reached native RECEIVE or authorized receive control absent')
        for row in ledger:
            require(any(packet['sha256'] == row.get('sha256') and packet['source'] == ['10.0.2.2',4443]
                        for packet in wire['peer_udp']), 'native RX ledger lacks authorized wire correspondence')
    if case['id'] in ('Q17','Q29','Q30','Q31'):
        require(wire['guest_udp_count'] == 0 and number(report, 'send_accepted') == 0, 'refusal emitted UDP')
    if case['id'] in ('Q29','Q30','Q31'):
        require(number(report, 'send_calls') == 0, 'pre-SEND refusal reached native SEND')
    if case['id'] == 'Q29':
        require(boolean(report, 'no_native_pair'), 'absent named startup output did not refuse')
    if case['id'] == 'Q30':
        require(number(report, 'entropy_attempts') == 0, 'missing fixture time acquired entropy')
    if case['id'] in ('Q01', 'Q02', 'Q03', 'Q04', 'Q05', 'Q06', 'Q08', 'Q09', 'Q10', 'Q11', 'Q12', 'Q13', 'Q15', 'Q16', 'Q18', 'Q19'):
        exits = records(output, 'QUIC CHILD EXIT', case)
        require(len(exits) == 1 and number(exits[0], 'kind') == 1 and number(exits[0], 'status') == 0
                and not boolean(exits[0], 'killed'), 'Q01 child did not exit normally')
        require(report['native_failure_kind'] == 'none' and report['native_error_code'] == 'none'
                and report['native_error_detail'] == 'none'
                and (report['transport_error_code'] == 'none' if case['expected_outcome'] == 'Complete' else report['transport_error_code'] == str(case['transport_error_codes'][0]))
                and not boolean(report, 'unknown_send') and number(report, 'entropy_attempts') == 1,
                'Q01 completed with a hidden failure or different entropy construction')
        prefill = 4 if case['id'] == 'Q19' else 0
        require(1 <= number(report, 'engine_transmits') <= 256
                and number(report, 'engine_transmits') + prefill == number(report, 'send_accepted') <= 256
                and number(report, 'send_calls') >= number(report, 'send_accepted')
                and number(report, 'send_bytes') <= 307200
                and 0 < len(wire['guest_udp']) <= number(report, 'send_accepted'),
                'Q01 native transmit budget differs')
        grant = grants[0]
        require(number(grant, 'local_port') == case['local_port'] and number(grant, 'peer_port') == 4443
                and number(grant, 'before_ms') <= number(grant, 'constructed_ms') <= start
                and number(grant, 'owner_expiry_ms') == expiry == number(report, 'grant_expiry_ms')
                and expiry == number(grant, 'before_ms') + 15000
                and number(report, 'start_ms') == start and number(report, 'deadline_ms') == deadline,
                'Q01 original grant/child deadline correspondence differs')
        require(start <= number(report, 'last_send_ms') <= number(report, 'fence_ms')
                <= number(report, 'end_ms') <= deadline, 'Q01 send/fence/end order differs')
        counts = records(output, 'QUIC FIXTURE NATIVE_COUNTS', case)
        sent = records(output, 'QUIC FIXTURE SEND', case)
        received = records(output, 'QUIC FIXTURE RX', case)
        require(len(counts) == 1 and number(counts[0], 'send_requests') == len(sent) == number(report, 'send_calls')
                and number(counts[0], 'receive_delivered') == len(received) == number(report, 'received')
                and number(counts[0], 'sends_after_owner_expiry') == 0
                and number(counts[0], 'partial_request_bytes') == number(counts[0], 'partial_reply_bytes') == 0,
                'Q01 complete native framing census differs')
        require(sum(number(row, 'bytes') for row in received) == number(report, 'receive_bytes'),
                'Q01 received-byte ledger differs')
        for ledger in (sent, received):
            require(ledger and [number(row, 'ordinal') for row in ledger] == list(range(1, len(ledger) + 1)),
                    'Q01 native ledger is empty/incomplete')
            require(all(row.get('peer_ip') == ('fd00:ab5d::2' if family == 'ipv6' else '10.0.2.2') and number(row, 'peer_port') == 4443
                        and start <= number(row, 'at_ms') < expiry for row in ledger),
                    'Q01 native ledger tuple/lifetime differs')
        for row in received:
            require(any(row.get('sha256') == packet['sha256'] and number(row, 'bytes') == packet['bytes']
                        for packet in wire['peer_udp']), 'Q01 native RX lacks independent captured datagram')
        initial = [row for row in fixture['events'] if row['event'] == 'initial-observed']
        require(len(initial) == 1 and any(row['sha256'] == initial[0]['sha256'] and row['bytes'] >= 1200
                                        for row in wire['guest_udp']), 'Q01 actual Initial correspondence absent')
    if case['id'] == 'Q07':
        # Silence ends at the engine clock deadline: no input, no transport close,
        # and every native SEND is an Initial the peer received and the wire carried.
        sent = records(output, 'QUIC FIXTURE SEND', case)
        received = records(output, 'QUIC FIXTURE RX', case)
        exits = records(output, 'QUIC CHILD EXIT', case)
        require(len(exits) == 1 and number(exits[0], 'kind') == 1 and number(exits[0], 'status') == 0
                and not boolean(exits[0], 'killed'), 'Q07 child did not exit normally')
        require(not received and number(report, 'received') == number(report, 'receive_bytes') == 0
                and report['transport_error_code'] == 'none' and report['transport_close_origin'] == 'none'
                and number(report, 'deadline_ms') == number(begins[0], 'deadline_ms')
                and number(report, 'deadline_ms') <= number(report, 'end_ms')
                <= number(report, 'deadline_ms') + Q07_DEADLINE_SLACK_MS,
                'Q07 native silence did not end at its own deadline without input')
        # The probe emits SEND hashes only for Q04/Q06; byte identity of each
        # datagram is bound capture-to-peer-receipt in verify_silent.
        require(sent and [number(row, 'ordinal') for row in sent] == list(range(1, len(sent) + 1))
                and number(report, 'send_accepted') == len(sent) == len(wire['guest_udp'])
                and [number(row, 'bytes') for row in sent] == [row['bytes'] for row in wire['guest_udp']]
                and all(row.get('sha256') in (None, packet['sha256']) for row, packet in zip(sent, wire['guest_udp'])),
                'Q07 native Initial SEND ledger differs from the capture')
    if case['id'] == 'Q14':
        # The overlong Retry reaches the engine once and changes nothing: the
        # child ends at its own deadline with no transport close.
        retry = verify_long_retry(fixture, wire)
        sent = records(output, 'QUIC FIXTURE SEND', case)
        received = records(output, 'QUIC FIXTURE RX', case)
        exits = records(output, 'QUIC CHILD EXIT', case)
        # Outcome Native and kind Deadline are the shared checks above; the
        # child must also exit normally and keep sending after it processed
        # the Retry, so a crash on the Retry cannot pass as an ignored one.
        require(len(exits) == 1 and number(exits[0], 'kind') == 1 and number(exits[0], 'status') == 0
                and not boolean(exits[0], 'killed'), 'Q14 child did not exit normally')
        require(len(received) == 1 and any(number(row, 'at_ms') > number(received[0], 'at_ms') for row in sent),
                'NOT_ESTABLISHED: Q14 no native Initial SEND after the native Retry receipt')
        require(len(received) == 1 and number(received[0], 'bytes') == len(retry)
                and received[0].get('sha256') == hashlib.sha256(retry).hexdigest()
                and number(report, 'received') == 1 and number(report, 'receive_bytes') == len(retry)
                and report['transport_error_code'] == 'none' and report['transport_close_origin'] == 'none'
                and number(report, 'deadline_ms') == number(begins[0], 'deadline_ms')
                and number(report, 'deadline_ms') <= number(report, 'end_ms')
                <= number(report, 'deadline_ms') + Q07_DEADLINE_SLACK_MS,
                'Q14 native Retry receipt or own-deadline end differs')
        require(sent and [number(row, 'ordinal') for row in sent] == list(range(1, len(sent) + 1))
                and number(report, 'send_accepted') == len(sent) == len(wire['guest_udp'])
                and [number(row, 'bytes') for row in sent] == [row['bytes'] for row in wire['guest_udp']]
                and all(row.get('sha256') in (None, packet['sha256']) for row, packet in zip(sent, wire['guest_udp'])),
                'Q14 native Initial SEND ledger differs from the capture')
    if case['id'] == 'Q15':
        selected = verify_stream_limit(fixture, wire=wire)
        ledger = records(output, 'QUIC FIXTURE RX', case)
        matches = [row for row in ledger if row['sha256'] == selected['sha256']]
        require(len(matches) == 1 and number(matches[0], 'bytes') == selected['bytes']
                and number(begins[0], 'start_ms') <= number(matches[0], 'at_ms')
                <= number(report, 'end_ms') <= number(begins[0], 'deadline_ms'),
                'NOT_ESTABLISHED: Q15 selected input absent or refusal outside original deadline')
        require(boolean(report, 'authenticated') and report['transport_error_code'] == '4'
                and report['transport_close_origin'] == 'local'
                and report['outcome'] == 'Protocol' and number(report, 'received_stream') == 0
                and not boolean(report, 'peer_fin'),
                'Q15 must be authenticated local STREAM_LIMIT_ERROR, not peer close, echo or timeout')
    if case['id'] == 'Q16':
        # Every native input carries the engine's own routing outcome. The
        # unknown-CID datagram must reach the endpoint and not the connection.
        stray = verify_unknown_cid(fixture, wire)
        ledger = records(output, 'QUIC FIXTURE RX', case)
        routes = records(output, 'QUIC ROUTE RX', case)
        require(len(routes) == len(ledger) == number(report, 'received')
                and len(routes) == sum(line.startswith('QUIC ROUTE RX ') for line in output.splitlines())
                and [(number(r, 'receive_ordinal'), number(r, 'bytes'), r.get('sha256')) for r in routes]
                == [(number(r, 'ordinal'), number(r, 'bytes'), r.get('sha256')) for r in ledger],
                'NOT_ESTABLISHED: Q16 complete native routing observations absent or different')
        unknown = [r for r in routes if r.get('sha256') == stray['sha256']]
        require(len(unknown) == 1 and not boolean(unknown[0], 'target_handled')
                and number(unknown[0], 'stream_frames_after') == number(unknown[0], 'stream_frames_before')
                and boolean(unknown[0], 'authenticated_before')
                and all(boolean(r, 'target_handled') for r in routes if r is not unknown[0])
                and number(report, 'endpoint_responses_discarded') <= 1,
                'NOT_ESTABLISHED: Q16 unknown-CID input was routed to the connection or another input was not')
    if case['id'] == 'Q04':
        verify_native_stream_loss(case, output, report, fixture, wire)
    if case['id'] == 'Q06':
        verify_native_flow_pause(case, output, report, fixture, wire)
    if case['id'] == 'Q05':
        selected = verify_duplicate_reorder(case, fixture, wire, reorder_stage=reorder_stage)
        delivered = [{'ordinal':number(row, 'ordinal'), 'bytes':number(row, 'bytes'), 'sha256':row['sha256'],
                      'source':[row['peer_ip'], number(row, 'peer_port')]}
                     for row in records(output, 'QUIC FIXTURE RX', case)]
        selected_ordinal = reorder_consumed(selected, delivered, wire['peer_udp'])
        if reorder_stage == 'post-handshake':
            verify_post_handshake_processing(case, output, report, delivered, selected_ordinal)
        require(len(wire['guest_udp']) == number(report, 'send_accepted')
                and sum(row['bytes'] for row in wire['guest_udp']) == number(report, 'send_bytes'),
                'Q05 complete accepted native SEND/capture census differs')

    if case['id'] == 'Q13':
        verify_native_tag_processing(case, output, report, fixture, wire)

    if case['id'] == 'Q12':
        malformed = verify_truncated_header(case, fixture, wire)
        delivered = records(output, 'QUIC FIXTURE RX', case)
        require(len(delivered) >= 2 and number(delivered[0], 'ordinal') == 1
                and number(delivered[0], 'bytes') == malformed['bytes']
                and delivered[0]['sha256'] == malformed['sha256']
                and sum(row['sha256'] == malformed['sha256'] for row in delivered) == 1,
                'Q12 exact malformed native RECEIVE ordinal/hash absent')
        cursor = 0
        for row in delivered:
            while cursor < len(wire['peer_udp']) and (wire['peer_udp'][cursor]['bytes'], wire['peer_udp'][cursor]['sha256']) != (number(row, 'bytes'), row['sha256']):
                cursor += 1
            require(cursor < len(wire['peer_udp']), 'Q12 native RECEIVE order differs from complete capture')
            cursor += 1
    if family == 'ipv6':
        verify_ipv6_native(case, output, report, wire)
    authority = verify_native_authority(case, output, report, wire) if case['id'] in ('Q23', 'Q29', 'Q30') else None
    entropy = verify_native_entropy(case, output, report, fixture, wire) if case['id'] == 'Q31' else None
    denial = verify_native_ipv4_denied(case, output, report, fixture, wire) if family == 'ipv4' and case['id'] == 'Q17' else None
    link = verify_native_link(case,output,report,fixture,wire) if case['id'] == 'Q24' else None
    icmp = verify_native_icmp(case,output,report,fixture,wire) if case['id'] in ('Q25', 'Q26', 'Q27', 'Q28') else None
    return {'actual_outcome':report['outcome'], 'typed_report':report, 'measured_cpu':cpu[0],
            'original_begin':begins[0] if begins else None, **({'authority':authority} if authority is not None else {}),
            **({'entropy':entropy} if entropy is not None else {}), **({'denial':denial} if denial is not None else {}), **({'link':link} if link is not None else {}), **({'icmp':icmp} if icmp is not None else {})}


def verify_ipv6_native(case, output, report, wire):
    def one(prefix):
        rows = records(output, prefix, case)
        require(len(rows) == sum(row.startswith(prefix + ' ') for row in output.splitlines()) == 1,
                'one actual selected-case IPv6 record required: ' + prefix)
        return rows[0]
    parent, child = one('QUIC SERVICE FAMILY'), one('QUIC TRANSPORT')
    require(parent.get('family') == child.get('family') == '6'
            and parent.get('scope') == child.get('scope') == '1'
            and parent.get('local_ip') == 'fd00:ab5d::15'
            and parent.get('peer_ip') == child.get('peer_ip') == 'fd00:ab5d::2'
            and parent.get('peer_port') == child.get('peer_port') == '4443', 'native IPv6 tuple/family/scope differs')
    setup, grant = one('QUIC IPV6 RX SETUP'), one('QUIC SERVICE GRANT')
    ready, nic_ready = number(setup, 'ready_ms'), number(setup, 'nic_ready_ms')
    require(setup.get('continuous_vm_required') == '1' and 1100 <= ready - nic_ready < 3000
            and number(setup, 'delta_ms') == ready - nic_ready
            and ready <= number(grant, 'before_ms'), 'pre-grant IPv6 NIC settling differs')
    authority = one('QUIC IPV6 CLIENT AUTHORITY')
    require(authority.get('nic') == '0' and authority.get('block') == 'false'
            and 0 < number(authority, 'input') != number(authority, 'output') > 0,
            'IPv6 child authority is not the distinct pipe pair')
    begin, counts, exited, retired = (one(prefix) for prefix in
        ('QUIC BEGIN', 'QUIC FIXTURE NATIVE_COUNTS', 'QUIC CHILD EXIT', 'QUIC SERVICE RETIRE'))
    # The parent publishes the buffered child report after reaping. Validate
    # each producer's order without mistaking publication for event time.
    orders = [('QUIC SERVICE SELECTOR', 'QUIC IPV6 RX SETUP', 'QUIC SERVICE FAMILY', 'QUIC SERVICE GRANT',
               'QUIC CHILD EXIT', 'QUIC SERVICE RETIRE', 'QUIC SERVICE DONE'),
              ('QUIC TRANSPORT', 'QUIC BEGIN', 'QUIC IPV6 CLIENT AUTHORITY', 'QUIC RESULT')]
    positions = {}
    for order in orders:
        for prefix in order:
            one(prefix)
            positions[prefix] = next(i for i, row in enumerate(output.splitlines()) if row.startswith(prefix + ' '))
        require([positions[p] for p in order] == sorted(positions[p] for p in order),
                'IPv6 parent or child record order differs')
    require(positions['QUIC SERVICE GRANT'] < positions['QUIC TRANSPORT']
            and positions['QUIC RESULT'] < positions['QUIC SERVICE RETIRE'], 'IPv6 child report outside owned grant publication')
    start, expiry, deadline = (number(begin, key) for key in ('start_ms', 'grant_expiry_ms', 'deadline_ms'))
    require(number(grant, 'before_ms') <= number(grant, 'constructed_ms') <= start
            and expiry == number(grant, 'owner_expiry_ms') == number(grant, 'before_ms') + 15000
            and number(report, 'start_ms') == start and number(report, 'deadline_ms') == deadline
            and number(report, 'grant_expiry_ms') == expiry and start <= number(report, 'fence_ms') <= number(report, 'end_ms') < deadline
            and report.get('phase') == 'Fenced' and boolean(report, 'pipe_fenced')
            and number(report, 'sends_after_fence') == 0 and not boolean(report, 'unknown_send'),
            'IPv6 original grant, deadline or final fence differs')
    require(number(exited, 'kind') == 1 and number(exited, 'status') == 0 and not boolean(exited, 'killed')
            and number(retired, 'sockets_before_fence') == number(retired, 'sockets_after_fence') == 0,
            'IPv6 child exit or socket retirement differs')
    sent, received = records(output, 'QUIC FIXTURE SEND', case), records(output, 'QUIC FIXTURE RX', case)
    require(number(counts, 'send_requests') == len(sent) == number(report, 'send_calls')
            and number(counts, 'receive_delivered') == len(received) == number(report, 'received')
            and number(counts, 'sends_after_owner_expiry') == number(counts, 'partial_request_bytes') == number(counts, 'partial_reply_bytes') == 0
            and all(row.get('family') == '6' and row.get('scope') == '1' for row in sent + received)
            and number(report, 'send_accepted') <= 256 and number(report, 'send_bytes') <= 307200,
            'IPv6 complete framed IPC census or budget differs')
    if case['id'] != 'Q17':
        require(len(wire['guest_udp']) == number(report, 'send_accepted')
                and sum(row['bytes'] for row in wire['guest_udp']) == number(report, 'send_bytes'),
                'accepted IPv6 SEND count/bytes differ from complete capture')
    if case['id'] == 'Q17':
        require(len(sent) == 1 and not received and number(sent[0], 'ordinal') == 1
                and sent[0].get('peer_ip') == 'fd00:ab5d::2' and number(sent[0], 'peer_port') == 4444
                and start <= number(sent[0], 'at_ms') < expiry
                and report['native_failure_kind'] == 'Native' and report['native_error_code'] == '2'
                and report['native_error_detail'] == report['transport_error_code'] == 'none'
                and all(number(report, key) == 0 for key in ('send_accepted', 'send_bytes', 'received', 'receive_bytes',
                    'receive_calls', 'engine_transmits', 'entropy_attempts', 'sent_stream', 'received_stream', 'close_calls'))
                and not boolean(report, 'authenticated') and not boolean(report, 'request_fin') and not boolean(report, 'peer_fin')
                and wire['guest_udp_count'] == wire['peer_udp_count'] == 0 and not wire['nd'],
                'one pre-engine capability-mediated IPv6 SEND refusal was not established')


def verify_unknown_completion(case, output, fixture, wire, report, grant, begin):
    require(case['id'] == 'Q20' and case['peer_mode'] == 'unknown-send'
            and case['local_port'] == 7819 and case['suppress_reply'] is True,
            'Q20 exact completion-loss case differs')
    setup = records(output, 'QUIC Q20 RX SETUP', case)
    require(len(setup) == 1 and number(setup[0], 'continuous_vm_required') == 1
            and number(setup[0], 'ready_ms') >= number(setup[0], 'nic_ready_ms')
            and 1100 <= number(setup[0], 'delta_ms') ==
                number(setup[0], 'ready_ms') - number(setup[0], 'nic_ready_ms') < 3000
            and number(setup[0], 'ready_ms') <= number(grant, 'before_ms'),
            'Q20 bounded continuous pre-grant NIC settling absent')
    suppressed = records(output, 'QUIC FIXTURE SUPPRESSED_REPLY', case)
    sent = records(output, 'QUIC FIXTURE SEND', case)
    counts = records(output, 'QUIC FIXTURE NATIVE_COUNTS', case)
    exits = records(output, 'QUIC CHILD EXIT', case)
    require(len(suppressed) == len(sent) == len(counts) == len(exits) == 1
            and not records(output, 'QUIC FIXTURE RX', case),
            'Q20 requires one request, one suppressed reply and no successful RECEIVE')
    require(number(suppressed[0], 'opcode') == 1 and number(suppressed[0], 'status') == 0
            and number(suppressed[0], 'framed_bytes') == 14,
            'Q20 complete successful SEND reply was not suppressed')
    require(report['outcome'] == 'Native' and report['native_failure_kind'] == 'Unknown'
            and report['native_error_code'] == report['transport_error_code'] == 'none'
            and report['native_error_detail'] == '-110'
            and boolean(report, 'unknown_send') and boolean(report, 'pipe_fenced')
            and not boolean(report, 'close_accepted'), 'Q20 unknown completion and fence differ')
    require(number(report, 'send_calls') == number(report, 'engine_transmits') == 1
            and all(number(report, k) == 0 for k in ('send_accepted', 'send_bytes', 'exhausted',
                'received', 'receive_bytes', 'close_calls', 'sends_after_fence', 'sent_stream', 'received_stream'))
            and not any(boolean(report, k) for k in ('authenticated', 'request_fin', 'peer_fin',
                'request_acked', 'connection_drained'))
            and number(report, 'entropy_attempts') == 1,
            'Q20 retried, hid an acceptance, or reached application work')
    require(number(sent[0], 'ordinal') == 1 and number(sent[0], 'bytes') == 1200
            and sent[0].get('peer_ip') == '10.0.2.2' and number(sent[0], 'peer_port') == 4443
            and number(counts[0], 'send_requests') == 1
            and all(number(counts[0], k) == 0 for k in ('receive_delivered', 'sends_after_owner_expiry',
                'partial_request_bytes', 'partial_reply_bytes')),
            'Q20 exact one-request service census differs')
    require(number(exits[0], 'kind') == 1 and number(exits[0], 'status') == 0
            and not boolean(exits[0], 'killed'), 'Q20 child did not exit normally')
    start, expiry = number(begin, 'start_ms'), number(begin, 'grant_expiry_ms')
    require(number(grant, 'local_port') == 7819 and number(grant, 'peer_port') == 4443
            and number(grant, 'before_ms') <= number(grant, 'constructed_ms') <= start
            and expiry == number(grant, 'owner_expiry_ms') == number(grant, 'before_ms') + 15000
            and number(report, 'start_ms') == start and number(report, 'grant_expiry_ms') == expiry
            and number(report, 'deadline_ms') == number(begin, 'deadline_ms') == min(start + 10000, expiry)
            and start <= number(report, 'last_send_ms') <= number(sent[0], 'at_ms')
                <= number(suppressed[0], 'at_ms') <= number(report, 'fence_ms')
                <= number(report, 'end_ms') <= number(report, 'deadline_ms'),
            'Q20 request/suppression/fence order or original lifetime differs')
    events = fixture['events']
    received = [e for e in events if e['event'] == 'udp-receive']
    initial = [e for e in events if e['event'] == 'initial-observed']
    sink = [e for e in events if e['event'] == 'q20-initial-sink']
    require(fixture.get('completion_policy') == 'q20-one-initial-sink-v1'
            and fixture.get('case') == 'Q20' and fixture.get('mode') == 'unknown-send'
            and fixture.get('engine_constructed') is False and fixture.get('certificate_selection') is None
            and len(received) == len(initial) == len(sink) == len(wire['guest_udp']) == 1
            and not wire['peer_udp'] and not any(e['event'] == 'udp-send' for e in events)
            and events.index(received[0]) < events.index(initial[0]) < events.index(sink[0])
            and initial[0].get('quic_version') == 1 and initial[0].get('engine_delivered') is False
            and initial[0]['receive_ordinal'] == 1
            and sink[0].get('policy') == 'q20-one-initial-sink-v1'
            and sink[0].get('engine_constructed') is False and sink[0]['response_datagrams'] == 0
            and received[0]['source'] == ['10.0.2.15', 7819]
            and all(e['bytes'] == 1200 and e['sha256'] == wire['guest_udp'][0]['sha256']
                    for e in (received[0], initial[0], sink[0]))
            and wire['guest_udp'][0]['bytes'] == 1200
            and wire['guest_udp'][0]['source'] == ['10.0.2.15', 7819]
            and wire['guest_udp'][0]['destination'] == ['10.0.2.2', 4443]
            and fixture['rx_datagrams'] == 1 and fixture['rx_bytes'] == 1200
            and fixture['tx_datagrams'] == fixture['tx_bytes'] == 0 and fixture.get('terminated') is None,
            'NOT_ESTABLISHED: Q20 single effected Initial/independent sink correspondence absent')
    require(not fixture['authenticated'] and fixture['request_bytes'] == fixture['echo_enqueued_bytes'] == 0
            and not fixture['request_fin'] and not fixture['echo_fin_enqueued'],
            'Q20 independent sink reported application work')




def conditional_prerequisite(admission, ordinary):
    """Verify a finite exact30-case union and its actual ended contributors.

    The independently reviewed receipt lists occurrences(run, unit, invocation_id,
    unit_identity_path/sha256) and rows(case, run, result_path/sha256,
    inputs_path/sha256). Paths are derived from the sealed ordinary_registry.
    Successful transient collection is allowed only with original UNIT custody;
    a live/different InvocationID never satisfies the prerequisite.
    """
    item=admission['conditional_ordinary_eligibility']
    require(sha(item['path'])==item['sha256'],'conditional eligibility receipt differs')
    receipt=json.loads(Path(item['path']).read_text())
    registry=Path(admission['ordinary_registry']).resolve(strict=True)
    occurrences=receipt['occurrences']
    run_ids=[row['run']for row in occurrences]
    require(run_ids and len(set(run_ids))==len(run_ids) and
            all(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',run)for run in run_ids),
            'distinct ordinary contributor identities required')
    for occurrence in occurrences:
        run=occurrence['run']
        require(occurrence['unit']=='absd-s2-quic-validate-'+run[:8]+'.service',
                'ordinary unit is not bound to contributor')
        identity=Path(occurrence['unit_identity_path']).resolve(strict=True)
        expected=registry/run/'evidence/UNIT.json'
        require(identity==expected.resolve(strict=True) and sha(identity)==occurrence['unit_identity_sha256'],
                'original contributor UNIT custody differs')
        original=json.loads(identity.read_text())
        require(original['invocation_id']==occurrence['invocation_id'], 'contributor invocation identity differs')
        result=subprocess.run(['/usr/bin/systemctl','show',occurrence['unit'],
              '--property=MainPID,ControlPID,InvocationID,ActiveState,LoadState'],
              text=True,capture_output=True,timeout=10,check=True)
        properties=dict(line.split('=',1)for line in result.stdout.splitlines()if'='in line)
        require(properties.get('MainPID')=='0' and properties.get('ControlPID')=='0',
                'ordinary contributor remains live')
        require(properties.get('InvocationID')==occurrence['invocation_id'] or
                properties.get('InvocationID')=='' and properties.get('LoadState')=='not-found' and
                properties.get('ActiveState')=='inactive', 'ordinary unit was replaced or is indeterminate')
    rows=receipt['rows']
    require(len(rows)==30 and {row['case']for row in rows}=={case['id']for case in ordinary},
            'ordinary finite30-case union incomplete/duplicated')
    contributors=set()
    for row in rows:
        require(row['run']in run_ids,'PASS row has no ended ordinary contributor')
        contributors.add(row['run'])
        case=next(case for case in ordinary if case['id']==row['case'])
        expected=registry/row['run']/'evidence/native-matrix'/case['id']
        result_path=Path(row['result_path']).resolve(strict=True)
        inputs_path=Path(row['inputs_path']).resolve(strict=True)
        require(result_path==(expected/'RESULT.json').resolve(strict=True) and
                inputs_path==(expected/'CASE-INPUTS.json').resolve(strict=True) and
                sha(result_path)==row['result_sha256'] and sha(inputs_path)==row['inputs_sha256'],
                'PASS row paths/hash are not its listed contributor')
        result=json.loads(result_path.read_text());inputs=json.loads(inputs_path.read_text())
        require(result['case']==case['id'] and result['disposition']=='PASS' and result['ABSD_execution'] is True,
                'ordinary case lacks actual native PASS')
        require(inputs['selected_case']==case and inputs['case_manifest_sha256']==admission['case_manifest_sha256'] and
                inputs['client_elf']['sha256']==admission['client_sha256'],'ordinary case/client correspondence differs')
        for name, expected_source in admission['sources'].items():
            source=inputs['source'][name]
            require(source['revision']==expected_source['revision'] and source['tree']==expected_source['tree'] and
                    source['dirty_state']=='' and source['clean_required'] is True,
                    'ordinary source correspondence differs')
    require(contributors==set(run_ids),'ordinary ended identities are disconnected from PASS rows')
    return {'receipt_sha256':item['sha256'],'ordinary_case_ids':[case['id']for case in ordinary],
            'ended_contributors':run_ids,'ordinary_rows_checked':30}


def qmp_link_down(path, expected_pid, receipt):
    observed = {'schema_version':1,'time':now(),'socket':str(path),'expected_qemu_pid':expected_pid,
                'device_id':'quicnic','qmp_acknowledged':False,'exchanges':[]}
    try:
        value = path.lstat()
        require(stat.S_ISSOCK(value.st_mode) and value.st_uid == os.geteuid(), 'exact owned QMP socket absent')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
            channel.settimeout(2)
            channel.connect(str(path))
            pid, uid, gid = struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(pid == expected_pid and uid == os.geteuid(), 'QMP peer differs from exact guest process')
            observed['socket_peer'] = {'pid':pid,'uid':uid,'gid':gid}
            with channel.makefile('rb') as source:
                def read():
                    raw=source.readline(16385)
                    require(raw.endswith(b'\n') and len(raw)<=16384, 'QMP reply bound/framing')
                    return json.loads(raw)
                hello=read()
                verify_qmp_greeting(hello)
                observed['greeting']=hello
                for identity, command in [('capabilities',{'execute':'qmp_capabilities'}),
                                          ('drop-link',{'execute':'set_link','arguments':{'name':'quicnic','up':False}})]:
                    command['id']=identity
                    channel.sendall((json.dumps(command)+'\n').encode())
                    replies=[]
                    for _ in range(32):
                        result=read()
                        require(isinstance(result,dict), 'QMP reply is not an object')
                        replies.append(result)
                        if result.get('id')==identity:
                            require(isinstance(result.get('return'),dict) and 'error' not in result, 'QMP exact command failed')
                            break
                    else:
                        raise RuntimeError('QMP command reply ceiling')
                    observed['exchanges'].append({'command':command,'replies':replies})
                observed['qmp_acknowledged']=True
                observed['acknowledged_monotonic_ns']=time.monotonic_ns()
    except BaseException as error:
        observed['error']={'type':type(error).__name__,'message':str(error)}
        raise
    finally:
        seal(receipt,observed)
    return {'qmp_acknowledged':True,'qmp_receipt':str(receipt),'qmp_receipt_sha256':sha(receipt),
            'exact_qemu_pid':expected_pid,'device_id':'quicnic'}


def verify_parent_build(built, selectors, client_sha256, family='ipv4', source=None, root_sha256=None, client_receipt=None):
    require(family in ('ipv4', 'ipv6'), 'unknown parent transport family')
    require(built['service_selectors'] == {key:selectors[key] for key in ('ABSD_QUIC_CASE','ABSD_QUIC_UNIX_SECONDS')}
            and built['reused_client_sha256'] == client_sha256,
            'actual parent build selector/child receipt differs')
    if family == 'ipv6':
        require(built.get('transport_family') == 'ipv6' and source is not None
                and built.get('source_revision') == source['revision'] and built.get('source_tree') == source['tree']
                and built.get('root_der', {}).get('sha256') == root_sha256
                and built.get('reused_client_receipt') == client_receipt,
                'actual IPv6 parent source/family/root/client receipt differs')


def verify_ipv6_client_receipt(receipt, admission, root):
    source = admission['sources']['platform']
    require(receipt.get('transport_family') == 'ipv6'
            and receipt.get('source_revision') == source['revision'] and receipt.get('source_tree') == source['tree']
            and receipt.get('root_der', {}).get('sha256') == root['sha256']
            and receipt.get('outputs', {}).get('quic_echo', {}).get('sha256') == admission['client_sha256']
            and receipt.get('tracked_dirty') is False and receipt.get('untracked_source') is False,
            'IPv6 child source/family/root/build receipt differs')


def wait_ipv6_guest(producer, measure, work, marker, timeout):
    deadline = time.monotonic() + timeout
    while producer.poll() is None and time.monotonic() < deadline:
        marker.poll(True)
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))
    # Preserve the existing measured terminal record and timeout/exit semantics.
    measure.wait_process(producer, work / 'QEMU-EXIT.json', max(0.001, deadline - time.monotonic()), expected_returncode=3)
    marker.poll(False)
    annotation = marker.seal(work)
    require(annotation['previous_absent'] is not None and annotation['observation'] is not None
            and annotation['observation']['producer_observed_running'] is True,
            'NIC ready line was not observed while the original guest was running')


def ipv6_nic_counters(raw, case):
    rows = re.findall(rb'(?m)^NIC STATS ([^\n]+)\n', raw)
    require(len(rows) == raw.count(b'NIC STATS ') == 1, 'one raw NIC counter snapshot required')
    counters = fields(rows[0].decode('ascii'))
    require(counters.get('flags') == '1', 'NIC is not link-up without disabled')
    for key in ('rx_frames', 'tx_frames', 'rx_refused', 'rx_missed', 'tx_refused', 'tx_errors'):
        number(counters, key)
    if case['id'] != 'Q17':
        require(number(counters, 'rx_frames') > 0 and number(counters, 'tx_frames') > 0,
                'native IPv6 case has no NIC progress')
    return counters


def native_case(case, args, admission, pki, peer_module, measure, helpers, manifest):
    family = args.family
    work = args.work / case['id']
    work.mkdir(mode=0o700,exist_ok=False)
    source = {key:measure.git_identity(value['path'],value['revision'],value['tree'])
              for key,value in admission['sources'].items()}
    child = Path(admission['client_elf'])
    root = pki['root_der']
    require(sha(child) == admission['client_sha256'] and sha(root['path']) == root['sha256'], 'client/root identity differs')
    require(Path(root['path']).read_bytes() in child.read_bytes(), 'exact public root absent from child')
    if family == 'ipv6':
        receipt = admission['client_build_receipt']
        require(set(receipt) == {'path', 'sha256'} and not Path(receipt['path']).is_symlink()
                and sha(receipt['path']) == receipt['sha256'], 'exact child build receipt differs')
        verify_ipv6_client_receipt(json.loads(Path(receipt['path']).read_text()), admission, root)
    environment = measure.private_environment(admission['environment'])
    selectors = {'ABSD_QUIC_CASE':case['id'], 'ABSD_QUIC_UNIX_SECONDS':str(pki['validation_unix_time']),
                 'ABSD_QUIC_CLIENT_ELF':str(child), 'ABSD_QUIC_CLIENT_SHA256':admission['client_sha256'], 'ABSD_QUIC_ROOT_DER':root['path'], 'ABSD_QUIC_ROOT_SHA256':root['sha256']}
    environment.update(selectors)
    seal(work/'CASE-INPUTS.json', {'schema_version':1, 'time':now(), 'selected_case':case, 'source':source,
                                 'client_elf':measure.identity(child), 'root':root,
                                 'child_case_source':'Runtime --case argument from selected parent; client-only ELF has no compile-time case selector.',
                                 'case_manifest_sha256':sha(args.manifest), 'selectors':selectors,
                                 'readiness_profile':development_profile(case, family),'canonical_campaign_acceptance':False,
                                 'transport_family':family,
                                 'wire_source_sha256':sha(Path(__file__).with_name('native-quic-ipv6-wire.py' if family == 'ipv6' else 'native-quic-wire.py')),
                                 'wire_macs':admission['wire_macs']})
    owned = allocation(admission['owned_allocation_roots'])
    require(owned + admission['expected_new_per_case_bytes'] <= admission['remote_allocation_ceiling_bytes'] <= 12 * 1024**3,
            'aggregate owned storage admission failed')
    measure.capacity('/', admission['expected_new_per_case_bytes'])
    seal(work/'STORAGE-ADMISSION.json', {'time':now(), 'actual_owned_allocated_bytes':owned,
                                      'expected_new_bytes':admission['expected_new_per_case_bytes'],
                                      'ceiling_bytes':admission['remote_allocation_ceiling_bytes']})
    build_argv = [value.replace('{case_work}', str(work.resolve())) for value in admission['parent_build_argv']]
    require(all('{' not in value and '}' not in value for value in build_argv), 'unresolved parent builder template')
    require(build_argv.count('--receipt') == 1 and Path(build_argv[build_argv.index('--receipt') + 1]) == work.resolve()/'NATIVE-BUILD.json',
            'parent build must retain an exact per-case receipt')
    if family == 'ipv6':
        require(build_argv.count('--family') == build_argv.count('--client-receipt') == 1
                and build_argv[build_argv.index('--family') + 1] == 'ipv6'
                and build_argv[build_argv.index('--client-receipt') + 1] == admission['client_build_receipt']['path'],
                'IPv6 parent construction must bind explicit family and child receipt')
    build = measure.start_process(build_argv,args.source,work/'parent-build.log',environment,
                                  work/'PARENT-BUILD-LAUNCH.json',{'case':case,'selectors':selectors})
    measure.wait_process(build,work/'PARENT-BUILD-EXIT.json',admission['parent_build_timeout_seconds'])
    built = json.loads((work/'NATIVE-BUILD.json').read_text())
    verify_parent_build(built, selectors, admission['client_sha256'], family,
                        source['platform'], root['sha256'], admission.get('client_build_receipt'))
    parent = Path(admission['parent_elf'])
    require(sha(child) == admission['client_sha256'] and child.read_bytes() in parent.read_bytes(), 'parent exact child custody differs')
    old_environment = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(environment)
        iso, image = helpers.build_iso(str(args.kernel),str(parent),str(work),1)
    finally:
        os.environ.clear()
        os.environ.update(old_environment)
    kernel = args.kernel/'build/external/target/debug/absd-kernel'
    boot = measure.iso_identity(iso,kernel,work/'boot-extracted',work/'BOOT-INPUTS.json',embedded_elfs=[child,parent])
    serial, capture = work/'quic.serial.log', work/'quic.pcap'
    qmp = work/'quic.qmp'
    require(not qmp.exists(), 'fresh QMP path already occupied')
    argv = served_qemu([admission['qemu'],'-accel','tcg,thread=single','-cpu','Haswell,-rdrand' if case['id']=='Q31' else 'Haswell,+rdrand',
            '-smp','1','-m','256M','-cdrom',iso,'-drive','file='+image+',format=raw,if=ide,index=0',
            '-display','none','-serial','file:'+str(serial),'-no-reboot','-no-shutdown',
            '-device','isa-debug-exit,iobase=0xf4,iosize=0x04','-device','e1000,id=quicnic,netdev=n0,mac='+admission['wire_macs']['guest'],
            '-netdev','tap,id=n0,ifname='+admission['tap']+',script=no,downscript=no',
            '-object','filter-dump,id=quicdump,netdev=n0,file='+str(capture)])
    if case['id'] == 'Q24':
        argv += ['-qmp','unix:'+str(qmp)+',server=on,wait=off']
    producer = None
    producer_ready = threading.Event()
    def link_action():
        require(producer_ready.wait(2), 'exact guest launch identity not ready for link action')
        require(producer is not None and producer.poll() is None, 'exact guest ended before link action')
        return qmp_link_down(qmp, producer.pid, work/'QMP-LINK.json')
    reasons = ipv6_accounting(case) if family == 'ipv6' else None
    marker = reasons.ReadyMarker(serial, capture) if reasons is not None else None
    if marker is not None:
        require(sha(args.kernel / 'src/e1000_ring.rs') == reasons.original.POLICY['source_sha256'],
                'actual kernel NIC filter source differs from fixed accounting policy')
        marker.poll(False)
    peer_kwargs = {'timeout':admission['peer_timeout_seconds'], 'startup_timeout':admission['boot_timeout_seconds']}
    if case['id'] == 'Q24':
        peer_kwargs['link_action'] = link_action
    if case['id'] in ('Q25', 'Q26', 'Q27', 'Q28'):
        peer_kwargs.update(icmp_interface=admission['tap'],
                           icmp_guest_mac=admission['wire_macs']['guest'],
                           icmp_peer_mac=admission['wire_macs']['peer'])
    if case['id'] == 'Q05':
        peer_kwargs['reorder_stage'] = args.reorder_stage
    if family == 'ipv6':
        peer_kwargs['family'] = family
    peer = peer_module.Peer(case,pki,'fd00:ab5d::2' if family == 'ipv6' else '10.0.2.2',4443,
                            ('fd00:ab5d::15' if family == 'ipv6' else '10.0.2.15',case['local_port']), **peer_kwargs)
    try:
        measured = {key:measure.git_identity(value['path'],value['revision'],value['tree'])
                    for key,value in admission['sources'].items()}
        producer = measure.start_qemu(argv,work,work/'qemu.log',environment,work/'QEMU-LAUNCH.json',boot,measured,
                                      missing_rdrand=case['id']=='Q31')
        producer_ready.set()
        if family == 'ipv6':
            wait_ipv6_guest(producer, measure, work, marker, admission['boot_timeout_seconds'])
        else:
            measure.wait_process(producer,work/'QEMU-EXIT.json',admission['boot_timeout_seconds'],expected_returncode=3)
        helpers.finish_boot(producer,str(serial),re.escape(('QUIC SERVICE DONE case='+case['id']+' sockets=0').encode()))
    finally:
        if producer is not None and producer.poll() is None:
            measure.stop_owned_group(producer)
        try:
            peer.close()
        finally:
            seal(work/'FIXTURE.json',peer.report())
            if qmp.exists():
                value=qmp.lstat()
                require(stat.S_ISSOCK(value.st_mode) and value.st_uid==os.geteuid(), 'unexpected retired QMP path')
                qmp.unlink()
            output = helpers.stdout_of(str(serial)).decode(errors='replace') if serial.exists() else ''
            (work/'native.stdout.log').write_text(output)
            seal(work/'CASE-END.json',{'time':now(), 'case':case['id'],
                'qemu_wait_returncode':producer.returncode if producer is not None else None,
                'cpu_observation_present':any(line.startswith('QUIC CPU ') for line in output.splitlines()),
                'consumer_begin_present':any(line.startswith('QUIC BEGIN case='+case['id']+' ') for line in output.splitlines()),
                'serial_sha256':sha(serial) if serial.exists() else None,
                'pcap_sha256':sha(capture) if capture.exists() else None})
    output = (work/'native.stdout.log').read_text()
    wire = wire_observations(capture,case,admission['wire_macs'],family)
    seal(work/'WIRE.json',wire)
    if case['id'] == 'Q24':
        verify_qmp_link_receipt(peer.report(),work/'QMP-LINK.json',producer.pid,qmp)
    # Refusal and engine-free peers select no server certificate. Their
    # selected peer verifier requires the actual certificate selection absent.
    if case['id'] not in ('Q17', 'Q07', 'Q14', 'Q21', 'Q23', 'Q24', 'Q25', 'Q26', 'Q27', 'Q28', 'Q29', 'Q30', 'Q31'):
        verify_certificate_selection(case,peer.report(),pki)
    observed = verify_native(case,output,peer.report(),wire,manifest,family,reorder_stage=args.reorder_stage)
    accounting_result = None
    if family == 'ipv6':
        counters = ipv6_nic_counters(serial.read_bytes(), case)
        accounting_result = reasons.evaluate(work, marker, counters, admission['wire_macs']['guest'], admission['wire_macs']['peer'], 'quic6')
    result = {'schema_version':1,'time':now(),'case':case['id'],'disposition':'PASS',
              'ABSD_execution':True,'readiness_profile':development_profile(case,family),'transport_family':family,
              'canonical_campaign_acceptance':False,'observed':observed,'measured_qemu_exit':producer.returncode,
              'boot_inputs':boot,'fixture_sha256':sha(work/'FIXTURE.json'),'wire_sha256':sha(work/'WIRE.json')}
    if accounting_result is not None:
        result.update(reason_accounting=accounting_result, nic_ready_capture_sha256=sha(work/'NIC-READY-CAPTURE.json'),
                      reason_accounting_sha256=sha(work/'NIC-REASON-ACCOUNTING.json'))
    seal(work/'RESULT.json',result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admission',type=Path,required=True)
    parser.add_argument('--profile', choices=['q01-development', 'q12-truncated-header-development', 'q13-invalid-tag-development', 'q02-partial-ipc-development', 'q03-initial-loss-development', 'q04-stream-loss-development', 'q05-duplicate-reorder-development', 'q06-flow-pause-development', 'q07-silent-development', 'q08-wrong-root-development', 'q14-long-retry-development', 'q15-stream-limit-development', 'q16-unknown-cid-development', 'q18-unauthorized-source-development', 'q09-wrong-name-development', 'q10-expired-development', 'q11-wrong-alpn-development', 'q19-queue-exhausted-development', 'q20-unknown-send-development',
                                            'q21-interrupt-handshake-development', 'q22-interrupt-stream-development',
                                            'q23-owner-expiry-development', 'q24-link-failure-development', 'q29-missing-output-development', 'q30-missing-time-development', 'q31-absent-rdrand-development', 'q17-denied-destination-development',
                                            'q25-icmp-576-development', 'q26-icmp-1227-development', 'q27-icmp-1200-development', 'q28-icmp-zero-development',
                                            'q01-ipv6-development', 'q08-ipv6-development', 'q17-ipv6-development'], required=True)
    parser.add_argument('--family', choices=('ipv4', 'ipv6'), default='ipv4')
    parser.add_argument('--reorder-stage', choices=('initial', 'post-handshake'), default='initial')
    parser.add_argument('--pki',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--controls',action='store_true')
    parser.add_argument('--source',type=Path)
    parser.add_argument('--kernel',type=Path)
    parser.add_argument('--measure-tools',type=Path)
    parser.add_argument('--case',action='append',default=[])
    args = parser.parse_args()
    require(not sys.flags.optimize and not os.environ.get('PYTHONOPTIMIZE'), 'optimized Python is refused')
    admission = json.loads(args.admission.read_text())
    require(admission.get('readiness_profile') == args.profile, 'explicit limited profile differs')
    require(admission.get('transport_family', 'ipv4') == args.family, 'explicit transport family differs')
    require(admission.get('reorder_stage', 'initial') == args.reorder_stage
            and (args.reorder_stage == 'initial' or args.profile == 'q05-duplicate-reorder-development'
                 and args.family == 'ipv4'), 'explicit Q05 reorder stage differs')
    peer_path = Path(__file__).with_name('native-quic-q01-peer.py')
    require(admission.get('disposition') == 'GO' and admission.get('runner_source_sha256') == sha(__file__) and
            admission.get('peer_source_sha256') == sha(peer_path), 'exact runner/peer source admission is held')
    wire_path = Path(__file__).with_name('native-quic-ipv6-wire.py' if args.family == 'ipv6' else 'native-quic-wire.py')
    require(admission.get('wire_source_sha256') == sha(wire_path), 'exact wire census source differs')
    if args.family == 'ipv6':
        require(sha(wire_path) == IPV6_PINS[wire_path.name]
                and admission.get('accounting_source_sha256') == IPV6_PINS['native-ipv6-accounting.py']
                and admission.get('reason_accounting_source_sha256') == IPV6_PINS['native-ipv6-reason-accounting.py'],
                'explicit pinned IPv6 classifier/accounting sources differ')
    require(os.geteuid() == 0 and sha(sys.executable)==admission['python_sha256'] and
            socket.gethostname() == admission['host_name'] and
            Path('/etc/machine-id').read_text().strip() == admission['machine_id'], 'exact isolated host identity differs')
    require(admission.get('peer_controls_go' if args.controls else 'native_execution_go') is True, 'execution remains held')
    require(admission['minimum_remaining_before_case_seconds'] >= 1200, 'cleanup reserve below admitted20minutes')
    require(admission['review_records'] and all(sha(row['path']) == row['sha256'] for row in admission['review_records']),
            'reviewed source/closure records differ')
    require(sha(args.manifest) == admission['case_manifest_sha256'], 'case manifest differs')
    manifest = json.loads(args.manifest.read_text())
    ordinary = manifest['native_occurrences']
    conditional = manifest['conditional_native_occurrences']
    require([row['id'] for row in ordinary] == ['Q%02d'%i for i in range(1,31)] and
            [row['id'] for row in conditional] == ['Q31'], 'explicit finite case set differs')
    all_cases = {case['id']:case for case in ordinary + conditional}
    original_peer_controls = ['Q%02d'%i for i in range(1,17)] + ['Q18']
    selected, peer_controls, execution_profile = select_development_cases(
        all_cases, args.profile, args.family, args.controls, args.case)
    require('Q31' not in selected or selected == ['Q31'], 'conditional missing-RDRAND must be a separate occurrence')
    pki = json.loads(args.pki.read_text())
    require(pki['private_keys_in_evidence'] is False, 'private fixture keys in ordinary evidence')
    require(all(sha(row['path']) == row['sha256'] for row in [*pki['public_certificates'],*pki['leaf_certificates'].values(),pki['root_der']]),
            'public PKI identities differ')
    require(abs(time.time()-pki['validation_unix_time']) < 14400, 'fixture anchor outside bounded occurrence')
    args.work.mkdir(exist_ok=False)
    results, attempted = [], []
    disposition, error = 'FAIL', None
    peer_module = module('native_quic_peer',peer_path)
    try:
        peer_module.validate_pki(pki)
        runtime = peer_module.verify_runtime(admission['peer_closure_path'],admission['peer_closure_sha256'],admission['peer_site_packages'])
        seal(args.work/'RUNTIME.json',runtime)
        measure = helpers = None
        if not args.controls:
            require(args.source and args.kernel and args.measure_tools, 'native source/kernel/measurement paths required')
            require(set(admission['sources']) == {'platform','kernel'} and
                    args.source.resolve() == Path(admission['sources']['platform']['path']).resolve() and
                    args.kernel.resolve() == Path(admission['sources']['kernel']['path']).resolve(), 'source argument correspondence differs')
            require(admission['wire_macs']['guest'] == '52:54:00:12:34:56' and
                    Path('/sys/class/net', admission['tap'], 'address').read_text().strip() == admission['wire_macs']['peer'],
                    'pinned guest/TAP MAC identities differ')
            require(sha(args.measure_tools) == admission['measure_sha256'] and
                    sha(args.source/'scripts/net-matrix.py') == admission['net_helper_sha256'], 'measured execution helpers differ')
            controls = admission['linux_controls_result']
            require(sha(controls['path']) == controls['sha256'], 'independent Linux controls receipt differs')
            control_result = json.loads(Path(controls['path']).read_text())
            require(control_result['disposition'] == 'PASS' and control_result['completed_case_ids'] == peer_controls
                    and control_result.get('requested_case_ids') == peer_controls
                    and control_result.get('attempted_case_ids') == peer_controls
                    and control_result.get('missing_requested_case_ids') == [] and control_result.get('error') is None and
                    control_result['peer_source_sha256'] == sha(peer_path) and control_result['case_manifest_sha256'] == sha(args.manifest)
                    and control_result.get('runner_source_sha256') == sha(__file__)
                    and control_result.get('readiness_profile') == development_profile(all_cases[peer_controls[0]], args.family)
                    and control_result.get('canonical_campaign_acceptance') is False
                    and control_result.get('reorder_stage', 'initial') == args.reorder_stage
                    and control_result.get('ABSD_execution') is False
                    and control_result.get('peer_closure_sha256') == admission['peer_closure_sha256']
                    and control_result.get('root_der_sha256') == pki['root_der']['sha256']
                    and control_result.get('pki_manifest_sha256') == sha(args.pki)
                    and (args.family != 'ipv6' or control_result.get('transport_family') == 'ipv6'),
                    'independent limited Q01 control is incomplete or differently bound')
            measure = module('quic_measure',args.measure_tools)
            helpers = module('quic_net_helper',args.source/'scripts/net-matrix.py')
            if selected == ['Q31']:
                eligibility=conditional_prerequisite(admission,ordinary)
                seal(args.work/'CONDITIONAL-PREREQUISITE.json',eligibility)
        for identity in selected:
            if admission['absolute_deletion_deadline_epoch'] - time.time() < admission['minimum_remaining_before_case_seconds']:
                disposition = 'INCOMPLETE'
                raise RuntimeError('lease margin exhausted; remaining cases NOT_RUN')
            attempted.append(identity)
            case = all_cases[identity]
            if args.controls:
                control_kwargs = {'timeout':admission['peer_timeout_seconds']}
                if identity == 'Q05':
                    control_kwargs['reorder_stage'] = args.reorder_stage
                if args.family == 'ipv6':
                    control_kwargs['family'] = 'ipv6'
                observed = peer_module.linux_control(case,pki,**control_kwargs)
                # Retain failed reference observations before checking any predicate.
                seal(args.work/(identity+'.observation.json'),observed)
                expected = 'Deadline' if identity in ('Q07','Q14','Q21','Q22','Q23') else case['expected_outcome']
                require(not observed['error'] and not observed['fixture']['errors'] and observed['actual_outcome'] == expected,
                        'independent Linux control failed: '+identity)
                if expected == 'Complete':
                    require(observed['fixture']['request_bytes'] == 4096 and observed['fixture']['request_fin'] and
                            observed['fixture']['echo_fin_enqueued'] and observed['peer_fin'], 'independent Linux FIN/body control absent')
                if identity == 'Q03':
                    verify_initial_loss(observed['fixture'])
                if identity == 'Q04':
                    verify_stream_loss(observed['fixture'])
                if identity == 'Q13':
                    verify_invalid_tag(case, observed['fixture'], client_datagrams=observed.get('client_datagrams'))
                if identity == 'Q07':
                    verify_silent(observed['fixture'])
                if identity == 'Q14':
                    verify_long_retry(observed['fixture'])
                if identity in ('Q21', 'Q22'):
                    verify_interruption_peer(case, observed['fixture'])
                    require(observed.get('authenticated') is (identity == 'Q22')
                            and observed.get('received_bytes') == 0 and observed.get('peer_fin') is False,
                            'Linux interruption fixture calibration completed or echoed data')
                    delivered = observed.get('client_datagrams')
                    sent = [row for row in observed['fixture']['events'] if row['event'] == 'udp-send']
                    require(isinstance(delivered, list) and len(delivered) == len(sent)
                            and [json_integer(row, 'ordinal') for row in delivered] == list(range(1, len(delivered) + 1))
                            and all(row.get('engine_delivered') is True for row in delivered)
                            and [(row['bytes'], row['sha256'], row['source']) for row in delivered] ==
                                [(row['bytes'], row['sha256'], row['source']) for row in sent],
                            'Linux interruption complete public input/peer output correspondence differs')
                    if identity == 'Q22':
                        verify_certificate_selection(case, observed['fixture'], pki)
                if identity == 'Q23':
                    verify_linux_owner_expiry(case, observed)
                if identity == 'Q15':
                    verify_stream_limit(observed['fixture'], client_datagrams=observed.get('client_datagrams'))
                    require(observed['authenticated'] and observed['terminal'] is not None
                            and observed['terminal']['error_code'] == 4
                            and observed['terminal']['frame_type'] == 17
                            and observed['received_bytes'] == 0,
                            'Q15 Linux zero-limit calibration did not refuse the selected frame')
                if identity == 'Q16':
                    verify_unknown_cid(observed['fixture'])
                if identity == 'Q18':
                    probe = verify_unauthorized_source(observed['fixture'])
                    filtered = observed.get('unauthorized_filtered_datagrams') or []
                    require(observed.get('unauthorized_source_filtered') == len(filtered) == 1
                            and filtered[0]['sha256'] == probe['sha256'] and filtered[0]['bytes'] == probe['bytes']
                            and filtered[0]['source'][1] == probe['source'][1],
                            'Linux Q18 client did not filter exactly the unauthorized probe')
                if identity == 'Q05':
                    verify_duplicate_reorder(case, observed['fixture'], client_datagrams=observed.get('client_datagrams'),
                                             reorder_stage=args.reorder_stage)
                if identity == 'Q06':
                    verify_flow_pause(case, observed['fixture'])
                if identity == 'Q19':
                    verify_queue_prelude(observed['fixture'])
                if identity == 'Q12':
                    verify_truncated_header(case, observed['fixture'], linux_control=True)
                if identity in ('Q08','Q09','Q10','Q11'):
                    verify_linux_auth_refusal(case, observed, pki, args.family)
                if args.family == 'ipv6':
                    require(observed['fixture'].get('readiness_profile') == execution_profile
                            and observed['fixture'].get('transport_family') == 'ipv6', 'actual Linux IPv6 fixture differs')
                    if identity == 'Q08':
                        verify_ipv6_response_flight(observed['fixture'])
                # Fault establishment is verified separately from a successful echo.
                events = observed['fixture']['events']
                required_event = {'Q03':'initial-drop','Q04':'stream-datagram-drop','Q05':'duplicate-reorder',
                                  'Q06':'q06-pause-release','Q07':'silent-input','Q12':'udp-send','Q13':'tag-mutation','Q14':'retry-fixture',
                                  'Q15':'stream-limit-frame-built','Q16':'unknown-cid-fixture','Q18':'unauthorized-probe'}.get(identity)
                if identity in ('Q21', 'Q22', 'Q23'):
                    required_event = {'Q21':'silent-input', 'Q22':'q22-stream-output-fenced', 'Q23':'expiry-observation-marker'}[identity]
                if required_event:
                    require(any(row['event'] == required_event for row in events), 'Linux fault was not established: '+identity)
                result = {'schema_version':1,'time':now(),'case':identity,'disposition':'PASS','ABSD_execution':False,'readiness_profile':execution_profile,
                          'requested_readiness_profile':args.profile,'transport_family':args.family,
                          'canonical_campaign_acceptance':False,'observation_sha256':sha(args.work/(identity+'.observation.json'))}
                seal(args.work/(identity+'.json'),result)
            else:
                result = native_case(case,args,admission,pki,peer_module,measure,helpers,manifest)
            results.append(result)
        disposition = 'PASS'
    except BaseException as caught:
        error = {'type':type(caught).__name__,'message':str(caught)}
        (args.work/'ERROR.log').write_text(traceback.format_exc())
    finally:
        qemu_records = []
        for identity in attempted if not args.controls else []:
            path = args.work/identity/'CASE-END.json'
            if path.exists():
                qemu_records.append({**json.loads(path.read_text()),'path':str(path),'sha256':sha(path)})
        conditional_record = next((row for row in qemu_records if row['case']=='Q31'),None)
        conditional_status = ('PASS' if selected==['Q31'] and disposition=='PASS' else
                              'NOT_RUN' if 'Q31' not in attempted or conditional_record and
                              not conditional_record['cpu_observation_present'] and not conditional_record['consumer_begin_present'] else 'FAIL')
        seal(args.work/'RESULT.json',{'schema_version':1,'time':now(),'disposition':disposition,'error':error,
            'ABSD_execution':not args.controls,'readiness_profile':execution_profile,
            'requested_readiness_profile':args.profile,'transport_family':args.family,
            'reorder_stage':args.reorder_stage,
            'canonical_campaign_acceptance':False,'original_peer_control_prerequisite':original_peer_controls,
            'omitted_original_peer_controls':[identity for identity in original_peer_controls if identity not in selected],
            'out_of_scope_case_ids':[identity for identity in all_cases if identity not in selected],
            'peer_closure_sha256':admission['peer_closure_sha256'],'pki_manifest_sha256':sha(args.pki),
            'root_der_sha256':pki['root_der']['sha256'],'wire_source_sha256':sha(wire_path),
            'runner_source_sha256':sha(__file__),'peer_source_sha256':sha(peer_path),
            'case_manifest_sha256':sha(args.manifest),'requested_case_ids':selected,'attempted_case_ids':attempted,
            'completed_case_ids':[row['case'] for row in results],
            'unattempted_case_ids':[identity for identity in selected if identity not in attempted],
            'missing_requested_case_ids':[identity for identity in selected if identity not in {row['case'] for row in results}],
            'results':results,'qemu_exit_records':qemu_records,'conditional_Q31_status':conditional_status if not args.controls else 'NOT_ABSD_EXECUTION',
            'private_material_included':False,'limits':['Finite selected protocol fixtures only, not Internet conformance or general congestion control.',
              'Control success is not native execution. Failed or unestablished setup is not native success.',
              'Raw packet emission, UDP queue acceptance, authenticated stream receipt and cleanup remain separate observations.',
              'Unsupported CPU before consumer reach establishes no entropy-refusal coverage.',
              'No migration, HTTP/3, 0-RTT, resumption, application DATAGRAM or live connection state transfer is admitted.']})
    return 0 if disposition == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
