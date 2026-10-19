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
                'Q03':('initial-loss', 'q03-initial-loss-development'),
                'Q08':('wrong-root', 'q08-wrong-root-development'),
                'Q09':('wrong-name', 'q09-wrong-name-development'),
                'Q10':('expired-certificate', 'q10-expired-development'),
                'Q11':('wrong-alpn', 'q11-wrong-alpn-development'),
                'Q19':('queue-exhausted', 'q19-queue-exhausted-development')}
    require(case['id'] in profiles and case['peer_mode'] == profiles[case['id']][0],
            'unsupported bounded development case')
    return profiles[case['id']][1]


def verify_certificate_selection(case, fixture, pki):
    selected = fixture.get('certificate_selection')
    kind = {'Q01':'valid', 'Q03':'valid', 'Q08':'untrusted', 'Q09':'wrong-name', 'Q10':'expired', 'Q11':'valid', 'Q19':'valid'}[case['id']]
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


def verify_fixture(case, fixture, wire, family="ipv4"):
    require(not fixture['errors'] and not fixture['thread_alive'], 'independent peer failed or remains live')
    require(fixture.get('readiness_profile') == development_profile(case, family)
            and fixture.get('canonical_campaign_acceptance') is False, 'limited peer profile differs')
    events = fixture['events']
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
    def event(kind):
        values = [row for row in events if row['event'] == kind]
        require(values, 'NOT_ESTABLISHED: independent fixture event missing: ' + kind)
        return values
    for sent in [row for row in events if row['event'] == 'udp-send']:
        require(any(row['sha256'] == sent['sha256'] and row['source'] == sent['source'] and
                    row['destination'] == sent['destination'] for row in wire['peer_udp']),
                'NOT_ESTABLISHED: independent UDP send absent from actual capture')
    if mode == 'queue-exhausted':
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
        lost = event('application-datagram-drop')
        require(len(lost) == 1 and lost[0]['built_stream_bytes'] > 0, 'application datagram loss was not established')
        # The selected datagram is intentionally not sent. Subsequent peer body
        # receipt and complete native echo/FIN establish selected recovery.
    elif mode == 'duplicate-reorder':
        event('duplicate-reorder')
        actions = [row['fixture'] for row in events if row['event'] == 'udp-send' and row.get('fixture','').startswith(('reorder-', 'duplicate-'))]
        require(actions == ['reorder-second-first','reorder-first-second','duplicate-first'], 'selected duplicate/reorder action order')
    elif mode == 'flow-pause':
        paused, released = event('flow-pause'), event('flow-release')
        require(len(paused) == len(released) == 1 and paused[0]['request_bytes'] == released[0]['request_bytes'] == 1024 and
                released[0]['pause_seconds'] >= 0.25 and released[0]['monotonic_ns'] > paused[0]['monotonic_ns'],
                'exact1024-byte flow window/pause was not established')
    elif mode in ('truncated-header','unknown-cid','unauthorized-source'):
        require(sum(row.get('fixture') == mode for row in events if row['event'] == 'udp-send') == 1,
                'selected one-datagram input was not established')
    elif mode == 'invalid-tag':
        changed = event('tag-mutation')
        require(len(changed) == 1 and changed[0]['original_sha256'] != changed[0]['changed_sha256'], 'actual selected tag mutation absent')
    elif mode == 'long-retry':
        retry = event('retry-fixture')
        require(len(retry) == 1 and retry[0]['source_cid_bytes'] == 21 and retry[0]['integrity_verified'],
                'valid-integrity overlong Retry fixture absent')
    elif mode == 'stream-limit':
        limit = event('stream-limit-frame-built')
        require(len(limit) == 1 and limit[0]['frame_type'] == 17 and limit[0]['stream_id'] == 1 and
                limit[0]['maximum'] == 8192 and limit[0]['native_peer_bidi_limit'] == 0,
                'authenticated MAX_STREAM_DATA boundary fixture absent')
    elif mode.startswith('icmp-'):
        sent = event('icmp-send')
        require(len(sent) == 1 and sent[0]['mtu'] == case['icmp_mtu'], 'selected ICMP MTU fixture absent')
        quotes = [row for row in wire['guest_udp'] if row['ip_header_udp_hex'] == sent[0]['quote_hex'] and
                  row['frame_sha256'] == sent[0]['submitted_frame_sha256']]
        replies = [row for row in wire['icmp'] if row['icmp_hex'] == sent[0]['icmp_hex']]
        require(len(quotes) >= 1 and len(replies) == 1 and 0 <= replies[0]['timestamp'] - quotes[-1]['timestamp'] <= 2,
                'NOT_ESTABLISHED: ICMP quote is not an exact recent submitted datagram')
    if case['id'] in ('Q01', 'Q03', 'Q08', 'Q09', 'Q10', 'Q11', 'Q19'):
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


def verify_native(case, output, fixture, wire, manifest, family='ipv4'):
    selected = records(output, 'QUIC SERVICE SELECTOR', case)
    done = records(output, 'QUIC SERVICE DONE', case)
    grants = [row for row in records(output,'QUIC SERVICE GRANT',case) if 'constructed_ms' in row]
    require(len(selected) == len(done) == len(grants) == 1, 'one actual parent selector/grant/terminal required')
    require(number(selected[0], 'local_port') == case['local_port'] and number(done[0], 'sockets') == 0,
            'selected tuple or native UDP resource terminal differs')
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
    verify_fixture(case, fixture, wire, family)
    if case['id'] in ('Q08', 'Q09', 'Q10', 'Q11'):
        after = 'q08-after-flight-input' if case['id'] == 'Q08' else 'auth-after-flight-input'
        require(not any(row['event'] == after for row in fixture['events']),
                ('native Q08 received input after the response flight; ' if family == 'ipv6' else '')
                + 'native authentication input was discarded after the response flight')
    if case['expected_outcome'] == 'Interrupted':
        observed = records(output, 'QUIC CHILD INTERRUPT OBSERVED', case)
        requested = records(output, 'QUIC CHILD INTERRUPT REQUEST', case)
        returned = records(output, 'QUIC CHILD INTERRUPT RETURN', case)
        exits = records(output, 'QUIC CHILD EXIT', case)
        require(len(observed) == len(requested) == len(returned) == len(exits) == 1 and
                observed[0].get('phase') == case['interrupt_phase'] and
                number(observed[0], 'delay_ms') == case['interrupt_delay_ms'] and
                number(requested[0], 'observed_ms') == number(observed[0], 'observed_ms') and
                number(requested[0], 'requested_ms') >= number(observed[0], 'observed_ms') + case['interrupt_delay_ms'] and
                number(returned[0], 'end_ms') >= number(requested[0], 'requested_ms') and
                number(returned[0], 'result') >= 0 and number(exits[0], 'kind') == 3 and boolean(exits[0], 'killed'),
                'NOT_ESTABLISHED: actual phase interruption/reap absent')
        require(records(output, 'QUIC SERVICE RETIRE', case), 'interrupted grant retirement absent')
        if case['interrupt_phase'] == 'Handshake':
            require(any(row['event'] == 'initial-observed' for row in fixture['events']), 'interrupted handshake never reached peer')
        else:
            require(fixture['authenticated'] and fixture['request_bytes'] > 0 and
                    any(row.get('phase')=='Authenticated' for row in records(output,'QUIC PHASE',case)),
                    'interrupted active stream never reached peer')
        return {'actual_outcome':'Interrupted', 'typed_report':None, 'measured_cpu':cpu[0]}
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
        require(number(report, 'partial_pipe_reads') > 0 and number(report, 'partial_pipe_writes') > 0,
                'actual partial native IPC reads/writes absent')
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
        suppressed = records(output, 'QUIC FIXTURE SUPPRESSED_REPLY', case)
        require(len(suppressed) == 1 and number(suppressed[0],'opcode')==1 and number(suppressed[0],'status')==0 and
                number(suppressed[0],'framed_bytes')==14 and boolean(report, 'unknown_send') and number(report, 'send_accepted') == 0 and
                number(report, 'sends_after_fence') == 0 and
                number(report, 'last_send_ms') <= number(report, 'fence_ms'), 'unknown SEND retirement/no replay was not established')
    if case['id'] == 'Q23':
        expired = records(output, 'QUIC SERVICE GRANT EXPIRED', case)
        retired = records(output, 'QUIC SERVICE RETIRE', case)
        require(len(expired)==len(retired)==1,'actual owner expiry/retirement record absent')
        markers=[row for row in fixture['events'] if row['event']=='expiry-observation-marker']
        rx=records(output,'QUIC FIXTURE RX',case)
        require(len(markers)==1 and markers[0]['marker_hex']==case['observation_marker_hex'] and
                markers[0]['case_port']==case['local_port'],'Q23 causal observation marker absent')
        witness=[row for row in rx if row.get('sha256')==markers[0]['marker_sha256']]
        require(len(witness)==1 and number(witness[0],'at_ms')<number(expired[0],'owner_expiry_ms') and
                any(row['sha256']==markers[0]['initial_sha256'] for row in wire['guest_udp']) and
                any(row['sha256']==markers[0]['marker_sha256'] and row['source']==['10.0.2.2',4443]
                    for row in wire['peer_udp']), 'NOT_ESTABLISHED: Initial-before-expiry causal witness absent')
        counts = records(output, 'QUIC FIXTURE NATIVE_COUNTS', case)
        sends = records(output, 'QUIC FIXTURE SEND', case)
        require(len(expired) == len(retired) == len(counts) == 1 and number(counts[0], 'sends_after_owner_expiry') == 0 and
                number(report, 'last_send_ms') < number(expired[0], 'owner_expiry_ms') <= number(expired[0], 'observed_ms') and
                sends and all(number(row, 'at_ms') < number(expired[0], 'owner_expiry_ms') for row in sends) and
                number(counts[0], 'send_requests') == len(sends) and
                any(row['event'] == 'initial-observed' for row in fixture['events']),
                'actual owner expiry/progress and no subsequent SEND were not established')
    if case['id'] == 'Q18':
        probes = [row for row in fixture['events'] if row['event'] == 'unauthorized-probe']
        ledger = records(output, 'QUIC FIXTURE RX', case)
        native_counts=records(output,'QUIC FIXTURE NATIVE_COUNTS',case)
        require(len(probes) == 1 and probes[0]['authorized_copy_sent'] is False,
                'NOT_ESTABLISHED: distinct bad-tuple encrypted probe absent')
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
    if case['id'] == 'Q24':
        link = [row for row in fixture['events'] if row['event'] == 'link-action']
        require(len(link) == 1 and link[0]['qmp_acknowledged'] is True and
                any(row['event'] == 'initial-observed' for row in fixture['events']) and wire['guest_udp_count'] > 0,
                'NOT_ESTABLISHED: actual exact-guest link action/Initial absent')
    if case['id'] in ('Q17','Q29','Q30','Q31'):
        require(wire['guest_udp_count'] == 0 and number(report, 'send_accepted') == 0, 'refusal emitted UDP')
    if case['id'] in ('Q29','Q30','Q31'):
        require(number(report, 'send_calls') == 0, 'pre-SEND refusal reached native SEND')
    if case['id'] == 'Q29':
        require(boolean(report, 'no_native_pair'), 'absent named startup output did not refuse')
    if case['id'] == 'Q30':
        require(number(report, 'entropy_attempts') == 0, 'missing fixture time acquired entropy')
    if case['id'] in ('Q01', 'Q03', 'Q08', 'Q09', 'Q10', 'Q11', 'Q19'):
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
    if family == 'ipv6':
        verify_ipv6_native(case, output, report, wire)
    return {'actual_outcome':report['outcome'], 'typed_report':report, 'measured_cpu':cpu[0],
            'original_begin':begins[0] if begins else None}


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
                require('QMP' in hello, 'QMP greeting absent')
                observed['greeting']=hello
                for identity, command in [('capabilities',{'execute':'qmp_capabilities'}),
                                          ('drop-link',{'execute':'set_link','arguments':{'name':'quicnic','up':False}})]:
                    command['id']=identity
                    channel.sendall((json.dumps(command)+'\n').encode())
                    replies=[]
                    for _ in range(32):
                        result=read();replies.append(result)
                        if result.get('id')==identity:
                            require('return' in result and 'error' not in result, 'QMP exact command failed')
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
    def link_action():
        require(producer is not None and producer.poll() is None, 'exact guest ended before link action')
        return qmp_link_down(qmp, producer.pid, work/'QMP-LINK.json')
    reasons = ipv6_accounting(case) if family == 'ipv6' else None
    marker = reasons.ReadyMarker(serial, capture) if reasons is not None else None
    if marker is not None:
        require(sha(args.kernel / 'src/e1000_ring.rs') == reasons.original.POLICY['source_sha256'],
                'actual kernel NIC filter source differs from fixed accounting policy')
        marker.poll(False)
    peer_kwargs = {'timeout':admission['peer_timeout_seconds'], 'startup_timeout':admission['boot_timeout_seconds']}
    if family == 'ipv6':
        peer_kwargs['family'] = family
    peer = peer_module.Peer(case,pki,'fd00:ab5d::2' if family == 'ipv6' else '10.0.2.2',4443,
                            ('fd00:ab5d::15' if family == 'ipv6' else '10.0.2.15',case['local_port']), **peer_kwargs)
    try:
        measured = {key:measure.git_identity(value['path'],value['revision'],value['tree'])
                    for key,value in admission['sources'].items()}
        producer = measure.start_qemu(argv,work,work/'qemu.log',environment,work/'QEMU-LAUNCH.json',boot,measured,
                                      missing_rdrand=case['id']=='Q31')
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
    if case['id'] != 'Q17':
        verify_certificate_selection(case,peer.report(),pki)
    observed = verify_native(case,output,peer.report(),wire,manifest,family)
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
    parser.add_argument('--profile', choices=['q01-development', 'q03-initial-loss-development', 'q08-wrong-root-development', 'q09-wrong-name-development', 'q10-expired-development', 'q11-wrong-alpn-development', 'q19-queue-exhausted-development',
                                            'q01-ipv6-development', 'q08-ipv6-development', 'q17-ipv6-development'], required=True)
    parser.add_argument('--family', choices=('ipv4', 'ipv6'), default='ipv4')
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
    profile_case = {'q01-development':'Q01', 'q03-initial-loss-development':'Q03', 'q08-wrong-root-development':'Q08',
                      'q09-wrong-name-development':'Q09', 'q10-expired-development':'Q10',
                      'q11-wrong-alpn-development':'Q11', 'q19-queue-exhausted-development':'Q19', 'q01-ipv6-development':'Q01',
                      'q08-ipv6-development':'Q08', 'q17-ipv6-development':'Q17'}[args.profile]
    peer_controls = ['Q01' if args.family == 'ipv6' and profile_case == 'Q17' else profile_case]
    selected = args.case or [profile_case]
    require(selected == [profile_case] and all(development_profile(all_cases[i], args.family) == args.profile for i in selected),
            'only the exact case for the explicit bounded development profile is admitted')
    require(selected and len(set(selected)) == len(selected) and set(selected) <= all_cases.keys(), 'duplicate/unknown case selection')
    require(not args.controls or selected == peer_controls, 'limited milestone requires exactly its selected case control')
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
                if args.family == 'ipv6':
                    control_kwargs['family'] = 'ipv6'
                observed = peer_module.linux_control(case,pki,**control_kwargs)
                # Retain failed reference observations before checking any predicate.
                seal(args.work/(identity+'.observation.json'),observed)
                expected = 'Deadline' if identity in ('Q07','Q14') else case['expected_outcome']
                require(not observed['error'] and not observed['fixture']['errors'] and observed['actual_outcome'] == expected,
                        'independent Linux control failed: '+identity)
                if expected == 'Complete':
                    require(observed['fixture']['request_bytes'] == 4096 and observed['fixture']['request_fin'] and
                            observed['fixture']['echo_fin_enqueued'] and observed['peer_fin'], 'independent Linux FIN/body control absent')
                if identity == 'Q03':
                    verify_initial_loss(observed['fixture'])
                if identity == 'Q19':
                    verify_queue_prelude(observed['fixture'])
                if identity in ('Q08','Q09','Q10','Q11'):
                    verify_linux_auth_refusal(case, observed, pki, args.family)
                if args.family == 'ipv6':
                    require(observed['fixture'].get('readiness_profile') == args.profile
                            and observed['fixture'].get('transport_family') == 'ipv6', 'actual Linux IPv6 fixture differs')
                    if identity == 'Q08':
                        verify_ipv6_response_flight(observed['fixture'])
                # Fault establishment is verified separately from a successful echo.
                events = observed['fixture']['events']
                required_event = {'Q03':'initial-drop','Q04':'application-datagram-drop','Q05':'duplicate-reorder',
                                  'Q06':'flow-release','Q12':'udp-send','Q13':'tag-mutation','Q14':'retry-fixture',
                                  'Q15':'stream-limit-frame-built','Q16':'udp-send','Q18':'udp-send'}.get(identity)
                if required_event:
                    require(any(row['event'] == required_event for row in events), 'Linux fault was not established: '+identity)
                result = {'schema_version':1,'time':now(),'case':identity,'disposition':'PASS','ABSD_execution':False,'readiness_profile':args.profile,'transport_family':args.family,
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
            'ABSD_execution':not args.controls,'readiness_profile':args.profile,'transport_family':args.family,
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
