#!/usr/bin/env python3
"""One ended canonical W01 report's Linux socket receipt; no packet parser.

The unchanged canonical runner supplies flow/build/boot/native/census/cleanup
qualification. Expected hashes come from that ended occurrence's custody.
This additional claim is exactly seven post-trigger bytes, not encrypted TLS.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

RUNNER_SHA256 = '9f82fc85874f61eb300ff635548cc80ad000803c8854e52b25acc2fb1635fbbd'
MANIFEST_SHA256 = '9e33abf2e5152efd91a47da564c49ffc919c8809f0fd6db283d1390e65b799fa'
ALERT = bytes.fromhex('15030300020232')
FILES = ('RESULT.json', 'FIXTURE.json', 'CASE-INPUTS.json')
MAX_JSON = 1024 * 1024


class NotEstablished(ValueError):
    pass


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=unique)
    require(isinstance(value, dict), 'JSON object required')
    return value


def bounded(path):
    with path.open('rb') as stream:
        data = stream.read(MAX_JSON + 1)
    require(len(data) <= MAX_JSON, 'JSON byte bound')
    return data


def inspect_fixture(fixture):
    case = fixture['case']
    require(case['id'] == 'W01' and case['peer_mode'] == 'bad-record'
            and case['local_port'] == 7311 and case['expect_http'] is False,
            'exact native W01 required')
    require(type(fixture['accepts']) is int and fixture['accepts'] == 1
            and type(fixture['guard_accepts']) is int and fixture['guard_accepts'] == 0,
            'one accepted flow and no guard connection required')
    require(fixture['errors'] == [] and type(fixture['request_bytes']) is int
            and fixture['request_bytes'] == 0
            and fixture['request_sha256'] == digest(b'')
            and fixture['server_handshake_complete'] is False,
            'unexpected peer error, HTTP or completed handshake')
    events = fixture['events']
    require(isinstance(events, list) and 7 <= len(events) <= 15, 'bounded ended event list required')
    times = [event['monotonic_ns'] for event in events]
    require(all(type(t) is int and t >= 0 for t in times) and times == sorted(times),
            'event order/monotonic samples')
    require([event['event'] for event in events[:6]]
            == ['accept', 'tcp-read', 'tcp-write', 'tcp-write', 'tcp-write', 'raw-record'],
            'canonical W01 prelude differs')
    require(events[0]['role'] == 'tls' and events[0]['source'] == ['10.0.2.15', 7311],
            'accepted source tuple differs')
    first = events[1]
    require(type(first['bytes']) is int and 0 < first['bytes'] <= 4096
            and re.fullmatch('[0-9a-f]{64}', first['sha256']), 'initial client receive absent')
    for event, count, offset in zip(events[2:5], (1, 2, 2), (0, 1, 3)):
        require(type(event['bytes']) is int and type(event['stream_offset']) is int
                and event['bytes'] == count and event['stream_offset'] == offset,
                'canonical malformed trigger send differs')
    require(events[5]['bytes_hex'] == 'ff03030000' and events[5]['phase'] == 'handshake',
            'exact pre-key malformed trigger absent')
    received = 0
    reads = []
    for index, event in enumerate(events[6:], 6):
        kind = event['event']
        if kind == 'tcp-read':
            count = event['bytes']
            require(type(count) is int and count >= 0, 'invalid receive length')
            if count:
                expected = ALERT[received:received + count]
                if len(expected) != count or event['sha256'] != digest(expected):
                    raise NotEstablished('unexplained/mixed post-trigger bytes or wrong alert')
                reads.append({'event_index': index, 'bytes': count, 'sha256': event['sha256']})
                received += count
                continue
            require(event['sha256'] == digest(b''), 'EOF digest differs')
        elif kind == 'connection-ended':
            require(isinstance(event['error_type'], str) and isinstance(event['reason'], str),
                    'unidentified teardown')
        else:
            raise ValueError('unexpected post-trigger event')
        require(index == len(events) - 1, 'events after EOF/teardown')
        if received != len(ALERT):
            raise NotEstablished('complete seven-byte client fatal alert not received')
        return {'received_bytes': received, 'record_hex': ALERT.hex(), 'reads': reads,
                'trigger_event_index': 5, 'terminal_event_index': index, 'terminal_kind': kind}
    raise NotEstablished('ended receive observation missing')


def source_arguments(parser):
    for component in ('platform', 'kernel'):
        for identity in ('revision', 'tree'):
            parser.add_argument('--' + component + '-' + identity, required=True)
    parser.add_argument('--runner', type=Path, required=True)


def expected_sources(args):
    expected = {name: {kind: getattr(args, name + '_' + kind)
                       for kind in ('revision', 'tree')}
                for name in ('platform', 'kernel')}
    validate_expected_sources(expected)
    return expected


def validate_expected_sources(expected):
    require(set(expected) == {'platform', 'kernel'}, 'both admitted source identities required')
    for source in expected.values():
        require(set(source) == {'revision', 'tree'}
                and all(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value)
                        for value in source.values()), 'full admitted revision and tree required')


def inspect_sources(inputs, expected):
    # Expectations come from the admitted run's caller, never from this same record.
    validate_expected_sources(expected)
    require(inputs['case_manifest_sha256'] == MANIFEST_SHA256, 'canonical manifest differs')
    for name, identity in expected.items():
        source = inputs['source'][name]
        require(source['revision'] == identity['revision'] and source['tree'] == identity['tree']
                and source['dirty_state'] == '' and source['clean_required'] is True,
                'canonical source prerequisite differs: ' + name)


def evaluate(buffers, expected):
    result, fixture, inputs = (decode(buffers[name]) for name in FILES)
    require(result['disposition'] == 'PASS' and result['case'] == 'W01'
            and result['actual_class'] == 'TlsRejected' and result['measured_qemu_exit'] == 3,
            'canonical W01 PASS prerequisite absent')
    require(result['fixture'] == fixture and inputs['selected_case'] == fixture['case'],
            'canonical/fixture/selected-case disagreement')
    inspect_sources(inputs, expected)
    return inspect_fixture(fixture)


def unchanged(paths, buffers):
    for name, path in paths.items():
        require(bounded(path) == buffers[name], 'evaluated input changed before seal: ' + name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-dir', type=Path, required=True)
    for name in ('result', 'fixture', 'case-inputs'):
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    source_arguments(parser)
    args = parser.parse_args(argv)
    require(not sys.flags.optimize, 'optimized Python refused')
    require(not args.output.resolve().is_relative_to(args.case_dir.resolve()),
            'write a separate new receipt, never modify the canonical case')
    paths = {name: args.case_dir / name for name in FILES}
    expected = dict(zip(FILES, (args.result_sha256, args.fixture_sha256, args.case_inputs_sha256)))
    require(all(re.fullmatch('[0-9a-f]{64}', value) for value in expected.values()),
            'exact ended custody hashes required')
    sources = expected_sources(args)
    buffers = {}
    runner = None
    output = {'schema': 'absd-tls-W01-socket-receipt/1', 'disposition': 'FAIL',
              'expected_sources': sources, 'required_canonical_runner_sha256': RUNNER_SHA256,
              'canonical_manifest_sha256': MANIFEST_SHA256, 'expected_input_sha256': expected,
              'limits': 'Canonical source/boot/native/census/cleanup qualification is a separate '
                        'prerequisite. Only seven pre-key bytes in Linux recv observations; '
                        'no encrypted/certificate/post-auth alert or packet/DMA/timing claim.'}
    try:
        for name, path in paths.items():
            buffers[name] = bounded(path)
            require(digest(buffers[name]) == expected[name], 'custody hash differs: ' + name)
        runner = bounded(args.runner)
        require(digest(runner) == RUNNER_SHA256, 'canonical runner differs')
        output['receipt'] = evaluate(buffers, sources)
        output['disposition'] = 'PASS_BOUNDED_SOCKET_RECEIPT'
    except (ValueError, KeyError, TypeError, OSError) as error:
        output['disposition'] = 'NOT_ESTABLISHED' if isinstance(error, NotEstablished) else 'FAIL'
        output['error'] = str(error)
    try:
        unchanged({name: paths[name] for name in buffers}, buffers)
        if runner is not None:
            require(bounded(args.runner) == runner, 'canonical runner changed before seal')
    except (ValueError, OSError) as error:
        output['disposition'] = 'FAIL'
        output['seal_error'] = str(error)
    if runner is not None:
        output['runner'] = {'path': str(args.runner.absolute()), 'bytes': len(runner),
                            'sha256': digest(runner)}
    output['evaluated_inputs'] = {
        name: {'path': str(paths[name].absolute()), 'bytes': len(data), 'sha256': digest(data)}
        for name, data in buffers.items()}
    with args.output.open('x') as stream:
        json.dump(output, stream, indent=2)
        stream.write('\n')
    return 0 if output['disposition'] == 'PASS_BOUNDED_SOCKET_RECEIPT' else 1


if __name__ == '__main__':
    raise SystemExit(main())
