#!/usr/bin/env python3
"""Separate finite DHCP refusal proof. Accepted positive runner stays unchanged."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from served_ram import served_qemu

ROOT = Path(__file__).resolve().parent.parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

positive = load('dhcp_positive', 'native-dhcp-directed-arp-matrix.py')
peer = load('dhcp_peer', 'native-dhcp-refusal-peer.py')
require = peer.require
HOST_MAC = bytes.fromhex('525500000301');GUEST_MAC = peer.MAC
UNRUN = ['native exhaustion', 'child interruption/stall', 'NAK/conflict/link/clock loss in each phase',
         'queued-data expiry', 'renew/rebind/RELEASE', 'concurrent SSH', 'physical elapsed clock accuracy']


def seal(path, value):
    with Path(path).open('x') as stream:json.dump(value, stream, indent=2);stream.write('\n')


def bounded(path, maximum):
    with Path(path).open('rb') as stream:data = stream.read(maximum + 1)
    require(len(data) <= maximum, 'input byte bound: ' + str(path));return data


def identity(data):return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def decode(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON key');result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=unique);require(isinstance(result, dict), 'JSON object required');return result


def build_binding(args, kernel, probe):
    raw = bounded(args.build_receipt, 1024 * 1024)
    require(identity(raw)['sha256'] == args.build_receipt_sha256, 'build receipt custody hash')
    receipt = decode(raw);require(receipt['schema'] == 'absd-native-dhcp-refusal-build/1', 'build receipt schema')
    for component in ('platform', 'kernel'):
        source = receipt['sources'][component]
        require(source['revision'] == getattr(args, component + '_revision')
                and source['tree'] == getattr(args, component + '_tree')
                and source['clean'] is True, 'expected clean source differs: ' + component)
        archive = source['archive'];data = bounded(archive['path'], 64 * 1024 * 1024)
        require(identity(data) == {key: archive[key] for key in ('bytes', 'sha256')}, 'source archive identity')
    require(receipt['outputs'] == {'probe': identity(probe), 'kernel': identity(kernel)}, 'exact output buffers')
    require(isinstance(receipt['commands'], list) and len(receipt['commands']) >= 2, 'actual native/kernel commands required')
    for command in receipt['commands']:
        require(isinstance(command['argv'], list) and command['argv']
                and all(isinstance(arg, str) for arg in command['argv']), 'literal actual argv')
        log = command['log'];data = bounded(log['path'], 16 * 1024 * 1024)
        require(identity(data) == {key: log[key] for key in ('bytes', 'sha256')}, 'actual build log identity')
    require(any(any(Path(arg).name == 'build-native-dhcp-refusal.sh' for arg in command['argv']) for command in receipt['commands']), 'native recipe command absent')
    require(any('EXTERNAL_USER_ELF=' + str(args.elf.resolve()) in command['argv'] for command in receipt['commands']), 'exact embedded probe command absent')
    toolchain = receipt['toolchain'];data = bounded(toolchain['path'], 1024 * 1024)
    require(identity(data) == {key: toolchain[key] for key in ('bytes', 'sha256')}, 'toolchain receipt identity')
    return {'receipt': identity(raw), 'sources': receipt['sources'], 'toolchain': toolchain,
            'limit': 'Exact recorded build/source/log/input correspondence; caller/independent review establishes actual command execution.'}


def stdout(raw):
    out = bytearray()
    matches = list(re.finditer(rb'^EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)\n', raw, re.M))
    require(len(matches) == raw.count(b'EXTERNAL OUTPUT CHUNK'), 'malformed or unanchored stdout chunk marker')
    for match in matches:
        require(int(match[1], 16) == len(out), 'stdout chunk gap/overlap')
        out.extend(bytes.fromhex(match[2].decode()))
    return out.decode('utf-8')


def inspect(capture, output, profile, peer_result):
    require(profile in peer.PROFILES, 'profile')
    require(peer_result['profile'] == profile and peer_result['errors'] == []
            and peer_result['socket_closed'] is True, 'ended independent peer required')
    tx, rx, rows = [], [], []
    for index, stamp, frame in positive.packet_records(capture):
        require(len(frame) >= 282 and frame[12:15] == bytes([8, 0, 69])
                and frame[23] == 17 and int.from_bytes(frame[20:22], 'big') & 0x3fff == 0, 'only direct DHCP IPv4 permitted')
        length = int.from_bytes(frame[16:18], 'big');ip = frame[14:14 + length];udp = ip[20:]
        require(len(frame) == 14 + length and len(udp) >= 248 and positive.boot.checksum(ip[:20]) == 0, 'IPv4 size/checksum')
        require(int.from_bytes(udp[4:6], 'big') == len(udp), 'UDP size')
        require(udp[6:8] == bytes(2) or positive.boot.checksum(ip[12:20] + bytes([0, 17]) + len(udp).to_bytes(2, 'big') + udp) == 0, 'UDP checksum')
        payload = udp[8:];outgoing = frame[6:12] == GUEST_MAC
        require(frame[:6] == bytes([255]) * 6 and frame[6:12] == (GUEST_MAC if outgoing else HOST_MAC), 'Ethernet tuple')
        require(ip[12:16] == (bytes(4) if outgoing else peer.HOST) and ip[16:20] == bytes([255]) * 4
                and udp[:4] == (bytes([0, 68, 0, 67]) if outgoing else bytes([0, 67, 0, 68])), 'UDP/IP tuple')
        require(payload[28:34] == GUEST_MAC, 'BOOTP client identity')
        row = {'index': index, 'timestamp': stamp, 'frame_hex': frame.hex(), 'sha256': identity(frame)['sha256'], 'payload': payload}
        if outgoing:
            opts, _ = peer.options(payload);kind = opts[53][0][1]
            require(kind in (b'\x01', b'\x03'), 'only Discover/selecting Request permitted')
            require(payload[:4] == bytes([1, 1, 6, 0]) and payload[12:28] == bytes(16), 'outgoing BOOTP')
            if kind == b'\x03':require(opts[54][0][1] == peer.HOST and opts[50][0][1] == peer.GUEST, 'selecting Request policy')
            row['kind'] = kind[0];tx.append(row)
        else:rx.append(row)
        rows.append(row)
    require(len(tx) >= 2 and tx[0]['kind'] == 1, 'active acquisition/retry evidence')
    xid = tx[0]['payload'][4:8]
    offered_xid = None
    if profile == 'no-offer':require(not rx and all(row['kind'] == 1 for row in tx), 'silent profile emitted/accepted Offer')
    else:
        require(len(rx) == 1 and rx[0]['index'] > tx[0]['index'], 'one observed post-Discover peer Offer')
        preceding = [row for row in tx if row['kind'] == 1 and row['index'] < rx[0]['index']]
        require(preceding, 'Offer before any Discover')
        offered_xid = rx[0]['payload'][4:8]
        require(offered_xid == preceding[-1]['payload'][4:8], 'stale Offer at captured delivery; refusal not established')
        require(rx[0]['payload'] == peer.offer(preceding[-1]['payload'], profile), 'exact current controlled Offer substitution')
        if profile == 'valid-offer-noack':
            require(all(row['index'] > rx[0]['index'] for row in tx if row['kind'] == 3), 'captured Request before delivered Offer')
            require(all(row['payload'][4:8] == offered_xid for row in tx if row['kind'] == 3)
                    and any(row['kind'] == 3 and row['index'] > rx[0]['index'] for row in tx)
                    and all(row['kind'] == 3 for row in tx if row['index'] > rx[0]['index']), 'valid Offer did not trigger selecting Request')
        else:
            require(all(row['kind'] == 1 for row in tx) and any(row['index'] > rx[0]['index'] for row in tx), 'refused Offer followed by no retry or an unauthorized Request')
    events = peer_result['events']
    require(isinstance(events, list) and 1 <= len(events) <= 64 and all(e['event'] in ('receive', 'send') for e in events), 'peer event envelope')
    times = [e['monotonic_ns'] for e in events]
    require(all(type(t) is int and t >= 0 for t in times) and times == sorted(times), 'peer event order')
    require(all(e.get('source') == ['0.0.0.0', 68] if e['event'] == 'receive' else e.get('destination') == ['255.255.255.255', 68] for e in events), 'peer event tuple')
    received = [e for e in events if e['event'] == 'receive'];sent = [e for e in events if e['event'] == 'send']
    require(len(received) == len(tx) and len(sent) == len(rx) == peer_result['sent'], 'peer/capture datagram counts')
    if sent:
        timing = sent[0]
        require(timing['first_discover_monotonic_ns'] == received[0]['monotonic_ns']
                and timing['trigger_discover_sha256'] == received[0]['sha256']
                and timing['offer_not_before_monotonic_ns'] == timing['first_discover_monotonic_ns'] + 1_100_000_000
                and timing['offer_not_before_monotonic_ns'] <= timing['send_ready_monotonic_ns'] <= timing['monotonic_ns'],
                'full first-Discover RX setup guard absent')
    for event, row in zip(received + sent, tx + rx):
        require(event['bytes'] == len(row['payload']) and event['hex'] == row['payload'].hex()
                and event['sha256'] == identity(row['payload'])['sha256'], 'Linux socket/capture byte correspondence')
    pattern = r'^DHCP REFUSAL FRAME direction=(rx|tx) start_ms=(\d+) end_ms=(\d+) status=(-?\d+) length=(\d+) hex=([0-9a-f]+)$'
    traced = []
    for line in output.splitlines():
        if line.startswith('DHCP REFUSAL FRAME '):
            match = re.fullmatch(pattern, line);require(match is not None, 'exact native Link frame record')
            direction, start, end, status, size, text = match.groups();frame = bytes.fromhex(text)
            require(int(status) == 0 and int(size) == len(frame) and int(start) <= int(end), 'native frame outcome/clock/size')
            traced.append((direction, frame, int(start), int(end)))
    for direction, expected in [('tx', tx), ('rx', rx)]:
        actual = [frame for kind, frame, _, _ in traced if kind == direction]
        require(actual == [bytes.fromhex(row['frame_hex']) for row in expected], 'native Link/capture complete-byte correspondence: ' + direction)
    # Wire arrival and userspace dequeue are distinct observations. Preserve
    # exact FIFO bytes in each direction without inventing a shared clock/order.
    if rx:
        rx_at = next(i for i, row in enumerate(traced) if row[0] == 'rx')
        preceding_native = [row[1] for row in traced[:rx_at] if row[0] == 'tx' and peer.options(row[1][42:])[0][53][0][1] == b'\x01']
        require(preceding_native and preceding_native[-1][46:50] == offered_xid, 'stale Offer at native dequeue; refusal not established')
    if profile == 'valid-offer-noack':
        rx_at = next(i for i, row in enumerate(traced) if row[0] == 'rx')
        requests = [i for i, row in enumerate(traced) if row[0] == 'tx' and peer.options(row[1][42:])[0][53][0][1] == b'\x03']
        require(requests and all(i > rx_at for i in requests), 'native Request before delivered Offer')
    require(all(previous[3] <= current[2] for previous, current in zip(traced, traced[1:])), 'native Link clock order')
    require(bool(output.splitlines()) and output.splitlines()[0] == 'DHCP REFUSAL BEGIN acquire_ms=20000 child=not-started'
            and all(line.startswith(('DHCP REFUSAL BEGIN ', 'DHCP REFUSAL FRAME ', 'DHCP REFUSAL LINK DROP ', 'DHCP REFUSAL END ')) for line in output.splitlines()), 'native output envelope')
    lines = output.splitlines()
    require(sum(line.startswith('DHCP REFUSAL BEGIN ') for line in lines) == 1
            and sum(line.startswith('DHCP REFUSAL LINK DROP ') for line in lines) == 1
            and sum(line.startswith('DHCP REFUSAL END ') for line in lines) == 1
            and len(lines) >= 3 and lines[-2].startswith('DHCP REFUSAL LINK DROP ')
            and lines[-1].startswith('DHCP REFUSAL END '), 'one exact native terminal envelope required')
    ends = re.findall(r'^DHCP REFUSAL END error=Timeout start_ms=(\d+) deadline_ms=(\d+) ended_ms=(\d+) dropped=true overflow=false rx=(\d+) tx=(\d+) child=not-started$', output, re.M)
    require(len(ends) == 1, 'exact Timeout/drop record absent')
    start, deadline, end, native_rx, native_tx = map(int, ends[0])
    require(deadline == start + 20000 and end >= deadline and native_rx == len(rx) and native_tx == len(tx), 'original deadline or Link count differs')
    drops = re.findall(r'^DHCP REFUSAL LINK DROP now_ms=(\d+) rx=(\d+) tx=(\d+) overflow=false$', output, re.M)
    require(len(drops) == 1 and deadline <= int(drops[0][0]) <= end
            and tuple(map(int, drops[0][1:])) == (native_rx, native_tx), 'terminal Link drop ordering')
    require(all(start <= first <= last <= end for _, _, first, last in traced)
            and 'DHCP REFUSAL UNEXPECTED' not in output and 'DHCP ACTIVE' not in output
            and 'DHCP DNS ANSWER' not in output, 'unexpected activation or trace clock')
    return {'profile': profile, 'initial_xid': xid.hex(), 'offered_xid': offered_xid.hex() if offered_xid is not None else None, 'discover_xids': [row['payload'][4:8].hex() for row in tx if row['kind'] == 1], 'start_ms': start, 'deadline_ms': deadline, 'ended_ms': end,
            'tx_kinds': [row['kind'] for row in tx], 'native_link_rx': native_rx, 'native_link_tx': native_tx,
            'frames': [{key: value for key, value in row.items() if key != 'payload'} for row in rows],
            'limits': 'Exact controlled bytes/captured order/boot-domain timeout and drop. No physical elapsed-time, general DHCP, child interruption or kernel NIC authority-transfer claim.'}


def reconcile_namespace(namespace, attempted, created, expected_identity, checked, stat=os.stat):
    record = {'namespace': namespace, 'creation_attempted': attempted, 'created': created,
              'expected_identity': expected_identity, 'observed_absent': None, 'errors': []}
    if not attempted:
        record['disposition'] = 'NOT_ATTEMPTED';return record
    try:
        present = namespace in [line.split()[0] for line in checked(['ip', 'netns', 'list']).stdout.splitlines()]
        if present:
            require(created and expected_identity is not None, 'uncertain namespace creation; retained residual')
            info = stat('/run/netns/' + namespace)
            require([info.st_dev, info.st_ino] == expected_identity, 'namespace identity changed; retained residual')
            require(not checked(['ip', 'netns', 'pids', namespace]).stdout.strip(), 'namespace has live processes; retained residual')
            info = stat('/run/netns/' + namespace)
            require([info.st_dev, info.st_ino] == expected_identity, 'namespace identity changed during process check; retained residual')
            # The final pathname check and ip deletion are not atomic. This
            # fixture requires no concurrent namespace mutator on its own VM.
            checked(['ip', 'netns', 'del', namespace])
        record['observed_absent'] = namespace not in [line.split()[0] for line in checked(['ip', 'netns', 'list']).stdout.splitlines()]
        require(record['observed_absent'], 'namespace deletion not established')
    except BaseException as error:record['errors'].append(repr(error))
    record['disposition'] = 'FAIL' if record['errors'] else 'PASS'
    return record


def run(args, work):
    require(os.geteuid() == 0, 'own disposable Linux VM root required')
    kernel = bounded(args.kernel_elf, 64 * 1024 * 1024);probe = bounded(args.elf, 64 * 1024 * 1024)
    require(kernel.startswith(b'\x7fELF') and probe.startswith(b'\x7fELF') and kernel.count(probe) == 1, 'exact unique probe embedded in kernel')
    binding = build_binding(args, kernel, probe)
    tree = work / 'iso-tree/boot/grub';tree.mkdir(parents=True)
    (tree.parent / 'absd-kernel').write_bytes(kernel)
    (tree / 'grub.cfg').write_text('insmod all_video\nset timeout=0\nmenuentry "ABSD DHCP refusal" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n')
    iso = work / 'native-dhcp-refusal.iso';disk = work / 'native-dhcp-refusal.img'
    with (work / 'iso-build.log').open('wb') as log:subprocess.run(['grub-mkrescue', '-o', str(iso), str(tree.parent.parent)], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)
    with disk.open('wb') as stream:stream.truncate(2 * 1024 * 1024)
    namespace = 'absddhcpn-' + uuid.uuid4().hex[:12];tap = 'dhcp-tap0';created = False;creation_attempted = False;creation_identity = None;qemu = None;server = None;logs = [];errors = []
    def checked(argv):return subprocess.run(argv, text=True, capture_output=True, check=True, timeout=5)
    try:
        require(namespace not in [line.split()[0] for line in checked(['ip', 'netns', 'list']).stdout.splitlines()], 'initial namespace collision; no mutation')
        creation_attempted = True
        checked(['ip', 'netns', 'add', namespace]);created = True
        ns_info = os.stat('/run/netns/' + namespace);creation_identity = [ns_info.st_dev, ns_info.st_ino]
        for key in ('all', 'default'):checked(['ip', 'netns', 'exec', namespace, 'sysctl', '-qw', 'net.ipv6.conf.' + key + '.disable_ipv6=1'])
        for command in (['link', 'set', 'lo', 'up'], ['tuntap', 'add', 'dev', tap, 'mode', 'tap'], ['link', 'set', tap, 'address', HOST_MAC.hex(':')], ['addr', 'add', '192.0.2.1/24', 'dev', tap], ['link', 'set', tap, 'up']):checked(['ip', '-n', namespace, *command])
        link = checked(['ip', '-j', '-n', namespace, 'link', 'show', 'dev', tap]).stdout
        addr = checked(['ip', '-j', '-4', '-n', namespace, 'addr', 'show', 'dev', tap]).stdout
        lrow, arow = json.loads(link), json.loads(addr)
        require(len(lrow) == len(arow) == 1 and lrow[0]['ifname'] == arow[0]['ifname'] == tap
                and lrow[0]['ifindex'] == arow[0]['ifindex'] > 0 and lrow[0]['address'] == HOST_MAC.hex(':')
                and lrow[0]['mtu'] == 1500 and any(a['local'] == '192.0.2.1' and a['prefixlen'] == 24 for a in arow[0]['addr_info']), 'exact isolated peer link/address')
        seal(work / 'SETUP.json', {'namespace': namespace, 'link_raw': link, 'addr_raw': addr, 'routes_raw': checked(['ip', '-n', namespace, 'route', 'show', 'table', 'all']).stdout})
        peer_work = work / 'peer';peer_work.mkdir()
        peer_log = (work / 'peer.log').open('wb');logs.append(peer_log)
        server = subprocess.Popen(['ip', 'netns', 'exec', namespace, 'python3', '-B', str(ROOT / 'scripts/native-dhcp-refusal-peer.py'), '--profile', args.profile, '--interface', tap, '--work', str(peer_work), '--timeout', str(args.timeout + 10)], stdout=peer_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 5
        while not (peer_work / 'PEER-READY.json').exists():
            require(server.poll() is None and time.monotonic() < deadline, 'peer readiness');time.sleep(0.02)
        ready = decode((peer_work / 'PEER-READY.json').read_bytes())
        require(ready['pid'] == server.pid and ready['netns_inode'] == os.stat('/run/netns/' + namespace).st_ino
                and ready['ifindex'] == lrow[0]['ifindex'] and ready['bound'] == ['0.0.0.0', 67]
                and os.stat('/proc/' + str(server.pid) + '/ns/net').st_ino == ready['netns_inode'], 'live exact peer identity')
        lease = datetime.datetime.fromisoformat(args.lease_end.replace('Z', '+00:00'))
        require(lease.tzinfo is not None and (lease - datetime.datetime.now(datetime.timezone.utc)).total_seconds() >= 1200, 'original lease minimum1200s')
        for path in ('/', str(work)):
            sample = os.statvfs(path);require(sample.f_bavail * sample.f_frsize >= 64424509440 and sample.f_favail > 1000, 'native storage reserve')
        serial = work / 'native-dhcp.serial.log';capture = work / 'native-dhcp.pcap';qlog = (work / 'qemu.log').open('wb');logs.append(qlog)
        command = served_qemu(['ip', 'netns', 'exec', namespace, os.environ.get('ABSD_QEMU', 'qemu-system-x86_64'), '-accel', 'tcg,thread=single', '-cpu', 'max,vendor=GenuineIntel,+rdrand', '-smp', '1', '-m', '256M', '-cdrom', str(iso), '-drive', f'file={disk},format=raw,if=ide,index=0', '-display', 'none', '-serial', f'file:{serial}', '-no-reboot', '-no-shutdown', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04', '-device', f'e1000,netdev=n0,mac={GUEST_MAC.hex(":")}', '-netdev', f'tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off', '-object', f'filter-dump,id=cap0,netdev=n0,file={capture}'])
        qemu = subprocess.Popen(command, stdout=qlog, stderr=subprocess.STDOUT)
        seal(work / 'LAUNCH.json', {'profile': args.profile, 'qemu_pid': qemu.pid, 'peer_pid': server.pid, 'qemu_argv': command, 'peer_argv': server.args, 'binding': binding, 'kernel': identity(kernel), 'probe': identity(probe), 'iso': positive.identity(iso), 'runner': positive.identity(__file__), 'peer_source': positive.identity(peer.__file__), 'timeout_seconds': args.timeout, 'lease_end': args.lease_end, 'setup_guard_assumptions': 'Continuous non-icount TCG; no QMP pause/reset/guest restart. First Discover plus1.1s peer monotonic allowance does not restart peer or original20s guest deadline; actual Link RX remains mandatory, early/lost Offer is setupFAIL.'})
        deadline = time.monotonic() + args.timeout
        while qemu.poll() is None:
            require(time.monotonic() < deadline and server.poll() is None, 'guest deadline/peer liveness')
            require(not serial.exists() or serial.stat().st_size <= positive.MAX_SERIAL, 'serial bound')
            require(not capture.exists() or capture.stat().st_size <= positive.MAX_CAPTURE, 'capture bound');time.sleep(0.05)
        _, counters = positive.boot.finish_boot(qemu, str(serial), rb'DHCP REFUSAL END error=Timeout')
        server.terminate();require(server.wait(timeout=5) == 0, 'normal peer terminal')
        output = stdout(bounded(serial, positive.MAX_SERIAL));presult = decode(bounded(peer_work / 'PEER-RESULT.json', 1024 * 1024))
        evidence = inspect(capture, output, args.profile, presult)
        values = dict(item.split('=', 1) for item in counters.split())
        require(all(int(values[k]) == 0 for k in ('rx_refused', 'rx_missed', 'tx_refused', 'tx_errors')), 'NIC failures')
        require(int(values['rx_frames']) == evidence['native_link_rx'] and int(values['tx_frames']) == evidence['native_link_tx'], 'kernel/native frame count correspondence')
        return {'disposition': 'PASS', 'profile': args.profile, 'native_output': output, 'NIC_counters': counters, 'evidence': evidence, 'binding': binding, 'unrun': UNRUN}
    finally:
        for process, name in ((qemu, 'qemu'), (server, 'peer')):
            if process is not None:
                try:
                    if process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=5)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                    require(process.poll() is not None, name + ' terminal')
                except BaseException as error:errors.append(name + ': ' + repr(error))
        for log in logs:log.close()
        namespace_cleanup = reconcile_namespace(namespace, creation_attempted, created, creation_identity, checked)
        errors.extend(namespace_cleanup['errors'])
        seal(work / 'LOCAL-CLEANUP.json', {'disposition': 'FAIL' if errors else 'PASS', 'errors': errors, 'namespace': namespace, 'created': created, 'namespace_reconciliation': namespace_cleanup, 'qemu_terminal': qemu is None or qemu.poll() is not None, 'peer_terminal': server is None or server.poll() is not None})
        require(not errors, 'cleanup errors: ' + repr(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('work', type=Path);parser.add_argument('--profile', choices=peer.PROFILES, required=True)
    parser.add_argument('--kernel-elf', type=Path, required=True);parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--build-receipt', type=Path, required=True);parser.add_argument('--build-receipt-sha256', required=True)
    parser.add_argument('--lease-end', required=True);parser.add_argument('--timeout', type=int, default=180)
    for name in ('platform', 'kernel'):
        for kind in ('revision', 'tree'):parser.add_argument('--' + name + '-' + kind, required=True)
    args = parser.parse_args();require(__debug__ and not os.environ.get('PYTHONOPTIMIZE'), 'normal assertions required')
    require(30 <= args.timeout <= 180 and re.fullmatch('[0-9a-f]{64}', args.build_receipt_sha256), 'time/hash bounds')
    require(all(re.fullmatch('[0-9a-f]{40}', getattr(args, name + '_' + kind)) for name in ('platform', 'kernel') for kind in ('revision', 'tree')), 'exact admitted source identities')
    work = args.work.resolve();work.mkdir(mode=0o700, parents=True, exist_ok=False)
    def stopped(_signal, _frame):raise KeyboardInterrupt('runner interrupted')
    signal.signal(signal.SIGTERM, stopped);signal.signal(signal.SIGINT, stopped)
    try:result = run(args, work)
    except BaseException as error:seal(work / 'RESULT.json', {'schema': 'absd-native-dhcp-refusal-proof/1', 'disposition': 'FAIL', 'profile': args.profile, 'error': repr(error), 'unrun': UNRUN});raise
    seal(work / 'RESULT.json', {'schema': 'absd-native-dhcp-refusal-proof/1', **result});print('NATIVE DHCP REFUSAL PASS')


if __name__ == '__main__':main()
