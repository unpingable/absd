#!/usr/bin/env python3
"""Collect real GDB OUT observations; offline fixtures never launch product ISOs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
KERNEL_SHA = {'enabled': 'fc4852ea42b7776e49789cb95edc04ff5a7d35d250fd98df286e18b06ef18e88',
              'default': '8ce0ed4ca760cd4658dcf8f56b0ebb7683d62a746da50065b0c6c1515e276116'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def instructions(text):
    rows = []
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) >= 3 and re.fullmatch(r'\s*[0-9a-f]+:', fields[0]):
            raw = fields[1].strip().split()
            if raw and all(re.fullmatch('[0-9a-f]{2}', byte) for byte in raw):
                rows.append({'pc': int(fields[0].strip()[:-1], 16),
                             'bytes': bytes.fromhex(''.join(raw)).hex(), 'asm': fields[2].strip()})
    return rows


def product_plan(elf, out):
    elf = Path(elf).resolve()
    digest = sha(elf)
    if digest not in KERNEL_SHA.values():
        raise ValueError('product ELF is outside exact frozen f47818e inputs')
    nm = subprocess.check_output(['nm', '-n', '-S', '-C', '--defined-only', str(elf)], text=True)
    listing = subprocess.check_output(['objdump', '-d', '-C', '-Mintel', '--insn-width=15', str(elf)], text=True)
    Path(out).mkdir(exist_ok=False)
    (Path(out) / 'nm.txt').write_text(nm)
    (Path(out) / 'disassembly.txt').write_text(listing)
    symbols = {}
    for line in nm.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4:
            symbols[fields[3]] = (int(fields[0], 16), int(fields[1], 16))
    def pick(name, prefix=False):
        found = [(key, value) for key, value in symbols.items() if key.startswith(name)] if prefix else [(name, symbols[name])]
        if len(found) != 1:
            raise ValueError('nonunique frozen symbol: ' + name)
        return found[0]
    entry_name, (entry, _) = pick('kernel_main')
    reset_name, (reset, reset_size) = pick('absd_kernel::machine_reset')
    closure_name, (closure, closure_size) = pick('absd_kernel::machine_reset::{closure#0}', True)
    legacy_name, (legacy, legacy_size) = pick('absd_kernel::legacy_machine_reset')
    sequence_name, (sequence, sequence_size) = pick('absd_kernel::acpi::reset_sequence::<', True)
    rows = instructions(listing)
    def within(address, size):
        return [row for row in rows if address <= row['pc'] < address + size]
    def outs(address, size):
        selected = [row for row in within(address, size) if row['asm'].startswith('out ')]
        if any(row['bytes'] != 'ee' or row['asm'].split() != ['out', 'dx,al'] for row in selected):
            raise ValueError('unsupported OUT shape in frozen reset body')
        return selected
    fadt = outs(closure, closure_size)
    legacy_outs = outs(legacy, legacy_size)
    if len(fadt) != 1 or len(legacy_outs) != 3 or outs(sequence, sequence_size):
        raise ValueError('frozen reset OUT count changed; inspect actual binary')
    reset_rows = within(reset, reset_size)
    if len(reset_rows) != 2 or reset_rows[0]['bytes'] != '50' or not reset_rows[1]['bytes'].startswith('e8') or len(bytes.fromhex(reset_rows[1]['bytes'])) != 5 or reset_rows[1]['pc'] + 5 + int.from_bytes(bytes.fromhex(reset_rows[1]['bytes'])[1:], 'little', signed=True) != sequence:
        raise ValueError('frozen reset entry shape changed; no assumed non-inlining')
    body = within(legacy, legacy_size)
    first, second, keyboard = [body.index(row) for row in legacy_outs]
    if ([body[first - 2]['bytes'], body[first - 1]['bytes'], body[second - 1]['bytes']] != ['66baf90c', 'b002', 'b006']
            or legacy_outs[1]['pc'] != legacy_outs[0]['pc'] + 3
            or [body[keyboard - 2]['bytes'], body[keyboard - 1]['bytes']] != ['66ba6400', 'b0fe']):
        raise ValueError('actual legacy port/value instruction sequence changed')
    callers = []
    for row in rows:
        if re.match(r'call\s+' + f'{reset:x}' + r'\s+<', row['asm']):
            if not row['bytes'].startswith('e8') or len(bytes.fromhex(row['bytes'])) != 5:
                raise ValueError('unsupported reset caller instruction')
            owner = [(name, addr) for name, (addr, size) in symbols.items() if addr <= row['pc'] < addr + size]
            if len(owner) != 1:
                raise ValueError('reset caller ownership is ambiguous')
            callers.append({'pc': row['pc'], 'return_pc': row['pc'] + 5, 'owner': owner[0][0], 'instruction': row})
    if {row['owner'] for row in callers} != {'user_syscall_dispatch', 'absd_kernel::suite::end_boot'} or len(callers) != 2:
        raise ValueError('frozen caller set changed')
    allowed = [row['return_pc'] for row in callers if row['owner'] == 'user_syscall_dispatch']
    plan = {'entry': entry, 'reset_entry': reset, 'allowed_return_addresses': allowed,
            'outs': [{'pc': fadt[0]['pc'], 'role': 'fadt'},
                     *[{'pc': row['pc'], 'role': role} for row, role in zip(legacy_outs, ['legacy-2', 'legacy-6', 'legacy-keyboard'])]],
            'elf_sha256': digest, 'source_commit': 'f47818e18ea1dcee54bb5836f2710c247a7683da',
            'symbols': [entry_name, reset_name, sequence_name, closure_name, legacy_name], 'all_reset_callers': callers}
    save(Path(out) / 'plan.json', plan)
    return plan


def collect(elf, plan, qemu_args, out, metadata, qemu='qemu-system-x86_64', deadline_seconds=90):
    protected_host = os.environ.get('ABSD_PROTECTED_HOST')
    if True:
        if protected_host is None:
            raise ValueError('set ABSD_PROTECTED_HOST explicitly before execution')
        if protected_host and socket.gethostname().split('.')[0].lower() == protected_host.split('.')[0].lower():
            raise ValueError('QEMU is prohibited on the configured protected host')
    out = Path(out).resolve()
    if len(str(out / 'gdb.sock').encode()) >= 104:
        raise ValueError('fresh output path is too long for the scoped UNIX debugger socket')
    out.mkdir(mode=0o700, exist_ok=False)
    st = os.statvfs(out)
    if st.f_bavail * st.f_frsize - 512 * 1024**2 < 64424509440:
        raise ValueError('60 GiB reserve plus offline forecast unavailable')
    config = {'out': str(out), 'elf': str(Path(elf).resolve()), 'plan': plan,
              'serial': str(out / 'serial.log'), 'gdb_socket': str(out / 'gdb.sock')}
    save(out / 'config.json', config)
    metadata = {**metadata, 'plan': plan, 'elf_sha256': sha(elf),
                'observer_sha256': sha(HERE / 'acpi-reset-gdb.py'), 'controller_sha256': sha(__file__),
                'qemu_version': subprocess.check_output([qemu, '--version'], text=True).splitlines()[0],
                'gdb_version': subprocess.check_output(['gdb', '--version'], text=True).splitlines()[0]}
    metadata['qemu_sha256'] = sha(shutil.which(qemu) or qemu)
    metadata['gdb_sha256'] = sha(shutil.which('gdb'))
    if not re.search(r'version 8\.2\.2(?:\s|$)', metadata['qemu_version']) or not metadata['gdb_version'].endswith(' 15.1'):
        raise ValueError('observer requires the measured QEMU8.2.2 and GDB15.1 profile')
    save(out / 'metadata.json', metadata)
    args = [qemu, '-M', metadata['machine'], '-accel', 'tcg', '-smp', '1', '-m', '64M' if metadata['kind'] == 'fixture' else '512M',
            *qemu_args, '-display', 'none', '-serial', f'file:{out / "serial.log"}', '-nic', 'none', '-no-reboot',
            '-S', '-gdb', f'unix:{out / "gdb.sock"},server=on,wait=off']
    children, streams, cleanup = {}, [], []
    result = {'schema_version': 1, 'observation_complete': False, 'qemu_argv': args,
              'started_unix': time.time(), 'cleanup': cleanup}
    save(out / 'result.json', result)
    try:
        env = dict(os.environ, ABSD_RESET_GDB_CONFIG=str(out / 'config.json'), PYTHONDONTWRITEBYTECODE='1')
        def launch(name, command):
            log = (out / (name + '.log')).open('wb');streams.append(log)
            children[name] = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
            result['children'] = {name: {'pid': p.pid} for name, p in children.items()}
            save(out / 'result.json', result)
        launch('qemu', args)
        deadline = time.monotonic() + deadline_seconds
        while not (out / 'gdb.sock').exists():
            if children['qemu'].poll() is not None:
                raise RuntimeError('QEMU ended before debugger socket')
            if time.monotonic() >= deadline:
                raise TimeoutError('debugger socket')
            time.sleep(.02)
        launch('gdb', ['gdb', '-q', '-nx', '-batch', '-x', str(HERE / 'acpi-reset-gdb.py')])
        while any(p.poll() is None for p in children.values()):
            if children['gdb'].poll() not in (None, 0):
                raise RuntimeError('native GDB observer failed')
            if time.monotonic() >= deadline:
                raise TimeoutError('observation deadline')
            time.sleep(.02)
        if any(p.returncode != 0 for p in children.values()):
            raise RuntimeError('observer or QEMU did not exit naturally with zero')
        result['observation_complete'] = True
    except BaseException as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        for name, p in children.items():
            if p.poll() is None:
                cleanup.append({'child': name, 'pid': p.pid, 'signal': 'SIGTERM'})
                os.killpg(p.pid, signal.SIGTERM)
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    cleanup.append({'child': name, 'pid': p.pid, 'signal': 'SIGKILL'})
                    os.killpg(p.pid, signal.SIGKILL);p.wait(timeout=3)
        for stream in streams:
            stream.close()
        sock = out / 'gdb.sock'
        if sock.exists():
            sock.unlink()
        result['children'] = {name: {'pid': p.pid, 'exit': p.returncode} for name, p in children.items()}
        result['ended_unix'] = time.time()
        result['evidence_sha256'] = {p.name: sha(p) for p in out.iterdir() if p.is_file() and p.name != 'result.json'}
        save(out / 'result.json', result)
    return result


def build_fixtures(source, out):
    source, out = Path(source).resolve(), Path(out).resolve()
    out.mkdir(exist_ok=False)
    for mode, name in enumerate(['fadt', 'legacy', 'wrong-value', 'missing', 'unexecuted']):
        directory = out / name
        directory.mkdir()
        commands = [
            ['as', '--64', '--defsym', f'MODE={mode}', '-o', str(directory / 'fixture.o'), str(source)],
            ['ld', '-m', 'elf_x86_64', '-Ttext', '0x7c00', '--entry', '_start', '-o', str(directory / 'fixture.elf'), str(directory / 'fixture.o')],
            ['objcopy', '-O', 'binary', '-j', '.text', str(directory / 'fixture.elf'), str(directory / 'boot.bin')],
        ]
        for command in commands:
            subprocess.run(command, check=True)
        raw = (directory / 'boot.bin').read_bytes()
        if len(raw) != 512 or raw[-2:] != b'\x55\xaa':
            raise ValueError('fixture build did not produce one signed sector')
        listing = subprocess.check_output(['nm', '-n', str(directory / 'fixture.elf')], text=True)
        (directory / 'symbols.txt').write_text(listing)
        symbols = {parts[2]: int(parts[0], 16) for line in listing.splitlines() if len(parts := line.split()) == 3}
        prefix = raw[raw.index(b'FIXTURE REQUEST'):].split(b'\0', 1)[0]
        save(directory / 'fixture.json', {
            'name': name, 'fixture_only': True, 'mode': mode,
            'entry': symbols['fixture_entry'], 'reset_entry': symbols['fixture_reset'],
            'allowed_return_addresses': [symbols['fixture_return']],
            'out_pcs': [symbols[key] for key in sorted(symbols) if key.startswith('fixture_out_')],
            'prefix_hex': prefix.hex(), 'prefix_sha256': hashlib.sha256(prefix).hexdigest(),
            'source_sha256': sha(source), 'build_commands': commands,
            'sha256': {path.name: sha(path) for path in [directory / 'fixture.elf', directory / 'boot.bin']},
        })
        (directory / 'disassembly.txt').write_text(subprocess.check_output(['objdump', '-D', '-Mintel', str(directory / 'fixture.elf')], text=True))


def product_cases(bundle, out, selected, qemu):
    if not Path(out).is_absolute() or not Path(qemu).is_absolute():
        raise ValueError('product output and admitted QEMU must be absolute paths')
    bundle, out = Path(bundle).resolve(), Path(out).resolve()
    if out == bundle or bundle in out.parents:
        raise ValueError('fresh output must be outside immutable product assets')
    # Existing v2 product assets are immutable. Its obsolete frontend is never run.
    if sha(bundle / 'MANIFEST.sha256') != 'f50bac34730d17aa793734a0e92992972e87e1a9538995816e5acf499e6ee2c8':
        raise ValueError('product asset manifest differs from frozen v2')
    for line in (bundle / 'MANIFEST.sha256').read_text().splitlines():
        expected, relative = line.split('  ', 1)
        if sha(bundle / relative) != expected:
            raise ValueError('product asset identity mismatch: ' + relative)
    out.mkdir(mode=0o700, exist_ok=False)
    (out / 'plans').mkdir()
    contracts = {
        'positive': ('enabled', 'q35', 'fadt', None),
        'feature-only': ('enabled', 'q35', 'legacy', 'Disabled'),
        'option-only': ('default', 'q35', 'legacy', 'Disabled'),
        'default': ('default', 'q35', 'legacy', 'Disabled'),
        'missing-descriptor': ('enabled', 'pc-i440fx-8.2', 'legacy', 'Missing'),
        'duplicate-fadt': ('enabled', 'q35', 'legacy', 'Walk'),
    }
    names = list(contracts) if selected == 'all' else [selected]
    if any(name not in contracts for name in names):
        raise ValueError('unknown product case')
    plans, summary = {}, {'source_commit': 'f47818e18ea1dcee54bb5836f2710c247a7683da', 'cases': [], 'disposition': 'RUNNING'}
    save(out / 'suite.json', summary)
    try:
        for name in names:
            profile, machine, mode, reason = contracts[name]
            spec = json.loads((bundle / 'cases' / name / 'case.json').read_text())
            if (spec['name'], spec['profile'], spec['machine'], spec['mode']) != (name, profile, machine, mode):
                raise ValueError('product case does not match its frozen contract')
            elf = bundle / 'kernels' / (profile + '.elf')
            if profile not in plans:
                plans[profile] = product_plan(elf, out / 'plans' / profile)
            iso = bundle / 'cases' / name / 'boot.iso'
            if sha(iso) != spec['iso_sha256']:
                raise ValueError('actual consumed ISO differs')
            arguments = ['-cdrom', str(iso), '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
            arguments += [f'file={bundle / argument[5:]}' if argument.startswith('file=') else argument for argument in spec['extra_qemu_args']]
            case_out = out / name
            print('RUN ' + name, flush=True)
            result = collect(elf, plans[profile], arguments, case_out,
                             {'kind': 'product', 'machine': machine, 'case_name': name,
                              'source_commit': summary['source_commit'], 'iso_sha256': spec['iso_sha256']}, qemu, 120)
            if not result['observation_complete']:
                raise RuntimeError('product observation incomplete: ' + name)
            command = [sys.executable, str(HERE / 'check-acpi-reset.py'), '--observation', str(case_out), '--mode', mode, '--case-name', name]
            if reason is not None:
                command += ['--expected-reason', reason]
            with (case_out / 'checker.log').open('wb') as log:
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
            summary['cases'].append(name)
            save(out / 'suite.json', summary)
            print('PASS ' + name, flush=True)
        summary['disposition'] = 'PASS'
    except BaseException as error:
        summary['disposition'] = 'FAIL'
        summary['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        save(out / 'suite.json', summary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('build-fixtures')
    build.add_argument('--source', type=Path, required=True);build.add_argument('--out', type=Path, required=True)
    derive = sub.add_parser('derive-plan')
    derive.add_argument('--elf', type=Path, required=True);derive.add_argument('--out', type=Path, required=True)
    product = sub.add_parser('product')
    product.add_argument('--bundle', type=Path, required=True);product.add_argument('--out', type=Path, required=True)
    product.add_argument('--case', default='all', choices=['all', 'positive', 'feature-only', 'option-only', 'default', 'missing-descriptor', 'duplicate-fadt'])
    product.add_argument('--qemu', required=True)
    fixture = sub.add_parser('collect-fixture')
    fixture.add_argument('--fixture', type=Path, required=True);fixture.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'product':
        product_cases(args.bundle, args.out, args.case, args.qemu);return
    if args.command == 'build-fixtures':
        build_fixtures(args.source, args.out);return
    if args.command == 'derive-plan':
        print(json.dumps(product_plan(args.elf, args.out), indent=2));return
    data = json.loads((args.fixture / 'fixture.json').read_text())
    for name, expected in data['sha256'].items():
        if sha(args.fixture / name) != expected:
            raise ValueError('fixture identity changed')
    boot = (args.fixture / 'boot.bin').read_bytes()
    if len(boot) != 512 or boot[-2:] != b'\x55\xaa':
        raise ValueError('fixture is not the bounded 55aa bootsector')
    plan = {'entry': data['entry'], 'reset_entry': data['reset_entry'],
            'allowed_return_addresses': data['allowed_return_addresses'],
            'outs': [{'pc': pc, 'role': 'fixture'} for pc in data['out_pcs']]}
    result = collect(args.fixture / 'fixture.elf', plan,
                     ['-drive', f'file={args.fixture.resolve() / "boot.bin"},format=raw,if=floppy,index=0', '-boot', 'a'],
                     args.out, {'kind': 'fixture', 'fixture': data, 'machine': 'q35'})
    print(json.dumps(result, indent=2))
    sys.exit(0 if result['observation_complete'] else 1)


if __name__ == '__main__':
    main()
