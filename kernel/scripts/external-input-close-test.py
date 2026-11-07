#!/usr/bin/env python3
"""Exercise output draining after an external worker closes its input pipe."""

import argparse
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
EXPECTED = bytes(index % 251 for index in range(4096))


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, default=ROOT)
    parser.add_argument('--fixture', type=Path)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--case', action='append', default=[], help='run a named focused control (repeatable)')
    args = parser.parse_args()
    kernel = args.kernel.resolve()
    (kernel / 'build').mkdir(exist_ok=True)
    work = args.work or Path(tempfile.mkdtemp(prefix='external-input-close-', dir=kernel / 'build'))
    work = work.resolve()
    if args.work:
        work.mkdir(parents=True, exist_ok=False)
    fixture = args.fixture
    if fixture is None:
        source_map = subprocess.check_output(['sh', str(ROOT / 'scripts/rust-source-map.sh')], text=True).strip()
        env = dict(os.environ)
        for name in ('CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                     'CARGO_BUILD_TARGET', 'CARGO_MAKEFLAGS', 'MAKEFLAGS', 'MFLAGS', 'TARGET'):
            env.pop(name, None)
        env['RUSTFLAGS'] = (f'--remap-path-prefix={source_map} -C relocation-model=static -C code-model=large '
                            f'-C link-arg=-nostdlib -C link-arg=-static -C link-arg=-no-pie '
                            f'-C link-arg=-Wl,-T,{ROOT}/user/linker.ld')
        target = work / 'cargo'
        with (work / 'fixture-build.log').open('wb') as output:
            subprocess.run([os.environ.get('CARGO', 'cargo'), 'build', '--quiet', '--release', '--locked',
                            '--manifest-path', str(ROOT / 'user/Cargo.toml'), '--target-dir', str(target),
                            '--target', 'x86_64-unknown-linux-gnu', '--features', 'input-close-fixture',
                            '--bin', 'external_input_close'], env=env, stdout=output,
                           stderr=subprocess.STDOUT, check=True)
        fixture = target / 'x86_64-unknown-linux-gnu/release/external_input_close'
    fixture = fixture.resolve()
    passed = 0
    known_cases = set()
    for kind in ('embedded', 'live', 'durable'):
        live = kind == 'live'
        durable = kind == 'durable'
        cases = [
                ('failed-worker', b'F', 112000, 96, 99, False),
                ('successful-worker-incomplete-input', b'0', 112000, 0, 99, False),
                ('complete-input', b'0', 1, 0, 0, False)]
        if not live:
            cases.append(('output-eof-incomplete-input', b'E', 112000, -1, 99, False))
        if durable:
            cases += [('drain-timeout', b'T', 112000, -1, 99, False),
                      ('incomplete-input-with-reader', b'F', 112000, 96, 99, True),
                      ('failed-worker-with-reader', b'F', 1, 96, 99, True),
                      ('successful-reader-chain', b'0', 1, 0, 0, True)]
        for name, mode, size, worker_status, status, reader in cases:
            label = kind + '-' + name
            known_cases.add(label)
            if args.case and label not in args.case:
                continue
            case = work / label
            case.mkdir()
            drain_timeout = mode == b'T'
            reader_runs = reader and size == 1
            case_expected = case / 'expected.bin'
            case_expected.write_bytes(EXPECTED * (2 if reader_runs else 1))
            reader_input = case / 'reader-input.bin'
            reader_input.write_bytes(b'0')
            source = case / 'input.bin'
            source.write_bytes(mode + b'x' * (size - 1))
            # Live input is supplied after boot; its embedded placeholder is empty.
            placeholder = case / 'embedded.bin'
            placeholder.write_bytes(b'' if live else source.read_bytes())
            with (case / 'build.log').open('wb') as output:
                subprocess.run(['make', '--no-print-directory', '-C', str(kernel),
                                'durable-iso' if durable else ('external-live-iso' if live else 'external-iso'),
                                f'EXTERNAL_USER_ELF={fixture}', f'EXTERNAL_INPUT={placeholder}',
                                f'EXTERNAL_EXPECTED={case_expected}',
                                f'EXTERNAL_READER_ELF={fixture if reader else ""}',
                                f'EXTERNAL_READER_INPUT={reader_input if reader else ""}',
                                'DURABLE_STEP=1', f'DURABLE_OPTIONS={"net" if drain_timeout else ""}',
                                f'NET_WAIT_TICKS={1000 if drain_timeout else ""}',
                                'FILE_SERVER_ELF=', 'BROKER_POLICY=', 'ENROLL_STREAM='],
                               stdout=output, stderr=subprocess.STDOUT, check=True)
            serial = case / 'serial.log'
            iso = kernel / 'build' / ('durable/absd-durable-1.iso' if durable else
                                      ('absd-external-live.iso' if live else 'absd-external.iso'))
            command = [*shlex.split(args.qemu), '-cdrom', str(iso), '-display', 'none',
                       '-no-reboot', '-no-shutdown', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
            if drain_timeout:
                command += ['-netdev', 'user,id=net0', '-device', 'e1000,netdev=net0']
            if durable:
                image = case / 'scratch.img'
                with image.open('wb') as disk:
                    disk.truncate(16 * 1024 * 1024)
                command += ['-drive', f'file={image},format=raw,if=ide,index=0']
            with tempfile.TemporaryDirectory(prefix='absd-input-close-') as socket_dir:
                socket = Path(socket_dir) / 'console.sock'
                if live:
                    command += ['-chardev', f'socket,id=con,path={socket},server=on,wait=on',
                                '-serial', 'chardev:con']
                else:
                    command += ['-serial', f'file:{serial}']
                with (case / 'qemu.log').open('wb') as output:
                    process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                               start_new_session=True)
                    try:
                        if live:
                            with (case / 'input-driver.log').open('wb') as driver_output:
                                subprocess.run(['python3', str(ROOT / 'scripts/external-live-session.py'),
                                                str(socket), str(serial), str(source), 'normal'],
                                               stdout=driver_output, stderr=subprocess.STDOUT,
                                               timeout=200, check=True)
                        returned = process.wait(timeout=240)
                    finally:
                        stop(process)
            if returned != (3 if status == 0 else 7):
                raise RuntimeError(f'{label}: unexpected QEMU exit {returned}')
            text = serial.read_text(errors='replace')
            census = 'DURABLE' if durable else 'EXTERNAL'
            if (len(re.findall(rf'^{census} status=', text, re.M)) != 1
                    or not re.search(rf'^{census} status={status} frames=0 processes=0 cells=0 pipes=0(?: |$)', text, re.M)):
                raise RuntimeError(f'{label}: missing exact outcome/resource census')
            captured = bytearray()
            for match in re.finditer(r'^EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)$', text, re.M):
                if int(match.group(1), 16) != len(captured):
                    raise RuntimeError(f'{label}: non-contiguous captured output')
                captured.extend(bytes.fromhex(match.group(2)))
            if bytes(captured) != case_expected.read_bytes():
                raise RuntimeError(f'{label}: output lost: {len(captured)} of {case_expected.stat().st_size} bytes')
            outcome_prefix = r'DURABLE WORKER OUTCOME generation=1' if durable else 'EXTERNAL WORKLOAD OUTCOME'
            outcomes = re.findall(rf'^{outcome_prefix} pid=\d+ status=(-?\d+)$', text, re.M)
            if outcomes != [str(worker_status)]:
                raise RuntimeError(f'{label}: worker outcome changed or missing: {outcomes}')
            if re.search(r'PANIC|KERNEL FAULT', text):
                raise RuntimeError(f'{label}: kernel failure')
            if status != 0 and (f'{census} WORKLOAD FAILED' not in text or 'ABSD BOOT OK' in text):
                raise RuntimeError(f'{label}: incomplete input accepted')
            if status == 0 and (f'{census} WORKLOAD OK' not in text or 'ABSD BOOT OK' not in text
                                or f'{census} WORKLOAD FAILED' in text):
                raise RuntimeError(f'{label}: successful input did not complete')
            if drain_timeout:
                if len(re.findall(r'^EXTERNAL OUTPUT BEGIN encoding=hex$', text, re.M)) != 1:
                    raise RuntimeError(f'{label}: missing or duplicate output begin')
                if 'FAILED at external workload deadline' not in text or 'EXTERNAL OUTPUT END' in text:
                    raise RuntimeError(f'{label}: timeout completed or mislabeled its capture')
            else:
                subprocess.run(['python3', str(ROOT / 'scripts/check-external-output.py'),
                                str(serial), str(case_expected)], check=True)
            readers = re.findall(r'^DURABLE READER OUTCOME pid=\d+ status=(-?\d+)$', text, re.M)
            if readers != (['0'] if reader_runs else []):
                raise RuntimeError(f'{label}: unexpected reader outcomes {readers}')
            if not reader_runs and 'DURABLE READER START' in text:
                raise RuntimeError(f'{label}: reader started after failed input/worker')
            passed += 1
            print(f'external-input-close: {label} PASS bytes={case_expected.stat().st_size} worker={worker_status} status={status}',
                  flush=True)
    if set(args.case) - known_cases:
        raise RuntimeError(f'unknown control names: {sorted(set(args.case) - known_cases)}')
    scope = 'selected' if args.case else 'all'
    print(f'external-input-close: {scope} {passed} controls passed ({work})', flush=True)


if __name__ == '__main__':
    main()
