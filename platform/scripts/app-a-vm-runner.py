#!/usr/bin/env python3
"""Materialize and execute one App A VM occurrence without manual phase control."""
import asyncio
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import tomllib
import uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from served_ram import served_qemu


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    return sha_bytes(Path(path).read_bytes())


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def replace_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def read_json(path):
    return json.loads(Path(path).read_text())


def replace_tree(path, replacements):
    if not path.is_file() or path.is_symlink():
        return
    try:
        text = path.read_text()
    except UnicodeDecodeError:
        return
    for old, new in replacements:
        text = text.replace(old, new)
    path.write_text(text)


def checked_file(path, pin, label):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError(label + ' is not a regular file: ' + str(path))
    if path.stat().st_size != pin['bytes'] or digest(path) != pin['sha256']:
        raise ValueError(label + ' changed: ' + str(path))
    return path


def rekey_path_pins(value, destination_hashes):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key == 'sha256' and isinstance(value.get('path'), str) and value['path'] in destination_hashes:
                result[key] = destination_hashes[value['path']]
            elif key == 'driver_sha256' and 'lifecycle/app.py' in destination_hashes:
                result[key] = destination_hashes['lifecycle/app.py']
            else:
                result[key] = rekey_path_pins(item, destination_hashes)
        return result
    if isinstance(value, list):
        return [rekey_path_pins(item, destination_hashes) for item in value]
    return value


def verify_source(candidate):
    root = Path(candidate['source_root']).resolve(strict=True)
    identity = candidate['source_identity']
    observed = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    if observed != candidate['source_revision'] or observed != identity['revision']:
        raise ValueError('candidate source revision differs from observed Git HEAD')
    if subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=all'], text=True):
        raise ValueError('candidate source tree is not clean')
    tree = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
    archive = subprocess.check_output(['git', '-C', str(root), 'archive', '--format=tar', 'HEAD'])
    actual = {'revision': observed, 'tree': tree, 'archive_sha256': sha_bytes(archive), 'archive_bytes': len(archive)}
    if actual != identity:
        raise ValueError('candidate source identity differs from observed Git identity')
    return actual


def make_machine(binary, args, work, qemu_python, wrapper=()):
    work = Path(work)
    pidfile = work / 'qemu.pid'
    if pidfile.exists() or pidfile.is_symlink():
        raise ValueError('QEMU PID file must be fresh: ' + str(pidfile))
    (work / 'logs').mkdir(parents=True, exist_ok=True)
    (work / 'scratch').mkdir(parents=True, exist_ok=True)
    asyncio.set_event_loop(asyncio.new_event_loop())
    sys.path.insert(0, str(qemu_python))
    from qemu.machine import QEMUMachine
    return QEMUMachine(
        binary,
        args=['-pidfile', str(pidfile), *args],
        wrapper=wrapper,
        name='app-a',
        base_temp_dir=str(work / 'scratch'),
        monitor_address=str(work / 'qmp.sock'),
        log_dir=str(work / 'logs'),
        qmp_timer=10,
    )


def read_qemu_pid(work):
    # QEMU writes its own PID, in its PID namespace. QEMUMachine.get_pid()
    # instead names the podman/timeout wrapper; QMP has no query-pid command.
    pidfile = Path(work) / 'qemu.pid'
    if not pidfile.is_file() or pidfile.is_symlink():
        raise ValueError('QEMU did not produce a regular PID file')
    pid = int(pidfile.read_text().strip())
    if pid <= 1:
        raise ValueError('invalid QEMU PID')
    return pid


def qemu_profile(profile, vm_root, control_port):
    argv = profile['qemu_argv']
    binary = argv[0]
    args = []
    skip = False
    for item in argv[1:]:
        if skip:
            skip = False
            continue
        if item in ('-monitor', '-qmp'):
            skip = True
            continue
        args.append(item.replace('<vm>', str(vm_root)).replace('<admitted-control-port>', str(control_port)))
    if any('<' in item or '>' in item for item in args):
        raise ValueError('unresolved QEMU profile placeholder')
    expected = 'hostfwd=tcp:127.0.0.1:' + str(control_port) + '-10.199.97.15:22'
    if sum(expected in item for item in args) != 1:
        raise ValueError('QEMU control forward differs from admitted port')
    return binary, args


def staging_host_ssh_argv(command, streamed):
    target = os.environ.get('ABSD_APP_A_SSH_TARGET', '')
    identity = os.environ.get('ABSD_APP_A_SSH_IDENTITY', '')
    if not target or not identity:
        raise ValueError('explicit ABSD_APP_A_SSH_TARGET and ABSD_APP_A_SSH_IDENTITY are required')
    if target.startswith('-') or any(c.isspace() for c in target):
        raise ValueError('invalid explicit SSH target')
    return [
        'ssh', *([] if streamed else ['-n']),
        '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no', '-i', identity,
        '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        target, command,
    ]


def guest_argv(run, vm_root, control_port):
    vm_root = str(vm_root)
    client = vm_root + '/private-client/'
    return {
        'execution_go': True,
        'run': run,
        'identity_agent': 'none',
        'strict_host_key': True,
        'argv': [
            'podman', 'exec', '-i', '--user', '1000:1000', '--workdir', vm_root,
            '--env', 'SSH_AUTH_SOCK=', 'absd-noble', 'ssh', '-F', '/dev/null',
            '-oIdentityAgent=none', '-oIdentitiesOnly=yes', '-oForwardAgent=no',
            '-oStrictHostKeyChecking=yes', '-oUpdateHostKeys=no', '-oGlobalKnownHostsFile=/dev/null',
            '-oUserKnownHostsFile=' + client + 'known_hosts', '-oBatchMode=yes', '-oConnectTimeout=5',
            '-i', client + 'client-ed25519', '-p', str(control_port), 'root@127.0.0.1',
        ],
    }


def terminal_result(output, context, error=None, cleanup_errors=()):
    result = dict(context)
    result.setdefault('product_result', 'NOT_RUN')
    result.setdefault('cleanup_state', 'COMPLETE')
    if error is None:
        result.setdefault('disposition', 'EXECUTION_COMPLETE_NOT_INDEPENDENT_ACCEPTANCE')
        result.setdefault('failure_domain', None)
        result.setdefault('first_diagnostic', None)
    else:
        result['disposition'] = 'INFRASTRUCTURE_INCOMPLETE'
        result['failure_domain'] = 'harness'
        result['first_diagnostic'] = type(error).__name__ + ': ' + str(error)
    result['cleanup_errors'] = list(cleanup_errors)
    if cleanup_errors:
        result['cleanup_state'] = 'INCOMPLETE'
    write_json(Path(output) / 'RESULT.json', result)
    return result


def prepare_admission(draft, input_manifest_sha256, stage_sums_sha256, control_port, outer_t10, now):
    bound = json.loads(json.dumps(draft))
    ceiling = bound['aggregate_preparation_ceiling_s']
    hard_end = outer_t10 - 1800
    preparation_deadline = now + ceiling
    if now + ceiling + 10705 >= hard_end:
        raise ValueError('original lease cannot fit preparation, driver and retirement reserves')
    bound.update(
        execution_go=True,
        input_manifest_sha256=input_manifest_sha256,
        stage_sums_sha256=stage_sums_sha256,
        outer_T10_unix_s=outer_t10,
        hard_end_unix_s=hard_end,
        control_port=control_port,
        preparation_deadline_unix_s=preparation_deadline,
    )
    return bound


def require_smoke(output, result):
    if result.get('disposition') != 'SMOKE_PASS_NOT_QUALIFICATION':
        raise ValueError('smoke disposition is not explicit non-qualification')
    expected = b'ABSD App A harness smoke\n'
    if output != expected:
        raise ValueError('smoke output differs from nested known-byte workload')
    if result.get('workload', {}).get('output_sha256') != sha_bytes(output):
        raise ValueError('smoke output digest differs from workload receipt')
    return {'product_result': 'SMOKE_PASS_NOT_QUALIFICATION', 'output_sha256': sha_bytes(output)}


def evidence_archive(output):
    output = Path(output)
    stream = io.BytesIO()
    rows = []
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for root_name in ('evidence', 'logs'):
            root = output / root_name
            if not root.exists():
                continue
            for path in sorted(root.rglob('*')):
                if path.is_dir():
                    continue
                if not path.is_file() or path.is_symlink():
                    raise ValueError('evidence contains a non-regular member: ' + str(path))
                data = path.read_bytes()
                if b'PRIVATE KEY-----' in data or b'OPENSSH PRIVATE KEY' in data:
                    raise ValueError('evidence contains private key material: ' + str(path))
                name = path.relative_to(output).as_posix()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o600
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
                rows.append(sha_bytes(data) + '  ' + name)
    return stream.getvalue(), rows


class StagedExecutor:
    def __init__(self, occurrence, public, mode, control_port, qemu_python, harness_revision):
        self.occurrence = Path(occurrence)
        self.public = Path(public)
        self.mode = mode
        self.control_port = control_port
        self.qemu_python = Path(qemu_python)
        self.harness_revision = harness_revision
        materialization = self.occurrence / 'MATERIALIZATION.json'
        self.materialization = read_json(materialization) if materialization.is_file() else {}
        self.run_id = self.materialization.get('run')
        self.source_revision = self.materialization.get('source_revision')
        self.phase = 'not_started'
        self.product_result = 'NOT_RUN'
        self.product_output = None
        self.machine = None
        self.bounds = None

    def load_helper(self, name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def execute(self, argv, data=None, timeout=7200):
        result = subprocess.run(
            list(argv), input=data, stdin=None if data is not None else subprocess.DEVNULL,
            capture_output=True, timeout=timeout, check=False,
        )
        record = {
            'argv': list(argv), 'input': None if data is None else {'bytes': len(data), 'sha256': sha_bytes(data)},
            'exit': result.returncode, 'stdout': result.stdout.decode(errors='replace'),
            'stderr': result.stderr.decode(errors='replace'),
        }
        log = self.public / 'logs/commands.jsonl'
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open('a') as stream:
            stream.write(json.dumps(record, sort_keys=True) + '\n')
        if result.returncode != 0:
            diagnostic = (result.stderr + result.stdout).decode(errors='replace')[-1000:]
            raise ValueError('command exited ' + str(result.returncode) + ': ' + diagnostic)
        return result

    def remote_bytes(self, path):
        return self.execute(self.guest['argv'] + ['cat ' + shlex.quote(str(path))], timeout=120).stdout

    def remote_json(self, path):
        return json.loads(self.remote_bytes(path))

    def remote_sha256(self, path):
        return self.execute(self.guest['argv'] + ['sha256sum ' + shlex.quote(str(path))], timeout=120).stdout.decode().split()[0]

    def deliver(self, local, remote):
        raw = Path(local).read_bytes()
        command = 'umask 077; set -C; cat > ' + shlex.quote(str(remote))
        self.execute(self.guest['argv'] + [command], data=raw, timeout=120)
        if self.remote_sha256(remote) != sha_bytes(raw):
            raise ValueError('guest byte readback differs: ' + str(remote))

    def launch(self):
        staged = read_json(self.occurrence / 'STAGED.json')
        if staged.get('run') != self.run_id:
            raise ValueError('staged run differs from occurrence')
        if staged.get('materialization_sha256') != digest(self.occurrence / 'MATERIALIZATION.json'):
            raise ValueError('staged materialization hash differs')
        if 'harness_inputs_sha256' in staged:
            manifest_path = self.occurrence / 'HARNESS-INPUTS.json'
            if not manifest_path.is_file() or digest(manifest_path) != staged['harness_inputs_sha256']:
                raise ValueError('staged harness manifest differs')
            if staged.get('control_port') != self.control_port:
                raise ValueError('staged control port differs')
            if staged.get('harness_revision') != self.harness_revision:
                raise ValueError('staged harness revision differs')
            if self.materialization.get('harness_inputs_sha256') != staged['harness_inputs_sha256']:
                raise ValueError('materialization harness identity differs')
            manifest = read_json(manifest_path)
            actual = self.execute(['podman', 'exec', '--user', '1000:1000', 'absd-noble', 'sha256sum', '/usr/bin/qemu-system-x86_64'], timeout=60).stdout.decode().split()[0]
            if actual != manifest['qemu_binary']['sha256']:
                raise ValueError('outer QEMU binary differs at staged launch')
        self.input_manifest_sha256 = staged['input_manifest_sha256']
        bounds_path = self.occurrence / 'LAUNCH-BOUNDS.json'
        if bounds_path.is_file():
            self.bounds = read_json(bounds_path)
            if (self.bounds.get('stage') != 'APP_REPLACEMENT' or self.bounds.get('ceiling_s') != 14400
                    or time.time() >= self.bounds['host_unit_end_unix_s']):
                raise ValueError('original dispatch bounds are not valid for launch')
        else:
            launch_helper = self.load_helper('app_a_lifetime', self.occurrence / 'bindings/host/launch.py')
            self.bounds, ok = launch_helper.lifetime_bounds(time.time(), stage='APP_REPLACEMENT', confirmed_ceiling_s=14400)
            if not ok:
                raise ValueError('original App A lifetime bounds refused launch')
        profile_path = self.occurrence / 'bindings/host/OUTER-LAUNCH-TEMPLATE.json'
        profile = read_json(profile_path)
        binary, args = qemu_profile(profile, self.occurrence, self.control_port)
        args = served_qemu(args)
        duration = max(1, int(self.bounds['container_term_unix_s'] - time.time()))
        wrapper = (
            '/usr/bin/podman', 'exec', '--user', '1000:1000', '--workdir', str(self.occurrence),
            '--env', 'SSH_AUTH_SOCK=', '--env', 'MALLOC_ARENA_MAX=2', 'absd-noble',
            'taskset', '-c', '0-2', 'nice', '-n', '10', 'timeout', '--signal=TERM',
            '--kill-after=120s', str(duration), 'prlimit', '--as=21474836480:21474836480', '--',
        )
        probe = make_machine(binary, served_qemu(['-machine', 'none', '-nodefaults']), self.public / 'helper-probe', self.qemu_python, wrapper=wrapper)
        probe_pid = None
        probe_error = None
        try:
            probe.launch()
            probe_pid = read_qemu_pid(self.public / 'helper-probe')
            probe.shutdown(timeout=30)
        except BaseException as error:
            probe_error = error
        finally:
            errors = []
            if probe.is_running() or self.qemu_process_running(probe, probe_pid):
                stopped, errors = self.stop_machine(probe, probe_pid)
            if probe_error is not None or errors:
                write_json(self.public / 'logs/QEMU-HELPER-PROBE.json', {
                    'disposition': 'FAIL', 'error': str(probe_error) if probe_error is not None else None,
                    'cleanup_errors': errors,
                })
        if probe_error is not None:
            raise probe_error
        if errors:
            raise RuntimeError('QEMU helper probe cleanup failed: ' + '; '.join(errors))
        write_json(self.public / 'logs/QEMU-HELPER-PROBE.json', {'disposition': 'PASS', 'exit': probe.exitcode()})
        self.machine = make_machine(binary, args, self.public, self.qemu_python, wrapper=wrapper)
        self.machine.launch()
        qemu_pid = read_qemu_pid(self.public)
        self.qemu_pid = qemu_pid
        write_json(self.public / 'logs/LAUNCH.json', {
            'run': self.run_id, 'profile_sha256': digest(profile_path),
            'argv': list(self.machine._qemu_full_args), 'wrapper_pid': self.machine.get_pid(),
            'qemu_pid': qemu_pid, 'bounds': self.bounds, 'watchdog_seconds': duration,
        })
        if '-S' in args:
            self.machine.qmp('cont')
        deadline = time.monotonic() + 240
        identity = None
        serial = self.occurrence / 'serial.log'
        while time.monotonic() < deadline:
            if serial.is_file():
                lines = [line for line in serial.read_text(errors='replace').splitlines() if line.startswith('ABSD_VM_IDENTITY ')]
                if lines:
                    identity = json.loads(lines[-1].split(' ', 1)[1])
                    break
            if not self.machine.is_running():
                raise ValueError('outer QEMU ended before guest identity')
            time.sleep(1)
        if identity is None:
            raise TimeoutError('outer guest identity not observed')
        if identity.get('run') != self.run_id or identity.get('input_manifest_sha256') != self.input_manifest_sha256:
            raise ValueError('outer guest identity or input manifest differs')
        host_key = identity['public_host_key']
        known = '[127.0.0.1]:' + str(self.control_port) + ' ' + host_key + '\n'
        (self.occurrence / 'private-client/known_hosts').write_text(known)
        self.guest = guest_argv(self.run_id, self.occurrence, self.control_port)
        write_json(self.occurrence / 'private-client/APP-GUEST-ARGV.json', self.guest)
        fingerprint = self.execute(self.guest['argv'] + ['ssh-keygen -E sha256 -lf /etc/ssh/ssh_host_ed25519_key.pub'], timeout=30).stdout.decode().strip()
        if fingerprint.split()[1] != identity['host_fingerprint'].split()[1]:
            raise ValueError('outer SSH host key differs from serial identity')

    def guest_phase(self, phase):
        if phase == 'inputs':
            # The first phase executable lives on this ISO. Its installer cannot
            # mount the medium until the launcher has made that executable visible.
            manifest = shlex.quote(self.input_manifest_sha256)
            command = (
                'set -eu; mkdir -p /mnt/input; '
                'mount -o ro /dev/disk/by-label/ABSDINPUT /mnt/input; '
                'test "$(sha256sum /mnt/input/INPUT-SHA256SUMS | cut -d \' \' -f 1)" = '
                + manifest + '; cd /mnt/input; sha256sum --quiet -c INPUT-SHA256SUMS'
            )
            self.execute(self.guest['argv'] + [command], timeout=300)
        outputs = {
            'inputs': '/root/APP-INPUTS-UNIT-' + self.run_id[:8] + '.json',
            'clock': '/root/absd-e-custody/APP-CLOCK-UNIT.json',
            'd-net': '/root/absd-e-custody/APP-d-net-UNIT.json',
            'd-units': '/root/absd-e-custody/APP-d-units-UNIT.json',
            'd-cpuid': '/root/absd-e-custody/APP-d-cpuid-UNIT.json',
        }
        admission = '/root/app-prepare-' + self.run_id + '.json'
        argv = [
            'python3', '-I', '-B', '/mnt/input/lifecycle/launch-app-phase.py', '--phase', phase,
            '--admission', admission, '--admission-sha256', digest(self.occurrence / 'APP-PREPARE-ADMISSION.json'),
            '--output', outputs[phase],
        ]
        try:
            self.execute(self.guest['argv'] + [shlex.join(argv)], timeout=1260)
        except BaseException:
            # Unit stdout/stderr otherwise die with the outer overlay. Preserve
            # the original command failure even if journal retrieval also fails.
            try:
                unit = 'absd-app-' + phase + '-' + self.run_id[:8]
                journal = self.execute(self.guest['argv'] + [shlex.join([
                    'journalctl', '--no-pager', '-o', 'short-precise', '-u', unit])], timeout=30)
                (self.public / 'logs').mkdir(parents=True, exist_ok=True)
                (self.public / 'logs' / (phase + '-failure-journal.txt')).write_bytes(journal.stdout)
            except BaseException as diagnostic_error:
                self.diagnostic_error = str(diagnostic_error)
            raise

    def clock_handoff(self, mode, admission):
        admission = Path(admission)
        (self.public / 'clock').mkdir(parents=True, exist_ok=True)
        argv = [
            '/usr/bin/python3', '-I', '-B', str(self.occurrence / 'source/clock-app-handoff.py'),
            '--admission', str(admission), '--admission-sha256', digest(admission),
            '--guest-argv', str(self.occurrence / 'private-client/APP-GUEST-ARGV.json'),
            '--output', str(self.public / 'clock' / mode),
            '--proof-script', str(self.occurrence / 'source/staging_host-clock-proof.py'),
            '--clock-helper', str(self.occurrence / 'staging/input-tree/lifecycle/files/0188'),
            '--mode', mode,
        ]
        self.execute(argv, timeout=300)

    def prepare(self):
        draft = read_json(self.occurrence / 'PREPARE-ADMISSION.DRAFT.json')
        prepare = prepare_admission(
            draft, self.input_manifest_sha256, self.materialization['stage_sha256'],
            self.control_port, self.bounds['monitor_t10_unix_s'], int(time.time()),
        )
        prepare_path = self.occurrence / 'APP-PREPARE-ADMISSION.json'
        write_json(prepare_path, prepare)
        self.deliver(prepare_path, '/root/app-prepare-' + self.run_id + '.json')
        self.guest_phase('inputs')
        d05 = [
            'python3', '-I', '-B', str(self.occurrence / 'staging/input-tree/lifecycle/d05-after-install.py'),
            '--run', self.run_id, '--guest-argv', str(self.occurrence / 'private-client/APP-GUEST-ARGV.json'),
            '--output', str(self.public / 'D05'), '--canary-port', '24133', '--control-port', str(self.control_port),
            '--admission', str(prepare_path), '--admission-sha256', digest(prepare_path),
        ]
        self.execute(d05, timeout=300)
        for phase in ('d-net', 'd-units', 'd-cpuid', 'clock'):
            self.guest_phase(phase)
        credentials = read_json(self.occurrence / 'CREDENTIALS-ADMISSION.DRAFT.json')
        credentials.update(
            execution_go=True, auto_bind_clock=True,
            hard_end_unix_s=prepare['hard_end_unix_s'],
            preparation_deadline_unix_s=prepare['preparation_deadline_unix_s'],
            outer_T10_unix_s=prepare['outer_T10_unix_s'],
            clock_composite_sha256=None,
        )
        credentials_path = self.occurrence / 'CREDENTIALS-PREAUTHORIZATION.json'
        write_json(credentials_path, credentials)
        self.clock_handoff('credentials', credentials_path)
        base = '/root/absd-app-replacement/' + self.run_id
        machine = self.remote_json(base + '/public/MACHINE-IDENTITY.json')
        namespace = self.remote_json(base + '/public/NAMESPACE-IDENTITY.json')
        runtime = read_json(self.occurrence / 'RUNTIME-ADMISSION.DRAFT.json')
        runtime.update(
            execution_go=True, auto_bind_clock=True,
            producer_runtime_max_s=runtime['remaining_forecast_s'] + 30,
            hard_end_unix_s=prepare['hard_end_unix_s'],
            outer_monitor_t10_unix_s=prepare['outer_T10_unix_s'],
            preparation_deadline_unix_s=prepare['preparation_deadline_unix_s'],
            machine_id_sha256=machine['stripped_identity_sha256'],
            machine_id_file_sha256=machine['raw_file_sha256'],
            parent_network_namespace_inode=machine['parent_netns_inode'],
            clock_attestor='staging_host CLOCK_REALTIME via KVM PTP/chrony PHC; guest bound remains guest-to-staging_host',
        )
        runtime['qemu'] = {'path': '/usr/bin/qemu-system-x86_64', 'sha256': self.remote_sha256('/usr/bin/qemu-system-x86_64')}
        runtime['network_namespace'].update(device=namespace['device'], inode=namespace['inode'])
        runtime['client_public_key']['sha256'] = self.remote_sha256(runtime['client_public_key']['path'])
        runtime['pki_result']['sha256'] = self.remote_sha256(runtime['pki_result']['path'])
        runtime['clock_composite']['sha256'] = None
        runtime_path = self.occurrence / 'RUNTIME-PREAUTHORIZATION.json'
        write_json(runtime_path, runtime)
        self.runtime = runtime
        self.clock_handoff('runtime', runtime_path)

    def wait_product_unit(self):
        deadline = time.monotonic() + self.runtime['producer_runtime_max_s']
        identity = None
        while time.monotonic() < deadline:
            command = 'systemctl show ' + self.runtime['unit'] + ' --property=Id,Result,ExecMainCode,ExecMainStatus,ActiveState,SubState,InvocationID,MainPID'
            props = dict(line.split('=', 1) for line in self.execute(self.guest['argv'] + [command], timeout=30).stdout.decode().splitlines() if '=' in line)
            invocation = props.get('InvocationID')
            terminal = (props.get('SubState') in ('exited', 'failed', 'dead')
                        or props.get('ActiveState') in ('failed', 'inactive'))
            if terminal:
                write_json(self.public / 'evidence/PRODUCER-UNIT-TERMINAL.json', props)
                return props
            if not invocation:
                raise ValueError('active product unit has no invocation identity')
            if identity is None:
                identity = invocation
            if invocation != identity:
                raise ValueError('product unit invocation changed')
            time.sleep(0.2)
        raise TimeoutError('product unit did not reach a terminal state')

    def run_product(self):
        base = '/root/absd-app-replacement/' + self.run_id
        self.wait_product_unit()
        product = self.remote_json(base + '/evidence/RESULT.json')
        write_json(self.public / 'evidence/PRODUCT-RESULT.json', product)
        if self.mode == 'smoke_cat' and product.get('disposition') == 'SMOKE_PASS_NOT_QUALIFICATION':
            self.product_output = self.remote_bytes(base + '/evidence/CAT-OUTPUT.txt')
            (self.public / 'evidence/CAT-OUTPUT.txt').write_bytes(self.product_output)
        return product

    def qemu_process_running(self, machine, qemu_pid):
        if qemu_pid is None:
            return True
        try:
            result = subprocess.run(
                ['podman', 'exec', '--user', '1000:1000', 'absd-noble', 'kill', '-0', str(qemu_pid)],
                capture_output=True, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return True
        if result.returncode == 0:
            try:
                state = subprocess.run(
                    ['podman', 'exec', '--user', '1000:1000', 'absd-noble', 'ps', '-p', str(qemu_pid), '-o', 'stat='],
                    capture_output=True, timeout=30, check=False,
                )
            except (OSError, subprocess.SubprocessError):
                return True
            return state.returncode != 0 or not state.stdout.strip().startswith(b'Z')
        return b'no such process' not in result.stderr.lower()

    def stop_machine(self, machine, qemu_pid):
        errors = []
        try:
            machine.shutdown(timeout=30)
        except BaseException:
            pass
        if self.qemu_process_running(machine, qemu_pid):
            try:
                if qemu_pid is not None:
                    self.execute(['podman', 'exec', '--user', '1000:1000', 'absd-noble', 'kill', '-TERM', str(qemu_pid)], timeout=30)
                deadline = time.monotonic() + 30
                while self.qemu_process_running(machine, qemu_pid) and time.monotonic() < deadline:
                    time.sleep(0.1)
                if self.qemu_process_running(machine, qemu_pid):
                    machine.shutdown(hard=True)
            except BaseException as error:
                errors.append('QEMU exact-PID termination: ' + str(error))
        if self.qemu_process_running(machine, qemu_pid):
            errors.append('QEMU process remains running')
        return not errors, errors

    def cleanup(self):
        errors = []
        if hasattr(self, 'guest'):
            base = '/root/absd-app-replacement/' + self.run_id
            try:
                (self.public / 'evidence').mkdir(parents=True, exist_ok=True)
                command = ('set -eu; cd ' + shlex.quote(base)
                           + '; set --; for name in evidence public; do '
                           'if test -d "$name"; then set -- "$@" "$name"; fi; done; '
                           'tar -cf - --files-from /dev/null "$@"')
                raw = self.execute(self.guest['argv'] + [command], timeout=600).stdout
                with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
                    for member in archive.getmembers():
                        if member.isfile() and b'PRIVATE KEY-----' in archive.extractfile(member).read():
                            raise ValueError('guest evidence contains private key material')
                (self.public / 'evidence/GUEST-EVIDENCE.tar').write_bytes(raw)
            except BaseException as error:
                errors.append('guest evidence export: ' + str(error))
        guest_filesystems_synced = None
        if hasattr(self, 'guest'):
            try:
                self.execute(self.guest['argv'] + ['sync -f / /evidence'], timeout=120)
                guest_filesystems_synced = True
            except BaseException as error:
                guest_filesystems_synced = False
                errors.append('outer guest filesystem sync: ' + str(error))
        qemu_stopped = False
        if self.machine is not None:
            qemu_stopped, stop_errors = self.stop_machine(self.machine, getattr(self, 'qemu_pid', None))
            errors.extend(stop_errors)
        try:
            raw, rows = evidence_archive(self.public)
            (self.public / 'QUALIFICATION-EVIDENCE.tar').write_bytes(raw)
            (self.public / 'QUALIFICATION-EVIDENCE-SHA256SUMS').write_text('\n'.join(rows) + '\n')
            evidence_sha = sha_bytes(raw)
        except BaseException as error:
            errors.append('local evidence archive: ' + str(error))
            evidence_sha = None
        try:
            self.execute(['shred', '-u', '--', str(self.occurrence / 'private-client/client-ed25519')], timeout=120)
        except BaseException as error:
            errors.append('client key retirement: ' + str(error))
        if (qemu_stopped and self.mode == 'smoke_cat'
                and self.product_result == 'SMOKE_PASS_NOT_QUALIFICATION' and not errors):
            try:
                self.execute(['rm', '-f', '--', str(self.occurrence / 'root.qcow2')], timeout=120)
            except BaseException as error:
                errors.append('outer overlay retirement: ' + str(error))
        elif not qemu_stopped and self.machine is not None:
            errors.append('outer overlay retained because QEMU exit is unproven')
        private_custody = None
        if self.mode == 'app_a' or (self.occurrence / 'root.qcow2').exists():
            # App A's failed images and recovery point live on this overlay.
            # Neither PASS nor a missing driver result ends their dependencies.
            # Failed smoke overlays also retain otherwise-unexported diagnostics.
            template = {}
            try:
                template = read_json(self.occurrence / 'CONFIG.TEMPLATE.NO-GO.json')
            except (OSError, ValueError) as error:
                errors.append('private artifact custody metadata: ' + str(error))
            private_custody = {
                'retained': (self.occurrence / 'root.qcow2').exists(),
                'overlay': str(self.occurrence / 'root.qcow2'),
                'backing_image': str(self.occurrence / 'base.img'),
                'custodian': template.get('custodian'),
                'retirement_condition': template.get('retirement_condition'),
                'scope': 'Guest private-work images/point and VM-local credentials remain confined to the VM overlay; no private export.',
            }
        write_json(self.public / 'CLOSEOUT.json', {
            'run': self.run_id, 'evidence_archive_sha256': evidence_sha,
            'machine_exit': self.machine.exitcode() if self.machine is not None else None,
            'qemu_stopped': qemu_stopped,
            'guest_filesystems_synced': guest_filesystems_synced,
            'evidence_disk_retained': str(self.occurrence / 'evidence.raw'),
            'private_artifact_custody': private_custody,
            'diagnostic_error': getattr(self, 'diagnostic_error', None),
            'cleanup_errors': errors,
        })
        return errors

    def run(self):
        error = None
        product = None
        try:
            self.phase = 'launch'
            self.launch()
            self.phase = 'prepare'
            self.prepare()
            self.phase = 'product'
            product = self.run_product()
            if self.mode == 'smoke_cat':
                if product.get('disposition') == 'FAIL':
                    self.product_result = 'FAIL'
                    raise RuntimeError(product.get('error') or 'harness smoke failed')
                self.product_result = require_smoke(self.product_output, product)['product_result']
            else:
                self.product_result = product.get('disposition')
                if self.product_result not in ('PASS', 'FAIL'):
                    raise ValueError('App A driver did not produce a terminal product result')
                if self.product_result == 'FAIL' and product.get('failure_domain') != 'product':
                    raise RuntimeError(product.get('error') or 'App A infrastructure execution failed')
        except BaseException as caught:
            error = caught
        try:
            cleanup_errors = self.cleanup()
        except BaseException as cleanup_error:
            cleanup_errors = [type(cleanup_error).__name__ + ': ' + str(cleanup_error)]
        if product is not None:
            cleanup_errors = [*product.get('cleanup_errors', []), *cleanup_errors]
        context = {
            'schema': 'absd-app-a-vm-execution/1',
            'run': self.run_id,
            'phase': self.phase,
            'harness_revision': self.harness_revision,
            'source_revision': self.source_revision,
            'product_result': self.product_result,
        }
        if error is None and cleanup_errors and self.product_result != 'FAIL':
            error = RuntimeError('required cleanup or evidence steps failed')
        if error is not None:
            return terminal_result(self.public, context, error=error, cleanup_errors=cleanup_errors)
        if self.mode == 'smoke_cat':
            context['disposition'] = 'SMOKE_SEQUENCE_COMPLETE_NOT_QUALIFICATION'
        elif self.product_result == 'PASS':
            context['disposition'] = 'APP_A_SEQUENCE_COMPLETE_NOT_INDEPENDENT_ACCEPTANCE'
        else:
            context.update(disposition='PRODUCT_FAIL', failure_domain='product',
                           first_diagnostic=product.get('error') or 'App A product oracle failed')
        return terminal_result(self.public, context, cleanup_errors=cleanup_errors)


def validate_release(candidate):
    required = ('release_manifest_destination', 'wrong_manifest_destination', 'app_build_receipt_destination')
    if any(not candidate.get(name) for name in required):
        raise ValueError('exact selected/wrong release and App build-receipt bindings are required')
    for destination_key, revision_key in (
        ('release_manifest_destination', 'source_revision'),
        ('wrong_manifest_destination', 'wrong_source_revision'),
    ):
        destination = candidate[destination_key]
        pin = candidate['payload_pins'][destination]
        path = checked_file(pin['source'], pin, 'release manifest')
        document = tomllib.loads(path.read_text())
        source = document['source']
        if source['platform_commit'] != candidate[revision_key] or source['kernel_commit'] != candidate['kernel_revision']:
            raise ValueError('release source differs from exact candidate')
        if source.get('platform_tree_clean') is not True or source.get('kernel_tree_clean') is not True:
            raise ValueError('release was not built from clean source')
        if destination_key == 'release_manifest_destination' and not document.get('build', {}).get('https_document', {}).get('enabled'):
            raise ValueError('selected release does not contain App A')
    pin = candidate['payload_pins'][candidate['app_build_receipt_destination']]
    path = checked_file(pin['source'], pin, 'App build receipt')
    native = read_json(path)
    if (native.get('source_revision') != candidate['source_revision']
            or native.get('source_tree') != candidate['source_identity']['tree']):
        raise ValueError('App build receipt differs from exact candidate')
    selected = tomllib.loads(Path(candidate['payload_pins'][candidate['release_manifest_destination']]['source']).read_text())
    if selected['build']['https_document'].get('build_receipt_sha256') != pin['sha256']:
        raise ValueError('App build receipt digest differs from selected release manifest')


def materialize(candidate, input_root, output_root, run):
    input_root = Path(input_root).resolve(strict=True)
    output_root = Path(output_root)
    if str(uuid.UUID(run)) != run:
        raise ValueError('run must be a canonical UUID')
    if output_root.exists():
        raise ValueError('output root must be fresh')
    identity = verify_source(candidate)
    go = read_json(input_root / 'GO.json')
    old_run = go['run']
    old_source = go['source_revision']
    if old_source != candidate['base_source_revision']:
        raise ValueError('input root base source differs from candidate')
    if go['kernel_revision'] != candidate['kernel_revision']:
        raise ValueError('candidate kernel differs from input root')
    for row in read_json(input_root / 'PAYLOAD-DESCRIPTOR.json')['files']:
        if row['destination'] not in candidate.get('payload_pins', {}):
            checked_file(row['source'], row, 'immutable payload input')
    for row in read_json(input_root / 'plan/bindings/stage/STAGE-INPUTS.json')['files']:
        if row['dest'] not in candidate.get('stage_pins', {}):
            checked_file(row['path'], row, 'immutable stage input')
    if candidate.get('harness_mode', 'app_a') != 'build':
        validate_release(candidate)
    driver_destination = candidate.get('driver_destination', 'lifecycle/app.py')
    old_driver_sha = read_json(input_root / 'CONFIG.TEMPLATE.NO-GO.json')['driver_sha256']
    driver_pin = candidate.get('payload_pins', {}).get(driver_destination)
    if candidate.get('driver_source'):
        checked_file(candidate['driver_source']['source'], candidate['driver_source'], 'App A driver source')
        new_driver_sha = candidate['driver_source']['sha256']
    else:
        new_driver_sha = driver_pin['sha256'] if driver_pin else old_driver_sha
    replacements = [
        (old_source, candidate['source_revision']), (old_driver_sha, new_driver_sha),
        (old_run, run), (old_run[:8], run[:8]),
    ]
    output_root.mkdir(parents=True)
    for name in ('evidence', 'logs', 'work'):
        (output_root / name).mkdir()
    for name in ('source', 'plan'):
        shutil.copytree(input_root / name, output_root / name, ignore=shutil.ignore_patterns('__pycache__'))
    top_names = [
        'PAYLOAD-DESCRIPTOR.json', 'DELIVERY-MANIFEST.json', 'CONFIG.TEMPLATE.NO-GO.json',
        'PREPARE-ADMISSION.DRAFT.json', 'CREDENTIALS-ADMISSION.DRAFT.json',
        'RUNTIME-ADMISSION.DRAFT.json', 'MATERIALIZATION.NO-GO.json',
    ]
    for name in top_names:
        shutil.copyfile(input_root / name, output_root / name)
    stage_source = input_root / 'assembly/stage-inputs'
    stage_output = output_root / 'assembly/stage-inputs'
    stage_output.mkdir(parents=True)
    stage_manifest = read_json(input_root / 'plan/bindings/stage/STAGE-INPUTS.json')
    for row in stage_manifest['files']:
        replacement = candidate.get('stage_pins', {}).get(row['dest'])
        pin = replacement or row
        label = 'declared stage input' if replacement else 'immutable stage input'
        source = checked_file(pin['source'] if replacement else row['path'], pin, label)
        destination = stage_output / 'stage' / row['dest']
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(int(row.get('mode', '0o644'), 8))
        if replacement:
            row['source'] = str(source)
            row['bytes'] = replacement['bytes']
            row['sha256'] = replacement['sha256']
        row['path'] = str(source)
    special_rows = []

    def copy_special(source, pin, dest, mode='0o644'):
        source = checked_file(source, pin, 'immutable special stage input')
        destination = stage_output / 'stage' / dest
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(int(mode, 8))
        special_rows.append({
            'path': str(source), 'source': str(source), 'dest': dest,
            'bytes': pin['bytes'], 'sha256': pin['sha256'], 'mode': mode,
        })

    if stage_manifest.get('rustup_proxy'):
        pin = candidate['rustup_proxy']
        copy_special(pin['source'], pin, 'rust/rustup')
        stage_manifest['rustup_proxy']['source'] = pin['source']
    for toolchain in stage_manifest.get('toolchains', []):
        pin = toolchain['members_manifest']
        pin = dict(pin, bytes=Path(pin['path']).stat().st_size)
        manifest_path = checked_file(pin['path'], pin, 'toolchain member manifest')
        copy_special(manifest_path, pin, 'rust/MEMBERS-' + toolchain['toolchain'] + '.json')
        members = read_json(manifest_path)
        source_root = Path(toolchain['source_rustup_toolchains'])
        for member in members['members']:
            if member.get('kind') != 'file':
                raise ValueError('toolchain member is not a regular file: ' + member['member'])
            copy_special(source_root / member['member'], member, 'rust/toolchains/' + member['member'], member.get('mode', '0o644'))
    ordinary_destinations = {row['dest'] for row in stage_manifest['files']}
    for name in ('platform', 'kernel'):
        if name in stage_manifest.get('sources', {}):
            dest = 'src/' + name + '.bundle'
            if dest not in ordinary_destinations:
                pin = candidate['stage_pins'][dest]
                copy_special(pin['source'], pin, dest, pin.get('mode', '0o644'))
    if 'platform' in stage_manifest.get('sources', {}):
        stage_manifest['sources']['platform'].update(
            repository=candidate['source_root'], revision=identity['revision'], tree=identity['tree'],
            archive_sha256=identity['archive_sha256'], archive_bytes=identity['archive_bytes'],
        )
    stage_script = stage_output / 'stage/rc2/stage-prep.py'
    if stage_script.is_file():
        text = stage_script.read_text()
        match = re.search(
            r'platform["\']?\s*(?:=|:)\s*\(\s*["\']([0-9a-f]{40})["\']\s*,\s*["\']([0-9a-f]{40})["\']\s*,\s*["\']([0-9a-f]{64})["\']\s*,\s*(\d+)\)',
            text,
        )
        if match is None:
            raise ValueError('stage platform identity tuple is missing')
        replacement = '("' + identity['revision'] + '", "' + identity['tree'] + '", "' + identity['archive_sha256'] + '", ' + str(identity['archive_bytes']) + ')'
        tuple_start = text.index('(', match.start(), match.end())
        text = text[:tuple_start] + replacement + text[match.end():]
        for target in (stage_script, output_root / 'plan/bindings/stage/stage-prep.py'):
            target.write_text(text)
        for row in stage_manifest['files']:
            if row['dest'] == 'rc2/stage-prep.py':
                row['path'] = str(stage_script)
                row['source'] = str(stage_script)
                row['bytes'] = stage_script.stat().st_size
                row['sha256'] = digest(stage_script)
    for path in output_root.rglob('*'):
        replace_tree(path, replacements)
    descriptor = read_json(input_root / 'PAYLOAD-DESCRIPTOR.json')
    delivery = read_json(input_root / 'DELIVERY-MANIFEST.json')
    template_path = output_root / 'CONFIG.TEMPLATE.NO-GO.json'
    delivery_path = output_root / 'DELIVERY-MANIFEST.json'

    def generated_source(original):
        original = Path(original)
        if original == input_root / 'CONFIG.TEMPLATE.NO-GO.json':
            return template_path
        if original == input_root / 'DELIVERY-MANIFEST.json':
            return delivery_path
        try:
            return output_root / 'source' / original.relative_to(input_root / 'source')
        except ValueError:
            return original

    platform_prefix = '/root/absd-app-replacement/' + old_run + '/source/platform/'
    platform_members = {}
    for row in delivery['files']:
        if row['proposed_destination'].startswith(platform_prefix):
            relative = Path(row['proposed_destination'].removeprefix(platform_prefix))
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('unsafe protected source destination')
            platform_members[row['input_member']] = relative
    fixture_members = {row['input_member'] for row in delivery['files']
                       if row.get('role') == 'create_coverage_fixture.py'}
    for row in descriptor['files']:
        replacement = candidate.get('payload_pins', {}).get(row['destination'])
        original_pin = replacement or row
        label = 'declared payload input' if replacement else 'immutable payload input'
        original_source = checked_file(original_pin['source'], original_pin, label)
        source = original_source if replacement else generated_source(original_source)
        if row['destination'] in platform_members:
            relative = platform_members[row['destination']]
            selected = subprocess.check_output([
                'git', '-C', candidate['source_root'], 'show',
                identity['revision'] + ':' + relative.as_posix(),
            ])
            if replacement and original_source.read_bytes() != selected:
                raise ValueError('protected source payload pin differs from selected source')
            source = output_root / 'source/platform-inputs' / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            with source.open('xb') as stream:
                stream.write(selected)
        if row['destination'] in fixture_members:
            # This pinned producer lives outside input/source, so the ordinary
            # source-tree rebind never reaches its older embedded revision.
            text = source.read_text()
            pattern = r'^SOURCE = ([\"\'])[0-9a-f]{40}\1$'
            if len(re.findall(pattern, text, re.MULTILINE)) != 1:
                raise ValueError('PKI fixture source identity assignment is missing or ambiguous')
            text = re.sub(pattern, 'SOURCE = "' + identity['revision'] + '"',
                          text, flags=re.MULTILINE)
            source = output_root / 'source/create_coverage_fixture.py'
            with source.open('x') as stream:
                stream.write(text)
        if not source.is_file() or source.is_symlink():
            raise ValueError('materialized payload source is not a regular file: ' + str(source))
        row['source'] = str(source)
        row['bytes'] = source.stat().st_size
        row['sha256'] = digest(source)
    for row in delivery['files']:
        match = next((item for item in descriptor['files'] if item['destination'] == row['input_member']), None)
        if match is None:
            raise ValueError('delivery member is absent from payload descriptor: ' + row['input_member'])
        row['source'] = match['source']
        row['bytes'] = match['bytes']
        row['sha256'] = match['sha256']
        row['proposed_destination'] = row['proposed_destination'].replace(old_run, run)
    for bundle in delivery.get('source_bundles', []):
        name = bundle['name']
        if name not in ('platform', 'kernel'):
            raise ValueError('unknown delivery source bundle: ' + name)
        pin = candidate['stage_pins']['src/' + name + '.bundle']
        checked_file(pin['source'], pin, 'delivery source bundle')
        bundle.update(source=pin['source'], bytes=pin['bytes'], sha256=pin['sha256'])
        bundle['future_clone'] = bundle['future_clone'].replace(old_run, run)
        if name == 'platform':
            bundle['revision'] = candidate['source_revision']
    delivery['file_count'] = len(delivery['files'])
    delivery['file_bytes'] = sum(row['bytes'] for row in delivery['files'])
    template = read_json(template_path)
    destination_hashes = {}
    for row in delivery['files']:
        destination_hashes[row['proposed_destination'].replace(old_run, run)] = row['sha256']
    if 'lifecycle/app.py' in candidate.get('payload_pins', {}):
        destination_hashes['lifecycle/app.py'] = candidate['payload_pins']['lifecycle/app.py']['sha256']
    template = rekey_path_pins(template, destination_hashes)
    template['driver_sha256'] = new_driver_sha
    template['harness_mode'] = candidate.get('harness_mode', 'app_a')
    replace_json(template_path, template)
    delivery['run'] = run
    replace_json(output_root / 'DELIVERY-MANIFEST.json', delivery)
    for row in descriptor['files']:
        if row['destination'] == 'lifecycle/CONFIG.TEMPLATE.json':
            row['source'] = str(template_path)
            row['bytes'] = template_path.stat().st_size
            row['sha256'] = digest(template_path)
        elif row['destination'] == 'lifecycle/DELIVERY-MANIFEST.json':
            row['source'] = str(delivery_path)
            row['bytes'] = delivery_path.stat().st_size
            row['sha256'] = digest(delivery_path)
    descriptor['run'] = run
    descriptor['expected_bytes'] = sum(row['bytes'] for row in descriptor['files'])
    replace_json(output_root / 'PAYLOAD-DESCRIPTOR.json', descriptor)
    lifecycle_sums = ''.join(row['sha256'] + '  ' + row['destination'] + '\n' for row in descriptor['files'])
    (output_root / 'LIFECYCLE-SHA256SUMS').write_text(lifecycle_sums)
    template_sha = digest(template_path)
    binder_sha = digest(output_root / 'source/bind-runtime.py')
    for name, template_key, binder_key in (
        ('RUNTIME-ADMISSION.DRAFT.json', 'template_sha256', 'binder_sha256'),
        ('MATERIALIZATION.NO-GO.json', 'accepted_template_sha256', 'accepted_binder_sha256'),
    ):
        value = read_json(output_root / name)
        value[template_key] = template_sha
        value[binder_key] = binder_sha
        replace_json(output_root / name, value)
    replace_json(output_root / 'plan/bindings/stage/STAGE-INPUTS.json', stage_manifest)
    stage_rows = []
    for row in sorted(stage_manifest['files'] + special_rows, key=lambda item: item['dest']):
        path = stage_output / 'stage' / row['dest']
        checked_file(path, row, 'materialized stage member')
        stage_rows.append(row['sha256'] + '  stage/' + row['dest'])
    (stage_output / 'STAGE-SHA256SUMS').write_text('\n'.join(stage_rows) + '\n')
    binding_rows = []
    for path in sorted((output_root / 'plan/bindings').rglob('*')):
        if path.is_dir():
            continue
        if not path.is_file() or path.is_symlink():
            raise ValueError('binding tree contains a non-regular member: ' + str(path))
        relative = path.relative_to(output_root / 'plan').as_posix()
        if relative != 'bindings/BINDINGS.SHA256SUMS':
            binding_rows.append(digest(path) + '  ' + relative)
    (output_root / 'plan/bindings/BINDINGS.SHA256SUMS').write_text('\n'.join(binding_rows) + '\n')
    result = {
        'schema': 'absd-app-a-vm-materialization/1',
        'run': run,
        'source_revision': candidate['source_revision'],
        'kernel_revision': candidate['kernel_revision'],
        'source_identity': identity,
        'payload_descriptor_sha256': digest(output_root / 'PAYLOAD-DESCRIPTOR.json'),
        'config_template_sha256': template_sha,
        'stage_sha256': digest(stage_output / 'STAGE-SHA256SUMS'),
        'bindings_sha256': digest(output_root / 'plan/bindings/BINDINGS.SHA256SUMS'),
        'payload_members': len(descriptor['files']),
        'stage_members': len(stage_rows),
    }
    write_json(output_root / 'MATERIALIZATION.json', result)
    return result


def seal_harness_inputs(output_root, qemu_python, harness_revision):
    output_root = Path(output_root)
    materialization_path = output_root / 'MATERIALIZATION.json'
    materialization = read_json(materialization_path)
    observed = subprocess.check_output(['git', '-C', str(HERE), 'rev-parse', 'HEAD'], text=True).strip()
    if observed != harness_revision:
        raise ValueError('harness revision differs from observed Git HEAD')
    if subprocess.check_output(['git', '-C', str(HERE), 'status', '--porcelain', '--untracked-files=all'], text=True):
        raise ValueError('harness source tree is not clean')
    inputs = [(HERE / 'app-a-vm-runner.py', 'app-a-vm-runner.py'), (HERE / 'served_ram.py', 'served_ram.py')]
    for path in sorted(Path(qemu_python).rglob('*')):
        if path.is_file() and not path.is_symlink():
            inputs.append((path, 'qemu-python/' + path.relative_to(qemu_python).as_posix()))
    members = []
    for path, destination in inputs:
        pin = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest(path), 'mode': oct(path.stat().st_mode & 0o777)}
        checked_file(path, pin, 'harness input')
        members.append(dict(pin, destination=destination))
    qemu_binary = '/usr/bin/qemu-system-x86_64'
    binary_pin = {'path': qemu_binary, 'bytes': Path(qemu_binary).stat().st_size, 'sha256': digest(qemu_binary)}
    checked_file(qemu_binary, binary_pin, 'outer QEMU binary')
    manifest = {
        'schema': 'absd-app-a-harness-inputs/1', 'harness_revision': harness_revision,
        'members': members, 'qemu_binary': binary_pin,
    }
    manifest_path = output_root / 'HARNESS-INPUTS.json'
    write_json(manifest_path, manifest)
    materialization.update(
        harness_revision=harness_revision,
        harness_inputs_sha256=digest(manifest_path),
        qemu_binary=binary_pin,
    )
    replace_json(materialization_path, materialization)
    return manifest


def validate_admission(admission, output_root, run, control_port, now=None):
    now = int(time.time()) if now is None else now
    if admission.get('go') is not True or admission.get('run') != run:
        raise ValueError('admission does not authorize this exact occurrence')
    expected = digest(Path(output_root) / 'MATERIALIZATION.json')
    if admission.get('materialization_sha256') != expected:
        raise ValueError('admission materialization hash differs')
    staged_path = Path(output_root) / 'STAGED.json'
    if not staged_path.is_file():
        raise ValueError('admission staged receipt is missing')
    staged = read_json(staged_path)
    if staged.get('run') != run:
        raise ValueError('staged run differs from admitted occurrence')
    if staged.get('materialization_sha256') != expected:
        raise ValueError('staged materialization hash differs')
    if staged.get('control_port') != control_port:
        raise ValueError('staged control port differs')
    if admission.get('control_port') != control_port:
        raise ValueError('admission control port differs')
    if admission.get('staged_sha256') != digest(staged_path):
        raise ValueError('admission staged receipt hash differs')
    if admission.get('harness_inputs_sha256') != staged.get('harness_inputs_sha256'):
        raise ValueError('admission harness identity differs')
    if admission.get('full_outer_window_s') != 14400:
        raise ValueError('admission changed the original outer window')
    if now < admission['not_before_unix_s'] or now > admission['latest_planned_launch_unix_s']:
        raise ValueError('admission launch window is closed')
    if abs(now - admission['sample_unix_s']) >= 150:
        raise ValueError('admission resource sample is stale')
    staging_host = admission['staging_host']
    if not staging_host.get('qemu_absent') or {control_port, 24133} & set(staging_host['host_listen_ports']):
        raise ValueError('admission QEMU or control-port gate failed')
    for path in ('/', '/data'):
        capacity = staging_host['capacity'][path]
        if capacity['free_bytes'] < 64424509440 + 20 * 1024**3 or capacity['free_inodes'] < 100000:
            raise ValueError('admission storage reserve failed: ' + path)
    if staging_host['memory']['MemAvailable'] < 20 * 10**9 or staging_host['load'][0] >= 10:
        raise ValueError('admission memory or load gate failed')
    return admission


class RemoteStager:
    def __init__(self, output_root, run, qemu_python, harness_revision):
        self.output_root = Path(output_root)
        self.run = run
        self.qemu_python = Path(qemu_python)
        self.harness_revision = harness_revision
        self.root = '/data/absd-p15-staging_host-vm-' + run
        self.vm = self.root + '/vm'

    def remote(self, command, data=None, timeout=7200, check=True):
        result = subprocess.run(
            staging_host_ssh_argv(command, streamed=data is not None),
            input=data, stdin=None if data is not None else subprocess.DEVNULL,
            capture_output=True, timeout=timeout, check=False,
        )
        log = self.output_root / 'logs/remote-staging.jsonl'
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open('a') as stream:
            stream.write(json.dumps({
                'command': command, 'input': None if data is None else {'bytes': len(data), 'sha256': sha_bytes(data)},
                'exit': result.returncode, 'stdout': result.stdout.decode(errors='replace'),
                'stderr': result.stderr.decode(errors='replace'),
            }, sort_keys=True) + '\n')
        if check and result.returncode != 0:
            raise ValueError('staging_host staging command failed: ' + (result.stderr + result.stdout).decode(errors='replace')[-1000:])
        return result

    def send(self, local, remote):
        raw = Path(local).read_bytes()
        self.remote('umask 077; set -C; cat > ' + shlex.quote(str(remote)), data=raw, timeout=600)
        actual = self.remote('sha256sum ' + shlex.quote(str(remote)), timeout=60).stdout.decode().split()[0]
        if actual != sha_bytes(raw):
            raise ValueError('staging_host staging readback differs: ' + str(remote))

    def stream_tree(self, source, member, destination):
        source = Path(source)
        producer = subprocess.Popen(['tar', '-C', str(source), '-cf', '-', member], stdout=subprocess.PIPE)
        consumer = subprocess.Popen(
            staging_host_ssh_argv('tar -C ' + shlex.quote(str(destination)) + ' -xf -', streamed=True),
            stdin=producer.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        producer.stdout.close()
        try:
            stdout, stderr = consumer.communicate(timeout=7200)
            producer_status = producer.wait(timeout=60)
        except BaseException:
            producer.terminate()
            producer.wait(timeout=30)
            consumer.terminate()
            consumer.wait(timeout=30)
            raise
        if producer_status != 0 or consumer.returncode != 0:
            raise ValueError('tar/SSH tree transfer failed: ' + (stderr + stdout).decode(errors='replace')[-1000:])

    def payload_archive(self):
        descriptor = read_json(self.output_root / 'PAYLOAD-DESCRIPTOR.json')
        path = self.output_root / 'work/payload.tar'
        path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path, 'w') as archive:
            for row in descriptor['files']:
                destination = Path(row['destination'])
                if destination.is_absolute() or '..' in destination.parts or destination.parts[0] != 'lifecycle':
                    raise ValueError('unsafe payload destination: ' + row['destination'])
                source = checked_file(row['source'], row, 'sealed payload input')
                archive.add(source, arcname=row['destination'], recursive=False)
            for name in ('PAYLOAD-DESCRIPTOR.json', 'DELIVERY-MANIFEST.json', 'LIFECYCLE-SHA256SUMS'):
                archive.add(self.output_root / name, arcname=name, recursive=False)
        return path

    def verify_harness(self):
        manifest_path = self.output_root / 'HARNESS-INPUTS.json'
        manifest = read_json(manifest_path)
        if manifest['harness_revision'] != self.harness_revision:
            raise ValueError('staged harness revision differs')
        for row in manifest['members']:
            checked_file(row['path'], row, 'harness input')
        self.send(manifest_path, self.vm + '/HARNESS-INPUTS.json')
        code = ("import hashlib,json,pathlib,sys; root=pathlib.Path(sys.argv[1]); m=json.load(open(sys.argv[2]));"
                "bad=[row['destination'] for row in m['members'] if (lambda p: not p.is_file() or p.is_symlink() or p.stat().st_size != row['bytes'] or hashlib.sha256(p.read_bytes()).hexdigest() != row['sha256'])(root / row['destination'])];"
                "assert not bad, bad")
        self.remote(shlex.join(['python3', '-I', '-c', code, self.vm, self.vm + '/HARNESS-INPUTS.json']), timeout=180)
        actual = self.remote('podman exec --user 1000:1000 absd-noble sha256sum /usr/bin/qemu-system-x86_64', timeout=60).stdout.decode().split()[0]
        if actual != manifest['qemu_binary']['sha256']:
            raise ValueError('outer QEMU binary digest differs from harness seal')

    def check_capacity(self):
        code = "import os,json; print(json.dumps({p: [os.statvfs(p).f_bavail * os.statvfs(p).f_frsize, os.statvfs(p).f_favail] for p in ('/', '/data')}))"
        result = self.remote(shlex.join(['python3', '-I', '-c', code]), timeout=60)
        capacity = json.loads(result.stdout)
        for path in ('/', '/data'):
            free_bytes, free_inodes = capacity[path]
            if free_bytes < 64424509440 + 20 * 1024**3 or free_inodes < 100000:
                raise ValueError('staging_host storage reserve failed before allocation: ' + path)
        return capacity

    def stage(self, base_image=None, control_port=24131):
        self.check_capacity()
        script = self.output_root / 'plan/bindings/host/s1-stage.sh'
        self.remote('sh -s -- ' + self.run + ' layout', data=script.read_bytes(), timeout=60)
        self.stream_tree(self.output_root / 'plan', 'bindings', self.vm)
        self.stream_tree(self.output_root / 'assembly', 'stage-inputs', self.vm)
        self.stream_tree(self.output_root, 'source', self.vm)
        for name in (
            'MATERIALIZATION.json', 'PAYLOAD-DESCRIPTOR.json', 'DELIVERY-MANIFEST.json',
            'CONFIG.TEMPLATE.NO-GO.json', 'PREPARE-ADMISSION.DRAFT.json',
            'CREDENTIALS-ADMISSION.DRAFT.json', 'RUNTIME-ADMISSION.DRAFT.json',
            'MATERIALIZATION.NO-GO.json',
        ):
            self.send(self.output_root / name, self.vm + '/' + name)
        phase = 'sh ' + self.vm + '/bindings/host/s1-stage.sh ' + self.run + ' '
        self.remote(phase + 'verify-bindings', timeout=120)
        if base_image is None:
            self.remote(phase + 'image', timeout=900)
        else:
            checked_file(base_image['path'], base_image, 'cached outer base image')
            self.send(base_image['path'], self.vm + '/base.img')
            self.remote('chmod 0444 ' + self.vm + '/base.img', timeout=60)
        self.remote(phase + 'debs', timeout=1800)
        self.remote(phase + 'verify-stage ' + read_json(self.output_root / 'MATERIALIZATION.json')['stage_sha256'], timeout=600)
        self.remote(phase + 'stage-tree', timeout=600)
        payload = self.payload_archive()
        self.send(payload, self.vm + '/payload.tar')
        self.remote('tar -C ' + self.vm + '/staging/input-tree -xf ' + self.vm + '/payload.tar && rm -f ' + self.vm + '/payload.tar', timeout=600)
        self.remote('cd ' + self.vm + '/staging/input-tree && sha256sum --quiet -c LIFECYCLE-SHA256SUMS', timeout=600)
        input_result = self.remote(phase + 'input-tree', timeout=1800)
        self.remote(phase + 'client-key', timeout=120)
        nonce = uuid.uuid4().hex
        self.remote(phase + 'seed ' + nonce, timeout=300)
        self.remote(phase + 'disks', timeout=300)
        input_sha = None
        iso_sha = None
        for line in input_result.stdout.decode().splitlines():
            if line.startswith('INPUT_SHA256SUMS '):
                input_sha = line.split()[1]
            if line.startswith('INPUT_ISO '):
                iso_sha = line.split()[1]
        if not input_sha or not iso_sha:
            raise ValueError('actual input manifest or input ISO identity missing from input-tree receipt')
        staged = {
            'schema': 'absd-app-a-vm-staging/1', 'run': self.run,
            'input_manifest_sha256': input_sha, 'input_iso_sha256': iso_sha,
            'materialization_sha256': digest(self.output_root / 'MATERIALIZATION.json'),
            'harness_revision': self.harness_revision,
            'control_port': control_port,
        }
        harness_manifest = self.output_root / 'HARNESS-INPUTS.json'
        if harness_manifest.is_file():
            staged['harness_inputs_sha256'] = digest(harness_manifest)
        write_json(self.output_root / 'STAGED.json', staged)
        self.send(self.output_root / 'STAGED.json', self.vm + '/STAGED.json')
        self.remote('mkdir -m 0700 ' + self.vm + '/qemu-python', timeout=60)
        self.stream_tree(self.qemu_python, '.', self.vm + '/qemu-python')
        self.send(Path(__file__), self.vm + '/app-a-vm-runner.py')
        self.send(HERE / 'served_ram.py', self.vm + '/served_ram.py')
        if harness_manifest.is_file():
            self.verify_harness()
        self.remote(phase + 'pre-launch', timeout=600)
        return staged


def wait_for_admission(path, output_root, run, control_port, timeout_s=3600):
    path = Path(path)
    deadline = time.monotonic() + timeout_s
    while True:
        if path.is_file():
            return validate_admission(read_json(path), output_root, run, control_port)
        if time.monotonic() >= deadline:
            raise TimeoutError('exact fresh admission was not supplied; no VM was launched')
        time.sleep(2)


def extract_public_archive(raw, destination):
    destination = Path(destination)
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError('unsafe public evidence archive member')
        archive.extractall(destination, filter='data')


def retrieve_serial(stager, output_root):
    present = stager.remote('test -f ' + stager.vm + '/serial.log', timeout=30, check=False)
    if present.returncode == 1:
        return None
    if present.returncode != 0:
        raise ValueError('serial probe failed: ' + (present.stderr + present.stdout).decode(errors='replace')[-1000:])
    serial = stager.remote('cat ' + stager.vm + '/serial.log', timeout=120).stdout
    (output_root / 'logs').mkdir(parents=True, exist_ok=True)
    (output_root / 'logs/serial.log').write_bytes(serial)
    return str(output_root / 'logs/serial.log')


def retrieve_execution_result(stager, output_root):
    output_root = Path(output_root)
    raw = stager.remote('tar -C ' + stager.root + ' -cf - public', timeout=600).stdout
    (output_root / 'REMOTE-PUBLIC.tar').write_bytes(raw)
    extract_public_archive(raw, output_root / 'remote-public')
    serial = retrieve_serial(stager, output_root)
    result = read_json(output_root / 'remote-public/public/RESULT.json')
    result['local_evidence'] = {
        'public_archive': str(output_root / 'REMOTE-PUBLIC.tar'),
        'public_archive_sha256': digest(output_root / 'REMOTE-PUBLIC.tar'),
        'serial_log': serial,
        'remote_staging_retained_for_custody': stager.root,
    }
    write_json(output_root / 'RESULT.json', result)
    return result


def wait_outer_unit(stager, unit, seconds):
    deadline = time.monotonic() + seconds
    identity = None
    while time.monotonic() < deadline:
        command = 'systemctl --user show ' + unit + ' --property=Id,Result,ExecMainCode,ExecMainStatus,ActiveState,SubState,InvocationID,MainPID'
        props = dict(line.split('=', 1) for line in stager.remote(command, timeout=30).stdout.decode().splitlines() if '=' in line)
        invocation = props.get('InvocationID')
        terminal = (props.get('SubState') in ('exited', 'failed', 'dead')
                    or props.get('ActiveState') in ('failed', 'inactive'))
        if terminal:
            return props
        if not invocation:
            raise ValueError('active outer unit has no invocation identity')
        if identity is None:
            identity = invocation
        if invocation != identity:
            raise ValueError('outer unit invocation changed')
        time.sleep(0.2)
    raise TimeoutError('outer unit did not reach a terminal state')


def remaining_seconds(bounds, now=None):
    now = time.time() if now is None else now
    remaining = int(bounds['host_unit_end_unix_s'] - now)
    if remaining <= 0:
        raise ValueError('original absolute deadline has expired')
    return remaining


def dispatch_failure(stager, output_root, run, harness_revision, primary_error):
    output_root = Path(output_root)
    errors = []
    serial = None
    try:
        if not (output_root / 'remote-public').exists():
            raw = stager.remote('tar -C ' + stager.root + ' -cf - public', timeout=600).stdout
            (output_root / 'REMOTE-PUBLIC.tar').write_bytes(raw)
            extract_public_archive(raw, output_root / 'remote-public')
        serial = retrieve_serial(stager, output_root)
    except BaseException as export_error:
        errors.append('public evidence export: ' + str(export_error))
    context = {
        'schema': 'absd-app-a-vm-dispatch/1', 'run': run, 'phase': 'dispatch-outcome-unknown',
        'harness_revision': harness_revision, 'serial_log': serial,
        'cleanup_state': 'RETAINED_FOR_CUSTODY',
        'remote_staging_retained_for_custody': stager.root,
    }
    return terminal_result(output_root, context, error=primary_error, cleanup_errors=errors)


def execute_occurrence(candidate, input_root, output_root, run, admission_path,
                       control_port, qemu_python, harness_revision):
    if candidate.get('harness_mode', 'app_a') not in ('app_a', 'smoke_cat'):
        raise ValueError('unsupported execution harness mode: ' + candidate.get('harness_mode', 'app_a'))
    output_root = Path(output_root)
    dispatched = False
    try:
        for name in ('/', '/data'):
            stat = os.statvfs(name)
            if stat.f_bavail * stat.f_frsize < 64424509440 + 20 * 1024**3 or stat.f_favail < 100000:
                raise ValueError('local storage reserve failed before materialization: ' + name)
        materialization = materialize(candidate, input_root, output_root, run)
        seal_harness_inputs(output_root, qemu_python, harness_revision)
        stager = RemoteStager(output_root, run, qemu_python, harness_revision)
        stager.stage(control_port=control_port)
        request = {
            'schema': 'absd-app-a-vm-admission-request/1', 'run': run,
            'materialization_sha256': digest(output_root / 'MATERIALIZATION.json'),
            'control_port': control_port, 'full_outer_window_s': 14400,
        }
        write_json(output_root / 'ADMISSION-REQUEST.json', request)
        admission = wait_for_admission(admission_path, output_root, run, control_port)
        spec = importlib.util.spec_from_file_location('app_a_lifetime', output_root / 'plan/bindings/host/launch.py')
        launch_helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launch_helper)
        bounds, ok = launch_helper.lifetime_bounds(time.time(), stage='APP_REPLACEMENT', confirmed_ceiling_s=14400)
        if not ok:
            raise ValueError('original dispatch bounds refused')
        write_json(output_root / 'LAUNCH-BOUNDS.json', bounds)
        stager.send(output_root / 'LAUNCH-BOUNDS.json', stager.vm + '/LAUNCH-BOUNDS.json')
        unit = 'absd-app-a-vm-' + run[:8]
        remaining = remaining_seconds(bounds)
        argv = [
            'systemd-run', '--user', '--unit=' + unit, '--property=Restart=no',
            '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=' + str(remaining) + 's',
            '--property=TimeoutStopSec=120s', '--property=Nice=10', '--property=CPUAffinity=3',
            '--property=MemoryMax=2G', '--property=WorkingDirectory=' + stager.vm,
            '--property=StandardOutput=append:' + stager.root + '/public/OUTER.stdout',
            '--property=StandardError=append:' + stager.root + '/public/OUTER.stderr',
            '--setenv=SSH_AUTH_SOCK=', '--', '/usr/bin/python3', '-I', '-B',
            stager.vm + '/app-a-vm-runner.py', '--staged', '--occurrence', stager.vm,
            '--public', stager.root + '/public', '--mode', candidate.get('harness_mode', 'app_a'),
            '--control-port', str(control_port), '--qemu-python', stager.vm + '/qemu-python',
            '--harness-revision', harness_revision,
        ]
        dispatched = True
        stager.remote(shlex.join(argv), timeout=30)
        terminal = wait_outer_unit(stager, unit, remaining_seconds(bounds))
        write_json(output_root / 'OUTER-UNIT-TERMINAL.json', terminal)
        return retrieve_execution_result(stager, output_root)
    except BaseException as error:
        if dispatched:
            return dispatch_failure(stager, output_root, run, harness_revision, error)
        context = {
            'schema': 'absd-app-a-vm-dispatch/1', 'run': run,
            'phase': 'pre-dispatch', 'harness_revision': harness_revision,
            'cleanup_state': 'RETAINED_FOR_CUSTODY',
        }
        return terminal_result(output_root, context, error=error)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--materialize', action='store_true')
    modes.add_argument('--execute', action='store_true')
    modes.add_argument('--staged', action='store_true')
    parser.add_argument('--candidate')
    parser.add_argument('--admission')
    parser.add_argument('--input-root')
    parser.add_argument('--output-root')
    parser.add_argument('--run')
    parser.add_argument('--occurrence')
    parser.add_argument('--public')
    parser.add_argument('--mode', choices=('app_a', 'smoke_cat'))
    parser.add_argument('--control-port', type=int)
    parser.add_argument('--qemu-python')
    parser.add_argument('--harness-revision')
    args = parser.parse_args()
    if args.materialize:
        required = ('candidate', 'input_root', 'output_root', 'run')
        if any(getattr(args, name) is None for name in required):
            parser.error('--materialize requires candidate, input-root, output-root and run')
        result = materialize(read_json(args.candidate), args.input_root, args.output_root, args.run)
    elif args.execute:
        required = ('candidate', 'input_root', 'output_root', 'run', 'admission', 'control_port', 'qemu_python', 'harness_revision')
        if any(getattr(args, name) is None for name in required):
            parser.error('--execute requires candidate, admission, input-root, output-root, run, control-port, qemu-python and harness-revision')
        result = execute_occurrence(
            read_json(args.candidate), args.input_root, args.output_root, args.run, args.admission,
            args.control_port, args.qemu_python, args.harness_revision,
        )
    else:
        required = ('occurrence', 'public', 'mode', 'control_port', 'qemu_python', 'harness_revision')
        if any(getattr(args, name) is None for name in required):
            parser.error('--staged requires occurrence, public, mode, control-port, qemu-python and harness-revision')
        result = StagedExecutor(
            args.occurrence, args.public, args.mode, args.control_port,
            args.qemu_python, args.harness_revision,
        ).run()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
