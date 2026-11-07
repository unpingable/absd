#!/usr/bin/env python3
"""App A producer qualification through a pinned replacement recovery point.

Run only in the admitted disposable VM's precreated isolated native TAP
namespace, inside its durable finite unit. No credentials, VM or namespace are
created here. Failed images and point bytes remain in private operator custody.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import tempfile
import tomllib
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import boot_artifacts as ba
from served_ram import served_qemu
import operator_build_receipt as br
import operator_boot_binding as ob
import release_manifest as rm
import storage_fence_state as guard
from e1000_rx import wait_rx_setup


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p2 = load('app_replacement_p2', HERE / 'recovery-point-matrix.py')
rel = p2.rel
P2_A = '03479a3e090e847ccdfa647dce44e7b16d035988'
BODY = bytes(range(256)) * 64
POST = '/home/operator/app-post-point.bin'
NEW = '/home/operator/app-recovered-write.bin'
POST_BYTES = b'committed after the clean point; intentionally outside its RPO\n'
NEW_BYTES = b'new writable service after App A replacement\n'
REQUIRED = ('inputs', 'app-clean-point', 'held-fetch-unclean-stop',
            'wrong-release-refused', 'replacement-app-durable', 'failed-images-retained')


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def pinned(entry):
    path = Path(entry['path']).resolve(strict=True)
    require(not Path(entry['path']).is_symlink() and path.is_file(), 'pinned input is not a regular file')
    require(ba.sha(path) == entry['sha256'], 'pinned input changed: ' + str(path))
    return path


def terminal(rows, error=None, failure_domain='infrastructure'):
    names = [row['case'] for row in rows]
    ordered = names == list(REQUIRED[:len(rows)]) and all(row.get('disposition') == 'PASS' for row in rows)
    passed = error is None and ordered and names == list(REQUIRED)
    failed = REQUIRED[len(rows)] if error is not None and ordered and len(rows) < len(REQUIRED) else None
    completed = {row['case'] for row in rows if row.get('disposition') == 'PASS'}
    return {'disposition': 'PASS' if passed else 'FAIL', 'cases': rows,
            'case_order_valid': ordered, 'failed_case': failed,
            'failure_domain': None if passed else failure_domain,
            'error': None if error is None else str(error),
            'not_run': [case for case in REQUIRED if case not in completed and case != failed],
            'scope': 'producer qualification; no unfamiliar-operator or pre-rename interruption claim'}


def require_pair(a, b, source_a, source_b, kernel):
    for doc, source in ((a, source_a), (b, source_b)):
        require(re.fullmatch('[0-9a-f]{40}', source or '') is not None, 'final source pin missing')
        require(doc['source']['platform_commit'] == source and doc['source']['kernel_commit'] == kernel,
                'release source/kernel differs from admitted input')
        require(doc['source']['platform_tree_clean'] is True and doc['source']['kernel_tree_clean'] is True,
                'release was not built from clean source')
    require(all(type(a['identity'].get(key)) is int and a['identity'][key] == b['identity'].get(key)
                for key in rel.IDENTITY), 'wrong-release ABI/filesystem identity differs')
    require(a['release']['id'] != b['release']['id'] and source_a != source_b,
            'wrong-release input must be a distinct actual release/source')
    require(a['build']['https_document']['enabled'] is True
            and 'tree/bin/https-document' in a['artifacts']['files'], 'selected release does not contain App A')
    require(a['artifacts']['files'][rel.ISO]['sha256'] != b['artifacts']['files'][rel.ISO]['sha256'],
            'wrong-release ISO is not distinct')


def require_ancestry(repo, entry, selected, earlier):
    require(earlier == P2_A, 'wrong release must be fixed P2 A')
    require(selected != earlier, 'selected source must follow fixed P2 A')
    path = pinned(entry)
    raw = path.read_bytes()
    receipt = json.loads(raw)
    require(receipt.get('schema') == 'p2-source-ancestry/1'
            and receipt.get('A') == earlier and receipt.get('B') == selected
            and receipt.get('command') == 'git merge-base --is-ancestor'
            and type(receipt.get('exit_code')) is int and receipt['exit_code'] == 0,
            'missing pinned fixed A-to-selected B ancestry evidence')
    # This producer executes from private B: both real commit objects are required.
    # A curated public snapshot cannot supply or replace this private history.
    for revision in (earlier, selected):
        require(subprocess.run(['git', '-C', str(repo), 'cat-file', '-e', revision + '^{commit}'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0,
                'private ancestry commit unavailable')
    require(subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', earlier, selected],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0,
            'fixed P2 A is not an ancestor of selected B')
    return raw


def reported_point_pin(output, release_id):
    rows = re.findall(rb'(?m)^RECOVERY POINT SHA256 ([0-9a-f]{64}) selected=' + re.escape(release_id.encode()) + rb'$', output)
    require(len(rows) == 1, 'successful point creation did not report one exact external pin')
    return rows[0].decode()


def require_bundle(body, receipt, *, boot, issuer, anchor):
    require(body == BODY, 'App A maximum body readback differs')
    lines = receipt.decode('ascii').splitlines()
    require(lines and lines[0] == 'absd-https-document/1' and receipt.endswith(b'\n'), 'App A receipt framing differs')
    pairs = [line.split('=', 1) for line in lines[1:]]
    require(all(len(row) == 2 for row in pairs), 'App A receipt row malformed')
    fields = dict(pairs)
    expected = {'peer': '192.0.2.1:8443', 'name': 'document.example', 'path': '/document.bin?edition=1',
                'issuer_spki': issuer, 'boot': boot, 'body_bytes': '16384', 'body_sha256': sha(BODY)}
    require(len(pairs) == len(fields) == 9 and all(fields.get(k) == v for k, v in expected.items()),
            'App A receipt body/config/boot identity differs')
    for key in ('verified_utc_ms', 'publication_check_utc_ms'):
        require(re.fullmatch('[1-9][0-9]*,[1-9][0-9]*', fields.get(key, '')) is not None, 'receipt time syntax differs')
        low, high = map(int, fields[key].split(','))
        require(0 <= high - low <= 5000 and low >= anchor['utc_ms'] - anchor['uncertainty_ms'],
                'receipt time differs from fresh attestation')
    return fields


def require_live_boot(raw):
    text = raw.decode(errors='replace')
    require(raw.count(b'ABSD KERNEL BOOT\n') == 1 and not any(
        marker in text for marker in ('ABSD PANIC', 'KERNEL FAULT', 'MACHINE STOP', 'MACHINE RECOVER RESET')),
        'owned boot already faulted, reset or has ambiguous history')


def unclean_stop(process, row, ssh_process):
    require(row.get('held') is True and row.get('held_monotonic_ns') is not None and not row.get('ended'),
            'no observed live network-held response')
    require(process.poll() is None and ssh_process.poll() is None, 'owned QEMU or in-flight SSH already ended')
    process.kill()  # Exact Popen returned by bound admission, never a supplied PID.
    require(process.wait(timeout=30) == -signal.SIGKILL, 'owned QEMU did not stop uncleanly')
    return time.monotonic_ns()


class Qualification:
    def __init__(self, cfg, private, evidence, config_identity=None, smoke=False):
        self.cfg, self.private, self.evidence = cfg, private, evidence
        self.config_identity = config_identity
        self.smoke, self.smoke_receipt = smoke, None
        self.failure_domain = 'infrastructure'
        self.rows, self.boots, self.events, self.peer = [], [], 0, None
        self.expected_host = None
        self.seen_boots = set()
        self.active = None
        self.held = None
        self.point = private / 'point'
        self.pin = None

    def event(self, kind, value):
        self.events += 1
        write(self.evidence / f'{self.events:04d}-{kind}.json', value)

    def mark(self, case, value):
        require(case == REQUIRED[len(self.rows)], 'qualification phase completed out of order')
        self.rows.append({'case': case, 'disposition': 'PASS', 'detail': value})
        self.event('case', self.rows[-1])

    def check_lease(self):
        require(time.time() + 120 < self.cfg['hard_end_unix_s'], 'original lease has no cleanup reserve')
        if self.config_identity is not None:
            pinned(self.config_identity)
        if hasattr(self, 'source'):
            require(br.git(ROOT, 'rev-parse', 'HEAD').decode().strip() == self.source['revision']
                    and not br.git(ROOT, 'status', '--porcelain', '--untracked-files=all').strip(), 'producer source changed')
            for key in ('manifest', 'wrong_manifest', 'app_build_receipt', 'qemu'):
                pinned(self.cfg[key])
            if hasattr(self, 'runbook_root'):
                require(all(ba.sha(self.runbook_root / path) == digest for path, digest in self.cfg['runbooks'].items()),
                        'intended documentation changed during qualification')

    def tool(self, *args):
        previous_domain = getattr(self, 'failure_domain', 'infrastructure')
        self.failure_domain = 'infrastructure'
        self.check_lease()
        command = [sys.executable, '-I', '-B', '-X', 'pycache_prefix=' + str(self.private / 'python-cache'),
                   str(HERE / 'release.py'), *map(str, args)]
        self.event('tool-intent', {'command': command, 'next': 'inspect original durable unit; do not duplicate producer'})
        env = dict(os.environ, ABSD_QEMU=shlex.join(self.qemu), ABSD_RELEASE_QEMU=shlex.join(self.importer_qemu),
                   ABSD_P2_BOUND_INPUTS=str(self.importer_inputs), ABSD_BLOCK_ATTACH='ata',
                   PYTHONDONTWRITEBYTECODE='1', PYTHONPYCACHEPREFIX=str(self.private / 'python-cache'))
        env.pop('SSH_AUTH_SOCK', None)
        env.pop('ABSD_QEMU_REBOOT', None)
        for name in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONOPTIMIZE'):
            env.pop(name, None)
        before = len(list(self.importer_receipts.glob('*.launch.json')))
        # Existing canonical importer timeouts and the admitted durable unit's
        # independent lease own this foreground child; no detached retry exists.
        done = subprocess.run(command, capture_output=True, env=env)
        self.event('tool-result', {'command': command, 'exit': done.returncode,
                                  'stdout': done.stdout.decode(errors='replace'), 'stderr': done.stderr.decode(errors='replace')})
        bindings = self.importer_binding.terminal_bindings(self.importer_receipts, self.cfg['qemu']['sha256'],
                                                          {self.cfg['manifest']['sha256']})
        self.event('importer-bindings', {'after_command': args[0], 'bindings': bindings})
        require(done.returncode == 0, 'canonical release command failed: ' + args[0])
        if args[0] in ('install', 'reconfigure'):
            require(len(list(self.importer_receipts.glob('*.launch.json'))) > before, 'mutator lacks a new bound importer occurrence')
        self.check_lease()
        self.failure_domain = previous_domain
        return done.stdout

    def preserve_ancestry(self, ancestry):
        self.private.mkdir(mode=0o700)
        self.evidence.mkdir(mode=0o700)
        (self.evidence / 'source-ancestry.json').write_bytes(ancestry)

    def validate(self):
        c = self.cfg
        require(c.get('execution_go') is True, 'draft has no execution authority')
        require(not c.get('unresolved_inputs'), 'draft still has unresolved inputs')
        require(self.config_identity is not None and json.loads(pinned(self.config_identity).read_text()) == c, 'actual admitted config bytes differ')
        require(c.get('schema') == 'absd-app-replacement-qualification/1', 'unknown qualification config')
        require(c['private_work'] == str(self.private) and c['evidence'] == str(self.evidence), 'admitted output paths differ')
        require(sys.dont_write_bytecode and sys.pycache_prefix is not None
                and Path(sys.pycache_prefix).resolve() == self.private / 'python-cache', 'fresh external Python cache prefix required')
        require(c['custodian'] and c['retirement_condition'], 'private image/key custody disposition missing')
        require(c['host_kind'] == 'disposable-qemu-vm', 'named disposable VM kind differs')
        require(subprocess.check_output(['systemd-detect-virt', '--vm'], text=True).strip() in ('kvm', 'qemu'), 'execution is not in the admitted VM')
        require(os.geteuid() == 0 and c['machine_id'] == Path('/etc/machine-id').read_text().strip(), 'named VM/root differs')
        require(c['unit_invocation_id'] and c['unit_invocation_id'] == os.environ.get('INVOCATION_ID'), 'durable unit identity differs')
        require(os.stat('/proc/self/ns/net').st_ino == c['network_namespace_inode']
                and c['network_namespace_inode'] != c['parent_network_namespace_inode'], 'isolated native namespace differs')
        require(ba.sha(__file__) == c['driver_sha256'], 'driver identity changed')
        self.check_lease()
        require(str(uuid.UUID(c['run'])) == c['run'], 'canonical occurrence UUID required')
        require(c['hard_end_unix_s'] <= time.time() + 4 * 3600, 'original finite lease differs')
        require(c['unit'] in Path('/proc/self/cgroup').read_text(), 'driver is outside named durable unit')
        properties = subprocess.check_output(['systemctl', 'show', c['unit'], '--property=InvocationID,RuntimeMaxUSec,KillMode'])
        require(sha(properties) == c['unit_runtime_properties_sha256'], 'durable unit properties differ')
        props = dict(line.split('=', 1) for line in properties.decode().splitlines())
        require(props.get('InvocationID') == c['unit_invocation_id'] and props.get('KillMode') == 'control-group'
                and props.get('RuntimeMaxUSec') not in (None, '', 'infinity', '0'), 'finite durable unit cleanup boundary absent')
        self.source = br.source(ROOT)
        self.repo_root = Path(br.git(ROOT, 'rev-parse', '--show-toplevel').decode().strip()).resolve()
        require(all(self.repo_root != path and self.repo_root not in path.parents for path in (self.private, self.evidence)),
                'qualification output overlaps producer source')
        require(self.source['revision'] == c['source_revision'], 'driver differs from final selected source')
        self.runbook_root = Path(c['runbook_root']).resolve(strict=True)
        require(all(out != self.runbook_root and out not in self.runbook_root.parents and self.runbook_root not in out.parents
                    for out in (self.private, self.evidence)), 'qualification output overlaps intended documentation')
        for path, digest in c['runbooks'].items():
            require(path in ('docs/P2-REPLACEMENT-RESTORE.md', 'docs/NATIVE-HTTPS-DOCUMENT.md', 'docs/OPERATOR-RUNBOOK.md')
                    and ba.sha(self.runbook_root / path) == digest, 'intended runbook changed')
        require(set(c['runbooks']) == {'docs/P2-REPLACEMENT-RESTORE.md', 'docs/NATIVE-HTTPS-DOCUMENT.md', 'docs/OPERATOR-RUNBOOK.md'}, 'runbook inventory incomplete')
        self.release, self.wrong = rel.Release(c['release']), rel.Release(c['wrong_release'])
        require(all(out != release.path and out not in release.path.parents and release.path not in out.parents
                    for out in (self.private, self.evidence) for release in (self.release, self.wrong)), 'qualification output overlaps release inputs')
        am, bm = pinned(c['manifest']), pinned(c['wrong_manifest'])
        require(am == self.release.manifest and bm == self.wrong.manifest, 'manifest path differs')
        self.adoc, self.bdoc = (tomllib.loads(p.read_text()) for p in (am, bm))
        require_pair(self.adoc, self.bdoc, c['source_revision'], c['wrong_source_revision'], c['kernel_revision'])
        ancestry = require_ancestry(self.repo_root, c['ancestry'], c['source_revision'], c['wrong_source_revision'])
        self.preserve_ancestry(ancestry)
        self.served_bindings = {}
        for release in (self.release, self.wrong):
            release.verified_tree_files(); release.verified_site_defaults()
            for member in (rel.ISO, 'fixture-import.elf', 'sshd.elf', 'absd-fsd.elf'):
                release.verify_artifact(member)
            with tempfile.TemporaryDirectory(prefix='app-iso-binding-') as scratch:
                kernel, grub = rm.iso_extract(release.path / rel.ISO, scratch)
                ob.validate_operator_grub(grub.read_bytes())
                self.served_bindings[release.id] = {
                    'iso': ob.verify_iso((release.path / rel.ISO).read_bytes(), kernel.read_bytes(), grub.read_bytes()),
                    'catalog': ob.verify_kernel_catalog(kernel.read_bytes(), {
                        'external-workload': (release.path / 'sshd.elf').read_bytes(),
                        'file-server': (release.path / 'absd-fsd.elf').read_bytes()})}
        # Only the selected release's importer is built here. The wrong boot
        # ISO is prebuilt and pinned, not rebuilt with the selected kernel copy.
        self.kernel = rel.check_kernel(c['kernel'], self.release)
        app_receipt = pinned(c['app_build_receipt'])
        native = json.loads(app_receipt.read_text())
        require(ba.sha(app_receipt) == self.adoc['build']['https_document']['build_receipt_sha256']
                and native['source_revision'] == c['source_revision'] and native['source_tree'] == self.source['tree']
                and native['tracked_dirty'] is False and native['untracked_source'] is False
                and native['application']['schema'] == 'absd-https-document-build/1'
                and native['application']['fixture_selectors'] is False
                and native['outputs']['https_document']['sha256'] == self.release.artifact_digests()['tree/bin/https-document'],
                'selected App A native receipt differs')
        self.qemu = [str(pinned(c['qemu'])), '-accel', 'tcg', '-cpu', 'max,vendor=GenuineIntel,+rdrand', '-m', '256M']
        importer_helper = pinned(c['importer_binding_helper'])
        require(importer_helper == HERE / 'p2_boot_binding.py', 'importer binding helper differs from selected source')
        self.importer_binding = load('app_replacement_importer_binding', importer_helper)
        self.importer_qemu = [sys.executable, '-I', '-B', '-X', 'pycache_prefix=' + str(self.private / 'python-cache'),
                              str(HERE / 'p2-bound-qemu.py'), '-accel', 'tcg', '-cpu', 'max,vendor=GenuineIntel,+rdrand']
        self.clock = load('app_replacement_clock', pinned(c['clock_helper']))
        clock_point = json.loads(pinned(c['clock_preflight']).read_text())
        require(clock_point.get('schema') == 'absd-linux-clock-preflight/1' and clock_point.get('run') == c['run']
                and clock_point.get('disposition') == 'PASS' and clock_point.get('synchronized') is True
                and c['clock_attestor'], 'existing operator-trusted clock preflight absent')
        self.clock.clock_bound(clock_point['adjtimex'])
        self.peer_module = load('app_replacement_peer', pinned(c['native_peer_helper']))
        require((self.peer_module.HOST, self.peer_module.GUEST, self.peer_module.TAP, self.peer_module.TLS_PORT)
                == ('192.0.2.1', '192.0.2.100', 'doc-tap0', 8443), 'native peer topology differs')
        self.peer_module.BODY = BODY
        self.key, self.public_key = Path(c['client_private_key']).resolve(strict=True), pinned(c['client_public_key'])
        require(stat.S_IMODE(self.key.stat().st_mode) == 0o600 and self.key.stat().st_uid == os.getuid(), 'client key custody differs')
        require(self.repo_root not in self.key.parents and self.evidence not in self.key.parents
                and not Path(c['client_private_key']).is_symlink(), 'private key overlaps public/source or is a symlink')
        public = subprocess.check_output(['ssh-keygen', '-y', '-f', str(self.key)]).strip()
        require(public.split()[:2] == self.public_key.read_bytes().split()[:2], 'client key/public input differ')
        self.client_fingerprint = subprocess.check_output(['ssh-keygen', '-lf', str(self.public_key)], text=True).strip()
        self.etc = Path(c['etc']).resolve(strict=True)
        self.config_files = {name: pinned(entry) for name, entry in c['configuration'].items()}
        require(set(self.config_files) == {'network.conf', 'https-document.conf', 'https-issuer.der'}
                and {p.name for p in self.etc.iterdir()} == set(self.config_files)
                and all(path.parent == self.etc and path.name == name for name, path in self.config_files.items()), 'configuration inventory differs')
        self.config_bytes = {'/etc/' + name: path.read_bytes() for name, path in self.config_files.items()}
        expected = ('peer=192.0.2.1:8443\nname=document.example\npath=/document.bin?edition=1\n'
                    + 'issuer_spki=' + c['issuer_spki'] + '\n').encode()
        require(self.config_bytes['/etc/https-document.conf'] == expected
                and self.config_bytes['/etc/network.conf'] == b'address 192.0.2.100\nnetmask 255.255.255.0\ngateway 192.0.2.1\n', 'native app/network config differs')
        self.peer_config = {'leaf_pem': str(pinned(c['leaf_pem'])), 'leaf_key': c['leaf_key']}
        leaf = Path(c['leaf_key']).resolve(strict=True)
        require(stat.S_IMODE(leaf.stat().st_mode) == 0o600 and leaf.stat().st_uid == os.getuid()
                and self.evidence not in leaf.parents and self.repo_root not in leaf.parents
                and not Path(c['leaf_key']).is_symlink(), 'TLS key custody differs')
        pinned(c['pki_lifecycle_receipt'])
        pub = subprocess.check_output(['openssl', 'x509', '-inform', 'DER', '-in', str(self.config_files['https-issuer.der']), '-pubkey', '-noout'])
        spki = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=pub, capture_output=True, check=True).stdout
        require(sha(spki) == c['issuer_spki'], 'issuer SPKI differs')
        # Read-only validation; this driver does not create a TAP or host route.
        link = json.loads(subprocess.check_output(['ip', '-j', 'addr', 'show', 'dev', 'doc-tap0']))[0]
        require(link['mtu'] == 1500 and any(a.get('local') == '192.0.2.1' and a.get('prefixlen') == 24 for a in link['addr_info']), 'native TAP differs')

    def ssh_argv(self, command, *, held=False):
        liveness = ['-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=3'] if held else []
        return ['ssh', '-F', '/dev/null', '-i', str(self.key), '-T', '-l', 'operator',
                '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no', '-o', 'IdentitiesOnly=yes',
                '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'UserKnownHostsFile=' + str(self.private / 'known_hosts'), '-o', 'ConnectTimeout=20',
                *liveness,
                '192.0.2.100', command]

    def finish_interrupted_client(self, peer, timeout=30):
        # VM loss need not close the established SSH TCP connection. The
        # authenticated server-alive policy owns loss detection, not a local
        # signal that could manufacture the nonzero status being checked.
        try:
            out, err = self.held.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            self.failure_domain = 'infrastructure'
            self.event('interrupted-client-timeout', {
                'timeout_s': timeout, 'stdout_hex': (error.output or b'').hex(),
                'stderr_hex': (error.stderr or b'').hex(),
                'claim': 'SSH liveness bound failed; no interruption oracle result',
            })
            raise
        self.event('interrupted-client', {'exit': self.held.returncode,
                                         'stdout_hex': out.hex(), 'stderr_hex': err.hex(), 'peer': dict(peer)})
        require(self.held.returncode != 0 and not out and b'/home/operator/https-document-' not in err,
                'interrupted fetch reported success')

    def ssh(self, command, data=b'', failure=False):
        done = subprocess.run(self.ssh_argv(command), input=data, capture_output=True, timeout=120)
        self.event('ssh', {'command': command, 'stdin_sha256': sha(data), 'exit': done.returncode,
                           'stdout_hex': done.stdout.hex(), 'stderr_hex': done.stderr.hex()})
        require(failure or done.returncode == 0, 'SSH command failed: ' + command)
        return done.returncode, done.stdout, done.stderr

    def start(self, target, label, wrong=False):
        previous_domain = getattr(self, 'failure_domain', 'infrastructure')
        self.failure_domain = 'infrastructure'
        self.check_lease()
        require(self.active is None, 'earlier logical identity still executing')
        iso = self.wrong.path / rel.ISO if wrong else target.iso
        require(ba.sha(iso) == (self.wrong if wrong else self.release).artifact_digests()[rel.ISO], 'selected boot ISO differs')
        console = self.evidence / (label + '.serial.log')
        command = served_qemu([*self.qemu, '-rtc', 'base=utc,clock=host', '-cdrom', str(iso),
                   '-drive', f'file={target.image},format=raw,if=ide,index=0', '-netdev', 'tap,id=n0,ifname=doc-tap0,script=no,downscript=no,vnet_hdr=off',
                   '-device', 'e1000,netdev=n0', '-display', 'none', '-serial', 'file:' + str(console),
                   '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04', '-no-reboot'])
        with (self.evidence / (label + '.qemu.log')).open('xb') as log:
            process = ba.launch(command, iso_sha256=ba.sha(iso), disk_sha256=ba.sha(target.image),
                                qemu_sha256=self.cfg['qemu']['sha256'], record_path=self.evidence / (label + '.launch.json'),
                                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        boot = {'process': process, 'target': target, 'console': console, 'label': label, 'boot_id': None}
        self.boots.append(boot); self.active = boot
        if wrong:
            self.failure_domain = previous_domain
            return boot
        end = time.monotonic() + 300
        while time.monotonic() < end:
            raw = console.read_bytes() if console.exists() else b''
            worker = rel.ssh_absd.captured(raw)
            if raw:
                require_live_boot(raw)
            match = re.search(r'SSH HOST KEY (?:GENERATED|LOADED) (ssh-ed25519 \S+) (SHA256:\S+)', worker)
            if match and 'SSH LISTENING' in worker:
                p2.require_ready(raw, {'fingerprint': match[2]}, self.release.id, self.expected_host[1] if self.expected_host else match[2])
                if self.expected_host:
                    require(match[1] == self.expected_host[0], 'restored host public identity changed')
                else:
                    self.expected_host = (match[1], match[2])
                require('sshd: network 192.0.2.100/24 gateway 192.0.2.1 (/etc/network.conf)' in worker, 'served network differs from point configuration')
                (self.private / 'known_hosts').write_text('192.0.2.100 ' + match[1] + '\n')
                wait_rx_setup(lambda: console.read_bytes().decode(errors='replace'), lambda: process.poll() is None, end)
                _, release, _ = self.ssh('/bin/release')
                require(re.search(rb'(?:^|\s)release=' + self.release.id.encode() + rb'(?:\s|$)', release), 'served wrong release')
                self.failure_domain = previous_domain
                return boot
            require(process.poll() is None, 'guest ended before readiness')
            time.sleep(.2)
        raise ValueError('served readiness timed out')

    def halt(self):
        boot = self.active
        rc, out, _ = self.ssh('shutdown', failure=True)
        ended = boot['process'].wait(timeout=240)
        p2.require_halt(boot['console'].read_bytes(), ended, rc, out)
        require(guard.parse(boot['target'].tree().get(guard.PATH)) == 'clean', 'clean halt guard absent')
        self.active = None
        return time.monotonic_ns()

    def attest(self, label):
        before = self.clock.read_clock(); error0 = self.clock.clock_bound(before)
        rc, out, err = self.ssh('/bin/https-document --sample')
        after = self.clock.read_clock(); error1 = self.clock.clock_bound(after)
        match = re.fullmatch(rb'absd-https-sample/1 boot=([0-9a-f]{32}) pit_ms=(0|[1-9][0-9]*) rtc=(0|[1-9][0-9]*)\n', err)
        require(rc == 0 and not out and match, 'native time sample differs')
        wall = after['realtime_ns'] - before['realtime_ns']; mono = after['monotonic_ns'] - before['monotonic_ns']
        require(min(wall, mono) >= 0 and abs(wall - mono) <= 20_000_000, 'host clock stepped during sample')
        uncertainty = math.ceil(max(wall, mono) / 2_000_000) + max(error0, error1) + 1
        require(uncertainty <= 1000, 'sample uncertainty too large; no attestation issued')
        boot = match[1].decode()
        if self.active['boot_id'] is None:
            require(boot not in self.seen_boots, 'restarted machine reused an earlier boot identity')
            self.active['boot_id'] = boot; self.seen_boots.add(boot)
        require(boot == self.active['boot_id'], 'sample changed boot within one process')
        anchor = {'utc_ms': (before['realtime_ns'] + after['realtime_ns']) // 2_000_000, 'uncertainty_ms': uncertainty}
        self.event('attestation', {'label': label, 'sample': err.decode(), 'before': before, 'after': after, 'anchor': anchor})
        command = (f'/bin/https-document --boot {boot} --pit-ms {match[2].decode()} --rtc {match[3].decode()} '
                   f'--utc-ms {anchor["utc_ms"]} --uncertainty {uncertainty}')
        return command, boot, anchor

    def fetch(self, label):
        command, boot, anchor = self.attest(label)
        before = len(self.peer.rows)
        rc, out, err = self.ssh(command)
        end = time.monotonic() + 5
        while not (len(self.peer.rows) == before + 1 and self.peer.rows[-1].get('ended')) and time.monotonic() < end:
            time.sleep(.02)
        require(len(self.peer.rows) == before + 1 and self.peer.rows[-1].get('closed') is True
                and not self.peer.rows[-1]['held'] and 'exception' not in self.peer.rows[-1], 'fetch lacks one completed native TLS peer exchange')
        self.event('fetch-peer', {'label': label, 'peer': dict(self.peer.rows[-1])})
        match = re.fullmatch(rb'(/home/operator/https-document-[0-9a-f]{32}/receipt)\n', err)
        require(rc == 0 and not out and match, 'fetch did not publish exactly one receipt')
        path = match[1].decode()
        _, body, _ = self.ssh('/bin/cat ' + path.removesuffix('receipt') + 'body')
        _, receipt, _ = self.ssh('/bin/cat ' + path)
        require_bundle(body, receipt, boot=boot, issuer=self.cfg['issuer_spki'], anchor=anchor)
        (self.evidence / (label + '.body')).write_bytes(body)
        (self.evidence / (label + '.receipt')).write_bytes(receipt)
        return {'path': path, 'body': body, 'receipt': receipt, 'boot': boot}

    def read_bundle(self, bundle):
        _, body, _ = self.ssh('/bin/cat ' + bundle['path'].removesuffix('receipt') + 'body')
        _, receipt, _ = self.ssh('/bin/cat ' + bundle['path'])
        require(body == bundle['body'] and receipt == bundle['receipt'], 'restored/restarted app bundle differs')
        for path, expected in self.config_bytes.items():
            _, actual, _ = self.ssh('/bin/cat ' + path)
            require(actual == expected, 'restored app configuration differs')

    def restore(self, name):
        target = rel.Target(self.private / name)
        self.tool('restore', self.point, '--target', target.out, '--recovery-point-sha256', self.pin, '--expected-release', self.release.id)
        require(ba.sha(target.image) == ba.sha(self.point / rel.IMAGE), 'replacement does not copy exact pinned point')
        p2.require_state(p2.inventory(target.image), self.base_state)
        return target

    def run_smoke(self):
        payload = b'ABSD App A harness smoke\n'
        path = '/home/operator/app-a-harness-smoke-input'
        started = time.monotonic_ns()
        self.ssh('/bin/cat > ' + path, payload)
        status, output, error = self.ssh('/bin/cat ' + path)
        elapsed = time.monotonic_ns() - started
        require(status == 0 and output == payload and not error, 'nested smoke cat output differs')
        (self.evidence / 'CAT-OUTPUT.txt').write_bytes(output)
        self.smoke_receipt = {'program': '/bin/cat in nested ABSD', 'run': self.cfg.get('run'), 'path': path,
                              'input_sha256': sha(payload), 'output_sha256': sha(output),
                              'exit': status, 'monotonic_ns': elapsed}
        self.event('smoke-cat', self.smoke_receipt)
        self.halt()

    def run(self):
        self.validate()
        self.importer_inputs = self.private / 'p2-bound-inputs.json'
        self.importer_receipts = self.evidence / 'importer-bindings'
        self.importer_binding.prepare(self.importer_inputs, self.qemu[0], self.cfg['qemu']['sha256'],
                                      [{'path': str(self.release.path), 'manifest_sha256': self.cfg['manifest']['sha256']}],
                                      self.importer_receipts)
        self.event('checkpoint' , {'run': self.cfg['run'], 'host': self.cfg['machine_id'], 'unit': self.cfg['unit'],
                                  'invocation': self.cfg['unit_invocation_id'], 'pid': os.getpid(), 'source': self.source,
                                  'config': self.config_identity, 'network_namespace_inode': self.cfg['network_namespace_inode'],
                                  'release_manifest': self.cfg['manifest'], 'qemu': self.cfg['qemu'],
                                  'private_work': str(self.private), 'evidence': str(self.evidence),
                                  'terminal': 'RESULT.json', 'next': 'inspect this exact durable producer; do not restart or duplicate'})
        self.event('credential-custody', {'client_private_path': str(self.key), 'client_public_fingerprint': self.client_fingerprint,
                                          'tls_private_path': self.cfg['leaf_key'], 'tls_public_certificate': self.cfg['leaf_pem'],
                                          'pki_lifecycle_receipt': self.cfg['pki_lifecycle_receipt'],
                                          'custodian': self.cfg['custodian'], 'retirement_condition': self.cfg['retirement_condition'],
                                          'created_here': False, 'agent_used': False})
        self.mark('inputs', {'release': self.release.id, 'wrong_release': self.wrong.id, 'manifest': self.cfg['manifest'],
                             'runbook_root': str(self.runbook_root), 'runbooks': self.cfg['runbooks'], 'qemu': self.cfg['qemu'],
                             'clock_preflight': self.cfg['clock_preflight'], 'clock_attestor': self.cfg['clock_attestor'],
                             'clock_limit': 'operator trusts Linux synchronization/error reports; not independent UTC authentication',
                             'served_bindings': self.served_bindings, 'interruption_scope': 'network-held response only'})
        self.failure_domain = 'product'
        original = rel.Target(self.private / 'original')
        self.tool('install', '--target', original.out, '--release', self.release.path, '--kernel', self.kernel,
                  '--target-identity', 'app-recovery-' + self.cfg['run'])
        self.tool('reconfigure', '--target', original.out, '--release', self.release.path, '--kernel', self.kernel,
                  '--etc', self.etc, '--authorized-keys', self.public_key)
        tree = original.tree()
        require(tree[rel.rr.physical('/bin/https-document', self.release.id)] == (self.release.path / 'tree/bin/https-document').read_bytes(), 'installed App A differs')
        require(all(tree.get(path) == data for path, data in self.config_bytes.items())
                and tree.get('/ssh/authorized_keys') == rel.oi.authorized(self.public_key), 'installed configuration/client identity differs')
        self.peer = self.peer_module.AcceptedPeer(self.peer_config)
        self.start(original, 'source-point')
        if self.smoke:
            self.run_smoke()
            return
        self.committed = self.fetch('committed-max16384')
        self.ssh('/bin/sync')
        halt_ns = self.halt()
        self.base_state = p2.inventory(original.image)
        report = self.tool('backup', '--target', original.out, self.point, '--recovery-point')
        self.pin = reported_point_pin(report, self.release.id)
        require(ba.sha(self.point / 'backup.toml') == self.pin, 'point metadata differs from creation report')
        self.event('point-pin', {'sha256': self.pin, 'expected_release': self.release.id, 'clean_halt_monotonic_ns': halt_ns,
                                 'RPO': 'last clean halted point; every subsequent change may be lost'})
        self.tool('verify-backup', self.point, '--recovery-point-sha256', self.pin, '--expected-release', self.release.id)
        point = rel.recovery_snapshot(p2.Args(backup=str(self.point), recovery_point_sha256=self.pin, expected_release=self.release.id))
        require(point.tree.get(self.committed['path']) == self.committed['receipt']
                and point.tree.get(self.committed['path'].removesuffix('receipt') + 'body') == BODY
                and all(point.tree.get(path) == value for path, value in self.config_bytes.items()), 'halted point lost App A body/receipt/config')
        require(point.metadata['identity']['host_key_fingerprint'] == self.expected_host[1]
                and rel.host_public_key(point.tree['/ssh/host_ed25519_seed']) == self.expected_host[0], 'point host identity differs')
        self.mark('app-clean-point', {'pin': self.pin, 'bundle': self.committed['path'], 'body_sha256': sha(BODY),
                                     'receipt_sha256': sha(self.committed['receipt']), 'state': p2.public_inventory(self.base_state)})
        boot = self.start(original, 'source-after-point')
        self.ssh('/bin/cat > ' + POST, POST_BYTES); self.ssh('/bin/sync')
        require(self.ssh('/bin/cat ' + POST)[1] == POST_BYTES, 'post-point committed marker readback differs')
        command, _, _ = self.attest('in-flight')
        self.peer.hold_next = True
        self.held = subprocess.Popen(self.ssh_argv(command, held=True), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(self.peer.held_get.wait(10), 'no actual held decrypted GET/partial response')
        row = self.peer.rows[-1]
        require_live_boot(boot['console'].read_bytes())
        stop_ns = unclean_stop(boot['process'], row, self.held)
        self.active = None
        failed_hash = ba.sha(original.image)
        self.event('unclean-stop', {'pid': boot['process'].pid, 'status': boot['process'].returncode, 'held_peer': dict(row),
                                    'point_to_stop_ns': stop_ns - halt_ns, 'post_point_marker_committed': True,
                                    'claim': 'network-held in-flight fetch; filesystem pre-rename boundary not observed'})
        # QEMU loss cannot promise remote EOF. Close only our exact remaining
        # peer socket locally; keep the listener for the restored machine.
        sockets = [s for s in self.peer.sockets if s.fileno() >= 0]
        require(len(sockets) == 1 and list(sockets[0].getpeername()) == row['source'], 'held peer socket identity differs')
        sockets[0].setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        sockets[0].shutdown(socket.SHUT_RDWR)
        sockets[0].close()
        row['local_close_after_qemu_stop'] = True
        end = time.monotonic() + 5
        while not row.get('ended') and time.monotonic() < end:
            time.sleep(.02)
        require(row.get('ended'), 'owned held peer did not end after local cleanup')
        row['transport_end_source'] = 'local fixture shutdown after QEMU terminal; not remote EOF evidence'
        self.finish_interrupted_client(row)
        self.mark('held-fetch-unclean-stop', {'failed_image_sha256': failed_hash, 'point_to_stop_ns': stop_ns - halt_ns,
                                           'RPO_cutoff': 'clean halt at pinned point', 'later_committed_write_may_be_lost': POST})
        wrong = self.restore('wrong-release')
        wrong_boot = self.start(wrong, 'wrong-release', wrong=True)
        require(wrong_boot['process'].wait(timeout=300) == 7, 'wrong-release boot did not exit with refusal')
        raw = wrong_boot['console'].read_bytes(); text = raw.decode(errors='replace')
        require(raw.count(b'ABSD KERNEL BOOT\n') == 1
                and re.search(r'(?m)^RELEASE REFUSED reason=release_mismatch$', text)
                and 'SSH LISTENING' not in p2.fence.captured_complete(raw) and 'MACHINE RECOVER RESET' not in text,
                'wrong release served, reset or lacked its exact refusal')
        self.active = None
        wrong_hash = ba.sha(wrong.image)
        self.mark('wrong-release-refused', {'wrong_image_sha256': wrong_hash, 'wrong_iso': self.cfg['wrong_manifest'],
                                           'next': 'retire execution; recover correct release from point into a fresh destination'})
        recovered = self.restore('recovered')
        self.start(recovered, 'replacement')
        self.read_bundle(self.committed)
        status, out, err = self.ssh('/bin/cat ' + POST, failure=True)
        require(status == 1 and not out and ('cat: ' + POST + ': ABSD path not found').encode() in err.splitlines(), 'RPO loss lacks exact absent marker')
        successor = self.fetch('recovered-max16384')
        require(successor['path'] != self.committed['path'] and successor['boot'] != self.committed['boot'], 'recovery reused publication or boot identity')
        self.ssh('/bin/cat > ' + NEW, NEW_BYTES); self.ssh('/bin/sync'); self.halt()
        expected = dict(self.base_state)
        directory = successor['path'].removesuffix('/receipt')
        expected.update({directory: {'kind': 'directory'},
                         directory + '/body': {'kind': 'file', 'bytes': len(BODY), 'sha256': sha(BODY)},
                         successor['path']: {'kind': 'file', 'bytes': len(successor['receipt']), 'sha256': sha(successor['receipt'])},
                         NEW: {'kind': 'file', 'bytes': len(NEW_BYTES), 'sha256': sha(NEW_BYTES)}})
        p2.require_state(p2.inventory(recovered.image), expected)
        self.start(recovered, 'clean-restart')
        self.attest('restart-fresh-sample')
        self.read_bundle(self.committed); self.read_bundle(successor)
        require(self.ssh('/bin/cat ' + NEW)[1] == NEW_BYTES, 'new application write did not survive restart')
        self.halt()
        p2.require_state(p2.inventory(recovered.image), expected)
        self.mark('replacement-app-durable', {'point_bundle': self.committed['path'], 'new_bundle': successor['path'],
                                             'new_body_sha256': sha(BODY), 'new_receipt_sha256': sha(successor['receipt']),
                                             'new_write_sha256': sha(NEW_BYTES), 'fresh_attestation': True, 'clean_restart_readback': True})
        require(ba.sha(original.image) == failed_hash and ba.sha(wrong.image) == wrong_hash
                and ba.sha(self.point / 'backup.toml') == self.pin, 'retained failure or point changed')
        self.mark('failed-images-retained', {'original': {'path': str(original.image), 'sha256': failed_hash},
                                             'wrong_release': {'path': str(wrong.image), 'sha256': wrong_hash},
                                             'point': {'path': str(self.point), 'metadata_sha256': self.pin},
                                             'custodian': self.cfg['custodian'], 'retire': self.cfg['retirement_condition']})

    def close(self, error):
        cleanup, errors = [], []
        for boot in self.boots:
            process = boot['process']
            if process.poll() is None:
                try:
                    process.kill(); process.wait(timeout=30)
                    cleanup.append({'owned_qemu_stopped': process.pid, 'status': process.returncode})
                except BaseException as exc:
                    errors.append('owned QEMU cleanup: ' + str(exc))
        if self.held is not None and self.held.poll() is None:
            try:
                self.held.kill(); self.held.communicate(timeout=10)
                cleanup.append({'owned_client_stopped': self.held.pid})
            except BaseException as exc:
                errors.append('owned client cleanup: ' + str(exc))
        if self.peer is not None:
            try:
                self.peer.stop()
                self.event('peer-closeout', {'rows': self.peer.rows, 'threads_ended': True,
                                             'limits': 'QEMU loss uses local peer socket cleanup, not remote EOF evidence'})
            except BaseException as exc:
                errors.append('owned peer cleanup: ' + str(exc))
        if self.evidence.is_dir():
            failure = error if error is not None else '; '.join(errors) if errors else None
            if self.smoke:
                passed = (failure is None and self.smoke_receipt is not None
                          and len(self.rows) == 1 and self.rows[0].get('case') == 'inputs'
                          and self.rows[0].get('disposition') == 'PASS')
                result = {'schema': 'absd-app-a-harness-smoke/1',
                          'disposition': 'SMOKE_PASS_NOT_QUALIFICATION' if passed else 'FAIL',
                          'workload': self.smoke_receipt, 'error': str(failure) if failure is not None else None}
            else:
                result = terminal(self.rows, failure, failure_domain=getattr(self, 'failure_domain', 'infrastructure'))
            images = []
            for path in sorted({boot['target'].image for boot in self.boots}):
                quiet = all(boot['process'].poll() is not None for boot in self.boots if boot['target'].image == path)
                images.append({'path': str(path), 'all_owned_producers_terminal': quiet,
                               'sha256': ba.sha(path) if quiet and path.is_file() else None})
            result.update(source=getattr(self, 'source', None), config=self.config_identity,
                          cleanup=cleanup, cleanup_errors=errors, private_images=images,
                          recovery_point={'path': str(self.point), 'pin': self.pin, 'preserved': self.point.exists()},
                          private_custodian=self.cfg.get('custodian'),
                          credential_disposition='supplied keys retained for named owner; no ambient agent use or key retirement by driver')
            write(self.evidence / 'RESULT.json', result)
        if errors:
            raise ValueError('owned runtime cleanup incomplete: ' + '; '.join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--private-work', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--smoke', action='store_true')
    args = parser.parse_args()
    private, evidence = args.private_work.resolve(), args.evidence.resolve()
    require(private != evidence and private not in evidence.parents and evidence not in private.parents,
            'private and evidence roots overlap')
    require(not private.exists() and not evidence.exists(), 'fresh private/evidence roots required')
    raw = args.config.read_bytes()
    cfg = json.loads(raw)
    require(not args.config.is_symlink(), 'admitted config must not be a symlink')
    require(cfg.get('harness_mode', 'app_a') in ('app_a', 'smoke_cat'), 'unknown harness mode')
    require(args.smoke == (cfg.get('harness_mode', 'app_a') == 'smoke_cat'), 'harness mode and --smoke flag differ')
    driver = Qualification(cfg, private, evidence, {'path': str(args.config.resolve()), 'sha256': sha(raw)}, smoke=args.smoke)
    error = None
    try:
        driver.run()
    except BaseException as exc:
        error = exc
        raise
    finally:
        driver.close(error)


if __name__ == '__main__':
    main()
