#!/usr/bin/env python3
"""Host-only RAM policy and launcher audit. Never starts QEMU or builds images.

Inventory actual argv construction sites rather than just their wrappers.
Every detected durable/QEMU builder requires classification, including scripts
in subdirectories. This is a bounded source-pattern audit, not Python or shell
data-flow analysis. The observe matrix is qualification-only; the sole served
low-RAM bypass is the negative gate. Importer/enrollment boots using the shared
launch paths also receive the floor; ABSD_GUEST_RAM may raise TLS/media boots.
"""
import ast
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import served_ram

LAUNCHERS = {
    'native-ipv6-mtu1280-matrix.py': 1,
    'native-tls-ipv6-routed-matrix.py': 1,
    'native-ipv6-dad-matrix.py': 1,
    'native-ipv6-echo-matrix.py': 1,
    'native-ipv6-echo-responder.py': 1,
    'native-ipv6-route-matrix.py': 1,
    'native-ipv6-routed-tcp-matrix.py': 1,
    'native-quic-q01.py': 1,
    'native-dhcp-refusal-matrix.py': 1,
    'absd_try.py': 2, 'ag-native-matrix.py': 2, 'durable-matrix.py': 1,
    'enroll-matrix.py': 1, 'exec-matrix.py': 1, 'link-matrix.py': 1,
    'mtime-matrix.py': 1,
    'media_boot.py': 1, 'media_operator.py': 1, 'native-tls-matrix.py': 1,
    'native-tls-ipv6-matrix.py': 1,
    'net-matrix.py': 1, 'nightshift-matrix.py': 1, 'observe-matrix.py': 1,
    'operator_image.py': 1, 'pipeline-matrix.py': 1, 'pulse-matrix.py': 1,
    'native-ipv6-matrix.py': 1, 'native-ipv6-tcp-matrix.py': 1,
    'release.py': 2, 'served-matrix.py': 1, 'ssh_absd.py': 3,
    'survival-pre-ready.py': 1, 'u1-endurance.py': 2,
    'boot-operator.sh': 1, 'run-broker.sh': 1,
    'native-dhcp-directed-arp-matrix.py': 1,
    'native-dhcp-matrix.py': 1,
    'native-echo-matrix-arp.py': 1,
    'native-echo-matrix.py': 1,
    'native-ipv6-accounting-matrix.py': 1,
    'native-ipv6-feedback-matrix.py': 1,
    'native-ipv6-reason-matrix.py': 1,
    'native-ipv6-tcp-accounting-matrix.py': 1,
    'native-ipv6-tcp-reason-matrix.py': 1,
    'native-sntp-matrix.py': 1,
    'native-tcp-server-matrix.py': 1,
}


def has_policy(node):
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
               and n.func.id == 'served_qemu' for n in ast.walk(node))


def audit(name, source):
    if name.endswith('.sh'):
        count = 0
        for line in source.replace('\\\n', ' ').splitlines():
            if line.lstrip().startswith('#'):
                continue
            if '-cdrom ' in line or re.search(r'\bdurable-boot\.sh\b', line):
                count += 1
                if 'python3 "$root/scripts/served_ram.py" --' not in line:
                    raise ValueError(f'{name}: shell QEMU launch bypasses RAM policy')
        return count
    tree = ast.parse(source)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    # Track simple local/module aliases of the durable script path. Keep
    # references conservative across scopes rather than treating unknown
    # aliases as proof that an argv cannot launch a durable guest.
    script_names = set()

    def script_reference(node):
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str) and 'durable-boot.sh' in node.value
        if isinstance(node, ast.Name):
            return node.id in script_names
        if isinstance(node, ast.BinOp):
            return script_reference(node.left) or script_reference(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(script_reference(part) for part in node.values)
        if isinstance(node, ast.FormattedValue):
            return script_reference(node.value)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ('str', 'Path'):
                return any(script_reference(arg) for arg in node.args)
            if (isinstance(node.func, ast.Attribute) and node.func.attr == 'Path'
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'pathlib'):
                return any(script_reference(arg) for arg in node.args)
            if isinstance(node.func, ast.Attribute) and node.func.attr in ('joinpath', 'resolve'):
                return script_reference(node.func.value) or any(script_reference(arg) for arg in node.args)
        return False

    assignments = [n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None]
    while True:
        added = set()
        for assignment in assignments:
            if script_reference(assignment.value):
                targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
                added.update(target.id for target in targets if isinstance(target, ast.Name))
        if added <= script_names:
            break
        script_names.update(added)
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.List, ast.Tuple)):
            continue
        # Only argv-level constants and the script expression in its first
        # word. Do not double-count an enclosing list or an inner RAM prefix.
        strings = [n.value for n in node.elts if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        first = ast.unparse(node.elts[0]) if node.elts else ''
        if not (any(s in ('-cdrom', '-machine', 'isa-debug-exit,iobase=0xf4,iosize=0x04') for s in strings)
                or 'durable-boot.sh' in first
                # A name in a nested file/digest metadata tuple is not a
                # newly discovered argv. Keep the original literal checks.
                or (node.elts and script_reference(node.elts[0])
                    and not isinstance(parents.get(node), (ast.List, ast.Tuple)))
                or (name == 'release.py' and first == 'str(script)')):
            continue
        count += 1
        owner = node
        while owner in parents and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
            owner = parents[owner]
        function = owner.name if isinstance(owner, ast.FunctionDef) else ''
        statement = node
        while statement in parents and not isinstance(statement, ast.stmt):
            statement = parents[statement]
        if name == 'observe-matrix.py' and function == 'raw_boot':
            if 'DURABLE_OPTIONS' in source:
                raise ValueError('observe matrix must remain qualification-only for its low-RAM probe')
            continue
        if name == 'served-matrix.py' and function == 'ram_below_minimum_boot':
            if not has_policy(owner) or '"128M"' not in ast.unparse(owner).replace("'", '"'):
                raise ValueError('missing deliberate 128M negative gate')
            continue
        if name == 'u1-endurance.py' and function == 'qemu_argv':
            if any(isinstance(n, ast.Return) and isinstance(n.value, ast.Call)
                   and isinstance(n.value.func, ast.Name) and n.value.func.id == 'served_qemu'
                   for n in ast.walk(owner)):
                continue
        if not has_policy(statement):
            raise ValueError(f'{name}:{node.lineno}: QEMU argv bypasses shared RAM policy')
    if count and name not in ('observe-matrix.py',) and 'from served_ram import served_qemu' not in source:
        raise ValueError(f'{name}: missing shared import')
    return count


def audit_tree(root):
    found = {}
    for path in sorted(root.rglob('*')):
        if (not path.is_file() or path.suffix not in ('.py', '.sh')
                or path.name.startswith('test') or path.name.endswith('-selftest.py')):
            continue
        name = path.relative_to(root).as_posix()
        count = audit(name, path.read_text())
        if count:
            found[name] = count
    return found


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ServedRamTests(unittest.TestCase):
    def test_all_launchers_use_policy(self):
        self.assertEqual(audit_tree(ROOT), LAUNCHERS)

    def test_every_launcher_bypass_is_rejected(self):
        for name in LAUNCHERS:
            if name == 'observe-matrix.py':
                continue
            source = (ROOT / name).read_text()
            mutant = source.replace('served_qemu(', 'list(').replace('served_ram.py', 'bypass.py')
            with self.subTest(launcher=name), self.assertRaises(ValueError):
                audit(name, mutant)
        for source in ('subprocess.Popen(["qemu", "-cdrom", iso])',
                       'commands = [["qemu", "-cdrom", iso]]',
                       'subprocess.run([str(kernel / "scripts/durable-boot.sh"), iso, image, log, "300", *qemu])'):
            with self.assertRaises(ValueError):
                audit('new.py', source)
        with self.assertRaises(ValueError):
            audit('new.sh', '$qemu -cdrom "$iso"')

    def test_variable_script_and_bare_shell_bypasses_are_rejected(self):
        # The two concrete missed spellings from the composition review,
        # plus a simple alias and an annotated assignment.
        sources = ('script = kernel / "scripts/durable-boot.sh"\n'
                   'subprocess.run([str(script), iso, image, log, "120", qemu])\n',
                   'script = kernel / "scripts" / "durable-boot.sh"\n'
                   'runner = script\nsubprocess.run([str(runner), iso, image, log, "120", qemu])\n',
                   'runner: Path = kernel / "scripts/durable-boot.sh"\n'
                   'subprocess.Popen([str(runner), iso, image, log, "120", qemu])\n',
                   'runner = pathlib.Path(kernel, "scripts", "durable-boot.sh")\n'
                   'subprocess.run([str(runner), iso, image, log, "120", qemu])\n')
        for source in sources:
            with self.subTest(source=source), self.assertRaises(ValueError):
                audit('new.py', source)
            compliant = 'from served_ram import served_qemu\n' + source.replace('"120", qemu', '"120", *served_qemu(qemu)')
            self.assertEqual(audit('new.py', compliant), 1)
        shell = '"$kernel/scripts/durable-boot.sh" "$iso" "$image" "$log" 120 "$qemu"\n'
        with self.assertRaises(ValueError):
            audit('new.sh', shell)
        self.assertEqual(audit('new.sh', 'python3 "$root/scripts/served_ram.py" --durable-boot ' + shell), 1)

    def test_recursive_scan_keeps_relative_names_and_refuses_bypasses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / 'nested'
            nested.mkdir()
            script = nested / 'launcher.py'
            script.write_text('from served_ram import served_qemu\n'
                              'script = kernel / "scripts/durable-boot.sh"\n'
                              'subprocess.run([str(script), iso, image, log, "120", *served_qemu(qemu)])\n')
            self.assertEqual(audit_tree(root), {'nested/launcher.py': 1})
            script.write_text(script.read_text().replace('served_qemu(', 'list('))
            with self.assertRaises(ValueError):
                audit_tree(root)
            script.unlink()
            (nested / 'launcher.sh').write_text('"$kernel/scripts/durable-boot.sh" "$iso" "$image" "$log" 120 "$qemu"\n')
            with self.assertRaises(ValueError):
                audit_tree(root)

    def test_default_and_upward_overrides(self):
        self.assertEqual(served_ram.served_qemu('qemu -cpu host', env={}),
                         ['qemu', '-cpu', 'host', '-m', '256M'])
        for value in ('256', '512M', '1G', '262144K', 'size=512M,slots=2,maxmem=1G'):
            with self.subTest(value=value):
                original = ['qemu', '-m', value]
                self.assertEqual(served_ram.served_qemu(original, env={})[-1], value)
                self.assertEqual(original, ['qemu', '-m', value])
        self.assertEqual(served_ram.served_qemu('qemu -m=512M', env={}), ['qemu', '-m', '512M'])
        self.assertEqual(served_ram.served_qemu('qemu -m 1G', memory='512M',
                                              env={'ABSD_GUEST_RAM': '768M'})[-1], '1G')
        self.assertEqual(served_ram.served_qemu('qemu -m 512M', env={'ABSD_GUEST_RAM': '1G'})[-1], '1G')
        self.assertEqual(served_ram.served_qemu('qemu', memory='512M', env={})[-1], '512M')
        self.assertEqual(served_ram.served_qemu('"/a path/qemu" -m 512M', env={})[0], '/a path/qemu')

    def test_low_and_malformed_sizes_are_refused(self):
        for value in ('128M', '255', '0', '-1G', '', '256MB', '1e9',
                      'size=128M,maxmem=1G', '256M,size=128M', '512M,slots=2,slots=1'):
            for argv, memory, env in ((['qemu', '-m', value], None, {}),
                                      (['qemu'], value, {}),
                                      (['qemu', '-m', '1G'], None, {'ABSD_GUEST_RAM': value})):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    served_ram.served_qemu(argv, memory=memory, env=env)
        for argv in (['qemu', '-m'], ['qemu', '-m', '128M', '-m', '512M'],
                     ['qemu', '--m=128M'], []):
            with self.assertRaises(ValueError):
                served_ram.served_qemu(argv, env={})

    def test_shell_entrypoints_preserve_status_and_arguments(self):
        # The executable is a Python argv recorder, never QEMU.
        with tempfile.TemporaryDirectory() as tmp:
            recorder = Path(tmp) / 'record.py'
            recorder.write_text('import sys; print(repr(sys.argv[1:])); sys.exit(7)\n')
            env = dict(os.environ, ABSD_GUEST_RAM='512M')
            prefix = [sys.executable, str(ROOT / 'served_ram.py')]
            result = subprocess.run([*prefix, '--', sys.executable, str(recorder), 'a b'],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertEqual(ast.literal_eval(result.stdout), ['a b', '-m', '512M'])
            result = subprocess.run([*prefix, '--durable-boot', sys.executable, str(recorder),
                                     'image', 'log', '120', 'qemu', '-m', '1G'],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertEqual(ast.literal_eval(result.stdout), ['image', 'log', '120', 'qemu', '-m', '1G'])
            result = subprocess.run([*prefix, '--', sys.executable, str(recorder), '-m', '128M'],
                                    env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
            self.assertIn('below the 256M minimum', result.stderr)

    def test_endurance_builder(self):
        endurance = load('u1-endurance.py')
        with patch.dict(os.environ, {}, clear=True):
            for memory, expected in ((None, '256M'), ('512M', '512M')):
                argv = endurance.qemu_argv('A', Path('/fixture'), 2222, '10.0.2.15', 22, memory)
                self.assertEqual(argv[-2:], ['-m', expected])
            with self.assertRaises(ValueError):
                endurance.qemu_argv('A', Path('/fixture'), 2222, '10.0.2.15', 22, '128M')

    def test_entropy_control_keeps_ram_and_omits_cpu_features(self):
        ssh = load('ssh_absd.py')
        with tempfile.TemporaryDirectory() as tmp:
            target = SimpleNamespace(work=Path(tmp), kernel=Path('/no-kernel'), image=Path('/no-image'),
                                     qemu='qemu -cpu max,+rdrand -m 512M', boots=0,
                                     sshd_iso=lambda: '/no-iso', system_digest=lambda: 'unchanged')
            def run(argv, **kw):
                self.assertEqual(argv[5:], ['qemu', '-m', '512M', '-netdev', 'user,id=n0',
                                           '-device', 'e1000,netdev=n0'])
                text = b'sshd: entropy: refused\n'
                Path(argv[3]).write_text(f'EXTERNAL OUTPUT CHUNK offset=0000000000000000 data={text.hex()}\n')
                return SimpleNamespace(stdout='7')
            def check(label, ok, detail):
                self.assertTrue(ok, label + detail)
            matrix = SimpleNamespace(check=check, mark=lambda text: None)
            with patch.object(ssh.subprocess, 'run', run), patch.dict(os.environ, {}, clear=True):
                ssh.AbsdTarget.negative_controls(target, matrix)

    def test_refusal_gate_oracle_without_guest(self):
        served = load('served-matrix.py')
        valid = ('ABSD KERNEL BOOT\nSERVED FRAME BOOT REFUSED reason=ram_below_minimum '
                 'usable_bytes=133692416 minimum_bytes=150047744\n')
        samples = [(valid, '7', True), (valid, '3', False),
                   (valid.replace('ram_below_minimum', 'another_reason'), '7', False),
                   (valid.replace('150047744', '1'), '7', False),
                   (valid + 'ABSD KERNEL BOOT\n', '7', False),
                   (valid + 'FILE SERVER START pid=2\n', '7', False),
                   (valid + 'MACHINE RECOVER RESET\n', '7', False)]
        for serial, status, accepted in samples:
            with self.subTest(status=status, serial=serial), tempfile.TemporaryDirectory() as tmp:
                target = SimpleNamespace(work=Path(tmp), kernel=Path('/no-kernel'), image=Path('/no-image'),
                                         qemu='qemu -m 1G', sshd_iso=lambda: '/no-iso')
                def run(argv, **kw):
                    self.assertEqual(argv[argv.index('-m') + 1], '128M')
                    self.assertEqual(argv.count('-m'), 1)
                    Path(argv[3]).write_text(serial)
                    return SimpleNamespace(stdout=status)
                def check(label, ok, detail):
                    if not ok:
                        raise AssertionError(label + detail)
                matrix = SimpleNamespace(t=target, check=check, mark=lambda text: None)
                with patch.object(served.subprocess, 'run', run), patch.dict(os.environ, {'ABSD_GUEST_RAM': '2G'}):
                    if accepted:
                        served.ServedMatrix.ram_below_minimum_boot(matrix)
                    else:
                        with self.assertRaises(AssertionError):
                            served.ServedMatrix.ram_below_minimum_boot(matrix)


if __name__ == '__main__':
    unittest.main()
