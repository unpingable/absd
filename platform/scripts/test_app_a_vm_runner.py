import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name('app-a-vm-runner.py')
OLD_RUN = '11111111-1111-4111-8111-111111111111'
NEW_RUN = '22222222-2222-4222-8222-222222222222'
OLD_SOURCE = '1' * 40
NEW_SOURCE = '2' * 40
KERNEL = '3' * 40


def load_runner():
    spec = importlib.util.spec_from_file_location('app_a_vm_runner', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (dict, list)):
        data = json.dumps(data, indent=2) + '\n'
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def make_input(root):
    old_app = root / 'source/app.py'
    write(old_app, 'OLD SOURCE = "' + OLD_SOURCE + '"\n')
    static = root / 'source/static.txt'
    write(static, 'immutable payload\n')
    template = root / 'CONFIG.TEMPLATE.NO-GO.json'
    app_destination = '/root/absd-app-replacement/' + OLD_RUN + '/app.py'
    write(template, {
        'run': OLD_RUN,
        'source_revision': OLD_SOURCE,
        'kernel_revision': KERNEL,
        'driver_sha256': digest(old_app),
        'manifest': {'path': app_destination, 'sha256': digest(old_app)},
    })
    guest_prepare = root / 'source/guest-prepare.sh'
    write(guest_prepare, 'run=' + OLD_RUN + '\nsource=' + OLD_SOURCE + '\n')
    binder = root / 'source/bind-runtime.py'
    write(binder, 'DRIVER = "' + digest(old_app) + '"\n')
    descriptor = {
        'run': OLD_RUN,
        'files': [
            {'source': str(old_app), 'destination': 'lifecycle/app.py',
             'bytes': old_app.stat().st_size, 'sha256': digest(old_app)},
            {'source': str(static), 'destination': 'lifecycle/static.txt',
             'bytes': static.stat().st_size, 'sha256': digest(static)},
            {'source': str(static), 'destination': 'lifecycle/selected.toml',
             'bytes': static.stat().st_size, 'sha256': digest(static)},
            {'source': str(static), 'destination': 'lifecycle/wrong.toml',
             'bytes': static.stat().st_size, 'sha256': digest(static)},
            {'source': str(static), 'destination': 'lifecycle/build-receipt.json',
             'bytes': static.stat().st_size, 'sha256': digest(static)},
            {'source': str(guest_prepare), 'destination': 'lifecycle/guest-prepare.sh',
             'bytes': guest_prepare.stat().st_size, 'sha256': digest(guest_prepare)},
            {'source': str(static), 'destination': 'lifecycle/DELIVERY-MANIFEST.json',
             'bytes': static.stat().st_size, 'sha256': digest(static)},
            {'source': str(template), 'destination': 'lifecycle/CONFIG.TEMPLATE.json',
             'bytes': template.stat().st_size, 'sha256': digest(template)},
        ],
    }
    write(root / 'PAYLOAD-DESCRIPTOR.json', descriptor)
    write(root / 'DELIVERY-MANIFEST.json', {
        'run': OLD_RUN,
        'files': [
            {'source': str(old_app), 'input_member': 'lifecycle/app.py',
             'proposed_destination': app_destination,
             'bytes': old_app.stat().st_size, 'sha256': digest(old_app)},
            {'source': str(guest_prepare), 'input_member': 'lifecycle/guest-prepare.sh',
             'proposed_destination': '/root/absd-app-replacement/' + OLD_RUN + '/guest-prepare.sh',
             'bytes': guest_prepare.stat().st_size, 'sha256': digest(guest_prepare)},
        ],
        'source_bundles': [
            {'name': 'platform', 'source': str(old_app), 'bytes': old_app.stat().st_size,
             'sha256': digest(old_app), 'revision': OLD_SOURCE,
             'future_clone': '/root/absd-app-replacement/' + OLD_RUN + '/source/platform'},
            {'name': 'kernel', 'source': str(old_app), 'bytes': old_app.stat().st_size,
             'sha256': digest(old_app), 'revision': KERNEL,
             'future_clone': '/root/absd-app-replacement/' + OLD_RUN + '/source/kernel'},
        ],
    })
    write(root / 'GO.json', {'run': OLD_RUN, 'source_revision': OLD_SOURCE, 'kernel_revision': KERNEL})
    for name in ('PREPARE-ADMISSION.DRAFT.json', 'CREDENTIALS-ADMISSION.DRAFT.json'):
        write(root / name, {'run': OLD_RUN, 'source_revision': OLD_SOURCE, 'kernel_revision': KERNEL})
    write(root / 'RUNTIME-ADMISSION.DRAFT.json', {'run': OLD_RUN, 'template_sha256': digest(template),
                                                 'binder_sha256': digest(binder)})
    write(root / 'MATERIALIZATION.NO-GO.json', {'run': OLD_RUN, 'accepted_template_sha256': digest(template),
                                                'accepted_binder_sha256': digest(binder)})
    stage_script = root / 'plan/bindings/stage/stage-prep.py'
    write(stage_script, 'ids = {"platform": ("' + OLD_SOURCE + '", "' + 'a' * 40 + '", "' + 'b' * 64 + '", 123)}\n')
    old_bundle = root / 'assembly/stage-inputs/stage/src/platform.bundle'
    write(old_bundle, 'old bundle bytes\n')
    kernel_bundle = root / 'assembly/stage-inputs/stage/src/kernel.bundle'
    write(kernel_bundle, 'old kernel bundle bytes\n')
    proxy = root / 'special/rustup'
    write(proxy, 'pinned rustup proxy\n')
    member = root / 'special/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc'
    write(member, 'pinned toolchain member\n')
    members = root / 'special/MEMBERS-1.95.0.json'
    write(members, {'schema': 'absd-selected-public-rust-members/1', 'toolchain': '1.95.0',
                    'directory': '1.95.0-x86_64-unknown-linux-gnu',
                    'members': [{'member': '1.95.0-x86_64-unknown-linux-gnu/bin/rustc', 'kind': 'file',
                                 'bytes': member.stat().st_size, 'sha256': digest(member), 'mode': '0o755'}]})
    write(stage_script.parent / 'STAGE-INPUTS.json', {
        'files': [
            {'path': str(old_bundle), 'dest': 'src/platform.bundle', 'bytes': old_bundle.stat().st_size,
             'sha256': digest(old_bundle), 'mode': '0o644'},
            {'path': str(stage_script), 'dest': 'rc2/stage-prep.py', 'bytes': stage_script.stat().st_size,
             'sha256': digest(stage_script), 'mode': '0o644'},
        ],
        'rustup_proxy': {'bytes': proxy.stat().st_size, 'sha256': digest(proxy)},
        'toolchains': [{'toolchain': '1.95.0', 'source_rustup_toolchains': str(root / 'special/toolchains'),
                        'members_manifest': {'path': str(members), 'sha256': digest(members)}}],
        'sources': {'platform': {'revision': OLD_SOURCE}, 'kernel': {'revision': KERNEL}},
        'revision': OLD_SOURCE,
    })


def make_candidate(root):
    repo = root / 'repo'
    repo.mkdir()
    subprocess.run(['git', 'init', '-q', str(repo)], check=True)
    new_app = repo / 'scripts/app.py'
    write(new_app, 'NEW SOURCE = "' + NEW_SOURCE + '"\n')
    subprocess.run(['git', '-C', str(repo), 'add', 'scripts/app.py'], check=True)
    subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    'commit', '-q', '-m', 'candidate'], check=True)
    revision = git(repo, 'rev-parse', 'HEAD').decode().strip()
    tree = git(repo, 'rev-parse', 'HEAD^{tree}').decode().strip()
    archive = git(repo, 'archive', '--format=tar', 'HEAD')
    bundle = root / 'platform.bundle'
    subprocess.run(['git', '-C', str(repo), 'bundle', 'create', str(bundle), 'HEAD'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    native_receipt = root / 'https-document-build.json'
    write(native_receipt, {'source_revision': revision, 'source_tree': tree})
    selected = root / 'selected.toml'
    write(selected, '[source]\nplatform_commit = "' + revision + '"\nkernel_commit = "' + KERNEL + '"\nplatform_tree_clean = true\nkernel_tree_clean = true\n\n[build.https_document]\nenabled = true\nbuild_receipt_sha256 = "' + digest(native_receipt) + '"\n')
    wrong = root / 'wrong.toml'
    write(wrong, '[source]\nplatform_commit = "' + 'a' * 40 + '"\nkernel_commit = "' + KERNEL + '"\nplatform_tree_clean = true\nkernel_tree_clean = true\n')
    return {
        'schema': 'absd-app-a-vm-candidate/1',
        'base_source_revision': OLD_SOURCE,
        'source_revision': revision,
        'kernel_revision': KERNEL,
        'wrong_source_revision': 'a' * 40,
        'release_manifest_destination': 'lifecycle/selected.toml',
        'wrong_manifest_destination': 'lifecycle/wrong.toml',
        'app_build_receipt_destination': 'lifecycle/build-receipt.json',
        'driver_destination': 'lifecycle/app.py',
        'driver_source': {'source': str(new_app), 'bytes': new_app.stat().st_size, 'sha256': digest(new_app)},
        'rustup_proxy': {'source': str(root / 'input/special/rustup'), 'bytes': (root / 'input/special/rustup').stat().st_size,
                         'sha256': digest(root / 'input/special/rustup')},
        'harness_mode': 'smoke_cat',
        'source_root': str(repo),
        'source_identity': {
            'revision': revision,
            'tree': tree,
            'archive_sha256': hashlib.sha256(archive).hexdigest(),
            'archive_bytes': len(archive),
        },
        'payload_pins': {
            'lifecycle/app.py': {'source': str(new_app), 'bytes': new_app.stat().st_size,
                                 'sha256': digest(new_app)},
            'lifecycle/selected.toml': {'source': str(selected), 'bytes': selected.stat().st_size,
                                        'sha256': digest(selected)},
            'lifecycle/wrong.toml': {'source': str(wrong), 'bytes': wrong.stat().st_size,
                                     'sha256': digest(wrong)},
            'lifecycle/build-receipt.json': {'source': str(native_receipt), 'bytes': native_receipt.stat().st_size,
                                             'sha256': digest(native_receipt)},
        },
        'stage_pins': {
            'src/platform.bundle': {'source': str(bundle), 'bytes': bundle.stat().st_size,
                                    'sha256': digest(bundle), 'mode': '0o644'},
            'src/kernel.bundle': {'source': str(root / 'input/assembly/stage-inputs/stage/src/kernel.bundle'),
                                  'bytes': (root / 'input/assembly/stage-inputs/stage/src/kernel.bundle').stat().st_size,
                                  'sha256': digest(root / 'input/assembly/stage-inputs/stage/src/kernel.bundle'), 'mode': '0o644'},
        },
    }


class RunnerTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        fixture = patch.dict(os.environ, {'ABSD_APP_A_SSH_TARGET': 'builder@example.invalid',
                                          'ABSD_APP_A_SSH_IDENTITY': '/public-fixture/identity'})
        fixture.start()
        self.addCleanup(fixture.stop)
        self.assertTrue(SCRIPT.is_file(), 'repository-owned runner entrypoint is missing')

    def test_json_writer_creates_fresh_parents_and_refuses_replacement(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'new/evidence/RESULT.json'
            runner.write_json(path, {'disposition': 'NOT_RUN'})
            self.assertEqual(json.loads(path.read_text()), {'disposition': 'NOT_RUN'})
            with self.assertRaises(FileExistsError):
                runner.write_json(path, {'disposition': 'PASS'})
            self.assertEqual(json.loads(path.read_text()), {'disposition': 'NOT_RUN'})

    def test_materialization_delivers_protected_files_from_selected_commit(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'input'
            source.mkdir()
            make_input(source)
            candidate = make_candidate(base)
            historical = source / 'source/static.txt'
            original = historical.read_bytes()
            descriptor = json.loads((source / 'PAYLOAD-DESCRIPTOR.json').read_text())
            descriptor['files'].append({'source': str(historical), 'destination': 'lifecycle/protected.py',
                                       'bytes': len(original), 'sha256': digest(historical)})
            write(source / 'PAYLOAD-DESCRIPTOR.json', descriptor)
            delivery = json.loads((source / 'DELIVERY-MANIFEST.json').read_text())
            destination = '/root/absd-app-replacement/' + OLD_RUN + '/source/platform/scripts/app.py'
            delivery['files'].append({'source': str(historical), 'input_member': 'lifecycle/protected.py',
                'proposed_destination': destination, 'bytes': len(original), 'sha256': digest(historical)})
            write(source / 'DELIVERY-MANIFEST.json', delivery)
            output = base / 'output'
            runner.materialize(candidate, source, output, NEW_RUN)
            archive = runner.RemoteStager(output, NEW_RUN, base / 'qemu-python', 'harness').payload_archive()
            with tarfile.open(archive) as tar:
                actual = tar.extractfile('lifecycle/protected.py').read()
            selected = git(base / 'repo', 'show', candidate['source_revision'] + ':scripts/app.py')
            self.assertEqual(actual, selected)
            self.assertEqual(historical.read_bytes(), original)
            row = json.loads((output / 'DELIVERY-MANIFEST.json').read_text())['files'][-1]
            self.assertEqual(row['sha256'], hashlib.sha256(selected).hexdigest())
            candidate['payload_pins']['lifecycle/protected.py'] = {
                'source': str(historical), 'bytes': len(original), 'sha256': digest(historical)}
            with self.assertRaisesRegex(ValueError, 'protected source payload pin differs'):
                runner.materialize(candidate, source, base / 'conflicting-pin', NEW_RUN)

    def test_materialization_binds_external_pki_fixture_to_selected_product(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'input'
            source.mkdir()
            make_input(source)
            candidate = make_candidate(base)
            # The historical producer is outside input/source and its source
            # constant predates the input's base revision.
            fixture = base / 'historical/create_coverage_fixture.py'
            original = 'SOURCE = "' + 'b' * 40 + '"\nintent = {"source_revision": SOURCE}\n'
            write(fixture, original)
            descriptor = json.loads((source / 'PAYLOAD-DESCRIPTOR.json').read_text())
            descriptor['files'].append({'source': str(fixture), 'destination': 'lifecycle/files/0189',
                                       'bytes': fixture.stat().st_size, 'sha256': digest(fixture)})
            write(source / 'PAYLOAD-DESCRIPTOR.json', descriptor)
            delivery = json.loads((source / 'DELIVERY-MANIFEST.json').read_text())
            delivery['files'].append({'source': str(fixture), 'input_member': 'lifecycle/files/0189',
                'role': 'create_coverage_fixture.py',
                'proposed_destination': '/root/absd-app-replacement/' + OLD_RUN + '/harness/create_coverage_fixture.py',
                'bytes': fixture.stat().st_size, 'sha256': digest(fixture)})
            write(source / 'DELIVERY-MANIFEST.json', delivery)
            output = base / 'output'
            runner.materialize(candidate, source, output, NEW_RUN)
            archive = runner.RemoteStager(output, NEW_RUN, base / 'qemu-python', 'harness').payload_archive()
            with tarfile.open(archive) as tar:
                delivered = tar.extractfile('lifecycle/files/0189').read()
            namespace = {}
            exec(compile(delivered, 'delivered-fixture', 'exec'), namespace)
            self.assertEqual(namespace['intent']['source_revision'], candidate['source_revision'])
            self.assertEqual(fixture.read_text(), original)
            row = json.loads((output / 'DELIVERY-MANIFEST.json').read_text())['files'][-1]
            self.assertEqual(row['sha256'], hashlib.sha256(delivered).hexdigest())
            self.assertEqual(row['bytes'], len(delivered))
            for index, invalid in enumerate(('SOURCE = None\n', original + original)):
                with self.subTest(invalid=invalid):
                    write(fixture, invalid)
                    descriptor['files'][-1].update(bytes=fixture.stat().st_size, sha256=digest(fixture))
                    write(source / 'PAYLOAD-DESCRIPTOR.json', descriptor)
                    with self.assertRaisesRegex(ValueError, 'PKI fixture source identity'):
                        runner.materialize(candidate, source, base / ('invalid-' + str(index)), NEW_RUN)

    def test_materialization_rebinds_real_candidate_and_seals_consumers(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'input'
            source.mkdir()
            make_input(source)
            candidate = make_candidate(base)
            result = runner.materialize(candidate, source, base / 'output', NEW_RUN)
            output = base / 'output'
            self.assertEqual(result['run'], NEW_RUN)
            self.assertEqual(result['source_revision'], candidate['source_revision'])
            self.assertTrue((output / 'evidence').is_dir())
            guest = (output / 'source/guest-prepare.sh').read_text()
            self.assertIn(NEW_RUN, guest)
            self.assertIn(candidate['source_revision'], guest)
            self.assertNotIn(OLD_SOURCE, guest)
            descriptor = json.loads((output / 'PAYLOAD-DESCRIPTOR.json').read_text())
            rows = {row['destination']: row for row in descriptor['files']}
            new_app = Path(candidate['payload_pins']['lifecycle/app.py']['source'])
            self.assertEqual(rows['lifecycle/app.py']['sha256'], digest(new_app))
            template = json.loads((output / 'CONFIG.TEMPLATE.NO-GO.json').read_text())
            self.assertEqual(template['driver_sha256'], digest(new_app))
            self.assertEqual(template['harness_mode'], 'smoke_cat')
            self.assertIn(digest(new_app), (output / 'source/bind-runtime.py').read_text())
            self.assertEqual(template['manifest']['sha256'], digest(new_app))
            self.assertEqual(template['run'], NEW_RUN)
            template_row = rows['lifecycle/CONFIG.TEMPLATE.json']
            self.assertEqual(template_row['sha256'], digest(output / 'CONFIG.TEMPLATE.NO-GO.json'))
            runtime = json.loads((output / 'RUNTIME-ADMISSION.DRAFT.json').read_text())
            self.assertEqual(runtime['template_sha256'], template_row['sha256'])
            self.assertEqual(runtime['binder_sha256'], digest(output / 'source/bind-runtime.py'))
            materialization = json.loads((output / 'MATERIALIZATION.NO-GO.json').read_text())
            self.assertEqual(materialization['accepted_template_sha256'], template_row['sha256'])
            self.assertEqual(materialization['accepted_binder_sha256'], digest(output / 'source/bind-runtime.py'))
            self.assertEqual(rows['lifecycle/guest-prepare.sh']['source'], str(output / 'source/guest-prepare.sh'))
            self.assertEqual(rows['lifecycle/guest-prepare.sh']['sha256'], digest(output / 'source/guest-prepare.sh'))
            delivery = json.loads((output / 'DELIVERY-MANIFEST.json').read_text())
            delivery_row = next(row for row in delivery['files'] if row['input_member'] == 'lifecycle/guest-prepare.sh')
            self.assertEqual(delivery_row['source'], str(output / 'source/guest-prepare.sh'))
            self.assertEqual(delivery_row['sha256'], digest(output / 'source/guest-prepare.sh'))
            self.assertEqual(delivery_row['proposed_destination'], '/root/absd-app-replacement/' + NEW_RUN + '/guest-prepare.sh')
            self.assertEqual(rows['lifecycle/DELIVERY-MANIFEST.json']['source'], str(output / 'DELIVERY-MANIFEST.json'))
            self.assertEqual(rows['lifecycle/DELIVERY-MANIFEST.json']['sha256'], digest(output / 'DELIVERY-MANIFEST.json'))
            platform_bundle = delivery['source_bundles'][0]
            self.assertEqual(platform_bundle['revision'], candidate['source_revision'])
            self.assertEqual(platform_bundle['sha256'], candidate['stage_pins']['src/platform.bundle']['sha256'])
            self.assertEqual(platform_bundle['future_clone'], '/root/absd-app-replacement/' + NEW_RUN + '/source/platform')
            archive_path = runner.RemoteStager(output, NEW_RUN, base / 'qemu-python', 'harness').payload_archive()
            with tarfile.open(archive_path) as archive:
                self.assertEqual(archive.extractfile('lifecycle/guest-prepare.sh').read(), (output / 'source/guest-prepare.sh').read_bytes())
            stage = json.loads((output / 'plan/bindings/stage/STAGE-INPUTS.json').read_text())
            stage_rows = {row['dest']: row for row in stage['files']}
            self.assertEqual(stage_rows['src/platform.bundle']['sha256'], digest(candidate['stage_pins']['src/platform.bundle']['source']))
            stage_script = (output / 'assembly/stage-inputs/stage/rc2/stage-prep.py').read_text()
            ast.parse(stage_script)
            namespace = {}
            exec(stage_script, namespace)
            self.assertEqual(namespace['ids']['platform'][0], candidate['source_revision'])
            self.assertEqual(namespace['ids']['platform'][1], candidate['source_identity']['tree'])
            self.assertEqual(namespace['ids']['platform'][2], candidate['source_identity']['archive_sha256'])
            self.assertEqual(namespace['ids']['platform'][3], candidate['source_identity']['archive_bytes'])
            self.assertIn(candidate['source_revision'], stage_script)
            self.assertIn(candidate['source_identity']['tree'], stage_script)
            self.assertIn(candidate['source_identity']['archive_sha256'], stage_script)
            self.assertIn(str(candidate['source_identity']['archive_bytes']), stage_script)
            sums = (output / 'assembly/stage-inputs/STAGE-SHA256SUMS').read_text().splitlines()
            self.assertEqual(len(sums), 6)
            self.assertTrue((output / 'assembly/stage-inputs/stage/rust/rustup').is_file())
            self.assertTrue((output / 'assembly/stage-inputs/stage/rust/MEMBERS-1.95.0.json').is_file())
            self.assertTrue((output / 'assembly/stage-inputs/stage/rust/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc').is_file())
            self.assertTrue((output / 'assembly/stage-inputs/stage/src/kernel.bundle').is_file())
            self.assertEqual(result['stage_sha256'], digest(output / 'assembly/stage-inputs/STAGE-SHA256SUMS'))
            self.assertEqual(result['bindings_sha256'], digest(output / 'plan/bindings/BINDINGS.SHA256SUMS'))

    def test_undeclared_input_change_is_rejected_not_rehashed(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'input'
            source.mkdir()
            make_input(source)
            candidate = make_candidate(base)
            write(source / 'source/static.txt', 'unexpected replacement bytes\n')
            with self.assertRaisesRegex(ValueError, 'immutable payload input changed'):
                runner.materialize(candidate, source, base / 'output', NEW_RUN)
            self.assertFalse((base / 'output/PAYLOAD-DESCRIPTOR.json').exists())

    def test_actual_qemu_machine_helper_launches_negotiates_and_preserves_logs(self):
        runner = load_runner()
        qemu_python = Path(os.environ.get('ABSD_QEMU_PYTHON', 'dependencies/qemu-8.2.2/python'))
        if not (qemu_python / 'qemu/machine/machine.py').is_file():
            self.skipTest('set ABSD_QEMU_PYTHON to the pinned QEMU 8.2.2 Python tree to run this API test')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            args_path = base / 'argv.json'
            fake = base / 'fake-qemu.py'
            write(fake, '''#!/usr/bin/python3
import json, os, socket, sys
Path = None
with open(os.environ["FAKE_QEMU_ARGS"], "w") as out:
    json.dump(sys.argv, out)
chardev = next(item for item in sys.argv if item.startswith("socket,id=mon,path="))
path = chardev.split("path=", 1)[1]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)
sock.sendall(b'{"QMP":{"version":{"qemu":{"major":8,"minor":2,"micro":2},"package":"fixture"},"capabilities":[]}}\\n')
print("FAKE_QEMU_UP", flush=True)
buffer = b""
decoder = json.JSONDecoder()
while True:
    buffer += sock.recv(4096)
    if not buffer:
        raise SystemExit(2)
    try:
        text = buffer.decode()
        request, end = decoder.raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        continue
    buffer = text[end:].lstrip().encode()
    command = request.get("execute")
    print("FAKE_QEMU_COMMAND", command, flush=True)
    if command == "query-status":
        response = {"return": {"status": "running", "singlestep": False}}
    else:
        response = {"return": {}}
    sock.sendall(json.dumps(response).encode() + b"\\n")
    if command == "quit":
        raise SystemExit(0)
''')
            fake.chmod(0o755)
            previous = os.environ.get('FAKE_QEMU_ARGS')
            os.environ['FAKE_QEMU_ARGS'] = str(args_path)
            try:
                machine = runner.make_machine(str(fake), ['-machine', 'none', '-smp', '3'], base, qemu_python)
                machine.launch()
                self.assertTrue(machine.is_running())
                self.assertEqual(machine.qmp('query-status')['return']['status'], 'running')
                machine.shutdown()
            finally:
                if previous is None:
                    os.environ.pop('FAKE_QEMU_ARGS', None)
                else:
                    os.environ['FAKE_QEMU_ARGS'] = previous
            self.assertEqual(machine.exitcode(), 0)
            argv = json.loads(args_path.read_text())
            self.assertEqual(argv[-4:], ['-machine', 'none', '-smp', '3'])
            self.assertIn('FAKE_QEMU_UP', machine.get_log())
            self.assertTrue(any((base / 'logs').glob('*.log')))

    def test_production_launcher_identifies_real_qemu_behind_wrapper(self):
        import socket
        import time
        from unittest.mock import patch

        runner = load_runner()
        qemu_python = Path(os.environ.get('ABSD_QEMU_PYTHON', 'dependencies/qemu-8.2.2/python'))
        binary = shutil.which('qemu-system-x86_64')
        if not binary or not (qemu_python / 'qemu/machine/machine.py').is_file():
            self.skipTest('requires installed QEMU and pinned ABSD_QEMU_PYTHON')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            vm = base / 'vm'
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            write(vm / 'MATERIALIZATION.json', {'run': NEW_RUN})
            write(vm / 'STAGED.json', {
                'run': NEW_RUN, 'input_manifest_sha256': 'fixture-input',
                'materialization_sha256': digest(vm / 'MATERIALIZATION.json'),
            })
            write(vm / 'LAUNCH-BOUNDS.json', {
                'stage': 'APP_REPLACEMENT', 'ceiling_s': 14400,
                'host_unit_end_unix_s': time.time() + 60,
                'container_term_unix_s': time.time() + 60,
            })
            write(vm / 'bindings/host/OUTER-LAUNCH-TEMPLATE.json', {'qemu_argv': [
                binary, '-machine', 'none', '-nodefaults', '-S',
                '-netdev', 'user,id=control,hostfwd=tcp:127.0.0.1:<admitted-control-port>-10.199.97.15:22',
            ]})
            # Guest identity/SSH are beyond this process/QMP boundary test.
            write(vm / 'serial.log', 'ABSD_VM_IDENTITY ' + json.dumps({
                'run': NEW_RUN, 'input_manifest_sha256': 'fixture-input',
                'public_host_key': 'ssh-ed25519 fixture', 'host_fingerprint': '256 SHA256:fixture',
            }) + '\n')
            (vm / 'private-client').mkdir()
            executor = runner.StagedExecutor(vm, base / 'public', 'smoke_cat', port,
                                             qemu_python, 'fixture-revision')
            original = runner.make_machine
            machines = []

            def local_transport(binary, args, work, helper, wrapper=()):
                # Keep the actual emulator and Python helper. Replace only remote
                # podman transport with a local wrapper whose PID is not QEMU's.
                machine = original(binary, args, work, helper, wrapper=(
                    '/usr/bin/python3', '-c',
                    'import subprocess,sys; sys.exit(subprocess.call(sys.argv[1:]))',
                ))
                machines.append(machine)
                return machine

            def local_process_running(machine, pid):
                if pid is None:
                    return machine.is_running()
                stat = Path('/proc') / str(pid) / 'stat'
                return stat.exists() and stat.read_text().rsplit(')', 1)[1].split()[0] != 'Z'

            try:
                with patch.object(runner, 'make_machine', local_transport), \
                        patch.object(executor, 'qemu_process_running', local_process_running), \
                        patch.object(executor, 'execute', return_value=subprocess.CompletedProcess(
                            [], 0, b'256 SHA256:fixture\n', b'')):
                    try:
                        executor.launch()
                    except Exception as error:
                        self.fail('production launcher rejected real QEMU: ' + repr(error))
                self.assertEqual(len(machines), 2)
                self.assertEqual(machines[0].exitcode(), 0)
                self.assertNotEqual(executor.qemu_pid, executor.machine.get_pid())
                self.assertEqual((Path('/proc') / str(executor.qemu_pid) / 'exe').resolve(),
                                 Path(binary).resolve())
                self.assertEqual(executor.machine.cmd('query-status')['status'], 'running')
            finally:
                for machine in reversed(machines):
                    machine.shutdown(timeout=10)

    def test_first_guest_phase_mounts_and_verifies_input_media(self):
        # Removing the media setup leaves the phase executable absent. Only the
        # privileged mount and SSH transport are substituted; run the real shell,
        # digest consumers, and Python phase executable against a fresh tree.
        runner = load_runner()
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                media = base / 'media'
                mounted = base / 'input'
                marker = base / 'phase-ran'
                script = media / 'lifecycle/launch-app-phase.py'
                write(script, 'from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("ran")\n')
                write(media / 'INPUT-SHA256SUMS', digest(script) + '  lifecycle/launch-app-phase.py\n')
                manifest_sha = digest(media / 'INPUT-SHA256SUMS')
                if corrupt:
                    script.write_text('raise RuntimeError("corrupt media executed")\n')
                mount = base / 'bin/mount'
                write(mount, '#!/bin/sh\nset -eu\ntest "$1" = -o && test "$2" = ro\n'
                      'test "$3" = /dev/disk/by-label/ABSDINPUT\ncp -a ' + str(media) + '/. "$4"/\n')
                mount.chmod(0o755)
                executor = runner.StagedExecutor(base / 'vm', base / 'public', 'smoke_cat',
                                                 24131, base / 'helper', 'revision')
                executor.run_id = NEW_RUN
                executor.input_manifest_sha256 = manifest_sha
                executor.guest = {'argv': ['sh', '-c']}
                write(executor.occurrence / 'APP-PREPARE-ADMISSION.json', {})
                execute = executor.execute

                def local_guest(argv, **kwargs):
                    command = argv[-1].replace('/mnt/input', str(mounted))
                    command = 'PATH=' + str(base / 'bin') + ':"$PATH"; export PATH; ' + command
                    return execute(['sh', '-c', command], **kwargs)

                executor.execute = local_guest
                if corrupt:
                    with self.assertRaises(ValueError):
                        executor.guest_phase('inputs')
                    self.assertFalse(marker.exists())
                else:
                    executor.guest_phase('inputs')
                    self.assertEqual(marker.read_text(), 'ran')

    def test_failed_guest_phase_exports_real_subprocess_diagnostic(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            transport = base / 'transport.py'
            write(transport, 'import sys\ncommand=sys.argv[-1]\n'
                  'if "journalctl" in command: print("stage preparation failed: concrete diagnostic")\n'
                  'else: sys.exit(17)\n')
            executor = runner.StagedExecutor(base / 'vm', base / 'public', 'smoke_cat',
                                             24131, base / 'helper', 'revision')
            executor.run_id = NEW_RUN
            executor.guest = {'argv': [os.sys.executable, str(transport)]}
            write(executor.occurrence / 'APP-PREPARE-ADMISSION.json', {})
            with self.assertRaisesRegex(ValueError, 'command exited 17'):
                executor.guest_phase('d-net')
            self.assertIn('concrete diagnostic', (executor.public / 'logs/d-net-failure-journal.txt').read_text())
            write(transport, 'import sys\nsys.exit(19 if "journalctl" in sys.argv[-1] else 17)\n')
            with self.assertRaisesRegex(ValueError, 'command exited 17'):
                executor.guest_phase('d-units')
            self.assertIn('command exited 19', executor.diagnostic_error)
            del executor.guest
            write(executor.occurrence / 'private-client/client-ed25519', 'disposable fixture')
            self.assertEqual(executor.cleanup(), [])
            closeout = json.loads((executor.public / 'CLOSEOUT.json').read_text())
            self.assertIn('command exited 19', closeout['diagnostic_error'])

    def test_qemu_profile_binds_real_paths_and_removes_legacy_controllers(self):
        runner = load_runner()
        profile = {'qemu_argv': [
            '/usr/bin/qemu-system-x86_64', '-S', '-monitor', 'none',
            '-drive', 'file=<vm>/root.qcow2,format=qcow2',
            '-netdev', 'user,id=control,hostfwd=tcp:127.0.0.1:<admitted-control-port>-10.199.97.15:22',
            '-qmp', 'unix:<vm>/qmp.sock,server=on,wait=off',
            '-qmp', 'unix:<vm>/watch-qmp.sock,server=on,wait=off',
        ]}
        binary, args = runner.qemu_profile(profile, '/data/occurrence/vm', 24131)
        self.assertEqual(binary, '/usr/bin/qemu-system-x86_64')
        self.assertEqual(args, [
            '-S', '-drive', 'file=/data/occurrence/vm/root.qcow2,format=qcow2',
            '-netdev', 'user,id=control,hostfwd=tcp:127.0.0.1:24131-10.199.97.15:22',
        ])
        self.assertNotIn('-qmp', args)
        self.assertNotIn('-monitor', args)

    def test_guest_transport_keeps_stdin_open_and_binds_exact_port(self):
        runner = load_runner()
        guest = runner.guest_argv(NEW_RUN, '/data/occurrence/vm', 24131)
        self.assertTrue(guest['execution_go'])
        self.assertTrue(guest['strict_host_key'])
        self.assertEqual(guest['run'], NEW_RUN)
        self.assertNotIn('-n', guest['argv'])
        self.assertEqual(guest['argv'][guest['argv'].index('-p') + 1], '24131')
        self.assertEqual(guest['argv'][:3], ['podman', 'exec', '-i'])
        self.assertIn('-oBatchMode=yes', guest['argv'])
        self.assertIn('-oConnectTimeout=5', guest['argv'])

    def test_terminal_result_preserves_primary_and_cleanup_failures(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            result = runner.terminal_result(
                Path(directory),
                {'run': NEW_RUN, 'phase': 'launch', 'harness_revision': 'abc', 'source_revision': 'def'},
                error=ValueError('primary launch failure'),
                cleanup_errors=['evidence export failed'],
            )
            self.assertEqual(result['disposition'], 'INFRASTRUCTURE_INCOMPLETE')
            self.assertEqual(result['product_result'], 'NOT_RUN')
            self.assertEqual(result['failure_domain'], 'harness')
            self.assertEqual(result['first_diagnostic'], 'ValueError: primary launch failure')
            self.assertEqual(result['cleanup_errors'], ['evidence export failed'])
            self.assertEqual(json.loads((Path(directory) / 'RESULT.json').read_text()), result)
            with self.assertRaises(FileExistsError):
                runner.terminal_result(Path(directory), {'run': NEW_RUN})

    def test_clock_handoff_supplies_parent_for_fresh_proof_directory(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            executor = runner.StagedExecutor(base / 'vm', base / 'public', 'smoke_cat',
                                             24131, base / 'helper', 'revision')
            admission = base / 'admission.json'
            write(admission, {})
            # The real clock helper owns the fresh phase directory, and mkdir()
            # requires its caller to supply the parent. Exercise that filesystem
            # boundary in a subprocess without pretending to measure a clock.
            write(executor.occurrence / 'source/clock-app-handoff.py',
                  'import sys\nfrom pathlib import Path\n'
                  'out=Path(sys.argv[sys.argv.index("--output")+1])\n'
                  'out.mkdir(mode=0o700)\n(out/"observed").write_text("ready")\n')
            for mode in ('credentials', 'runtime'):
                executor.clock_handoff(mode, admission)
                self.assertEqual((executor.public / 'clock' / mode / 'observed').read_text(), 'ready')

    def test_export_directory_failure_does_not_skip_key_retirement(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            executor = runner.StagedExecutor(base / 'vm', base / 'public', 'smoke_cat',
                                             24131, base / 'helper', 'revision')
            executor.run_id = NEW_RUN
            executor.guest = {'argv': ['/bin/false']}
            write(executor.public / 'evidence', 'not a directory')
            key = executor.occurrence / 'private-client/client-ed25519'
            write(key, 'disposable fixture')
            errors = executor.cleanup()
            self.assertTrue(any('guest evidence export' in error for error in errors))
            self.assertFalse(key.exists())
            self.assertTrue((executor.public / 'CLOSEOUT.json').is_file())

    def test_preproduct_cleanup_preserves_public_guest_evidence(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            executor = runner.StagedExecutor(base / 'vm', base / 'public', 'smoke_cat',
                                             24131, base / 'helper', 'revision')
            executor.run_id = NEW_RUN
            executor.guest = {'argv': ['sh', '-c']}
            guest = base / 'guest'
            write(guest / 'public/clock-observation.json', {'diagnostic': 'failed before product'})
            write(executor.occurrence / 'private-client/client-ed25519', 'disposable fixture')
            original = executor.execute

            def local_guest(argv, **kwargs):
                if argv[:2] == ['sh', '-c']:
                    if argv[-1] == 'sync -f / /evidence':
                        return subprocess.CompletedProcess(argv, 0, b'', b'')
                    argv = [*argv[:2], argv[-1].replace('/root/absd-app-replacement/' + NEW_RUN, str(guest))]
                return original(argv, **kwargs)

            executor.execute = local_guest
            self.assertEqual(executor.cleanup(), [])
            with tarfile.open(executor.public / 'evidence/GUEST-EVIDENCE.tar') as archive:
                self.assertEqual(json.load(archive.extractfile('public/clock-observation.json')),
                                 {'diagnostic': 'failed before product'})

    def test_prepare_binding_preserves_original_lease_and_clock_budget(self):
        runner = load_runner()
        draft = {'run': NEW_RUN, 'source_revision': 'abc', 'aggregate_preparation_ceiling_s': 1100}
        bound = runner.prepare_admission(draft, 'input-sha', 'stage-sha', 24131, 20000, 1000)
        self.assertEqual(bound['outer_T10_unix_s'], 20000)
        self.assertEqual(bound['hard_end_unix_s'], 18200)
        self.assertEqual(bound['preparation_deadline_unix_s'], 2100)
        self.assertEqual(bound['input_manifest_sha256'], 'input-sha')
        self.assertEqual(bound['stage_sums_sha256'], 'stage-sha')
        self.assertEqual(bound['control_port'], 24131)
        self.assertTrue(bound['execution_go'])
        with self.assertRaisesRegex(ValueError, 'original lease'):
            runner.prepare_admission(draft, 'input-sha', 'stage-sha', 24131, 14000, 1000)

    def test_smoke_requires_exact_nested_output_and_explicit_nonqualification(self):
        runner = load_runner()
        output = b'ABSD App A harness smoke\n'
        result = {'disposition': 'SMOKE_PASS_NOT_QUALIFICATION',
                  'workload': {'output_sha256': hashlib.sha256(output).hexdigest()}}
        self.assertEqual(runner.require_smoke(output, result)['product_result'], 'SMOKE_PASS_NOT_QUALIFICATION')
        with self.assertRaisesRegex(ValueError, 'smoke output'):
            runner.require_smoke(b'not the nested workload\n', result)
        with self.assertRaisesRegex(ValueError, 'smoke disposition'):
            runner.require_smoke(output, {'disposition': 'PASS', 'workload': result['workload']})

    def test_evidence_archive_rejects_private_key_material(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            write(base / 'evidence/RESULT.json', {'disposition': 'NOT_RUN'})
            raw, rows = runner.evidence_archive(base)
            self.assertEqual(rows, [digest(base / 'evidence/RESULT.json') + '  evidence/RESULT.json'])
            self.assertTrue(raw)
            write(base / 'evidence/leak.txt', '-----BEGIN PRIVATE KEY-----\n')
            with self.assertRaisesRegex(ValueError, 'private key'):
                runner.evidence_archive(base)

    def make_executor(self, runner, base, mode):
        executor = runner.StagedExecutor(base / 'vm', base, mode, 24131, base / 'qemu-python', 'harness-revision')
        executor.run_id = NEW_RUN
        executor.launch = lambda: None
        executor.prepare = lambda: None
        executor.cleanup = lambda: []
        return executor

    def test_executor_preserves_genuine_product_failure(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            executor = self.make_executor(runner, Path(directory), 'app_a')
            executor.run_product = lambda: {'disposition': 'FAIL', 'failure_domain': 'product', 'error': 'actual App A assertion failed'}
            result = executor.run()
            self.assertEqual(result['disposition'], 'PRODUCT_FAIL')
            self.assertEqual(result['failure_domain'], 'product')
            self.assertEqual(result['product_result'], 'FAIL')
            self.assertEqual(result['first_diagnostic'], 'actual App A assertion failed')
            self.assertEqual(result['cleanup_state'], 'COMPLETE')

    def test_executor_preserves_smoke_failure_without_fetching_absent_output(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            executor = self.make_executor(runner, Path(directory), 'smoke_cat')
            product = {'disposition': 'FAIL', 'error': 'importer launch failed', 'workload': None}
            executor.wait_product_unit = lambda: None
            executor.remote_json = lambda path: product
            def unexpected_output(path):
                raise AssertionError('failed smoke has no CAT output')
            executor.remote_bytes = unexpected_output
            result = executor.run()
            self.assertEqual(result['product_result'], 'FAIL')
            self.assertEqual(result['disposition'], 'INFRASTRUCTURE_INCOMPLETE')
            self.assertIn('importer launch failed', result['first_diagnostic'])
            self.assertEqual(json.loads((Path(directory) / 'evidence/PRODUCT-RESULT.json').read_text()), product)

    def test_executor_smoke_success_is_not_qualification(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            executor = self.make_executor(runner, Path(directory), 'smoke_cat')
            payload = b'ABSD App A harness smoke\n'
            executor.product_output = payload
            executor.run_product = lambda: {'disposition': 'SMOKE_PASS_NOT_QUALIFICATION',
                                            'workload': {'output_sha256': hashlib.sha256(payload).hexdigest()}}
            result = executor.run()
            self.assertEqual(result['disposition'], 'SMOKE_SEQUENCE_COMPLETE_NOT_QUALIFICATION')
            self.assertEqual(result['product_result'], 'SMOKE_PASS_NOT_QUALIFICATION')
            self.assertIsNone(result['failure_domain'])

    def test_staging_ssh_only_closes_stdin_for_nonstreaming_commands(self):
        runner = load_runner()
        streamed = runner.staging_host_ssh_argv('tar -C /data/vm -xf -', streamed=True)
        plain = runner.staging_host_ssh_argv('true', streamed=False)
        self.assertNotIn('-n', streamed)
        self.assertIn('-n', plain)
        self.assertNotIn('ForwardAgent=yes', streamed)

    def test_materialize_cli_uses_explicit_candidate_input_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'input'
            source.mkdir()
            make_input(source)
            candidate = make_candidate(base)
            candidate_path = base / 'candidate.json'
            write(candidate_path, candidate)
            output = base / 'output'
            done = subprocess.run([
                os.fsencode(os.sys.executable), '-I', '-B', '-X', 'pycache_prefix=' + (os.sys.pycache_prefix or ''), os.fsencode(SCRIPT), '--materialize',
                '--candidate', os.fsencode(candidate_path), '--input-root', os.fsencode(source),
                '--output-root', os.fsencode(output), '--run', NEW_RUN,
            ], capture_output=True, timeout=30)
            self.assertEqual(done.returncode, 0, done.stderr.decode())
            receipt = json.loads(done.stdout)
            self.assertEqual(receipt['run'], NEW_RUN)
            self.assertTrue((output / 'MATERIALIZATION.json').is_file())

    def test_materialized_binding_seal_matches_every_real_consumer_file(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'input'
            source.mkdir()
            make_input(source)
            candidate = make_candidate(base)
            runner.materialize(candidate, source, base / 'output', NEW_RUN)
            seal = base / 'output/plan/bindings/BINDINGS.SHA256SUMS'
            rows = seal.read_text().splitlines()
            self.assertTrue(rows)
            for row in rows:
                expected, relative = row.split('  ', 1)
                self.assertEqual(digest(base / 'output/plan' / relative), expected)

    def test_remote_staging_uses_actual_input_manifest_receipt(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stager = runner.RemoteStager(base, NEW_RUN, base / 'qemu-python', 'harness-revision')
            write(base / 'plan/bindings/host/s1-stage.sh', '# fixture media producer\n')
            write(base / 'MATERIALIZATION.json', {'stage_sha256': 'stage-sha'})
            calls = []

            def remote(command, data=None, timeout=7200):
                calls.append(command)
                output = 'INPUT_SHA256SUMS actual-input-sha\nINPUT_ISO actual-iso-sha\n' if ' input-tree' in command else ''
                return subprocess.CompletedProcess(command, 0, output.encode(), b'')

            stager.remote = remote
            stager.stream_tree = lambda *args, **kwargs: None
            stager.send = lambda *args, **kwargs: None
            stager.payload_archive = lambda: base / 'payload.tar'
            stager.check_capacity = lambda: {'/': [100000000000, 1000000], '/data': [100000000000, 1000000]}
            result = stager.stage()
            self.assertEqual(result['input_manifest_sha256'], 'actual-input-sha')
            self.assertEqual(result['input_iso_sha256'], 'actual-iso-sha')
            self.assertEqual(result['run'], NEW_RUN)
            self.assertIn('pre-launch', calls[-1])

    def test_failed_product_unit_is_read_as_product_failure(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            executor = self.make_executor(runner, Path(directory), 'app_a')
            executor.runtime = {'unit': 'product.service', 'producer_runtime_max_s': 100}
            executor.guest = {'argv': ['guest-ssh']}
            product = {'disposition': 'FAIL', 'failure_domain': 'product', 'error': 'native assertion failed'}

            def execute(argv, data=None, timeout=7200):
                command = argv[-1]
                if command.startswith('systemctl show product.service'):
                    output = ('Id=product.service\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\n'
                              'ActiveState=failed\nSubState=failed\nInvocationID=original\nMainPID=0\n')
                    return subprocess.CompletedProcess(argv, 0, output.encode(), b'')
                if command == 'cat /root/absd-app-replacement/' + NEW_RUN + '/evidence/RESULT.json':
                    return subprocess.CompletedProcess(argv, 0, json.dumps(product).encode(), b'')
                raise AssertionError(argv)

            executor.execute = execute
            result = executor.run()
            self.assertEqual(result['disposition'], 'PRODUCT_FAIL')
            self.assertEqual(result['failure_domain'], 'product')
            self.assertEqual(result['product_result'], 'FAIL')

    def test_product_unit_terminal_without_invocation_is_read(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            executor = self.make_executor(runner, Path(directory), 'app_a')
            executor.runtime = {'unit': 'product.service', 'producer_runtime_max_s': 100}
            executor.guest = {'argv': ['guest-ssh']}
            product = {'disposition': 'FAIL', 'failure_domain': 'product', 'error': 'native assertion failed'}

            def execute(argv, data=None, timeout=7200):
                command = argv[-1]
                if command.startswith('systemctl show product.service'):
                    output = ('Id=product.service\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\n'
                              'ActiveState=failed\nSubState=failed\nInvocationID=\nMainPID=0\n')
                    return subprocess.CompletedProcess(argv, 0, output.encode(), b'')
                if command == 'cat /root/absd-app-replacement/' + NEW_RUN + '/evidence/RESULT.json':
                    return subprocess.CompletedProcess(argv, 0, json.dumps(product).encode(), b'')
                raise AssertionError(argv)

            executor.execute = execute
            self.assertEqual(executor.run_product(), product)

    def test_product_failure_and_outer_cleanup_failure_keep_product_domain(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            executor = self.make_executor(runner, Path(directory), 'app_a')
            executor.run_product = lambda: {'disposition': 'FAIL', 'failure_domain': 'product', 'error': 'native assertion failed'}
            executor.cleanup = lambda: ['overlay cleanup failed']
            result = executor.run()
            self.assertEqual(result['disposition'], 'PRODUCT_FAIL')
            self.assertEqual(result['failure_domain'], 'product')
            self.assertEqual(result['first_diagnostic'], 'native assertion failed')
            self.assertEqual(result['cleanup_state'], 'INCOMPLETE')

    def test_product_failure_remains_product_when_native_cleanup_fails(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            executor = self.make_executor(runner, Path(directory), 'app_a')
            executor.run_product = lambda: {'disposition': 'FAIL', 'failure_domain': 'product',
                                            'error': 'native assertion failed',
                                            'cleanup_errors': ['driver evidence cleanup failed']}
            executor.cleanup = lambda: ['outer overlay cleanup failed']
            result = executor.run()
            self.assertEqual(result['disposition'], 'PRODUCT_FAIL')
            self.assertEqual(result['failure_domain'], 'product')
            self.assertEqual(result['product_result'], 'FAIL')
            self.assertEqual(result['first_diagnostic'], 'native assertion failed')
            self.assertEqual(result['cleanup_state'], 'INCOMPLETE')
            self.assertEqual(result['cleanup_errors'], ['driver evidence cleanup failed', 'outer overlay cleanup failed'])

    def test_product_receipt_domain_drives_outer_classification(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            executor = self.make_executor(runner, Path(directory), 'app_a')
            executor.run_product = lambda: {'disposition': 'FAIL', 'failure_domain': 'infrastructure',
                                            'error': 'nested QEMU readiness failed'}
            result = executor.run()
            self.assertEqual(result['disposition'], 'INFRASTRUCTURE_INCOMPLETE')
            self.assertEqual(result['failure_domain'], 'harness')
            self.assertEqual(result['product_result'], 'FAIL')
            executor = self.make_executor(runner, Path(directory) / 'second', 'app_a')
            executor.run_product = lambda: {'disposition': 'FAIL', 'failure_domain': 'product',
                                            'error': 'App A body differs'}
            result = executor.run()
            self.assertEqual(result['disposition'], 'PRODUCT_FAIL')
            self.assertEqual(result['failure_domain'], 'product')

    def test_unknown_qemu_pid_is_not_proof_of_exit(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            executor = self.make_executor(runner, Path(directory), 'app_a')

            class Machine:
                def is_running(self):
                    return False
                def shutdown(self, **kwargs):
                    pass

            stopped, errors = executor.stop_machine(Machine(), None)
            self.assertFalse(stopped)
            self.assertTrue(errors)

    def test_zombie_qemu_process_is_not_running(self):
        runner = load_runner()
        executor = self.make_executor(runner, Path('/tmp/unused'), 'app_a')

        def command(argv, **kwargs):
            if argv[-2] == '-0':
                return subprocess.CompletedProcess(argv, 0, b'', b'')
            if argv[-1] == 'stat=':
                return subprocess.CompletedProcess(argv, 0, b'Z\n', b'')
            raise AssertionError(argv)

        original = runner.subprocess.run
        runner.subprocess.run = command
        try:
            self.assertFalse(executor.qemu_process_running(object(), 123))
            command = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, b'S\n', b'') if argv[-1] == 'stat=' else subprocess.CompletedProcess(argv, 0, b'', b'')
            runner.subprocess.run = command
            self.assertTrue(executor.qemu_process_running(object(), 123))
        finally:
            runner.subprocess.run = original

    def test_outer_unit_terminal_without_invocation_is_accepted(self):
        runner = load_runner()
        stager = runner.RemoteStager(Path('/tmp/unused'), NEW_RUN, Path('/tmp/qemu'), 'harness')
        output = ('Id=unit.service\nResult=success\nExecMainCode=0\nExecMainStatus=0\n'
                  'ActiveState=inactive\nSubState=dead\nInvocationID=\nMainPID=0\n')
        stager.remote = lambda command, **kwargs: subprocess.CompletedProcess(command, 0, output.encode(), b'')
        props = runner.wait_outer_unit(stager, 'unit.service', 1)
        self.assertEqual(props['ActiveState'], 'inactive')

    def test_success_with_cleanup_failure_is_infrastructure_incomplete(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            executor = self.make_executor(runner, Path(directory), 'smoke_cat')
            payload = b'ABSD App A harness smoke\n'
            executor.product_output = payload
            executor.run_product = lambda: {'disposition': 'SMOKE_PASS_NOT_QUALIFICATION',
                                            'workload': {'output_sha256': hashlib.sha256(payload).hexdigest()}}
            executor.cleanup = lambda: ['overlay cleanup failed']
            result = executor.run()
            self.assertEqual(result['disposition'], 'INFRASTRUCTURE_INCOMPLETE')
            self.assertEqual(result['failure_domain'], 'harness')
            self.assertEqual(result['product_result'], 'SMOKE_PASS_NOT_QUALIFICATION')

    def test_retrieve_result_uses_production_tar_layout_and_writes_local_result(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stager = runner.RemoteStager(base, NEW_RUN, base / 'qemu-python', 'harness-revision')
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode='w') as archive:
                body = json.dumps({'disposition': 'SMOKE_SEQUENCE_COMPLETE_NOT_QUALIFICATION'}).encode()
                info = tarfile.TarInfo('public/RESULT.json')
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            stager.remote = lambda command, **kwargs: subprocess.CompletedProcess(
                command, 0, raw.getvalue() if command.startswith('tar ') else b'serial bytes', b'')
            result = runner.retrieve_execution_result(stager, base)
            self.assertEqual(result['disposition'], 'SMOKE_SEQUENCE_COMPLETE_NOT_QUALIFICATION')
            self.assertTrue((base / 'RESULT.json').is_file())
            self.assertEqual((base / 'logs/serial.log').read_bytes(), b'serial bytes')
            self.assertIn('public_archive_sha256', result['local_evidence'])

    def test_cleanup_flushes_guest_filesystems_before_quit_and_retains_on_failure(self):
        runner = load_runner()
        for fails in (False, True):
            with self.subTest(fails=fails), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                executor = self.make_executor(runner, base, 'smoke_cat')
                executor.guest = {'argv': ['guest-ssh']}
                executor.product_result = 'SMOKE_PASS_NOT_QUALIFICATION'
                write(base / 'vm/root.qcow2', 'overlay')
                write(base / 'vm/base.img', 'backing')
                write(base / 'vm/private-client/client-ed25519', 'disposable fixture')
                write(base / 'vm/CONFIG.TEMPLATE.NO-GO.json', {'custodian': 'owner', 'retirement_condition': 'dependency closure'})
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode='w'): pass
                events = []
                execute = executor.execute
                def guest(argv, **kwargs):
                    if argv[0] != 'guest-ssh': return execute(argv, **kwargs)
                    if argv[-1] == 'sync -f / /evidence':
                        events.append('sync')
                        if fails: raise TimeoutError('guest sync timeout')
                        return subprocess.CompletedProcess(argv, 0, b'', b'')
                    return subprocess.CompletedProcess(argv, 0, raw.getvalue(), b'')
                executor.execute = guest
                class Machine:
                    def exitcode(self): return 0
                executor.machine = Machine()
                executor.stop_machine = lambda machine, pid: (events.append('quit') is None, [])
                errors = runner.StagedExecutor.cleanup(executor)
                self.assertEqual(events, ['sync', 'quit'])
                self.assertEqual(bool(errors), fails)
                self.assertEqual((base / 'vm/root.qcow2').exists(), fails)
                closeout = json.loads((base / 'CLOSEOUT.json').read_text())
                self.assertEqual(closeout['guest_filesystems_synced'], not fails)

    def test_app_a_cleanup_retains_stopped_overlay_and_backing_dependency(self):
        runner = load_runner()
        for mode, passed in (('app_a', False), ('smoke_cat', True), ('smoke_cat', False)):
            with self.subTest(mode=mode, passed=passed), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                executor = self.make_executor(runner, base, mode)
                if passed:
                    executor.product_result = 'SMOKE_PASS_NOT_QUALIFICATION'
                write(base / 'vm/root.qcow2', 'private App A images and point')
                write(base / 'vm/base.img', 'backing dependency')
                write(base / 'vm/private-client/client-ed25519', 'disposable transport key')
                write(base / 'vm/CONFIG.TEMPLATE.NO-GO.json', {
                    'custodian': 'named lane owner', 'retirement_condition': 'retain until dependency disposition'})
                class Machine:
                    def exitcode(self): return 0
                executor.machine = Machine()
                stops = []
                executor.stop_machine = lambda machine, pid: (stops.append(machine) is None, [])
                self.assertEqual(runner.StagedExecutor.cleanup(executor), [])
                self.assertEqual(stops, [executor.machine])
                self.assertEqual((base / 'vm/root.qcow2').exists(), mode == 'app_a' or not passed)
                self.assertTrue((base / 'vm/base.img').exists())
                self.assertFalse((base / 'vm/private-client/client-ed25519').exists())
                closeout = json.loads((base / 'CLOSEOUT.json').read_text())
                if mode == 'app_a' or not passed:
                    custody = closeout['private_artifact_custody']
                    self.assertEqual(custody['overlay'], str(base / 'vm/root.qcow2'))
                    self.assertEqual(custody['backing_image'], str(base / 'vm/base.img'))
                    self.assertEqual(custody['custodian'], 'named lane owner')
                    self.assertEqual(custody['retirement_condition'], 'retain until dependency disposition')
                    self.assertTrue(custody['retained'])

    def test_cleanup_retains_overlay_until_qemu_exit_is_proven(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            executor = self.make_executor(runner, base, 'app_a')
            executor.qemu_pid = 123
            write(base / 'vm/root.qcow2', 'overlay')

            class Machine:
                def shutdown(self, **kwargs):
                    if not kwargs.get('hard'):
                        raise RuntimeError('QMP unavailable')
                def exitcode(self):
                    return None

            executor.machine = Machine()
            calls = []

            def execute(argv, data=None, timeout=7200):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, b'', b'')

            executor.execute = execute
            executor.qemu_process_running = lambda machine, pid: True
            executor.cleanup = lambda: runner.StagedExecutor.cleanup(executor)
            errors = executor.cleanup()
            self.assertTrue(errors)
            self.assertTrue((base / 'vm/root.qcow2').is_file())
            self.assertFalse(any(argv[0] == 'rm' for argv in calls))
            self.assertTrue((base / 'CLOSEOUT.json').is_file())

    def test_dispatch_failure_recovers_public_evidence_and_names_remote_root(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stager = runner.RemoteStager(base, NEW_RUN, base / 'qemu-python', 'harness-revision')
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode='w') as archive:
                body = b'{}\n'
                info = tarfile.TarInfo('public/PRODUCER.log')
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            stager.remote = lambda command, **kwargs: subprocess.CompletedProcess(
                command, 0, raw.getvalue() if command.startswith('tar ') else b'serial failure', b'')
            result = runner.dispatch_failure(stager, base, NEW_RUN, 'harness-revision', ValueError('controller died'))
            self.assertEqual(result['disposition'], 'INFRASTRUCTURE_INCOMPLETE')
            self.assertEqual(result['remote_staging_retained_for_custody'], stager.root)
            self.assertTrue((base / 'REMOTE-PUBLIC.tar').is_file())
            self.assertEqual((base / 'logs/serial.log').read_bytes(), b'serial failure')

    def test_real_remote_missing_serial_preserves_primary_error(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stager = runner.RemoteStager(base, NEW_RUN, base / 'qemu-python', 'harness-revision')
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode='w') as archive:
                body = b'{}\n'
                info = tarfile.TarInfo('public/RESULT.json')
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))

            def command(argv, **kwargs):
                remote = argv[-1]
                if remote.startswith('tar '):
                    return subprocess.CompletedProcess(argv, 0, raw.getvalue(), b'')
                if remote.startswith('test -f '):
                    return subprocess.CompletedProcess(argv, 1, b'', b'')
                raise AssertionError(argv)

            original = runner.subprocess.run
            runner.subprocess.run = command
            try:
                result = runner.dispatch_failure(stager, base, NEW_RUN, 'harness-revision', ValueError('probe cleanup failed'))
            finally:
                runner.subprocess.run = original
            self.assertIn('probe cleanup failed', result['first_diagnostic'])
            self.assertEqual(result['cleanup_errors'], [])
            self.assertIsNone(result['serial_log'])
            stager.remote = lambda *args, **kwargs: subprocess.CompletedProcess([], 2, b'', b'permission denied')
            with self.assertRaisesRegex(ValueError, 'serial probe failed'):
                runner.retrieve_serial(stager, base)

    def test_dispatch_failure_reuses_existing_public_export(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stager = runner.RemoteStager(base, NEW_RUN, base / 'qemu-python', 'harness-revision')
            write(base / 'remote-public/public/RESULT.json', {})
            write(base / 'REMOTE-PUBLIC.tar', 'existing archive')
            stager.remote = lambda command, **kwargs: subprocess.CompletedProcess(command, 1, b'', b'')
            result = runner.dispatch_failure(stager, base, NEW_RUN, 'harness-revision', ValueError('result decoding failed'))
            self.assertIn('result decoding failed', result['first_diagnostic'])
            self.assertEqual(result['cleanup_errors'], [])
            self.assertEqual((base / 'REMOTE-PUBLIC.tar').read_bytes(), b'existing archive')

    def test_probe_cleanup_does_not_mask_launch_failure(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            executor = runner.StagedExecutor(base / 'vm', base, 'smoke_cat', 24131, base / 'qemu-python', 'harness-revision')
            executor.run_id = NEW_RUN
            write(base / 'vm/MATERIALIZATION.json', {'run': NEW_RUN})
            write(base / 'vm/STAGED.json', {'run': NEW_RUN, 'input_manifest_sha256': 'input',
                                            'materialization_sha256': digest(base / 'vm/MATERIALIZATION.json')})
            write(base / 'vm/LAUNCH-BOUNDS.json', {'stage': 'APP_REPLACEMENT', 'ceiling_s': 14400,
                                                   'host_unit_end_unix_s': 4102444800, 'container_term_unix_s': 4102444800})
            write(base / 'vm/bindings/host/OUTER-LAUNCH-TEMPLATE.json', {
                'qemu_argv': ['qemu', '-netdev', 'user,id=control,hostfwd=tcp:127.0.0.1:<admitted-control-port>-10.199.97.15:22'],
            })

            class Probe:
                def launch(self):
                    raise ValueError('probe launch failed')
                def is_running(self):
                    return True

            original = runner.make_machine
            runner.make_machine = lambda *args, **kwargs: Probe()
            executor.qemu_process_running = lambda machine, pid: True
            executor.stop_machine = lambda machine, pid: (False, ['probe cleanup failed'])
            try:
                with self.assertRaisesRegex(ValueError, '^probe launch failed$'):
                    executor.launch()
            finally:
                runner.make_machine = original
            receipt = json.loads((base / 'logs/QEMU-HELPER-PROBE.json').read_text())
            self.assertEqual(receipt['error'], 'probe launch failed')
            self.assertEqual(receipt['cleanup_errors'], ['probe cleanup failed'])

    def test_remaining_deadline_uses_absolute_bounds(self):
        runner = load_runner()
        bounds = {'host_unit_end_unix_s': 1100}
        self.assertEqual(runner.remaining_seconds(bounds, 1000), 100)
        with self.assertRaisesRegex(ValueError, 'deadline'):
            runner.remaining_seconds(bounds, 1101)

    def test_harness_inputs_are_sealed_independently_of_product_revision(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / 'harness'
            scripts = repo / 'scripts'
            write(scripts / 'app-a-vm-runner.py', 'harness source\n')
            write(scripts / 'served_ram.py', 'memory policy\n')
            git(repo, 'init', '-q')
            git(repo, 'add', '.')
            git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture')
            revision = git(repo, 'rev-parse', 'HEAD').decode().strip()
            runner.HERE = scripts
            helper = base / 'qemu-python'
            write(helper / 'qemu/machine/machine.py', 'machine helper\n')
            write(helper / 'qemu/qmp/legacy.py', 'qmp helper\n')
            output = base / 'output'
            write(output / 'MATERIALIZATION.json', {'run': NEW_RUN, 'source_revision': 'frozen-product'})
            manifest = runner.seal_harness_inputs(output, helper, revision)
            self.assertEqual(len(manifest['members']), 4)
            self.assertEqual(manifest['harness_revision'], revision)
            self.assertEqual(manifest['qemu_binary']['sha256'], digest('/usr/bin/qemu-system-x86_64'))
            materialization = json.loads((output / 'MATERIALIZATION.json').read_text())
            self.assertEqual(materialization['source_revision'], 'frozen-product')
            self.assertEqual(materialization['harness_inputs_sha256'], digest(output / 'HARNESS-INPUTS.json'))
            with self.assertRaisesRegex(ValueError, 'harness revision'):
                runner.seal_harness_inputs(output, helper, 'different-revision')
            write(scripts / 'app-a-vm-runner.py', 'uncommitted edit\n')
            with self.assertRaisesRegex(ValueError, 'harness.*clean'):
                runner.seal_harness_inputs(output, helper, revision)

    def test_admission_binds_exact_materialization_and_fresh_resources(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            write(base / 'MATERIALIZATION.json', {'run': NEW_RUN})
            write(base / 'STAGED.json', {'run': NEW_RUN, 'materialization_sha256': digest(base / 'MATERIALIZATION.json'),
                                        'control_port': 24131, 'harness_inputs_sha256': 'harness-sha'})
            admission = {
                'go': True, 'run': NEW_RUN, 'materialization_sha256': digest(base / 'MATERIALIZATION.json'),
                'control_port': 24131, 'staged_sha256': digest(base / 'STAGED.json'),
                'harness_inputs_sha256': 'harness-sha',
                'not_before_unix_s': 900, 'latest_planned_launch_unix_s': 1100,
                'full_outer_window_s': 14400, 'sample_unix_s': 999,
                'staging_host': {
                    'qemu_absent': True, 'host_listen_ports': [],
                    'capacity': {'/': {'free_bytes': 100000000000, 'free_inodes': 1000000},
                                 '/data': {'free_bytes': 100000000000, 'free_inodes': 1000000}},
                    'memory': {'MemAvailable': 30000000000}, 'load': [1, 1, 1],
                },
            }
            self.assertEqual(runner.validate_admission(admission, base, NEW_RUN, 24131, now=1000)['run'], NEW_RUN)
            staged = json.loads((base / 'STAGED.json').read_text())
            staged['control_port'] = 9999
            write(base / 'STAGED.json', staged)
            admission['staged_sha256'] = digest(base / 'STAGED.json')
            with self.assertRaisesRegex(ValueError, 'staged control port'):
                runner.validate_admission(admission, base, NEW_RUN, 24131, now=1000)
            staged['control_port'] = 24131
            staged['materialization_sha256'] = '0' * 64
            write(base / 'STAGED.json', staged)
            admission['staged_sha256'] = digest(base / 'STAGED.json')
            with self.assertRaisesRegex(ValueError, 'staged materialization'):
                runner.validate_admission(admission, base, NEW_RUN, 24131, now=1000)
            write(base / 'STAGED.json', {'run': NEW_RUN, 'materialization_sha256': digest(base / 'MATERIALIZATION.json'),
                                        'control_port': 24131, 'harness_inputs_sha256': 'harness-sha'})
            admission['staged_sha256'] = digest(base / 'STAGED.json')
            with self.assertRaisesRegex(ValueError, 'authorize'):
                runner.validate_admission(admission, base, '33333333-3333-4333-8333-333333333333', 24131, now=1000)
            write(base / 'MATERIALIZATION.json', {'run': NEW_RUN, 'changed': True})
            with self.assertRaisesRegex(ValueError, 'materialization'):
                runner.validate_admission(admission, base, NEW_RUN, 24131, now=1000)
            write(base / 'MATERIALIZATION.json', {'run': NEW_RUN})
            with self.assertRaisesRegex(ValueError, 'launch window'):
                runner.validate_admission(admission, base, NEW_RUN, 24131, now=1200)

    def test_build_mode_is_offline_only_and_cannot_execute(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'input'
            source.mkdir()
            make_input(source)
            candidate = make_candidate(base)
            candidate['harness_mode'] = 'build'
            for name in ('release_manifest_destination', 'wrong_manifest_destination', 'app_build_receipt_destination'):
                candidate.pop(name, None)
            candidate['payload_pins'] = {}
            result = runner.materialize(candidate, source, base / 'output', NEW_RUN)
            self.assertEqual(result['run'], NEW_RUN)
            with self.assertRaisesRegex(ValueError, 'harness mode'):
                runner.execute_occurrence(candidate, source, base / 'execute', NEW_RUN, base / 'admission.json',
                                          24131, base / 'qemu-python', candidate['source_revision'])

    def test_release_manifest_must_match_exact_candidate_source(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'input'
            source.mkdir()
            make_input(source)
            candidate = make_candidate(base)
            manifest = base / 'release-manifest.toml'
            write(manifest, '[source]\nplatform_commit = "' + '0' * 40 + '"\nkernel_commit = "' + KERNEL + '"\nplatform_tree_clean = true\nkernel_tree_clean = true\n')
            destination = 'lifecycle/release-B/release-manifest.toml'
            descriptor = json.loads((source / 'PAYLOAD-DESCRIPTOR.json').read_text())
            descriptor['files'].append({'source': str(source / 'source/static.txt'), 'destination': destination,
                                        'bytes': 1, 'sha256': '0' * 64})
            write(source / 'PAYLOAD-DESCRIPTOR.json', descriptor)
            candidate['release_manifest_destination'] = destination
            candidate['payload_pins'][destination] = {
                'source': str(manifest), 'bytes': manifest.stat().st_size, 'sha256': digest(manifest),
            }
            with self.assertRaisesRegex(ValueError, 'release source differs'):
                runner.materialize(candidate, source, base / 'output', NEW_RUN)
            self.assertFalse((base / 'output/MATERIALIZATION.json').exists())


if __name__ == '__main__':
    unittest.main()
