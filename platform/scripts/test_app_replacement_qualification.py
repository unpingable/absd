#!/usr/bin/env python3
"""Bounded controls for new App A scenario decisions; no guest or compiler."""
import copy
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('app_replacement_qualification', Path(__file__).with_name('app-replacement-qualification.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Process:
    def __init__(self, status=None, final=-signal.SIGKILL):
        self.status, self.final, self.kills = status, final, 0
    def poll(self): return self.status
    def kill(self): self.kills += 1; self.status = self.final
    def wait(self, timeout): return self.status


class Decisions(unittest.TestCase):
    def pair(self):
        a = {'source': {'platform_commit': 'a' * 40, 'kernel_commit': 'c' * 40,
                        'platform_tree_clean': True, 'kernel_tree_clean': True},
             'identity': dict(m.rel.IDENTITY), 'release': {'id': 'release-a'}, 'build': {'https_document': {'enabled': True}},
             'artifacts': {'files': {'tree/bin/https-document': {'sha256': 'd' * 64}, m.rel.ISO: {'sha256': 'e' * 64}}}}
        b = copy.deepcopy(a)
        b['source']['platform_commit'] = 'b' * 40
        b['release']['id'] = 'release-b'
        b['artifacts']['files'][m.rel.ISO]['sha256'] = 'f' * 64
        return a, b

    def test_distinct_actual_source_and_enabled_application_required(self):
        a, b = self.pair()
        m.require_pair(a, b, 'a' * 40, 'b' * 40, 'c' * 40)
        for field in ('source', 'application', 'same-iso', 'dirty'):
            bad = copy.deepcopy(a)
            if field == 'source': bad['source']['platform_commit'] = 'f' * 40
            elif field == 'application': del bad['artifacts']['files']['tree/bin/https-document']
            elif field == 'same-iso': bad['artifacts']['files'][m.rel.ISO] = b['artifacts']['files'][m.rel.ISO]
            else: bad['source']['platform_tree_clean'] = False
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.require_pair(bad, b, 'a' * 40, 'b' * 40, 'c' * 40)

    def test_real_private_ancestry_and_fixed_A_receipt_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()
            git('init', '-q'); git('config', 'user.name', 'Fixture'); git('config', 'user.email', 'fixture@example.invalid')
            def commit(name):
                (repo / 'state').write_text(name); git('add', 'state'); git('commit', '-qm', name)
                return git('rev-parse', 'HEAD')
            a = commit('A'); b = commit('B'); later = commit('later')
            git('checkout', '--orphan', 'unrelated'); git('rm', '-qf', 'state'); unrelated = commit('unrelated')
            receipt = repo / 'ancestry.json'
            def entry(earlier, selected):
                receipt.write_text(json.dumps({'schema': 'p2-source-ancestry/1', 'A': earlier, 'B': selected,
                                              'command': 'git merge-base --is-ancestor', 'exit_code': 0}))
                return {'path': str(receipt), 'sha256': m.sha(receipt.read_bytes())}
            with patch.object(m, 'P2_A', a):
                pin = entry(a, b)
                self.assertEqual(m.require_ancestry(repo, pin, b, a), receipt.read_bytes())
                for wrong in (later, unrelated, b):
                    with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, 'fixed P2 A'):
                        m.require_ancestry(repo, entry(wrong, b), b, wrong)
                with self.assertRaisesRegex(ValueError, 'not an ancestor'):
                    m.require_ancestry(repo, entry(a, unrelated), unrelated, a)
                with self.assertRaisesRegex(ValueError, 'ancestry evidence'):
                    m.require_ancestry(repo, entry(a, later), b, a)
                with self.assertRaisesRegex(ValueError, 'changed'):
                    m.require_ancestry(repo, dict(pin, sha256='0' * 64), b, a)

    def test_public_monorepo_refuses_generic_clone_before_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / 'public'; repo.mkdir()
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            (repo / 'kernel').mkdir(); (repo / 'kernel/source').write_text('curated bytes')
            (repo / 'SOURCE-MANIFEST.json').write_text('{}')
            subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit', '-qm', 'curated public snapshot'], check=True)
            upstream = '1' * 40
            self.assertNotEqual(subprocess.run(['git', '-C', str(repo), 'cat-file', '-e', upstream],
                                              capture_output=True).returncode, 0)
            manifest = Path(tmp) / 'release.toml'
            manifest.write_text('schema="absd-release-manifest/2"\n[source]\nkernel_commit="' + upstream
                                + '"\nkernel_repository="' + str(repo) + '"\n[source.kernel_snapshot]\nkind="public"\n')
            output = Path(tmp) / 'must-not-exist'
            result = subprocess.run(['sh', str(m.HERE / 'reconstruct-release.sh'), '--workdir', str(output), str(manifest)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('tools/rebuild-release.sh', result.stderr)
            self.assertFalse(output.exists())
            self.assertNotIn('toolchain', result.stdout)
            doc = (m.ROOT / 'docs/RELEASE.md').read_text()
            self.assertIn('tools/rebuild-release.sh', doc)

    def test_point_pin_comes_from_one_success_report_not_later_backup_contents(self):
        line = b'RECOVERY POINT SHA256 ' + b'a' * 64 + b' selected=release-a\n'
        self.assertEqual(m.reported_point_pin(line, 'release-a'), 'a' * 64)
        for report in (b'', line + line, line.replace(b'release-a', b'release-b')):
            with self.assertRaises(ValueError): m.reported_point_pin(report, 'release-a')

    def receipt(self):
        return ('absd-https-document/1\npeer=192.0.2.1:8443\nname=document.example\npath=/document.bin?edition=1\n'
                + 'issuer_spki=' + 'c' * 64 + '\nboot=' + 'a' * 32 + '\nverified_utc_ms=10000,10002\n'
                + 'publication_check_utc_ms=10001,10003\nbody_bytes=16384\nbody_sha256=' + m.sha(m.BODY) + '\n').encode()

    def check_bundle(self, body=None, receipt=None):
        return m.require_bundle(m.BODY if body is None else body, self.receipt() if receipt is None else receipt,
                                boot='a' * 32, issuer='c' * 64, anchor={'utc_ms': 10000, 'uncertainty_ms': 1})

    def test_actual_maximum_body_and_receipt_correspondence(self):
        self.assertEqual(self.check_bundle()['body_bytes'], '16384')
        with self.assertRaisesRegex(ValueError, 'body readback'):
            self.check_bundle(body=m.BODY[:-1])
        with self.assertRaises(ValueError):
            self.check_bundle(receipt=self.receipt() + b'body_bytes=16384\n')
        with self.assertRaises(ValueError):
            self.check_bundle(receipt=self.receipt().replace(b'body_bytes=16384', b'body_bytes=16385'))

    def test_old_boot_wrong_configuration_and_earlier_attestation_rejected(self):
        for changed in (self.receipt().replace(('boot=' + 'a' * 32).encode(), ('boot=' + 'b' * 32).encode()),
                        self.receipt().replace(b'name=document.example', b'name=other.example'),
                        self.receipt().replace(b'10000,10002', b'1,2')):
            with self.assertRaises(ValueError): self.check_bundle(receipt=changed)

    def test_prior_fault_or_reset_is_not_converted_to_deliberate_stop(self):
        m.require_live_boot(b'ABSD KERNEL BOOT\nSSH LISTENING\n')
        for raw in (b'ABSD KERNEL BOOT\nKERNEL FAULT\n', b'ABSD KERNEL BOOT\nMACHINE RECOVER RESET\n',
                    b'ABSD KERNEL BOOT\nABSD KERNEL BOOT\n'):
            with self.assertRaises(ValueError): m.require_live_boot(raw)

    def test_unclean_stop_needs_live_observed_held_request(self):
        row = {'held': True, 'held_monotonic_ns': 1}
        selected, other, client = Process(), Process(), Process()
        m.unclean_stop(selected, row, client)
        self.assertEqual(selected.kills, 1)
        self.assertEqual(other.kills, 0)
        for changed, qemu, ssh in (({}, Process(), Process()),
                                    (dict(row, ended=True), Process(), Process()),
                                    (row, Process(status=3), Process()),
                                    (row, Process(), Process(status=1))):
            with self.assertRaises(ValueError): m.unclean_stop(qemu, changed, ssh)
            self.assertEqual(qemu.kills, 0)

    def test_normal_stop_cannot_be_reported_as_unclean(self):
        with self.assertRaisesRegex(ValueError, 'stop uncleanly'):
            m.unclean_stop(Process(final=3), {'held': True, 'held_monotonic_ns': 1}, Process())

    def test_held_ssh_has_established_session_liveness_bound(self):
        driver = object.__new__(m.Qualification)
        driver.key, driver.private = Path('/dev/null'), Path('/unused-private')
        effective = subprocess.check_output(driver.ssh_argv('/bin/true', held=True)[:1]
                                           + ['-G'] + driver.ssh_argv('/bin/true', held=True)[1:], text=True)
        options = dict(line.split(' ', 1) for line in effective.splitlines())
        interval = int(options['serveraliveinterval'])
        self.assertGreater(interval, 0)
        self.assertLess(interval * int(options['serveralivecountmax']), 30)

    def test_interrupted_client_timeout_preserves_output_and_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            driver = object.__new__(m.Qualification)
            driver.evidence, driver.events = Path(tmp), 0
            driver.failure_domain = 'product'
            driver.held = subprocess.Popen([sys.executable, '-c',
                "import sys,time; print('partial',file=sys.stderr,flush=True); time.sleep(60)"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    driver.finish_interrupted_client({}, timeout=0.5)
                self.assertEqual(driver.failure_domain, 'infrastructure')
                event = json.loads(next(Path(tmp).glob('*-interrupted-client-timeout.json')).read_text())
                self.assertIn(b'partial', bytes.fromhex(event['stderr_hex']))
                self.assertIsNone(driver.held.poll())
            finally:
                driver.held.kill(); driver.held.communicate(timeout=5)

    def test_interrupted_client_keeps_no_success_oracle(self):
        for code, accepted in [("raise SystemExit(255)", True),
                               ("raise SystemExit(0)", False),
                               ("print('published'); raise SystemExit(255)", False),
                               ("import sys; print('/home/operator/https-document-x',file=sys.stderr); raise SystemExit(255)", False)]:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                driver = object.__new__(m.Qualification)
                driver.evidence, driver.events = Path(tmp), 0
                driver.failure_domain = 'product'
                driver.held = subprocess.Popen([sys.executable, '-c', code],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    if accepted:
                        driver.finish_interrupted_client({}, timeout=5)
                    else:
                        with self.assertRaisesRegex(ValueError, 'reported success'):
                            driver.finish_interrupted_client({}, timeout=5)
                finally:
                    if driver.held.poll() is None: driver.held.kill()
                    driver.held.communicate(timeout=5)

    def test_partial_generic_or_failed_cases_cannot_pass_app_lifecycle(self):
        rows = [{'case': case, 'disposition': 'PASS'} for case in m.REQUIRED]
        self.assertEqual(m.terminal(rows)['disposition'], 'PASS')
        self.assertEqual(m.terminal(rows[:-1])['disposition'], 'FAIL')
        self.assertEqual(m.terminal(rows, RuntimeError('native fetch failed'))['disposition'], 'FAIL')
        bad = copy.deepcopy(rows); bad[1]['disposition'] = 'FAIL'
        self.assertEqual(m.terminal(bad)['disposition'], 'FAIL')
        self.assertEqual(m.terminal([{'case': 'P04-A-recovered-durable', 'disposition': 'PASS'}])['disposition'], 'FAIL')

    def test_terminal_failure_domain_is_explicit_not_inferred_from_fail(self):
        rows = [{'case': case, 'disposition': 'PASS'} for case in m.REQUIRED]
        self.assertEqual(m.terminal([], RuntimeError('validation failed'))['failure_domain'], 'infrastructure')
        self.assertEqual(m.terminal(rows, RuntimeError('assertion failed'), failure_domain='product')['failure_domain'], 'product')
        self.assertIsNone(m.terminal(rows)['failure_domain'])

    def test_close_defaults_failure_domain_before_initialization_finishes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            driver = object.__new__(m.Qualification)
            driver.boots, driver.held, driver.peer = [], None, None
            driver.evidence = base
            driver.smoke, driver.rows = False, []
            driver.point, driver.pin = base / 'point', None
            driver.config_identity, driver.cfg = None, {}
            driver.close(ValueError('infrastructure validation failed'))
            result = json.loads((base / 'RESULT.json').read_text())
            self.assertEqual(result['failure_domain'], 'infrastructure')
            self.assertEqual(result['disposition'], 'FAIL')

    def test_no_go_refuses_before_artifact_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config = base / 'config.json'; config.write_text('{"execution_go":false}')
            private, evidence = base / 'private', base / 'evidence'
            done = subprocess.run([sys.executable, '-B', str(Path(m.__file__)), '--config', str(config),
                                   '--private-work', str(private), '--evidence', str(evidence)], capture_output=True, timeout=20)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn(b'draft has no execution authority', done.stderr)
            self.assertFalse(private.exists()); self.assertFalse(evidence.exists())

    def test_ancestry_preservation_creates_fresh_output_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            driver = m.Qualification({}, base / 'private', base / 'evidence')
            driver.preserve_ancestry(b'fixture ancestry\n')
            self.assertEqual((driver.evidence / 'source-ancestry.json').read_bytes(), b'fixture ancestry\n')
            self.assertTrue(driver.private.is_dir())
            with self.assertRaises(FileExistsError):
                driver.preserve_ancestry(b'different\n')
            self.assertEqual((driver.evidence / 'source-ancestry.json').read_bytes(), b'fixture ancestry\n')

    def test_smoke_cat_executes_inside_nested_absd(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            driver = m.Qualification({'run': 'smoke-run'}, base / 'private', base / 'evidence', smoke=True)
            driver.preserve_ancestry(b'fixture ancestry\n')
            payload = b'ABSD App A harness smoke\n'
            commands = []

            def nested(command, data=None, **kwargs):
                commands.append(command)
                if command.startswith('/bin/cat > '):
                    return 0, b'', b''
                if command == '/bin/cat /home/operator/app-a-harness-smoke-input':
                    return 0, payload, b''
                raise AssertionError(command)

            driver.ssh = nested
            driver.halt = lambda: 123
            with patch.object(m.subprocess, 'run', side_effect=AssertionError('outer host cat executed')):
                driver.run_smoke()
            self.assertEqual((driver.evidence / 'CAT-OUTPUT.txt').read_bytes(), payload)
            self.assertEqual(driver.smoke_receipt['program'], '/bin/cat in nested ABSD')
            self.assertEqual(driver.smoke_receipt['output_sha256'], m.sha(payload))
            self.assertTrue(any(command.startswith('/bin/cat > ') for command in commands))
            self.assertIn('/bin/cat /home/operator/app-a-harness-smoke-input', commands)

    def test_smoke_cli_mode_must_match_config(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config = base / 'config.json'; config.write_text('{"harness_mode":"app_a"}')
            private, evidence = base / 'private', base / 'evidence'
            done = subprocess.run([sys.executable, '-B', str(Path(m.__file__)), '--config', str(config),
                                   '--private-work', str(private), '--evidence', str(evidence), '--smoke'],
                                  capture_output=True, timeout=20)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn(b'harness mode', done.stderr)
            self.assertFalse(private.exists()); self.assertFalse(evidence.exists())

    def driver(self, base):
        private, evidence = base / 'private', base / 'evidence'
        private.mkdir(); evidence.mkdir()
        driver = m.Qualification({'hard_end_unix_s': time.time() + 1000, 'qemu': {'sha256': 'f' * 64},
                                  'manifest': {'sha256': 'a' * 64}}, private, evidence)
        driver.qemu, driver.importer_qemu = ['/unexecuted/qemu'], ['/unexecuted/adapter']
        driver.importer_inputs = private / 'inputs.json'
        driver.importer_receipts = evidence / 'bindings'; driver.importer_receipts.mkdir()
        driver.importer_binding = type('Binding', (), {'terminal_bindings': staticmethod(lambda *args: {})})()
        return driver

    def test_cli_failure_and_unbound_mutator_do_not_advance_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            driver = self.driver(Path(directory))
            for exit_code, reason in ((17, 'canonical release command failed'), (0, 'new bound importer')):
                with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], exit_code, b'', b'fixture')):
                    with self.assertRaisesRegex(ValueError, reason): driver.tool('install')
                self.assertEqual(driver.rows, [])
            self.assertTrue(list(driver.evidence.glob('*tool-result.json')))

    def test_cleanup_failure_is_terminal_failure_even_after_all_phases(self):
        with tempfile.TemporaryDirectory() as directory:
            driver = self.driver(Path(directory))
            driver.rows = [{'case': case, 'disposition': 'PASS'} for case in m.REQUIRED]
            driver.peer = type('Peer', (), {'stop': lambda self: (_ for _ in ()).throw(ValueError('fixture stop'))})()
            with self.assertRaisesRegex(ValueError, 'cleanup incomplete'): driver.close(None)
            result = json.loads((driver.evidence / 'RESULT.json').read_text())
            self.assertEqual(result['disposition'], 'FAIL')
            self.assertTrue(result['cleanup_errors'])


if __name__ == '__main__': unittest.main()
