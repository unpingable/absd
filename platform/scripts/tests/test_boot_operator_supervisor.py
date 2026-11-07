#!/usr/bin/env python3
"""Offline launcher lifecycle regressions with the real recovery classifier.

Only QEMU is substituted. Real format-2 images and authorization records come
from the canonical resume test fixtures. Private source barriers exercise
otherwise unobservable transitions; there are no production test hooks.
"""
import contextlib
import ctypes
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pty
import shutil
import signal
import subprocess
import sys
import termios
import time
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from test_storage_fence_resume import Base, CONSUME, sfr, toml


class Supervisor(Base):
    @classmethod
    def setUpClass(cls):
        # Reap exact substitute children even when a broken launcher orphans
        # them. This applies only to this foreground test process.
        cls.libc = ctypes.CDLL(None, use_errno=True)
        cls.previous = ctypes.c_int()
        if cls.libc.prctl(37, ctypes.byref(cls.previous), 0, 0, 0):
            raise OSError(ctypes.get_errno(), 'PR_GET_CHILD_SUBREAPER')
        if cls.libc.prctl(36, 1, 0, 0, 0):
            raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')

    @classmethod
    def tearDownClass(cls):
        cls.libc.prctl(36, cls.previous.value, 0, 0, 0)

    def setUp(self):
        super().setUp()
        self.scripts = self.work/'scripts'
        self.scripts.mkdir()
        for source in SCRIPTS.glob('*.py'):
            (self.scripts/source.name).symlink_to(source)
        for name in ('boot-operator.sh', 'boot_operator_supervisor.py'):
            source = SCRIPTS/name
            if source.exists():
                target = self.scripts/name
                if target.is_symlink(): target.unlink()
                shutil.copyfile(source, target)
        self.launcher = self.scripts/'boot-operator.sh'
        self.out = self.target('machine with space')
        (self.out/'absd-operator.iso').write_bytes(b'fixture ISO')
        self.intent, _ = self.act(self.out)
        self.ready = self.work/'child-ready'
        self.fake = self.work/'substitute-qemu'
        self.fake.write_text('''#!/usr/bin/python3
import os,signal,subprocess,sys,time
from pathlib import Path
if os.environ.get('QEMU_SIGNAL_EXIT_ZERO'):
    for stop in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(stop, lambda signum, frame: sys.exit(0))
else:signal.signal(signal.SIGHUP, signal.SIG_IGN)
if os.environ.get('IGNORE_TERM'):signal.signal(signal.SIGTERM, signal.SIG_IGN)
args=sys.argv[1:]
spec=args[args.index('-chardev')+1]
console=spec.split('logfile=',1)[1].split(',logappend=',1)[0]
Path(console).write_text('ABSD KERNEL BOOT\\n' if os.environ.get('FAKE_BOOT') else 'substitute did not boot\\n')
with open(os.environ['CHILD_READY'],'w') as ready:ready.write(str(os.getpid()))
if os.environ.get('FAKE_CONSUME'):
    image=args[args.index('-drive')+1].split('file=',1)[1].split(',format=',1)[0]
    subprocess.run([sys.executable,'-I','-B','-X',f"pycache_prefix={sys.pycache_prefix or ''}",os.environ['FAKE_CONSUME'],image,console],check=True)
while not os.environ.get('AUTO_HALT') and not Path(os.environ['CHILD_READY']+'.halt').exists():time.sleep(0.005)
sys.exit(3)
''')
        self.fake.chmod(0o700)
        self.consume = self.work/'consume.py'
        self.consume.write_text(CONSUME.replace('"scripts"', repr(str(SCRIPTS))))
        self.env = dict(os.environ, ABSD_QEMU=str(self.fake), CHILD_READY=str(self.ready))
        self.proc = None
        self.addCleanup(self.retire)

    def retire(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=3)
        if self.ready.exists():
            pid = int(self.ready.read_text())
            with contextlib.suppress(ProcessLookupError): os.kill(pid, signal.SIGKILL)
            with contextlib.suppress(ChildProcessError): os.waitpid(pid, 0)
        if self.proc is not None:
            for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                if stream is not None: stream.close()

    def until(self, predicate, detail):
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            if predicate(): return
            time.sleep(0.005)
        self.fail(detail)

    def start(self, **kw):
        self.proc = subprocess.Popen(['sh', str(self.launcher), '--local-only', '--console', str(self.out)],
                                     env=self.env, **kw)
        self.until(lambda: self.ready.exists(), 'substitute child never ready')
        self.until(lambda: toml(self.out/'recovery'/sfr.ACTIVE)['active']['state']=='launched',
                   'real launched record not published')

    def assert_interrupted_and_closed(self):
        status = self.proc.wait(timeout=6)
        active = toml(self.out/'recovery'/sfr.ACTIVE)['active']
        try:
            os.kill(int(self.ready.read_text()), 0)
            alive = True
        except ProcessLookupError:
            alive = False
        self.assertEqual((status, active['state'], active.get('last_launch'),
                          active.get('last_launch_status'), alive),
                         (130, 'authorized', 'launch_failed', '130', False))
        with sfr.recovery_lock(self.out): pass

    def test_closed_stderr_term_retires_hup_ignoring_child_and_classifies(self):
        self.start(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                   start_new_session=True)
        self.proc.stderr.close()
        self.proc.send_signal(signal.SIGTERM)
        self.assert_interrupted_and_closed()

    def test_group_hup_keeps_interruption_status_when_qemu_handler_exits_zero(self):
        source = (self.scripts/'boot_operator_supervisor.py').read_text()
        marker = '                    returncode = child.wait(timeout=0.1)'
        self.assertEqual(source.count(marker), 1)
        # Pause after the interruption guard and before wait. A group HUP
        # then makes both the owner's latch and QEMU-shaped exit0 observable
        # to that same wait; scheduling cannot turn this into an early stop.
        barrier = '''                    import time
                    checkpoint = Path(os.environ['WAIT_ENTERED'])
                    checkpoint.write_text('ready')
                    while not Path(str(checkpoint)+'.release').exists(): time.sleep(0.005)
'''
        (self.scripts/'boot_operator_supervisor.py').write_text(source.replace(marker, barrier+marker))
        for booted in (False, True):
            with self.subTest(booted=booted):
                self.out = self.target('group-hup-'+str(booted))
                (self.out/'absd-operator.iso').write_bytes(b'ISO')
                self.intent, _ = self.act(self.out)
                self.ready = self.work/('group-ready-'+str(booted))
                checkpoint = self.work/('waiting-'+str(booted))
                release = Path(str(checkpoint)+'.release')
                self.env.update(QEMU_SIGNAL_EXIT_ZERO='1', CHILD_READY=str(self.ready), WAIT_ENTERED=str(checkpoint))
                if booted: self.env['FAKE_BOOT'] = '1'
                try:
                    self.start(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True)
                    self.until(checkpoint.exists, 'owner wait barrier not reached')
                    os.killpg(self.proc.pid, signal.SIGHUP)
                    self.until(lambda: not Path('/proc/'+self.ready.read_text()).exists()
                               or Path('/proc/'+self.ready.read_text()+'/stat').read_text().split()[2]=='Z',
                               'QEMU-shaped signal handler did not exit')
                    release.write_text('continue')
                    if not booted:
                        self.assert_interrupted_and_closed()
                    else:
                        self.assertEqual(self.proc.wait(timeout=6), 130)
                        self.assertEqual(toml(self.out/'recovery'/sfr.ACTIVE)['active']['state'], 'launched')
                        with self.assertRaises(ProcessLookupError): os.kill(int(self.ready.read_text()), 0)
                        with sfr.recovery_lock(self.out): pass
                finally:
                    release.write_text('continue')
                    self.retire()
        (self.scripts/'boot_operator_supervisor.py').write_text(source)

    def test_attended_owner_handles_hup_even_when_inherited_ignored(self):
        def ignore_hup(): signal.signal(signal.SIGHUP, signal.SIG_IGN)
        self.start(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   start_new_session=True, preexec_fn=ignore_hup)
        self.proc.send_signal(signal.SIGHUP)
        self.assert_interrupted_and_closed()

    def test_closed_controlling_pty_master_hup_retires_child_and_classifies(self):
        master, slave = pty.openpty()
        self.addCleanup(lambda: os.close(master) if master >= 0 else None)
        self.addCleanup(os.close, slave)
        def control_terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        self.start(stdin=slave, stdout=slave, stderr=slave, preexec_fn=control_terminal)
        os.close(master)
        master = -1
        self.assert_interrupted_and_closed()

    def test_closed_stderr_and_sigpipe_cannot_abort_term_to_kill_escalation(self):
        self.env['IGNORE_TERM'] = '1'
        self.start(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                   start_new_session=True)
        self.proc.stderr.close()
        self.proc.send_signal(signal.SIGPIPE)
        self.proc.send_signal(signal.SIGTERM)
        self.assert_interrupted_and_closed()

    def uart_fixture(self):
        spec = importlib.util.spec_from_file_location('uart_fixture', SCRIPTS/'check-uart-stdio.py')
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        return fixture

    def test_uart_prepare_dependency_closure_follows_transitive_imports(self):
        fixture = self.uart_fixture()
        scripts = self.work/'closure'/'scripts'
        scripts.mkdir(parents=True)
        (scripts/'check-harness-cohort.py').write_bytes((SCRIPTS/'check-harness-cohort.py').read_bytes())
        sources = {'operator_cpus.py': 'import first\n',
                   'boot_operator_supervisor.py': 'import storage_fence_resume\n',
                   'storage_fence_resume.py': 'from first import value\n',
                   'first.py': 'from second import value\n',
                   'second.py': 'raise AssertionError("must inspect, never import")\n',
                   'unused.py': 'raise AssertionError("unreachable")\n'}
        for name, source in sources.items():
            (scripts/name).write_text(source)
        fixture.ROOT = scripts.parent
        self.assertEqual(fixture.launcher_sources(),
                         ['boot_operator_supervisor.py', 'first.py', 'operator_cpus.py',
                          'second.py', 'storage_fence_resume.py'])

    def test_uart_removed_geometry_dependency_refuses_before_spawn(self):
        fixture = self.uart_fixture()
        bundle = self.work/'prepared-uart'
        fixture.prepare(bundle, str(self.fake))
        (bundle/'scripts/operator_geometry.py').unlink(missing_ok=True)
        with mock.patch.object(fixture.subprocess, 'Popen', side_effect=AssertionError('emulator must not start')):
            with self.assertRaises(FileNotFoundError):
                fixture.run(bundle)

    def test_uart_omitted_dependency_identity_refuses_before_spawn(self):
        fixture = self.uart_fixture()
        bundle = self.work/'prepared-uart'
        metadata = fixture.prepare(bundle, str(self.fake))
        metadata['launcher_inputs_sha256'].pop('operator_geometry.py', None)
        (bundle/'fixture.json').write_text(json.dumps(metadata))
        with mock.patch.object(fixture.subprocess, 'Popen', side_effect=AssertionError('emulator must not start')):
            with self.assertRaisesRegex(ValueError, 'identity closure'):
                fixture.run(bundle)

    def test_uart_prepare_bundle_runs_successor_with_real_classifier(self):
        fixture = self.uart_fixture()
        bundle = self.work/'prepared-uart'
        fixture.prepare(bundle, str(self.fake))
        # Execute the builder's actual copied launcher tree, substituting only
        # the emulator. No emulator, VM, network or UART qualification occurs.
        self.proc = subprocess.Popen(['sh', str(bundle/'scripts/boot-operator.sh'), '--local-only',
                                      '--console', str(bundle/'machine')],
                                     env=dict(self.env, AUTO_HALT='1'), stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = self.proc.communicate(timeout=6)
        self.assertEqual(self.proc.returncode, 0, (stdout, stderr))
        self.assertIn(b'the machine halted', stdout)
        with self.assertRaises(ProcessLookupError): os.kill(int(self.ready.read_text()), 0)

    def test_signals_across_spawn_cleanup_and_completed_wait_preserve_one_outcome(self):
        source = (SCRIPTS/'boot_operator_supervisor.py').read_text()
        helper = '''
def _test_barrier():
    import time
    checkpoint = Path(os.environ['BARRIER'])
    checkpoint.write_text('ready')
    while not Path(str(checkpoint)+'.release').exists(): time.sleep(0.005)

'''
        # Instrument only the private copy. Signals are handled by the real
        # supervisor; real Popen/wait, child processes and classifier remain.
        phases = {
            'before_spawn': ('            child = subprocess.Popen(', '            _test_barrier()\n', False),
            'cleanup': ('        retire(child)\n', '        _test_barrier()\n', False),
            'after_wait': ('                # A normal exit returned', '                _test_barrier()\n', True),
            'classification': ('        classified = recovery.exit_path(', '        _test_barrier()\n', True),
            'after_classification': ('    if bookkeeping_failed:\n', '    _test_barrier()\n', True),
        }
        for phase in (*phases, 'before_popen_returns'):
            with self.subTest(phase=phase):
                # A new occurrence and image prevent a previous run's
                # record/console/PID from satisfying the next transition.
                self.out = self.target(phase)
                (self.out/'absd-operator.iso').write_bytes(b'ISO')
                self.intent, _ = self.act(self.out)
                self.ready = self.work/(phase+'-ready')
                barrier = self.work/(phase+'-barrier')
                release = Path(str(barrier)+'.release')
                self.env.update(CHILD_READY=str(self.ready), BARRIER=str(barrier))
                normal = phases[phase][2] if phase in phases else False
                if normal: self.env.update(FAKE_BOOT='1', AUTO_HALT='1', FAKE_CONSUME=str(self.consume))
                else:
                    self.env.pop('FAKE_BOOT', None)
                    self.env.pop('AUTO_HALT', None)
                    self.env.pop('FAKE_CONSUME', None)
                private = source.replace('\ndef diagnostic(', helper+'\ndef diagnostic(')
                if phase == 'before_popen_returns':
                    private = private.replace('child = subprocess.Popen(', 'child = _test_spawn(')
                    wrapper = '''
def _test_spawn(*args, **kwargs):
    child = subprocess.Popen(*args, **kwargs)
    _test_barrier()
    return child

'''
                    private = private.replace('\ndef diagnostic(', wrapper+'\ndef diagnostic(')
                else:
                    marker, prefix, _ = phases[phase]
                    self.assertEqual(private.count(marker), 1)
                    private = private.replace(marker, prefix+marker)
                (self.scripts/'boot_operator_supervisor.py').write_text(private)
                self.proc = subprocess.Popen(['sh', str(self.launcher), '--local-only', '--console', str(self.out)],
                                             env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL, start_new_session=True)
                try:
                    if phase == 'cleanup':
                        self.until(lambda: self.ready.exists(), 'child ready for initial TERM')
                        self.until(lambda: toml(self.out/'recovery'/sfr.ACTIVE)['active']['state']=='launched',
                                   'real launch publication before TERM')
                        self.proc.send_signal(signal.SIGTERM)
                    self.until(barrier.exists, phase+' barrier not reached')
                    self.refused(sfr.recovery_lock(self.out).__enter__, 'tool_busy')
                    if phase in ('after_wait', 'classification', 'after_classification'):
                        with self.assertRaises(ProcessLookupError): os.kill(int(self.ready.read_text()), 0)
                    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                        self.proc.send_signal(signum)
                    release.write_text('continue')
                    self.assertEqual(self.proc.wait(timeout=6), 0 if normal else 130)
                    if normal:
                        self.assertFalse((self.out/'recovery'/sfr.ACTIVE).exists())
                        archive = toml(self.out/'recovery'/('consumed-'+self.intent['id']+'.toml'))
                        self.assertEqual(archive['archive']['disposition'], 'consumed')
                    else:
                        active = toml(self.out/'recovery'/sfr.ACTIVE)['active']
                        self.assertEqual(active['state'], 'authorized')
                        if phase != 'before_spawn': self.assertEqual(active['last_launch_status'], '130')
                    if self.ready.exists():
                        with self.assertRaises(ProcessLookupError): os.kill(int(self.ready.read_text()), 0)
                    with sfr.recovery_lock(self.out): pass
                finally:
                    release.write_text('continue')
                    self.retire()
        (self.scripts/'boot_operator_supervisor.py').write_text(source)


if __name__ == '__main__': unittest.main()
