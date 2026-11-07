"""Actual probe arm and complete live consumer expressions, host only."""
from pathlib import Path
from types import SimpleNamespace
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('fsd_matrix_startup_role', ROOT / 'scripts/fsd-matrix.py')
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)
ABSENT = 'block: STARTUP ROLE ABSENT process_handle_coverage=UNVERIFIED'
PRESENT = 'block: STARTUP ROLE PRESENT process_handle_coverage=UNVERIFIED'
PERMISSION = 'spawn: /bin/fsd-probe: permission denied'


class ProbeRole(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='absd-startup-block-role-')
        cls.addClassCleanup(cls.temporary.cleanup)
        work = Path(cls.temporary.name)
        source = (ROOT / 'src/bin/fsd_probe.rs').read_text()
        arm = source[source.index('        "block" => {'):source.index('        "pingpong" => {')]
        fail = source[source.index('fn fail('):source.index('fn run(')]
        runtime = (ROOT / 'runtime/src/lib.rs').read_text()
        block = re.findall(r'^static BLOCK: AtomicU64 = AtomicU64::new\(0\);$', runtime, re.M)
        assert len(block) == 1
        getter = runtime[runtime.index('pub fn block_handle()'):runtime.index('pub(crate) fn map(')]
        fixture = '''#![allow(dead_code)]
mod absd_runtime {
    use core::sync::atomic::{AtomicU64,Ordering};
''' + block[0] + '\n' + getter + '''
    pub fn fixture_install() { BLOCK.store(std::env::var("STARTUP_BLOCK_HANDLE").unwrap().parse().unwrap(),Ordering::Relaxed); }
    pub mod layout {
        pub const SECTOR_BYTES:usize=512;
        pub fn read_raw(_:u64,_:u64,_:&mut[u8])->Result<(),i64>{panic!("unexpected block read")}
        pub fn write_raw(_:u64,_:u64,_:&[u8])->Result<(),i64>{panic!("unexpected block write")}
    }
}
''' + fail + '\nfn main() { absd_runtime::fixture_install(); match "block" {\n' + arm + '\n_ => unreachable!(), } }\n'
        (work / 'probe.rs').write_text(fixture)
        cls.binary = work / 'probe'
        subprocess.run(['rustc', '--edition=2024', str(work / 'probe.rs'), '-o', str(cls.binary)], check=True)

    def test_actual_probe_zero_getter_says_only_startup_role_absent(self):
        run = subprocess.run([str(self.binary)], env=dict(os.environ, STARTUP_BLOCK_HANDLE='0'), capture_output=True)
        self.assertEqual((run.returncode, run.stdout, run.stderr), (0, (ABSENT + '\n').encode(), b''))

    def test_actual_probe_nonzero_and_tagged_last_slot_getters_refuse(self):
        for handle in (1, 0x70000807f):
            with self.subTest(handle=handle):
                run = subprocess.run([str(self.binary)], env=dict(os.environ, STARTUP_BLOCK_HANDLE=str(handle)), capture_output=True)
                self.assertEqual((run.returncode, run.stdout, run.stderr), (1, (PRESENT + '\n').encode(), b''))


class LiveConsumers(unittest.TestCase):
    def fragment(self, start, end):
        source = (ROOT / 'scripts/fsd-matrix.py').read_text()
        at = source.index(start)
        return compile(textwrap.dedent(source[at:source.index(end, at)]), 'actual fsd-matrix fragment', 'exec')

    def check(self, name, good, detail=''):
        self.assertTrue(good, name + ': ' + str(detail))

    def block_checks(self, *, exec_rc=0, exec_out=None, shell_rc=0, shell_out=None):
        if exec_out is None: exec_out = (ABSENT + '\n').encode()
        if shell_out is None: shell_out = ('\n'.join([ABSENT, PERMISSION, ABSENT]) + '\n').encode()
        target = SimpleNamespace(ssh=lambda *a, **kw: (exec_rc, exec_out, b''),
                                 shell=lambda *a, **kw: (shell_rc, shell_out, b''),
                                 check=self.check, mark=lambda *a: None)
        code = self.fragment('        rc, out, err = self.ssh("/bin/fsd-probe block")',
                             '        # -- SSH HOST KEY ISOLATED')
        exec(code, {'self': target, 'lines': matrix.lines})

    def test_actual_block_consumers_accept_exact_narrow_claim_and_permission_refusal(self):
        self.block_checks()

    def test_actual_exec_consumer_refuses_bad_status_and_extra_or_stale_text(self):
        for rc, out in [(1, ABSENT + '\n'), (0, ABSENT + '\nextra\n'),
                        (0, 'block: REFUSED handles=64 block_handle=0\n'),
                        (0, PRESENT + '\n'), (0, ABSENT.replace('UNVERIFIED', 'PASS') + '\n')]:
            with self.subTest(rc=rc, out=out), self.assertRaises(AssertionError):
                self.block_checks(exec_rc=rc, exec_out=out.encode())

    def test_actual_shell_block_consumer_refuses_bad_status_extra_rows_and_wrong_grandchild_reason(self):
        good = [ABSENT, PERMISSION, ABSENT]
        cases = [(1, good), (0, good + ['extra']), (0, good + [ABSENT]),
                 (0, [ABSENT, PERMISSION.replace('permission denied', 'not found'), ABSENT]),
                 (0, [ABSENT, ABSENT]), (0, [ABSENT, PERMISSION, PRESENT])]
        for rc, rows in cases:
            with self.subTest(rc=rc, rows=rows), self.assertRaises(AssertionError):
                self.block_checks(shell_rc=rc, shell_out=('\n'.join(rows) + '\n').encode())

    def narrowing_check(self, *, rc=0, rows=None, tree_extra=None):
        expected = ['try-write: ReadOnlyFilesystem /home/operator/other',
                    'try-write: ReadOnlyFilesystem /home/operator/redir',
                    'try-read: NotFound /etc/motd', ABSENT,
                    'mounts: /home/operator:ro,/tmp/session-7:ro,/bin:ro,/etc:ro,/share:ro,/var/log:ro',
                    'mounts: /home/operator:rw,/tmp/session-7:rw,/bin:ro,/etc:ro,/share:ro,/var/log:ro']
        if rows is None: rows = expected
        output = ('\n'.join(rows) + '\n').encode()
        tree = {'/home/operator/redir': output, **(tree_extra or {})}
        target = SimpleNamespace(shell=lambda *a, **kw: (rc, output, b''), device=lambda: tree,
                                 check=self.check, mark=lambda *a: None)
        source = (ROOT / 'scripts/fsd-matrix.py').read_text()
        begin = source.index('        # -- SHELL AUTHORITY NARROWING')
        at = source.index('        rc, out, err = self.shell([', begin)
        code = compile(textwrap.dedent(source[at:source.index('        # -- SSH MULTI SESSION', at)]),
                       'actual fsd-matrix narrowing fragment', 'exec')
        exec(code, {'self': target, 'lines': matrix.lines, 're': re})
        return expected

    def test_actual_redirected_consumer_keeps_mount_and_effect_checks(self):
        rows = self.narrowing_check()
        cases = [(1, rows, None), (0, rows + ['extra'], None),
                 (0, [row.replace('/home/operator:ro', '/home/operator:rw') for row in rows], None),
                 (0, rows, {'/home/operator/other': b'bad'}),
                 (0, [row.replace('UNVERIFIED', 'PASS') for row in rows], None)]
        for rc, changed, extra in cases:
            with self.subTest(rc=rc, rows=changed, extra=extra), self.assertRaises(AssertionError):
                self.narrowing_check(rc=rc, rows=changed, tree_extra=extra)


if __name__ == '__main__':
    unittest.main()
