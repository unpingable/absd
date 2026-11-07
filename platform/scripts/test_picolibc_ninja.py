#!/usr/bin/env python3
"""Exercise actual setup tool selection with local recording tools only."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest

SPEC = importlib.util.spec_from_file_location(
    'picolibc_recording_fixture', Path(__file__).with_name('test_picolibc_tmpdir.py'))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class NinjaSelectionControls(unittest.TestCase):
    def setUp(self):
        self.fixture = FIXTURE.TmpdirControls()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.exe('ninja', "import os,pathlib\n"
                         "pathlib.Path(os.environ['OWNED_NINJA_USED']).write_text('selected')\n"
                         "print('1.13.0')\n")
        self.fixture.exe('meson', "import json,os,pathlib,shutil,subprocess,sys\n"
                         "if sys.argv[1]=='--version': print('1.9.1');sys.exit(0)\n"
                         "selected=os.environ.get('NINJA') or shutil.which('ninja')\n"
                         "pathlib.Path(os.environ['RECORD']).write_text(json.dumps({'args':sys.argv[1:],'ninja':selected,'path':os.environ['PATH']}))\n"
                         "subprocess.run([selected,'--version'],check=True)\n"
                         "sys.exit(77) # deliberate stop before any build\n")
        self.base = Path(self.fixture.temp.name)
        self.ambient = self.base / 'ambient'
        self.ambient.mkdir()
        ninja = self.ambient / 'ninja'
        ninja.write_text('#!/bin/sh\nprintf ambient > "$AMBIENT_NINJA_USED"\nexit 91\n')
        ninja.chmod(0o755)
        self.env = {
            'PATH': str(self.ambient) + ':/usr/bin:/bin',
            'HOME': os.environ['HOME'],
            'TMPDIR': str(self.fixture.tmp),
            'ABSD_PICOLIBC_PREFIX': str(self.fixture.prefix),
            'ABSD_PICOLIBC_VENV': str(self.fixture.venv),
            'ABSD_PICOLIBC_JOBS': '1',
            'RECORD': str(self.fixture.record),
            'OWNED_NINJA_USED': str(self.base / 'owned-used'),
            'AMBIENT_NINJA_USED': str(self.base / 'ambient-used'),
        }

    def run_setup(self):
        return subprocess.run(['sh', str(self.fixture.root / 'scripts/build-picolibc.sh')],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def assert_owned(self, result):
        self.assertNotEqual(result.returncode, 0)  # intentional recording stop
        self.assertIn('meson setup failed', result.stderr)
        record = json.loads(self.fixture.record.read_text())
        self.assertEqual(record['args'][0], 'setup')
        self.assertEqual(record['ninja'], str(self.fixture.venv / 'bin/ninja'))
        self.assertEqual(record['path'], self.env['PATH'])
        self.assertEqual((self.base / 'owned-used').read_text(), 'selected')
        self.assertFalse((self.base / 'ambient-used').exists())
        self.assertFalse((self.fixture.prefix / 'install').exists())

    def test_setup_selects_owned_ninja_without_venv_on_path(self):
        self.assertNotIn(str(self.fixture.venv / 'bin'), self.env['PATH'].split(':'))
        self.assert_owned(self.run_setup())

    def test_ambient_ninja_override_cannot_replace_owned_selection(self):
        self.env['NINJA'] = str(self.ambient / 'ninja')
        self.assert_owned(self.run_setup())

    def test_pre_fix_setup_is_detected_by_actual_tool_observation(self):
        script = self.fixture.root / 'scripts/build-picolibc.sh'
        fixed = script.read_text()
        prefix = 'NINJA="$venv/bin/ninja" "$venv/bin/meson" setup'
        self.assertEqual(fixed.count(prefix), 1)
        script.write_text(fixed.replace(prefix, '"$venv/bin/meson" setup', 1))
        with self.assertRaises(AssertionError):
            self.assert_owned(self.run_setup())
        self.assertEqual((self.base / 'ambient-used').read_text(), 'ambient')
        self.assertFalse((self.base / 'owned-used').exists())


if __name__ == '__main__':
    unittest.main()
