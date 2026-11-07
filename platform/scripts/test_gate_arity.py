from pathlib import Path
import importlib.util
import unittest
import subprocess
import tempfile
import hashlib
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("gate_arity", HERE / "check-gate-arity.py")
arity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arity)


class Arity(unittest.TestCase):
    def setUp(self):
        self.original = (HERE / "check-all.sh").read_text()

    def test_shell_labels_follow_artifacts_and_additions(self):
        match = re.search(r'(?ms)^# Reproducibility artifact declaration\n(.*?)^# End reproducibility helpers\n', self.original)
        self.assertIsNotNone(match, 'single artifact declaration and helpers missing')
        helpers = match.group(1)
        for profile in ('full', 'core'):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as tmp:
                script = 'set -eu\nroot=$1\nABSD_PROFILE=$2\n' + helpers
                paths = subprocess.check_output(['sh', '-c', script + '\nartifact_paths', 'test', tmp, profile], text=True).splitlines()
                count = len(paths)
                commands = sum(path.startswith("commands/") for path in paths)
                self.assertEqual(count, arity.check(self.original)[profile])
                for i, path in enumerate(paths):
                    target = Path(tmp, path)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(str(i))
                run = script + '\nsecond_hashes=$(artifact_hashes)\nsecond_manual=manual-sentinel\nartifact_summary\n'
                result = subprocess.check_output(['sh', '-c', run, 'test', tmp, profile], text=True)
                self.assertIn(f'programs={count}', result)
                self.assertIn(f'commands={commands}', result)
                for i, path in enumerate(paths):
                    self.assertIn(f'{path}={hashlib.sha256(str(i).encode()).hexdigest()}', result)
                # A newly declared artifact updates its own name, hash and count.
                extra = helpers.replace('        probe.elf', '        extra.elf probe.elf')
                Path(tmp, 'extra.elf').write_text('added')
                result = subprocess.run(['sh', '-c', 'set -eu\nroot=$1\nABSD_PROFILE=$2\n' + extra + '\nsecond_hashes=$(artifact_hashes)\nsecond_manual=x\nartifact_summary', 'test', tmp, profile], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = count + 1
                self.assertIn(f'programs={expected}', result.stdout)
                self.assertIn('extra.elf=' + hashlib.sha256(b'added').hexdigest(), result.stdout)
                # Missing a declared file must fail before any success message.
                Path(tmp, paths[0]).unlink()
                result = subprocess.run(['sh', '-c', run, 'test', tmp, profile], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('REPRODUCIBLE OK', result.stdout)

    def test_current_declarations_match_the_real_shell(self):
        helpers = re.search(r'(?ms)^# Reproducibility artifact declaration\n(.*?)^# End reproducibility helpers\n', self.original).group(1)
        counts = {}
        for profile in ('full', 'core'):
            paths = subprocess.check_output(['sh', '-c', 'ABSD_PROFILE=$1\n' + helpers + '\nartifact_paths', 'test', profile], text=True).splitlines()
            counts[profile] = len(paths)
        self.assertEqual(arity.check(self.original), counts)

    def test_stale_full_constant_refuses(self):
        with self.assertRaisesRegex(arity.Refused, 'stale literal'):
            arity.check(self.original + '\ntest "$#" -eq 60\n')

    def test_stale_core_constant_refuses(self):
        with self.assertRaisesRegex(arity.Refused, 'stale literal'):
            arity.check(self.original.replace('commands=%s', 'commands=26'))

    def test_second_hash_list_growth_refuses(self):
        with self.assertRaisesRegex(arity.Refused, 'second stale'):
            arity.check(self.original.replace('second_hashes=$(artifact_hashes)',
                                             'second_hashes=$(sha256sum extra.elf)'))

    def test_missing_canonical_boundary_refuses(self):
        with self.assertRaisesRegex(arity.Refused, 'summary boundary'):
            arity.check(self.original.replace('artifact_summary\n\nrun=', 'other\n\nrun='))

    def test_unsupported_dynamic_list_is_not_counted_as_a_literal(self):
        with self.assertRaisesRegex(arity.Refused, 'dynamic'):
            arity.check(self.original.replace('        probe.elf', '        $(select-program)', 1))

    def test_duplicate_path_refuses(self):
        with self.assertRaisesRegex(arity.Refused, 'duplicate'):
            arity.check(self.original.replace('        probe.elf', '        probe.elf probe.elf', 1))

    def test_missing_full_artifact_refuses(self):
        changed = self.original.replace('sshtest.elf', 'extra.elf', 1)
        with self.assertRaisesRegex(arity.Refused, 'missing from full'):
            arity.check(changed)

    def test_hash_consumer_cannot_skip_declaration(self):
        with self.assertRaisesRegex(arity.Refused, 'hash consumer'):
            arity.check(self.original.replace('set -- $paths', 'set -- probe.elf'))
    def test_later_shadow_declaration_refuses(self):
        with self.assertRaises(arity.Refused):
            arity.check(self.original + '\nartifact_paths() { echo wrong; }\n')

    def test_commented_comparison_refuses(self):
        with self.assertRaises(arity.Refused):
            arity.check(self.original.replace('test "$first_hashes" =', '# test "$first_hashes" ='))

    def test_neutralized_comparison_refuses(self):
        with self.assertRaises(arity.Refused):
            arity.check(self.original.replace('program hashes differ between builds" >&2; exit 1; }',
                                             'program hashes differ between builds" >&2; exit 1; } || true'))

    def test_indented_hash_reassignment_refuses(self):
        with self.assertRaises(arity.Refused):
            arity.check(self.original.replace('artifact_summary\n\nrun=',
                                             '    second_hashes=$first_hashes\nartifact_summary\n\nrun='))

    def test_shipped_native_command_cannot_be_omitted(self):
        with self.assertRaises(arity.Refused):
            arity.check(self.original.replace('commands/terminal-size', 'commands/wrong'))

    def test_empty_or_failed_declaration_refuses_in_real_shell(self):
        helpers = re.search(r'(?ms)^# Reproducibility artifact declaration\n(.*?)^# End reproducibility helpers\n', self.original).group(1)
        for definition in ('artifact_paths() { :; }', 'artifact_paths() { return 1; }'):
            result = subprocess.run(['sh', '-c', 'set -eu\nroot=$1\nABSD_PROFILE=core\n' + helpers + '\n' + definition + '\nartifact_hashes', 'test', str(HERE)], input=b'', capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(result.stdout)


if __name__ == "__main__":
    unittest.main()
