#!/usr/bin/env python3
"""Host-only policy gate: audit all durable builders and exercise real make.

Live build sites must use the shared prefix; reconstruction alone replays
recorded features. The sole external-build exception is media.py's standalone
probe; served media delegates to operator_image.kernel_iso. No kernel
compilation or guest execution here.
"""
import ast
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import served_kernel

ROOT = Path(__file__).resolve().parent
BUILDERS = {
    'ag-native-matrix.py': 2, 'durable-matrix.py': 1, 'exec-matrix.py': 1,
    'net-matrix.py': 1, 'nightshift-matrix.py': 1, 'observe-matrix.py': 1,
    'operator_image.py': 1, 'pipeline-matrix.py': 1, 'pulse-matrix.py': 2,
    'enroll-matrix.py': 1, 'served-matrix.py': 1, 'ssh_absd.py': 1,
    'reconstruct-release.sh': 1, 'run-broker.sh': 1,
}


# Classify every current reference file, including receipt vocabulary. This is
# an explicit file inventory, not proof that every possible Python call is known.
EXTERNAL_BUILD_REFERENCES = {
    'native-ipv6-mtu1280-matrix.py': 'Validate the producer command in a build receipt.',
    'native-tls-ipv6-routed-matrix.py': 'Validate the producer command in a build receipt.',
    'media.py': 'Standalone media probe; served media uses operator_image.',
    'native-ipv6-echo-matrix.py': 'Validate the producer command in a build receipt.',
    'native-ipv6-echo-responder.py': 'Validate the producer command in a build receipt.',
    'native-ipv6-route-matrix.py': 'Validate the producer command in a build receipt.',
    'native-ipv6-routed-tcp-matrix.py': 'Validate the producer command in a build receipt.',
    'native-ipv6-echo-matrix-test.py': 'Local build-receipt substitution fixture.',
    'native-ipv6-echo-responder-test.py': 'Local build-receipt substitution fixture.',
    'native-ipv6-route-matrix-test.py': 'Local build-receipt substitution fixture.',
    'native-dhcp-refusal-tests.py': 'Local build-receipt substitution fixture.',
    'native-tls-ipv6-matrix.py': 'Validate the producer command in a build receipt.',
}


def classify_external_reference(name, source):
    """Conservative literal trigger, independent of the Python call spelling.

    An unclassified file mentioning the target is refused, even in metadata.
    Classified files require source review when changed: this gate does not
    distinguish a newly added call inside one of those files from its data.
    Computed strings without this literal are outside the lexical check.
    """
    if 'external-build' not in source:
        return None
    if name not in EXTERNAL_BUILD_REFERENCES:
        raise ValueError(f'{name}: unclassified external-build reference')
    return EXTERNAL_BUILD_REFERENCES[name]


def audit(name, source):
    count = 0
    if name.endswith('.py'):
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.List, ast.Tuple)):
                continue
            if not any(isinstance(n, ast.Constant) and n.value == 'durable-iso' for n in node.elts):
                continue
            count += 1
            if ast.unparse(node.elts[0]) != '*kernel_make()':
                raise ValueError(f'{name}: durable build bypasses shared feature policy')
        if count and 'from served_kernel import kernel_make' not in source:
            raise ValueError(f'{name}: missing shared import')
    else:
        for line in source.replace('\\\n', ' ').splitlines():
            if line.lstrip().startswith('#') or not re.search(r'\bdurable-iso\b', line):
                continue
            count += 1
            # Reconstruction replays a recorded recipe, including an explicit
            # empty feature set. It must not substitute today's served policy.
            if name == 'reconstruct-release.sh':
                if (line.startswith('make --no-print-directory ')
                        and 'EXTERNAL_KERNEL_FEATURES="$features"' in line
                        and 'features=$(field build.kernel_image.EXTERNAL_KERNEL_FEATURES' in source):
                    continue
                raise ValueError(f'{name}: reconstruction bypasses recorded kernel features')
            if not line.startswith('python3 "$root/scripts/served_kernel.py" '):
                raise ValueError(f'{name}: durable build bypasses shared feature policy')
    return count


class ServedKernelTests(unittest.TestCase):
    def test_all_builders_use_policy(self):
        found = {}
        references = set()
        for path in ROOT.iterdir():
            if path.suffix not in ('.py', '.sh') or path.name.startswith('test'):
                continue
            source = path.read_text()
            count = audit(path.name, source)
            if count:
                found[path.name] = count
            if classify_external_reference(path.name, source) is not None:
                references.add(path.name)
        self.assertEqual(found, BUILDERS)
        self.assertEqual(references, set(EXTERNAL_BUILD_REFERENCES))

    def test_unclassified_call_forms_are_refused(self):
        cases = {
            'keyword': 'subprocess.run(args=["make", "external-build"])',
            'concatenation': 'run(["make", "-C", k] + ["external-build"])',
            'variable': 'target = "external-build"; run(["make", target])',
            'starred': 'run(*["make", "external-build"])',
            'attribute': 'self.argv = ["make", "external-build"]; run(self.argv)',
            'direct': 'run(tool("make"), "external-build")',
            'single_quotes': "run(['make', 'external-build'])",
            'bytes': 'run([b"make", b"external-build"])',
            'unused': 'argv = ("make", "external-build")',
            'receipt_data': 'required = {"external-build", "EXTERNAL_INPUT=x"}',
        }
        for label, source in cases.items():
            with self.subTest(form=label), self.assertRaises(ValueError):
                classify_external_reference('unclassified-call.py', source)

    def test_reference_inventory_is_explicit_and_scoped(self):
        self.assertIsNone(classify_external_reference('new.py', 'run(["make", "other"])'))
        for name, reason in EXTERNAL_BUILD_REFERENCES.items():
            with self.subTest(file=name):
                self.assertTrue(reason)
                self.assertEqual(classify_external_reference(name, '"external-build"'), reason)

    def test_every_builder_bypass_is_rejected(self):
        for name in BUILDERS:
            source = (ROOT / name).read_text()
            mutant = source.replace('*kernel_make()', '"make"').replace(
                'python3 "$root/scripts/served_kernel.py"', 'make')
            if name == 'reconstruct-release.sh':
                mutant = mutant.replace('EXTERNAL_KERNEL_FEATURES="$features"', '')
            with self.subTest(builder=name), self.assertRaises(ValueError):
                audit(name, mutant)
        with self.assertRaises(ValueError):
            audit('new.py', 'subprocess.run(["make", "durable-iso"])')

    def test_effective_make_features_and_failure_status(self):
        with tempfile.TemporaryDirectory() as directory:
            makefile = Path(directory) / 'Makefile'
            makefile.write_text('durable-iso:\n\t@echo "$(EXTERNAL_KERNEL_FEATURES)"\n'
                                'fail:\n\t@exit 1\n')
            for inherited in ('', 'frame-reservation-experiment',
                              'frame-reservation-qualification'):
                env = dict(os.environ, EXTERNAL_KERNEL_FEATURES=inherited)
                result = subprocess.run([*served_kernel.kernel_make(), '-e', '--no-print-directory',
                                         '-C', directory, 'durable-iso'],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), 'frame-admission-v0')
            result = subprocess.run([*served_kernel.kernel_make(), '-C', directory, 'fail'],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_isolated_builder_imports(self):
        for name in BUILDERS:
            if name.endswith('.py'):
                with self.subTest(builder=name):
                    result = subprocess.run(
                        [sys.executable, '-I', '-c',
                         'import runpy, sys; runpy.run_path(sys.argv[1])', str(ROOT / name)],
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_callers_cannot_override_features(self):
        for value in ('', 'frame-reservation-experiment', 'frame-admission-v0,frame-reservation-experiment'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                served_kernel.main(['durable-iso', f'EXTERNAL_KERNEL_FEATURES={value}'])


if __name__ == '__main__':
    unittest.main()
