#!/usr/bin/env python3
"""Check real fixture observations plus refusal controls; never launch a guest."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('reset_oracle', HERE / 'check-acpi-reset.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--evidence', type=Path, required=True, help='root containing actual named GDB fixture observations')
args = parser.parse_args()


class Controls(unittest.TestCase):
    def test_actual_consumer_matrix(self):
        for name, mode, accepted in [('fadt', 'fadt', True), ('legacy', 'legacy', True),
                                     ('wrong-value', 'fadt', False), ('missing', 'fadt', False), ('unexecuted', 'fadt', False)]:
            with self.subTest(name=name):
                if accepted:
                    result = oracle.check_observation(args.evidence / name, mode, 'Disabled' if mode == 'legacy' else None, fixture=True)
                    self.assertEqual(result['cf9_values'], [15] if mode == 'fadt' else [2, 6])
                else:
                    with self.assertRaisesRegex(ValueError, 'CF9 sequence mismatch'):
                        oracle.check_observation(args.evidence / name, mode, fixture=True)

    def test_located_but_not_executed_refuses(self):
        self.mutated(lambda rows: [row for row in rows if row['event'] != 'step-issued'])

    def test_missing_terminal_execution_refuses(self):
        self.mutated(lambda rows: [row for row in rows if row['event'] not in ('step-disconnected', 'step-target-exited', 'after-step')])

    def test_wrong_value_port_opcode_and_pc_refuse(self):
        for key, value in [('al', 14), ('dx', 0x80), ('opcode_hex', '90'), ('pc', 0x1234)]:
            def alter(rows):
                for row in rows:
                    if row['event'] == 'before-out':
                        row[key] = value
                return rows
            with self.subTest(key=key):
                self.mutated(alter)

    def test_prefix_and_caller_refuse(self):
        for event, key, value in [('before-out', 'prefix_sha256', '0' * 64), ('reset-entry', 'return_pc', 0x1234)]:
            def alter(rows):
                for row in rows:
                    if row['event'] == event:
                        row[key] = value
                return rows
            with self.subTest(key=key):
                self.mutated(alter)

    def test_fixture_cannot_certify_product(self):
        with self.assertRaisesRegex(ValueError, 'fixture/product identity boundary'):
            oracle.check_observation(args.evidence / 'fadt', 'fadt')

    def test_legacy_after_fadt_refuses(self):
        # A real legacy observation checked against the FADT contract cannot pass.
        with self.assertRaisesRegex(ValueError, 'CF9 sequence mismatch'):
            oracle.check_observation(args.evidence / 'legacy', 'fadt', fixture=True)

    def test_natural_exit_and_cleanup_required(self):
        for changed in ['qemu-exit', 'cleanup']:
            with tempfile.TemporaryDirectory(prefix='.oracle-control-', dir=args.evidence) as directory:
                out = Path(directory) / 'observation'
                shutil.copytree(args.evidence / 'fadt', out)
                result = json.loads((out / 'result.json').read_text())
                if changed == 'qemu-exit':
                    result['children']['qemu']['exit'] = -15
                else:
                    result['cleanup'] = [{'child': 'qemu', 'signal': 'SIGTERM'}]
                (out / 'result.json').write_text(json.dumps(result))
                with self.assertRaises(ValueError):
                    oracle.check_observation(out, 'fadt', fixture=True)

    def test_exact_serial_contract(self):
        prefix = ('HEAP OK\nMACHINE RECOVER TEST handing recover-only handle\n'
                  'SPAWN OK pid=2 parent=1 program=machine-probe\n'
                  'SERVED RECOVERY CENSUS processes=2 handles=5\nMACHINE RECOVER RESET pid=2\n')
        for expected in ['Disabled', 'Missing', 'Walk']:
            text = prefix + f'ACPI RESET UNAVAILABLE reason={expected} fallback=legacy\n'
            oracle.serial_contract('legacy', text, expected)
            for actual in ['Disabled', 'Missing', 'Walk', 'Unknown', '', expected + 'Extra']:
                if actual == expected:
                    continue
                changed = prefix + f'ACPI RESET UNAVAILABLE reason={actual} fallback=legacy\n'
                with self.assertRaises(ValueError):
                    oracle.serial_contract('legacy', changed, expected)
            for changed in [prefix, text + text[len(prefix):], text + 'ACPI RESET ARMED\n', text.replace('processes=2', 'processes=3'), text.replace('pid=2 parent=1', 'pid=1 parent=1'), text + 'SERVED SHUTDOWN\n']:
                with self.assertRaises(ValueError):
                    oracle.serial_contract('legacy', changed, expected)
        fadt = prefix + 'ACPI OK\nACPI RESET ARMED profile=q35-byte-io port=0xcf9 value=0x0f\nACPI RESET ATTEMPT port=0xcf9 value=0x0f\n'
        oracle.serial_contract('fadt', fadt)
        with self.assertRaises(ValueError):
            oracle.serial_contract('fadt', fadt + 'ACPI RESET RETURNED fallback=legacy\n')

    def mutated(self, transform):
        with tempfile.TemporaryDirectory(prefix='.oracle-control-', dir=args.evidence) as directory:
            out = Path(directory) / 'observation'
            shutil.copytree(args.evidence / 'fadt', out)
            path = out / 'observations.jsonl'
            rows = transform([json.loads(line) for line in path.read_text().splitlines()])
            for index, row in enumerate(rows):
                row['sequence'] = index
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            result = json.loads((out / 'result.json').read_text())
            result['evidence_sha256']['observations.jsonl'] = hashlib.sha256(path.read_bytes()).hexdigest()
            (out / 'result.json').write_text(json.dumps(result))
            with self.assertRaises(ValueError):
                oracle.check_observation(out, 'fadt', fixture=True)


suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
