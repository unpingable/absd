"""The selected tranche must reach the operator image with manuals and cases."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('operator_image', ROOT / 'scripts/operator_image.py')
oi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oi)


class Toolbox(unittest.TestCase):
    def test_selected_utilities_are_built_and_exposed(self):
        utils = next(line.split()[2:] for line in (ROOT / 'userland/Makefile').read_text().splitlines()
                     if line.startswith('UTILS := '))
        for name in ('rmdir', 'paste'):
            with self.subTest(command=name):
                self.assertIn(name, utils)
                self.assertIn(name, oi.PORTS)
                self.assertTrue((ROOT / f'man/{name}.1').is_file())
                self.assertIn('\t' + name + '\t', (ROOT / 'userland/cases.tsv').read_text())


if __name__ == '__main__':
    unittest.main()
