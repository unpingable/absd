"""Exercise shell declaration and actual image composition before writes."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parent))
import operator_image as oi

class Packaging(unittest.TestCase):
    def test_live_terminal_observer_is_installed(self):
        self.assertIn('terminal-size', oi.command_names())
        self.assertIn('terminal-size', __import__('operator_build_receipt').COMMANDS)

    def test_shell_alias_is_declared_and_has_canonical_manual(self):
        self.assertIn('sh',oi.command_names())
        self.assertEqual((oi.ROOT/'man/sh.1').is_file(),True)

    def test_composition_refuses_a_different_shell_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'commands').mkdir()
            (root/'commands/absd-sh').write_bytes(b'canonical shell')
            (root/'commands/sh').write_bytes(b'different shell')
            (root/'man').mkdir(); (root/'manpages/cat1').mkdir(parents=True)
            for name in ('absd-sh', 'sh'):
                (root/'man'/f'{name}.1').write_text(f'.Dt {name.upper()} 1\n.Nd shell\n')
                (root/'manpages/cat1'/f'{name}.0').write_bytes(b'shell manual\n')
            (root/'manpages/whatis').write_bytes(b'absd-sh(1) - shell\nsh(1) - shell\n')
            with mock.patch.object(oi,'NATIVE',[]),mock.patch.object(oi,'PORTS',[]),mock.patch.object(oi,'RUST_PORTS',[]),mock.patch.object(oi,'c_ports_installed',return_value={}):
                with self.assertRaisesRegex(oi.Failed,'byte-identical'):
                    oi.system_files(root)

if __name__=='__main__': unittest.main()
