#!/usr/bin/env python3
"""Actual boot builders must pass the real logger parameter; no compiler/guest."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class LoggerBootBinding(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='absd-logger-boot-binding-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.root = self.work / 'platform'
        self.kernel = self.work / 'kernel'
        self.root.mkdir()
        self.kernel.mkdir()
        (self.root / 'absd-logd.elf').write_bytes(b'fixture logger bytes, not an ELF')
        # Run the real builder/served_kernel/make boundary, independent of
        # whether the caller uses run() or drains Popen's output pipe.
        (self.kernel / 'Makefile').write_text(
            "durable-iso:\n"
            "\t@printf '%s\\n' 'LOGD_ELF=$(LOGD_ELF)' 'LOGD_FAULT=$(LOGD_FAULT)' > make-vars\n"
            "\t@mkdir -p build/durable\n"
            "\t@printf '%s\\n' 'fixture ISO: parameters only' > build/durable/absd-durable-$(DURABLE_STEP).iso\n")

    def variables(self):
        return dict(line.split('=', 1) for line in (self.kernel / 'make-vars').read_text().splitlines())

    def target(self, module, kind):
        target = kind.__new__(kind)
        target.root = self.root
        target.kernel = self.kernel
        target.work = self.work
        return target

    def check_served(self, target):
        target.iso(0, self.root / 'sshd.elf', options='net fsd served', server=self.root / 'absd-fsd.elf')
        self.assertEqual(self.variables().get('LOGD_ELF'), str(self.root / 'absd-logd.elf'))
        self.assertEqual(self.variables().get('LOGD_FAULT'), '0')

    def test_actual_ssh_builder_binds_logger(self):
        module = load('logger_binding_ssh', 'ssh_absd.py')
        self.check_served(self.target(module, module.AbsdTarget))

    def test_actual_served_matrix_builder_binds_logger(self):
        module = load('logger_binding_served', 'served-matrix.py')
        self.check_served(self.target(module, module.ServedTarget))

    def test_importer_boot_explicitly_clears_logger_and_fault(self):
        module = load('logger_binding_importer', 'ssh_absd.py')
        target = self.target(module, module.AbsdTarget)
        target.iso(4, self.root / 'fixture-import.elf', input_bytes=b'fixture')
        self.assertEqual(self.variables().get('LOGD_ELF'), '')
        self.assertEqual(self.variables().get('LOGD_FAULT'), '0')

    def test_storage_resume_release_builder_binds_logger(self):
        module = load('logger_binding_resume', 'storage-fence-resume-matrix.py')
        lane = types.SimpleNamespace(work=self.work, kernel=self.kernel, release=self.root)
        output = module.release_iso(lane, 'net fsd served')
        self.assertTrue(output.is_file())
        self.assertEqual(self.variables().get('LOGD_ELF'), str(self.root / 'absd-logd.elf'))
        self.assertEqual(self.variables().get('LOGD_FAULT'), '0')


if __name__ == '__main__':
    unittest.main()
