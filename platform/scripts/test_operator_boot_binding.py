#!/usr/bin/env python3
"""Structured catalog controls: decoy bytes must never satisfy slot binding."""
import struct
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import operator_boot_binding as binding


def elf(payload=b''):
    data = bytearray(128 + len(payload))
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', data, 16, 2, 62)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HH', data, 54, 56, 1)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 4, 0, 0x100000, 0, len(data), len(data), 4096)
    data[128:] = payload
    return data


def fixture():
    body = bytearray(32 * len(binding.NAMES))
    table = 128
    for index, name in enumerate(binding.NAMES):
        np = 0x100000 + 128 + len(body)
        body += name.encode()
        image = elf(name.encode())
        ip = 0x100000 + 128 + len(body)
        body += image
        struct.pack_into('<QQQQ', body, index * 32, np, len(name), ip, len(image))
    return elf(body), table


class CatalogTests(unittest.TestCase):
    def test_real_logger_slot_is_bound_to_its_own_elf(self):
        kernel, _ = fixture()
        result = binding.verify_kernel_catalog(kernel, {'logd': bytes(elf(b'logd'))})
        self.assertEqual([r['index'] for r in result['selected']], [44])
        with self.assertRaises(binding.BindingError):
            binding.verify_kernel_catalog(kernel, {'logd': bytes(elf(b'file-server'))})

    def test_exact_named_slots(self):
        kernel, _ = fixture()
        expected = {name: bytes(elf(name.encode())) for name in ('init', 'external-workload', 'file-server')}
        result = binding.verify_kernel_catalog(kernel, expected)
        self.assertEqual([r['index'] for r in result['selected']], [0, 30, 38])

    def test_decoy_image_elsewhere_does_not_bind_slot(self):
        kernel, _ = fixture()
        # Exact requested bytes exist in another legitimate catalog slot.
        with self.assertRaisesRegex(binding.BindingError, 'catalog image differs'):
            binding.verify_kernel_catalog(kernel, {'external-workload': bytes(elf(b'file-server'))})

    def test_pointer_to_unmapped_bytes_rejected(self):
        kernel, table = fixture()
        struct.pack_into('<Q', kernel, table + 30 * 32 + 16, 0x90000000)
        with self.assertRaisesRegex(binding.BindingError, 'unique complete'):
            binding.verify_kernel_catalog(kernel, {'init': bytes(elf(b'init'))})

    def test_catalog_name_order_rejected(self):
        kernel, table = fixture()
        kernel[table:table + 32], kernel[table + 32:table + 64] = kernel[table + 32:table + 64], kernel[table:table + 32]
        with self.assertRaises(binding.BindingError):
            binding.verify_kernel_catalog(kernel, {'init': bytes(elf(b'init'))})

    def test_duplicate_complete_catalog_rejected(self):
        kernel, table = fixture()
        kernel.extend(b'\0' * (-len(kernel) % 8))
        kernel.extend(kernel[table:table + 32 * len(binding.NAMES)])
        struct.pack_into('<QQ', kernel, 64 + 32, len(kernel), len(kernel))
        with self.assertRaisesRegex(binding.BindingError, 'unique complete'):
            binding.verify_kernel_catalog(kernel, {'init': bytes(elf(b'init'))})

    def test_iso_missing_or_malformed_rejected(self):
        for data in (b'', b'\0' * 40000):
            with self.assertRaises(binding.BindingError):
                binding.verify_iso(data, b'kernel', b'grub')


class GrubTests(unittest.TestCase):
    CONFIG = b'''insmod all_video
set timeout=0
menuentry "ABSD durable step" {
  multiboot2 /boot/absd-kernel durable=0 net fsd served nvme-write=absd
  boot
}
'''

    def test_canonical_and_comments(self):
        binding.validate_operator_grub(self.CONFIG)
        binding.validate_operator_grub(b'# recorded config\n\n' + self.CONFIG)

    def test_each_count_requires_its_own_canonical_boot_word(self):
        configs = ((1, self.CONFIG),
                   (2, self.CONFIG.replace(b'served nvme', b'served smp-operator=2 nvme')),
                   (4, self.CONFIG.replace(b'served nvme', b'served smp-operator=4 nvme')),
                   (6, self.CONFIG.replace(b'served nvme', b'served smp-operator=6 nvme')))
        for selected in (1, 2, 4, 6):
            for actual, config in configs:
                with self.subTest(selected=selected, actual=actual):
                    if selected == actual:
                        binding.validate_operator_grub(config, selected)
                    else:
                        with self.assertRaises(binding.BindingError):
                            binding.validate_operator_grub(config, selected)
            for words in (b'smp-operator=0', b'smp-operator=1', b'smp-operator=3',
                          b'smp-operator=5', b'smp-operator=7', b'smp-operator=8',
                          b'smp-operator=04', b'smp-operator=4,cores=4',
                          b'smp-operator=2 smp-operator=2', b'smp-operator=4 smp-operator=6',
                          b'smp-operator=6 smp-operator=4'):
                config = self.CONFIG.replace(b'served nvme', b'served ' + words + b' nvme')
                with self.subTest(selected=selected, words=words), self.assertRaises(binding.BindingError):
                    binding.validate_operator_grub(config, selected)
            for first in (2, 4, 6):
                for second in (2, 4, 6):
                    config = self.CONFIG.replace(b'served nvme',
                             f'served smp-operator={first} smp-operator={second} nvme'.encode())
                    with self.subTest(selected=selected, first=first, second=second), self.assertRaises(binding.BindingError):
                        binding.validate_operator_grub(config, selected)

    def test_count_argument_requires_a_supported_integer(self):
        for count in (0, 3, 5, 7, 8, True, False, 1.0, 2.0, '2', None):
            with self.subTest(count=count), self.assertRaises(binding.BindingError):
                binding.validate_operator_grub(self.CONFIG, count)

    def test_additional_loader_commands_refused(self):
        for command in (b'multiboot2 /other', b'module /other', b'configfile /other',
                        b'chainloader /other', b'set root=other', b'boot; reboot'):
            with self.subTest(command=command), self.assertRaises(binding.BindingError):
                binding.validate_operator_grub(self.CONFIG + command + b'\n')

    def test_altered_boot_and_substitution_refused(self):
        for config in (self.CONFIG.replace(b'durable=0', b'durable=1'),
                       self.CONFIG.replace(b'/boot/absd-kernel', b'$kernel'),
                       self.CONFIG.replace(b'  boot', b'  boot; reboot')):
            with self.assertRaises(binding.BindingError):
                binding.validate_operator_grub(config)


if __name__ == '__main__':
    unittest.main()
