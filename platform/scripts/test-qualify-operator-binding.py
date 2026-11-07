#!/usr/bin/env python3
"""Independent controls for admission checks; no compiler or guest is launched."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('qualify_operator_binding', HERE / 'qualify-operator-binding.py')
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
REAL_VERIFY_ISO = q.ob.verify_iso
# Structural ELF fixture used by the catalog's own negative controls.
spec2 = importlib.util.spec_from_file_location('catalog_fixture', HERE / 'test_operator_boot_binding.py')
cf = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(cf)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'platform'
        self.root.mkdir()
        self.addCleanup(patch.stopall)
        patch.object(q, 'ROOT', self.root).start()
        patch.dict(os.environ, {'ABSD_HTTPS_DOCUMENT': '0'}).start()
        self.identity = {'revision': 'fixture-revision', 'tree': 'fixture-tree', 'git_archive_sha256': 'fixture-archive'}
        patch.object(q.br, 'source', return_value=self.identity).start()
        self.output = {}
        for index, name in enumerate(q.br.OUTPUTS):
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(bytes(cf.elf(('produced-' + str(index)).encode())))
            self.output[name] = {'sha256': q.ba.sha(p), 'bytes': p.stat().st_size}
        self.record = {'status': 'success', 'source': dict(self.identity), 'outputs': copy.deepcopy(self.output)}
        self.receipt = self.base / 'build.json'
        self.args = SimpleNamespace(build_receipt=self.receipt)
        self.save_receipt()

    def save_receipt(self):
        self.receipt.write_text(json.dumps(self.record))
        self.args.build_receipt_sha256 = q.ba.sha(self.receipt)

    def test_platform_success(self):
        self.assertEqual(q.platform_build(self.args), self.record)

    def test_platform_missing_expected_output(self):
        del self.record['outputs']['sshd.elf']
        self.save_receipt()
        with self.assertRaisesRegex(q.ba.Refused, 'incomplete'):
            q.platform_build(self.args)

    def test_enabled_document_requires_output_and_matching_selection(self):
        self.record['environment'] = {'ABSD_HTTPS_DOCUMENT': '1'}
        self.save_receipt()
        with patch.dict(os.environ, {'ABSD_HTTPS_DOCUMENT': '1'}):
            with self.assertRaisesRegex(q.ba.Refused, 'incomplete'):
                q.platform_build(self.args)
            app = self.root / 'commands/https-document'
            app.write_bytes(b'fresh app')
            self.record['outputs']['commands/https-document'] = {'sha256': q.ba.sha(app), 'bytes': app.stat().st_size}
            self.save_receipt()
            self.assertEqual(q.platform_build(self.args), self.record)
        with self.assertRaisesRegex(q.ba.Refused, 'selection differs'):
            q.platform_build(self.args)

    def test_media_binds_document_as_installed_not_executed(self):
        self.media()
        physical = q.release_record.physical('/bin/https-document', 'fixture')
        self.files[physical] = b'app'
        build = copy.deepcopy(self.record)
        build['outputs']['commands/https-document'] = {'sha256': sha(b'app'), 'bytes': 3}
        self.manifest()
        result = q.inspect_media(self.out, self.kernel, build)
        self.assertEqual(result['installed_apps'], {physical: sha(b'app')})
        self.assertNotIn(physical, result['executed_files'])
        self.files[physical] = b'changed'
        self.manifest()
        with self.assertRaisesRegex(q.ba.Refused, 'disk App A differs'):
            q.inspect_media(self.out, self.kernel, build)

    def test_platform_wrong_output_hash(self):
        (self.root / 'sshd.elf').write_bytes(b'different build')
        with self.assertRaisesRegex(q.ba.Refused, 'executable changed'):
            q.platform_build(self.args)

    def test_platform_stale_source(self):
        self.record['source']['revision'] = 'earlier-source'
        self.save_receipt()
        with self.assertRaisesRegex(q.ba.Refused, 'source differs'):
            q.platform_build(self.args)

    def test_platform_wrong_receipt_pin(self):
        self.args.build_receipt_sha256 = '0' * 64
        with self.assertRaisesRegex(q.ba.Refused, 'receipt identity changed'):
            q.platform_build(self.args)

    def media(self):
        self.out = self.base / 'media'
        self.out.mkdir()
        self.kernel = self.base / 'kernel'
        self.binary = self.kernel / 'build/external/target/debug/absd-kernel'
        self.binary.parent.mkdir(parents=True)
        kernel, _ = cf.fixture()
        self.binary.write_bytes(kernel)
        # Bind actual named fixture images, independent of q's output inventory.
        for name, slot in [('sshd.elf', 'external-workload'), ('absd-fsd.elf', 'file-server'),
                           ('absd-logd.elf', 'logd')]:
            (self.root / name).write_bytes(cf.elf(slot.encode()))
        config = self.kernel / 'build/durable/iso-0/boot/grub/grub.cfg'
        config.parent.mkdir(parents=True)
        config.write_bytes(b'insmod all_video\nset timeout=0\nmenuentry "ABSD durable step" {\n  multiboot2 /boot/absd-kernel durable=0 net fsd served nvme-write=absd\n  boot\n}\n')
        (self.out / q.op.ISO).write_bytes(b'fixture ISO handled by independent verifier')
        (self.out / q.op.IMAGE).write_bytes(b'fixture disk handled by canonical reader')
        self.files = {'/absd/selected': q.release_record.selected_bytes('fixture')}
        for command in ('uname', 'sha256sum', 'absd-sh', 'release'):
            self.files[q.release_record.physical('/bin/' + command, 'fixture')] = (self.root / 'commands' / command).read_bytes()
        self.manifest()
        patch.object(q.op, 'tree', side_effect=lambda _: dict(self.files)).start()
        # ISO validation is independently tested against retained real ISO below;
        # these cases exercise disk/catalog composition with it held successful.
        patch.object(q.ob, 'verify_iso', return_value={'fixture': 'iso verified'}).start()

    def manifest(self):
        lines = ['file ' + sha(data) + ' ' + name for name, data in self.files.items()]
        lines += ['iso ' + q.ba.sha(self.out / q.op.ISO)]
        (self.out / 'MANIFEST').write_text('\n'.join(lines) + '\n')

    def test_media_success_named_slots_and_selected_disk(self):
        self.media()
        got = q.inspect_media(self.out, self.kernel, self.record)
        self.assertEqual(got['selected_release'], 'fixture')
        self.assertEqual(len(got['executed_files']), 4)

    def test_media_wrong_disk_elf_even_with_consistent_manifest(self):
        self.media()
        path = q.release_record.physical('/bin/uname', 'fixture')
        self.files[path] = bytes(cf.elf(b'substituted uname'))
        self.manifest()
        with self.assertRaisesRegex(q.ba.Refused, 'disk executable differs'):
            q.inspect_media(self.out, self.kernel, self.record)

    def test_media_wrong_catalog_slot_even_when_expected_bytes_elsewhere(self):
        self.media()
        # file-server's exact ELF is in the kernel, but not in worker's slot.
        (self.root / 'sshd.elf').write_bytes(cf.elf(b'file-server'))
        with self.assertRaisesRegex(q.ob.BindingError, 'catalog image differs'):
            q.inspect_media(self.out, self.kernel, self.record)

    def test_inspect_media_rejects_iso_kernel_mismatch_before_disk_checks(self):
        self.media()
        if not os.environ.get('ABSD_TEST_OPERATOR_ISO'):
            self.skipTest('set ABSD_TEST_OPERATOR_ISO for retained-media checks')
        retained = Path(os.environ['ABSD_TEST_OPERATOR_ISO'])
        if not retained.exists():
            self.skipTest('retained operator ISO unavailable')
        (self.out / q.op.ISO).write_bytes(retained.read_bytes())
        # The fixture kernel is a valid catalog, but is not this ISO's kernel.
        with patch.object(q.ob, 'verify_iso', side_effect=REAL_VERIFY_ISO):
            with self.assertRaisesRegex(q.ob.BindingError, "ISO"):
                q.inspect_media(self.out, self.kernel, self.record)

    def test_media_manifest_cannot_hide_extra_disk_file(self):
        self.media()
        self.files['/unexpected'] = b'not admitted in manifest'
        with self.assertRaisesRegex(q.ba.Refused, 'manifest differs'):
            q.inspect_media(self.out, self.kernel, self.record)


class RetainedISOTests(unittest.TestCase):
    def test_retained_iso_rejects_different_kernel_and_configuration(self):
        if not os.environ.get('ABSD_TEST_OPERATOR_ISO'):
            self.skipTest('set ABSD_TEST_OPERATOR_ISO for retained-media checks')
        iso = Path(os.environ['ABSD_TEST_OPERATOR_ISO'])
        if not os.environ.get('ABSD_TEST_OPERATOR_EXTRACTION'):
            self.skipTest('set ABSD_TEST_OPERATOR_EXTRACTION for retained-media checks')
        extracted = Path(os.environ['ABSD_TEST_OPERATOR_EXTRACTION'])
        if not iso.exists() or not (extracted / 'absd-kernel.extracted').exists():
            self.skipTest('retained operator ISO extraction unavailable')
        raw, kernel, grub = iso.read_bytes(), (extracted / 'absd-kernel.extracted').read_bytes(), (extracted / 'grub.cfg').read_bytes()
        q.ob.verify_iso(raw, kernel, grub)
        for wrong_kernel, wrong_grub in [(kernel[:-1] + bytes([kernel[-1] ^ 1]), grub), (kernel, grub + b'changed')]:
            with self.assertRaises(q.ob.BindingError):
                q.ob.verify_iso(raw, wrong_kernel, wrong_grub)


class TerminalMediaTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.out=self.root/'out';self.results=self.root/'results'
        self.out.mkdir();self.results.mkdir()
        self.binding={'media':{'iso_sha256':'a'*64,'disk_sha256':'b'*64},'qemu_sha256':'c'*64}
        (self.out/'BOOT-BINDING.json').write_text(json.dumps(self.binding));self.pin=q.ba.sha(self.out/'BOOT-BINDING.json')
        self.launch={'admitted':True,'iso_sha256':'a'*64,'disk_before_sha256':'b'*64,'qemu_sha256':'c'*64}
        self.result={'passed':True,'binding_sha256':self.pin,'qemu_status':3,'disk_retired':True}
        (self.results/'console.log').write_bytes(b'actual local console fixture')
        self.result['console_sha256']=q.ba.sha(self.results/'console.log')
        self.save()

    def save(self):
        (self.results/'LAUNCH.json').write_text(json.dumps(self.launch))
        self.result['launch_sha256']=q.ba.sha(self.results/'LAUNCH.json')
        (self.results/'RESULT.json').write_text(json.dumps(self.result))

    def test_actual_terminal_chain_passes(self):
        self.assertEqual(q.execution_status(self.out,self.results,self.pin),self.result)

    def test_changed_raw_console_refuses(self):
        (self.results/'console.log').write_bytes(b'changed')
        with self.assertRaisesRegex(q.ba.Refused,'console identity'):q.execution_status(self.out,self.results,self.pin)

    def test_pass_label_without_launch_is_insufficient(self):
        (self.results/'LAUNCH.json').unlink()
        with self.assertRaises(OSError):q.execution_status(self.out,self.results,self.pin)

    def test_wrong_terminal_or_binding_refuses(self):
        for key,value in [('passed',False),('binding_sha256','0'*64),('qemu_status',7),('disk_retired',False)]:
            with self.subTest(key=key):
                old=self.result[key];self.result[key]=value;self.save()
                with self.assertRaises(q.ba.Refused):q.execution_status(self.out,self.results,self.pin)
                self.result[key]=old

    def test_launch_input_substitution_or_nonadmission_refuses(self):
        for key,value in [('admitted',False),('iso_sha256','0'*64),('disk_before_sha256','0'*64),('qemu_sha256','0'*64)]:
            with self.subTest(key=key):
                old=self.launch[key];self.launch[key]=value;self.save()
                with self.assertRaises(q.ba.Refused):q.execution_status(self.out,self.results,self.pin)
                self.launch[key]=old


if __name__ == '__main__':
    unittest.main()
