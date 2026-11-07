#!/usr/bin/env python3
"""Legacy clean-evidence boundary, using the same vectors as Rust recovery."""
from pathlib import Path
import hashlib
import importlib.util
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import absd_fs
import storage_fence_host as host
import storage_fence_upgrade as upgrade
import storage_fence_state as guard

VECTORS = Path(__file__).resolve().parents[1] / 'fixtures/storage-fence'
BOOT = '0123456789abcdef0123456789abcdef'


def fixture():
    tree = {'/var/state/recovery.init': b'',
            '/var/state/recovery': (VECTORS/'recovery-v1-ledger.bin').read_bytes()}
    for name in ('ready', 'end', 'stopped', 'completed'):
        tree['/var/state/facts/served-'+name] = (VECTORS/('recovery-v1-'+name+'.bin')).read_bytes()
    console = ('ABSD KERNEL BOOT\nFSD RECOVERY seq=7 streak=2 previous=failed\n'
               'FSD READY channels=1\nFSD STOPPED served=1 commits=1\n'
               'SERVED SHUTDOWN action=halt worker_status=0 file_server_status=0 orphans_reaped=0 drained=true\n'
               'FSD FINALIZED boot='+BOOT+'\nSERVED SHUTDOWN FINALIZED status=0\nABSD BOOT OK\n')
    return tree, console


class CleanEvidence(unittest.TestCase):
    def test_shared_vectors_preserve_ledger_and_facts(self):
        tree, console = fixture()
        self.assertEqual(upgrade.clean_history(tree, console), {'seq':7,'streak':2,'boot':BOOT})
        for name in ('ready','stopped','completed'):
            self.assertEqual(tree['/var/state/facts/served-'+name], upgrade.fact(BOOT))
        self.assertEqual(tree['/var/state/facts/served-end'], upgrade.fact(BOOT,'halt'))

    def test_missing_and_mismatched_fact_never_establish_clean(self):
        tree, console = fixture()
        for path in tree:
            for value in (None, b'\0'*len(tree[path]), b'changed', tree[path].replace(BOOT.encode(), b'f'*32)):
                if value == tree[path]: continue
                changed = dict(tree)
                if value is None:del changed[path]
                else:changed[path]=value
                with self.subTest(path=path,value=value), self.assertRaises(ValueError):
                    upgrade.clean_history(changed,console)

    def test_every_changed_ledger_byte_refuses(self):
        raw = fixture()[0]['/var/state/recovery']
        for index in range(len(raw)):
            changed=bytearray(raw);changed[index]^=1
            with self.subTest(index=index),self.assertRaises(ValueError):upgrade.ledger(changed)

    def test_dirty_existing_guard_and_staging_never_reseed(self):
        tree,console=fixture()
        for path,value in [(guard.PATH,guard.encode(state)) for state in ('fresh','dirty','clean')]+[
                ('/var/state.new/recovery',b'')]:
            with self.subTest(path=path),self.assertRaises(ValueError):
                upgrade.clean_history(dict(tree,**{path:value}),console)

    def test_console_must_match_final_halted_generation(self):
        tree,console=fixture()
        for changed in ('',console.replace(BOOT,'f'*32),console.replace('seq=7','seq=8'),
                console.replace('streak=2','streak=0'),console.replace('status=0\n','status=3\n'),
                console.replace('drained=true','drained=false'),console.replace('action=halt','action=restart'),
                console.replace('FSD READY channels=1\n',''), console+console.split('ABSD KERNEL BOOT\n')[1],
                console+'ABSD KERNEL BOOT\n',console+'RECOVERY STATE REFUSED reason=lost\n',
                console.replace('FSD STOPPED served=1 commits=1\n','')+'FSD STOPPED served=1 commits=1\n'):
            with self.subTest(console=changed),self.assertRaises(ValueError):upgrade.clean_history(tree,changed)


spec=importlib.util.spec_from_file_location('upgrade_fs_vectors',Path(__file__).with_name('test_absd_fs.py'))
vectors=importlib.util.module_from_spec(spec);spec.loader.exec_module(vectors)


def disk(path, seed=None, *, changed_file=False, root_mtime=0, new_fs_id=False, slot=None):
    """Real format-2 sectors; only the guest importer is substituted below."""
    data=vectors.load('format2.sectors');raw=vectors.selected_raw(data)[:64]
    files,_=fixture()
    objects=[('/',None),('/var',None),('/var/state',None),('/var/state/facts',None),
             ('/etc',None),('/etc/motd',b'changed\n' if changed_file else b'original\n')]+sorted(files.items())
    if seed is not None:objects.append((guard.PATH,seed))
    if slot is not None:objects.append((guard.RESUME_PATH,slot))
    ids={name:index+1 for index,(name,_) in enumerate(objects)}
    struct.pack_into('<Q',raw,32,len(objects)+1);struct.pack_into('<I',raw,44,len(objects))
    block=0;geo=absd_fs.geometry(len(data)//512)
    for name,content in objects:
        directory=content is None;parent=0 if name=='/' else ids[str(Path(name).parent)]
        leaf=b'' if name=='/' else Path(name).name.encode()
        blocks=[] if not content else [block]
        if blocks:
            offset=geo['data_first']*512+block*4096
            data[offset:offset+len(content)]=content;block+=1
        raw+=struct.pack('<QQQBBHIQ',ids[name],parent,0 if directory else len(content),
                         2 if directory else 1,0,len(leaf),len(blocks),root_mtime if name=='/' else 0)
        raw+=leaf+b''.join(struct.pack('<I',b) for b in blocks)
    if new_fs_id:struct.pack_into('<Q',raw,16,vectors.FIXTURE_ID+1)
    vectors.resign(data,raw)
    if new_fs_id:
        for slot in (0,1):
            sector=bytearray(data[slot*512:(slot+1)*512]);struct.pack_into('<Q',sector,16,vectors.FIXTURE_ID+1)
            sector[480:]=hashlib.sha256(sector[:480]).digest();data[slot*512:(slot+1)*512]=sector
    path.write_bytes(data)


class Conversion(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'source.img';disk(self.source)
        self.output=self.root/'output.img';self.work=self.root/'work'
        self.original=self.source.read_bytes();self.halt_hash=upgrade.digest(self.source)
        self.console=fixture()[1]
        region=patch.object(absd_fs,'fs_region',lambda path,_:
                            absd_fs.Region(path,0,Path(path).stat().st_size//512))
        region.start();self.addCleanup(region.stop)
        importer=self.root/'fixture-import.elf';importer.write_bytes(b'host substitute; real guest control is separate')
        self.importer=Mock(side_effect=lambda kernel,image,*args,**kwargs:disk(image,guard.encode('clean'),slot=guard.RESUME_NONE))
        self.oi=SimpleNamespace(ROOT=self.root,import_boots=self.importer,identity=lambda _: 'host-fixture')
        self.release=SimpleNamespace(refuse_in_use=Mock(),storage_fence_host=host)

    def convert(self,**kwargs):
        options=dict(attest_no_writes_since_halt=True,halt_image_sha256=self.halt_hash);options.update(kwargs)
        return upgrade.convert(self.source,self.output,self.console,self.work,self.root,
                               oi=self.oi,release=self.release,**options)

    def test_convert_preserves_real_source_history_namespace_and_distinct_inode(self):
        result=self.convert()
        self.assertEqual(self.source.read_bytes(),self.original)
        self.assertNotEqual(self.source.stat().st_ino,self.output.stat().st_ino)
        self.assertEqual(self.output.stat().st_nlink,1)
        self.assertEqual(upgrade.inspect(self.output)[0],dict(fixture()[0],**{
            '/etc/motd':b'original\n',guard.PATH:guard.encode('clean'),guard.RESUME_PATH:guard.RESUME_NONE}))
        self.assertEqual(result['preserved_recovery'],{'seq':7,'streak':2,'boot':BOOT})
        self.assertEqual(result['disposition'],'PREPARED_UNACTIVATED')

    def test_unattested_conversion_is_off_by_default(self):
        with self.assertRaisesRegex(ValueError,'attestation'):self.convert(attest_no_writes_since_halt=False)
        self.assertFalse(self.work.exists());self.assertFalse(self.output.exists());self.importer.assert_not_called()

    def test_post_halt_nonledger_host_write_refuses_before_allocation(self):
        disk(self.source,changed_file=True)
        self.assertEqual(upgrade.clean_history(upgrade.inspect(self.source)[0],self.console)['seq'],7)
        with self.assertRaisesRegex(ValueError,'image changed since'):self.convert()
        self.assertFalse(self.work.exists());self.assertFalse(self.output.exists());self.importer.assert_not_called()

    def test_existing_guard_is_never_reseeded(self):
        for state in ('fresh','dirty','clean'):
            disk(self.source,guard.encode(state));self.halt_hash=upgrade.digest(self.source)
            with self.subTest(state=state),self.assertRaisesRegex(ValueError,'existing guard'):self.convert()
            self.assertFalse(self.work.exists());self.assertFalse(self.output.exists())
        self.importer.assert_not_called()

    def test_existing_resume_slot_is_refused_like_a_guard(self):
        disk(self.source,slot=guard.RESUME_NONE);self.halt_hash=upgrade.digest(self.source)
        with self.assertRaisesRegex(ValueError,'existing guard, resume slot'):self.convert()
        self.assertFalse(self.work.exists());self.assertFalse(self.output.exists());self.importer.assert_not_called()

    def test_converter_seeds_the_resume_slot_beside_the_guard_and_widens_its_comparisons(self):
        self.importer.side_effect=lambda kernel,image,*args,**kwargs:disk(image,guard.encode('clean'))
        with self.assertRaisesRegex(ValueError,'conversion changed existing file content'):self.convert()
        self.assertFalse(self.output.exists())

    def test_partial_import_never_publishes_and_never_changes_source(self):
        def partial(kernel,image,*args,**kwargs):
            disk(image,guard.encode('clean'),slot=guard.RESUME_NONE);raise OSError('interrupted importer')
        self.importer.side_effect=partial
        with self.assertRaisesRegex(OSError,'interrupted'):self.convert()
        self.assertFalse(self.output.exists());self.assertEqual(self.source.read_bytes(),self.original)

    def test_different_filesystem_or_root_identity_refuses_publication(self):
        for options in ({'new_fs_id':True},{'root_mtime':1},{'changed_file':True}):
            with self.subTest(options=options),tempfile.TemporaryDirectory(dir=self.root) as parent:
                self.work=Path(parent)/'work'
                self.importer.side_effect=lambda kernel,image,*args,**kwargs:disk(image,guard.encode('clean'),slot=guard.RESUME_NONE,**options)
                with self.assertRaisesRegex(ValueError,'conversion changed'):self.convert()
                self.assertFalse(self.output.exists());self.assertEqual(self.source.read_bytes(),self.original)


if __name__=='__main__':unittest.main()
