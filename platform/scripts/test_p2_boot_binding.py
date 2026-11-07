"""Canonical P2 launch/candidate binding controls. No QEMU is run."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import signal
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import boot_artifacts as ba
import operator_boot_binding as ob
import p2_boot_binding as p2
import media_operator as media_profile
from test_operator_boot_binding import fixture,elf


def iso(kernel,grub):
    def entry(name,block,size,directory=False):
        n=33+len(name)+(len(name)%2==0);record=bytearray(n);record[0]=n
        struct.pack_into('<II',record,2,block,0);struct.pack_into('>I',record,6,block)
        struct.pack_into('<I',record,10,size);struct.pack_into('>I',record,14,size)
        record[25]=2 if directory else 0;record[32]=len(name);record[33:33+len(name)]=name
        return record
    data=bytearray((25+(len(kernel)+2047)//2048)*2048)
    data[16*2048:16*2048+7]=b'\x01CD001\x01'
    struct.pack_into('<H',data,16*2048+128,2048);struct.pack_into('>H',data,16*2048+130,2048)
    root=entry(b'\0',20,2048,True);data[16*2048+156:16*2048+156+len(root)]=root
    boot=entry(b'BOOT',21,2048,True);data[20*2048:20*2048+len(boot)]=boot
    body=entry(b'ABSD-KERNEL;1',24,len(kernel))+entry(b'GRUB',22,2048,True)
    data[21*2048:21*2048+len(body)]=body
    config=entry(b'GRUB.CFG;1',23,len(grub));data[22*2048:22*2048+len(config)]=config
    data[23*2048:23*2048+len(grub)]=grub;data[24*2048:24*2048+len(kernel)]=kernel
    return bytes(data)


SERVED=b'insmod all_video\nset timeout=0\nmenuentry "ABSD durable step" {\n  multiboot2 /boot/absd-kernel durable=0 net fsd served nvme-write=absd\n  boot\n}\n'
IMPORT=SERVED.replace(b'durable=0 net fsd served',b'durable=4 ')


class Binding(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.kernel,_=fixture();self.iso=self.root/'image.iso';self.iso.write_bytes(iso(self.kernel,SERVED))
        self.disk=self.root/'disk';self.disk.write_bytes(b'owned fixture disk')
        self.qemu=self.root/'qemu';self.qemu.write_bytes(b'executable fixture')
        self.release=self.root/'release';self.release.mkdir()
        files={}
        for name,role in [('sshd.elf','external-workload'),('fixture-import.elf','external-workload'),('absd-fsd.elf','file-server')]:
            payload=bytes(elf(role.encode()));(self.release/name).write_bytes(payload)
            files[name]=hashlib.sha256(payload).hexdigest()
        raw='[artifacts.files]\n'+''.join('"'+name+'"={sha256="'+pin+'"}\n' for name,pin in files.items())
        (self.release/'release-manifest.toml').write_text(raw)
        self.releases=[{'path':str(self.release),'manifest_sha256':ba.sha(self.release/'release-manifest.toml')}]
        self.inputs=self.root/'inputs.json';self.receipts=self.root/'receipts'
        p2.prepare(self.inputs,self.qemu,ba.sha(self.qemu),self.releases,self.receipts)

    def test_real_adapter_entrypoint_isolated_python_reaches_input_validation(self):
        # Exercise App A's actual interpreter flags from an unrelated cwd.
        # Deliberately invalid bound inputs must reach the real proxy's refusal,
        # without creating a QEMU process or a launch receipt.
        self.inputs.write_text(json.dumps({'schema': 'invalid'}))
        command = [sys.executable, '-I', '-B', '-X', 'pycache_prefix=' + str(self.root / 'cache'),
                   str(Path(p2.__file__).with_name('p2-bound-qemu.py')),
                   '-accel', 'tcg', '-cpu', 'max,vendor=GenuineIntel,+rdrand']
        done = subprocess.run(command, env=dict(os.environ, ABSD_P2_BOUND_INPUTS=str(self.inputs)),
                              capture_output=True, text=True, cwd=self.root)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('P2 bound input schema differs', done.stderr)
        self.assertNotIn('ModuleNotFoundError', done.stderr)
        self.assertFalse(list(self.receipts.iterdir()))

    def test_structured_iso_and_active_served_catalog(self):
        self.assertEqual(ob.iso_payload(self.iso.read_bytes()),(bytes(self.kernel),SERVED))
        found=p2.inspect_iso(self.iso.read_bytes(),self.releases)
        self.assertEqual(found['profile'],'served')
        self.assertEqual([e['name'] for e in found['matches'][0]['catalog']['selected']],['external-workload','file-server'])

    def test_importer_profile_is_exact_and_binds_its_active_worker(self):
        found=p2.inspect_iso(iso(self.kernel,IMPORT),self.releases)
        self.assertEqual(found['profile'],'importer')
        self.assertEqual([e['name'] for e in found['matches'][0]['catalog']['selected']],['external-workload'])

    def test_other_grub_command_or_step_refused(self):
        for grub in (IMPORT.replace(b'durable=4',b'durable=6'),SERVED.replace(b'  boot\n',b'  set root=hd0\n  boot\n')):
            with self.subTest(grub=grub),self.assertRaises(ValueError):p2.inspect_iso(iso(self.kernel,grub),self.releases)

    def test_wrong_manifest_or_consumed_elf_refused(self):
        (self.release/'sshd.elf').write_bytes(b'changed ELF')
        with self.assertRaisesRegex(ba.Refused,'consumed release ELF'):p2.inspect_iso(self.iso.read_bytes(),self.releases)
        with self.assertRaisesRegex(ba.Refused,'manifest differs'):p2.release_inputs(self.release,'0'*64)

    def test_catalog_decoy_does_not_bind_actual_slot(self):
        # Re-pin a different actual candidate input, while the catalog stays original.
        path=self.release/'sshd.elf';path.write_bytes(elf(b'file-server'))
        raw=(self.release/'release-manifest.toml').read_text().replace(hashlib.sha256(elf(b'external-workload')).hexdigest(),ba.sha(path),1)
        (self.release/'release-manifest.toml').write_text(raw);self.releases[0]['manifest_sha256']=ba.sha(self.release/'release-manifest.toml')
        with self.assertRaisesRegex(ba.Refused,'admitted active'):p2.inspect_iso(self.iso.read_bytes(),self.releases)

    def test_proxy_preserves_argv_process_group_status_and_exact_inputs(self):
        argv=['-cpu','max,vendor=GenuineIntel,+rdrand','-cdrom',str(self.iso),'-drive',f'file={self.disk},format=raw,if=ide,index=0',
              '-display','none','-no-reboot','-no-shutdown']
        calls=[]
        class Process:
            def wait(self):return 7
        def launch(command,**kwargs):
            calls.append((command,kwargs));Path(kwargs['record_path']).write_text(json.dumps({'admitted':True,'iso_sha256':kwargs['iso_sha256']}));return Process()
        with patch.dict(os.environ,{'ABSD_P2_BOUND_INPUTS':str(self.inputs)}),patch.object(p2.ba,'launch',side_effect=launch):
            self.assertEqual(p2.proxy(argv),7)
        self.assertEqual(calls[0][0],[str(self.qemu),*argv])
        self.assertNotIn('start_new_session',calls[0][1])
        self.assertEqual(calls[0][1]['iso_sha256'],ba.sha(self.iso))
        self.assertEqual(calls[0][1]['disk_sha256'],ba.sha(self.disk))
        self.assertEqual(p2.terminal_bindings(self.receipts),1)
        next(self.receipts.glob('*.catalog.json')).unlink()
        with self.assertRaisesRegex(ba.Refused,'inventory incomplete'):p2.terminal_bindings(self.receipts)

    def test_profile_importer_uses_explicit_pinned_handoff(self):
        env={}
        command=media_profile.bound_importer_qemu(self.release,str(self.qemu),self.inputs,ba.sha(self.inputs),env)
        self.assertIn('p2-bound-qemu.py',command)
        self.assertEqual(env['ABSD_P2_BOUND_INPUTS'],str(self.inputs))
        self.assertEqual(env['ABSD_BLOCK_ATTACH'],'ata')
        with self.assertRaisesRegex(ba.Refused,'input pin'):
            media_profile.bound_importer_qemu(self.release,str(self.qemu),self.inputs,'0'*64,{})
        (self.release/'sshd.elf').write_bytes(b'changed')
        with self.assertRaises(ba.Refused):
            media_profile.bound_importer_qemu(self.release,str(self.qemu),self.inputs,ba.sha(self.inputs),{})

    def test_profile_boot_binds_actual_catalog_and_inputs(self):
        kernel=self.root/'kernel';binary=kernel/media_profile.KERNEL_OUTPUT;binary.parent.mkdir(parents=True)
        binary.write_bytes(self.kernel)
        tree=kernel/'build/durable/iso-0';(tree/'boot/grub').mkdir(parents=True);(tree/'boot/grub/grub.cfg').write_bytes(SERVED)
        (tree/'boot/absd-kernel').write_bytes(self.kernel)
        profile={'kernel':{'durable_tree':'build/durable/iso-0'},'expect':{'iso_files':['boot/absd-kernel','boot/grub/grub.cfg'],'grub_entry':'durable=0 net fsd served'}}
        with patch.object(ba,'launch',return_value='owned process') as launch:
            process,catalog=media_profile.bound_operator_launch([str(self.qemu)],self.iso,self.disk,ba.sha(self.iso),ba.sha(self.disk),
                kernel,self.release,profile,self.root/'launch.json')
        self.assertEqual(process,'owned process')
        self.assertEqual([entry['name'] for entry in catalog['selected']],['external-workload','file-server'])
        self.assertEqual(launch.call_args.kwargs['iso_sha256'],ba.sha(self.iso))
        (self.release/'sshd.elf').write_bytes(b'changed')
        with patch.object(ba,'launch') as launch:
            with self.assertRaises(ob.BindingError):
                media_profile.bound_operator_launch([str(self.qemu)],self.iso,self.disk,ba.sha(self.iso),ba.sha(self.disk),
                    kernel,self.release,profile,self.root/'launch.json')
            launch.assert_not_called()

    def test_explicit_release_qemu_selection_is_consumed(self):
        spec=importlib.util.spec_from_file_location('explicit_release',Path(__file__).with_name('release.py'))
        module=importlib.util.module_from_spec(spec)
        configured=str(self.qemu)+' -accel tcg -cpu max,vendor=GenuineIntel,+rdrand'
        with patch.dict(os.environ,{'ABSD_RELEASE_QEMU':configured}):spec.loader.exec_module(module)
        self.assertEqual(module.QEMU,configured)
        with patch.object(module.subprocess,'run',return_value=SimpleNamespace(stdout='3\n')) as run:
            self.assertEqual(module.run_boot(Path('/kernel/durable-boot.sh'),self.iso,self.disk,self.root/'serial'),'3')
        self.assertEqual(run.call_args.args[0][5],str(self.qemu))

    def test_bound_matrix_main_rebinds_actual_module_not_ignored_environment(self):
        spec=importlib.util.spec_from_file_location('bound_p2_main',Path(__file__).with_name('recovery-point-matrix.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        original=module.rel.QEMU;evidence=self.root/'main-evidence';evidence.mkdir();observed=[]
        class Matrix:
            def __init__(inner,args):
                inner.evidence=evidence;inner.A=inner.B=SimpleNamespace(path=self.release)
                inner.original_run_boot=module.rel.run_boot;inner.traced_importer_boot=lambda *args:None
            def run(inner):
                observed.append(list(module.rel.QEMU))
                record=json.loads(Path(os.environ['ABSD_P2_BOUND_INPUTS']).read_text())
                self.assertEqual(record['qemu'],str(self.qemu))
            def finish(inner,error):
                self.assertIsNone(error);self.assertEqual(module.rel.QEMU,original);return True
        args=['runner','--release-a',str(self.release),'--release-b',str(self.release),'--source-a','a'*40,'--source-b','b'*40,
              '--ancestry','unused','--ancestry-sha256','f'*64,'--kernel','unused','--key','unused',
              '--private-work','unused','--evidence',str(evidence),'--bound-qemu',str(self.qemu),
              '--bound-qemu-sha256',ba.sha(self.qemu),'--release-a-manifest-sha256',self.releases[0]['manifest_sha256'],
              '--release-b-manifest-sha256',self.releases[0]['manifest_sha256']]
        with patch.object(module,'Matrix',Matrix),patch.object(sys,'argv',args):self.assertEqual(module.main(),0)
        self.assertEqual(observed[0][0],sys.executable)
        self.assertTrue(observed[0][1].endswith('/p2-bound-qemu.py'))

    def test_adapter_reflects_child_signal_to_its_parent(self):
        argv=['-cdrom',str(self.iso),'-drive',f'file={self.disk},format=raw,if=ide,index=0','-display','none']
        code=("import sys;sys.path.insert(0,"+repr(str(Path(__file__).parent))+");"
              "from unittest.mock import patch;from types import SimpleNamespace;import p2_boot_binding as p;"
              "patch.object(p.ba,'launch',return_value=SimpleNamespace(wait=lambda:-9)).start();"
              "sys.exit(p.proxy("+repr(argv)+"))")
        env={**os.environ,'ABSD_P2_BOUND_INPUTS':str(self.inputs)}
        done=subprocess.run([sys.executable,'-I','-B','-X',f"pycache_prefix={sys.pycache_prefix or ''}",'-c',code],env=env,capture_output=True)
        self.assertEqual(done.returncode,-signal.SIGKILL,done.stderr)

    def test_unclean_stop_targets_actual_owned_qemu_identity(self):
        record={'admitted':True,'requested_command':['qemu','-serial','file:/serial'],
                'pid':123,'start_ticks':'456'}
        (self.receipts/'stop.launch.json').write_text(json.dumps(record))
        fields=['S','999']+['0']*17+['456']
        original=Path.read_text
        def read(path,*args,**kwargs):
            return '123 (owned qemu) '+' '.join(fields) if str(path)=='/proc/123/stat' else original(path,*args,**kwargs)
        with patch.object(Path,'read_text',read),patch.object(p2.os,'kill') as kill:
            p2.kill_served(999,'/serial',self.receipts)
            kill.assert_called_once_with(123,signal.SIGKILL)
        fields[19]='different'
        with patch.object(Path,'read_text',read),patch.object(p2.os,'kill') as kill:
            with self.assertRaisesRegex(ba.Refused,'process identity differs'):p2.kill_served(999,'/serial',self.receipts)
            kill.assert_not_called()

    def test_proxy_refuses_noncanonical_drive_before_launch(self):
        argv=['-cdrom',str(self.iso),'-drive',f'file={self.disk},format=raw,if=virtio','-display','none']
        with patch.dict(os.environ,{'ABSD_P2_BOUND_INPUTS':str(self.inputs)}),patch.object(p2.ba,'launch') as launch:
            with self.assertRaisesRegex(ba.Refused,'noncanonical'):p2.proxy(argv)
            launch.assert_not_called()


if __name__=='__main__':unittest.main()
