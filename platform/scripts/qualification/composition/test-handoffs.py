"""Actual shell handoffs with local producer substitutes; no build/VM."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).parent


class Handoffs(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.platform=self.root/'platform';self.run=self.root/'run';tools=self.run/'tools';self.bin=self.root/'bin'
        for p in (self.platform,tools,self.run/'logs',self.run/'work',self.bin):p.mkdir(parents=True,exist_ok=True)
        gate=tools/'gate.sh';gate.write_text('#!/bin/sh\nexit 0\n');gate.chmod(0o755)
        fake=self.bin/'python3'
        fake.write_text('#!'+sys.executable+'\n'+'''import hashlib,json,os,pathlib,sys,importlib.util
args=sys.argv[1:]
while args and args[0] in ('-I','-B'):args.pop(0)
script=pathlib.Path(args.pop(0)).name
run=pathlib.Path(os.environ['ABSD_COMPOSITION_RUN_ROOT'])
with (run/'calls.jsonl').open('a') as out:out.write(json.dumps({'script':script,'args':args})+'\\n')
if script=='recovery-point-matrix.py':sys.exit(int(os.environ.get('MOCK_FAIL','0')))
mode=args.pop(0)
if os.environ.get('MOCK_FAIL')==mode:sys.exit(9)
flags=dict(zip(args[::2],args[1::2]));out=pathlib.Path(flags['--out'])
if mode=='build':
 out.mkdir();(out/'BOOT-BINDING.json').write_text(json.dumps({'media':{'iso_sha256':'a'*64,'disk_sha256':'b'*64},'qemu_sha256':'c'*64}))
elif mode=='boot':
 results=pathlib.Path(flags['--results']);results.mkdir()
 (results/'console.log').write_bytes(b'local console fixture')
 launch=results/'LAUNCH.json';launch.write_text(json.dumps({'admitted':True,'iso_sha256':'a'*64,'disk_before_sha256':'b'*64,'qemu_sha256':'c'*64}))
 (results/'RESULT.json').write_text(json.dumps({'passed':True,'binding_sha256':flags['--binding-sha256'],'qemu_status':3,'disk_retired':True,'launch_sha256':hashlib.sha256(launch.read_bytes()).hexdigest(),'console_sha256':hashlib.sha256(b'local console fixture').hexdigest()}))
else:
 # The existing real terminal-status checker consumes the local fixture chain.
 path=pathlib.Path(os.environ['REAL_BINDING_TOOL']);sys.path.insert(0,str(path.parent))
 spec=importlib.util.spec_from_file_location('real_status',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 m.execution_status(out,pathlib.Path(flags['--results']),flags['--binding-sha256']);print('PASS')
''');fake.chmod(0o755)
        self.env={**os.environ,'PATH':str(self.bin)+os.pathsep+os.environ['PATH'],'ABSD_HTTPS_DOCUMENT':'1',
            'REAL_BINDING_TOOL':str(HERE.parents[1]/'qualify-operator-binding.py')}
        values={'PLATFORM':self.platform,'RUN_ROOT':self.run,'MEDIA_KERNEL':self.root/'KMEDIA','KERNEL_COMMIT':'f'*40,
            'QEMU':self.root/'qemu','QEMU_SHA256':'c'*64,'BUILD_RECEIPT':self.root/'build.json','BUILD_RECEIPT_SHA256':'d'*64,
            'KEY':self.root/'key','MEDIA_STATUS':self.run/'logs/media-status','P2_A':self.root/'A','P2_B':self.root/'B',
            'P2_A_MANIFEST_SHA256':'a'*64,'P2_B_MANIFEST_SHA256':'b'*64,'SOURCE_REVISION':'e'*40,
            'P2_ANCESTRY':self.root/'ancestry.json','P2_ANCESTRY_SHA256':'f'*64}
        self.env.update({'ABSD_COMPOSITION_'+key:str(value) for key,value in values.items()})

    def execute(self,script,fail=None):
        if fail:self.env['MOCK_FAIL']=fail
        return subprocess.run(['sh',str(HERE/script)],env=self.env,capture_output=True)

    def test_full_media_build_boot_and_actual_terminal_check_produce_status(self):
        result=self.execute('media.sh');self.assertEqual(result.returncode,0,result.stderr)
        calls=[json.loads(row) for row in (self.run/'calls.jsonl').read_text().splitlines()]
        self.assertEqual([row['args'][0] for row in calls],['build','boot','status'])
        self.assertEqual((self.run/'logs/media-status').read_text(),'PASS\n')

    def test_failed_boot_does_not_create_status(self):
        result=self.execute('media.sh','boot');self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.run/'logs/media-status').exists())

    def test_p2_handoff_requires_actual_binary_and_all_bound_pins(self):
        result=self.execute('p2.sh');self.assertEqual(result.returncode,0,result.stderr)
        call=json.loads((self.run/'calls.jsonl').read_text())
        flags=dict(zip(call['args'][::2],call['args'][1::2]))
        self.assertEqual(flags['--require-binary-change'],'tree/bin/https-document')
        self.assertEqual(flags['--bound-qemu'],self.env['ABSD_COMPOSITION_QEMU'])
        self.assertEqual(flags['--release-b-manifest-sha256'],'b'*64)
        self.assertEqual(flags['--source-a'],'03479a3e090e847ccdfa647dce44e7b16d035988')

    def test_failed_p2_propagates(self):
        self.assertNotEqual(self.execute('p2.sh','9').returncode,0)


if __name__=='__main__':unittest.main()
