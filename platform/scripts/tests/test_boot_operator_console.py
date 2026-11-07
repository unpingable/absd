#!/usr/bin/env python3
"""The real launcher with private command substitutes; no emulator launch."""
from pathlib import Path
import json
import os
import shutil
import signal
import time
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]

class Launcher(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='config-console-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);scripts=self.root/'scripts';scripts.mkdir()
        shutil.copyfile(ROOT/'scripts/boot-operator.sh',scripts/'boot-operator.sh')
        shutil.copyfile(ROOT/'scripts/boot_operator_supervisor.py',scripts/'boot_operator_supervisor.py')
        self.launcher=scripts/'boot-operator.sh';self.launcher.chmod(0o700)
        self.out=self.root/'machine with space';self.out.mkdir()
        (self.out/'absd-operator.iso').write_bytes(b'fixture ISO');(self.out/'absd-operator.img').write_bytes(b'fixture disk')
        (scripts/'operator_cpus.py').write_text("import os,sys\nif sys.argv[1]=='launch':os.execvp(sys.argv[2],sys.argv[2:])\n")
        (scripts/'served_ram.py').write_text("import os,sys\nos.execvp(sys.argv[2],sys.argv[2:])\n")
        (scripts/'operator_image.py').write_text("import os,sys\nassert not os.environ.get('FORBID_ENDPOINT'), 'malformed configuration must not be read'\nprint('10.0.2.15 22')\n")
        (scripts/'storage_fence_resume.py').write_text("""import json,os,sys
LAUNCH_FAILED=6
def record(args):
    with open(os.environ['CLASSIFICATION'],'a') as f:f.write(json.dumps(args)+'\\n')
def launched(out,*,ident,pid,console,log):
    record(['launched',out,'--id',ident,'--pid',str(pid),'--console',console]);return 0
def exit_path(out,*,status_word,console,log):
    record(['exit',out,'--status',status_word,'--console',console]);return 0
if __name__=='__main__':
    record(sys.argv[1:])
    if sys.argv[1]=='precheck':print('precheck: fresh')
""")
        self.qemu=self.root/'private-qemu'
        self.qemu.write_text("""#!/usr/bin/python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:];payload=b''
if os.environ.get('WAIT_UART'):
    Path(os.environ['QEMU_READY']).write_text(str(os.getpid()))
if '-chardev' in args:
    value=args[args.index('-chardev')+1]
    assert value.startswith('stdio,') and 'signal=off' in value
    logfile=value.split('logfile=',1)[1].split(',logappend=',1)[0]
    payload=sys.stdin.buffer.readline()
    output=b'UART FIXTURE '+payload
    sys.stdout.buffer.write(output);sys.stdout.buffer.flush();Path(logfile).write_bytes(output)
else:
    value=args[args.index('-serial')+1];assert value.startswith('file:')
    Path(value[5:]).write_bytes(b'default serial fixture\\n')
Path(os.environ['QEMU_RECEIPT']).write_text(json.dumps({'args':args,'stdin':payload.hex()}))
sys.exit(3)
""");self.qemu.chmod(0o700)
        self.receipt=self.root/'qemu.json';self.classification=self.root/'classify.jsonl'
        self.env=dict(os.environ,ABSD_QEMU=str(self.qemu),QEMU_RECEIPT=str(self.receipt),CLASSIFICATION=str(self.classification))
    def run_launcher(self,*args,forbid_endpoint=False):
        env=dict(self.env)
        if forbid_endpoint:env['FORBID_ENDPOINT']='1'
        return subprocess.run(['sh',str(self.launcher),*args,str(self.out)],input=b'preserved operator input\n',capture_output=True,env=env)
    def test_default_keeps_network_and_file_console(self):
        result=self.run_launcher();self.assertEqual(result.returncode,0,result.stderr)
        args=json.loads(self.receipt.read_text())['args'];self.assertIn('-netdev',args);self.assertIn('e1000,netdev=n0',args)
        self.assertEqual(args[args.index('-serial')+1],'file:'+str(self.out/'console.log'));self.assertNotIn('-chardev',args)
    def test_local_console_skips_malformed_endpoint_and_preserves_background_stdin_and_log(self):
        result=self.run_launcher('--local-only','--console',forbid_endpoint=True);self.assertEqual(result.returncode,0,result.stderr)
        receipt=json.loads(self.receipt.read_text());args=receipt['args']
        self.assertEqual(args[args.index('-nic')+1],'none');self.assertNotIn('-netdev',args);self.assertNotIn('e1000,netdev=n0',args)
        self.assertEqual(receipt['stdin'],b'preserved operator input\n'.hex())
        self.assertEqual((self.out/'console.log').read_bytes(),b'UART FIXTURE preserved operator input\n')
        self.assertIn((self.out/'console.log').read_bytes(),result.stdout)
        calls=[json.loads(line) for line in self.classification.read_text().splitlines()]
        self.assertEqual(calls[0][0],'precheck');self.assertEqual(calls[-1][0],'exit');self.assertIn('3',calls[-1])
    def test_console_hangup_retires_its_child_and_runs_exit_classification(self):
        ready=self.root/'ready';env=dict(self.env,WAIT_UART='1',QEMU_READY=str(ready))
        proc=subprocess.Popen(['sh',str(self.launcher),'--local-only','--console',str(self.out)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
        try:
            deadline=time.monotonic()+3
            while not ready.exists() and time.monotonic()<deadline:time.sleep(0.01)
            self.assertTrue(ready.exists(),'owned fake UART never started')
            # Keep UART input open until the owner handles HUP; communicate
            # would close it and race a genuine normal halt against HUP.
            proc.send_signal(signal.SIGHUP);proc.wait(timeout=5)
            stdout,stderr=proc.communicate(timeout=5)
            self.assertEqual(proc.returncode,130,(stdout,stderr))
            calls=[json.loads(line) for line in self.classification.read_text().splitlines()]
            self.assertEqual(calls[-1][0],'exit');self.assertIn('130',calls[-1])
            with self.assertRaises(ProcessLookupError):os.kill(int(ready.read_text()),0)
        finally:
            if proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM);proc.wait(timeout=3)
            for stream in [proc.stdin,proc.stdout,proc.stderr]:
                if stream is not None:stream.close()

    def test_local_only_requires_explicit_console_and_unknown_option_refuses(self):
        for options in [('--local-only',),('--unknown',)]:
            with self.subTest(options=options):
                result=self.run_launcher(*options);self.assertEqual(result.returncode,2,result.stderr);self.assertFalse(self.receipt.exists())

if __name__=='__main__':unittest.main()
