#!/usr/bin/env python3
"""Real kernel producer -> wire -> Collector -> RPC/FSD/Fs host regression.

--kernel names a read-only kernel checkout. Only compile-time authorization
bindings and acquisition/device transport are substituted; no VM is launched.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess

ROOT=Path(__file__).resolve().parent.parent

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel',type=Path,required=True);parser.add_argument('--work',type=Path,required=True);parser.add_argument('--target-dir',type=Path,required=True)
    parser.add_argument('--scenario',choices=['admission','recovery'],default='admission')
    args=parser.parse_args();kernel=args.kernel.resolve();work=args.work.resolve();work.mkdir(parents=True,exist_ok=True);(work/'src').mkdir(exist_ok=True)
    for golden in ['logd-lifecycle-v1.txt','logd-startup-v1.hex','logd-supervision-v1.txt']:
        if (kernel/'tests/fixtures'/golden).read_bytes() != (ROOT/'tests/fixtures'/golden).read_bytes(): parser.error('cross-repository golden differs: '+golden)
    source=kernel/'src/kernel_log.rs'
    if not source.is_file():parser.error('kernel production kernel_log.rs is required')
    manifest='[package]\nname="journal-source-admission-proof"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\n'
    for package,path in [('absd-fsd',ROOT/'fsd'),('absd-fs',ROOT/'fs')]:manifest+=package+'={path='+json.dumps(str(path))+'}\n'
    manifest+='absd-broker={path='+json.dumps(str(ROOT/'broker'))+'}\n'
    manifest+='[profile.test]\ndebug=0\n';(work/'Cargo.toml').write_text(manifest)
    modules={'kernel_producer':source,'wire':ROOT/'runtime/src/kernel_log_wire.rs','collector':ROOT/'ssh/src/service_journal.rs'}
    if args.scenario == 'recovery':
        modules['kernel_policy']=kernel/'user/src/logd_policy.rs'
        modules['logs']=ROOT/'src/bin/logs.rs'
    startup_source=kernel/'user/src/broker.rs'
    startup_prefix=startup_source.read_text().split('/// A parsed startup record:',1)[0]
    (work/'src/kernel_startup.rs').write_text(startup_prefix)
    text=''.join('#[allow(dead_code)]\n#[path='+json.dumps(str(path))+']\npub mod '+name+';\n' for name,path in modules.items())
    fixture=ROOT/('tests/fixtures/journal_source_admission.rs' if args.scenario=='admission' else 'tests/fixtures/journal_recovery.rs')
    text+='pub mod kernel_startup;\n'
    text+='include!('+json.dumps(str(fixture))+');\n';(work/'src/lib.rs').write_text(text)
    identity={'scope':'host producer/wire/collector/RPC/filesystem; no VM or authorization claim','runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'kernel_checkout':str(kernel),'kernel_revision':subprocess.check_output(['git','-C',str(kernel),'rev-parse','HEAD'],text=True).strip(),'source_sha256':{str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in [*modules.values(),startup_source,ROOT/'fsd/src/journal.rs',ROOT/'fsd/src/journal_rpc.rs',fixture,ROOT/'tests/fixtures/journal_support.rs',ROOT/'src/bin/absd_logd.rs',ROOT/'tests/fixtures/logd-lifecycle-v1.txt',kernel/'tests/fixtures/logd-lifecycle-v1.txt',ROOT/'tests/fixtures/logd-startup-v1.hex',kernel/'tests/fixtures/logd-startup-v1.hex',ROOT/'tests/fixtures/logd-supervision-v1.txt',kernel/'tests/fixtures/logd-supervision-v1.txt',ROOT/'fsd/src/client_startup.rs',ROOT/'runtime/src/fsd.rs',ROOT/'runtime/src/lib.rs']}}
    (work/'SOURCE.json').write_text(json.dumps(identity,indent=2)+'\n')
    env=dict(os.environ,CARGO_TARGET_DIR=str(args.target_dir.resolve()),CARGO_INCREMENTAL='0',CARGO_PROFILE_DEV_DEBUG='0')
    subprocess.run(['cargo','+1.95.0','test','--manifest-path',str(work/'Cargo.toml'),'--target','x86_64-unknown-linux-gnu','--offline','--lib','--','--nocapture','--test-threads=1'],env=env,check=True)

if __name__=='__main__':main()
