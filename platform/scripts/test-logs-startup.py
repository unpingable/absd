#!/usr/bin/env python3
"""Execute actual CRT, logs/health dispatch and FSD client/decoder on a host transport."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    (work/'src').mkdir()
    source = (ROOT/'runtime/src/lib.rs').read_text()
    start = source.index('    // A client of a file server asks')
    end = source.index('    #[cfg(not(feature = "c-entry"))]', start)
    (work/'src/crt.rs').write_text('fn actual_crt(name: &[u8]) {\n'+source[start:end]+'}\n')
    logs = (ROOT/'src/bin/logs.rs').read_text().replace('#![cfg_attr(target_os = "absd", feature(restricted_std))]\n', '')
    logs = logs.replace('target_os = "absd"', 'feature = "absd-host-fixture"')
    logs = logs.replace('    fs::File,', '').replace('std::process::exit(', 'crate::__absd_std_exit(')
    logs += '\npub fn invoke() { main(); }\n'
    (work/'src/logs.rs').write_text('use crate::FileAdapter as File;\n'+logs.replace('//!', '//', 1))
    health = (ROOT/'src/bin/health.rs').read_text().replace('#![feature(restricted_std)]\n', '')
    health = health.replace('#[path = "../health_observation.rs"]', '#[path = '+json.dumps(str(ROOT/'src/health_observation.rs'))+']')
    health = health.replace('std::process::exit(', 'crate::__absd_std_exit(').replace('std::fs::read(', 'crate::fixture_read(').replace('std::fs::metadata(', 'crate::fixture_metadata(')
    (work/'src/health.rs').write_text(health+'\npub fn invoke() { main(); }\n')
    fixture = (ROOT/'tests/fixtures/logs_startup.rs').read_text()
    modules = ''.join('#[allow(dead_code)] #[path='+json.dumps(str(ROOT/path))+'] '+visibility+'mod '+name+';\n' for name, path, visibility in [('fsd','runtime/src/fsd.rs','pub '),('wire_kind','runtime/src/wire_kind.rs',''),('wire','runtime/src/kernel_log_wire.rs','')])
    (work/'src/main.rs').write_text(modules+fixture)
    deps = ''.join(name+'={path='+json.dumps(str(ROOT/path))+'}\n' for name, path in [('absd-fsd','fsd'),('absd-fs','fs'),('absd-broker','broker'),('absd-release','release')])
    (work/'Cargo.toml').write_text('[package]\nname="logs-startup-proof"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[features]\nabsd-host-fixture=[]\n[dependencies]\n'+deps+'serde_json="1.0"\n[profile.dev]\ndebug=0\n')
    binding = {'scope':'actual CRT selection/full runtime FSD/logs parser-dispatch/health main and real FSD server; only syscall, kernel-read and host File transport adapter substituted; no guest claim', 'revision':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(), 'source_sha256':{str(ROOT/p):hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ['runtime/src/lib.rs','runtime/src/fsd.rs','runtime/src/wire_kind.rs','runtime/src/kernel_log_wire.rs','src/bin/logs.rs','src/bin/health.rs','src/health_observation.rs','fsd/src/client_startup.rs','fsd/src/version.rs','fsd/src/server.rs','tests/fixtures/logs_startup.rs','scripts/test-logs-startup.py']}}
    (work/'SOURCE.json').write_text(json.dumps(binding,indent=2)+'\n')
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()), CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0')
    subprocess.run(['cargo','+1.95.0','build','--manifest-path',str(work/'Cargo.toml'),'--features','absd-host-fixture','--target','x86_64-unknown-linux-gnu','--offline'],env=env,check=True)
    binary = args.target_dir.resolve()/'x86_64-unknown-linux-gnu/debug/logs-startup-proof'
    cases = []
    for mode in ['missing','silent','wrong','malformed','refused','current']:
        cases.append((mode, ['--volatile'], {}, 0, 'Logging is retrying.', []))
        cases.append((mode, ['--health'], {}, 0, 'unknown', [] if mode=='missing' else [23] if mode!='current' else None))
    cases += [('silent',['--volatile'],{'EXEC_NAME':'logs'},0,'Logging is retrying.',[]),('silent',['--health'],{'EXEC_NAME':'/usr/bin/logs'},0,'unknown',[23]),('wrong',[],{},104,'FSD PROTOCOL REFUSED',[23]),('silent',[],{},104,'no_answer',[23]),('current',[],{},0,'fixture retained record',None),('wrong',[],{'ACTION':'spoof'},104,'FSD PROTOCOL REFUSED',[23]),('wrong',[],{'ACTION':'raw'},104,'FSD PROTOCOL REFUSED',[23]),('wrong',[],{'ACTION':'raw_bounded'},104,'FSD PROTOCOL REFUSED',[23]),('current',[],{'ACTION':'raw_version'},104,'FSD PROTOCOL REFUSED',[23,23]),('current',[],{'ACTION':'failed_recheck'},104,'FSD PROTOCOL REFUSED',[23,23,23]),('silent',[],{'ACTION':'late_reply'},104,'FSD PROTOCOL REFUSED',[23,23]),('current',[],{'ACTION':'rebind'},104,'FSD PROTOCOL REFUSED',[23,1,2,23]),('silent',[],{'EXEC_NAME':'logd'},75,'no_answer',[23]),('silent',[],{'EXEC_NAME':'ordinary'},104,'no_answer',[23]),('current',['--health'],{'READ_ERROR':'1'},1,'Permission denied',None),('current',['--volatile'],{'RING_ERROR':'1'},1,'kernel-view',[])]
    # Combined acquisition and selector contract: refusal never becomes empty
    # history, and a valid sample comes from the actual Journal producer.
    for mode in ['missing', 'silent', 'wrong', 'malformed', 'refused']:
        cases.append((mode, ['--health', '-b', '0'], {}, 1, 'collector-health unavailable for explicit boot selection', [] if mode=='missing' else [23]))
    cases += [('current',['--health','-b','0'],{},0,'sample_boot=0123456789abcdef0123456789abcdef',None),('current',['--health','-b','-1'],{},1,'no previous boot retained',None),('current',['--health','-b','ffffffffffffffffffffffffffffffff'],{},1,'requested boot is not retained',None),('current',['--health','-b','0'],{'READ_ERROR':'1'},1,'Permission denied',None)]
    cases += [('current',[],{'EXEC_NAME':'/bin/health','ACTION':'health_refused'},1,'release: FSD PROTOCOL REFUSED',None),('current',[],{'EXEC_NAME':'/bin/health','ACTION':'health_timeout'},1,'release: FSD PROTOCOL REFUSED reason=no_answer',None)]
    failures = []
    for n,(mode,argv,extra,status,contains,ops) in enumerate(cases):
        run = subprocess.run([str(binary),*argv],env=dict(env,SERVER_MODE=mode,**extra),capture_output=True,text=True,timeout=15)
        combined = run.stdout+run.stderr
        (work/f'case-{n:02}.log').write_text(combined)
        actual = re.search(r'FIXTURE operations=(\[[\d, ]*\]) ticks=(\d+)', combined)
        found = json.loads(actual.group(1)) if actual else None
        checks = [run.returncode==status, contains in combined, ops is None or found==ops]
        if argv == ['--health'] and mode!='current':
            checks += ['Current collector persistence, errors, and consecutive-unproductive count are unknown.' in run.stdout,'Retained sample unavailable: FSD PROTOCOL REFUSED' in run.stdout,'observed_state=retrying' in run.stdout,'No retained collector sample is available.' not in run.stdout]
        if '--health' in argv and '-b' in argv:
            if mode!='current':
                checks += ['Last retained collector sample' not in run.stdout, 'No retained collector sample is available.' not in run.stdout, 'kernel-view' not in combined]
            elif not extra and argv[-1]=='0':
                checks += [found is not None and found[:2]==[23,1] and found.count(23)==1, 'Supervisor observation unavailable for the selected boot' in run.stdout, 'observed_boot=' not in run.stdout]
        if mode=='silent' and '--health' in argv:
            checks += [actual is not None and int(actual.group(2))<=1000]
        if mode=='silent' and extra.get('EXEC_NAME')=='logd':
            checks += [actual is not None and int(actual.group(2))==1000]
        if mode=='current' and not extra and argv in [[], ['--health']]:
            checks += [found is not None and found[:2]==[23,1] and found.count(23)==1]
        if extra.get('ACTION', '').startswith('health_'):
            checks += [all(label in run.stdout for label in ['boot:', 'recovery:', 'config: network', 'config: sshd', 'logs:']), found is not None and found.count(23)==2 and any(opcode!=23 for opcode in found)]
            if extra['ACTION']=='health_timeout':
                checks += [actual is not None and int(actual.group(2))==60000]
        ok = all(checks)
        print(f'case={n} server={mode} argv={argv} extra={extra} status={run.returncode} ops={found} {"PASS" if ok else "FAIL"}',flush=True)
        if not ok: failures.append(n)
    if failures: raise SystemExit('failed actual consumer cases: '+str(failures))
    print(f'PASS {len(cases)} actual startup/mode/protocol controls')


if __name__=='__main__': main()
