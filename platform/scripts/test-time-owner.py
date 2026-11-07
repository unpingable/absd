#!/usr/bin/env python3
"""Actual Service/Poller/Stack host regression; substitute only kernel I/O and log output."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def function(source, marker):
    start=source.index(marker);at=source.index('{',start);end=at+1;depth=1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    (work/'src').mkdir(parents=True, exist_ok=True)
    manifest = '[package]\nname="time-owner-proof"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\ngetrandom="0.4"\n'

    for name, directory in [('absd-net','net'),('absd-fs','fs'),('absd-fsd','fsd')]:
        manifest += name+'={path='+json.dumps(str(ROOT/directory))+'}\n'
    manifest += '[profile.test]\ndebug=0\n'
    (work/'Cargo.toml').write_text(manifest)
    sources = [ROOT/'ssh/src/time_owner.rs', ROOT/'ssh/src/time_policy.rs', ROOT/'ssh/src/etc.rs', ROOT/'runtime/src/civil_clock.rs', ROOT/'tests/fixtures/time_owner.rs']
    code = ''.join('#[allow(dead_code)]\n#[path='+json.dumps(str(p))+']\nmod '+name+';\n' for name,p in [('time_policy',sources[1]),('etc',sources[2]),('civil_clock',sources[3])])
    sources.extend([ROOT/'ssh/src/fsd_server.rs', ROOT/'runtime/src/lib.rs', ROOT/'tests/fixtures/time_clock_cache.rs'])
    code += (ROOT/'tests/fixtures/time_owner.rs').read_text()
    code += function((ROOT/'runtime/src/lib.rs').read_text(),'pub fn wall_clock_seconds()')+'\n'
    fsd_source=(ROOT/'ssh/src/fsd_server.rs').read_text()
    code += function(fsd_source,'fn wall_clock()')+'\n'+function(fsd_source,'fn refresh_civil_clock(')+'\n'
    code += (ROOT/'tests/fixtures/time_clock_cache.rs').read_text()
    code += '\nmod owner {\n'+sources[0].read_text()+'\ninclude!('+json.dumps(str(ROOT/'tests/fixtures/time_owner_cases.rs'))+');\n}\n'
    sources.append(ROOT/'tests/fixtures/time_owner_cases.rs')
    (work/'src/lib.rs').write_text(code)
    (work/'SOURCE.json').write_text(json.dumps({'scope':'Actual Service, policy, configuration, codec, Poller and Stack; simulated kernel clock/owner grant and log output; no authority or guest claim','revision':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),*sources]}},indent=2)+'\n')
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()), CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0')
    subprocess.run(['cargo','+1.95.0','test','--manifest-path',str(work/'Cargo.toml'),'--target','x86_64-unknown-linux-gnu','--offline','--lib','--','--test-threads=1','--nocapture'],env=env,check=True)

if __name__ == '__main__': main()
