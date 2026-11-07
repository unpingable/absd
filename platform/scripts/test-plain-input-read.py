#!/usr/bin/env python3
"""Run the actual native plain-read adapter against bounded host inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
function = runpy.run_path(str(ROOT / 'scripts/test-system-time.py'))['function']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    host = ROOT / 'src/sh_host.rs'
    shell = ROOT / 'sh/src/lib.rs'
    fixture = ROOT / 'tests/fixtures/plain_input_read.rs'
    adapter = function(host.read_text(), 'fn read_interactive(&mut self,')
    text = shell.read_text()
    helper = function(text, 'pub fn read_interactive_plain(') if 'pub fn read_interactive_plain(' in text else ''
    source = '#![allow(dead_code)]\nuse std::io;\nmod shell { use std::io;\n'
    limit = re.search(r'(?m)^pub const MAX_SCRIPT_BYTES: usize = [^;]+;', text)
    assert limit, 'actual source limit must be present'
    source += limit.group() + '\n' + helper + '\n'
    source += 'pub fn read_interactive_record(_: &mut dyn io::BufRead,_:&mut String)->io::Result<usize>{panic!("record branch selected on plain input")}\n}\n'
    source += 'struct Adapter { paste_records:bool }\nimpl Adapter {\n' + adapter + '\n}\n'
    source += fixture.read_text()
    (work / 'proof.rs').write_text(source)
    (work / 'SOURCE.json').write_text(json.dumps({'scope': 'Actual native read_interactive method and actual bounded helper when present; host BufRead endpoints. Record branch is a refusal stub and is not claimed tested.', 'files': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [host, shell, fixture, Path(__file__)]}}, indent=2) + '\n')
    subprocess.run(['rustc', '+1.95.0', '--edition=2024', '--test', str(work / 'proof.rs'), '-o', str(work / 'proof')], check=True)
    subprocess.run([str(work / 'proof'), '--test-threads=1'], check=True)


if __name__ == '__main__':
    main()
