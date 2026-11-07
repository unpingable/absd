#!/usr/bin/env python3
"""Exercise actual readiness emitters and kernel admission on host pipe substitutes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess

ROOT = Path(__file__).resolve().parents[1]
block = runpy.run_path(str(ROOT / 'scripts/test-system-time.py'))['function']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    identities = {}

    def source(root, relative):
        path = root / relative
        data = path.read_bytes()
        identities[str(path)] = hashlib.sha256(data).hexdigest()
        return data.decode()

    kernel = args.kernel.resolve()
    init = source(kernel, 'user/src/bin/init.rs')
    gate = source(kernel, 'src/frame_admission.rs')
    obj = source(kernel, 'src/object.rs')
    (work / 'program.rs').write_text(source(kernel, 'abi/src/program.rs'))
    (work / 'abi.rs').write_text(source(kernel, 'abi/src/syscall.rs'))
    (work / 'gate.rs').write_text('use crate::{object::PipeId, program::ServedReadyProbe};\n' + '\n'.join(
        block(gate, marker) for marker in ('pub struct BootstrapAdmission', 'impl BootstrapAdmission', 'pub fn read_request(')))
    (work / 'object.rs').write_text('#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n' + block(obj, 'pub struct PipeId') +
                                  '\npub fn fixture(index:u16,generation:u32)->PipeId {PipeId{index,generation}}\n')
    (work / 'observer.rs').write_text(block(init, 'fn observe_served_ready('))
    main_source = source(ROOT, 'ssh/src/main.rs')
    oplog = source(ROOT, 'ssh/src/oplog.rs')
    backend = source(ROOT, 'ssh/src/absd.rs')
    emitter = block(main_source, 'macro_rules! say') + '\n' + block(main_source, 'macro_rules! info') + '\n'
    emitter += 'mod oplog {\n' + block(oplog, 'pub fn line(') + '\n' + block(oplog, 'pub fn info(') + '\n}\n'
    # Match the concrete readiness invocations, including their selected macros.
    ssh = re.search(r'(?:info|say)!\(\s*"SSH LISTENING port=\{port\}.*?\n    \);', backend, re.S)
    local = re.search(r'(?:info|say)!\("LOCAL READY boot=\{boot\} enrolled=\{\}", u8::from\(verifier.is_some\(\)\)\);', backend)
    assert ssh and local, 'actual readiness invocations must be present'
    emitter += 'fn emit_ssh_ready(){let port=22;let authorized=[1];const PREAUTH_PER_SOURCE:usize=2;\n' + ssh.group() + '\n}\n'
    emitter += 'fn emit_local_ready(enrolled:bool){let verifier=if enrolled{Some(())}else{None};let boot="0123456789abcdef0123456789abcdef";\n' + local.group() + '\n}\n'
    (work / 'emitter.rs').write_text(emitter)
    fixture = source(ROOT, 'tests/fixtures/local_ready_stream.rs')
    (work / 'main.rs').write_text(fixture)
    source(ROOT, 'scripts/test-local-ready-stream.py')
    (work / 'SOURCE.json').write_text(json.dumps({'scope': 'Actual emitter macros/oplog/readiness calls, shared readiness probe, init observer and BootstrapAdmission/read_request; process/pipe endpoints substituted. No native syscall execution claim.', 'sha256': identities}, indent=2) + '\n')
    subprocess.run(['rustc', '+1.95.0', '--edition=2024', '-A', 'warnings', str(work / 'main.rs'), '-o', str(work / 'proof')], check=True)
    rows = []
    for scenario in ('ssh', 'local', 'local-stdout-control', 'local-unenrolled', 'local-unenrolled-stdout', 'foreign', 'missing-newline', 'never-ready', 'fragmented'):
        result = subprocess.run([str(work / 'proof'), scenario], capture_output=True, text=True, timeout=10)
        rows.append({'scenario': scenario, 'status': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        print(scenario, result.returncode, result.stdout.strip(), flush=True)
    (work / 'RESULTS.json').write_text(json.dumps(rows, indent=2) + '\n')
    if any(row['status'] for row in rows):
        raise SystemExit('readiness stream controls failed')


if __name__ == '__main__':
    main()
