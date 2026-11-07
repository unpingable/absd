"""Execute the actual startup prefix up to the first output-loop boundary."""
import hashlib,json,subprocess
from pathlib import Path

def check(init, work, root, mutants=False):
    function = init[init.index('fn run_external_with('):]
    function = function[:function.index('\nfn ', 1)]
    call = '        logd_bootstrap(console);\n'
    cases = [('unchanged', function)]
    if mutants:
        assert function.count(call) == 1
        deleted = function.replace(call, '', 1)
        # Actual source mutation: move the call into the first read's EOF arm.
        needle = 'match Pipe::from_raw(stderr_reader).read_timeout(&mut bytes, 1) {\n                Ok(0) => {'
        assert deleted.count(needle) == 1
        late = deleted.replace(needle, needle+'\n                    logd_bootstrap(console);', 1)
        early = deleted.replace('    let input = Pipe::create()', '    logd_bootstrap(console);\n    let input = Pipe::create()', 1)
        cases += [('M1-deleted', deleted), ('M1-after-read', late), ('M1-before-spawn', early)]
    rows = []
    for name, source in cases:
        directory = work / ('callsite-' + name)
        directory.mkdir()
        (directory/'run_external_with.rs').write_text(source)
        # Keep the actual function prefix unchanged; replace only the output
        # loop and remainder with an instrumented output-reader I/O endpoint.
        prefix = source[:source.index('    while !output_eof || stderr_open {')]
        prefix += '    output_reader.read_timeout(&mut [0u8;1],1).unwrap();\n    unreachable!()\n}\n'
        fixture = (root/'tests/fixtures/logd_callsite.rs.in').read_text().replace('@ROOT@',str(root)).replace('EXTRACTED_PREFIX',prefix)
        (directory/'proof.rs').write_text(fixture)
        (directory/'SOURCE.json').write_text(json.dumps({'scope':__doc__,'original_init_sha256':hashlib.sha256(init.encode()).hexdigest(),'publisher_sha256':hashlib.sha256((root/'user/src/worker_console.rs').read_bytes()).hexdigest(),'extracted_function_sha256':hashlib.sha256(source.encode()).hexdigest(),'executed_prefix_sha256':hashlib.sha256(prefix.encode()).hexdigest(),'fixture_sha256':hashlib.sha256(fixture.encode()).hexdigest(),'mutant':name},indent=2)+'\n')
        build=subprocess.run(['rustc','+1.95.0','--edition=2024','-A','warnings',str(directory/'proof.rs'),'-o',str(directory/'proof')],capture_output=True)
        (directory/'compile.log').write_bytes(build.stdout+build.stderr)
        if build.returncode:raise RuntimeError('callsite fixture compile failed: '+str(directory))
        run=subprocess.run([str(directory/'proof')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        (directory/'result.log').write_bytes(run.stdout)
        expected = run.returncode == 0 if name == 'unchanged' else run.returncode != 0 and b'actual_callsite_trace=' in run.stdout
        rows.append({'case':name,'status':run.returncode,'expected_outcome':expected})
        print(name,run.stdout.decode(),end='')
        if not expected:raise RuntimeError('callsite behavior/control refused: '+name)
    (work/'CALLSITE-RESULTS.json').write_text(json.dumps(rows,indent=2)+'\n')
