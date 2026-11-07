#!/usr/bin/env python3
"""Run existing release-matrix cases 9 and 13 with their own bound boot receipts."""
import importlib.util
import os
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
import boot_artifacts as ba
import p2_boot_binding as binding


def main():
    def env(name):return os.environ['ABSD_COMPOSITION_'+name]
    run=Path(env('RUN_ROOT'));work=run/'work/recovery-seams';evidence=run/'recovery-seams-evidence'
    ba.need(not work.exists() and not evidence.exists(),'fresh cases 9 and 13 occurrence required')
    evidence.mkdir();inputs=evidence/'BOOT-INPUTS.json'
    binding.prepare(inputs,env('QEMU'),env('QEMU_SHA256'),[
        {'path':env('P2_A'),'manifest_sha256':env('P2_A_MANIFEST_SHA256')},
        {'path':env('P2_B'),'manifest_sha256':env('P2_B_MANIFEST_SHA256')}],evidence/'boot-bindings')
    spec=importlib.util.spec_from_file_location('candidate_release_matrix',ROOT/'scripts/release-matrix.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    original=module.rel.QEMU;previous=os.environ.get('ABSD_P2_BOUND_INPUTS')
    os.environ['ABSD_P2_BOUND_INPUTS']=str(inputs)
    module.rel.QEMU=binding.proxy_command(original)
    sys.argv=['release-matrix.py','--only','9,13','--release-a',env('P2_A'),'--release-b',env('P2_B'),
              '--kernel',str(run/'work/KA'),'--key',env('KEY'),'--work',str(work),'--results',str(evidence/'RESULT.json')]
    try:
        try:module.main()
        except SystemExit as exit:
            if exit.code not in (None,0):raise
    finally:
        module.rel.QEMU=original
        if previous is None:os.environ.pop('ABSD_P2_BOUND_INPUTS',None)
        else:os.environ['ABSD_P2_BOUND_INPUTS']=previous
    rows=json.loads((evidence/'RESULT.json').read_text())
    ba.need(len(rows)==2 and {row['case'] for row in rows}=={9,13}
            and all(row['verdict']=='PASS' for row in rows),'cases 9 and 13 result inventory incomplete')
    count=binding.terminal_bindings(evidence/'boot-bindings',env('QEMU_SHA256'),
        {env('P2_A_MANIFEST_SHA256'),env('P2_B_MANIFEST_SHA256')})
    (evidence/'BINDING-SUMMARY.json').write_text(json.dumps({'launch_count':count,'cases':[9,13],
        'results_sha256':ba.sha(evidence/'RESULT.json')},indent=2)+'\n')


if __name__=='__main__':main()
