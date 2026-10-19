#!/usr/bin/env python3
"""Bounded host check of the two standalone ports; not the full userland gate.

Consumes the actual top-level Makefile's linux/absd binaries and obj files at
ABSD_USERLAND_BUILD, and the explicitly identified kit/adapter environment.
No build, guest or mutation of expected output is performed.
"""
import importlib.util, shlex, subprocess, sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('check_userland',root/'scripts/check-userland.py')
cu=importlib.util.module_from_spec(spec);spec.loader.exec_module(cu)
classify=cu.ud.classifier(cu.ud.CPORTS/'lib/libabsd-posix.a')
for utility in ['diff','hexdump']:
    elf=cu.OUT/'absd'/utility
    subprocess.run([sys.executable,'-I',str(root/'scripts/check-c-elf.py'),str(elf),'--map',str(elf)+'.map'],check=True)
    need,pulled=cu.ud.closure([cu.OUT/'obj/absd'/(utility+'.o')],{})
    assert not pulled
    for symbol in sorted(need):
        bucket,links,note=classify(symbol)
        if not links or bucket=='MISSING':raise SystemExit(f'{utility}: unresolved {symbol}: {note}')
    print(f'TOYBOX DEMAND {utility} names={len(need)} unresolved=0')
cases=0
for line in (root/'userland/cases.tsv').read_text().splitlines():
    if not line or line.startswith('#'):continue
    cid,utility,stdin,args=line.split('\t')
    if utility not in {'diff','hexdump'}:continue
    actual=cu.run_case(cid,utility,stdin,shlex.split(args))
    expected=(root/'userland/expected'/cid).read_bytes()
    if actual!=expected:raise SystemExit(f'{cid}: differs from retained expected output')
    cases+=1
if not cases:raise SystemExit('no Toybox cases')
print(f'TOYBOX PIPELINE HOST OK cases={cases} full_userland=not_run guest=unverified')
