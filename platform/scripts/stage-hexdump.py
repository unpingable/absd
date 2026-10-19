#!/usr/bin/env python3
"""Stage only the two admitted Toybox members; offline, fresh destination only."""
import argparse, hashlib, json, pathlib, subprocess, tarfile
p=argparse.ArgumentParser();p.add_argument('archive',type=pathlib.Path);p.add_argument('destination',type=pathlib.Path);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];local=root/'userland/hexdump'
m=json.loads((local/'SOURCE.json').read_text())
def digest(b):return hashlib.sha256(b).hexdigest()
archive=a.archive.read_bytes()
if digest(archive)!=m['archive_sha256']:raise SystemExit('hexdump stage: archive identity mismatch')
patch=(local/'hexdump.patch').read_bytes()
if digest(patch)!=m['patch_sha256']:raise SystemExit('hexdump stage: patch identity mismatch')
if digest((local/'hexdump.c').read_bytes())!=m['adapted_sha256']:raise SystemExit('hexdump stage: adapted source identity mismatch')
if a.destination.exists():raise SystemExit('hexdump stage: destination must be absent')
# Verify all selected inputs before creating any staging output; never extract
# archive paths, links, modes, owners or unrelated members.
selected={}
with tarfile.open(a.archive,'r:gz') as t:
    for member,key,name in [('toybox-0.8.15/toys/pending/hexdump.c','upstream_sha256','hexdump.c'),('toybox-0.8.15/LICENSE','license_sha256','LICENSE')]:
        i=t.getmember(member)
        if not i.isfile() or i.size>32768:raise SystemExit('hexdump stage: member shape refused')
        data=t.extractfile(i).read()
        if digest(data)!=m[key]:raise SystemExit('hexdump stage: member identity mismatch')
        selected[name]=data
if selected['LICENSE']!=(local/'LICENSE').read_bytes():raise SystemExit('hexdump stage: license hexdumpers')
a.destination.mkdir(parents=True)
for name,data in selected.items():(a.destination/name).write_bytes(data)
subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(local/'hexdump.patch')],cwd=a.destination,check=True)
if digest((a.destination/'hexdump.c').read_bytes())!=m['adapted_sha256']:raise SystemExit('hexdump stage: patched output identity mismatch')
(a.destination/'SOURCE.json').write_text(json.dumps(m,indent=2)+'\n')
print('HEXDUMP STAGE OK '+m['adapted_sha256'])
