#!/usr/bin/env python3
"""Host-only checks of the named tar-create fixture projection/custody path.
No guest execution, compiler invocation or general archive validation claim.
"""
import importlib.util,io,json,pathlib,sys,tarfile,tempfile
root=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'scripts'))
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
cu=load('tar_fixture_check',root/'scripts/check-userland.py')
um=load('tar_fixture_matrix',root/'scripts/userland-matrix.py')
entries=[('words-short.txt',b'b\na\na\n'),('tree',None),('tree/sub',None),('tree/sub/leaf.txt',b'leaf\n')]
want=b'[["words-short.txt","file","620a610a610a"],["tree","directory"],["tree/sub","directory"],["tree/sub/leaf.txt","file","6c6561660a"]]\n'
def archive(rows,fmt=tarfile.USTAR_FORMAT,pax=False):
    b=io.BytesIO()
    with tarfile.open(fileobj=b,mode='w',format=fmt) as tf:
        for name,data in rows:
            t=tarfile.TarInfo(name);t.mode=0o755;t.uid=17;t.gid=31;t.mtime=123456789
            if pax:t.pax_headers={'comment':'hidden extension'}
            if data is None:t.type=tarfile.DIRTYPE
            else:t.size=len(data)
            tf.addfile(t,None if data is None else io.BytesIO(data))
    return b.getvalue()
raw=archive(entries);assert cu.tar_create_contents(raw)==want
for rows in [entries[:-1],entries+[('extra',b'x')],entries+[entries[0]],[('words-short.txt',b'wrong'),*entries[1:]],[('words-short.txt',None),*entries[1:]]]:
    assert cu.tar_create_contents(archive(rows))!=want
bad_checksum=bytearray(raw);bad_checksum[0]^=1
for bad in [b'invalid',bytes(bad_checksum),raw[:512],archive(entries,tarfile.PAX_FORMAT,True),archive(entries,tarfile.GNU_FORMAT)]:
    try:cu.tar_create_contents(bad)
    except (ValueError,tarfile.TarError):pass
    else:raise AssertionError('unadmitted archive accepted')
# Exercise actual run_cases -> lifecycle -> format_result for both occurrences.
# Filesystem bytes are a deterministic fixture in place of the remote fs reader.
with tempfile.TemporaryDirectory(prefix='tar-matrix-fixture-') as td:
    work=pathlib.Path(td);m=um.UserlandMatrix.__new__(um.UserlandMatrix)
    m.work=work;m.cases=[um.Case('tar-create','tar','-',['-cf','made.ustar','words-short.txt','tree'])]
    m.expected=root/'userland/expected';m.divergences={}
    m.judged={'images':[],'objects':[]}
    m.stable=lambda *a:m.judged
    m.compare_census=lambda *a:('fixture','fixture')
    m.fresh_dir=lambda c:None
    m.run_text=lambda *a:''
    m.shell_ssh=lambda *a,**k:(0,b'',b'',100,[101])
    m.check=lambda label,ok,detail: None if ok else (_ for _ in ()).throw(AssertionError((label,detail)))
    m.below=lambda path:{**cu.FIXTURES,'made.ustar':raw}
    removed=[]
    def remove(case):
        label='repeat' if case.name.endswith(' repeat') else 'first'
        assert (work/'tar-create-raw'/(label+'.ustar')).read_bytes()==raw
        removed.append(label)
    m.remove_dir=remove
    counts=m.run_cases()
    assert counts=={'agree':1,'diverge':0,'defect':0},counts
    assert removed==['first','repeat']
print('TAR FIXTURE PASS semantic negatives=5 format refusals=5 actual first/repeat custody=2')
