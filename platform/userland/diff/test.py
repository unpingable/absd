#!/usr/bin/env python3
"""Bounded host controls; never compiles or invokes an ABSD/guest artifact."""
import argparse, pathlib, subprocess, random, re, json, os, signal
p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--sanitize',default='undefined',choices=['undefined','address,undefined']);a=p.parse_args()
out=pathlib.Path(a.out).resolve();out.mkdir(parents=True,exist_ok=True)
src=pathlib.Path(__file__).resolve().parent/'diff.c'
count=0

def compile(name,extra=(),source=src):
    exe=out/name
    subprocess.run(['gcc','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize='+a.sanitize,'-fno-sanitize-recover=all',*extra,str(source),'-o',str(exe)],check=True,timeout=15)
    return exe

def run(exe,left=b'',right=b'',args=(),status=None,stdout=None,diagnostic=None):
    global count
    x=out/'left';y=out/'right';x.write_bytes(left);y.write_bytes(right)
    r=subprocess.run([str(exe),*args,str(x),str(y)],stdout=subprocess.PIPE if stdout is None else stdout,stderr=subprocess.PIPE,timeout=2)
    count+=1
    if status is not None: assert r.returncode==status,(exe.name,left[:50],right[:50],r)
    if diagnostic is not None: assert diagnostic in r.stderr,(diagnostic,r)
    assert not r.stderr or b'runtime error:' not in r.stderr,r
    return r

def apply_unified(data,output):
    # Independent hunk applicator validates coordinates, context/deletions and
    # reconstructs exact target bytes, including missing-final-newline markers.
    old=data.splitlines(keepends=True); lines=output.splitlines(keepends=True)
    ans=[];pos=0;i=2
    while i<len(lines):
        m=re.fullmatch(rb'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n',lines[i]);assert m,lines[i]
        start=int(m[1]);n=int(m[2] or b'1');ns=int(m[3]);nn=int(m[4] or b'1')
        at=start-1 if n else start;assert at>=pos
        ans+=old[pos:at];pos=at;i+=1;consumed=produced=0
        assert len(ans)==(ns-1 if nn else ns)
        while i<len(lines) and not lines[i].startswith(b'@@ '):
            line=lines[i];i+=1;kind=line[:1];body=line[1:];assert kind in (b' ',b'-',b'+'),line
            if i<len(lines) and lines[i]==b'\\ No newline at end of file\n':
                assert body.endswith(b'\n');body=body[:-1];i+=1
            if kind in (b' ',b'-'): assert pos<len(old) and old[pos]==body,(pos,body,old);pos+=1;consumed+=1
            if kind in (b' ',b'+'):ans.append(body);produced+=1
        assert (consumed,produced)==(n,nn)
    ans+=old[pos:];return b''.join(ans)

exe=compile('diff')
pairs=[(b'',b''),(b'a\n',b'a\n'),(b'',b'x\n'),(b'x\n',b''),(b'a',b'a\n'),(b'a\n',b'a'),(b'a',b'b'),(b'a\nb\nc\n',b'a\nc\nd\n'),(b'x\n'*1024,b'x\n'*1024),(b'a'*65536,b'b'*65536)]
rng=random.Random(8311)
for _ in range(200):
    pairs.append(tuple(b''.join(rng.choice([b'a\n',b'b\n',b'c\n',b'\n',b'long line\n']) for n in range(rng.randrange(25))) for side in range(2)))
    if _ % 3 == 0: pairs[-1]=tuple(v[:-1] if v else v for v in pairs[-1])
for left,right in pairs:
    r=run(exe,left,right,status=int(left!=right))
    assert (not r.stdout) if left==right else apply_unified(left,r.stdout)==right,(left,right,r.stdout)
    ref=subprocess.run(['/usr/bin/diff',str(out/'left'),str(out/'right')],capture_output=True,timeout=2)
    assert ref.returncode==r.returncode
run(exe,b'x\n'*1024,b'x\n'*1023+b'y\n',status=2,diagnostic=b'work limit') # bounded work refusal
for left,right in [(b'',b'x'*5000+b'\0'),(b'\0',b'\0'),(b'x\0',b'y\0'),(b'\0',b'\0z')]:
    r=run(exe,left,right,status=int(left!=right));assert (b'Binary files' in r.stdout)==(left!=right)
for left,right in [(b'x'*65537,b''),(b'',b'x'*65537)]:run(exe,left,right,status=2,diagnostic=b'byte limit')
for left,right in [(b'\n'*1025,b''),(b'',b'\n'*1025)]:run(exe,left,right,status=2,diagnostic=b'line limit')
run(exe,b'a',b'b',args=('-u','--'),status=1)
run(exe,b'a',b'b',args=('-r',),status=2)
for args in [[],['-'],[str(out),str(out/'left')],['-',str(out/'left')],[str(out/'absent'),str(out/'left')]]:
    r=subprocess.run([str(exe),*args],capture_output=True,timeout=2);assert r.returncode==2;count+=1
with open('/dev/full','wb') as f: run(exe,b'a',b'b',status=2,stdout=f,diagnostic=b'output failed')
# Host signal termination is distinct from stdio-reported status2.
readfd,writefd=os.pipe();os.close(readfd)
r=subprocess.run([str(exe),str(out/'left'),str(out/'right')],stdout=writefd,stderr=subprocess.PIPE,timeout=2)
os.close(writefd)
assert r.returncode==-signal.SIGPIPE,r;count+=1
for limit in ['WORK','CANDIDATES','ALLOC']:
    small=compile('limit-'+limit,['-DDIFF_MAX_'+limit+'=1'])
    run(small,b'a\nb\n',b'b\na\n',status=2,diagnostic={'WORK':b'work limit','CANDIDATES':b'candidate limit','ALLOC':b'allocation limit'}[limit])
# Compile-time substitution fixtures wrap libc calls in this translation unit.
# No environment-driven injection hooks are present in the shipped executable.
for mode in ['read','short','seek','close','alloc']:
    fixture=out/('fail-'+mode+'.c')
    wrappers={
      'read':'''static size_t fault_read(void *p,size_t a,size_t b,FILE *f) {(void)p;(void)a;(void)b;(void)f; return 0;}\nstatic int fault_error(FILE *f) {(void)f;return 1;}\n#define fread fault_read\n#define ferror fault_error\n''',
      'short':'''static size_t fault_read(void *p,size_t a,size_t b,FILE *f) {(void)p;(void)a;(void)b;(void)f;return 0;}\n#define fread fault_read\n''',
      'seek':'''static int fault_seek(FILE *f,long o,int w) {(void)f;(void)o;(void)w;return -1;}\n#define fseek fault_seek\n''',
      'close':'''static int fault_close(FILE *f) {fclose(f);return -1;}\n#define fclose fault_close\n''',
      'alloc':'''static void *fault_alloc(void *p,size_t n) {(void)p;(void)n;return NULL;}\n#define realloc fault_alloc\n'''}
    fixture.write_text('#define _POSIX_C_SOURCE 200809L\n#include <stdio.h>\n#include <stdlib.h>\n'+wrappers[mode]+'#include '+json.dumps(str(src))+'\n')
    run(compile('fail-'+mode,source=fixture),b'a',b'b',status=2,diagnostic={'read':b'input read/close failed','short':b'input read/close failed','seek':b'seek failed','close':b'input read/close failed','alloc':b'allocation failure'}[mode])
# Names with whitespace, controls and high bytes are escaped in output labels.
x=out/'name \" \n é';y=out/'other';x.write_bytes(b'a\xff\n');y.write_bytes(b'b\xfe\n')
r=subprocess.run([str(exe),'--',str(x),str(y)],capture_output=True,timeout=2)
assert r.returncode==1 and b'\\012' in r.stdout and b'\\303' in r.stdout
assert apply_unified(x.read_bytes(),r.stdout)==y.read_bytes();count+=1
# Post-capture mutation of first pathname must not change its captured sequence.
fixture=out/'capture-mutation.c'
fixture.write_text('#define _POSIX_C_SOURCE 200809L\n#include <stdio.h>\n#include <stdlib.h>\nstatic const char *path; static int calls;\nstatic int change_close(FILE *f) {int r=fclose(f); if(!calls++){FILE *w=fopen(path,"wb"); if(!w)exit(99); fputs("replacement\\n",w); fclose(w);}return r;}\n#define fclose change_close\n#define main diff_main\n#include '+json.dumps(str(src))+'\n#undef main\nint main(int n,char **v){path=v[1];return diff_main(n,v); }\n')
run(compile('capture-mutation',source=fixture),b'same\n',b'same\n',status=0)
assert (out/'left').read_bytes()==b'replacement\n'
print(json.dumps({'status':'PASS' ,'cases':count,'seed':8311,'scope':'Linux host only; no target qualification','compiler':'gcc '+a.sanitize+' sequential'},indent=2))
