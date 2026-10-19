#!/usr/bin/env python3
"""Compile sequential bounded regression mutations; require each to be detected."""
import pathlib, subprocess, sys
src=pathlib.Path(__file__).with_name('hexdump.c');out=pathlib.Path(sys.argv[1]);out.mkdir(exist_ok=True)
def build(name,text,extra=()):
    p=out/(name+'.c');p.write_text(text);exe=out/name
    subprocess.run(['gcc','-std=c11','-O1','-g',*extra,str(p),'-o',str(exe)],check=True)
    return str(exe)
s=src.read_text()
sanflags=['-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-sanitize-recover=all']
# Deliberate signed overflow must terminate rather than report and continue.
ub=build('sanitizer-control','#include <limits.h>\nint main(void){volatile int n=INT_MAX; return (n+1)==0;}\n',sanflags)
p=subprocess.run([ub],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
(out/'sanitizer-control.stderr').write_bytes(p.stderr)
(out/'sanitizer-control.status').write_text(str(p.returncode)+'\n')
assert p.returncode!=0 and b'runtime error:' in p.stderr,(p.returncode,p.stderr)
print('SANITIZER NONZERO CONTROL PASS',flush=True)
exe=build('sanitized',s,sanflags)
subprocess.run([sys.executable,str(src.with_name('test.py')),exe],check=True)
for name,old,new,args,data,want in [
 ('signed-byte','static unsigned char line','static signed char line',['-C'],b'\xff',b'00000000  ff                                                |.|\n00000001\n'),
 ('first-zero','count == 16 && have_previous &&','count == 16 &&',[],b'\0'*16,b'0000000 0000 0000 0000 0000 0000 0000 0000 0000\n0000010\n'),
 ('zero-limit','remaining_limit = val; limited = 1;','remaining_limit = val; limited = !!val;', ['-n0'],b'A',b'0000000\n')]:
    assert old in s
    exe=build(name,s.replace(old,new,1));p=subprocess.run([exe,*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
    assert p.returncode!=0 or p.stdout!=want,(name,'escaped detection')
    print('NEGATIVE DETECTED',name,flush=True)
print('NEGATIVE CONTROLS PASS')
