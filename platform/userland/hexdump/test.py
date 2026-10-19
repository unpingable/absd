#!/usr/bin/env python3
"""Independent finite-input oracle; takes an already-built executable."""
import os, pathlib, signal, subprocess, sys, tempfile
exe=str(pathlib.Path(sys.argv[1]).resolve()); checks=0
esc={0:r'\0',7:r'\a',8:r'\b',9:r'\t',10:r'\n',11:r'\v',12:r'\f'}
def expected(data, mode='x', skip=0, limit=None, verbose=False):
    pos=min(skip,len(data));data=data[pos:];data=data if limit is None else data[:limit]
    lines=[];previous=None;squeezed=False
    for at in range(0,len(data),16):
        b=data[at:at+16];off=pos+at
        if len(b)==16 and b==previous and not verbose:
            if not squeezed:lines.append('*')
            squeezed=True;continue
        squeezed=False
        prefix=f'{off:08x}' if mode=='C' else f'{off:07x}'
        if mode=='C':
            cols=[' '+f'{n:02x}' for n in b]+['   ']*(16-len(b))
            text=prefix+' '+''.join(cols[:8])+' '+''.join(cols[8:])+'  |'+''.join(chr(n) if 32<=n<=126 else '.' for n in b)+'|'
        elif mode=='c':text=prefix+''.join(f'{chr(n) if 32<=n<=126 else esc.get(n,"??"):>4}' for n in b)
        elif mode=='b':text=prefix+''.join(f' {n:03o}' for n in b)
        else:
            words=[int.from_bytes(b[i:i+2],'little') for i in range(0,len(b),2)]
            spec={'x':'04x','d':'05d','o':'06o'}[mode]
            text=prefix+''.join(' '+format(n,spec) for n in words)
        lines.append(text)
        if len(b)==16:previous=b
    lines.append(format(pos+len(data),'08x' if mode=='C' else '07x'))
    return ('\n'.join(lines)+'\n').encode()
def run(args,data=b'',out=None):
    p=subprocess.run([exe,*args],input=data,stdout=out or subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
    assert not any(marker in p.stderr for marker in [b'runtime error:',b'AddressSanitizer',b'UndefinedBehaviorSanitizer',b'LeakSanitizer']),(args,p.stderr)
    if p.returncode==0:assert not p.stderr,(args,p.stderr)
    return p
def check(args,data,want,status=0):
    global checks
    p=run(args,data);assert (p.returncode,p.stdout)==(status,want),(args,p.returncode,p.stdout,want,p.stderr);checks+=1
# Literal goldens separate from oracle.
check([],b'simple\n',b'0000000 6973 706d 656c 000a\n0000007\n')
check(['-C'],b'\x80\xff',b'00000000  80 ff                                             |..|\n00000002\n')
with tempfile.TemporaryDirectory(prefix='hexdump-test-') as temp:
    root=pathlib.Path(temp)
    for mode in 'bcCdox':
        for data in [b'',b'\0'*16,b'\0'*48,bytes(range(256)),b'A'*48+b'B'*32,b'hello\n']:
            for size in sorted(set([0,1,15,16,17,len(data)])):
                d=data[:size]
                for args in [[f'-{mode}'],[f'-{mode}','-']]:check(args,d,expected(d,mode))
        for n in [0,1,15,16,17,40]:
            d=bytes(range(90))
            for skip in [0,1,15,16,30,50,89,90,99]:
                check([f'-{mode}','-s',str(skip),'-n',str(n)],d,expected(d,mode,skip,n))
        d=bytes(range(90)); paths=[]
        for i,part in enumerate([b'',d[:30],b'',d[30:60],d[60:],b'']):
            p=root/str(i);p.write_bytes(part);paths.append(str(p))
        for skip in [0,29,30,31,50,60,100]:check([f'-{mode}','-s',str(skip),*paths],b'',expected(d,mode,skip))
        check([f'-{mode}','-v'],b'\0'*48,expected(b'\0'*48,mode,verbose=True))
        check([f'-{mode}',paths[1],'-',paths[4]],d[30:60],expected(d,mode))
    # Distinguish zero limit from unlimited, and read only requested stdin bytes.
    check(['-n0'],b'A'*30,b'0000000\n')
    for text,n in [('010',10),('0x10',16),('1w',2),('1b',512),('1k',1024),('1kd',1000),('1C',1)]:
        check(['-n',text],b'A'*2048,expected(b'A'*2048,limit=n))
    for args in [['-e','x'],['-f','x'],['-C','-b'],['-n','-1'],['-n',''],['-n','0x'],['-n','1junk'],['-n','18446744073709551616'],['-s','18446744073709551615k'],['-n','k'],['-n']]:
        p=run(args);assert p.returncode==2,(args,p);checks+=1
    p=run([str(root/'missing')]);assert p.returncode==2;checks+=1
    p=run([str(root)]);assert p.returncode==2;checks+=1
    with open('/dev/full','wb') as f:
        p=run([],b'A'*8192,out=f);assert p.returncode==2;checks+=1
# Reader is closed before launch; no timing assumption or successful pipe write.
    readfd,writefd=os.pipe();os.close(readfd)
    try:
        p=run([],b'A'*32,out=writefd)
        assert p.returncode==-signal.SIGPIPE,p
        checks+=1
    finally:os.close(writefd)
print(f'HEXDUMP PASS {checks} cases')
