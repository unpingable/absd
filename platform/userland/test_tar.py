#!/usr/bin/env python3
"""Bounded host conformance fixtures for the admitted native ustar port.
No guest, SDK build or active source mutation. Pass the exact host executable.
"""
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

binary = str(Path(sys.argv[1]).resolve())
count = 0

def call(args, cwd, data=None, good=True, stdout=subprocess.PIPE):
    global count
    p = subprocess.run([binary, *args], cwd=cwd, input=data, stdout=stdout,
                       stderr=subprocess.PIPE, timeout=10)
    assert (p.returncode == 0) == good, (args, p.returncode, p.stderr)
    count += 1
    return p

def standard(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as tf:
        for name, data, mode in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.mtime = 0
            if data is None:
                info.type = tarfile.DIRTYPE
            else:
                info.size = len(data)
            tf.addfile(info, None if data is None else io.BytesIO(data))
    return stream.getvalue()

def checksum(record):
    b = bytearray(record)
    b[148:156] = b' ' * 8
    b[148:156] = ('%06o\0 ' % sum(b)).encode()
    return bytes(b)

with tempfile.TemporaryDirectory(prefix='absd-tar-host-') as tmp:
    root = Path(tmp)
    src = root/'source'; src.mkdir()
    for n in (0, 1, 511, 512, 513):
        (src/f'f{n}').write_bytes(bytes(range(256)) * (n//256) + bytes(range(n%256)))
    (src/'empty').mkdir()
    (src/'nested').mkdir(); (src/'nested'/'text').write_text('example\n')
    (src/'readonly').write_text('r'); (src/'readonly').chmod(0o444)
    p = call(['-cv', '-f', '-', '.'], src)
    assert b'empty' in p.stderr
    with tarfile.open(fileobj=io.BytesIO(p.stdout), mode='r:') as tf:
        assert tf.extractfile('f513').read() == (src/'f513').read_bytes()
        assert tf.getmember('empty').isdir()
        assert tf.getmember('readonly').mode == 0o444
    assert p.stdout[-1024:] == bytes(1024)
    reference = subprocess.run(['tar', '-tf', '-'], input=p.stdout, capture_output=True, timeout=10)
    assert reference.returncode == 0, reference.stderr
    dest=root/'dest'; dest.mkdir()
    call(['-x'], dest, p.stdout)
    assert (dest/'nested'/'text').read_text() == 'example\n'
    assert (dest/'f513').read_bytes() == (src/'f513').read_bytes()
    assert (dest/'readonly').stat().st_mode & 0o777 == 0o444
    external=standard([('./',None,0o755), ('dir/',None,0o755), ('dir/file',b'123',0o755)])
    out=root/'external'; out.mkdir()
    call(['-x'], out, external)
    assert (out/'dir'/'file').read_bytes() == b'123'
    assert (out/'dir'/'file').stat().st_mode & 0o777 == 0o644
    assert call(['-t'], root, external).stdout == b'.\ndir\ndir/file\n'
    assert call(['-t','dir'], root, external).stdout == b'dir\ndir/file\n'
    call(['-t','absent'],root,external,good=False)
    call(['-tz'],root,external,good=False)
    # Exact '-' sentinel; a filename merely beginning with '-' is ordinary.
    call(['-cf','-archive','f1'],src)
    assert (src/'-archive').is_file()
    call(['-tf','-archive'],src)
    self_archive=src/'self.tar'
    call(['-cf',str(self_archive),'.'],src)
    assert 'self.tar' not in call(['-tf',str(self_archive)],src).stdout.decode().splitlines()
    # Golden names use both full-width name100 and full-width prefix155.
    prefix='a'*77+'/'+'b'*77
    name=prefix+'/'+'c'*100
    long_archive=standard([('n'*100,b'full',0o644),(name,b'split',0o644)])
    assert name.encode() in call(['-t'],root,long_archive).stdout
    longsrc=root/'longsrc'; longsrc.mkdir()
    (longsrc/prefix).mkdir(parents=True); (longsrc/name).write_text('split')
    produced=call(['-c',name],longsrc).stdout
    with tarfile.open(fileobj=io.BytesIO(produced),mode='r:') as tf:
        assert tf.extractfile(name).read()==b'split'
    unsplit='u'*101; (longsrc/unsplit).write_text('x')
    call(['-c',unsplit],longsrc,good=False)
    golden=(Path(__file__).parent/'tar-vectors/basic.ustar').read_bytes()
    assert golden == standard([('file',b'abc',0o644)])
    for cut in (1,511,512,513,1023,1024,1535):
        call(['-t'],root,golden[:cut],good=False)
    for field, data in ((148,b'7777777\0'),(124,b'777777777777'),(124,b'\x80'+bytes(11)),(100,b'0008888\0'),(257,b'ustar '),(263,b'01')):
        b=bytearray(golden); b[field:field+len(data)]=data
        if field!=148: b[:512]=checksum(b[:512])
        call(['-t'],root,bytes(b),good=False)
    # All 512 header bytes contribute to checksum, including final padding.
    b=bytearray(golden); b[511]=1
    call(['-t'],root,bytes(b),good=False)
    b[:512]=checksum(b[:512]); call(['-t'],root,bytes(b))
    for kind in b'123467xgLS':
        b=bytearray(golden); b[156]=kind; b[:512]=checksum(b[:512])
        call(['-x'],root,bytes(b),good=False)
        assert not (root/'file').exists()
    pathdest=root/'pathdest'; pathdest.mkdir()
    for name in ('../outside','/absolute','dir/../outside'):
        call(['-x'],pathdest,standard([(name,b'x',0o644)]),good=False)
        assert not (root/'outside').exists()
    conflicts=root/'conflicts'; conflicts.mkdir()
    (conflicts/'file').mkdir()
    call(['-x'],conflicts,golden,good=False)
    assert (conflicts/'file').is_dir()
    (conflicts/'file').rmdir(); (conflicts/'file').write_bytes(b'old'); (conflicts/'file').chmod(0o444)
    call(['-x'],conflicts,golden,good=False)
    assert (conflicts/'file').read_bytes()==b'old'
    (conflicts/'file').chmod(0o644)
    call(['-x'],conflicts,standard([('file',b'first',0o644),('file',b'last',0o644)]))
    assert (conflicts/'file').read_bytes()==b'last'
    (conflicts/'link').symlink_to(root,target_is_directory=True)
    call(['-x'],conflicts,standard([('link/not-written',b'x',0o644)]),good=False)
    assert not (root/'not-written').exists()
    # Partial failure preserves earlier members and reports failure.
    partial=standard([('first',b'ok',0o644),('last',b'abc',0o644)])[:1537]
    part=root/'partial';part.mkdir();call(['-x'],part,partial,good=False)
    assert (part/'first').read_bytes()==b'ok'
    # Payload byte156 must never be reused as header.type for metadata.
    alias=bytearray(200);alias[156]=ord('1')
    aliasdir=root/'alias';aliasdir.mkdir()
    call(['-x'],aliasdir,standard([('readonly',bytes(alias),0o444)]))
    assert (aliasdir/'readonly').stat().st_mode & 0o777 == 0o444
    # Fragmented pipe writes force the record reader to handle short reads.
    proc=subprocess.Popen([binary,'-t'],cwd=root,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    def feed():
        try:
            for i in range(0,len(golden),7): proc.stdin.write(golden[i:i+7]);proc.stdin.flush();time.sleep(0.0001)
        except BrokenPipeError: pass
        finally:
            try: proc.stdin.close()
            except BrokenPipeError: pass
    thread=threading.Thread(target=feed);thread.start()
    stdout=proc.stdout.read();stderr=proc.stderr.read();thread.join();assert proc.wait(timeout=10)==0,stderr
    assert stdout==b'file\n';count+=1
    with open('/dev/full','wb',buffering=0) as full:
        call(['-t'],root,golden,good=False,stdout=full)
    print(f'TAR HOST CONFORMANCE OK cases={count}')
