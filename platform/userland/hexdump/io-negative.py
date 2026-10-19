#!/usr/bin/env python3
"""Injected ordinary I/O failures, preserving the production implementation."""
import pathlib,subprocess,sys,os
root=pathlib.Path(__file__).resolve().parent;out=pathlib.Path(sys.argv[1]);out.mkdir(exist_ok=True)
wrapper='''#define read fixture_read
#define close fixture_close
#include "hexdump.c"
#undef read
#undef close
extern ssize_t read(int,void *,size_t);
extern int close(int);
ssize_t fixture_read(int fd, void *buf, size_t n) {
  static int calls;
  const char *v=getenv("HEXDUMP_IO_FIXTURE");
  if (v && !strcmp(v,"read")) {
    if (calls++) { errno=EIO; return -1; }
    if (n>1) n=1;
  }
  return read(fd,buf,n);
}
int fixture_close(int fd) {
  int rc=close(fd);
  const char *v=getenv("HEXDUMP_IO_FIXTURE");
  if (v && !strcmp(v,"close")) { errno=EIO; return -1; }
  return rc;
}
'''
f=out/'io.c';f.write_text(wrapper);exe=out/'io'
subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I',str(root),str(f),'-o',str(exe)],check=True)
fixture=out/'input';fixture.write_bytes(b'AB')
for kind,want in [('read',b'0000000 0041\n0000001\n'),('close',b'0000000 4241\n0000002\n')]:
    p=subprocess.run([str(exe),str(fixture)],env={**os.environ,'HEXDUMP_IO_FIXTURE':kind},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
    assert p.returncode==2 and p.stdout==want and (kind+' error').encode() in p.stderr,(kind,p)
    print('IO FAILURE DETECTED',kind)
print('IO CONTROLS PASS')
