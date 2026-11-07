#!/usr/bin/env python3
"""Real init formatter and bounded buffer against the existing full-stream reader."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def item(source, marker):
    start = source.index(marker)
    at = source.index('{', start)
    depth = 1
    end = at + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


init = (ROOT / 'user/src/bin/init.rs').read_text()
user = (ROOT / 'user/src/lib.rs').read_text()
source = '''use std::fmt::Write;
const MAX_WRITE: usize = 256;
#[derive(Clone, Copy)] struct Console;
impl Console {
 fn write_once(self, bytes: &[u8]) -> Result<usize, ()> {
  assert!(bytes.len() <= MAX_WRITE);
  std::io::Write::write_all(&mut std::io::stdout(), bytes).unwrap();
  Ok(bytes.len())
 }
}
'''
for marker in ('pub struct LineBuffer', 'impl LineBuffer', 'impl core::fmt::Write for LineBuffer'):
    source += item(user, marker) + '\n'
source += '#[path=' + repr(str(ROOT / 'user/src/console_lines.rs')).replace("'", '"') + '] mod console_lines;\n'
for name in ('external_line', 'external_chunk'):
    source += item(init, 'fn ' + name + '(') + '\n'
source += '''fn main() {
 let bytes = std::fs::read(std::env::args().nth(1).unwrap()).unwrap();
 external_chunk(Console, 0, &bytes).unwrap();
}'''
with tempfile.TemporaryDirectory(prefix='absd-external-frame-') as temporary:
    out = Path(temporary)
    (out / 'formatter.rs').write_text(source)
    subprocess.run(['rustc', '--edition=2024', str(out / 'formatter.rs'), '-o', str(out / 'formatter')], check=True)
    for size in (0, 1, 95, 96, 97, 255, 256, 8192):
        expected = bytes((i % 256 for i in range(size)))
        (out / 'expected').write_bytes(expected)
        digest = 0x811c9dc5
        for byte in expected:
            digest = ((digest ^ byte) * 0x01000193) & 0xffffffff
        frames = subprocess.check_output([str(out / 'formatter'), str(out / 'expected')])
        (out / 'serial').write_bytes(b'EXTERNAL OUTPUT BEGIN encoding=hex\n' + frames + f'EXTERNAL OUTPUT END bytes={size} digest={digest:08x}\n'.encode())
        subprocess.run(['python3', str(ROOT / 'scripts/check-external-output.py'), str(out / 'serial'), str(out / 'expected')], check=True)
        assert all(len(line) + 1 <= 256 for line in frames.splitlines())
        print(f'actual formatter/full-stream reader: {size} bytes PASS', flush=True)
