#!/usr/bin/env python3
"""Exercise init's actual logger capture/render function with host I/O adapters."""
from pathlib import Path
import argparse
import importlib
import json
import os
import re
import sys
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--platform', type=Path, help='unchanged shipped absd_try decoder checkout')
parser.add_argument('--work', type=Path, help='retain generated source and exact console replay')
args = parser.parse_args()
raw_fixture = (ROOT / 'user/tests/vectors/init-console-offset0-149.input').read_bytes()
# Offline fixture construction only: recover the three logical worker events,
# including the frame whose prefix landed inside a logger read. The oracle
# below always uses anchored lines/the unchanged shipped decoder.
frames = list(re.finditer(rb'EXTERNAL OUTPUT CHUNK offset=([0-9a-f]+) data=([0-9a-f]*)\n', raw_fixture))
assert [int(m[1], 16) for m in frames] == [0, 53, 149]
logger = raw_fixture[frames[0].end():frames[1].start()]
assert len(logger) == 256 and logger.startswith(b'LOGD READY ')
expected = b''.join(bytes.fromhex(m[2].decode()) for m in frames)


def item(source, marker):
    start = source.index(marker)
    at = source.index('{', start)
    depth, end = 1, at + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


init = (ROOT / 'user/src/bin/init.rs').read_text()
user = (ROOT / 'user/src/lib.rs').read_text()
local = (ROOT / 'user/src/local_console.rs').read_text()
source = '#[path='+json.dumps(str(ROOT / 'user/src/logd_policy.rs'))+'] mod logd_policy;\n' + '''use std::fmt::Write;
use std::sync::Mutex;
const MAX_WRITE: usize = 256;
static DISPLAY: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static CAPTURE: Mutex<Vec<(u64, u64, u64, Vec<u8>)>> = Mutex::new(Vec::new());
static INPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static READ_FAULT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
static WRITE_FAULT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
#[derive(Clone, Copy)] pub struct Console;
impl Console {
 fn raw(self) -> u64 { 9 }
 fn write_once(self, bytes: &[u8]) -> Result<usize, ()> {
  assert!(bytes.len() <= MAX_WRITE);
  let mode = WRITE_FAULT.load(std::sync::atomic::Ordering::Relaxed);
  if mode == 1 { return Err(()); }
  let n = bytes.len() - usize::from(mode == 2);
  DISPLAY.lock().unwrap().extend_from_slice(&bytes[..n]); Ok(n)
 }
}
#[derive(Clone, Copy, PartialEq, Eq)] enum Error { Timeout, Other }
struct Pipe;
impl Pipe {
 fn from_raw(handle: u64) -> Self { assert_eq!(handle, 1); Self }
 fn read_timeout(&self, bytes: &mut [u8], ticks: u64) -> Result<usize, Error> {
  assert_eq!(ticks, 1);
  match READ_FAULT.load(std::sync::atomic::Ordering::Relaxed) {
   1 => return Err(Error::Timeout), 2 => return Err(Error::Other), _ => {}
  }
  let mut input = INPUT.lock().unwrap();
  let n = input.len().min(bytes.len()); bytes[..n].copy_from_slice(&input[..n]);
  input.drain(..n); Ok(n)
 }
}
mod absd_user { pub use super::Console; pub mod kernel_log {
 pub fn append_service(console: u64, pid: u64, service: u64, stream: u64,
                       bytes: &[u8]) -> Result<(), ()> {
  assert_eq!(console, 9);
  super::super::CAPTURE.lock().unwrap().push((pid, service, stream, bytes.to_vec()));
  Ok(())
 }
}}
static mut LOGD_INPUT: u64 = 0;
static mut LOGD_OUTPUT: u64 = 1;
fn close(_: u64) -> Result<(), ()> { Ok(()) }
static mut LOGD_PID: u64 = 37;
static mut LOGD_FAULT_INJECTED: bool = false;
static mut LOGD_COLLECT_PROBE: logd_policy::Collected = logd_policy::Collected::new();
static mut LOGD_POLICY: logd_policy::Policy = logd_policy::Policy::new();
static mut LOGD_FAULT_AT: u64 = u64::MAX;
const LOGD_FAULT: bool = true;
static NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(100);
fn time() -> u64 { NOW.load(std::sync::atomic::Ordering::Relaxed) }
fn getpid() -> u64 { 1 }
mod local_console {
 use std::sync::atomic::{AtomicBool, Ordering};
 static STARTUP_CAPTURE_CLOSED: AtomicBool = AtomicBool::new(false);
 pub fn set_owned(value: bool) { STARTUP_CAPTURE_CLOSED.store(value, Ordering::Relaxed); }
'''
source += item(local, 'pub fn startup_capture_closed()') + '}\n'
for marker in ('pub struct LineBuffer', 'impl LineBuffer', 'impl core::fmt::Write for LineBuffer'):
    source += item(user, marker)
if (ROOT / 'user/src/console_lines.rs').exists():
    source += '#[path=' + json.dumps(str(ROOT / 'user/src/console_lines.rs')) + '] mod console_lines;\n'
    source += 'fn reset_arbiter() { console_lines::reset(); }\n'
else:
    source += 'fn reset_arbiter() {}\n'
source += item(init, 'fn service_record(') + item(init, 'fn external_line(') + item(init, 'fn external_chunk(') + item(init, 'fn logd_output(') + item(init, 'fn logd_release_streams(')
fixture = r'''
fn reset(owned: bool) {
 READ_FAULT.store(0, std::sync::atomic::Ordering::Relaxed); WRITE_FAULT.store(0, std::sync::atomic::Ordering::Relaxed); reset_arbiter(); DISPLAY.lock().unwrap().clear(); CAPTURE.lock().unwrap().clear();
 INPUT.lock().unwrap().clear(); local_console::set_owned(owned);
 NOW.store(100, std::sync::atomic::Ordering::Relaxed);
 let mut policy = logd_policy::Policy::new(); assert!(policy.begin(0)); policy.spawned();
 unsafe { LOGD_OUTPUT = 1; LOGD_COLLECT_PROBE = logd_policy::Collected::new();
          LOGD_POLICY = policy; LOGD_FAULT_AT = u64::MAX; LOGD_FAULT_INJECTED = false; }
}
fn feed(bytes: &[u8]) {
 INPUT.lock().unwrap().extend_from_slice(bytes); logd_output(Console);
}
#[test] fn owned_terminal_keeps_logger_capture_without_display() {
 reset(true);
 let bytes = b"LOGD READY boot=a\n\0\r\t\x7f\xff";
 feed(bytes);
 assert_eq!(*CAPTURE.lock().unwrap(), vec![(37, 3, 1, bytes.to_vec())]);
 assert!(DISPLAY.lock().unwrap().is_empty(), "logger output crossed owned prompt");
}
#[test] fn headless_keeps_exact_escaping_and_bounded_batches() {
 reset(false);
 let bytes = b"LOGD READY boot=a\n\0\r\t\x7f\xff\n";
 for _ in 0..10 { INPUT.lock().unwrap().extend_from_slice(bytes); }
 logd_output(Console);
 assert_eq!(*DISPLAY.lock().unwrap(), b"LOGD READY boot=a\n\\x00\\x0d\\x09\\x7f\\xff\n".repeat(10));
 assert_eq!(CAPTURE.lock().unwrap()[0].3, bytes.repeat(10));
}
#[test] fn owned_terminal_still_processes_fragmented_fault_marker() {
 reset(true); feed(b"LOGD COLLECTED bo");
 assert_eq!(unsafe { LOGD_FAULT_AT }, u64::MAX);
 feed(b"ot=");
 assert_eq!(unsafe { LOGD_FAULT_AT }, u64::MAX, "a prefix is not a collected notice");
 feed(b"0123456789abcdef0123456789abcdef written=1 flushed=1");
 assert_eq!(unsafe { LOGD_FAULT_AT }, u64::MAX, "notice needs its terminating newline");
 feed(b"\n");
 assert_eq!(unsafe { LOGD_FAULT_AT }, 120);
 assert_eq!(CAPTURE.lock().unwrap().len(), 4);
 assert!(DISPLAY.lock().unwrap().is_empty());
}
#[test] fn owned_terminal_preserves_sustained_progress_and_full_capture() {
 reset(true);
 unsafe { (*core::ptr::addr_of_mut!(LOGD_POLICY)).unproductive = 17; }
 let notice = b"LOGD COLLECTED boot=0123456789abcdef0123456789abcdef written=1 flushed=1\n";
 feed(notice);
 assert_eq!(unsafe { (*core::ptr::addr_of!(LOGD_POLICY)).unproductive }, 17);
 NOW.store(60099, std::sync::atomic::Ordering::Relaxed); feed(notice);
 assert_eq!(unsafe { (*core::ptr::addr_of!(LOGD_POLICY)).unproductive }, 17);
 NOW.store(60100, std::sync::atomic::Ordering::Relaxed); feed(notice);
 assert_eq!(unsafe { (*core::ptr::addr_of!(LOGD_POLICY)).unproductive }, 0);
 let captured = CAPTURE.lock().unwrap();
 assert_eq!(captured.iter().filter(|(_, _, stream, bytes)| *stream == 1 && bytes == notice).count(), 3);
 assert!(captured.iter().any(|(_, _, stream, bytes)| *stream == 3 && bytes.starts_with(b"Logging collected and synced new records.")));
 assert!(DISPLAY.lock().unwrap().is_empty());
}
#[test] fn empty_or_absent_logger_has_no_output_or_capture() {
 reset(true); feed(b""); unsafe { LOGD_OUTPUT = 0; }
 feed(b"unread");
 assert!(DISPLAY.lock().unwrap().is_empty()); assert!(CAPTURE.lock().unwrap().is_empty());
}
'''
fsd = item(init, 'fn spawn_file_server(')
fsd_prefix = fsd[fsd.index('{') + 1:fsd.index('    let (startup_reader, startup_writer) = split_pipe()?;')]
fsd_prefix = re.sub(r'    use absd_user::broker::\{.*?\};\n', '', fsd_prefix, flags=re.S)
source += 'static ALLOCATIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);\n'
source += 'fn split_pipe() -> Result<(u64,u64), &' + "'static str" + '> { ALLOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed); Ok((1,2)) }\n'
source += 'fn actual_fsd_construction_prefix() -> Result<(), &' + "'static str" + '> { let console = Console;' + fsd_prefix + 'let (startup_reader, startup_writer) = split_pipe()?; let _ = (startup_reader,startup_writer); Ok(()) }\n'
fixture += r"""
#[test] fn poisoned_generation_refuses_before_fsd_resource_construction() {
 reset(false); ALLOCATIONS.store(0, std::sync::atomic::Ordering::Relaxed);
 assert!(actual_fsd_construction_prefix().is_ok());
 assert_eq!(ALLOCATIONS.load(std::sync::atomic::Ordering::Relaxed), 1);
 WRITE_FAULT.store(1, std::sync::atomic::Ordering::Relaxed); feed(&[b'x';256]);
 WRITE_FAULT.store(0, std::sync::atomic::Ordering::Relaxed);
 ALLOCATIONS.store(0, std::sync::atomic::Ordering::Relaxed);
 assert!(actual_fsd_construction_prefix().is_err());
 assert_eq!(ALLOCATIONS.load(std::sync::atomic::Ordering::Relaxed), 0);
}
#[test] fn unterminated_bound_is_visible_and_bounded() {
 reset(false); feed(&[b'x'; 256]);
 let mut expected = vec![b'x'; 224];
 expected.extend_from_slice(b" [console limit; continued]\n");
 assert_eq!(*DISPLAY.lock().unwrap(), expected);
 assert_eq!(CAPTURE.lock().unwrap()[0].3, vec![b'x'; 256]);
 feed(b"");
 expected.extend_from_slice(&[b'x'; 32]);
 expected.extend_from_slice(b" [console partial]\n");
 assert_eq!(*DISPLAY.lock().unwrap(), expected, "bounded continuation lost the remainder");
}
#[test] fn eof_closes_pending_logger_line() {
 reset(false); feed(b"logger tail");
 assert!(DISPLAY.lock().unwrap().is_empty());
 feed(b"");
 assert_eq!(*DISPLAY.lock().unwrap(), b"logger tail [console partial]\n");
}
#[test] fn unterminated_binary_tail_is_buffered_then_escaped_at_eof() {
 reset(false); let bytes = b"LOGD READY boot=a\n\0\r\t\x7f\xff";
 feed(bytes); assert_eq!(*DISPLAY.lock().unwrap(), b"LOGD READY boot=a\n");
 assert_eq!(CAPTURE.lock().unwrap()[0].3, bytes);
 feed(b"");
 assert_eq!(*DISPLAY.lock().unwrap(), b"LOGD READY boot=a\n\\x00\\x0d\\x09\\x7f\\xff [console partial]\n");
}
#[test] fn timeout_coalesces_but_read_error_closes_pending_line() {
 reset(false); feed(b"logger tail");
 READ_FAULT.store(1, std::sync::atomic::Ordering::Relaxed); logd_output(Console);
 assert!(DISPLAY.lock().unwrap().is_empty());
 READ_FAULT.store(0, std::sync::atomic::Ordering::Relaxed); feed(b" suffix\n");
 assert_eq!(*DISPLAY.lock().unwrap(), b"logger tail suffix\n");
 feed(b"error tail"); READ_FAULT.store(2, std::sync::atomic::Ordering::Relaxed); logd_output(Console);
 assert!(DISPLAY.lock().unwrap().ends_with(b"error tail [console partial]\n"));
}
#[test] fn logger_release_flushes_before_closing_generation() {
 reset(false); feed(b"generation tail"); logd_release_streams(Console);
 assert_eq!(*DISPLAY.lock().unwrap(), b"generation tail [console partial]\n");
 assert_eq!(unsafe { LOGD_OUTPUT }, 0);
}
#[test] fn escaping_is_not_split_at_the_buffer_bound() {
 reset(false); let mut bytes = vec![b'x'; 221]; bytes.push(0); feed(&bytes);
 external_chunk(Console, 0, b"worker\n").unwrap();
 let shown = DISPLAY.lock().unwrap().clone();
 assert!(shown.windows(4).any(|w| w == b"\\x00"));
 assert!(!shown.windows(3).any(|w| w == b"\\ ["));
}
#[test] fn short_or_failed_forwarding_retires_frame_publication() {
 for fault in [1, 2] {
  reset(false); WRITE_FAULT.store(fault, std::sync::atomic::Ordering::Relaxed);
  feed(&[b'x'; 256]);
  let before = DISPLAY.lock().unwrap().clone();
  WRITE_FAULT.store(0, std::sync::atomic::Ordering::Relaxed);
  assert!(external_chunk(Console, 0, b"worker\n").is_err());
  assert_eq!(*DISPLAY.lock().unwrap(), before, "uncertain forwarded line was retried");
 }
}
"""
fixture += '''
#[test] fn exact_logger_read_interleaved_with_worker_frames() {
 reset(false);
 external_chunk(Console, 0, &@FIRST@).unwrap();
 feed(&@LOGGER@);
 external_chunk(Console, 53, &@SECOND@).unwrap();
 external_chunk(Console, 149, &@THIRD@).unwrap();
 std::fs::write(std::env::var("ABSD_CONSOLE_REPLAY").unwrap(), DISPLAY.lock().unwrap().clone()).unwrap();
}
'''
for name, value in [('FIRST', bytes.fromhex(frames[0][2].decode())), ('LOGGER', logger), ('SECOND', bytes.fromhex(frames[1][2].decode())), ('THIRD', bytes.fromhex(frames[2][2].decode()))]:
    fixture = fixture.replace('@' + name + '@', repr(list(value)))
source += fixture
with tempfile.TemporaryDirectory(prefix='absd-logd-console-') as temporary:
    out = args.work.resolve() if args.work else Path(temporary)
    out.mkdir(exist_ok=True, parents=True)
    (out / 'test.rs').write_text(source)
    subprocess.run(['rustc', '--edition=2024', '--test', '-Adead_code',
                    str(out / 'test.rs'), '-o', str(out / 'test')], check=True)
    subprocess.run([str(out / 'test'), '--test-threads=1'], check=True, env=os.environ | {'ABSD_CONSOLE_REPLAY': str(out / 'serial.log')})
    rendered = (out / 'serial.log').read_bytes()
    decoder = None
    if args.platform:
        sys.path.insert(0, str(args.platform.resolve() / 'scripts'))
        decoder = importlib.import_module('absd_try')
        # Before the fix this is the actual console_gap at149/expected53.
        assert decoder.decode_console(rendered) == [expected.decode()]
    anchored = list(re.finditer(rb'^EXTERNAL OUTPUT CHUNK offset=([0-9a-f]+) data=([0-9a-f]*)\n', rendered, re.M))
    assert len(anchored) == 3, 'worker frame landed inside a forwarded logger line'
    assert b''.join(bytes.fromhex(m[2].decode()) for m in anchored) == expected
    assert all(len(line) <= 256 for line in rendered.splitlines(keepends=True))
    if decoder:
        middle = anchored[1]
        for label, replacement in [('missing-middle', b''), ('odd-hex', b'EXTERNAL OUTPUT CHUNK offset=0000000000000035 data=f\n'), ('wrong-offset', middle[0].replace(b'0000000000000035', b'0000000000000036')), ('damaged-frame-prefix', middle[0].replace(b'EXTERNAL OUTPUT', b'BROKEN OUTPUT'))]:
            malformed = rendered[:middle.start()] + replacement + rendered[middle.end():]
            try:
                decoder.decode_console(malformed)
            except decoder.Refused as error:
                print(f'unchanged shipped decoder {label}: REFUSED {error}')
            else:
                raise AssertionError(f'{label} was accepted')
    print('actual logd_output/external_chunk: exact 0/53/149 worker bytes and line boundaries PASS')
