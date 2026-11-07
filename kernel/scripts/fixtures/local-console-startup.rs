// The real init relay/formatter/drain bodies, with finite programmed host IO.
// Kernel ownership checks, scheduling, hardware and SSH authentication are
// separately tested; these adapters make no claim to implement those systems.
#![allow(dead_code)]
extern crate self as absd_user;
use std::{cell::{Cell, RefCell}, collections::{BTreeMap, VecDeque}, fmt::Write};
#[path = "@ROOT@/user/src/local_console.rs"] mod local_console;
#[path = "@ROOT@/user/src/kernel_log_wire.rs"] mod wire;
pub mod kernel_log {
    pub use crate::wire::*;
    pub fn read_decoded(_: u64, cursor: u64) -> Result<Read, i64> {
        if !crate::SNAPSHOT_ENABLED.with(|v| v.get()) { return Err(-38); }
        crate::SNAPSHOT_READS.with(|v| v.set(v.get() + 1));
        // Finite Diagnostics transport; the actual wire decoder and actual
        // maintenance Snapshot renderer consume this well-formed frame.
        let mut frame = [0u8; FRAME_BYTES];
        frame[..4].copy_from_slice(&1u32.to_le_bytes());
        frame[8..16].copy_from_slice(&2u64.to_le_bytes());
        frame[16..24].copy_from_slice(&1u64.to_le_bytes());
        frame[24..32].copy_from_slice(&2u64.to_le_bytes());
        if cursor == 0 {
            frame[4..8].copy_from_slice(&1u32.to_le_bytes());
            frame[48..56].copy_from_slice(&1u64.to_le_bytes());
            frame[56..64].copy_from_slice(&123u64.to_le_bytes());
            frame[68] = 4; frame[69] = 6;
            let text = b"read-only snapshot survives";
            frame[70..72].copy_from_slice(&(text.len() as u16).to_le_bytes());
            frame[72..78].copy_from_slice(b"kernel");
            frame[88..88 + text.len()].copy_from_slice(text);
        }
        decode(&frame)
    }
}
thread_local! {
    static SNAPSHOT_ENABLED: Cell<bool> = const { Cell::new(false) };
    static SNAPSHOT_READS: Cell<usize> = const { Cell::new(0) };
    static FAIL_SERIAL: Cell<bool> = const { Cell::new(false) };
    static FAIL_AFTER_WRITE: Cell<bool> = const { Cell::new(false) };
    static SERIAL: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static INPUT: RefCell<VecDeque<u8>> = const { RefCell::new(VecDeque::new()) };
    static PIPES: RefCell<BTreeMap<u64, VecDeque<u8>>> = RefCell::new(BTreeMap::new());
    static EOF_PIPE: Cell<u64> = const { Cell::new(0) };
    static ERROR_PIPE: Cell<u64> = const { Cell::new(0) };
    static RETAINED: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Error { Timeout, Other }
#[derive(Clone, Copy)] pub struct Console;
#[derive(Clone, Copy)] pub struct Pipe(u64);
pub const RIGHT_READ: u8 = 1;
pub const RIGHT_WRITE: u8 = 2;
const MAX_WRITE: usize = 256;
fn queue(handle: u64, bytes: &[u8]) { PIPES.with(|p| p.borrow_mut().entry(handle).or_default().extend(bytes)); }
fn queued(handle: u64) -> Vec<u8> { PIPES.with(|p| p.borrow().get(&handle).map(|v| v.iter().copied().collect()).unwrap_or_default()) }
fn read(q: &mut VecDeque<u8>, bytes: &mut [u8]) -> Result<usize, Error> {
    if q.is_empty() { return Err(Error::Timeout); }
    let n = bytes.len().min(q.len());
    for byte in &mut bytes[..n] { *byte = q.pop_front().unwrap(); }
    Ok(n)
}
impl Console {
    pub fn write_once(self, bytes: &[u8]) -> Result<usize, Error> {
        assert!(bytes.len() <= MAX_WRITE);
        if FAIL_SERIAL.with(Cell::get) { return Err(Error::Other); }
        SERIAL.with(|v| v.borrow_mut().extend_from_slice(bytes));
        if FAIL_AFTER_WRITE.with(|v| v.replace(false)) { FAIL_SERIAL.with(|v| v.set(true)); }
        Ok(bytes.len())
    }
    pub fn write_all(self, bytes: &[u8]) -> Result<(), Error> { for chunk in bytes.chunks(MAX_WRITE) { self.write_once(chunk)?; } Ok(()) }
    pub fn write_str(self, s: &str) -> Result<(), Error> { self.write_all(s.as_bytes()) }
    pub fn read_timeout(self, bytes: &mut [u8], _: u64) -> Result<usize, Error> { INPUT.with(|q| read(&mut q.borrow_mut(), bytes)) }
}
impl Pipe {
    pub fn create() -> Result<Self, Error> { Ok(Self(10)) }
    pub fn from_raw(raw: u64) -> Self { Self(raw) }
    pub fn raw(self) -> u64 { self.0 }
    pub fn read_timeout(self, bytes: &mut [u8], _: u64) -> Result<usize, Error> {
        if ERROR_PIPE.with(Cell::get) == self.0 { return Err(Error::Other); }
        if EOF_PIPE.with(Cell::get) == self.0 { return Ok(0); }
        PIPES.with(|p| read(p.borrow_mut().entry(self.0).or_default(), bytes))
    }
    pub fn write_timeout(self, bytes: &[u8], _: u64) -> Result<usize, Error> { queue(self.0, bytes); Ok(bytes.len()) }
}
pub fn duplicate(handle: u64, _: u8) -> Result<u64, Error> { Ok(handle) }
pub fn close(_: u64) -> Result<(), Error> { Ok(()) }
pub fn set_console_presentation(_: Console, _: bool) -> Result<(), Error> { Ok(()) }
fn service_record(_: Console, _: u64, _: u64, _: u64, bytes: &[u8]) { RETAINED.with(|v| v.borrow_mut().extend_from_slice(bytes)); }
static mut FSD_SERVER_PID: u64 = 2;
#[path = "@ROOT@/user/src/worker_console.rs"] mod worker_console;
#[path = "@ROOT@/user/src/console_lines.rs"] mod console_lines;
@PRODUCTION@
fn serial() -> Vec<u8> { SERIAL.with(|v| v.borrow().clone()) }
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = std::path::Path::new(&args[1]);
    let local = args[2] != "headless";
    let worker_chunk: usize = args[3].parse().unwrap();
    let fsd_chunk: usize = args[4].parse().unwrap();
    let fsd = std::fs::read(out.join("fsd.input")).unwrap();
    let worker = std::fs::read(out.join("worker.input")).unwrap();
    let mut worker_output = worker_console::Output::new(Console, 0, 0x811c9dc5);
    let mut terminal = if local { Some(local_console::Terminal::new().unwrap()) } else { None };
    unsafe { FSD_LOG_READERS = [1, 2]; }
    Console.write_str("ABSD KERNEL BOOT\nEXTERNAL OUTPUT BEGIN encoding=hex\n").unwrap();
    if let Some(t) = terminal.as_mut() {
        queue(t.writer(), b"LOCAL LOGIN FIXTURE\n");
        t.spawned();
        INPUT.with(|q| q.borrow_mut().extend(b"discarded-before-prompt\n"));
        t.step(Console, Pipe(3));
        assert!(queued(3).is_empty());
        assert!(!serial().windows(b"LOCAL LOGIN FIXTURE\n".len()).any(|w| w == b"LOCAL LOGIN FIXTURE\n"));
        INPUT.with(|q| q.borrow_mut().extend(b"\x1dk"));
        t.step(Console, Pipe(3));
        assert!(String::from_utf8_lossy(&serial()).contains("kernel maintenance"));
        INPUT.with(|q| q.borrow_mut().extend(b"\x1dr")); t.step(Console, Pipe(3));
        assert!(queued(3).is_empty());
    }
    // Fragmented FSD publication, interleaved with other init records. The
    // actual line relay must withhold incomplete raw witnesses atomically.
    if args[2] == "partial" || args[2] == "write-failure" {
        queue(1, &fsd);
        FAIL_SERIAL.with(|v| v.set(args[2] == "write-failure"));
        assert!(external_worker_chunk(Console, terminal.as_mut(), &mut worker_output, 1, &worker).is_err());
        assert!(!local_console::startup_capture_closed());
        assert!(queued(3).is_empty());
        std::fs::write(out.join("serial"), serial()).unwrap();
        println!("actual startup publication refusal: {} PASS", args[2]);
        return;
    }
    if args[2] == "network-race" { queue(1, &fsd); }
    else {
        for bytes in fsd.chunks(fsd_chunk) {
            queue(1, bytes); drain_fsd_logs(Console);
            Console.write_str("INIT FIXTURE interleaving\n").unwrap();
        }
        assert!(drain_fsd_logs(Console));
    }
    for bytes in worker.chunks(worker_chunk) {
        let idle = drain_fsd_logs(Console);
        if let Some(t) = terminal.as_mut() { external_worker_startup(Console, t, &mut worker_output, Pipe(3), idle).unwrap(); }
        external_worker_chunk(Console, terminal.as_mut(), &mut worker_output, 1, bytes).unwrap();
    }
    let before_handoff = serial();
    if args[2] == "no-marker" {
        let t = terminal.as_mut().unwrap();
        external_worker_startup(Console, t, &mut worker_output, Pipe(3), drain_fsd_logs(Console)).unwrap();
        assert!(!local_console::startup_capture_closed());
        assert!(queued(3).is_empty());
        assert!(!serial().windows(b"LOCAL LOGIN FIXTURE\n".len()).any(|w| w == b"LOCAL LOGIN FIXTURE\n"));
        std::fs::write(out.join("serial"), serial()).unwrap();
        println!("no trusted marker: presentation stays held PASS");
        return;
    }
    if let Some(t) = terminal.as_mut() {
        // FSD data queued after the worker marker must precede UI handoff.
        queue(1, b"FSD queued before handoff\n");
        external_worker_startup(Console, t, &mut worker_output, Pipe(3), drain_fsd_logs(Console)).unwrap();
        assert!(!serial().windows(b"LOCAL LOGIN FIXTURE\n".len()).any(|w| w == b"LOCAL LOGIN FIXTURE\n"));
        external_worker_startup(Console, t, &mut worker_output, Pipe(3), drain_fsd_logs(Console)).unwrap();
        assert!(serial().windows(b"LOCAL LOGIN FIXTURE\n".len()).any(|w| w == b"LOCAL LOGIN FIXTURE\n"), "closed={} queue={:?} serial={}", local_console::startup_capture_closed(), queued(10), String::from_utf8_lossy(&serial()));
        INPUT.with(|q| q.borrow_mut().extend(b"after-prompt\n")); t.step(Console, Pipe(3));
        assert_eq!(queued(3), b"after-prompt\n");
        assert!(local_console::Terminal::new().is_err(), "never restart physical framing after a skipped range");
    }
    let after_handoff = serial();
    let runtime = b"worker-runtime\n";
    external_worker_chunk(Console, terminal.as_mut(), &mut worker_output, 0, runtime).unwrap();
    queue(1, b"fsd-runtime\n"); drain_fsd_logs(Console);
    worker_output.finish().unwrap();
    let (offset, digest) = worker_output.position();
    external_output_end(Console, terminal.is_some(), offset, digest).unwrap();
    if local { assert_eq!(serial(), after_handoff); }
    else { assert!(String::from_utf8_lossy(&serial()).contains("EXTERNAL OUTPUT END")); }
    assert!(RETAINED.with(|v| v.borrow().ends_with(b"fsd-runtime\n")));
    std::fs::write(out.join("serial"), serial()).unwrap();
    std::fs::write(out.join("startup-prefix"), before_handoff).unwrap();
    println!("actual init relay, line publication, frame formatter and {} handoff PASS", args[2]);
}
