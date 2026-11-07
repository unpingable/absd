extern crate alloc;
extern crate self as absd_runtime;
use absd_fs::{Device, Error, Fs, OpenFlags, SECTOR};
use absd_fsd::{
    Inbox, PipeState, Server, Taken,
    proto::{self, Frame, op},
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    io::{self, Read},
    path::Path,
};
mod health;
mod logs;
include!("crt.rs");
struct Disk(BTreeMap<u64, [u8; SECTOR]>);
impl Device for Disk {
    fn sectors(&self) -> u64 {
        16384
    }
    fn read(&mut self, n: u64, b: &mut [u8; SECTOR]) -> Result<(), Error> {
        *b = self.0.get(&n).copied().unwrap_or([0; SECTOR]);
        Ok(())
    }
    fn write(&mut self, n: u64, b: &[u8; SECTOR]) -> Result<(), Error> {
        self.0.insert(n, *b);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
struct Transport {
    server: Server<Disk>,
    input: Inbox,
    reply: VecDeque<u8>,
    ops: Vec<u8>,
    now: u64,
    mode: String,
}
impl Transport {
    fn new() -> Self {
        let mut d = Disk(BTreeMap::new());
        absd_fs::format(&mut d, 7).unwrap();
        let mut fs = Fs::mount(d, true).unwrap();
        for p in [b"/var".as_slice(), b"/var/log", b"/var/log/journal"] {
            fs.mkdir(p).unwrap();
        }
        let mut journal = absd_fsd::journal::Journal::new(*b"0123456789abcdef0123456789abcdef");
        journal.collector_pid = Some(9);
        journal.sample_ticks = 1;
        let health = journal.health();
        for (path, data) in [
            (b"/var/log/journal-health".as_slice(), health.as_bytes()),
            (b"/var/log/journal/current".as_slice(), b"J1 0123456789abcdef0123456789abcdef 1 1 6 service.fsd 1 0 fixture retained record\n".as_slice()),
        ] {
            let h = fs.open(path, OpenFlags { write: true, create: true, ..Default::default() }).unwrap();
            fs.write_at(h, 0, data).unwrap();
            fs.close(h).unwrap();
        }
        let mut server = Server::new(fs, 6, Vec::new());
        assert!(server.attach_logger(6));
        Self {
            server,
            input: Inbox::new(),
            reply: VecDeque::new(),
            ops: Vec::new(),
            now: 0,
            mode: std::env::var("SERVER_MODE").unwrap(),
        }
    }
    fn write(&mut self, bytes: &[u8]) -> usize {
        self.input.push(bytes);
        while let Taken::Frame { seq, body } = self.input.take() {
            let operation = body[0];
            self.ops.push(operation);
            if self.mode == "silent" || (self.mode == "version_silent" && operation == op::VERSION)
            {
                continue;
            }
            let mut reply = if operation == op::VERSION && self.mode != "current" {
                let mut frame = Frame::reply(if self.mode == "refused" { -95 } else { 0 });
                if self.mode == "malformed" {
                    frame.0.push(0);
                } else {
                    let mut v = absd_fsd::version::compiled();
                    v.fsd_protocol += 1;
                    frame.0.extend(absd_fsd::version::encode(&v));
                }
                frame.finish()
            } else if operation == op::OPEN && std::env::var_os("READ_ERROR").is_some() {
                Frame::reply(-13).finish()
            } else {
                self.server.dispatch(
                    6,
                    &body,
                    &|_| {
                        Some(PipeState {
                            request_available: 0,
                            request_writers: 1,
                            reply_available: 0,
                            reply_readers: 1,
                        })
                    },
                    self.now,
                )
            };
            proto::stamp_seq(&mut reply, seq);
            self.reply.extend(reply);
        }
        bytes.len()
    }
}
thread_local! {static TRANSPORT:RefCell<Transport>=RefCell::new(Transport::new());}
pub fn ticks() -> u64 {
    TRANSPORT.with(|t| t.borrow().now)
}
pub fn write_within(_: u64, b: &[u8], _: u64) -> Result<usize, i64> {
    Ok(TRANSPORT.with(|t| t.borrow_mut().write(b)))
}
pub fn read_within(_: u64, b: &mut [u8], budget: u64) -> Result<usize, i64> {
    TRANSPORT.with(|t| {
        let mut t = t.borrow_mut();
        if t.reply.is_empty() {
            t.now += budget;
            return Err(-110);
        }
        let n = b.len().min(t.reply.len());
        for item in &mut b[..n] {
            *item = t.reply.pop_front().unwrap();
        }
        Ok(n)
    })
}
unsafe fn syscall3(n: u64, _a: u64, b: u64, c: u64) -> i64 {
    match n {
        4 => 7,
        1 => write_within(
            0,
            unsafe { std::slice::from_raw_parts(b as *const u8, c as usize) },
            0,
        )
        .unwrap() as i64,
        15 => read_within(
            0,
            unsafe { std::slice::from_raw_parts_mut(b as *mut u8, c as usize) },
            10,
        )
        .unwrap_or(0) as i64,
        _ => 0,
    }
}
fn report() {
    TRANSPORT.with(|t| {
        let t = t.borrow();
        eprintln!("FIXTURE operations={:?} ticks={}", t.ops, t.now);
    });
}
unsafe fn __absd_std_stderr_write(p: *const u8, n: usize) {
    eprint!(
        "{}",
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(p, n) })
    );
}
fn __absd_std_exit(status: i32) -> ! {
    report();
    std::process::exit(status)
}
pub fn link_anchor() {}
pub fn boot_id() -> Result<[u8; 16], i64> {
    Ok([1; 16])
}
pub fn sleep_ticks(_: u64) {}
pub fn boot_millis() -> u64 {
    ticks()
}
pub mod kernel_log {
    pub use crate::wire::*;
    pub fn read(c: &mut Cursor) -> Result<Read, i64> {
        eprintln!("kernel-view");
        if std::env::var_os("RING_ERROR").is_some() {
            return Err(-13);
        }
        let text=b"pid=1 stream=lifecycle Logging is retrying. consecutive_unproductive=60 crash_restarts=1 retry_ticks=60000";
        let mut encoded = [0u8; FRAME_BYTES];
        encoded[..4].copy_from_slice(&1u32.to_le_bytes());
        for (offset, value) in [(8, 2u64), (16, 1), (24, 2)] {
            encoded[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        if c.0 < 2 {
            encoded[4..8].copy_from_slice(&1u32.to_le_bytes());
            encoded[48..56].copy_from_slice(&1u64.to_le_bytes());
            encoded[56..64].copy_from_slice(&100u64.to_le_bytes());
            encoded[68] = 5;
            encoded[69] = 12;
            encoded[70..72].copy_from_slice(&(text.len() as u16).to_le_bytes());
            encoded[72..84].copy_from_slice(b"service.logd");
            encoded[88..88 + text.len()].copy_from_slice(text);
        }
        let read = decode(&encoded)?;
        c.0 = read.next;
        Ok(read)
    }
}
struct FileAdapter {
    handle: u64,
    offset: u64,
}
impl FileAdapter {
    fn open(p: &Path) -> io::Result<Self> {
        let h = fsd::open(p.as_os_str().as_encoded_bytes(), 1);
        if h < 0 {
            Err(io::Error::from_raw_os_error(-h as i32))
        } else {
            Ok(Self {
                handle: h as u64,
                offset: 0,
            })
        }
    }
}
impl Read for FileAdapter {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = fsd::read_at(self.handle, self.offset, b);
        if n < 0 {
            Err(io::Error::from_raw_os_error(-n as i32))
        } else {
            self.offset += n as u64;
            Ok(n as usize)
        }
    }
}
impl Drop for FileAdapter {
    fn drop(&mut self) {
        fsd::close(self.handle);
    }
}
// Host std transport adapters: actual health control flow still performs
// each read/stat through the full runtime and real server dispatcher.
fn fixture_read(path: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    FileAdapter::open(Path::new(path))?.read_to_end(&mut bytes)?;
    Ok(bytes)
}
struct FixtureMetadata(u64);
impl FixtureMetadata {
    fn len(&self) -> u64 {
        self.0
    }
}
fn fixture_metadata(path: &str) -> io::Result<FixtureMetadata> {
    fsd::stat(path.as_bytes())
        .map(|attr| FixtureMetadata(u64::from_le_bytes(attr[8..16].try_into().unwrap())))
        .map_err(|code| io::Error::from_raw_os_error(-code as i32))
}
fn main() {
    let name = std::env::var("EXEC_NAME").unwrap_or_else(|_| "/bin/logs".into());
    if std::env::var("SERVER_MODE").unwrap() != "missing" {
        fsd::install(&[(1, 2)]);
    } else {
        fsd::install(&[]);
    }
    actual_crt(name.as_bytes());
    match std::env::var("ACTION").as_deref() {
        Ok("health_refused") | Ok("health_timeout") => {
            let mode = if std::env::var("ACTION").unwrap() == "health_refused" {
                "refused"
            } else {
                "version_silent"
            };
            TRANSPORT.with(|t| t.borrow_mut().mode = mode.into());
            health::invoke();
        }
        Ok("spoof") => {
            let h = fsd::open(b"/var/log/journal-health", 1);
            if h >= 0 {
                fsd::close(h as u64);
            }
        }
        Ok("raw") => {
            let _ = fsd::request_on(
                0,
                Frame::request(op::OPEN)
                    .u32(1)
                    .bytes(b"/var/log/journal-health")
                    .finish(),
            );
        }
        Ok("raw_bounded") => {
            let _ = fsd::request_on_within(
                0,
                Frame::request(op::OPEN)
                    .u32(1)
                    .bytes(b"/var/log/journal-health")
                    .finish(),
                100,
            );
        }
        Ok("raw_version") => {
            let _ = fsd::request_on(0, Frame::request(op::VERSION).finish());
            TRANSPORT.with(|t| t.borrow_mut().mode = "wrong".into());
            let _ = fsd::open(b"/var/log/journal-health", 1);
        }
        Ok("failed_recheck") => {
            assert!(fsd::check_server(0, false).is_ok());
            TRANSPORT.with(|t| t.borrow_mut().mode = "wrong".into());
            assert!(fsd::check_server_within(0, false, 1000).is_err());
            let _ = fsd::open(b"/var/log/journal-health", 1);
        }
        Ok("late_reply") => {
            assert!(fsd::check_server_within(0, false, 1000).is_err());
            TRANSPORT.with(|t| {
                let mut t = t.borrow_mut();
                t.mode = "wrong".into();
                let mut reply = Frame::reply(0);
                reply
                    .0
                    .extend(absd_fsd::version::encode(&absd_fsd::version::compiled()));
                t.reply.extend(reply.finish_seq((7u64 << 32) | 1));
            });
            let _ = fsd::open(b"/var/log/journal-health", 1);
        }
        Ok("rebind") => {
            let h = fsd::open(b"/var/log/journal-health", 1);
            assert!(h >= 0);
            fsd::close(h as u64);
            TRANSPORT.with(|t| t.borrow_mut().mode = "wrong".into());
            fsd::install(&[(3, 4)]);
            let _ = fsd::open(b"/var/log/journal-health", 1);
        }
        _ => logs::invoke(),
    }
    report();
}
