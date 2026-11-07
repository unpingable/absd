#[path = "../../src/sh_drain.rs"]
mod copier;
use super::SharedSink;
use copier::{BufferedFile, Drain, Step, Target};
use std::{
    cell::{Cell, RefCell},
    io::{self, Cursor, Read, Write},
    rc::Rc,
};
#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    max_write: Option<usize>,
    fail_at: Option<usize>,
    fail_flush: bool,
    interrupt_writes: usize,
}
struct Writer(Rc<RefCell<State>>);
impl Write for Writer {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let mut s = self.0.borrow_mut();
        s.writes += 1;
        if s.interrupt_writes != 0 {
            s.interrupt_writes -= 1;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if s.fail_at.is_some_and(|at| s.bytes.len() >= at) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "first write failure",
            ));
        }
        let mut n = b.len().min(s.max_write.unwrap_or(usize::MAX));
        if let Some(at) = s.fail_at {
            n = n.min(at - s.bytes.len());
        }
        s.bytes.extend_from_slice(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        s.flushes += 1;
        if s.fail_flush {
            Err(io::Error::other("first sync failure"))
        } else {
            Ok(())
        }
    }
}
type File = BufferedFile<Writer, Box<dyn Fn() -> u64>>;
impl Target for SharedSink<File> {
    fn flush_pending(&mut self, force: bool) -> io::Result<bool> {
        self.with_mut(|w| w.flush_pending(force))
    }
    fn wait_limit(&self, ticks: u64) -> u64 {
        self.with_mut(|w| w.wait_limit(ticks))
    }
    fn finish(&mut self, durable: bool) -> io::Result<()> {
        self.flush_pending(true)?;
        if durable { self.flush() } else { Ok(()) }
    }
}
fn endpoint() -> (SharedSink<File>, Rc<RefCell<State>>, Rc<Cell<u64>>) {
    let s = Rc::new(RefCell::new(State::default()));
    let now = Rc::new(Cell::new(0));
    let clock = now.clone();
    (
        SharedSink(Rc::new(RefCell::new(BufferedFile::new(
            Writer(s.clone()),
            Box::new(move || clock.get()) as Box<dyn Fn() -> u64>,
        )))),
        s,
        now,
    )
}
#[test]
fn shared_file_coalesces_both_actual_drains_in_received_order() {
    let (sink, state, _) = endpoint();
    let mut a = Drain::new(1, Cursor::new(vec![b'a'; 32768]), sink.clone());
    let mut b = Drain::new(2, Cursor::new(vec![b'b'; 32768]), sink.clone());
    let mut expected = Vec::new();
    for _ in 0..128 {
        assert!(matches!(
            a.step(1, |r, b, _| r.read(b).map(Some)),
            Step::Moved
        ));
        expected.extend_from_slice(&[b'a'; 256]);
        assert!(matches!(
            b.step(1, |r, b, _| r.read(b).map(Some)),
            Step::Moved
        ));
        expected.extend_from_slice(&[b'b'; 256]);
    }
    a.finish(true).unwrap();
    b.finish(true).unwrap();
    assert_eq!(state.borrow().bytes, expected);
    assert_eq!(
        state.borrow().writes,
        16,
        "one shared4KiB buffer must coalesce256 receivedchunks without alias reordering"
    );
}

#[test]
fn full_buffer_flushes_before_the_next_pipe_read() {
    let (sink, state, _) = endpoint();
    let mut d = Drain::new(0, (), sink);
    for _ in 0..16 {
        assert!(matches!(
            d.step(1, |_, b, _| {
                b.fill(b'x');
                Ok(Some(256))
            }),
            Step::Moved
        ));
    }
    assert_eq!(
        state.borrow().bytes.len(),
        4096,
        "capacity must flush without another source read or EOF"
    );
    assert_eq!(state.borrow().flushes, 0);
}
#[test]
fn final_scope_flush_attempts_both_files_and_preserves_first_failure() {
    let (mut a, sa, _) = endpoint();
    let (mut b, sb, _) = endpoint();
    a.write_all(b"a").unwrap();
    b.write_all(b"b").unwrap();
    sa.borrow_mut().fail_flush = true;
    let streams = [
        Rc::new(super::streams::Destination::File(a)),
        Rc::new(super::streams::Destination::File(b)),
    ];
    let e = super::streams::flush(&streams).unwrap_err();
    assert_eq!(e.to_string(), "first sync failure");
    assert_eq!(
        sb.borrow().bytes,
        b"b",
        "a failed first endpoint must not discard a second endpoint's accepted bytes"
    );
    assert_eq!(sb.borrow().flushes, 1);
}

fn failure(step: Step) -> io::Error {
    match step {
        Step::Failed(e) => e,
        _ => panic!("expected failure"),
    }
}
fn pump<R: Read, T: Target>(d: &mut Drain<R, T>) -> io::Result<()> {
    for _ in 0..1_000_000 {
        match d.step(1, |r, b, _| r.read(b).map(Some)) {
            Step::Done => return Ok(()),
            Step::Failed(e) => return Err(e),
            _ => {}
        }
    }
    panic!("finite source never ended")
}
#[test]
fn shared_age_belongs_to_the_file_not_each_alias() {
    let (mut a, s, now) = endpoint();
    let mut b = a.clone();
    a.write_all(b"a").unwrap();
    now.set(8);
    b.write_all(b"b").unwrap();
    assert_eq!(a.wait_limit(1000), 8);
    now.set(16);
    assert!(b.flush_pending(false).unwrap());
    assert!(!a.flush_pending(false).unwrap());
    assert_eq!(s.borrow().bytes, b"ab");
    assert_eq!(s.borrow().flushes, 0);
}
#[test]
fn timeout_flushes_other_alias_bytes_without_sync() {
    let (mut a, s, _) = endpoint();
    let b = a.clone();
    a.write_all(b"a").unwrap();
    let mut d = Drain::new(1, (), b);
    assert!(matches!(d.step(1, |_, _, _| Ok(None)), Step::Moved));
    assert_eq!(s.borrow().bytes, b"a");
    assert_eq!(s.borrow().flushes, 0);
    assert!(matches!(d.step(1, |_, _, _| Ok(None)), Step::Pending));
}
#[test]
fn pending_age_limits_a_long_pipe_wait() {
    let (mut a, _, now) = endpoint();
    a.write_all(b"x").unwrap();
    now.set(1);
    let mut d = Drain::new(7, (), a);
    assert_eq!(d.stage, 7);
    d.step(1000, |_, _, wait| {
        assert_eq!(wait, 15);
        Ok(None)
    });
}
#[test]
fn short_read_is_not_eof() {
    let (a, s, _) = endpoint();
    let mut d = Drain::new(0, 0usize, a);
    for _ in 0..3 {
        assert!(matches!(
            d.step(1, |at, b, _| {
                let n = *at + 1;
                b[..n].fill(b'a' + *at as u8);
                *at += 1;
                Ok(Some(n))
            }),
            Step::Moved
        ));
        assert!(s.borrow().bytes.is_empty());
    }
    assert!(matches!(d.step(1, |_, _, _| Ok(Some(0))), Step::Done));
    assert_eq!(s.borrow().bytes, b"abbccc");
    assert_eq!(s.borrow().flushes, 1);
}
#[test]
fn one_eof_keeps_the_shared_file_writable_by_another_drain() {
    let (a, s, _) = endpoint();
    let b = a.clone();
    let mut x = Drain::new(0, (), a);
    let mut y = Drain::new(1, (), b);
    x.step(1, |_, v, _| {
        v[..3].copy_from_slice(b"aaa");
        Ok(Some(3))
    });
    y.step(1, |_, v, _| {
        v[..3].copy_from_slice(b"bbb");
        Ok(Some(3))
    });
    assert!(matches!(x.step(1, |_, _, _| Ok(Some(0))), Step::Done));
    drop(x);
    assert_eq!(s.borrow().bytes, b"aaabbb");
    y.step(1, |_, v, _| {
        v[..3].copy_from_slice(b"ccc");
        Ok(Some(3))
    });
    y.finish(true).unwrap();
    assert_eq!(s.borrow().bytes, b"aaabbbccc");
}
#[test]
fn dropping_an_early_alias_does_not_flush_or_discard_the_shared_buffer() {
    let (mut a, s, _) = endpoint();
    let mut b = a.clone();
    a.write_all(b"first").unwrap();
    drop(a);
    assert!(s.borrow().bytes.is_empty());
    b.write_all(b"second").unwrap();
    b.flush().unwrap();
    assert_eq!(s.borrow().bytes, b"firstsecond");
}
#[test]
fn partial_writes_preserve_exact_bytes() {
    let (a, s, _) = endpoint();
    s.borrow_mut().max_write = Some(3);
    let data: Vec<u8> = (0..1003).map(|n| (n % 251) as u8).collect();
    let mut d = Drain::new(0, Cursor::new(data.clone()), a);
    pump(&mut d).unwrap();
    assert_eq!(s.borrow().bytes, data);
}
#[test]
fn partial_write_failure_is_shared_and_drop_never_retries() {
    let (a, s, _) = endpoint();
    let mut alias = a.clone();
    {
        let mut s = s.borrow_mut();
        s.max_write = Some(3);
        s.fail_at = Some(5);
    }
    let mut d = Drain::new(0, Cursor::new(vec![b'x'; 4096]), a);
    let e = pump(&mut d).unwrap_err();
    assert_eq!(e.to_string(), "first write failure");
    let calls = s.borrow().writes;
    assert_eq!(s.borrow().bytes, b"xxxxx");
    assert_eq!(
        alias.write_all(b"later").unwrap_err().to_string(),
        "first write failure"
    );
    assert_eq!(
        alias.flush().unwrap_err().to_string(),
        "first write failure"
    );
    drop(d);
    drop(alias);
    assert_eq!(s.borrow().writes, calls);
    assert_eq!(s.borrow().flushes, 0);
}
#[test]
fn eof_write_failure_is_not_retried_when_the_last_owner_drops() {
    let (a, s, _) = endpoint();
    s.borrow_mut().fail_at = Some(0);
    let mut d = Drain::new(0, Cursor::new(b"buffered".to_vec()), a);
    assert_eq!(pump(&mut d).unwrap_err().kind(), io::ErrorKind::StorageFull);
    let calls = s.borrow().writes;
    drop(d);
    assert_eq!(s.borrow().writes, calls);
    assert!(s.borrow().bytes.is_empty());
}
#[test]
fn sync_failure_is_shared_and_not_retried_at_last_drop() {
    let (a, s, _) = endpoint();
    let mut alias = a.clone();
    s.borrow_mut().fail_flush = true;
    let mut d = Drain::new(0, Cursor::new(b"buffered".to_vec()), a);
    assert_eq!(pump(&mut d).unwrap_err().to_string(), "first sync failure");
    assert_eq!(s.borrow().bytes, b"buffered");
    let calls = s.borrow().writes;
    assert_eq!(
        alias.write_all(b"later").unwrap_err().to_string(),
        "first sync failure"
    );
    drop(d);
    drop(alias);
    assert_eq!(s.borrow().writes, calls);
    assert_eq!(s.borrow().flushes, 1);
}
#[test]
fn read_failure_preserves_preceding_bytes_and_the_first_error() {
    let (a, s, _) = endpoint();
    let mut d = Drain::new(0, (), a);
    d.step(1, |_, b, _| {
        b[..3].copy_from_slice(b"abc");
        Ok(Some(3))
    });
    let e = failure(d.step(1, |_, _, _| Err(io::Error::other("first read failure"))));
    assert_eq!(e.to_string(), "first read failure");
    assert_eq!(s.borrow().bytes, b"abc");
    assert_eq!(s.borrow().flushes, 0);
}
#[test]
fn read_failure_precedes_a_later_flush_error() {
    let (a, s, _) = endpoint();
    s.borrow_mut().fail_at = Some(0);
    let mut d = Drain::new(0, (), a);
    d.step(1, |_, b, _| {
        b[0] = b'x';
        Ok(Some(1))
    });
    assert_eq!(
        failure(d.step(1, |_, _, _| Err(io::Error::other("first read failure")))).to_string(),
        "first read failure"
    );
    let calls = s.borrow().writes;
    drop(d);
    assert_eq!(s.borrow().writes, calls);
}
#[test]
fn interrupt_and_end_flush_accepted_bytes_with_distinct_sync_behavior() {
    for durable in [false, true] {
        let (a, s, _) = endpoint();
        let mut d = Drain::new(0, (), a);
        d.step(1, |_, b, _| {
            b[..3].copy_from_slice(b"abc");
            Ok(Some(3))
        });
        d.finish(durable).unwrap();
        assert_eq!(s.borrow().bytes, b"abc");
        assert_eq!(s.borrow().flushes, usize::from(durable));
        let calls = s.borrow().writes;
        drop(d);
        assert_eq!(s.borrow().writes, calls);
    }
}
#[test]
fn terminal_partial_failure_stays_visible_without_hidden_writes() {
    for durable in [false, true] {
        let (a, s, _) = endpoint();
        s.borrow_mut().fail_at = Some(2);
        let mut d = Drain::new(0, (), a);
        d.step(1, |_, b, _| {
            b[..3].copy_from_slice(b"abc");
            Ok(Some(3))
        });
        assert_eq!(
            d.finish(durable).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        let calls = s.borrow().writes;
        drop(d);
        assert_eq!(s.borrow().writes, calls);
        assert_eq!(s.borrow().bytes, b"ab");
    }
}
#[test]
fn zero_write_becomes_a_shared_failure_without_retry() {
    let (a, s, _) = endpoint();
    s.borrow_mut().max_write = Some(0);
    let mut d = Drain::new(0, Cursor::new(b"x".to_vec()), a);
    assert_eq!(pump(&mut d).unwrap_err().kind(), io::ErrorKind::WriteZero);
    let calls = s.borrow().writes;
    drop(d);
    assert_eq!(s.borrow().writes, calls);
}
#[test]
fn last_scope_reports_the_first_error_even_when_the_second_file_also_fails() {
    let (mut a, sa, _) = endpoint();
    let (mut b, sb, _) = endpoint();
    a.write_all(b"a").unwrap();
    b.write_all(b"b").unwrap();
    sa.borrow_mut().fail_at = Some(0);
    sb.borrow_mut().fail_flush = true;
    let streams = [
        Rc::new(super::streams::Destination::File(a)),
        Rc::new(super::streams::Destination::File(b)),
    ];
    assert_eq!(
        super::streams::flush(&streams).unwrap_err().to_string(),
        "first write failure"
    );
    assert_eq!(sb.borrow().bytes, b"b");
    assert_eq!(sb.borrow().flushes, 1);
    let calls = (sa.borrow().writes, sb.borrow().writes);
    drop(streams);
    assert_eq!((sa.borrow().writes, sb.borrow().writes), calls);
}
#[test]
fn alias_scope_syncs_one_resolved_endpoint_once() {
    let (mut a, s, _) = endpoint();
    a.write_all(b"a").unwrap();
    let ep = Rc::new(super::streams::Destination::File(a));
    let streams = [ep.clone(), ep];
    super::streams::flush(&streams).unwrap();
    assert_eq!(s.borrow().writes, 1);
    assert_eq!(s.borrow().flushes, 1);
}
struct Immediate(Writer);
impl Write for Immediate {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl Target for Immediate {
    fn flush_pending(&mut self, _: bool) -> io::Result<bool> {
        Ok(false)
    }
    fn wait_limit(&self, n: u64) -> u64 {
        n
    }
    fn finish(&mut self, durable: bool) -> io::Result<()> {
        if durable { self.flush() } else { Ok(()) }
    }
}
#[test]
fn capture_and_discard_style_targets_are_immediate() {
    let state = Rc::new(RefCell::new(State::default()));
    let mut d = Drain::new(0, (), Immediate(Writer(state.clone())));
    d.step(1, |_, b, _| {
        b[..3].copy_from_slice(b"abc");
        Ok(Some(3))
    });
    assert_eq!(state.borrow().bytes, b"abc");
    assert_eq!(state.borrow().writes, 1);
    d.finish(false).unwrap();
    assert_eq!(state.borrow().flushes, 0);
}
#[test]
fn drain_has_no_large_inline_output_buffer() {
    assert!(std::mem::size_of::<Drain<(), SharedSink<File>>>() < 256);
    assert_eq!(copier::FILE_BUFFER_BYTES, 4096);
    assert_eq!(copier::MAX_BUFFER_TICKS, 16);
}
#[cfg(target_os = "linux")]
#[test]
fn actual_host_pipe_over_capacity_drains_with_shared_file_order_intact() {
    use std::{fs::File, os::fd::FromRawFd, thread};
    unsafe extern "C" {
        fn pipe(p: *mut i32) -> i32;
        fn fcntl(fd: i32, cmd: i32) -> i32;
    }
    let mut fds = [0; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
    let cap = unsafe { fcntl(fds[0], 1032) };
    assert!(cap > 0 && cap <= 1 << 20);
    let from = unsafe { File::from_raw_fd(fds[0]) };
    let mut to = unsafe { File::from_raw_fd(fds[1]) };
    let data: Vec<u8> = (0..cap as usize * 4).map(|n| (n % 251) as u8).collect();
    let bytes = data.clone();
    let child = thread::spawn(move || to.write_all(&bytes).unwrap());
    let (a, s, _) = endpoint();
    let mut d = Drain::new(0, from, a);
    pump(&mut d).unwrap();
    child.join().unwrap();
    assert_eq!(s.borrow().bytes, data);
    assert_eq!(
        s.borrow().writes,
        data.len().div_ceil(copier::FILE_BUFFER_BYTES)
    );
}
struct BuiltinHost {
    state: Rc<RefCell<State>>,
}
impl super::Host for BuiltinHost {
    type Source = Cursor<Vec<u8>>;
    type Sink = File;
    fn open_read(&mut self, _: &str) -> io::Result<Self::Source> {
        Err(io::ErrorKind::NotFound.into())
    }
    fn open_write(&mut self, _: &str, _: bool) -> io::Result<File> {
        Ok(BufferedFile::new(
            Writer(self.state.clone()),
            Box::new(|| 0u64) as Box<dyn Fn() -> u64>,
        ))
    }
    fn run(&mut self, _: Vec<super::Stage<Self::Source, File>>) -> Vec<super::Ran> {
        panic!("builtin regression must not spawn")
    }
    fn is_dir(&mut self, _: &str) -> io::Result<bool> {
        Ok(true)
    }
    fn session_request(&mut self, _: super::SessionRequest) -> io::Result<(i32, String)> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
#[test]
fn actual_shell_owner_flushes_builtin_bytes_before_last_shared_drop() {
    let state = Rc::new(RefCell::new(State::default()));
    let mut shell = super::Shell::new(
        BuiltinHost {
            state: state.clone(),
        },
        "/".into(),
    );
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line(
        "{ echo first; echo second >&2; } >out 2>&1",
        &mut out,
        &mut err,
    );
    assert_eq!(shell.status, 0);
    assert!(err.is_empty());
    assert_eq!(state.borrow().bytes, b"first\nsecond\n");
    let calls = state.borrow().writes;
    drop(shell);
    assert_eq!(state.borrow().writes, calls);
}
#[test]
fn actual_shell_owner_reports_last_flush_error_before_drop() {
    let state = Rc::new(RefCell::new(State {
        fail_flush: true,
        ..State::default()
    }));
    let mut shell = super::Shell::new(
        BuiltinHost {
            state: state.clone(),
        },
        "/".into(),
    );
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line("echo data >out", &mut out, &mut err);
    assert_eq!(shell.status, super::STATUS_REDIRECT);
    assert!(
        String::from_utf8(err)
            .unwrap()
            .contains("first sync failure")
    );
    assert_eq!(state.borrow().bytes, b"data\n");
    let calls = state.borrow().writes;
    drop(shell);
    assert_eq!(state.borrow().writes, calls);
    assert_eq!(state.borrow().flushes, 1);
}

#[test]
fn direct_interrupted_write_can_be_retried_without_a_sticky_failure() {
    let (mut sink, state, _) = endpoint();
    state.borrow_mut().interrupt_writes = 1;
    let bytes = vec![b'x'; 4096];
    assert_eq!(
        sink.write(&bytes).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(sink.write(&bytes).unwrap(), 4096);
    sink.flush().unwrap();
    assert_eq!(state.borrow().bytes, bytes);
}
#[test]
fn direct_zero_write_records_the_shared_terminal_failure() {
    let (mut a, state, _) = endpoint();
    let mut b = a.clone();
    state.borrow_mut().max_write = Some(0);
    let bytes = vec![b'x'; 4096];
    assert_eq!(
        a.write_all(&bytes).unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    let calls = state.borrow().writes;
    assert_eq!(
        b.write_all(&bytes).unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!(state.borrow().writes, calls);
}
