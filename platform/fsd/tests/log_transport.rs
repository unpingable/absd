//! Production control-transport budgets with deterministic stalled endpoints.
extern crate alloc;
#[allow(dead_code)]
#[path = "../../runtime/src/fsd.rs"]
mod transport;
#[allow(dead_code)]
#[path = "../../runtime/src/wire_kind.rs"]
mod wire_kind;
use std::sync::atomic::{AtomicU64, Ordering};
static NOW: AtomicU64 = AtomicU64::new(10);
static PHASE: AtomicU64 = AtomicU64::new(4);
static WRITES: AtomicU64 = AtomicU64::new(0);
static READS: AtomicU64 = AtomicU64::new(0);
static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);
unsafe fn syscall3(n: u64, _a: u64, _b: u64, _c: u64) -> i64 {
    assert_eq!(
        n, 4,
        "logging must never issue an unbounded SYS_WRITE/SYS_READ"
    );
    7
}
fn ticks() -> u64 {
    NOW.load(Ordering::Relaxed)
}
fn write_within(_h: u64, b: &[u8], budget: u64) -> Result<usize, i64> {
    if PHASE.load(Ordering::Relaxed) == 4 {
        assert!(budget > 0 && budget <= 60000);
        assert_eq!(b[absd_fsd::proto::HEADER], absd_fsd::proto::op::VERSION);
    } else {
        assert!(budget > 0 && budget <= 100);
    }
    WRITES.fetch_add(1, Ordering::Relaxed);
    match PHASE.load(Ordering::Relaxed) {
        0 => Err(-110),
        1 => {
            let n = WRITES.load(Ordering::Relaxed);
            NOW.fetch_add(60, Ordering::Relaxed);
            if n == 1 {
                Ok(8.min(b.len()))
            } else {
                Err(-110)
            }
        }
        _ => { if b.len()>=16 {REQUEST_SEQ.store(u64::from_le_bytes(b[8..16].try_into().unwrap()),Ordering::Relaxed);} Ok(b.len()) },
    }
}
fn read_within(_h: u64, bytes: &mut [u8], budget: u64) -> Result<usize, i64> {
    assert!(budget > 0 && budget <= 100);
    let call=READS.fetch_add(1,Ordering::Relaxed);
    if PHASE.load(Ordering::Relaxed)==4 {
        let mut reply=absd_fsd::proto::Frame::reply(0);
        reply.0.extend(absd_fsd::version::encode(&absd_fsd::version::compiled()));
        let reply=reply.finish_seq(REQUEST_SEQ.load(Ordering::Relaxed));
        bytes[..reply.len()].copy_from_slice(&reply);
        return Ok(reply.len());
    }
    if PHASE.load(Ordering::Relaxed)==3 && call==0 {
        use absd_fsd::proto::{self,Frame};
        let mut old=Frame::reply(0).bytes(&[b'x';100]).finish();proto::stamp_seq(&mut old,6<<32);
        let mut new=Frame::reply(0).bytes(b"new reply").finish();proto::stamp_seq(&mut new,REQUEST_SEQ.load(Ordering::Relaxed));
        let mut data=old[..proto::HEADER+3].to_vec();data.extend_from_slice(&new);bytes[..data.len()].copy_from_slice(&data);return Ok(data.len());
    }
    NOW.fetch_add(budget,Ordering::Relaxed);Err(-110)
}

unsafe fn __absd_std_stderr_write(_b: *const u8, _n: usize) -> i64 {
    panic!("not a refusal test")
}
fn __absd_std_exit(_n: i32) -> ! {
    panic!("not an exit test")
}
#[test]
fn dead_sink_bounds_initial_write_partial_write_and_reply_wait() {
    use absd_fsd::proto::{Frame, op};
    transport::install(&[(17, 18)]);
    // Match the real logger's successful CRT negotiation before testing
    // its data transport. Every original 100-tick fault assertion remains.
    transport::check_server(0, false).unwrap();
    PHASE.store(0, Ordering::Relaxed);
    WRITES.store(0, Ordering::Relaxed);
    READS.store(0, Ordering::Relaxed);
    let request = || Frame::request(op::NOTICE).bytes(b"diagnostic").finish();
    assert_eq!(transport::request_on_within(0, request(), 100), Err(-110));
    assert_eq!(WRITES.load(Ordering::Relaxed), 1);
    assert_eq!(READS.load(Ordering::Relaxed), 0);
    PHASE.store(1, Ordering::Relaxed);
    WRITES.store(0, Ordering::Relaxed);
    assert_eq!(transport::request_on_within(0, request(), 100), Err(-110));
    assert_eq!(WRITES.load(Ordering::Relaxed), 2);
    assert_eq!(READS.load(Ordering::Relaxed), 0);
    PHASE.store(2, Ordering::Relaxed);
    WRITES.store(0, Ordering::Relaxed);
    assert_eq!(transport::request_on_within(0, request(), 100), Err(-110));
    assert_eq!(WRITES.load(Ordering::Relaxed), 1);
    assert_eq!(READS.load(Ordering::Relaxed), 10);
    PHASE.store(3,Ordering::Relaxed);READS.store(0,Ordering::Relaxed);WRITES.store(0,Ordering::Relaxed);
    assert_eq!(transport::request_on_within(0,request(),100),Ok((0,b"new reply".to_vec())));
    assert_eq!(READS.load(Ordering::Relaxed),2);
}
