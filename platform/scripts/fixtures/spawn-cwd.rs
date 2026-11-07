#![allow(dead_code)]
extern crate alloc;
#[path = "@ROOT@/fsd/tests/common/mod.rs"]
mod common;
#[path = "@ROOT@/runtime/src/fsd.rs"]
mod fsd;
#[path = "@ROOT@/runtime/src/wire_kind.rs"]
mod wire_kind;
fn sim_enter() {}
fn sim_exit() {}
use absd_fs::Fs;
use absd_fsd::log as logfile;
use absd_fsd::recovery;
use absd_fsd::{
    CONTROL, PipeState, Server,
    proto::{self, Frame, Mount, op},
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    sync::atomic::{AtomicU64, Ordering},
};
static CLOCK: AtomicU64 = AtomicU64::new(1);
fn ticks() -> u64 {
    CLOCK.fetch_add(1, Ordering::Relaxed)
}
struct Backend {
    server: Server<common::Disk>,
    requests: BTreeMap<usize, Vec<u8>>,
    replies: BTreeMap<usize, VecDeque<u8>>,
    ops: Vec<(usize, u8)>,
    mode: &'static str,
    stat_pending: Option<usize>,
    local: Option<Fs<common::Disk>>,
}
thread_local! {static BACKEND:RefCell<Option<Backend>>=const{RefCell::new(None)};}
fn channel(handle: u64) -> usize {
    (handle as usize - 101) / 2
}
fn quiet(_: usize) -> Option<PipeState> {
    Some(PipeState {
        request_writers: 1,
        reply_readers: 1,
        ..Default::default()
    })
}
fn request(handle: u64, bytes: &[u8]) -> Result<usize, i64> {
    BACKEND.with_borrow_mut(|slot| {
        let b = slot.as_mut().unwrap();
        let at = channel(handle);
        let pending = b.requests.entry(at).or_default();
        pending.extend_from_slice(bytes);
        if pending.len() < proto::HEADER {
            return Ok(bytes.len());
        }
        let (len, seq) = proto::parse_header(pending).unwrap();
        if pending.len() < proto::HEADER + len + proto::TRAILER {
            return Ok(bytes.len());
        }
        let frame = std::mem::take(pending);
        let opcode = frame[proto::HEADER];
        b.ops.push((at, opcode));
        b.stat_pending = (opcode == op::STAT).then_some(at);
        let mut reply = if b.mode == "denied" && opcode == op::STAT {
            Frame::reply(-13).finish()
        } else {
            b.server.dispatch(
                at,
                &frame[proto::HEADER..proto::HEADER + len],
                &quiet,
                ticks(),
            )
        };
        if b.mode == "positive-status" && opcode == op::STAT {
            reply[proto::HEADER..proto::HEADER + 8].copy_from_slice(&1i64.to_le_bytes());
        }
        proto::stamp_seq(&mut reply, seq);
        if b.mode == "stale" && opcode == op::STAT {
            let mut old = Frame::reply(-2).finish();
            proto::stamp_seq(&mut old, seq - 1);
            b.replies.entry(at).or_default().extend(old);
        }
        b.replies.entry(at).or_default().extend(reply);
        Ok(bytes.len())
    })
}
fn write_within(handle: u64, bytes: &[u8], budget: u64) -> Result<usize, i64> {
    assert!((1..=1000).contains(&budget));
    request(handle, bytes)
}
fn read_within(handle: u64, bytes: &mut [u8], budget: u64) -> Result<usize, i64> {
    assert!((1..=1000).contains(&budget));
    BACKEND.with_borrow_mut(|slot| {
        let b = slot.as_mut().unwrap();
        let at = channel(handle);
        if b.mode == "stall" && b.stat_pending == Some(at) {
            CLOCK.fetch_add(budget, Ordering::Relaxed);
            return Err(-110);
        }
        let reply = b.replies.entry(at).or_default();
        let n = bytes.len().min(reply.len()).min(13);
        for byte in &mut bytes[..n] {
            *byte = reply.pop_front().unwrap()
        }
        Ok(n)
    })
}
unsafe fn syscall3(number: u64, handle: u64, address: u64, length: u64) -> i64 {
    match number {
        1 => request(handle, unsafe {
            std::slice::from_raw_parts(address as *const u8, length as usize)
        })
        .map(|n| n as i64)
        .unwrap_or_else(|e| e),
        15 => {
            let bytes =
                unsafe { std::slice::from_raw_parts_mut(address as *mut u8, length as usize) };
            read_within(handle, bytes, 1000)
                .map(|n| n as i64)
                .unwrap_or_else(|e| e)
        }
        36 => {
            let data = unsafe { &mut *(address as *mut [u64; 4]) };
            let n = BACKEND.with_borrow(|s| {
                s.as_ref()
                    .unwrap()
                    .replies
                    .get(&channel(handle))
                    .map_or(0, |q| q.len())
            });
            *data = [n as u64, 1024, 1, 1];
            0
        }
        4 => 7,
        9 => 0,
        13 => 90,
        19 => {
            unsafe { (*(address as *mut [u64; 4]))[3] = 2 };
            0
        }
        _ => panic!("unexpected syscall {number}"),
    }
}
unsafe fn __absd_std_stderr_write(_: *const u8, _: usize) -> isize {
    panic!("unexpected startup stderr")
}
fn __absd_std_exit(_: i32) -> ! {
    panic!("unexpected startup exit")
}
mod cwd {
    pub fn get() -> &'static [u8] {
        b"/"
    }
}
mod storage {
    use crate::wire_kind::WireKind;
    use absd_fs::{Error, Fs, Kind};
    @ERRNO@
    fn with_fs<T>(
        f: impl FnOnce(&mut Fs<super::common::Disk>) -> Result<T, i64>,
    ) -> Option<Result<T, i64>> {
        super::BACKEND.with_borrow_mut(|s| s.as_mut().unwrap().local.as_mut().map(f))
    }
    @STAT@
}
@NOTDIR@
@VALIDATE@
pub struct RawSpawn {
    cwd_length: usize,
}
mod session {
    pub struct ChildEnds;
    pub fn take_next() -> Option<ChildEnds> {
        None
    }
}
mod terminal {
    pub struct Child;
    pub fn take_next() -> Option<Child> {
        None
    }
}
unsafe fn spawn(
    _: &RawSpawn,
    _: Option<&session::ChildEnds>,
    _: Option<&terminal::Child>,
) -> Result<[u64; 5], i64> {
    Err(-2)
}
@WRAPPER@
fn prepare(directory: &[u8], explicit: bool) -> Result<fsd::Plan, i64> {
    let child_cwd = directory;
    let request = RawSpawn {
        cwd_length: usize::from(explicit),
    };
    @PREPARE@
    Ok(plan)
}
@SESSION@
fn dispatch(at: usize, frame: Vec<u8>) -> i64 {
    let (len, _) = proto::parse_header(&frame).unwrap();
    BACKEND.with_borrow_mut(|s| {
        let r = s.as_mut().unwrap().server.dispatch(
            at,
            &frame[proto::HEADER..proto::HEADER + len],
            &quiet,
            ticks(),
        );
        i64::from_le_bytes(r[proto::HEADER..proto::HEADER + 8].try_into().unwrap())
    })
}
fn setup(own_session: bool, spares: bool) {
    let disk = common::image();
    let fs = Fs::mount(disk, true).unwrap();
    @CONTROL@
    BACKEND.with_borrow_mut(|s| {
        *s = Some(Backend {
            server: Server::new(fs, 18, control),
            requests: BTreeMap::new(),
            replies: BTreeMap::new(),
            ops: Vec::new(),
            mode: "happy",
            stat_pending: None,
            local: None,
        })
    });
    assert_eq!(
        dispatch(
            CONTROL,
            Frame::request(op::BIND)
                .u8(1)
                .u8(2)
                .u8(2)
                .u8(3)
                .mounts(&session_mounts(1))
                .finish()
        ),
        0
    );
    let channels = if own_session {
        if spares {
            vec![(103, 104), (105, 106), (107, 108)]
        } else {
            vec![(103, 104)]
        }
    } else {
        vec![(101, 102), (103, 104), (105, 106), (107, 108)]
    };
    fsd::install(&channels);
    // Complete real protocol admission before exercising the cwd-only
    // 1000-tick assertions; ordinary clients have already passed CRT here.
    fsd::check_server_within(0, false, 1000).expect("fixture VERSION admission");
    fsd::set_default_child(fsd::ChildFs::None);
}
fn slot() {
    fsd::set_next_child(fsd::ChildFs::Slot {
        own: 1,
        spares: vec![2, 3],
    })
}
fn mode(m: &'static str) {
    BACKEND.with_borrow_mut(|s| s.as_mut().unwrap().mode = m)
}
fn underives() -> usize {
    BACKEND.with_borrow(|s| {
        s.as_ref()
            .unwrap()
            .ops
            .iter()
            .filter(|(_, op)| *op == op::UNDERIVE)
            .count()
    })
}
fn main() {
    setup(false, true);
    assert_eq!(
        fsd::stat(b"/home/operator"),
        Err(-2),
        "parent CONTROL must stay narrow"
    );
    slot();
    let p = prepare(b"/home/operator", true).expect("actual delegated home must start shell");
    assert!(matches!(p, fsd::Plan::Slot(_)));
    fsd::child_failed(&p);
    assert_eq!(underives(), 0, "caller owns Slot RELEASE");
    assert_eq!(
        dispatch(
            1,
            Frame::request(op::STAT).bytes(b"/home/operator").finish()
        ),
        0
    );
    assert_eq!(
        dispatch(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
        0
    );
    assert_ne!(
        dispatch(
            1,
            Frame::request(op::STAT).bytes(b"/home/operator").finish()
        ),
        0
    );
    println!("Slot home succeeds; parent unchanged; caller RELEASE retained");
    for (path, error) in [
        (b"/ssh".as_slice(), -2),
        (b"/etc/motd", SPAWN_NOT_A_DIRECTORY),
        (b"/home/operator/missing", -2),
    ] {
        setup(false, true);
        slot();
        assert_eq!(prepare(path, true).err(), Some(error));
        assert_eq!(underives(), 0);
        assert_eq!(
            dispatch(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
            0
        );
    }
    println!("hidden/non-directory/missing explicit cwd refuse with caller cleanup");
    for (m, expected) in [
        ("stale", None),
        ("denied", Some(-13)),
        ("positive-status", Some(-5)),
        ("stall", Some(-110)),
    ] {
        setup(false, true);
        slot();
        mode(m);
        let begin = ticks();
        let got = prepare(b"/home/operator", true);
        assert_eq!(got.err(), expected);
        assert!(ticks() - begin <= 1020);
        assert_eq!(underives(), 0);
        mode("happy");
        assert_eq!(
            dispatch(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
            0
        );
    }
    println!("sequenced stale reply skipped; refusal and bounded timeout preserve Slot ownership");
    setup(false, true);
    mode("positive-status");
    assert!(fsd::stat(b"/").is_ok(), "legacy STAT acceptance changed");
    println!("new cwd boundary rejects positive STAT code; legacy STAT unchanged");
    setup(true, true);
    fsd::set_default_child(fsd::ChildFs::SpareOnly);
    let p = prepare(b"/home/operator", true).unwrap();
    assert!(matches!(p, fsd::Plan::Spare(_)));
    fsd::child_failed(&p);
    assert_eq!(underives(), 1);
    assert_eq!(prepare(b"/home/operator/missing", true).err(), Some(-2));
    assert_eq!(underives(), 2);
    mode("denied");
    assert_eq!(prepare(b"/home/operator", true).err(), Some(-13));
    assert_eq!(underives(), 3);
    mode("stall");
    assert_eq!(prepare(b"/home/operator", true).err(), Some(-110));
    assert_eq!(underives(), 4);
    mode("happy");
    let p = prepare(b"/home/operator", true).unwrap();
    fsd::child_failed(&p);
    assert_eq!(underives(), 5);
    println!("Spare failures UNDERIVE exactly once and permit actual reuse");
    setup(true, false);
    fsd::set_default_child(fsd::ChildFs::Inherit);
    let p = prepare(b"/home/operator", true).unwrap();
    assert!(matches!(p, fsd::Plan::Lend(_)));
    fsd::child_failed(&p);
    assert_eq!(underives(), 0);
    println!("Lend uses its existing view without UNDERIVE");
    setup(false, true);
    let before = BACKEND.with_borrow(|s| s.as_ref().unwrap().ops.len());
    assert!(matches!(
        prepare(b"/home/operator", false).unwrap(),
        fsd::Plan::NoFs
    ));
    assert_eq!(
        BACKEND.with_borrow(|s| s.as_ref().unwrap().ops.len()),
        before
    );
    assert!(matches!(prepare(b"/", true).unwrap(), fsd::Plan::NoFs));
    assert_eq!(prepare(b"/home/operator", true).err(), Some(-2));
    println!("NoFs inherited label unchanged; legacy explicit fallback grants no filesystem");
    fsd::install(&[]);
    fsd::set_default_child(fsd::ChildFs::Inherit);
    assert!(matches!(prepare(b"/", true).unwrap(), fsd::Plan::None));
    assert_eq!(prepare(b"/home/operator", true).err(), Some(-2));
    let local = Fs::mount(common::image(), false).unwrap();
    BACKEND.with_borrow_mut(|s| s.as_mut().unwrap().local = Some(local));
    assert!(matches!(
        prepare(b"/home/operator", true).unwrap(),
        fsd::Plan::None
    ));
    println!("None preserves root-without-FS and actual local-FS validation");
    setup(false, true);
    slot();
    let request = RawSpawn { cwd_length: 0 };
    let mut ends = [0; 5];
    assert_eq!(
        unsafe { __absd_std_process_spawn_image(&request, &mut ends) },
        -2
    );
    assert!(matches!(fsd::plan_child().unwrap(), fsd::Plan::NoFs));
    println!("actual spawn wrapper spends one-shot policy on pre-plan failure");
}
