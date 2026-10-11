//! Exercises the production runtime FSD bookkeeping with bounded syscall
//! substitution. No guest/device effect is simulated: reaching SYS_WRITE is
//! the parent-admission observation, and that write returns IO immediately.

extern crate alloc;

#[allow(dead_code)]
#[path = "../../runtime/src/fsd.rs"]
mod runtime_fsd;

use std::sync::Mutex;

use absd_fsd::proto::status;

const OWN_REQUEST: u64 = 17;
const OWN_REPLY: u64 = 18;
const CHILD: u64 = 41;
const WAIT_COPY: u64 = 42;
const RIGHT_WAIT: u64 = 1 << 1;
const TOO_MANY_HANDLES: i64 = -24;

struct Substitution {
    duplicate_result: i64,
    child_live: bool,
    duplicates: usize,
    live_info: usize,
    writes: usize,
}

static SUBSTITUTION: Mutex<Substitution> = Mutex::new(Substitution {
    duplicate_result: WAIT_COPY as i64,
    child_live: true,
    duplicates: 0,
    live_info: 0,
    writes: 0,
});

unsafe fn syscall3(number: u64, a0: u64, a1: u64, _a2: u64) -> i64 {
    let mut sample = SUBSTITUTION.lock().unwrap();
    match number {
        4 => 7, // Parent PID used solely for framing.
        13 => {
            assert_eq!((a0, a1), (CHILD, RIGHT_WAIT));
            sample.duplicates += 1;
            sample.duplicate_result
        }
        19 => {
            assert_eq!(a0, WAIT_COPY);
            // A valid wait copy still names a live child. The production
            // runtime interprets state word 2 as terminal; 1 is nonterminal.
            let info = unsafe { &mut *(a1 as *mut [u64; 4]) };
            *info = [CHILD, 7, 0, if sample.child_live { 1 } else { 2 }];
            sample.live_info += 1;
            0
        }
        9 => {
            assert_eq!(a0, WAIT_COPY);
            assert!(!sample.child_live);
            0
        }
        1 => {
            assert_eq!(a0, OWN_REQUEST);
            sample.writes += 1;
            status::IO
        }
        other => panic!("unexpected syscall in bounded holder witness: {other}"),
    }
}

fn ticks() -> u64 {
    panic!("deadline path is outside this holder witness")
}

fn read_within(_handle: u64, _bytes: &mut [u8], _ticks: u64) -> Result<usize, i64> {
    panic!("reply transport is outside this holder witness")
}

unsafe fn __absd_std_stderr_write(_bytes: *const u8, _length: usize) -> i64 {
    panic!("server-version refusal is outside this holder witness")
}

fn __absd_std_exit(_code: i32) -> ! {
    panic!("process exit is outside this holder witness")
}

#[test]
fn parent_request_stays_refused_after_lent_holder_duplicate_exhaustion() {
    // One test serializes the production runtime's single-process globals.
    runtime_fsd::install(&[(OWN_REQUEST, OWN_REPLY)]);
    runtime_fsd::set_default_child(runtime_fsd::ChildFs::Inherit);
    let plan = runtime_fsd::plan_child().unwrap();
    assert!(matches!(plan, runtime_fsd::Plan::Lend((OWN_REQUEST, OWN_REPLY))));

    // Positive control: recording a valid live borrower must prevent the
    // parent from even attempting transport on that borrowed channel.
    runtime_fsd::child_started(&plan, CHILD);
    assert_eq!(runtime_fsd::open(b"/home/operator/notes", 1), status::AGAIN);
    {
        let sample = SUBSTITUTION.lock().unwrap();
        assert_eq!(sample.duplicates, 1);
        assert_eq!(sample.live_info, 1);
        assert_eq!(sample.writes, 0);
    }

    // Finish the positive borrow before obtaining a fresh lend plan.
    // This avoids overwriting an already live registration in the fixture.
    SUBSTITUTION.lock().unwrap().child_live = false;
    let plan = runtime_fsd::plan_child().unwrap();
    assert!(matches!(plan, runtime_fsd::Plan::Lend((OWN_REQUEST, OWN_REPLY))));

    // Model the next successful spawn's post-spawn registration with the
    // permitted Full refusal. The new child/channel remain live; only the
    // optional WAIT duplicate failed. This deliberately does not model a
    // foreign mount grant or a second process taking an unauthorized path.
    {
        let mut sample = SUBSTITUTION.lock().unwrap();
        sample.duplicate_result = TOO_MANY_HANDLES;
        sample.child_live = true;
        sample.duplicates = 0;
        sample.live_info = 0;
        sample.writes = 0;
    }
    runtime_fsd::child_started(&plan, CHILD);
    let result = runtime_fsd::open(b"/home/operator/notes", 1);
    let sample = SUBSTITUTION.lock().unwrap();
    assert_eq!(sample.duplicates, 1);
    eprintln!(
        "FSD HOLDER WITNESS duplicate={} parent_result={} parent_writes={} child_info_calls={}",
        sample.duplicate_result, result, sample.writes, sample.live_info,
    );
    assert_eq!(
        sample.writes, 0,
        "parent transport admitted while a live borrower holds the channel after WAIT-copy exhaustion"
    );
    assert_eq!(result, status::AGAIN);
}
