//! Exercises the production runtime FSD bookkeeping with bounded syscall
//! substitution. No guest/device effect is simulated: reaching SYS_WRITE is
//! the parent-admission observation, and that write returns IO immediately.

extern crate alloc;

// fsd.rs reads wire kinds through the runtime's decoder (R12); this test crate
// is its own root, so the decoder module is included beside it.
#[allow(dead_code)]
#[path = "../../runtime/src/wire_kind.rs"]
mod wire_kind;

#[allow(dead_code)]
#[path = "../../runtime/src/fsd.rs"]
mod runtime_fsd;

use std::sync::Mutex;

use absd_fsd::proto::status;

const OWN_REQUEST: u64 = 17;
const OWN_REPLY: u64 = 18;
const SPARE_REQUEST: u64 = 19;
const SPARE_REPLY: u64 = 20;
const CHILD: u64 = 41;
const WAIT_COPY: u64 = 42;
const RIGHT_WAIT: u64 = 1 << 1;
const TOO_MANY_HANDLES: i64 = -24;

struct Substitution {
    duplicate_result: i64,
    child_live: bool,
    info_result: i64,
    duplicates: usize,
    live_info: usize,
    closes: usize,
    writes: usize,
}

static SUBSTITUTION: Mutex<Substitution> = Mutex::new(Substitution {
    duplicate_result: WAIT_COPY as i64,
    child_live: true,
    info_result: 0,
    duplicates: 0,
    live_info: 0,
    closes: 0,
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
            sample.info_result
        }
        9 => {
            assert_eq!(a0, WAIT_COPY);
            assert!(!sample.child_live);
            sample.closes += 1;
            0
        }
        36 => {
            assert_eq!(a0, SPARE_REPLY);
            let info = unsafe { &mut *(a1 as *mut [u64; 4]) };
            *info = [0, 4096, 2, 2];
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
    runtime_fsd::install(&[(OWN_REQUEST, OWN_REPLY), (SPARE_REQUEST, SPARE_REPLY)]);
    runtime_fsd::set_default_child(runtime_fsd::ChildFs::SpareOnly);

    // Bookkeeping for an already-derived spare: live tracking prevents
    // reuse, while terminal tracking closes its handle and permits the
    // parent to attempt DERIVE again. The transport deliberately returns
    // IO; this witness does not pretend to bind an actual file server.
    let spare = runtime_fsd::Plan::Spare(0);
    runtime_fsd::child_started(&spare, CHILD);
    assert!(matches!(runtime_fsd::plan_child(), Err(status::AGAIN)));
    assert_eq!(SUBSTITUTION.lock().unwrap().writes, 0);
    SUBSTITUTION.lock().unwrap().child_live = false;
    assert!(matches!(runtime_fsd::plan_child(), Err(status::IO)));
    {
        let sample = SUBSTITUTION.lock().unwrap();
        assert_eq!(sample.closes, 1);
        assert_eq!(sample.writes, 1);
    }

    // Failed tracking of a newly started spare remains occupied, even
    // after time/liveness assumptions change. No nonexistent handle is
    // queried as though it could prove that child gone.
    {
        let mut sample = SUBSTITUTION.lock().unwrap();
        sample.duplicate_result = TOO_MANY_HANDLES;
        sample.child_live = true;
        sample.duplicates = 0;
        sample.live_info = 0;
        sample.closes = 0;
        sample.writes = 0;
    }
    runtime_fsd::child_started(&spare, CHILD);
    assert!(matches!(runtime_fsd::plan_child(), Err(status::AGAIN)));
    {
        let mut sample = SUBSTITUTION.lock().unwrap();
        sample.child_live = false;
        // A stale tracking observation must never clear Untracked: there
        // is no valid tracking handle to query in this state.
        sample.info_result = -9;
    }
    for _ in 0..3 {
        assert!(matches!(runtime_fsd::plan_child(), Err(status::AGAIN)));
    }
    {
        let sample = SUBSTITUTION.lock().unwrap();
        assert_eq!(sample.duplicates, 1);
        assert_eq!(sample.live_info, 0);
        assert_eq!(sample.closes, 0);
        assert_eq!(sample.writes, 0);
    }
    // Only the spare is quarantined: ordinary own-channel filesystem
    // work still reaches transport. IO is the intentional stub result,
    // not a real file effect or successful server operation.
    assert_eq!(runtime_fsd::open(b"/home/operator/notes", 1), status::IO);
    assert_eq!(SUBSTITUTION.lock().unwrap().writes, 1);

    // The unavailable spare does not prevent ordinary inheritance from
    // choosing the parent's own channel. A successful WAIT copy protects
    // this lend independently of the unavailable spare.
    {
        let mut sample = SUBSTITUTION.lock().unwrap();
        sample.duplicate_result = WAIT_COPY as i64;
        sample.child_live = true;
        sample.info_result = 0;
        sample.duplicates = 0;
        sample.live_info = 0;
        sample.closes = 0;
        sample.writes = 0;
    }
    runtime_fsd::set_default_child(runtime_fsd::ChildFs::Inherit);
    let plan = runtime_fsd::plan_child().unwrap();
    assert!(matches!(
        plan,
        runtime_fsd::Plan::Lend((OWN_REQUEST, OWN_REPLY))
    ));

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
    assert!(matches!(
        plan,
        runtime_fsd::Plan::Lend((OWN_REQUEST, OWN_REPLY))
    ));
    assert_eq!(SUBSTITUTION.lock().unwrap().closes, 1);

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
        sample.closes = 0;
        sample.writes = 0;
    }
    runtime_fsd::child_started(&plan, CHILD);
    let result = runtime_fsd::open(b"/home/operator/notes", 1);
    {
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
    }
    assert_eq!(result, status::AGAIN);
    assert!(matches!(runtime_fsd::plan_child(), Err(status::AGAIN)));
    {
        let mut sample = SUBSTITUTION.lock().unwrap();
        sample.child_live = false;
        // A stale tracking observation must never clear Untracked: there
        // is no valid tracking handle to query in this state.
        sample.info_result = -9;
    }
    for _ in 0..3 {
        assert_eq!(runtime_fsd::open(b"/home/operator/notes", 1), status::AGAIN);
        assert!(matches!(runtime_fsd::plan_child(), Err(status::AGAIN)));
    }
    let sample = SUBSTITUTION.lock().unwrap();
    assert_eq!(sample.live_info, 0);
    assert_eq!(sample.closes, 0);
    assert_eq!(sample.writes, 0);
}
