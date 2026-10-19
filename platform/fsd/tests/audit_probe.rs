//! Regression tests from the 2026-10-02 architecture audit (kernel
//! docs/architecture-audit-20261002/README.md). They were first committed
//! as characterization probes that passed while the defects were present
//! (platform 31461cb); each is now inverted to assert the repaired
//! behaviour. The loop model `L` makes the same decisions as
//! ssh/src/fsd_server.rs: read while the inbox wants more, give a head up
//! only when the pipe is quiet (`idle`), discard what a released channel
//! left once it is quiet, and stamp each reply with its request's
//! sequence word.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use absd_fs::{Device, Error, Fs, SECTOR};
use absd_fsd::proto::{self, Frame, Mount, Reader, derive, op, status as errno};
use absd_fsd::{CONTROL, Event, Inbox, PipeState, Server, Taken};

#[derive(Clone)]
struct Disk(Rc<RefCell<BTreeMap<u64, [u8; SECTOR]>>>);
impl Device for Disk {
    fn sectors(&self) -> u64 {
        16384
    }
    fn read(&mut self, s: u64, b: &mut [u8; SECTOR]) -> Result<(), Error> {
        *b = self.0.borrow().get(&s).copied().unwrap_or([0; SECTOR]);
        Ok(())
    }
    fn write(&mut self, s: u64, b: &[u8; SECTOR]) -> Result<(), Error> {
        self.0.borrow_mut().insert(s, *b);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

fn mounts() -> Vec<Mount> {
    vec![Mount::new(b"/home/operator", true), Mount::new(b"/tmp/session-1", true)]
}

fn setup() -> Server<Disk> {
    let disk = Disk(Rc::new(RefCell::new(BTreeMap::new())));
    absd_fs::format(&mut disk.clone(), 7).unwrap();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    fs.mkdir(b"/home").unwrap();
    fs.mkdir(b"/tmp").unwrap();
    fs.sync().unwrap();
    Server::new(Fs::mount(disk, true).unwrap(), 4, vec![Mount::new(b"/var/log", true)])
}

fn body(frame: &[u8]) -> &[u8] {
    &frame[proto::HEADER..frame.len() - proto::TRAILER]
}

fn status(reply: &[u8]) -> i64 {
    Reader(&reply[proto::HEADER..]).i64().unwrap()
}

/// What one look at a channel did.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Skipped,
    Nothing,
    /// A request served: the status replied and the sequence word stamped.
    Replied(i64, u64),
}

/// Pipe bytes plus the loop's inbox per channel; writers = keeper (1).
struct L {
    pipe: Vec<Vec<u8>>,
    inbox: Vec<Inbox>,
    reply: Vec<Vec<u8>>,
}

impl L {
    fn new(channels: usize) -> Self {
        L {
            pipe: vec![vec![]; channels],
            inbox: (0..channels).map(|_| Inbox::new()).collect(),
            reply: vec![vec![]; channels],
        }
    }
    fn st(&self, c: usize) -> Option<PipeState> {
        Some(PipeState {
            request_available: (self.pipe[c].len() + self.inbox[c].len()) as u64,
            request_writers: 1,
            reply_available: 0,
            reply_readers: 1,
        })
    }
    fn serve(&mut self, s: &mut Server<Disk>, c: usize) -> Step {
        if !s.active(c) {
            return Step::Skipped;
        }
        let mut quiet = false;
        while self.inbox[c].wants_more() {
            if self.pipe[c].is_empty() {
                quiet = true;
                break;
            }
            let n = self.pipe[c].len().min(256);
            let chunk: Vec<u8> = self.pipe[c].drain(..n).collect();
            self.inbox[c].push(&chunk);
        }
        let mut taken = self.inbox[c].take();
        if taken == Taken::Nothing && quiet {
            self.inbox[c].idle();
            taken = self.inbox[c].take();
        }
        match taken {
            Taken::Nothing => {
                if quiet && s.draining(c) {
                    self.inbox[c].discard();
                    let st = self.st(c);
                    s.settle(c, st);
                }
                Step::Nothing
            }
            Taken::Frame { seq, body } => {
                let snap: Vec<Option<PipeState>> = (0..self.pipe.len()).map(|i| self.st(i)).collect();
                let mut r = s.dispatch(c, &body, &|i| snap.get(i).copied().flatten(), 1);
                proto::stamp_seq(&mut r, seq);
                for i in std::mem::take(&mut s.resets) {
                    self.inbox[i].discard();
                    self.pipe[i].clear();
                }
                let st = status(&r);
                self.reply[c] = r;
                Step::Replied(st, seq)
            }
        }
    }
}

fn bind(slot: u8, spares: &[u8]) -> Vec<u8> {
    let mut f = Frame::request(op::BIND).u8(slot).u8(spares.len() as u8);
    for s in spares {
        f = f.u8(*s);
    }
    f.mounts(&mounts()).finish_seq(0x9)
}

const CHILD: u64 = 0x0000_0005_0000_0001;
const PARENT: u64 = 0x0000_0004_0000_0007;

/// Audit D5, repaired: a client killed after part of a frame leaves a
/// released channel that settles once it is quiet, and the slot binds
/// again.
#[test]
fn killed_mid_frame_released_slot_settles_and_rebinds() {
    let mut s = setup();
    let mut l = L::new(5);
    l.pipe[CONTROL] = bind(1, &[]);
    assert_eq!(l.serve(&mut s, CONTROL), Step::Replied(0, 0x9));
    l.pipe[1] = Frame::request(op::OPEN).u32(2 | 8).bytes(b"/home/operator/f").finish_seq(CHILD);
    assert_eq!(l.serve(&mut s, 1), Step::Replied(1, CHILD));
    let w = Frame::request(op::WRITE_AT).u64(1).u64(0).bytes(&[b'A'; 1000]).finish_seq(CHILD);
    l.pipe[1] = w[..256].to_vec();
    assert_eq!(l.serve(&mut s, 1), Step::Nothing);
    l.pipe[CONTROL] = Frame::request(op::RELEASE).u8(1).finish_seq(0x9);
    assert_eq!(l.serve(&mut s, CONTROL), Step::Replied(1, 0x9));
    assert!(s.draining(1));
    assert_eq!(l.serve(&mut s, 1), Step::Nothing);
    assert!(!s.draining(1), "a quiet released channel settles");
    assert!(l.inbox[1].is_empty());
    s.events.clear();
    l.pipe[CONTROL] = bind(1, &[]);
    assert_eq!(l.serve(&mut s, CONTROL), Step::Replied(0, 0x9));
    assert!(matches!(s.events[..], [Event::Bound { slot: 1, .. }]));
    assert_eq!(s.capacity(), (1, 0, 0));
    // The dead holder's write never ran: the file it opened is empty.
    assert_eq!(s.fs.stat(b"/home/operator/f").unwrap().size, 0);
}

/// Audit D5, the other ordering: bytes that are no frame, then a release.
#[test]
fn garbage_then_release_settles() {
    let mut s = setup();
    let mut l = L::new(5);
    l.pipe[CONTROL] = bind(1, &[]);
    l.serve(&mut s, CONTROL);
    l.pipe[1] = vec![0xff; 300];
    assert_eq!(l.serve(&mut s, 1), Step::Nothing);
    l.pipe[CONTROL] = Frame::request(op::RELEASE).u8(1).finish_seq(0x9);
    l.serve(&mut s, CONTROL);
    // One pass reads and drops the garbage; the next finds the pipe quiet.
    assert_eq!(l.serve(&mut s, 1), Step::Nothing);
    assert_eq!(l.serve(&mut s, 1), Step::Nothing);
    assert!(!s.draining(1));
    s.events.clear();
    l.pipe[CONTROL] = bind(1, &[]);
    assert_eq!(l.serve(&mut s, CONTROL), Step::Replied(0, 0x9));
    assert!(matches!(s.events[..], [Event::Bound { slot: 1, .. }]));
}

/// Audit D6, repaired, over every prefix length: a lent child dies after
/// `n` bytes of its write; the parent's next request runs whole, under the
/// parent's sequence word, and the child's request never runs.
#[test]
fn lent_channel_dead_holders_partial_frame_never_runs_and_parent_request_does() {
    let w = Frame::request(op::WRITE_AT).u64(1).u64(0).bytes(&[b'C'; 40]).finish_seq(CHILD);
    for n in 1..w.len() {
        let mut s = setup();
        let mut l = L::new(5);
        l.pipe[CONTROL] = bind(1, &[]);
        l.serve(&mut s, CONTROL);
        l.pipe[1] = Frame::request(op::OPEN).u32(2 | 8).bytes(b"/home/operator/child").finish_seq(CHILD);
        assert_eq!(l.serve(&mut s, 1), Step::Replied(1, CHILD));
        l.pipe[1] = w[..n].to_vec();
        assert_eq!(l.serve(&mut s, 1), Step::Nothing, "prefix {n}");
        // The parent resumes on the same channel: a whole write of 100
        // bytes on the same handle (the table is the channel's).
        l.pipe[1] = Frame::request(op::WRITE_AT).u64(1).u64(0).bytes(&[b'P'; 100]).finish_seq(PARENT);
        let mut steps = vec![l.serve(&mut s, 1)];
        if steps[0] == Step::Nothing {
            steps.push(l.serve(&mut s, 1));
        }
        assert!(steps.contains(&Step::Replied(100, PARENT)), "prefix {n}: {steps:?}");
        assert!(!steps.iter().any(|st| matches!(st, Step::Replied(_, CHILD))), "prefix {n}");
        let mut b = vec![0u8; 128];
        let h = s.fs.open(b"/home/operator/child", absd_fs::OpenFlags { read: true, ..Default::default() }).unwrap();
        let got = s.fs.read_at(h, 0, &mut b).unwrap();
        assert_eq!(&b[..got], &[b'P'; 100][..], "prefix {n}");
        assert!(l.inbox[1].is_empty(), "prefix {n}");
    }
}

/// Audit D7: the derived channel cannot move a read-only carve-out out of
/// its mount path by renaming an ancestor under a wider writable mount.
#[test]
fn nested_readonly_carveout_cannot_be_escaped_by_ancestor_rename() {
    let mut s = setup();
    s.fs.mkdir(b"/home/operator").unwrap();
    s.fs.mkdir(b"/home/operator/a").unwrap();
    s.fs.mkdir(b"/home/operator/a/b").unwrap();
    let h = s
        .fs
        .open(b"/home/operator/a/b/secret", absd_fs::OpenFlags { write: true, create: true, ..Default::default() })
        .unwrap();
    s.fs.write_at(h, 0, b"orig").unwrap();
    s.fs.close(h).unwrap();
    s.fs.sync().unwrap();
    let q = |_: usize| Some(PipeState { request_available: 0, request_writers: 1, reply_available: 0, reply_readers: 1 });
    let b = Frame::request(op::BIND).u8(1).u8(1).u8(2).mounts(&[Mount::new(b"/home/operator", true)]).finish();
    assert_eq!(status(&s.dispatch(CONTROL, body(&b), &q, 1)), 0);
    let q2 = |_: usize| Some(PipeState { request_available: 0, request_writers: 2, reply_available: 0, reply_readers: 2 });
    let d = Frame::request(op::DERIVE)
        .u8(1)
        .u8(derive::LIST)
        .mounts(&[Mount::new(b"/home/operator", true), Mount::new(b"/home/operator/a/b", false)])
        .finish();
    assert_eq!(status(&s.dispatch(1, body(&d), &q2, 1)), 0);
    let o = Frame::request(op::OPEN).u32(2).bytes(b"/home/operator/a/b/secret").finish();
    assert_eq!(status(&s.dispatch(2, body(&o), &q, 1)), -30);
    let from = b"/home/operator/a";
    let r = Frame::request(op::RENAME).u8(0).u16(from.len() as u16).bytes(from).bytes(b"/home/operator/z").finish();
    assert_eq!(status(&s.dispatch(2, body(&r), &q, 1)), errno::BUSY);
    let o = Frame::request(op::OPEN).u32(2).bytes(b"/home/operator/z/b/secret").finish();
    assert_eq!(status(&s.dispatch(2, body(&o), &q, 1)), errno::NOT_FOUND);
    let o = Frame::request(op::OPEN).u32(2).bytes(b"/home/operator/a/b/secret").finish();
    assert_eq!(status(&s.dispatch(2, body(&o), &q, 1)), errno::READ_ONLY);
    let h = s.fs.open(b"/home/operator/a/b/secret", absd_fs::OpenFlags { read: true, ..Default::default() }).unwrap();
    let mut bytes = [0; 4];
    assert_eq!(s.fs.read_at(h, 0, &mut bytes).unwrap(), 4);
    assert_eq!(&bytes, b"orig");
    s.fs.close(h).unwrap();
}

/// Audit D4: one session can fill the object budget; before the repair the
/// next boot could then bind no session (the scratch mount's directory
/// could not be made). See `fsd/src/tests.rs` for the repaired rule.
#[test]
fn one_session_can_exhaust_the_object_budget() {
    let mut s = setup();
    let q = |_: usize| Some(PipeState { request_available: 0, request_writers: 1, reply_available: 0, reply_readers: 1 });
    let mk = |n: &str| {
        Frame::request(op::BIND)
            .u8(1)
            .u8(0)
            .mounts(&[Mount::new(b"/home/operator", true), Mount::new(n.as_bytes(), true)])
            .finish()
    };
    assert_eq!(status(&s.dispatch(CONTROL, body(&mk("/tmp/session-1")), &q, 1)), 0);
    let mut made = 0;
    for i in 0..100000u32 {
        let name = format!("/home/operator/{i:0>12}");
        let o = Frame::request(op::OPEN).u32(2 | 16).bytes(name.as_bytes()).finish();
        let h = status(&s.dispatch(1, body(&o), &q, 1));
        if h < 0 {
            break;
        }
        made += 1;
        let c = Frame::request(op::CLOSE).u64(h as u64).finish();
        s.dispatch(1, body(&c), &q, 1);
    }
    assert!(made > 0);
    let rel = Frame::request(op::RELEASE).u8(1).finish();
    assert_eq!(status(&s.dispatch(CONTROL, body(&rel), &q, 1)), 0);
}
