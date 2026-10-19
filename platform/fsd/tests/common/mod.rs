//! The dispatcher simulator of `fsd/src/tests.rs` (Disk, image, server,
//! Harness, Pipes), copied here with only `absd_fsd`'s public API so a
//! test binary with its own global allocator can drive it, plus the
//! guest's `posix.lock-contention` scenario and three controls
//! (docs/fsd-heap-step-20261013).
//!
//! What is the simulator's and not the file server's, and how it is kept
//! out of a heap measurement:
//! - Everything the simulator allocates for the guest's other parties (the
//!   image builder, the block device, the kernel's pipes, the frames sshd
//!   and the probes build) is allocated inside a [`SimScope`]. The test
//!   crate root defines `sim_enter` / `sim_exit`: the pool driver routes
//!   such allocations away from the measured allocator, the counting
//!   driver counts them as before (no-ops).
//! - `Disk`: the guest's block device, not heap. One flat buffer of every
//!   sector, made in the scope, so a write never allocates.
//! - `Pipes::request` / `Pipes::reply`: the kernel's pipes. Each is
//!   reserved once at `Pipes::new` (in the scope) with room for the
//!   largest frame, and is cleared, never taken, so its capacity is reused
//!   across runs (the copy in `fsd/src/tests.rs` takes the reply buffer).
//! - The loop reads a request pipe [`MAX_TRANSFER`] bytes at a time into
//!   the channel's `Inbox`, as `ssh/src/fsd_server.rs` does; `Pipes::inbox`
//!   is the loop's `Io::inbox`, the file server's own, so it is measured.
//! - A reply is held until the dispatch's events are reported, as the
//!   loop's `io[channel].output` is, then dropped (a live client reads it
//!   before the loop looks at the channel again).
//! - `Server::events` is taken after each dispatch, as the loop does. With
//!   [`Harness::log`] set, each event is formatted as the loop's `report`
//!   does and the logged ones are appended to `/var/log/fsd` through the
//!   server's own filesystem (`Log::say`, minus the console line);
//!   otherwise they are dropped.

#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;

use absd_fs::{Device, Error, Fs, OpenFlags, SECTOR};
use absd_fsd::Event;
use absd_fsd::log::{self as logfile, LogFile};
use absd_fsd::proto::{self, Frame, Mount, Reader, derive, op, status};
use absd_fsd::{CONTROL, Inbox, PipeState, Server, Taken};

const SECTORS: u64 = 16384;

/// While one is alive, allocations are the simulator's (the guest's other
/// parties), not the file server's. Nests.
pub struct SimScope(());

impl SimScope {
    pub fn new() -> Self {
        crate::sim_enter();
        SimScope(())
    }
}

impl Drop for SimScope {
    fn drop(&mut self) {
        crate::sim_exit();
    }
}

#[derive(Clone)]
pub struct Disk(Rc<RefCell<Vec<[u8; SECTOR]>>>);

impl Disk {
    /// Every sector present (zero), in one buffer: writes never allocate.
    fn blank(sectors: u64) -> Self {
        let _sim = SimScope::new();
        Disk(Rc::new(RefCell::new(vec![[0; SECTOR]; sectors as usize])))
    }
    /// An independent copy of the whole device.
    pub fn copy(&self) -> Self {
        let _sim = SimScope::new();
        Disk(Rc::new(RefCell::new(self.0.borrow().clone())))
    }
}

impl Device for Disk {
    fn sectors(&self) -> u64 {
        self.0.borrow().len() as u64
    }
    fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error> {
        *buffer = self.0.borrow()[sector as usize];
        Ok(())
    }
    fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
        self.0.borrow_mut()[sector as usize] = *buffer;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

const SEED: &[u8] = b"0123456789abcdef0123456789abcdef";

fn put(fs: &mut Fs<Disk>, path: &[u8], data: &[u8]) {
    let flags = OpenFlags {
        read: true,
        write: true,
        create: true,
        create_new: false,
        truncate: true,
    };
    let handle = fs.open(path, flags).unwrap();
    fs.write_at(handle, 0, data).unwrap();
    fs.close(handle).unwrap();
}

/// The case's working directory on ABSD (`cports/cases.tsv`: CWD `posix`
/// under `/home/operator/cports/`).
pub const CWD: &[u8] = b"/home/operator/cports/posix";
/// The scenario's lock file (`posix.lock-contention ... l`).
pub const LOCK_FILE: &[u8] = b"/home/operator/cports/posix/l";

/// The simulator's image, with the directories a guest session's mounts
/// name (`ssh/src/absd.rs` `session_mounts`) and the case's directory.
pub fn image() -> Disk {
    image_of(SECTORS, 0)
}

/// Objects at rest in the guest's file server after the scenario
/// (FINDING-fsd-heap-step-lock-contention.md: `fs_objects` 161).
pub const GUEST_OBJECTS: usize = 161;
/// The guest-scale device: 32 MiB.
const GUEST_SECTORS: u64 = 65536;

/// [`image`] grown to the guest's object count: files of 1-48 KiB (every
/// sixteenth 256 KiB, like a program in /bin) in sixteen case directories
/// under `/home/operator/cports`, until the image holds
/// `GUEST_OBJECTS - 2` objects: the guest's 161 is counted after the
/// scenario, so it includes the lock file `l` and `/var/log/fsd`, which
/// the scenario's first run and the mirrored log add here (rest 161 for
/// lock-contention with the log; 160 without the log or without `l`).
/// A synthetic population at the guest's count, not the guest's tree.
pub fn guest_image() -> Disk {
    image_of(GUEST_SECTORS, GUEST_OBJECTS - 2)
}

fn image_of(sectors: u64, objects: usize) -> Disk {
    let _sim = SimScope::new();
    let disk = Disk::blank(sectors);
    absd_fs::format(&mut disk.clone(), 7).unwrap();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    for dir in [
        &b"/bin"[..],
        b"/etc",
        b"/ssh",
        b"/home",
        b"/home/operator",
        b"/home/operator/cports",
        CWD,
        b"/tmp",
        b"/share",
        b"/var",
        absd_fsd::log::DIR,
    ] {
        fs.mkdir(dir).unwrap();
    }
    put(&mut fs, b"/bin/ls", b"ELF ls");
    put(&mut fs, b"/bin/posixprobe", b"ELF posixprobe");
    put(&mut fs, b"/etc/motd", b"hello\n");
    put(&mut fs, b"/ssh/host_ed25519_seed", SEED);
    let mut file = 0usize;
    while fs.object_count() < objects {
        let dir = format!("/home/operator/cports/case-{:02}", file % 16);
        if fs.stat(dir.as_bytes()).is_err() {
            fs.mkdir(dir.as_bytes()).unwrap();
            continue;
        }
        let size = if file % 16 == 15 { 256 * 1024 } else { (file * 7919 % 48 + 1) * 1024 };
        put(&mut fs, format!("{dir}/file-{file:03}.c").as_bytes(), &vec![0x41; size]);
        file += 1;
    }
    fs.sync().unwrap();
    disk
}

pub fn server(disk: &Disk, slots: usize) -> Server<Disk> {
    let fs = Fs::mount(disk.clone(), true).unwrap();
    Server::new(
        fs,
        slots,
        vec![Mount::new(b"/ssh", false), Mount::new(b"/bin", false)],
    )
}

/// The client slots of the scenario's server (sshd's picks below assume
/// six). [`Scenario::SlotDrift`] uses [`GUEST_SLOTS`].
pub const SLOTS: usize = 6;
/// The guest's client slots (`scripts/fsd-matrix.py:95`: `slots=10`).
pub const GUEST_SLOTS: usize = 10;
/// A fixed wall clock (seconds) for `Server::clock` and the log's stamps,
/// advanced by the tick count so stamps change but keep their length.
const WALL: u64 = 1_791_000_000;

/// A guest session's mounts (`ssh/src/absd.rs` `session_mounts`), with or
/// without its scratch directory `/tmp/session-<id>`.
pub fn session_mounts(id: u64, scratch: bool) -> Vec<Mount> {
    let mut mounts = vec![Mount::new(b"/home/operator", true)];
    if scratch {
        mounts.push(Mount::new(format!("/tmp/session-{id}").as_bytes(), true));
    }
    mounts.extend([
        Mount::new(b"/bin", false),
        Mount::new(b"/etc", false),
        Mount::new(b"/share", false),
        Mount::new(absd_fsd::log::DIR, false),
    ]);
    mounts
}

pub struct Harness {
    pub server: Server<Disk>,
    pub now: u64,
    /// The loop's `/var/log/fsd` (`ssh/src/fsd_server.rs` `Log`), when the
    /// run mirrors it.
    pub log: Option<LogFile>,
}

impl Harness {
    pub fn new(disk: &Disk, slots: usize, log: bool) -> Self {
        Self {
            server: server(disk, slots),
            now: 1,
            log: log.then(|| LogFile::new(b"/var/log/fsd", "fsd")),
        }
    }
    fn wall(&self) -> Option<u64> {
        Some(WALL + self.now / 100)
    }
    /// The loop's `report` over one dispatch's events: each is formatted as
    /// it is there; the logged ones are appended to `/var/log/fsd` (the
    /// loop's `Log::say` without the console line), and their write noted
    /// for the idle commit. Without a log the events are only dropped.
    fn report(&mut self, events: Vec<Event>) {
        let Some(mut log) = self.log.take() else {
            drop(events);
            return;
        };
        let list = |mounts: &[Mount]| {
            mounts
                .iter()
                .map(|m| format!("{}:{}", String::from_utf8_lossy(&m.path), if m.writable { "rw" } else { "ro" }))
                .collect::<Vec<_>>()
                .join(",")
        };
        for event in events {
            let text = match event {
                Event::Bound { slot, spares, mounts } => {
                    format!("FSD BIND slot={slot} spares={spares:?} mounts={}", list(&mounts))
                }
                Event::BindRefused { slot, status } => format!("FSD BIND REFUSED slot={slot} status={status}"),
                Event::BindDeferred { slot } => format!("FSD BIND DEFERRED slot={slot}"),
                Event::Released { slot, closed, scratch } => {
                    let (bound, opens, draining) = self.server.capacity();
                    format!(
                        "FSD RELEASE slot={slot} closed={closed} scratch_removed={scratch} fs_objects={} bound={bound} opens={opens} draining={draining}",
                        self.server.fs.object_count()
                    )
                }
                // The console only in the loop: formatted, not logged.
                Event::Derived { spare, owner, mounts } => {
                    drop(format!("FSD DERIVE spare={spare} owner={owner} mounts={}", list(&mounts)));
                    continue;
                }
                Event::DeriveRefused { owner, status } => format!("FSD DERIVE REFUSED owner={owner} status={status}"),
                Event::Notice(text) => {
                    drop(text);
                    continue;
                }
            };
            // `Log::write`.
            let wall = self.wall();
            let line = logfile::line(wall, "fsd", &text);
            self.server.fs.set_clock(wall);
            if log.append(&mut self.server.fs, wall, &line).is_ok() {
                self.server.note_write(self.now);
            }
        }
        self.log = Some(log);
    }
}

/// What one look at a channel came to, as the loop would log or reply it.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Not read: unbound and quiet.
    Skipped,
    /// Read, but no whole request there.
    Nothing,
    /// A request served, with the status replied.
    Replied(i64),
}

/// Room reserved once per pipe: the largest frame (a 64 KiB write).
const PIPE_ROOM: usize = proto::MAX_FRAME;
/// What the loop reads from a request pipe at a time
/// (`ssh/src/fsd_server.rs` `MAX_TRANSFER`).
pub const MAX_TRANSFER: usize = 256;

/// The loop of `ssh/src/fsd_server.rs` over fake pipes (copied from
/// `fsd/src/tests.rs`; the pipes' buffers are reserved once and reused).
pub struct Pipes {
    pub request: Vec<Vec<u8>>,
    pub reply: Vec<Vec<u8>>,
    pub inbox: Vec<Inbox>,
}

impl Pipes {
    pub fn new(channels: usize) -> Self {
        let _sim = SimScope::new();
        Self {
            request: (0..channels).map(|_| Vec::with_capacity(PIPE_ROOM)).collect(),
            reply: (0..channels).map(|_| Vec::with_capacity(PIPE_ROOM)).collect(),
            inbox: (0..channels).map(|_| Inbox::new()).collect(),
        }
    }
    /// A client writes `bytes` on its channel; nothing reads them yet.
    pub fn queue(&mut self, channel: usize, bytes: &[u8]) {
        assert!(
            self.request[channel].len() + bytes.len() <= PIPE_ROOM,
            "the simulator's request pipe would grow"
        );
        self.request[channel].extend_from_slice(bytes);
    }
    pub fn state(&self, channel: usize) -> Option<PipeState> {
        Some(PipeState {
            request_available: (self.request[channel].len() + self.inbox[channel].len()) as u64,
            request_writers: 1,
            reply_available: self.reply[channel].len() as u64,
            reply_readers: 1,
        })
    }
    /// sshd, before a bind: a reply an earlier holder never read. Cleared
    /// in place (the pipe's buffer is the simulator's, reused).
    pub fn drain_reply(&mut self, channel: usize) -> usize {
        let count = self.reply[channel].len();
        self.reply[channel].clear();
        count
    }
    pub fn replied_status(&self, channel: usize) -> Option<i64> {
        let reply = &self.reply[channel];
        (reply.len() >= proto::HEADER + 8 + proto::TRAILER)
            .then(|| Reader(&reply[proto::HEADER..]).i64().unwrap())
    }
    /// One look at `channel`, as the loop takes it.
    pub fn serve(&mut self, h: &mut Harness, channel: usize) -> Step {
        if !h.server.active(channel) {
            return Step::Skipped;
        }
        // The loop's reads: at most `MAX_TRANSFER` bytes each.
        while self.inbox[channel].wants_more() && !self.request[channel].is_empty() {
            let count = self.request[channel].len().min(MAX_TRANSFER);
            self.inbox[channel].push(&self.request[channel][..count]);
            self.request[channel].drain(..count);
        }
        let mut taken = self.inbox[channel].take();
        if taken == Taken::Nothing && self.request[channel].is_empty() {
            self.inbox[channel].idle();
            taken = self.inbox[channel].take();
        }
        match taken {
            Taken::Nothing => {
                if h.server.draining(channel) && self.request[channel].is_empty() {
                    self.inbox[channel].discard();
                    h.server.settle(channel, self.state(channel));
                }
                Step::Nothing
            }
            Taken::Frame { seq, body } => {
                let lookup = |index: usize| self.state(index);
                let now = h.now;
                h.server.clock(now, || Some(WALL + now / 100));
                let mut reply = h.server.dispatch(channel, &body, &lookup, now);
                proto::stamp_seq(&mut reply, seq);
                let status = Reader(&reply[proto::HEADER..]).i64().unwrap();
                for index in core::mem::take(&mut h.server.resets) {
                    self.inbox[index].discard();
                    self.request[index].clear();
                }
                if h.server.draining(channel) {
                    assert!(
                        self.reply[channel].len() + reply.len() <= PIPE_ROOM,
                        "the simulator's reply pipe would grow"
                    );
                    self.reply[channel].extend_from_slice(&reply);
                }
                // The loop holds the reply (`io[channel].output`) while it
                // takes the events and reports them.
                let events = core::mem::take(&mut h.server.events);
                h.report(events);
                drop(reply);
                drop(body);
                Step::Replied(status)
            }
        }
    }
}

/// The simulator: one server, its pipes, and sshd's session counter.
pub struct Sim {
    pub h: Harness,
    pub pipes: Pipes,
    /// sshd's next session id. Started at 1000 so `/tmp/session-<id>`
    /// keeps the same length for the first 9000 sessions; a name one digit
    /// longer would otherwise move a live-byte count by itself.
    pub next_session: u64,
    /// Runs started (`run_scenario`), for scenarios that vary by run.
    pub runs: u64,
    /// Idle commits `settle_all` made (each one asserted to leave nothing
    /// dirty).
    pub idle_commits: u64,
}

impl Sim {
    /// Task 1's simulator: [`SLOTS`] slots, no log.
    pub fn new(disk: &Disk) -> Self {
        Self::with(disk, SLOTS, false)
    }
    pub fn with(disk: &Disk, slots: usize, log: bool) -> Self {
        let h = Harness::new(disk, slots, log);
        let pipes = Pipes::new(h.server.channels());
        Self {
            h,
            pipes,
            next_session: 1000,
            runs: 0,
            idle_commits: 0,
        }
    }
    /// A live client's request, built (in the simulator's scope), queued,
    /// served at once; its status.
    pub fn ask(&mut self, channel: usize, build: impl FnOnce() -> Vec<u8>) -> i64 {
        {
            let _sim = SimScope::new();
            let frame = build();
            self.pipes.queue(channel, &frame);
            drop(frame);
        }
        match self.pipes.serve(&mut self.h, channel) {
            Step::Replied(status) => status,
            other => panic!("channel {channel}: no reply: {other:?}"),
        }
    }
    /// A request written but not yet read by the loop.
    pub fn queue(&mut self, channel: usize, build: impl FnOnce() -> Vec<u8>) {
        let _sim = SimScope::new();
        let frame = build();
        self.pipes.queue(channel, &frame);
    }
    /// sshd's BIND; returns the status and the session id.
    fn bind(&mut self, slot: u8, spares: &[u8], scratch: bool) -> (i64, u64) {
        let id = self.next_session;
        self.next_session += 1;
        for &channel in core::iter::once(&slot).chain(spares) {
            self.pipes.drain_reply(channel as usize);
        }
        let status = self.ask(CONTROL, || {
            let mut frame = Frame::request(op::BIND).u8(slot).u8(spares.len() as u8);
            for spare in spares {
                frame = frame.u8(*spare);
            }
            frame.mounts(&session_mounts(id, scratch)).finish()
        });
        (status, id)
    }
    fn release(&mut self, slot: u8) -> i64 {
        self.ask(CONTROL, || Frame::request(op::RELEASE).u8(slot).finish())
    }
    /// The shell starts a child on its first spare (`derive::SAME`).
    fn derive_child(&mut self, slot: usize) -> i64 {
        self.ask(slot, || Frame::request(op::DERIVE).u8(1).u8(derive::SAME).finish())
    }
    fn open(&mut self, channel: usize, flags: u32, path: &[u8]) -> i64 {
        self.ask(channel, || Frame::request(op::OPEN).u32(flags).bytes(path).finish())
    }
    fn lock(&mut self, channel: usize, handle: i64, mode: u32) -> i64 {
        self.ask(channel, || {
            Frame::request(op::LOCK).u64(handle as u64).u32(mode).finish()
        })
    }
    fn write_at(&mut self, channel: usize, handle: i64, offset: u64, data: &[u8]) -> i64 {
        self.ask(channel, || {
            Frame::request(op::WRITE_AT)
                .u64(handle as u64)
                .u64(offset)
                .bytes(data)
                .finish()
        })
    }
    fn close(&mut self, channel: usize, handle: i64) -> i64 {
        self.ask(channel, || Frame::request(op::CLOSE).u64(handle as u64).finish())
    }
    /// The loop's passes until every channel has settled: sshd drains a
    /// reply nobody will read (as it does before binding that slot), each
    /// draining channel is read until quiet, then an idle commit (the loop
    /// commits idle writes after `COMMIT_TICKS`, fsd/src/server.rs:33; not
    /// exported). The idle commit is asserted to leave nothing dirty, so
    /// the census point cannot move if that constant does.
    pub fn settle_all(&mut self) {
        for _ in 0..16 {
            let channels = self.h.server.channels();
            for channel in 0..channels {
                if self.h.server.draining(channel) {
                    self.pipes.drain_reply(channel);
                }
                self.pipes.serve(&mut self.h, channel);
            }
            let quiet = (0..channels).all(|channel| {
                !self.h.server.draining(channel)
                    && self.pipes.request[channel].is_empty()
                    && self.pipes.inbox[channel].is_empty()
            });
            if quiet {
                // Well past `COMMIT_TICKS` (200).
                self.h.now += 1000;
                if self.h.server.idle_commit(self.h.now).unwrap() {
                    self.idle_commits += 1;
                }
                // Nothing dirty is left at any later tick: `idle_commit`
                // commits (and returns true) whenever a write is pending.
                assert!(
                    !self.h.server.idle_commit(u64::MAX).unwrap(),
                    "settle: a write was still uncommitted after the idle commit"
                );
                return;
            }
        }
        panic!("channels did not settle: {:?}", self.h.server.capacity());
    }
}

/// Open flags as `std` passes them (`Server::open`).
const O_RDWR: u32 = 1 | 2;
const O_CREAT: u32 = 8;

const SHARED: u32 = 1;
const EXCLUSIVE: u32 = 2;
const UNLOCK: u32 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scenario {
    /// `posix.lock-contention` as the guest runs it.
    LockContention,
    /// Control: one session locks and unlocks, no contention, no kill.
    PlainLock,
    /// Control: the contention, but A unlocks, closes and is released
    /// normally (no killed holder).
    ContentionNoKill,
    /// Control: the contention without a scratch mount, so no release
    /// removes a scratch tree (no release commit).
    ContentionNoScratch,
    /// Ruling R4: one session writes a [`LARGE_FILE`]-byte file in its
    /// scratch directory in 64 KiB writes, closes it (a commit with its
    /// long block list), and is released (the scratch removal's commit).
    /// The host stand-in for the cports zlib 8 MiB pair.
    LargeRelease,
    /// M4b: the contention on a [`GUEST_SLOTS`]-slot server where B2 binds
    /// a slot triple that moves by three slots every run (as sshd binds the
    /// next slot after a BUSY on a still-draining one), so every channel
    /// is in time a session's own, a probe's and an idle spare.
    SlotDrift,
}

impl Scenario {
    pub const ALL: [Scenario; 4] = [
        Scenario::LockContention,
        Scenario::PlainLock,
        Scenario::ContentionNoKill,
        Scenario::ContentionNoScratch,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Scenario::LockContention => "lock-contention",
            Scenario::PlainLock => "plain-lock",
            Scenario::ContentionNoKill => "contention-no-kill",
            Scenario::ContentionNoScratch => "contention-no-scratch",
            Scenario::LargeRelease => "large-release",
            Scenario::SlotDrift => "slot-drift",
        }
    }
    /// The server's client slots this scenario runs on.
    pub fn slots(self) -> usize {
        match self {
            Scenario::SlotDrift => GUEST_SLOTS,
            _ => SLOTS,
        }
    }
}

// Slots as sshd picks them with six slots and a two-session reserve:
// the lowest free slot, two spares for a shell.
const A: u8 = 1;
const A_SPARES: [u8; 2] = [2, 3];
const B: u8 = 4;
const B_SPARES: [u8; 2] = [5, 6];

/// The large file's size: 2 MiB, 512 blocks of 4 KiB, so its block list
/// (`Vec<u32>`, 2 KiB) is in the pooled class.
pub const LARGE_FILE: usize = 2 * 1024 * 1024;
/// One write: `proto::MAX_IO`, as std splits a large write.
const WRITE_CHUNK: usize = proto::MAX_IO;
static WRITE_DATA: [u8; WRITE_CHUNK] = [0x5a; WRITE_CHUNK];

/// B2's slot triple in run `run` (1-based) of [`Scenario::SlotDrift`]:
/// starting after B's (7, 8, 9), three slots further every run, wrapping
/// over 1..=GUEST_SLOTS. The probe's channel (the first spare) is then a
/// different one of the ten in each of runs 1-10.
fn drift_triple(run: u64) -> (u8, [u8; 2]) {
    let slots = GUEST_SLOTS as u64;
    let at = |offset: u64| (((run - 1) * 3 + 6 + offset) % slots + 1) as u8;
    (at(0), [at(1), at(2)])
}

/// One run of `scenario`; returns only after every channel has settled.
/// Every status is asserted, so a run that returns ran the sequence.
pub fn run_scenario(sim: &mut Sim, scenario: Scenario) {
    sim.runs += 1;
    assert_eq!(
        sim.h.server.channels(),
        scenario.slots() + 1,
        "{}: the simulator's slot count",
        scenario.name()
    );
    let scratch = scenario != Scenario::ContentionNoScratch;
    if scenario == Scenario::PlainLock {
        // One session: open l, lock exclusive, unlock, close, released.
        assert_eq!(sim.bind(A, &A_SPARES, scratch).0, 0, "plain: bind");
        assert_eq!(sim.derive_child(A as usize), 0, "plain: derive");
        let probe = A_SPARES[0] as usize;
        let fd = sim.open(probe, O_RDWR | O_CREAT, LOCK_FILE);
        assert!(fd > 0, "plain: open l: {fd}");
        assert_eq!(sim.lock(probe, fd, EXCLUSIVE), 0, "plain: lock exclusive");
        assert_eq!(sim.lock(probe, fd, UNLOCK), 0, "plain: unlock");
        assert_eq!(sim.close(probe, fd), 0, "plain: close");
        assert_eq!(sim.release(A), 0, "plain: release");
        sim.settle_all();
        return;
    }
    if scenario == Scenario::LargeRelease {
        // One session writes the file in its scratch, closes it, ends.
        let (bound, id) = sim.bind(A, &A_SPARES, true);
        assert_eq!(bound, 0, "large: bind");
        assert_eq!(sim.derive_child(A as usize), 0, "large: derive");
        let probe = A_SPARES[0] as usize;
        let path = {
            let _sim = SimScope::new();
            format!("/tmp/session-{id}/large").into_bytes()
        };
        let fd = sim.open(probe, O_RDWR | O_CREAT, &path);
        assert!(fd > 0, "large: open: {fd}");
        for chunk in 0..LARGE_FILE / WRITE_CHUNK {
            let offset = (chunk * WRITE_CHUNK) as u64;
            assert_eq!(
                sim.write_at(probe, fd, offset, &WRITE_DATA),
                WRITE_CHUNK as i64,
                "large: write at {offset}"
            );
        }
        assert_eq!(sim.close(probe, fd), 0, "large: close");
        assert_eq!(sim.release(A), 0, "large: release");
        {
            let _sim = SimScope::new();
            drop(path);
        }
        sim.settle_all();
        return;
    }

    // (1) A: `posixprobe hold l` in a held session. The shell (slot A)
    // starts the probe on its first spare; open O_RDWR|O_CREAT; F_WRLCK.
    assert_eq!(sim.bind(A, &A_SPARES, scratch).0, 0, "A: bind");
    assert_eq!(sim.derive_child(A as usize), 0, "A: derive");
    let a = A_SPARES[0] as usize;
    let a_fd = sim.open(a, O_RDWR | O_CREAT, LOCK_FILE);
    assert!(a_fd > 0, "A: open l: {a_fd}");
    assert_eq!(sim.lock(a, a_fd, EXCLUSIVE), 0, "A: lock exclusive (HELD)");

    // (2) B: `posixprobe try l`: open O_RDWR; F_RDLCK and F_WRLCK both
    // refused at once (EAGAIN); close.
    assert_eq!(sim.bind(B, &B_SPARES, scratch).0, 0, "B: bind");
    assert_eq!(sim.derive_child(B as usize), 0, "B: derive");
    let b = B_SPARES[0] as usize;
    let b_fd = sim.open(b, O_RDWR, LOCK_FILE);
    assert!(b_fd > 0, "B: open l: {b_fd}");
    assert_eq!(sim.lock(b, b_fd, SHARED), status::AGAIN, "B: try shared");
    assert_eq!(sim.lock(b, b_fd, EXCLUSIVE), status::AGAIN, "B: try exclusive");
    assert_eq!(sim.close(b, b_fd), 0, "B: close");

    // B's session ends with one request still in its channel: sshd's
    // RELEASE is served before the loop reads it, so the channel drains
    // (the request is answered as refused, -13, its reply left unread).
    sim.queue(b, || Frame::request(op::LOCK).u64(b_fd as u64).u32(SHARED).finish());
    assert_eq!(sim.release(B), 0, "B: release (closed nothing)");
    assert!(sim.h.server.draining(b), "B's probe channel drains");
    assert_eq!(sim.pipes.serve(&mut sim.h, b), Step::Replied(status::DENIED), "B: queued frame refused");
    assert_eq!(sim.pipes.replied_status(b), Some(status::DENIED));

    // (3) A ends.
    if scenario == Scenario::ContentionNoKill {
        // stdin closed: F_UNLCK, RELEASED, close, then the session ends.
        assert_eq!(sim.lock(a, a_fd, UNLOCK), 0, "A: unlock");
        assert_eq!(sim.close(a, a_fd), 0, "A: close");
        assert_eq!(sim.release(A), 0, "A: release (closed nothing)");
    } else {
        // Killed holder: the open still holds the lock; the release's
        // `drop_opens` closes it, which unlocks.
        assert_eq!(sim.release(A), 1, "A: release closes the held open");
    }
    sim.settle_all();
    assert_eq!(sim.h.server.capacity(), (0, 0, 0), "A and B reclaimed");

    // (4) B2: `posixprobe try l` again: both locks granted. B2 binds A's
    // slots again (sshd's lowest free), or under SlotDrift the run's
    // drifting triple.
    let (b2_slot, b2_spares) = match scenario {
        Scenario::SlotDrift => drift_triple(sim.runs),
        _ => (A, A_SPARES),
    };
    assert_eq!(sim.bind(b2_slot, &b2_spares, scratch).0, 0, "B2: bind");
    assert_eq!(sim.derive_child(b2_slot as usize), 0, "B2: derive");
    let b2 = b2_spares[0] as usize;
    let b2_fd = sim.open(b2, O_RDWR, LOCK_FILE);
    assert!(b2_fd > 0, "B2: open l: {b2_fd}");
    assert_eq!(sim.lock(b2, b2_fd, SHARED), 0, "B2: try shared");
    assert_eq!(sim.lock(b2, b2_fd, EXCLUSIVE), 0, "B2: try exclusive");
    assert_eq!(sim.close(b2, b2_fd), 0, "B2: close");
    assert_eq!(sim.release(b2_slot), 0, "B2: release");
    sim.settle_all();
}

/// The rest census for the sanity line: (fs_objects, bound, opens, draining).
pub fn rest_census(server: &Server<Disk>) -> (usize, usize, usize, usize) {
    let (bound, opens, draining) = server.capacity();
    (server.fs.object_count(), bound, opens, draining)
}
