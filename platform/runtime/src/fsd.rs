//! `std::fs` through the file server (kernel `docs/PROCESS-STARTUP.md`,
//! "File server"; the platform's `fsd/`). A process whose startup record
//! names file server channels (roles 13 and 14) and no block handle
//! reaches the filesystem only here: every hook becomes one request on its
//! own channel and one reply. It holds no block handle, so what it can see
//! and change is exactly what the server's record for that channel allows.
//!
//! A channel carries one conversation: one process uses it at a time. A
//! child therefore gets either a spare channel of its own, bound by the
//! server on this process's request to this process's authority or less,
//! or, when no spare is free, this channel lent to it; this process then
//! makes no request until that child has ended (`WouldBlock` until then).
//! A child may also get no filesystem at all.

use alloc::vec::Vec;
use core::cell::UnsafeCell;

use absd_fsd::Inbox;
use absd_fsd::proto::{self, Frame, Mount, Reader, derive, op, status};
use absd_fsd::version;

use crate::syscall3;
use crate::wire_kind::WireKind;

const SYS_WRITE: u64 = 1;
const SYS_GETPID: u64 = 4;
const SYS_CLOSE: u64 = 9;
const SYS_DUPLICATE: u64 = 13;
const SYS_READ: u64 = 15;
const SYS_INFO: u64 = 19;
const SYS_PIPE_INFO: u64 = 36;
const RIGHT_WAIT: u64 = 1 << 1;
const INFO_STATE_TERMINAL: u64 = 2;
const MAX_TRANSFER: usize = 256;

/// How the next child `std::process` starts reaches the filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChildFs {
    /// A free spare bound to this process's mounts, else this channel lent.
    Inherit,
    /// A free spare bound to this process's mounts, else the spawn is
    /// refused (`WouldBlock`): for a child that runs while this process
    /// keeps using its own channel (a shell copying a redirection).
    SpareOnly,
    /// A free spare bound to this process's mounts, all read-only.
    ReadOnly,
    /// A free spare bound to exactly these mounts (each inside one of
    /// this process's, with no more access).
    Mounts(Vec<Mount>),
    /// No filesystem at all.
    None,
    /// This process's channel number `own` (1-based among its spares) as
    /// the child's own, already bound by the server, plus these spares
    /// (sshd starting a session on a slot it bound).
    Slot { own: usize, spares: Vec<usize> },
}

/// A failed tracking copy is occupied, not an unused channel. Without a
/// valid wait handle it cannot be proven retired within this process.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Holder {
    Vacant,
    Tracked(u64),
    Untracked,
}

struct Spare {
    request: u64,
    reply: u64,
    /// Child tracking, including a failed-copy state that forbids reuse.
    holder: Holder,
}

struct State {
    own: Option<(u64, u64)>,
    spares: Vec<Spare>,
    /// Reply bytes read so far, per reply end: whole frames always, the
    /// first of which may be an earlier holder's (`proto`).
    inboxes: Vec<(u64, Inbox)>,
    /// This process's sequence words: its PID in the high half, a count
    /// in the low half (0 means not yet taken).
    seq: u64,
    /// Child tracking, including a failed-copy state that forbids requests.
    lent: Holder,
    default_child: ChildFs,
    next_child: Option<ChildFs>,
    /// The last directory listed, for `read_dir`'s one-entry-per-call hook.
    listing: Option<(Vec<u8>, Vec<(Vec<u8>, [u8; proto::ATTR_BYTES])>)>,
}

struct Global(UnsafeCell<State>);
// ABSD runs this process single-threaded and the hooks never re-enter.
unsafe impl Sync for Global {}
static STATE: Global = Global(UnsafeCell::new(State {
    own: None,
    spares: Vec::new(),
    inboxes: Vec::new(),
    seq: 0,
    lent: Holder::Vacant,
    default_child: ChildFs::Inherit,
    next_child: None,
    listing: None,
}));

fn state() -> &'static mut State {
    unsafe { &mut *STATE.0.get() }
}

/// Called by the CRT with the record's channels in order; the first is
/// this process's own.
pub(crate) fn install(channels: &[(u64, u64)]) {
    let state = state();
    state.own = channels.first().copied();
    state.spares =
        channels.iter().skip(1).map(|&(request, reply)| Spare { request, reply, holder: Holder::Vacant }).collect();
}

/// Whether `std::fs` goes through a file server in this process.
pub fn active() -> bool {
    state().own.is_some()
}

/// The raw ends of this process's channels: its own first, then spares.
pub fn channels() -> Vec<(u64, u64)> {
    let state = state();
    state.own.into_iter().chain(state.spares.iter().map(|s| (s.request, s.reply))).collect()
}

/// Policy for every later child (a server such as sshd sets `None`, so no
/// child of its ever gets its control channel by default).
pub fn set_default_child(policy: ChildFs) {
    state().default_child = policy;
}

/// Policy for the next child only.
pub fn set_next_child(policy: ChildFs) {
    state().next_child = Some(policy);
}

/// `pipe_info` words: available, space, readers, writers.
pub fn pipe_info(handle: u64) -> Result<[u64; 4], i64> {
    let mut record = [0u64; 4];
    let result = unsafe { syscall3(SYS_PIPE_INFO, handle, record.as_mut_ptr() as u64, 0) };
    if result < 0 { Err(result) } else { Ok(record) }
}

fn ended(holder: u64) -> bool {
    let mut info = [0u64; 4];
    let result = unsafe { syscall3(SYS_INFO, holder, info.as_mut_ptr() as u64, 0) };
    result < 0 || info[3] == INFO_STATE_TERMINAL
}

fn release_holder(holder: &mut Holder) {
    if let Holder::Tracked(handle) = *holder
        && ended(handle)
    {
        unsafe { syscall3(SYS_CLOSE, handle, 0, 0) };
        *holder = Holder::Vacant;
    }
}

fn write_all(handle: u64, mut bytes: &[u8]) -> Result<(), i64> {
    while !bytes.is_empty() {
        let length = bytes.len().min(MAX_TRANSFER);
        let written = unsafe { syscall3(SYS_WRITE, handle, bytes.as_ptr() as u64, length as u64) };
        if written <= 0 {
            return Err(status::IO);
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

/// The next sequence word of this process (never 0).
fn next_seq() -> u64 {
    let state = state();
    if state.seq == 0 {
        let pid = unsafe { syscall3(SYS_GETPID, 0, 0, 0) } as u64;
        state.seq = pid << 32;
    }
    state.seq = (state.seq & !0xffff_ffff) | ((state.seq + 1) & 0xffff_ffff).max(1);
    state.seq
}

fn reply_inbox(reply: u64) -> &'static mut Inbox {
    let state = state();
    let at = match state.inboxes.iter().position(|(end, _)| *end == reply) {
        Some(at) => at,
        None => {
            state.inboxes.push((reply, Inbox::new()));
            state.inboxes.len() - 1
        }
    };
    &mut state.inboxes[at].1
}

/// One request on `channel` and its whole reply: `(status, payload)`.
/// The request goes out under this process's next sequence word, and the
/// reply read is the one carrying it; replies addressed to an earlier
/// holder of the channel (a killed child) are read past.
fn exchange(channel: (u64, u64), frame: Vec<u8>) -> Result<(i64, Vec<u8>), i64> {
    exchange_within(channel, frame, None)
}

/// [`exchange`], waiting at most `budget` ticks in all for the reply when
/// given (`-110` once they pass): for a first request to a server that may
/// not understand the frame and so never answers.
fn exchange_within(channel: (u64, u64), mut frame: Vec<u8>, budget: Option<u64>) -> Result<(i64, Vec<u8>), i64> {
    // A body the server cannot take (a path of tens of KiB) would leave
    // this process waiting for a reply that never comes: refuse it here.
    if frame.len() < proto::HEADER + 1 + proto::TRAILER || frame.len() > proto::MAX_FRAME {
        return Err(status::INVALID);
    }
    let seq = next_seq();
    proto::stamp_seq(&mut frame, seq);
    write_all(channel.0, &frame)?;
    let deadline = budget.map(|ticks| crate::ticks().saturating_add(ticks));
    let inbox = reply_inbox(channel.1);
    loop {
        if let Some(body) = inbox.take_for(seq) {
            if body.len() < 8 {
                return Err(status::IO);
            }
            let status = i64::from_le_bytes(body[..8].try_into().unwrap());
            return Ok((status, body[8..].to_vec()));
        }
        let mut chunk = [0u8; MAX_TRANSFER];
        let count = match deadline {
            None => unsafe { syscall3(SYS_READ, channel.1, chunk.as_mut_ptr() as u64, MAX_TRANSFER as u64) },
            Some(deadline) => {
                let now = crate::ticks();
                if now >= deadline {
                    return Err(absd_fsd::version::TIMEOUT);
                }
                crate::read_within(channel.1, &mut chunk, deadline - now)? as i64
            }
        };
        if count <= 0 {
            // End of file: the server is gone.
            return Err(status::IO);
        }
        inbox.push(&chunk[..count as usize]);
    }
}

/// Asks the server on channel `index` of [`channels`] (0 is this process's
/// own; for sshd, the control channel) who it is (`op::VERSION`), waiting
/// at most `absd_fsd::version::ANSWER_TICKS`, and judges the answer: the
/// protocol must be this build's, and with `require_release` the release
/// too.
pub fn check_server(index: usize, require_release: bool) -> Result<version::Version, version::Refusal> {
    let channel = *channels().get(index).ok_or(version::Refusal::NoServer(status::NOT_FOUND))?;
    let answer = exchange_within(channel, Frame::request(op::VERSION).finish(), Some(version::ANSWER_TICKS));
    version::check(answer, require_release)
}

/// [`check_server`], or the refusal's line on standard error (the console
/// unless the startup record named another) and exit 104. The runtime
/// calls it before `main` for every client of a file server; sshd calls it
/// again, requiring its own release, before it listens.
pub fn require_server(index: usize, require_release: bool) -> version::Version {
    match check_server(index, require_release) {
        Ok(version) => version,
        Err(refusal) => {
            let mut line = refusal.line().into_bytes();
            line.push(b'\n');
            unsafe { crate::__absd_std_stderr_write(line.as_ptr(), line.len()) };
            crate::__absd_std_exit(version::REFUSED_STATUS)
        }
    }
}

/// One request on this process's own channel.
fn call(frame: Vec<u8>) -> Result<(i64, Vec<u8>), i64> {
    let state = state();
    let own = state.own.ok_or(status::NOT_FOUND)?;
    release_holder(&mut state.lent);
    if state.lent != Holder::Vacant {
        // A child is using this channel: it is not ours to use until then.
        return Err(status::AGAIN);
    }
    exchange(own, frame)
}

fn status_of(frame: Vec<u8>) -> i64 {
    match call(frame) {
        Ok((status, _)) => status,
        Err(code) => code,
    }
}

/// The mounts this process's channel sees.
pub fn mounts() -> Result<Vec<Mount>, i64> {
    let (code, payload) = call(Frame::request(op::MOUNTS).finish())?;
    if code < 0 {
        return Err(code);
    }
    Reader(&payload).mounts().ok_or(status::IO)
}

/// The filesystem's capacity, as the file server's format reports it
/// (`op::SPACE`): one filesystem behind every binding, so the numbers are
/// shared by every session, not a quota of this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Space {
    pub block_bytes: u32,
    pub data_blocks: u32,
    pub free_blocks: u32,
    pub filesystem_id: u64,
    /// The commit sequence durable on the device.
    pub commit: u64,
}

pub fn space() -> Result<Space, i64> {
    let (code, payload) = call(Frame::request(op::SPACE).finish())?;
    if code < 0 {
        return Err(code);
    }
    if payload.len() != proto::SPACE_BYTES {
        return Err(status::IO);
    }
    let mut reader = Reader(&payload);
    let block_bytes = reader.u32().ok_or(status::IO)?;
    let data_blocks = reader.u32().ok_or(status::IO)?;
    let free_blocks = reader.u32().ok_or(status::IO)?;
    reader.u32().ok_or(status::IO)?;
    let filesystem_id = reader.u64().ok_or(status::IO)?;
    let commit = reader.u64().ok_or(status::IO)?;
    Ok(Space { block_bytes, data_blocks, free_blocks, filesystem_id, commit })
}

/// Asks the file server to commit everything it has accepted and flush the
/// device (`op::COMMIT`); returns the commit sequence now durable.
pub fn commit() -> Result<u64, i64> {
    let (code, payload) = call(Frame::request(op::COMMIT).finish())?;
    if code < 0 {
        return Err(code);
    }
    Ok(u64::from_le_bytes(payload.as_slice().try_into().map_err(|_| status::IO)?))
}

/// sshd: a request on the channel at `index` of [`channels`] (the control
/// channel is 0), such as `BIND` and `RELEASE`.
pub fn request_on(index: usize, frame: Vec<u8>) -> Result<(i64, Vec<u8>), i64> {
    let channel = *channels().get(index).ok_or(status::INVALID)?;
    exchange(channel, frame)
}

/// Reads and discards reply bytes an earlier holder of channel `index`
/// never read (a killed client), so the next holder's first reply is its
/// own. Only a keeper of the channel's reply end can do this.
pub fn drain_reply(index: usize) -> Result<usize, i64> {
    let (_, reply) = *channels().get(index).ok_or(status::INVALID)?;
    reply_inbox(reply).discard();
    let mut drained = 0;
    loop {
        let [available, ..] = pipe_info(reply)?;
        if available == 0 {
            return Ok(drained);
        }
        let mut chunk = [0u8; MAX_TRANSFER];
        let length = (available as usize).min(MAX_TRANSFER);
        let count = unsafe { syscall3(SYS_READ, reply, chunk.as_mut_ptr() as u64, length as u64) };
        if count <= 0 {
            return Err(status::IO);
        }
        drained += count as usize;
    }
}

/// The channels a child gets, as `(request, reply)` ends, own first; the
/// caller records the child with [`child_started`] once it runs.
pub(crate) enum Plan {
    /// This process reaches no file server: the child gets what it would
    /// have without one (a read-only view where there is a block handle).
    None,
    /// The child is to get no filesystem at all.
    NoFs,
    Lend((u64, u64)),
    Spare(usize),
    Slot(Vec<(u64, u64)>),
}

impl Plan {
    pub(crate) fn ends(&self) -> Vec<(u64, u64)> {
        match self {
            Plan::None | Plan::NoFs => Vec::new(),
            Plan::Lend(own) => alloc::vec![*own],
            Plan::Spare(index) => {
                let spare = &state().spares[*index];
                alloc::vec![(spare.request, spare.reply)]
            }
            Plan::Slot(ends) => ends.clone(),
        }
    }
}

/// Decides, and asks the server for, the next child's channel.
pub(crate) fn plan_child() -> Result<Plan, i64> {
    let state = state();
    let policy = state.next_child.take().unwrap_or_else(|| state.default_child.clone());
    if policy == ChildFs::None {
        return Ok(Plan::NoFs);
    }
    let Some(own) = state.own else { return Ok(Plan::None) };
    match &policy {
        ChildFs::None => return Ok(Plan::NoFs),
        ChildFs::Slot { own, spares } => {
            let all = channels();
            let mut ends = Vec::with_capacity(1 + spares.len());
            for index in core::iter::once(own).chain(spares) {
                ends.push(*all.get(*index).ok_or(status::INVALID)?);
            }
            return Ok(Plan::Slot(ends));
        }
        ChildFs::Inherit | ChildFs::SpareOnly | ChildFs::ReadOnly | ChildFs::Mounts(_) => {}
    }
    for index in 0..state.spares.len() {
        release_holder(&mut state.spares[index].holder);
        if state.spares[index].holder != Holder::Vacant {
            continue;
        }
        // A reply an earlier child left unread would be read by the next.
        let _ = drain_reply(1 + index);
        let frame = Frame::request(op::DERIVE).u8(1 + index as u8);
        let frame = match &policy {
            ChildFs::Inherit | ChildFs::SpareOnly => frame.u8(derive::SAME),
            ChildFs::ReadOnly => frame.u8(derive::READ_ONLY),
            ChildFs::Mounts(mounts) => frame.u8(derive::LIST).mounts(mounts),
            _ => unreachable!(),
        };
        match call(frame.finish())? {
            (0, _) => return Ok(Plan::Spare(index)),
            // Still held by an earlier child's descendants: try another.
            (status::BUSY, _) => continue,
            (code, _) => return Err(code),
        }
    }
    match policy {
        ChildFs::Inherit => {
            release_holder(&mut state.lent);
            if state.lent != Holder::Vacant {
                return Err(status::AGAIN);
            }
            Ok(Plan::Lend(own))
        }
        // Narrower authority needs a channel of its own.
        _ => Err(status::AGAIN),
    }
}

/// Records which child now uses the planned channel (`process` is the
/// child's process handle). A failed wait copy keeps the channel occupied
/// without inventing a handle. Process exit drops this local record, but
/// does not prove that adopted children have released their channel ends.
pub(crate) fn child_started(plan: &Plan, process: u64) {
    let holder = || {
        let result = unsafe { syscall3(SYS_DUPLICATE, process, RIGHT_WAIT, 0) };
        if result < 0 { Holder::Untracked } else { Holder::Tracked(result as u64) }
    };
    match plan {
        Plan::Lend(_) => state().lent = holder(),
        Plan::Spare(index) => state().spares[*index].holder = holder(),
        _ => {}
    }
}

/// A spawn that failed after planning: nobody uses the channel.
pub(crate) fn child_failed(plan: &Plan) {
    if let Plan::Spare(index) = plan {
        let _ = call(Frame::request(op::UNDERIVE).u8(1 + *index as u8).finish());
    }
}

// -- std::fs hooks ------------------------------------------------------------

pub(crate) fn open(path: &[u8], flags: u32) -> i64 {
    status_of(Frame::request(op::OPEN).u32(flags).bytes(path).finish())
}

pub(crate) fn close(handle: u64) -> i64 {
    status_of(Frame::request(op::CLOSE).u64(handle).finish())
}

pub(crate) fn read_at(handle: u64, offset: u64, buffer: &mut [u8]) -> isize {
    let length = buffer.len().min(proto::MAX_IO) as u32;
    match call(Frame::request(op::READ_AT).u64(handle).u64(offset).u32(length).finish()) {
        Ok((count, data)) if count >= 0 => {
            let count = data.len().min(buffer.len());
            buffer[..count].copy_from_slice(&data[..count]);
            count as isize
        }
        Ok((code, _)) | Err(code) => code as isize,
    }
}

pub(crate) fn write_at(handle: u64, offset: u64, data: &[u8]) -> isize {
    let data = &data[..data.len().min(proto::MAX_IO)];
    status_of(Frame::request(op::WRITE_AT).u64(handle).u64(offset).bytes(data).finish()) as isize
}

pub(crate) fn set_len(handle: u64, length: u64) -> i64 {
    status_of(Frame::request(op::SET_LEN).u64(handle).u64(length).finish())
}

pub(crate) fn sync(handle: u64) -> i64 {
    status_of(Frame::request(op::SYNC).u64(handle).finish())
}

/// `stat` or `fstat`: the attribute record (`proto::ATTR_BYTES`) in
/// `RawAttr` layout.
pub(crate) fn attr(frame: Vec<u8>) -> Result<[u8; proto::ATTR_BYTES], i64> {
    let (code, payload) = call(frame)?;
    if code < 0 {
        return Err(code);
    }
    payload.as_slice().try_into().map_err(|_| status::IO)
}

pub(crate) fn fstat(handle: u64) -> Result<[u8; proto::ATTR_BYTES], i64> {
    attr(Frame::request(op::FSTAT).u64(handle).finish())
}

pub(crate) fn stat(path: &[u8]) -> Result<[u8; proto::ATTR_BYTES], i64> {
    attr(Frame::request(op::STAT).bytes(path).finish())
}

/// The kind of an attribute record: 1 file, 2 directory; any other word
/// is refused with -5 (SPEC A21), never read as either.
pub(crate) fn kind(attr: &[u8; proto::ATTR_BYTES]) -> Result<WireKind, i64> {
    crate::wire_kind::of_attr(attr)
}

pub(crate) fn size(attr: &[u8; proto::ATTR_BYTES]) -> u64 {
    u64::from_le_bytes(attr[8..16].try_into().unwrap())
}

pub(crate) fn set_readonly(handle: u64, readonly: bool) -> i64 {
    status_of(Frame::request(op::SET_READONLY).u64(handle).u8(readonly as u8).finish())
}

pub(crate) fn set_readonly_path(path: &[u8], readonly: bool) -> i64 {
    status_of(Frame::request(op::SET_READONLY_PATH).u8(readonly as u8).bytes(path).finish())
}

pub(crate) fn path_op(code: u8, path: &[u8]) -> i64 {
    status_of(Frame::request(code).bytes(path).finish())
}

pub(crate) fn rename(from: &[u8], to: &[u8], noreplace: bool) -> i64 {
    if from.len() > proto::MAX_PATH {
        return status::INVALID;
    }
    let frame =
        Frame::request(op::RENAME).u8(noreplace as u8).u16(from.len() as u16).bytes(from).bytes(to);
    status_of(frame.finish())
}

pub(crate) fn lock(handle: u64, mode: u32) -> i64 {
    status_of(Frame::request(op::LOCK).u64(handle).u32(mode).finish())
}

pub(crate) fn canonical(path: &[u8]) -> Result<Vec<u8>, i64> {
    let (code, payload) = call(Frame::request(op::CANONICAL).bytes(path).finish())?;
    if code < 0 { Err(code) } else { Ok(payload) }
}

/// Entry `index` of the directory at `path`: the whole listing is fetched
/// at index 0 (or for another path) and served from memory after that.
pub(crate) fn read_dir_entry(path: &[u8], index: u64) -> Result<Option<(Vec<u8>, [u8; proto::ATTR_BYTES])>, i64> {
    let state = state();
    let cached = matches!(&state.listing, Some((listed, _)) if listed == path);
    if index == 0 || !cached {
        let (count, payload) = call(Frame::request(op::READ_DIR).bytes(path).finish())?;
        if count < 0 {
            return Err(count);
        }
        let mut reader = Reader(&payload);
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let length = reader.u16().ok_or(status::IO)? as usize;
            let name = reader.take(length).ok_or(status::IO)?.to_vec();
            let attr: [u8; proto::ATTR_BYTES] =
                reader.take(proto::ATTR_BYTES).ok_or(status::IO)?.try_into().unwrap();
            entries.push((name, attr));
        }
        state.listing = Some((path.to_vec(), entries));
    }
    let Some((_, entries)) = &state.listing else { return Ok(None) };
    Ok(entries.get(index as usize).cloned())
}

/// The whole regular file at `path` (already resolved), at most `limit`
/// bytes: for starting a program from its image.
pub(crate) fn read_file(path: &[u8], limit: u64) -> Result<Vec<u8>, i64> {
    let mut bytes = Vec::new();
    read_file_into(path, limit, &mut bytes)?;
    Ok(bytes)
}

/// [`read_file`] into `bytes` (cleared first, capacity kept; see
/// `storage::read_file_into`).
pub(crate) fn read_file_into(path: &[u8], limit: u64, bytes: &mut Vec<u8>) -> Result<(), i64> {
    bytes.clear();
    let attr = stat(path)?;
    match kind(&attr)? {
        WireKind::File => {}
        WireKind::Dir => return Err(-21),
    }
    if size(&attr) > limit {
        return Err(-27);
    }
    let handle = open(path, 1);
    if handle < 0 {
        return Err(handle);
    }
    let handle = handle as u64;
    bytes.resize(size(&attr) as usize, 0);
    let mut filled = 0usize;
    let outcome = loop {
        if filled == bytes.len() {
            break Ok(());
        }
        match read_at(handle, filled as u64, &mut bytes[filled..]) {
            0 => break Err(status::IO),
            count if count < 0 => break Err(count as i64),
            count => filled += count as usize,
        }
    };
    close(handle);
    if outcome.is_err() {
        bytes.clear();
    }
    outcome
}
