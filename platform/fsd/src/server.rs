//! The dispatcher: channel records, bindings, and every request.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use absd_fs::{Attr, Device, Error, Fs, Kind, OpenFlags};

use crate::proto::{
    self, Frame, MAX_IO, MAX_MOUNTS, Mount, Reader, derive, normalize, op, status, within,
};
use crate::recovery;
use crate::release::{BOUND, HIDDEN, hidden};

/// The control channel is always channel 0; client slots follow.
pub const CONTROL: usize = 0;
/// Subtree no session binding may include: the host key lives there.
pub const RESERVED: &[u8] = b"/ssh";
/// A read-write mount point below this is scratch: emptied when bound,
/// removed when released, and swept whole before the server first serves
/// (`sweep_scratch`), so nothing a session of an earlier boot left there
/// outlives that boot.
pub const SCRATCH: &[u8] = b"/tmp";
/// Object-record bytes kept back from every session's creations so that
/// a scratch directory can still be made for a new session when the
/// sessions have filled the filesystem (`absd_fs::Fs::set_reserve`): the
/// operator can then get in and delete. Room for every slot's directory.
pub const SCRATCH_RESERVE: usize = 1024;
/// Open files one channel may hold at once.
pub const MAX_OPEN: usize = 64;
/// A file written but not yet committed is committed after this many ticks
/// without a commit (about 200 ms), so an abrupt stop loses at most that.
pub const COMMIT_TICKS: u64 = 200;
/// A wall-clock reading is reused for changes made within this many ticks
/// of it (about 250 ms), so an `mtime` lags the RTC by less than that plus
/// the RTC's own whole second, and a busy server reads the RTC at most
/// four times a second instead of once a request.
pub const CLOCK_TICKS: u64 = 250;

/// What the kernel's `pipe_info` says about one channel's two pipes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipeState {
    /// Bytes waiting in the request pipe.
    pub request_available: u64,
    /// Handles, in every process, that can write the request pipe.
    pub request_writers: u64,
    /// Bytes waiting in the reply pipe (not yet read by any client).
    pub reply_available: u64,
    /// Handles, in every process, that can read the reply pipe.
    pub reply_readers: u64,
}

impl PipeState {
    /// Only the keepers hold client ends.
    fn held_by(self, keepers: u64) -> bool {
        self.request_writers <= keepers && self.reply_readers <= keepers
    }
    /// Only the keepers hold client ends and no reply bytes wait: nothing
    /// from an earlier holder can reach, or be read by, the next one.
    fn quiescent(self, keepers: u64) -> bool {
        self.held_by(keepers) && self.reply_available == 0
    }
}

/// Something the loop should report on the console.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Bound {
        slot: usize,
        spares: Vec<usize>,
        mounts: Vec<Mount>,
    },
    /// A holder other than the keeper, or a reply left unread by one:
    /// something leaked from an earlier session.
    BindRefused {
        slot: usize,
        status: i64,
    },
    /// Refused `BUSY` only because a released channel's work is not yet
    /// consumed (a request still waiting, or its refusal not yet drained):
    /// the loop gets to it, and sshd binds another slot or tries again.
    BindDeferred {
        slot: usize,
    },
    /// `scratch`: objects removed with the session's own scratch
    /// directories (the directories included).
    Released {
        slot: usize,
        closed: usize,
        scratch: usize,
    },
    Derived {
        spare: usize,
        owner: usize,
        mounts: Vec<Mount>,
    },
    DeriveRefused {
        owner: usize,
        status: i64,
    },
    /// sshd's line for the console (`op::NOTICE`), made printable.
    Notice(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Role {
    Unbound,
    Control,
    /// A session's own channel and the spares reserved for its children.
    Session {
        spares: Vec<usize>,
    },
    /// A spare of the session on channel `owner`, bound for one child.
    Spare {
        owner: usize,
        bound: bool,
    },
}

#[derive(Clone, Copy, Debug)]
struct Open {
    fs: u64,
    /// Opened under a read-write mount.
    writable: bool,
    wrote: bool,
}

struct Channel {
    role: Role,
    /// Released (the binding is over), but read on: what the session sent
    /// while its binding was live is its work and is not discarded. Each
    /// request still waiting, and any a process the session left keeps
    /// writing, is read and refused (`-13`), so no holder is left blocked
    /// on a reply, and a length no frame may have is reported as a broken
    /// channel. The reading stops once only the keeper holds the channel.
    /// A release never puts the channel in `resets`: only a bind does.
    draining: bool,
    mounts: Vec<Mount>,
    opens: BTreeMap<u64, Open>,
    next_open: u64,
}

impl Channel {
    fn new(role: Role) -> Self {
        Self {
            role,
            draining: false,
            mounts: Vec::new(),
            opens: BTreeMap::new(),
            next_open: 1,
        }
    }
    /// Whether requests other than control ones are served.
    fn serves(&self) -> bool {
        match self.role {
            Role::Unbound => false,
            Role::Control | Role::Session { .. } => true,
            Role::Spare { bound, .. } => bound,
        }
    }
    /// The longest mount covering `path`. Nothing under the [`HIDDEN`]
    /// roots (`/releases`, `/absd`) is ever covered, whatever the mounts say: the selected tree is reached
    /// only through its binding (`Server::physical`).
    fn mount_for(&self, path: &[u8]) -> Option<&Mount> {
        if hidden(path) {
            return None;
        }
        Self::covering(&self.mounts, path)
    }
    fn covering<'a>(mounts: &'a [Mount], path: &[u8]) -> Option<&'a Mount> {
        mounts
            .iter()
            .filter(|m| within(path, &m.path))
            .max_by_key(|m| m.path.len())
    }
    /// On validated, normalized mount lists, access changes only at a mount
    /// root. Comparing the union of roots therefore covers every path, even
    /// when the child omits a parent's nested read-only carve-out.
    fn narrows(parent: &[Mount], child: &[Mount]) -> bool {
        let access = |mounts: &[Mount], path: &[u8]| {
            Self::covering(mounts, path).map_or(0, |m| if m.writable { 2 } else { 1 })
        };
        parent.iter().chain(child).all(|m| {
            access(child, &m.path) <= access(parent, &m.path)
        })
    }
    /// `path` is a strict ancestor of a mount point: a directory the
    /// client may look at but sees only the way down to its mounts in.
    fn ancestor(&self, path: &[u8]) -> bool {
        !hidden(path)
            && self
                .mounts
                .iter()
                .any(|m| m.path != path && within(&m.path, path))
    }
    fn visible(&self, path: &[u8]) -> bool {
        self.mount_for(path).is_some() || self.ancestor(path)
    }
    /// The mount a mutation of `path` needs: read-write, and `path` not the
    /// mount point itself (a mount point cannot be removed or renamed).
    fn writable_below(&self, path: &[u8]) -> Result<(), i64> {
        match self.mount_for(path) {
            Some(m) if !m.writable => Err(status::READ_ONLY),
            Some(m) if m.path == path => Err(status::BUSY),
            Some(_) => Ok(()),
            None if self.ancestor(path) => Err(status::READ_ONLY),
            None => Err(status::NOT_FOUND),
        }
    }
    /// Removing or replacing a namespace anchor must not relocate a nested
    /// mount into a wider writable mount. Check both endpoints of a rename.
    fn writable_namespace(&self, path: &[u8]) -> Result<(), i64> {
        self.writable_below(path)?;
        if self.ancestor(path) {
            return Err(status::BUSY);
        }
        Ok(())
    }
}

pub fn errno(error: Error) -> i64 {
    match error {
        Error::NotFound => -2,
        Error::Exists => -17,
        Error::NotDir => -20,
        Error::IsDir => -21,
        Error::NotEmpty => -39,
        Error::NoSpace => -28,
        Error::ReadOnlyFs => -30,
        Error::Denied => -13,
        Error::Invalid => -22,
        Error::WouldBlock => -11,
        Error::BadHandle => -9,
        Error::Device(-1) => -1,
        Error::Device(_) => -5,
        Error::Poisoned => -116,
        Error::Unformatted => -2,
        Error::NotBlank => -17,
        Error::Corrupt(_) => -74,
        Error::UnsupportedFormat => status::UNSUPPORTED,
    }
}

fn attr_bytes(frame: Frame, attr: Attr) -> Frame {
    frame
        .u32(match attr.kind {
            Kind::File => 1,
            Kind::Dir => 2,
        })
        .u32(u32::from(attr.readonly))
        .u64(attr.size)
        .u64(attr.fs_id)
        .u64(attr.serial)
        .u64(u64::from(attr.links))
        .u64(attr.mtime)
}

fn reply(result: Result<i64, i64>) -> Vec<u8> {
    match result {
        Ok(value) => Frame::reply(value).finish(),
        Err(code) => Frame::reply(code).finish(),
    }
}

pub struct Server<D: Device> {
    pub fs: Fs<D>,
    channels: Vec<Channel>,
    /// Channels just bound: their buffered and waiting request bytes
    /// predate the binding, and the loop discards them, so nothing an
    /// earlier binding sent runs under the new one. A release adds
    /// nothing here (see `Channel::draining`): it ends a binding, and the
    /// bytes that binding sent are still read and refused or reported.
    pub resets: Vec<usize>,
    pub events: Vec<Event>,
    dirty_since: Option<u64>,
    /// The selected release's id once bound (`bind_release`): `/bin` and
    /// `/share` then resolve under `/releases/<id>/`.
    release: Option<Vec<u8>>,
    /// The last wall-clock reading and the tick it was taken at.
    wall: Option<(u64, Option<u64>)>,
    /// Released channels that have left draining (see [`Server::settled`]).
    settled: u64,
}

impl<D: Device> Server<D> {
    /// Sets the filesystem's clock (`Fs::set_clock`) for what happens next,
    /// at tick `ticks`: `read` is the wall clock (`None` when it is
    /// unavailable or refused), called only when the last reading is
    /// [`CLOCK_TICKS`] old or older, or from a later tick than `ticks`.
    /// The loop calls this before each request and before its own work.
    pub fn clock(&mut self, ticks: u64, read: impl FnOnce() -> Option<u64>) {
        let fresh = match self.wall {
            Some((at, value)) if at <= ticks && ticks - at < CLOCK_TICKS => value,
            _ => {
                let value = read();
                self.wall = Some((ticks, value));
                value
            }
        };
        self.fs.set_clock(fresh);
    }

    /// A server over a writable mount with `slots` client channels after
    /// the control channel, which sees `control` (sshd: `/ssh` and `/bin`
    /// read-only).
    pub fn new(mut fs: Fs<D>, slots: usize, control: Vec<Mount>) -> Self {
        fs.set_reserve(SCRATCH_RESERVE);
        let mut channels = Vec::with_capacity(1 + slots);
        let mut first = Channel::new(Role::Control);
        first.mounts = control;
        channels.push(first);
        for _ in 0..slots {
            channels.push(Channel::new(Role::Unbound));
        }
        Self {
            fs,
            channels,
            resets: Vec::new(),
            events: Vec::new(),
            dirty_since: None,
            release: None,
            wall: None,
            settled: 0,
        }
    }

    /// How many released channels have left draining since the server
    /// started: each channel a RELEASE marks draining is counted once, when
    /// it settles. The loop reports it as `settled_releases`.
    pub fn settled(&self) -> u64 {
        self.settled
    }

    /// Binds `/bin` and `/share` to the release tree `/releases/<id>/`
    /// for the rest of this server's life (`docs/RELEASE.md` section 3,
    /// item 3): once, from the record that passed `release::select`.
    /// Returns false, changing nothing, when a release is already bound.
    pub fn bind_release(&mut self, id: &[u8]) -> bool {
        if self.release.is_some() {
            return false;
        }
        self.release = Some(id.to_vec());
        true
    }

    /// Where a logical path (normalized, already authorized) is stored:
    /// below a bound root, inside the selected tree; anywhere else, the
    /// path itself. Every filesystem call the dispatcher makes on a
    /// client's behalf goes through this.
    pub fn physical(&self, path: &[u8]) -> Vec<u8> {
        if let Some(id) = &self.release
            && BOUND.iter().any(|root| within(path, root))
        {
            return crate::release::tree_path(id, path);
        }
        path.to_vec()
    }

    pub fn channels(&self) -> usize {
        self.channels.len()
    }

    /// Removes everything under the scratch root: what sessions of an
    /// earlier boot left there when the machine reset under them. Before
    /// the server first serves, so no session of this boot has anything
    /// there yet. Returns the objects removed; a missing scratch root is
    /// nothing to sweep.
    pub fn sweep_scratch(&mut self) -> Result<usize, Error> {
        let entries = match self.fs.read_dir(SCRATCH) {
            Ok(entries) => entries,
            Err(Error::NotFound) => return Ok(0),
            Err(error) => return Err(error),
        };
        let mut removed = 0;
        for (name, attr) in entries {
            let mut path = SCRATCH.to_vec();
            path.push(b'/');
            path.extend_from_slice(&name);
            if attr.kind == Kind::Dir {
                removed += self.fs.remove_tree(&path, true)?;
            } else {
                self.fs.unlink(&path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Current file-server table occupancy at one dispatcher boundary:
    /// bound session roles, open file records, and released channels still
    /// draining prior requests.
    pub fn capacity(&self) -> (usize, usize, usize) {
        let bound = self
            .channels
            .iter()
            .filter(|channel| matches!(&channel.role, Role::Session { .. }))
            .count();
        let opens = self
            .channels
            .iter()
            .map(|channel| channel.opens.len())
            .sum();
        let draining = self
            .channels
            .iter()
            .filter(|channel| channel.draining)
            .count();
        (bound, opens, draining)
    }

    /// Whether the loop reads `channel` now: bound, the control channel,
    /// or released and not yet quiet. A released channel with work waiting
    /// is not bound before the loop has consumed it (`bind` answers BUSY),
    /// so what a bind discards is only what nobody sent as that
    /// binding's work.
    pub fn active(&self, channel: usize) -> bool {
        self.channels[channel].serves() || self.channels[channel].draining
    }

    /// Whether `channel` was released and may still have other holders.
    pub fn draining(&self, channel: usize) -> bool {
        self.channels[channel].draining
    }

    /// Stops reading a released channel once only the keeper holds it.
    pub fn settle(&mut self, channel: usize, state: Option<PipeState>) -> bool {
        if self.channels[channel].draining && state.is_some_and(|state| state.quiescent(1)) {
            self.channels[channel].draining = false;
            self.settled = self.settled.saturating_add(1);
            return true;
        }
        false
    }

    /// Commits file data written more than [`COMMIT_TICKS`] ago.
    pub fn idle_commit(&mut self, now: u64) -> Result<bool, Error> {
        match self.dirty_since {
            Some(since) if now.saturating_sub(since) >= COMMIT_TICKS => {
                self.dirty_since = None;
                self.fs.sync()?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Something other than a client wrote the filesystem (the server's
    /// own log): the idle commit covers it like a client's write.
    pub fn note_write(&mut self, now: u64) {
        self.dirty_since.get_or_insert(now);
    }

    /// Commits everything (the server is stopping).
    pub fn sync(&mut self) -> Result<(), Error> {
        self.dirty_since = None;
        self.fs.sync()
    }

    /// Closes every file of `channel` (its framing is lost or its holder
    /// is gone), committing what they wrote. Returns how many it closed.
    pub fn drop_opens(&mut self, channel: usize) -> usize {
        let opens = core::mem::take(&mut self.channels[channel].opens);
        let mut wrote = false;
        for open in opens.values() {
            let _ = self.fs.close(open.fs);
            wrote |= open.wrote;
        }
        if wrote {
            let _ = self.sync();
        }
        opens.len()
    }

    /// Serves one request `body` that arrived on `channel`; returns the
    /// whole reply frame. `pipes` reports a channel's pipe state for the
    /// binding checks.
    pub fn dispatch(
        &mut self,
        channel: usize,
        body: &[u8],
        pipes: &dyn Fn(usize) -> Option<PipeState>,
        now: u64,
    ) -> Vec<u8> {
        let mut reader = Reader(body);
        let Some(code) = reader.u8() else {
            return reply(Err(status::INVALID));
        };
        match code {
            op::BIND | op::RELEASE | op::NOTICE if channel != CONTROL => reply(Err(status::DENIED)),
            op::NOTICE => {
                let text = reader.rest();
                if text.len() > proto::MAX_NOTICE {
                    return reply(Err(status::INVALID));
                }
                let shown = text
                    .iter()
                    .map(|&b| if (0x20..0x7f).contains(&b) { b } else { b'?' })
                    .collect();
                self.events.push(Event::Notice(shown));
                reply(Ok(0))
            }
            op::BIND => {
                let result = self.bind(&mut reader, pipes);
                reply(result)
            }
            op::RELEASE => {
                let result = self.release(&mut reader);
                reply(result)
            }
            // Before anything else a client may ask who serves it, on any
            // channel: the answer is a constant of this build.
            op::VERSION if reader.0.is_empty() => Frame::reply(0)
                .bytes(&crate::version::encode(&crate::version::compiled()))
                .finish(),
            op::VERSION => reply(Err(status::INVALID)),
            _ if !self.channels[channel].serves() => reply(Err(status::DENIED)),
            op::DERIVE => {
                let result = self.derive(channel, &mut reader, pipes);
                if let Err(status) = result {
                    self.events.push(Event::DeriveRefused {
                        owner: channel,
                        status,
                    });
                }
                reply(result)
            }
            op::UNDERIVE => {
                let result = self.underive(channel, &mut reader);
                reply(result)
            }
            op::MOUNTS => Frame::reply(0)
                .mounts(&self.channels[channel].mounts)
                .finish(),
            op::SPACE => {
                let geometry = self.fs.geometry();
                Frame::reply(0)
                    .u32(absd_fs::BLOCK as u32)
                    .u32(geometry.data_blocks)
                    .u32(self.fs.free_blocks())
                    .u32(0)
                    .u64(self.fs.fs_id())
                    .u64(self.fs.sequence())
                    .finish()
            }
            op::COMMIT => match self.sync() {
                Ok(()) => Frame::reply(0).u64(self.fs.sequence()).finish(),
                Err(error) => reply(Err(errno(error))),
            },
            op::READ_AT => self.read_at(channel, &mut reader),
            op::FSTAT | op::STAT => self.stat(channel, code, &mut reader),
            op::READ_DIR => self.read_dir(channel, &mut reader),
            op::CANONICAL => self.canonical(channel, &mut reader),
            _ => {
                let result = self.simple(channel, code, &mut reader, now);
                reply(result)
            }
        }
    }

    fn path(reader: &mut Reader) -> Result<Vec<u8>, i64> {
        normalize(reader.rest()).ok_or(status::INVALID)
    }

    fn open_of(&self, channel: usize, reader: &mut Reader) -> Result<(u64, Open), i64> {
        let handle = reader.u64().ok_or(status::INVALID)?;
        let open = self.channels[channel]
            .opens
            .get(&handle)
            .copied()
            .ok_or(status::BAD_HANDLE)?;
        Ok((handle, open))
    }

    fn simple(
        &mut self,
        channel: usize,
        code: u8,
        reader: &mut Reader,
        now: u64,
    ) -> Result<i64, i64> {
        match code {
            op::OPEN => {
                let flags = reader.u32().ok_or(status::INVALID)?;
                let path = Self::path(reader)?;
                self.open(channel, flags, &path)
            }
            op::CLOSE => {
                let (handle, open) = self.open_of(channel, reader)?;
                self.channels[channel].opens.remove(&handle);
                self.fs.close(open.fs).map_err(errno)?;
                // A file is durable once its writer closes it.
                if open.wrote {
                    self.sync().map_err(errno)?;
                }
                Ok(0)
            }
            op::WRITE_AT => {
                let (handle, open) = self.open_of(channel, reader)?;
                let offset = reader.u64().ok_or(status::INVALID)?;
                let data = reader.rest();
                if data.len() > MAX_IO {
                    return Err(status::INVALID);
                }
                if !open.writable {
                    return Err(status::DENIED);
                }
                let written = self.fs.write_at(open.fs, offset, data).map_err(errno)?;
                self.wrote(channel, handle, now);
                Ok(written as i64)
            }
            op::SET_LEN => {
                let (handle, open) = self.open_of(channel, reader)?;
                let length = reader.u64().ok_or(status::INVALID)?;
                if !open.writable {
                    return Err(status::DENIED);
                }
                self.fs.set_len(open.fs, length).map_err(errno)?;
                self.wrote(channel, handle, now);
                Ok(0)
            }
            op::SYNC => {
                self.open_of(channel, reader)?;
                self.sync().map_err(errno)?;
                Ok(0)
            }
            op::SET_READONLY => {
                let (_, open) = self.open_of(channel, reader)?;
                let flag = reader.u8().ok_or(status::INVALID)?;
                if !open.writable {
                    return Err(status::READ_ONLY);
                }
                self.fs.set_readonly(open.fs, flag != 0).map_err(errno)?;
                Ok(0)
            }
            op::SET_READONLY_PATH => {
                let flag = reader.u8().ok_or(status::INVALID)?;
                let path = Self::path(reader)?;
                self.channels[channel].writable_below(&path)?;
                let path = self.physical(&path);
                self.fs.set_readonly_path(&path, flag != 0).map_err(errno)?;
                Ok(0)
            }
            op::MKDIR | op::RMDIR | op::UNLINK => {
                let path = Self::path(reader)?;
                let target = &self.channels[channel];
                match target.mount_for(&path) {
                    // mkdir of an existing mount point answers as the
                    // filesystem would.
                    Some(m) if code == op::MKDIR && m.path == path && m.writable => {}
                    _ => target.writable_below(&path)?,
                }
                if code == op::RMDIR {
                    target.writable_namespace(&path)?;
                }
                let path = self.physical(&path);
                match code {
                    op::MKDIR => self.fs.mkdir(&path),
                    op::RMDIR => self.fs.rmdir(&path),
                    _ => self.fs.unlink(&path),
                }
                .map_err(errno)?;
                Ok(0)
            }
            op::RENAME => {
                let noreplace = reader.u8().ok_or(status::INVALID)? != 0;
                let length = reader.u16().ok_or(status::INVALID)? as usize;
                let from = normalize(reader.take(length).ok_or(status::INVALID)?)
                    .ok_or(status::INVALID)?;
                let to = Self::path(reader)?;
                let target = &self.channels[channel];
                target.writable_namespace(&from)?;
                target.writable_namespace(&to)?;
                let (from, to) = (self.physical(&from), self.physical(&to));
                self.fs.rename(&from, &to, noreplace).map_err(errno)?;
                Ok(0)
            }
            op::LOCK => {
                let (_, open) = self.open_of(channel, reader)?;
                let mode = reader.u32().ok_or(status::INVALID)?;
                match mode {
                    0 => self.fs.unlock(open.fs),
                    1 => self.fs.try_lock(open.fs, false),
                    2 => self.fs.try_lock(open.fs, true),
                    _ => return Err(status::INVALID),
                }
                .map_err(errno)?;
                Ok(0)
            }
            _ => Err(status::UNSUPPORTED),
        }
    }

    fn wrote(&mut self, channel: usize, handle: u64, now: u64) {
        if let Some(open) = self.channels[channel].opens.get_mut(&handle) {
            open.wrote = true;
        }
        self.dirty_since.get_or_insert(now);
    }

    /// Flags as `std` passes them: 1 read, 2 write, 8 create, 16 create
    /// new, 32 truncate.
    fn open(&mut self, channel: usize, flags: u32, path: &[u8]) -> Result<i64, i64> {
        let flags = OpenFlags {
            read: flags & 1 != 0,
            write: flags & 2 != 0,
            create: flags & 8 != 0,
            create_new: flags & 16 != 0,
            truncate: flags & 32 != 0,
        };
        let wants_write = flags.write || flags.truncate || flags.create || flags.create_new;
        let target = &self.channels[channel];
        let writable = match target.mount_for(path) {
            Some(m) if wants_write && !m.writable => return Err(status::READ_ONLY),
            Some(m) => m.writable,
            None if target.ancestor(path) && !wants_write => false,
            None if target.ancestor(path) => return Err(status::READ_ONLY),
            None => return Err(status::NOT_FOUND),
        };
        if target.opens.len() >= MAX_OPEN {
            return Err(status::TOO_MANY);
        }
        let fs = self.fs.open(&self.physical(path), flags).map_err(errno)?;
        let target = &mut self.channels[channel];
        let handle = target.next_open;
        target.next_open += 1;
        target.opens.insert(
            handle,
            Open {
                fs,
                writable,
                wrote: false,
            },
        );
        Ok(handle as i64)
    }

    fn read_at(&mut self, channel: usize, reader: &mut Reader) -> Vec<u8> {
        let result = (|| {
            let (_, open) = self.open_of(channel, reader)?;
            let offset = reader.u64().ok_or(status::INVALID)?;
            let length = (reader.u32().ok_or(status::INVALID)? as usize).min(MAX_IO);
            let mut buffer = vec![0u8; length];
            let count = self
                .fs
                .read_at(open.fs, offset, &mut buffer)
                .map_err(errno)?;
            buffer.truncate(count);
            Ok(buffer)
        })();
        match result {
            Ok(data) => Frame::reply(data.len() as i64).bytes(&data).finish(),
            Err(code) => reply(Err(code)),
        }
    }

    fn stat(&mut self, channel: usize, code: u8, reader: &mut Reader) -> Vec<u8> {
        let result = if code == op::FSTAT {
            self.open_of(channel, reader)
                .and_then(|(_, open)| self.fs.fstat(open.fs).map_err(errno))
        } else {
            Self::path(reader).and_then(|path| {
                if !self.channels[channel].visible(&path) {
                    return Err(status::NOT_FOUND);
                }
                self.fs.stat(&self.physical(&path)).map_err(errno)
            })
        };
        match result {
            Ok(attr) => attr_bytes(Frame::reply(0), attr).finish(),
            Err(code) => reply(Err(code)),
        }
    }

    fn read_dir(&mut self, channel: usize, reader: &mut Reader) -> Vec<u8> {
        let result = Self::path(reader).and_then(|path| {
            let target = &self.channels[channel];
            let whole = target.mount_for(&path).is_some();
            if !whole && !target.ancestor(&path) {
                return Err(status::NOT_FOUND);
            }
            let mut entries = self.fs.read_dir(&self.physical(&path)).map_err(errno)?;
            if path == b"/" {
                self.bound_roots(&mut entries);
            }
            let mut shown = Vec::new();
            for (name, attr) in entries {
                if !whole {
                    let mut child = if path == b"/" {
                        Vec::new()
                    } else {
                        path.clone()
                    };
                    child.push(b'/');
                    child.extend_from_slice(&name);
                    if !target.visible(&child) {
                        continue;
                    }
                }
                shown.push((name, attr));
            }
            Ok(shown)
        });
        match result {
            Ok(entries) => {
                let mut frame = Frame::reply(entries.len() as i64);
                for (name, attr) in &entries {
                    frame = attr_bytes(frame.u16(name.len() as u16).bytes(name), *attr);
                }
                if frame.0.len() > proto::MAX_BODY {
                    return reply(Err(status::INVALID));
                }
                frame.finish()
            }
            Err(code) => reply(Err(code)),
        }
    }

    /// The root listing as clients see it: `releases` and `absd` never; `bin` and
    /// `share`, when a release is bound, as the selected tree's (whatever
    /// the root itself holds under those names), in name order.
    fn bound_roots(&self, entries: &mut Vec<(Vec<u8>, absd_fs::Attr)>) {
        entries.retain(|(name, _)| !HIDDEN.iter().any(|root| name.as_slice() == &root[1..]));
        if self.release.is_none() {
            return;
        }
        for root in BOUND {
            entries.retain(|(name, _)| name.as_slice() != &root[1..]);
            if let Ok(attr) = self.fs.stat(&self.physical(root)) {
                entries.push((root[1..].to_vec(), attr));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
    }

    fn canonical(&mut self, channel: usize, reader: &mut Reader) -> Vec<u8> {
        let result = Self::path(reader).and_then(|path| {
            if !self.channels[channel].visible(&path) {
                return Err(status::NOT_FOUND);
            }
            // Resolves the stored path; the answer is the logical one
            // (there are no links, so it is the normalized path itself).
            self.fs.canonical(&self.physical(&path)).map_err(errno)?;
            Ok(path)
        });
        match result {
            Ok(path) => Frame::reply(path.len() as i64).bytes(&path).finish(),
            Err(code) => reply(Err(code)),
        }
    }

    fn slot_index(&self, raw: u8) -> Result<usize, i64> {
        let slot = raw as usize;
        if slot == CONTROL || slot >= self.channels.len() {
            return Err(status::INVALID);
        }
        Ok(slot)
    }

    /// Checks a session binding's mounts: normalized, absolute, never `/`,
    /// never touching [`RESERVED`], a [`HIDDEN`] root, or the recovery
    /// state (`recovery::DIR` and its staging directory, which only the
    /// server and sshd's control channel reach), at most [`MAX_MOUNTS`],
    /// no duplicates.
    fn valid_session_mounts(mounts: &[Mount]) -> bool {
        mounts.len() <= MAX_MOUNTS
            && mounts.iter().enumerate().all(|(index, m)| {
                normalize(&m.path).as_deref() == Some(&m.path[..])
                    && m.path != b"/"
                    && !within(&m.path, RESERVED)
                    && !within(RESERVED, &m.path)
                    && !within(&m.path, recovery::DIR)
                    && !within(recovery::DIR, &m.path)
                    && !within(&m.path, recovery::STAGING)
                    && !within(recovery::STAGING, &m.path)
                    && !HIDDEN
                        .iter()
                        .any(|root| within(&m.path, root) || within(root, &m.path))
                    && !mounts[..index].iter().any(|earlier| earlier.path == m.path)
            })
    }

    /// `mkdir -p` for a read-write mount point, with the server's own
    /// authority (the session could not create its own mount point).
    /// Makes `path` and its parents; `reserved` lets a scratch directory
    /// come out of the budget reserve on a full filesystem.
    fn ensure_directory(&mut self, path: &[u8], reserved: bool) -> Result<(), i64> {
        let mut at = Vec::new();
        for part in path.split(|b| *b == b'/').filter(|p| !p.is_empty()) {
            at.push(b'/');
            at.extend_from_slice(part);
            match self.fs.stat(&at) {
                Ok(attr) if attr.kind == Kind::Dir => {}
                Ok(_) => return Err(-20),
                Err(Error::NotFound) if reserved => self.fs.mkdir_reserved(&at).map_err(errno)?,
                Err(Error::NotFound) => self.fs.mkdir(&at).map_err(errno)?,
                Err(error) => return Err(errno(error)),
            }
        }
        Ok(())
    }

    fn bind(
        &mut self,
        reader: &mut Reader,
        pipes: &dyn Fn(usize) -> Option<PipeState>,
    ) -> Result<i64, i64> {
        let slot = self.slot_index(reader.u8().ok_or(status::INVALID)?)?;
        let count = reader.u8().ok_or(status::INVALID)? as usize;
        let mut spares = Vec::with_capacity(count);
        for _ in 0..count {
            let spare = self.slot_index(reader.u8().ok_or(status::INVALID)?)?;
            if spare == slot || spares.contains(&spare) {
                return Err(status::INVALID);
            }
            spares.push(spare);
        }
        let mounts = reader.mounts().ok_or(status::INVALID)?;
        if !reader.0.is_empty() || !Self::valid_session_mounts(&mounts) {
            return Err(status::INVALID);
        }
        let mut deferred = false;
        let result = (|| {
            // The control request writer belongs only to sshd. A queued
            // BIND can outlive sshd, so slot counts alone cannot identify
            // whether their sole holder is the keeper or an old client.
            if !pipes(CONTROL).is_some_and(|state| state.request_writers == 1) {
                return Err(status::BUSY);
            }
            for &channel in core::iter::once(&slot).chain(&spares) {
                if self.channels[channel].role != Role::Unbound {
                    return Err(status::BUSY);
                }
                let Some(state) = pipes(channel) else {
                    return Err(status::BUSY);
                };
                // Only the keeper (the control channel's holder) may hold
                // client ends now: anything an earlier session started is
                // gone.
                if !state.held_by(1) {
                    return Err(status::BUSY);
                }
                // A released channel whose work is not yet consumed: a
                // request its session sent is still to be read and refused,
                // or the refusal is still to be drained. Binding now would
                // discard that work, so the bind waits (BUSY); the loop
                // consumes it within a pass, and sshd takes another slot.
                if self.channels[channel].draining
                    && (state.request_available > 0 || state.reply_available > 0)
                {
                    deferred = true;
                    return Err(status::BUSY);
                }
                // No reply of an earlier holder's is left to be read.
                if !state.quiescent(1) {
                    return Err(status::BUSY);
                }
            }
            Ok(())
        })();
        if let Err(code) = result {
            if deferred {
                self.events.push(Event::BindDeferred { slot });
            } else {
                self.events.push(Event::BindRefused { slot, status: code });
            }
            return Err(code);
        }
        for mount in mounts.iter().filter(|m| m.writable) {
            let scratch = within(&mount.path, SCRATCH) && mount.path != SCRATCH;
            let path = self.physical(&mount.path);
            self.ensure_directory(&path, scratch)?;
            // Scratch starts empty: whatever an earlier binding of the
            // same name left there is gone (an earlier boot's was swept).
            if scratch {
                self.fs.remove_tree(&path, false).map_err(errno)?;
            }
        }
        // Recheck after filesystem preparation, immediately before the
        // role/mount commit. If sshd departed after the earlier samples,
        // an old holder may now be the sole counted slot endpoint. If sshd
        // remains, the <=1 slot samples excluded every old source, and its
        // synchronous BIND wait cannot copy a new endpoint in this gap.
        if !pipes(CONTROL).is_some_and(|state| state.request_writers == 1) {
            self.events.push(Event::BindRefused {
                slot,
                status: status::BUSY,
            });
            return Err(status::BUSY);
        }
        // The new binding starts clean: whatever an earlier binding of
        // these channels sent and was not yet read is discarded by the
        // loop (`resets`), so no request from before this binding runs
        // under it. (A release does the opposite: see `release`.)
        for &spare in &spares {
            self.channels[spare].role = Role::Spare {
                owner: slot,
                bound: false,
            };
            self.reset(spare);
        }
        self.channels[slot].role = Role::Session {
            spares: spares.clone(),
        };
        self.channels[slot].mounts = mounts.clone();
        self.reset(slot);
        // A released channel the bind takes over has settled: the bind
        // checked it quiescent, as `settle` would have. Count it here, or a
        // BIND that reaches a quiet spare before the loop's quiet read loses
        // that channel's settlement.
        for &channel in core::iter::once(&slot).chain(&spares) {
            if self.channels[channel].draining {
                self.channels[channel].draining = false;
                self.settled = self.settled.saturating_add(1);
            }
        }
        self.events.push(Event::Bound {
            slot,
            spares,
            mounts,
        });
        Ok(0)
    }

    /// A new binding of `channel`: its files are closed, its handles start
    /// over, and the loop is asked to discard what predates the binding.
    fn reset(&mut self, channel: usize) {
        self.drop_opens(channel);
        let target = &mut self.channels[channel];
        target.next_open = 1;
        if !self.resets.contains(&channel) {
            self.resets.push(channel);
        }
    }

    fn release(&mut self, reader: &mut Reader) -> Result<i64, i64> {
        let slot = self.slot_index(reader.u8().ok_or(status::INVALID)?)?;
        let Role::Session { spares } = self.channels[slot].role.clone() else {
            return Err(status::INVALID);
        };
        // The session's own scratch (`/tmp/session-N`): gone with the
        // session, so that session names used once do not accumulate.
        let scratch: Vec<Vec<u8>> = self.channels[slot]
            .mounts
            .iter()
            .filter(|m| m.writable && within(&m.path, SCRATCH) && m.path != SCRATCH)
            .map(|m| self.physical(&m.path))
            .collect();
        let mut closed = 0;
        for channel in core::iter::once(slot).chain(spares) {
            closed += self.channels[channel].opens.len();
            // Not `reset`: a release ends the binding but discards nothing
            // the binding sent. Bytes already on the channel are still
            // read and answered as the channel now stands (refused, `-13`)
            // or reported as a framing break, so a holder is never left
            // waiting on a request that was dropped, and the channel
            // quiesces only after that. Only a new binding (`bind`)
            // discards what predates it.
            self.drop_opens(channel);
            let target = &mut self.channels[channel];
            target.next_open = 1;
            target.role = Role::Unbound;
            target.mounts.clear();
            target.draining = true;
        }
        // Every open on the session's channels was dropped above; whatever
        // the session left can no longer reach the tree. One commit
        // however many files the session made, so the release (which sshd
        // waits for) costs what one namespace operation costs. A missing
        // scratch tree is harmless; a real cleanup failure must be reported
        // so sshd cannot reuse this channel as though release succeeded.
        let mut removed = 0;
        for path in scratch {
            match self.fs.remove_tree(&path, true) {
                Ok(count) => removed += count,
                Err(Error::NotFound) => {}
                Err(error) => return Err(errno(error)),
            }
        }
        self.events.push(Event::Released {
            slot,
            closed,
            scratch: removed,
        });
        Ok(closed as i64)
    }

    fn spare_of(&self, channel: usize, reader: &mut Reader) -> Result<usize, i64> {
        let Role::Session { spares } = &self.channels[channel].role else {
            return Err(status::DENIED);
        };
        let index = reader.u8().ok_or(status::INVALID)? as usize;
        index
            .checked_sub(1)
            .and_then(|at| spares.get(at))
            .copied()
            .ok_or(status::INVALID)
    }

    fn derive(
        &mut self,
        channel: usize,
        reader: &mut Reader,
        pipes: &dyn Fn(usize) -> Option<PipeState>,
    ) -> Result<i64, i64> {
        let spare = self.spare_of(channel, reader)?;
        let how = reader.u8().ok_or(status::INVALID)?;
        let parent = &self.channels[channel].mounts;
        let mounts: Vec<Mount> = match how {
            derive::SAME => parent.clone(),
            derive::READ_ONLY => parent.iter().map(|m| Mount::new(&m.path, false)).collect(),
            derive::LIST => {
                let asked = reader.mounts().ok_or(status::INVALID)?;
                if !Self::valid_session_mounts(&asked) {
                    return Err(status::INVALID);
                }
                // Compare effective longest-prefix authority, not individual
                // entries: an outer writable mount cannot erase a carve-out.
                if !Channel::narrows(parent, &asked) {
                    return Err(status::DENIED);
                }
                asked
            }
            _ => return Err(status::INVALID),
        };
        if !reader.0.is_empty() {
            return Err(status::INVALID);
        }
        // The keepers of a spare are the control channel's holder and the
        // session's own process; an earlier child (and anything it
        // started) must be gone, and its last reply read.
        if !pipes(spare).is_some_and(|state| state.quiescent(2)) {
            return Err(status::BUSY);
        }
        self.reset(spare);
        self.channels[spare].role = Role::Spare {
            owner: channel,
            bound: true,
        };
        self.channels[spare].mounts = mounts.clone();
        self.events.push(Event::Derived {
            spare,
            owner: channel,
            mounts,
        });
        Ok(0)
    }

    fn underive(&mut self, channel: usize, reader: &mut Reader) -> Result<i64, i64> {
        let spare = self.spare_of(channel, reader)?;
        let closed = self.channels[spare].opens.len();
        self.drop_opens(spare);
        self.channels[spare].role = Role::Spare {
            owner: channel,
            bound: false,
        };
        self.channels[spare].mounts.clear();
        Ok(closed as i64)
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;

    #[test]
    fn narrowing_matches_bounded_path_permission_sets() {
        let roots: [&[u8]; 5] = [
            b"/home/operator", b"/home/operator/a", b"/home/operator/a/b",
            b"/home/operator/a/b/c", b"/home/operator/ab",
        ];
        // Include each boundary, the intervening subtree, a byte-prefix
        // sibling and an inaccessible path. None/read/write at five roots
        // gives 243 lists and 59,049 ordered parent/child comparisons.
        let witnesses: [&[u8]; 11] = [
            b"/home/operator", b"/home/operator/other", b"/home/operator/a",
            b"/home/operator/a/other", b"/home/operator/a/b",
            b"/home/operator/a/b/other", b"/home/operator/a/b/c",
            b"/home/operator/a/b/c/leaf", b"/home/operator/ab",
            b"/home/operator/ab/leaf", b"/outside",
        ];
        let mut cases = Vec::new();
        for mut code in 0..3usize.pow(roots.len() as u32) {
            let mut mounts = Vec::new();
            for root in roots {
                match code % 3 {
                    1 => mounts.push(Mount::new(root, false)),
                    2 => mounts.push(Mount::new(root, true)),
                    _ => {}
                }
                code /= 3;
            }
            // Independent reference: apply overlays from broadest to
            // narrowest to concrete read/write permission sets.
            mounts.sort_by_key(|m| m.path.len());
            let (mut read, mut write) = (0u16, 0u16);
            for mount in &mounts {
                for (i, path) in witnesses.iter().enumerate() {
                    if within(path, &mount.path) {
                        read |= 1 << i;
                        if mount.writable { write |= 1 << i; } else { write &= !(1 << i); }
                    }
                }
            }
            cases.push((mounts, read, write));
        }
        assert_eq!(cases.len(), 243);
        for (parent, pr, pw) in &cases {
            for (child, cr, cw) in &cases {
                let subset = cr & !pr == 0 && cw & !pw == 0;
                assert_eq!(Channel::narrows(parent, child), subset,
                    "parent={parent:?}, child={child:?}");
            }
        }
    }
}
