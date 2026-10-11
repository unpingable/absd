//! Wire formats of ABSD's init-brokered spawning (the kernel repository's
//! `docs/BROKER.md`): the startup record a program reads from `handles[0]`
//! when its startup vector has five or more handles, the request a worker
//! writes to init, and the fixed 24-byte replies init writes back. The
//! startup record is also what a parent that holds the spawn right writes
//! for a child it starts from a filesystem image (kernel
//! `docs/PROCESS-STARTUP.md`), with its optional working-directory section.
//!
//! Everything here is pure and allocation-free so the runtime can use it
//! before its allocator is trusted and the host can test it exhaustively.
//! Parsing is strict: anything the format does not name exactly is refused.

#![no_std]

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

pub const STARTUP_MAGIC: &[u8; 8] = b"ABSDSU01";
pub const REQUEST_MAGIC: &[u8; 8] = b"ABSDBR01";
pub const REPLY_MAGIC: &[u8; 8] = b"ABSDBP01";

/// Fewest handles in a startup vector that carries a startup record; two
/// and four remain the older fixed shapes.
pub const MIN_RECORD_HANDLES: usize = 5;
/// Slots a worker can be given (K in the specification).
pub const MAX_SLOTS: usize = 8;
/// File server channels a startup record may name (kernel
/// `docs/PROCESS-STARTUP.md`, "File server"): a server's control channel
/// and its client slots, or a client's own channel and its spares.
pub const MAX_CHANNELS: usize = 16;
/// Largest argv a request or startup record may carry.
pub const MAX_ARGC: usize = 32;
/// Largest request, in bytes.
pub const MAX_REQUEST: usize = 4096;
/// Bounds of the startup record's optional environment section.
pub const MAX_ENVC: usize = 32;
pub const MAX_ENV_ENTRY: usize = 1024;
/// Longest working directory the startup record carries.
pub const MAX_CWD: usize = 1024;
/// Largest startup record this runtime will read. A record carries at most
/// the roles of a full vector and one request's argv, so this is generous.
pub const MAX_STARTUP: usize = 8192;
pub const REPLY_BYTES: usize = 24;

pub const REQUEST_SPAWN: u8 = 1;

pub mod role {
    pub const STDIN: u8 = 1;
    /// The stdout pipe's write end, the same pipe the console handle is.
    pub const STDOUT: u8 = 2;
    pub const STDERR: u8 = 3;
    pub const BLOCK: u8 = 4;
    pub const STEP: u8 = 5;
    pub const REQUEST: u8 = 6;
    pub const REPLY: u8 = 7;
    pub const SLOT_STDIN: u8 = 8;
    pub const SLOT_STDOUT: u8 = 9;
    pub const SLOT_STDERR: u8 = 10;
    /// A block handle the runtime mounts read-only as this process's view
    /// of the filesystem before `main` (a child started from an image).
    pub const FS: u8 = 11;
    /// The network interface handle (kernel `docs/NETWORK.md`).
    pub const NIC: u8 = 12;
    /// One file server channel's request pipe and reply pipe. A client
    /// holds the request write end and the reply read end, the server the
    /// opposite ends. Channels are the pairs in record order; a client's
    /// first channel is its own, later ones are spares it may hand on.
    pub const FS_REQUEST: u8 = 13;
    pub const FS_REPLY: u8 = 14;
    /// A machine handle (kernel `SYS_MACHINE_STOP`): init copies one, with
    /// the stop right only, to a qualification durable worker, never in a
    /// served boot, and no parent here hands one on.
    pub const MACHINE: u8 = 15;
    /// A session control channel (kernel `docs/PROCESS-STARTUP.md`,
    /// "Session control"): sshd creates one per interactive session before
    /// it starts the session's shell, and gives the shell the read end of
    /// the events pipe (sshd to the shell: ^C, replies) and the write end
    /// of the requests pipe (the shell to sshd). They come together or not
    /// at all, and no process passes them on.
    pub const SESSION_EVENTS: u8 = 16;
    pub const SESSION_REQUESTS: u8 = 17;
}

pub mod reply {
    pub const STARTED: u8 = 1;
    pub const REFUSED: u8 = 2;
    pub const EXITED: u8 = 3;
}

/// REFUSED codes.
pub mod refusal {
    pub const NOT_PERMITTED: u32 = 1;
    pub const SLOT_UNAVAILABLE: u32 = 2;
    pub const MALFORMED: u32 = 3;
    pub const NO_RESOURCES: u32 = 4;
}

/// EXITED values below zero: killed is -1, a fault is -1000 - vector.
pub const OUTCOME_KILLED: i64 = -1;
pub const OUTCOME_FAULT_BASE: i64 = -1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

/// Positions in the startup vector of one slot's three worker-side ends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotIndexes {
    pub stdin: usize,
    pub stdout: usize,
    pub stderr: usize,
}

/// Positions in the startup vector of one file server channel's ends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelIndexes {
    pub request: usize,
    pub reply: usize,
}

/// A validated startup record. Indexes are positions in the startup vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Startup<'a> {
    pub stdin: Option<usize>,
    pub stdout: Option<usize>,
    pub stderr: Option<usize>,
    pub block: Option<usize>,
    pub fs: Option<usize>,
    pub step: Option<usize>,
    pub request: Option<usize>,
    pub reply: Option<usize>,
    pub nic: Option<usize>,
    pub machine: Option<usize>,
    pub session_events: Option<usize>,
    pub session_requests: Option<usize>,
    pub slots: [SlotIndexes; MAX_SLOTS],
    pub slot_count: usize,
    pub channels: [ChannelIndexes; MAX_CHANNELS],
    pub channel_count: usize,
    pub argc: usize,
    args: &'a [u8],
    pub envc: usize,
    env: &'a [u8],
    /// The working directory: absolute, without NUL; empty when the record
    /// has no working-directory section (then it is `/`).
    pub cwd: &'a [u8],
    /// The program name (`argv[0]`), only after a working directory; empty
    /// when absent (then the runtime uses the name fixed at build time).
    pub name: &'a [u8],
}

impl<'a> Startup<'a> {
    /// The runtime arguments, in order, without a program name.
    pub fn args(&self) -> Args<'a> {
        Args { rest: self.args, left: self.argc }
    }

    /// The policy-given environment as `KEY=VALUE` entries (validated: the
    /// key before the first `=` is non-empty and unique).
    pub fn env(&self) -> Args<'a> {
        Args { rest: self.env, left: self.envc }
    }
}

/// Splits a validated `KEY=VALUE` entry at its first `=`.
pub fn split_env(entry: &[u8]) -> (&[u8], &[u8]) {
    match entry.iter().position(|&byte| byte == b'=') {
        Some(at) => (&entry[..at], &entry[at + 1..]),
        None => (entry, &[]),
    }
}

/// Length-prefixed arguments already validated by the parser.
#[derive(Clone)]
pub struct Args<'a> {
    rest: &'a [u8],
    left: usize,
}

impl<'a> Iterator for Args<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.left == 0 {
            return None;
        }
        let mut reader = Reader(self.rest);
        let length = reader.u16().ok()? as usize;
        let bytes = reader.take(length).ok()?;
        self.rest = reader.0;
        self.left -= 1;
        Some(bytes)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Malformed> {
        if self.0.len() < count {
            return Err(Malformed);
        }
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Malformed> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
    /// `count` x `{u16 length, bytes}`, none containing NUL (argv strings are
    /// NUL-terminated for `main`). Returns the covered region.
    fn argv(&mut self, count: usize) -> Result<&'a [u8], Malformed> {
        let start = self.0;
        let mut used = 0usize;
        for _ in 0..count {
            let length = self.u16()? as usize;
            if self.take(length)?.contains(&0) {
                return Err(Malformed);
            }
            used += 2 + length;
        }
        Ok(&start[..used])
    }
}

/// Validates a startup record for a vector of `handle_count` handles.
///
/// Index 0 is the startup pipe and the last index the console, so roles name
/// only the positions between them, and every one of those positions must
/// carry exactly one role: a vector that does not match its record is
/// refused rather than guessed at. Single roles appear at most once; slot
/// roles form complete triples, at most [`MAX_SLOTS`] of them; a slot needs
/// the request and reply channel, and request and reply come together.
pub fn parse_startup(record: &[u8], handle_count: usize) -> Result<Startup<'_>, Malformed> {
    if handle_count < MIN_RECORD_HANDLES || handle_count > 64 || record.len() > MAX_STARTUP {
        return Err(Malformed);
    }
    let mut reader = Reader(record);
    if reader.take(8)? != STARTUP_MAGIC {
        return Err(Malformed);
    }
    let mut startup = Startup {
        stdin: None,
        stdout: None,
        stderr: None,
        block: None,
        fs: None,
        step: None,
        request: None,
        reply: None,
        nic: None,
        machine: None,
        session_events: None,
        session_requests: None,
        slots: [SlotIndexes::default(); MAX_SLOTS],
        slot_count: 0,
        channels: [ChannelIndexes::default(); MAX_CHANNELS],
        channel_count: 0,
        argc: 0,
        args: &[],
        envc: 0,
        env: &[],
        cwd: &[],
        name: &[],
    };
    let mut assigned = 0u64;
    let mut slot_ends = [0usize; 3];
    let mut channel_ends = [0usize; 2];
    let role_count = reader.u16()? as usize;
    for _ in 0..role_count {
        let role = reader.u8()?;
        let index = reader.u8()? as usize;
        if index == 0 || index >= handle_count - 1 || assigned & (1 << index) != 0 {
            return Err(Malformed);
        }
        assigned |= 1 << index;
        let single = match role {
            role::STDIN => &mut startup.stdin,
            role::STDOUT => &mut startup.stdout,
            role::STDERR => &mut startup.stderr,
            role::BLOCK => &mut startup.block,
            role::FS => &mut startup.fs,
            role::STEP => &mut startup.step,
            role::REQUEST => &mut startup.request,
            role::REPLY => &mut startup.reply,
            role::NIC => &mut startup.nic,
            role::MACHINE => &mut startup.machine,
            role::SESSION_EVENTS => &mut startup.session_events,
            role::SESSION_REQUESTS => &mut startup.session_requests,
            role::SLOT_STDIN | role::SLOT_STDOUT | role::SLOT_STDERR => {
                let end = (role - role::SLOT_STDIN) as usize;
                let slot = slot_ends[end];
                if slot >= MAX_SLOTS {
                    return Err(Malformed);
                }
                let place = &mut startup.slots[slot];
                match end {
                    0 => place.stdin = index,
                    1 => place.stdout = index,
                    _ => place.stderr = index,
                }
                slot_ends[end] += 1;
                continue;
            }
            role::FS_REQUEST | role::FS_REPLY => {
                let end = (role - role::FS_REQUEST) as usize;
                let channel = channel_ends[end];
                if channel >= MAX_CHANNELS {
                    return Err(Malformed);
                }
                let place = &mut startup.channels[channel];
                if end == 0 {
                    place.request = index;
                } else {
                    place.reply = index;
                }
                channel_ends[end] += 1;
                continue;
            }
            _ => return Err(Malformed),
        };
        if single.replace(index).is_some() {
            return Err(Malformed);
        }
    }
    // Every position between the startup pipe and the console is named.
    let expected = ((1u64 << (handle_count - 1)) - 1) & !1;
    if assigned != expected {
        return Err(Malformed);
    }
    if slot_ends[0] != slot_ends[1] || slot_ends[1] != slot_ends[2] {
        return Err(Malformed);
    }
    startup.slot_count = slot_ends[0];
    if channel_ends[0] != channel_ends[1] {
        return Err(Malformed);
    }
    startup.channel_count = channel_ends[0];
    if startup.session_events.is_some() != startup.session_requests.is_some() {
        return Err(Malformed);
    }
    if startup.request.is_some() != startup.reply.is_some()
        || (startup.slot_count > 0 && startup.request.is_none())
    {
        return Err(Malformed);
    }
    let argc = reader.u16()? as usize;
    if argc > MAX_ARGC {
        return Err(Malformed);
    }
    startup.argc = argc;
    startup.args = reader.argv(argc)?;
    // Optional environment: absent (the record ends here) is empty.
    if !reader.0.is_empty() {
        let envc = reader.u16()? as usize;
        if envc > MAX_ENVC {
            return Err(Malformed);
        }
        let env = reader.argv(envc)?;
        let entries = Args { rest: env, left: envc };
        for (position, entry) in entries.clone().enumerate() {
            let (key, _) = split_env(entry);
            if entry.len() > MAX_ENV_ENTRY || key.is_empty() || key.len() == entry.len() {
                return Err(Malformed);
            }
            if entries.clone().take(position).any(|earlier| split_env(earlier).0 == key) {
                return Err(Malformed);
            }
        }
        startup.envc = envc;
        startup.env = env;
    }
    // Optional working directory, only after an environment section.
    if !reader.0.is_empty() {
        let length = reader.u16()? as usize;
        let cwd = reader.take(length)?;
        if !valid_cwd(cwd) {
            return Err(Malformed);
        }
        startup.cwd = cwd;
    }
    // Optional program name, only after a working directory.
    if !reader.0.is_empty() {
        let length = reader.u16()? as usize;
        let name = reader.take(length)?;
        if name.is_empty() || name.len() > MAX_CWD || name.contains(&0) {
            return Err(Malformed);
        }
        startup.name = name;
    }
    // A filesystem comes either as a read-only view or through a file
    // server, never both.
    if startup.fs.is_some() && startup.channel_count > 0 {
        return Err(Malformed);
    }
    if startup.block.is_some() && startup.fs.is_some() {
        return Err(Malformed);
    }
    if !reader.0.is_empty() {
        return Err(Malformed);
    }
    Ok(startup)
}

/// A working directory the record may carry: absolute, at most
/// [`MAX_CWD`] bytes, no NUL, no empty, `.` or `..` component (a trailing
/// `/` only for the root itself).
pub fn valid_cwd(cwd: &[u8]) -> bool {
    if cwd.is_empty() || cwd.len() > MAX_CWD || cwd[0] != b'/' || cwd.contains(&0) {
        return false;
    }
    cwd == b"/"
        || cwd[1..]
            .split(|&byte| byte == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}

/// Encodes a startup record: `roles` as `(role, vector index)`, the
/// arguments (without a program name), the environment as `KEY=VALUE`
/// entries, the working directory, and the program name (each empty: no
/// section; a name needs a working directory). The encoding
/// is checked by [`parse_startup`] for a vector of `handle_count` handles
/// before it is returned, so a record this writes is one a child accepts.
pub fn encode_startup<'b>(
    roles: &[(u8, u8)],
    args: impl IntoIterator<Item = &'b [u8]>,
    env: impl IntoIterator<Item = &'b [u8]>,
    cwd: &[u8],
    name: &[u8],
    handle_count: usize,
    out: &mut [u8],
) -> Result<usize, RequestError> {
    if !name.is_empty() && cwd.is_empty() {
        return Err(RequestError::Invalid);
    }
    let mut writer = Writer { out, used: 0, limit: MAX_STARTUP };
    writer.put(STARTUP_MAGIC)?;
    let role_count = u16::try_from(roles.len()).map_err(|_| RequestError::TooLarge)?;
    writer.put(&role_count.to_le_bytes())?;
    for &(role, index) in roles {
        writer.put(&[role, index])?;
    }
    for (section, list) in [(0, args.into_iter().collect::<Collected<'b>>()), (1, env.into_iter().collect())] {
        let count_at = writer.used;
        writer.put(&[0, 0])?;
        let mut count = 0usize;
        for item in list.iter() {
            count += 1;
            if count > if section == 0 { MAX_ARGC } else { MAX_ENVC } {
                return Err(RequestError::TooManyArguments);
            }
            writer.string(item)?;
        }
        writer.out[count_at..count_at + 2].copy_from_slice(&(count as u16).to_le_bytes());
    }
    if !cwd.is_empty() {
        writer.string(cwd)?;
    }
    if !name.is_empty() {
        writer.string(name)?;
    }
    let used = writer.used;
    parse_startup(&writer.out[..used], handle_count).map_err(|_| RequestError::Invalid)?;
    Ok(used)
}

/// A bounded, allocation-free collection of borrowed items for the encoder.
struct Collected<'b> {
    items: [&'b [u8]; MAX_ARGC],
    count: usize,
    overflow: bool,
}

impl<'b> FromIterator<&'b [u8]> for Collected<'b> {
    fn from_iter<I: IntoIterator<Item = &'b [u8]>>(iter: I) -> Self {
        let mut collected = Collected { items: [&[]; MAX_ARGC], count: 0, overflow: false };
        for item in iter {
            if collected.count == MAX_ARGC {
                collected.overflow = true;
                break;
            }
            collected.items[collected.count] = item;
            collected.count += 1;
        }
        collected
    }
}

impl<'b> Collected<'b> {
    /// The items, then one more (an empty one) if the input overflowed, so
    /// the caller's bound check sees the overflow.
    fn iter(&self) -> impl Iterator<Item = &'b [u8]> + '_ {
        self.items[..self.count]
            .iter()
            .copied()
            .chain(self.overflow.then_some(&[][..]))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// Empty path, or a NUL byte in the path or an argument.
    Invalid,
    TooManyArguments,
    TooLarge,
}

struct Writer<'a> {
    out: &'a mut [u8],
    used: usize,
    limit: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), RequestError> {
        let end = self.used.checked_add(bytes.len()).ok_or(RequestError::TooLarge)?;
        if end > self.out.len() || end > self.limit {
            return Err(RequestError::TooLarge);
        }
        self.out[self.used..end].copy_from_slice(bytes);
        self.used = end;
        Ok(())
    }
    fn string(&mut self, bytes: &[u8]) -> Result<(), RequestError> {
        if bytes.contains(&0) {
            return Err(RequestError::Invalid);
        }
        let length = u16::try_from(bytes.len()).map_err(|_| RequestError::TooLarge)?;
        self.put(&length.to_le_bytes())?;
        self.put(bytes)
    }
}

/// Encodes one spawn request into `out`, returning its length.
pub fn encode_request<'b>(
    slot: u8,
    path: &[u8],
    args: impl IntoIterator<Item = &'b [u8]>,
    out: &mut [u8],
) -> Result<usize, RequestError> {
    if path.is_empty() {
        return Err(RequestError::Invalid);
    }
    let mut writer = Writer { out, used: 0, limit: MAX_REQUEST };
    writer.put(REQUEST_MAGIC)?;
    writer.put(&[REQUEST_SPAWN, slot])?;
    writer.string(path)?;
    let count_at = writer.used;
    writer.put(&[0, 0])?;
    let mut argc = 0usize;
    for arg in args {
        argc += 1;
        if argc > MAX_ARGC {
            return Err(RequestError::TooManyArguments);
        }
        writer.string(arg)?;
    }
    writer.out[count_at..count_at + 2].copy_from_slice(&(argc as u16).to_le_bytes());
    Ok(writer.used)
}

/// A decoded request (init's side; here for round-trip tests and as the
/// reference reading of the format).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub slot: u8,
    pub path: &'a [u8],
    pub argc: usize,
    args: &'a [u8],
}

impl<'a> Request<'a> {
    pub fn args(&self) -> Args<'a> {
        Args { rest: self.args, left: self.argc }
    }
}

pub fn decode_request(bytes: &[u8]) -> Result<Request<'_>, Malformed> {
    if bytes.len() > MAX_REQUEST {
        return Err(Malformed);
    }
    let mut reader = Reader(bytes);
    if reader.take(8)? != REQUEST_MAGIC || reader.u8()? != REQUEST_SPAWN {
        return Err(Malformed);
    }
    let slot = reader.u8()?;
    let path_length = reader.u16()? as usize;
    let path = reader.take(path_length)?;
    if path.is_empty() || path.contains(&0) {
        return Err(Malformed);
    }
    let argc = reader.u16()? as usize;
    if argc > MAX_ARGC {
        return Err(Malformed);
    }
    let args = reader.argv(argc)?;
    if !reader.0.is_empty() {
        return Err(Malformed);
    }
    Ok(Request { slot, path, argc, args })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub kind: u8,
    pub slot: u8,
    pub code: u32,
    pub value: u64,
}

pub fn decode_reply(bytes: &[u8; REPLY_BYTES]) -> Result<Reply, Malformed> {
    if &bytes[..8] != REPLY_MAGIC || bytes[10] != 0 || bytes[11] != 0 {
        return Err(Malformed);
    }
    let kind = bytes[8];
    if !matches!(kind, reply::STARTED | reply::REFUSED | reply::EXITED) {
        return Err(Malformed);
    }
    let mut code = [0u8; 4];
    code.copy_from_slice(&bytes[12..16]);
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[16..24]);
    Ok(Reply {
        kind,
        slot: bytes[9],
        code: u32::from_le_bytes(code),
        value: u64::from_le_bytes(value),
    })
}

pub fn encode_reply(reply: Reply) -> [u8; REPLY_BYTES] {
    let mut bytes = [0u8; REPLY_BYTES];
    bytes[..8].copy_from_slice(REPLY_MAGIC);
    bytes[8] = reply.kind;
    bytes[9] = reply.slot;
    bytes[12..16].copy_from_slice(&reply.code.to_le_bytes());
    bytes[16..24].copy_from_slice(&reply.value.to_le_bytes());
    bytes
}

/// What the worker knows about one slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Unspent,
    /// A request is outstanding; its STARTED or REFUSED has not arrived.
    Requested,
    /// REFUSED arrived and the spawner has not yet taken it.
    Refused(u32),
    Started { pid: u64 },
    Exited { pid: u64, value: i64 },
    /// Init said the slot is unavailable: never ask for it again.
    Lost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BookError {
    /// A malformed reply, or one that contradicts the slot's state. The
    /// channel is no longer trusted.
    Protocol,
    /// The slot was not requested, or its outcome was already taken.
    NotPending,
}

/// The worker's demultiplexer: replies arrive as a byte stream in any slot
/// order, and each is filed against its slot until someone asks for it.
#[derive(Clone, Debug)]
pub struct Book {
    states: [SlotState; MAX_SLOTS],
    slots: usize,
    partial: [u8; REPLY_BYTES],
    partial_length: usize,
    poisoned: bool,
}

impl Book {
    pub const fn new(slots: usize) -> Self {
        let slots = if slots > MAX_SLOTS { MAX_SLOTS } else { slots };
        Self {
            states: [SlotState::Unspent; MAX_SLOTS],
            slots,
            partial: [0; REPLY_BYTES],
            partial_length: 0,
            poisoned: false,
        }
    }

    pub fn slot_count(&self) -> usize {
        self.slots
    }

    pub fn state(&self, slot: usize) -> Option<SlotState> {
        (slot < self.slots).then(|| self.states[slot])
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// The lowest slot never started and not lost.
    pub fn next_unspent(&self) -> Option<usize> {
        (0..self.slots).find(|&slot| self.states[slot] == SlotState::Unspent)
    }

    pub fn mark_requested(&mut self, slot: usize) -> Result<(), BookError> {
        if self.poisoned {
            return Err(BookError::Protocol);
        }
        if slot >= self.slots || self.states[slot] != SlotState::Unspent {
            return Err(BookError::NotPending);
        }
        self.states[slot] = SlotState::Requested;
        Ok(())
    }

    /// Files every complete reply in `bytes`, keeping a trailing fragment.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), BookError> {
        if self.poisoned {
            return Err(BookError::Protocol);
        }
        for &byte in bytes {
            self.partial[self.partial_length] = byte;
            self.partial_length += 1;
            if self.partial_length == REPLY_BYTES {
                self.partial_length = 0;
                let frame = self.partial;
                if self.file(&frame).is_err() {
                    self.poisoned = true;
                    return Err(BookError::Protocol);
                }
            }
        }
        Ok(())
    }

    fn file(&mut self, frame: &[u8; REPLY_BYTES]) -> Result<(), Malformed> {
        let reply = decode_reply(frame)?;
        let slot = reply.slot as usize;
        if slot >= self.slots {
            return Err(Malformed);
        }
        let state = &mut self.states[slot];
        *state = match (reply.kind, *state) {
            (reply::STARTED, SlotState::Requested) if reply.code == 0 => {
                SlotState::Started { pid: reply.value }
            }
            (reply::REFUSED, SlotState::Requested) if reply.value == 0 && reply.code != 0 => {
                SlotState::Refused(reply.code)
            }
            (reply::EXITED, SlotState::Started { pid }) if reply.code == 0 => {
                SlotState::Exited { pid, value: reply.value as i64 }
            }
            _ => return Err(Malformed),
        };
        Ok(())
    }

    /// The answer to the slot's request, once it has arrived: `Ok(pid)` for
    /// STARTED, `Err(code)` for REFUSED. A refusal spends nothing, so the
    /// slot returns to unspent (except "slot unavailable", after which it is
    /// never asked for again). `None` while the answer is still outstanding.
    pub fn take_spawn(&mut self, slot: usize) -> Result<Option<Result<u64, u32>>, BookError> {
        if self.poisoned {
            return Err(BookError::Protocol);
        }
        match self.state(slot) {
            Some(SlotState::Requested) => Ok(None),
            Some(SlotState::Started { pid }) | Some(SlotState::Exited { pid, .. }) => {
                Ok(Some(Ok(pid)))
            }
            Some(SlotState::Refused(code)) => {
                self.states[slot] = if code == refusal::SLOT_UNAVAILABLE {
                    SlotState::Lost
                } else {
                    SlotState::Unspent
                };
                Ok(Some(Err(code)))
            }
            _ => Err(BookError::NotPending),
        }
    }

    /// The slot's EXITED value once it has arrived.
    pub fn exit_value(&self, slot: usize) -> Result<Option<i64>, BookError> {
        if self.poisoned {
            return Err(BookError::Protocol);
        }
        match self.state(slot) {
            Some(SlotState::Started { .. }) => Ok(None),
            Some(SlotState::Exited { value, .. }) => Ok(Some(value)),
            _ => Err(BookError::NotPending),
        }
    }
}
