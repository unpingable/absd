//! Wire formats of init-brokered spawning (docs/BROKER.md): the startup
//! record, the requester's request, and init's fixed-size reply.

pub const STARTUP_MAGIC: &[u8; 8] = b"ABSDSU01";
pub const REQUEST_MAGIC: &[u8; 8] = b"ABSDBR01";
pub const REPLY_MAGIC: &[u8; 8] = b"ABSDBP01";

pub const ROLE_STDIN: u8 = 1;
/// A second handle to the stdout pipe, which is also the console.
pub const ROLE_STDOUT: u8 = 2;
pub const ROLE_STDERR: u8 = 3;
pub const ROLE_BLOCK: u8 = 4;
pub const ROLE_STEP: u8 = 5;
pub const ROLE_REQUEST: u8 = 6;
pub const ROLE_REPLY: u8 = 7;
pub const ROLE_SLOT_STDIN: u8 = 8;
pub const ROLE_SLOT_STDOUT: u8 = 9;
pub const ROLE_SLOT_STDERR: u8 = 10;
/// The network interface (docs/NETWORK.md): read and write rights.
pub const ROLE_NIC: u8 = 12;
/// A file server channel (docs/PROCESS-STARTUP.md, "File server"): the
/// request pipe and the reply pipe. A client holds the request pipe's
/// write end and the reply pipe's read end; the server the opposite ends.
/// Channels are the pairs in record order; a client's first is its own.
pub const ROLE_FS_REQUEST: u8 = 13;
pub const ROLE_FS_REPLY: u8 = 14;
/// A machine handle (kernel `SYS_MACHINE_STOP`): init copies one, with the
/// stop right only, to a qualification durable worker, never in a served
/// boot.
pub const ROLE_MACHINE: u8 = 15;
// Roles 16 and 17 are the platform's session control channels (sshd to
// its session children); init never writes them.
/// A served service's liveness cell (docs/service-lifecycle-20261008/
/// LIVENESS.md): init creates one cell per essential service (the file
/// server, sshd) in a served boot and copies it with read and write rights;
/// the service transitions it once per loop pass, and init treats a cell
/// unchanged for `program::SERVED_LIVENESS_TICKS` after readiness as that
/// service's fault. Never present outside a served boot.
pub const ROLE_LIVENESS: u8 = 18;

pub const REQUEST_SPAWN: u8 = 1;
pub const REPLY_STARTED: u8 = 1;
pub const REPLY_REFUSED: u8 = 2;
pub const REPLY_EXITED: u8 = 3;

pub const REFUSED_NOT_PERMITTED: u32 = 1;
pub const REFUSED_SLOT: u32 = 2;
pub const REFUSED_MALFORMED: u32 = 3;
pub const REFUSED_RESOURCES: u32 = 4;

pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_ARGS: usize = 32;
pub const REPLY_BYTES: usize = 24;
/// Largest startup record: roles for a full vector plus the largest argv.
pub const MAX_STARTUP_BYTES: usize = 8 + 2 + 2 * 64 + MAX_REQUEST_BYTES;

/// What `parse_request` found at the front of a buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Parsed {
    /// More bytes are needed.
    Incomplete,
    /// The bytes cannot become a valid request.
    Malformed,
    /// A whole request of `length` bytes. `args` is the offset of the
    /// argument list (`u16 argc` then the arguments) within it.
    Request {
        length: usize,
        slot: u8,
        path: (usize, usize),
        args: usize,
    },
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<usize> {
    let pair = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([pair[0], pair[1]]) as usize)
}

/// Parses one request at the front of `bytes`, never reading past a bound.
pub fn parse_request(bytes: &[u8]) -> Parsed {
    let prefix = bytes.len().min(8);
    if bytes[..prefix] != REQUEST_MAGIC[..prefix] {
        return Parsed::Malformed;
    }
    if bytes.len() < 12 {
        return Parsed::Incomplete;
    }
    if bytes[8] != REQUEST_SPAWN {
        return Parsed::Malformed;
    }
    let slot = bytes[9];
    let Some(path_length) = u16_at(bytes, 10) else {
        return Parsed::Incomplete;
    };
    let path = (12, 12 + path_length);
    if path_length == 0 || path.1 > MAX_REQUEST_BYTES {
        return Parsed::Malformed;
    }
    let args = path.1;
    let Some(argc) = u16_at(bytes, args) else {
        return Parsed::Incomplete;
    };
    if argc > MAX_ARGS {
        return Parsed::Malformed;
    }
    let mut offset = args + 2;
    for _ in 0..argc {
        let Some(length) = u16_at(bytes, offset) else {
            return if offset + 2 > MAX_REQUEST_BYTES {
                Parsed::Malformed
            } else {
                Parsed::Incomplete
            };
        };
        offset += 2 + length;
        if offset > MAX_REQUEST_BYTES {
            return Parsed::Malformed;
        }
    }
    if offset > bytes.len() {
        return Parsed::Incomplete;
    }
    Parsed::Request {
        length: offset,
        slot,
        path,
        args,
    }
}

/// The arguments of a well-formed argument list (`u16 argc`, then each
/// `u16 length` and its bytes), as produced by `parse_request`.
pub struct Args<'a> {
    bytes: &'a [u8],
    remaining: usize,
    offset: usize,
}

impl<'a> Args<'a> {
    pub fn new(list: &'a [u8]) -> Self {
        Self {
            bytes: list,
            remaining: u16_at(list, 0).unwrap_or(0),
            offset: 2,
        }
    }
    /// Arguments not yet returned.
    pub fn argc(&self) -> usize {
        self.remaining
    }
}

impl<'a> Iterator for Args<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.remaining == 0 {
            return None;
        }
        let length = u16_at(self.bytes, self.offset)?;
        let arg = self.bytes.get(self.offset + 2..self.offset + 2 + length)?;
        self.offset += 2 + length;
        self.remaining -= 1;
        Some(arg)
    }
}

pub fn encode_reply(kind: u8, slot: u8, code: u32, value: i64) -> [u8; REPLY_BYTES] {
    let mut reply = [0u8; REPLY_BYTES];
    reply[..8].copy_from_slice(REPLY_MAGIC);
    reply[8] = kind;
    reply[9] = slot;
    reply[12..16].copy_from_slice(&code.to_le_bytes());
    reply[16..24].copy_from_slice(&value.to_le_bytes());
    reply
}

/// `(kind, slot, code, value)` of a reply, or `None` if it is not one.
pub fn decode_reply(reply: &[u8; REPLY_BYTES]) -> Option<(u8, u8, u32, i64)> {
    if &reply[..8] != REPLY_MAGIC || reply[10..12] != [0, 0] {
        return None;
    }
    let code = u32::from_le_bytes([reply[12], reply[13], reply[14], reply[15]]);
    let mut value = [0u8; 8];
    value.copy_from_slice(&reply[16..24]);
    Some((reply[8], reply[9], code, i64::from_le_bytes(value)))
}

/// Appends bytes to a fixed buffer, failing instead of truncating.
pub struct Writer<'a> {
    buffer: &'a mut [u8],
    length: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, length: 0 }
    }
    pub fn bytes(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.length.checked_add(bytes.len())?;
        self.buffer
            .get_mut(self.length..end)?
            .copy_from_slice(bytes);
        self.length = end;
        Some(())
    }
    pub fn u16(&mut self, value: usize) -> Option<()> {
        self.bytes(&u16::try_from(value).ok()?.to_le_bytes())
    }
    pub fn len(&self) -> usize {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// Writes a startup record: `roles` as `(role, vector index)` and the
/// arguments, taken as an already encoded argument list.
pub fn startup_record(out: &mut [u8], roles: &[(u8, u8)], args: &[u8]) -> Option<usize> {
    let mut writer = Writer::new(out);
    writer.bytes(STARTUP_MAGIC)?;
    writer.u16(roles.len())?;
    for &(role, index) in roles {
        writer.bytes(&[role, index])?;
    }
    writer.bytes(args)?;
    Some(writer.len())
}

/// A parsed startup record: the vector index of each role (slot roles in
/// order) and the offset of its argument list.
pub struct Startup<'a> {
    pub record: &'a [u8],
    pub args: usize,
}

impl<'a> Startup<'a> {
    pub fn parse(record: &'a [u8], vector_length: usize) -> Option<Self> {
        if record.get(..8)? != STARTUP_MAGIC {
            return None;
        }
        let roles = u16_at(record, 8)?;
        let args = 10 + 2 * roles;
        let mut seen = [false; 64];
        for index in 0..roles {
            let slot = *record.get(10 + 2 * index + 1)? as usize;
            if slot >= vector_length || slot >= seen.len() || seen[slot] {
                return None;
            }
            seen[slot] = true;
        }
        let list = record.get(args..)?;
        let argc = u16_at(list, 0)?;
        if argc > MAX_ARGS || Args::new(list).argc() != argc {
            return None;
        }
        let mut parsed = Args::new(list);
        let mut used = 2;
        for _ in 0..argc {
            used += 2 + parsed.next()?.len();
        }
        // An optional environment list may follow the arguments.
        if used != list.len() {
            let env = list.get(used..)?;
            let envc = u16_at(env, 0)?;
            let mut offset = 2;
            for _ in 0..envc {
                offset += 2 + u16_at(env, offset)?;
            }
            if envc > MAX_ARGS || offset != env.len() {
                return None;
            }
        }
        Some(Self { record, args })
    }
    /// The vector index holding the `nth` handle with `role`.
    pub fn role(&self, role: u8, nth: usize) -> Option<usize> {
        let roles = u16_at(self.record, 8)?;
        (0..roles)
            .map(|index| (self.record[10 + 2 * index], self.record[11 + 2 * index]))
            .filter(|&(found, _)| found == role)
            .nth(nth)
            .map(|(_, slot)| slot as usize)
    }
    pub fn args(&self) -> Args<'a> {
        Args::new(&self.record[self.args..])
    }
}

/// Encodes one spawn request.
pub fn encode_request(out: &mut [u8], slot: u8, path: &[u8], args: &[&[u8]]) -> Option<usize> {
    let mut writer = Writer::new(out);
    writer.bytes(REQUEST_MAGIC)?;
    writer.bytes(&[REQUEST_SPAWN, slot])?;
    writer.u16(path.len())?;
    writer.bytes(path)?;
    writer.u16(args.len())?;
    for arg in args {
        writer.u16(arg.len())?;
        writer.bytes(arg)?;
    }
    Some(writer.len())
}

/// Reads a pipe to end-of-file into `buffer`, failing if it does not fit.
pub fn read_to_end(pipe: crate::Pipe, buffer: &mut [u8]) -> Result<usize, crate::Error> {
    let mut length = 0;
    loop {
        if length == buffer.len() {
            let mut probe = [0u8; 1];
            return match pipe.read_once(&mut probe)? {
                0 => Ok(length),
                _ => Err(crate::Error::Invalid),
            };
        }
        match pipe.read_once(&mut buffer[length..])? {
            0 => return Ok(length),
            count => length += count,
        }
    }
}

/// A requester's side of its channel, as its startup record names it.
pub struct Channel {
    pub request: crate::Pipe,
    pub reply: crate::Pipe,
    /// Per slot: stdin writer, stdout reader, stderr reader.
    pub slots: [(u64, u64, u64); 8],
    pub slot_count: usize,
}

impl Channel {
    pub fn from_startup(handles: &[u64], startup: &Startup<'_>) -> Option<Self> {
        let request = crate::Pipe::from_raw(handles[startup.role(ROLE_REQUEST, 0)?]);
        let reply = crate::Pipe::from_raw(handles[startup.role(ROLE_REPLY, 0)?]);
        let mut slots = [(0, 0, 0); 8];
        let mut slot_count = 0;
        while let Some(stdin) = startup.role(ROLE_SLOT_STDIN, slot_count) {
            *slots.get_mut(slot_count)? = (
                handles[stdin],
                handles[startup.role(ROLE_SLOT_STDOUT, slot_count)?],
                handles[startup.role(ROLE_SLOT_STDERR, slot_count)?],
            );
            slot_count += 1;
        }
        Some(Self {
            request,
            reply,
            slots,
            slot_count,
        })
    }
    pub fn send(&self, slot: u8, path: &[u8], args: &[&[u8]]) -> Result<(), crate::Error> {
        let mut request = [0u8; 512];
        let length = encode_request(&mut request, slot, path, args).ok_or(crate::Error::Invalid)?;
        self.request.write_all(&request[..length])
    }
    /// The next reply, in arrival order.
    pub fn next_reply(&self) -> Result<(u8, u8, u32, i64), crate::Error> {
        let mut reply = [0u8; REPLY_BYTES];
        let mut length = 0;
        while length < REPLY_BYTES {
            match self.reply.read_once(&mut reply[length..])? {
                0 => return Err(crate::Error::BrokenPipe),
                count => length += count,
            }
        }
        decode_reply(&reply).ok_or(crate::Error::Invalid)
    }
}
