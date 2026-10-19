//! Bounded stream framing for one endpoint capability. Exactly one request
//! is in flight. The adapter makes at most one <=256 byte pipe transfer per
//! call; an incomplete request or blocked response expires after 250 ms.

use super::*;

pub const FRAME_TIMEOUT_MS: u64 = 250;

pub trait Pipe {
    /// Nonblocking or bounded to one timer tick. None means no progress;
    /// zero or Err means EOF/failure. Never return more than buffer.len().
    fn read(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, i64>;
    fn write(&mut self, buffer: &[u8]) -> Result<Option<usize>, i64>;
    fn now_ms(&self) -> u64;
}

/// One bounded client transaction. A lost reply never retries SEND: its
/// remote effect is unknown. Partial/error streams must be discarded.
pub fn transact<P: Pipe>(
    pipe: &mut P,
    request: &[u8],
    reply: &mut [u8; MAX_MESSAGE],
    timeout_ms: u64,
) -> Result<usize, i64> {
    transact_versioned(pipe, request, reply, timeout_ms, VERSION, 0)
}

/// Internal typed-header reuse; existing v1 callers retain their exact bytes.
pub(crate) fn transact_versioned<P: Pipe>(
    pipe: &mut P,
    request: &[u8],
    reply: &mut [u8; MAX_MESSAGE],
    timeout_ms: u64,
    version: u8,
    family: u8,
) -> Result<usize, i64> {
    if !(12..=MAX_MESSAGE).contains(&request.len()) || timeout_ms == 0 || timeout_ms > 10_000 {
        return Err(-22);
    }
    let end = pipe.now_ms().checked_add(timeout_ms).ok_or(-22i64)?;
    let prefix = (request.len() as u16).to_be_bytes();
    for bytes in [&prefix[..], request] {
        let mut at = 0;
        while at < bytes.len() {
            if pipe.now_ms() >= end {
                return Err(-110);
            }
            match pipe.write(&bytes[at..(at + 256).min(bytes.len())])? {
                Some(n) if n > 0 && n <= (bytes.len() - at).min(256) => at += n,
                None => {}
                _ => return Err(-5),
            }
        }
    }
    let mut prefix = [0; 2];
    let mut wanted = 2;
    let mut at = 0;
    loop {
        if pipe.now_ms() >= end {
            return Err(-110);
        }
        let target: &mut [u8] = if wanted == 2 {
            &mut prefix
        } else {
            &mut reply[..wanted]
        };
        match pipe.read(&mut target[at..(at + 256).min(wanted)])? {
            Some(n) if n > 0 && n <= (wanted - at).min(256) => at += n,
            None => {}
            _ => return Err(-5),
        }
        if at == wanted {
            if wanted == 2 {
                wanted = u16::from_be_bytes(prefix) as usize;
                if !(12..=MAX_MESSAGE).contains(&wanted) {
                    return Err(-22);
                }
                at = 0;
            } else {
                if reply[0] != version || reply[1] != request[1] || reply[3] != family {
                    return Err(-22);
                }
                return Ok(wanted);
            }
        }
    }
}

pub struct Channel {
    session: Session,
    input: [u8; MAX_MESSAGE + 2],
    used: usize,
    wanted: usize,
    output: [u8; MAX_MESSAGE + 2],
    sent: usize,
    pending: usize,
    deadline: Option<u64>,
    live: bool,
}

impl Channel {
    pub fn grant<L: Link>(stack: &mut Stack<L>, grant: Grant) -> Result<Self, Error> {
        Ok(Self {
            session: Session::grant(stack, grant)?,
            input: [0; MAX_MESSAGE + 2],
            used: 0,
            wanted: 2,
            output: [0; MAX_MESSAGE + 2],
            sent: 0,
            pending: 0,
            deadline: None,
            live: true,
        })
    }

    pub fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        self.session.revoke(stack);
        self.live = false;
        self.pending = 0;
        self.used = 0;
    }

    pub fn live(&self) -> bool {
        self.live
    }

    /// Returns whether the channel remains usable. At false the owner must
    /// drop both pipe ends, and reap/stop its consumer under existing policy.
    pub fn poll<L: Link, P: Pipe>(&mut self, stack: &mut Stack<L>, pipe: &mut P) -> bool {
        if !self.live {
            return false;
        }
        let now = pipe.now_ms();
        if self.deadline.is_some_and(|end| now >= end) {
            self.revoke(stack);
            return false;
        }
        if self.pending != 0 {
            let end = (self.sent + 256).min(self.pending);
            match pipe.write(&self.output[self.sent..end]) {
                Ok(Some(n)) if n > 0 && n <= end - self.sent => {
                    self.sent += n;
                    if self.sent == self.pending {
                        self.pending = 0;
                        self.sent = 0;
                        self.deadline = None;
                    }
                }
                Ok(None) => {}
                _ => self.revoke(stack),
            }
            return self.live;
        }
        let end = (self.used + 256).min(self.wanted);
        match pipe.read(&mut self.input[self.used..end]) {
            Ok(Some(n)) if n > 0 && n <= end - self.used => {
                if self.used == 0 {
                    self.deadline = now.checked_add(FRAME_TIMEOUT_MS);
                }
                if self.deadline.is_none() {
                    self.revoke(stack);
                    return false;
                }
                self.used += n;
                if self.used == 2 && self.wanted == 2 {
                    let length = u16::from_be_bytes(self.input[..2].try_into().unwrap()) as usize;
                    if !(12..=MAX_MESSAGE).contains(&length) {
                        self.revoke(stack);
                        return false;
                    }
                    self.wanted = length + 2;
                }
                if self.used == self.wanted {
                    let mut reply = [0; MAX_MESSAGE];
                    let length = self
                        .session
                        .request(stack, &self.input[2..self.used], &mut reply);
                    self.output[..2].copy_from_slice(&(length as u16).to_be_bytes());
                    self.output[2..2 + length].copy_from_slice(&reply[..length]);
                    self.pending = 2 + length;
                    self.used = 0;
                    self.wanted = 2;
                    self.deadline = now.checked_add(FRAME_TIMEOUT_MS);
                }
            }
            Ok(None) => {}
            _ => self.revoke(stack),
        }
        self.live
    }
}

#[cfg(target_os = "absd")]
pub struct KernelPipe {
    pub request_reader: u64,
    pub reply_writer: u64,
}

#[cfg(target_os = "absd")]
impl Pipe for KernelPipe {
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        match absd_runtime::read_within(self.request_reader, bytes, 1) {
            Ok(n) => Ok(Some(n)),
            Err(-110 | -11) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        match absd_runtime::write_within(self.reply_writer, bytes, 1) {
            Ok(n) => Ok(Some(n)),
            Err(-110 | -11) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn now_ms(&self) -> u64 {
        absd_runtime::boot_millis()
    }
}

#[cfg(target_os = "absd")]
impl Drop for KernelPipe {
    fn drop(&mut self) {
        let _ = absd_runtime::close(self.request_reader);
        let _ = absd_runtime::close(self.reply_writer);
    }
}
