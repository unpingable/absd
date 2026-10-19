//! Bounded stream framing for one endpoint capability. Exactly one request
//! is in flight. The adapter makes at most one <=256 byte pipe transfer per
//! call; an incomplete request or blocked response expires after 250 ms.

use super::session::{FAMILY, HEADER, MAX_MESSAGE, Session, VERSION};
use super::*;
#[cfg(target_os = "absd")]
pub use crate::datagram::channel::KernelPipe;
pub use crate::datagram::channel::Pipe;

pub const FRAME_TIMEOUT_MS: u64 = 250;

/// One bounded client transaction. A lost reply never retries SEND: its
/// remote effect is unknown. Partial/error streams must be discarded.
pub fn transact<P: Pipe>(
    pipe: &mut P,
    request: &[u8],
    reply: &mut [u8; MAX_MESSAGE],
    timeout_ms: u64,
) -> Result<usize, i64> {
    if !(HEADER..=MAX_MESSAGE).contains(&request.len()) || timeout_ms == 0 || timeout_ms > 10_000 {
        return Err(-22);
    }
    let mut previous = pipe.now_ms();
    let end = previous.checked_add(timeout_ms).ok_or(-22i64)?;
    let prefix = (request.len() as u16).to_be_bytes();
    for bytes in [&prefix[..], request] {
        let mut at = 0;
        while at < bytes.len() {
            let now = pipe.now_ms();
            if now < previous {
                return Err(-22);
            }
            previous = now;
            if now >= end {
                return Err(-110);
            }
            match pipe.write(&bytes[at..(at + 256).min(bytes.len())])? {
                Some(n) if n > 0 && n <= (bytes.len() - at).min(256) => at += n,
                None => {}
                _ => return Err(-5),
            }
            let observed = pipe.now_ms();
            if observed < previous {
                return Err(-22);
            }
            if observed >= end {
                return Err(-110);
            }
            previous = observed;
        }
    }
    let mut prefix = [0; 2];
    let mut wanted = 2;
    let mut at = 0;
    loop {
        let now = pipe.now_ms();
        if now < previous {
            return Err(-22);
        }
        previous = now;
        if now >= end {
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
        let observed = pipe.now_ms();
        if observed < previous {
            return Err(-22);
        }
        if observed >= end {
            return Err(-110);
        }
        previous = observed;
        if at == wanted {
            if wanted == 2 {
                wanted = u16::from_be_bytes(prefix) as usize;
                if !(HEADER..=MAX_MESSAGE).contains(&wanted) {
                    return Err(-22);
                }
                at = 0;
            } else {
                if reply[0] != VERSION || reply[1] != request[1] || reply[3] != FAMILY {
                    return Err(-22);
                }
                return Ok(wanted);
            }
        }
    }
}

pub trait Handler {
    /// Only an already-issued UDP endpoint can select a pending FEEDBACK
    /// guard. Custom handlers default to refusing that new response form.
    fn feedback_endpoint(&self) -> Option<super::Endpoint> {
        None
    }
    fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        request: &[u8],
        reply: &mut [u8; MAX_MESSAGE],
    ) -> usize;
    fn revoke<L: Link>(&mut self, stack: &mut Stack<L>);
}
impl Handler for Session {
    fn feedback_endpoint(&self) -> Option<super::Endpoint> {
        Some(Session::feedback_endpoint(self))
    }
    fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        request: &[u8],
        reply: &mut [u8; MAX_MESSAGE],
    ) -> usize {
        self.request(stack, request, reply)
    }
    fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        self.revoke(stack)
    }
}

pub struct Channel<H = Session> {
    session: H,
    input: [u8; MAX_MESSAGE + 2],
    used: usize,
    wanted: usize,
    output: [u8; MAX_MESSAGE + 2],
    sent: usize,
    pending: usize,
    deadline: Option<u64>,
    live: bool,
    previous: u64,
    feedback_guard: Option<super::feedback::Stamp>,
}

impl Channel<Session> {
    pub fn grant<L: Link>(stack: &mut Stack<L>, grant: Grant) -> Result<Self, Error> {
        Ok(Self::new(Session::grant(stack, grant)?))
    }
}
impl<H: Handler> Channel<H> {
    pub fn new(session: H) -> Self {
        Self {
            session,
            input: [0; MAX_MESSAGE + 2],
            used: 0,
            wanted: 2,
            output: [0; MAX_MESSAGE + 2],
            sent: 0,
            pending: 0,
            deadline: None,
            live: true,
            previous: 0,
            feedback_guard: None,
        }
    }

    pub fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        self.session.revoke(stack);
        self.live = false;
        self.pending = 0;
        self.used = 0;
        self.feedback_guard = None;
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
        if now < self.previous || self.deadline.is_some_and(|end| now >= end) {
            self.revoke(stack);
            return false;
        }
        self.previous = now;
        if self.pending != 0 {
            let feedback_guard = self.feedback_guard;
            if feedback_guard.is_some_and(|stamp| !stack.ipv6_feedback_valid(stamp)) {
                self.revoke(stack);
                return false;
            }
            let response_deadline = self.deadline;
            let end = (self.sent + 256).min(self.pending);
            match pipe.write(&self.output[self.sent..end]) {
                Ok(Some(n)) if n > 0 && n <= end - self.sent => {
                    self.sent += n;
                    if self.sent == self.pending {
                        self.pending = 0;
                        self.sent = 0;
                        self.deadline = None;
                        self.feedback_guard = None;
                    }
                }
                Ok(None) => {}
                _ => self.revoke(stack),
            }
            let observed = pipe.now_ms();
            if observed < now
                || response_deadline.is_some_and(|end| observed >= end)
                || feedback_guard.is_some_and(|stamp| !stack.ipv6_feedback_valid(stamp))
            {
                self.revoke(stack);
            }
            self.previous = observed;
            return self.live;
        }
        let end = (self.used + 256).min(self.wanted);
        match pipe.read(&mut self.input[self.used..end]) {
            Ok(Some(n)) if n > 0 && n <= end - self.used => {
                let observed = pipe.now_ms();
                if observed < now || self.deadline.is_some_and(|end| observed >= end) {
                    self.revoke(stack);
                    return false;
                }
                self.previous = observed;
                if self.used == 0 {
                    self.deadline = now.checked_add(FRAME_TIMEOUT_MS);
                }
                if self.deadline.is_none_or(|end| observed >= end) {
                    self.revoke(stack);
                    return false;
                }
                self.used += n;
                if self.used == 2 && self.wanted == 2 {
                    let length = u16::from_be_bytes(self.input[..2].try_into().unwrap()) as usize;
                    if !(HEADER..=MAX_MESSAGE).contains(&length) {
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
                    if reply[1] == super::feedback::FEEDBACK && reply[2] == 0 {
                        self.feedback_guard = self
                            .session
                            .feedback_endpoint()
                            .and_then(|endpoint| stack.ipv6_feedback_stamp(endpoint).ok());
                        if self.feedback_guard.is_none() {
                            self.revoke(stack);
                            return false;
                        }
                    }
                    self.output[..2].copy_from_slice(&(length as u16).to_be_bytes());
                    self.output[2..2 + length].copy_from_slice(&reply[..length]);
                    self.pending = 2 + length;
                    self.used = 0;
                    self.wanted = 2;
                    self.deadline = now.checked_add(FRAME_TIMEOUT_MS);
                    if self.deadline.is_none() {
                        self.revoke(stack);
                    }
                }
            }
            Ok(None) => {}
            _ => self.revoke(stack),
        }
        self.live
    }
}
