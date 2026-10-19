//! Bounded framing shared by a native stream or an explicitly paired DNS grant.
use super::{Error, Grant, Session};
use crate::{
    Link, Stack,
    datagram::{
        MAX_MESSAGE,
        channel::{FRAME_TIMEOUT_MS, Pipe},
    },
};

pub trait Handler {
    fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        request: &[u8],
        reply: &mut [u8; MAX_MESSAGE],
    ) -> usize;
    fn revoke<L: Link>(&mut self, stack: &mut Stack<L>);
    /// Strict opt-in channels recheck endpoint authority around each pipe I/O.
    fn authorized<L: Link>(&mut self, _stack: &mut Stack<L>) -> bool {
        true
    }
    fn fence<L: Link>(&mut self, stack: &mut Stack<L>) {
        self.revoke(stack)
    }
}
impl Handler for Session {
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
    strict: bool,
    last_ms: Option<u64>,
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
            strict: false,
            last_ms: None,
        }
    }

    pub(crate) fn strict(mut self) -> Self {
        self.strict = true;
        self
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

    fn fail<L: Link>(&mut self, stack: &mut Stack<L>) {
        if self.strict {
            self.session.fence(stack);
        }
        self.revoke(stack);
    }

    /// Returns whether the channel remains usable. At false the owner must
    /// drop both pipe ends, and reap/stop its consumer under existing policy.
    pub fn poll<L: Link, P: Pipe>(&mut self, stack: &mut Stack<L>, pipe: &mut P) -> bool {
        if !self.live {
            return false;
        }
        if self.strict && !self.session.authorized(stack) {
            self.fail(stack);
            return false;
        }
        let now = pipe.now_ms();
        if self.strict && self.last_ms.is_some_and(|last| now < last) {
            self.fail(stack);
            return false;
        }
        self.last_ms = Some(now);
        if self.deadline.is_some_and(|end| now >= end) {
            self.fail(stack);
            return false;
        }
        if self.pending != 0 {
            let end = (self.sent + 256).min(self.pending);
            let result = pipe.write(&self.output[self.sent..end]);
            if self.strict {
                let after = pipe.now_ms();
                if after < now
                    || self.deadline.is_none_or(|bound| after >= bound)
                    || !self.session.authorized(stack)
                {
                    self.fail(stack);
                    return false;
                }
                self.last_ms = Some(after);
            }
            match result {
                Ok(Some(n)) if n > 0 && n <= end - self.sent => {
                    self.sent += n;
                    if self.sent == self.pending {
                        self.pending = 0;
                        self.sent = 0;
                        self.deadline = None;
                    }
                }
                Ok(None) => {}
                _ => self.fail(stack),
            }
            return self.live;
        }
        let end = (self.used + 256).min(self.wanted);
        let result = pipe.read(&mut self.input[self.used..end]);
        if self.strict {
            let after = pipe.now_ms();
            let bound = self.deadline.or_else(|| now.checked_add(FRAME_TIMEOUT_MS));
            if after < now
                || bound.is_none_or(|end| after >= end)
                || !self.session.authorized(stack)
            {
                self.fail(stack);
                return false;
            }
            self.last_ms = Some(after);
        }
        match result {
            Ok(Some(n)) if n > 0 && n <= end - self.used => {
                if self.used == 0 {
                    self.deadline = now.checked_add(FRAME_TIMEOUT_MS);
                }
                if self.deadline.is_none() {
                    self.fail(stack);
                    return false;
                }
                self.used += n;
                if self.used == 2 && self.wanted == 2 {
                    let length = u16::from_be_bytes(self.input[..2].try_into().unwrap()) as usize;
                    if !(12..=MAX_MESSAGE).contains(&length) {
                        self.fail(stack);
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
            Ok(Some(0)) => self.revoke(stack),
            _ => self.fail(stack),
        }
        self.live
    }
}
