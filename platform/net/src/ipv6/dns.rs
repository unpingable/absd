//! DNS over one delegated IPv6 datagram channel. Answer family is chosen by
//! the resolver independently of transport family. No implicit TCP grant.
use super::channel::{Pipe, transact};
use super::session::{FAMILY, HEADER, MAX_MESSAGE, RECEIVE, SEND, VERSION};
use super::{Address, Error as DatagramError, MAX_DATAGRAM, feedback};
use crate::dns::{Error, Transport};

pub struct Datagram<P: Pipe> {
    pipe: P,
    peer: Address,
    pause: fn(u64),
    live: bool,
    feedback: bool,
}

impl<P: Pipe> Datagram<P> {
    pub fn new(pipe: P, peer: Address, pause: fn(u64)) -> Self {
        Self {
            pipe,
            peer,
            pause,
            live: true,
            feedback: false,
        }
    }

    /// Explicit opt-in: type 1 errors are terminal endpoint diagnostics;
    /// Packet Too Big and Time Exceeded are consumed as advisory observations.
    /// The reply has no query identity, so a delayed type 1 error for an earlier
    /// query can end a later lookup on this endpoint. Use a fresh owner-issued
    /// channel for a bounded single-query invocation when that matters.
    /// Existing new() transports send no new operations.
    pub fn with_feedback(pipe: P, peer: Address, pause: fn(u64)) -> Self {
        Self {
            feedback: true,
            ..Self::new(pipe, peer, pause)
        }
    }

    pub fn live(&self) -> bool {
        self.live
    }

    fn call(
        &mut self,
        op: u8,
        data: &[u8],
        deadline: u64,
        reply: &mut [u8; MAX_MESSAGE],
    ) -> Result<usize, Error> {
        if !self.live {
            return Err(Error::Transport(DatagramError::Stale));
        }
        let left = deadline
            .checked_sub(self.pipe.now_ms())
            .filter(|n| *n > 0)
            .ok_or(Error::Timeout)?;
        if data.len() > MAX_DATAGRAM {
            return Err(Error::TooLarge);
        }
        let mut request = [0; MAX_MESSAGE];
        request[0] = VERSION;
        request[1] = op;
        request[3] = FAMILY;
        if op == SEND {
            request[4..20].copy_from_slice(&self.peer.ip);
            request[20..24].copy_from_slice(&self.peer.scope.to_be_bytes());
            request[24..26].copy_from_slice(&self.peer.port.to_be_bytes());
            request[26..28].copy_from_slice(&(data.len() as u16).to_be_bytes());
            request[HEADER..HEADER + data.len()].copy_from_slice(data);
        } else if op == RECEIVE {
            request[26..28].copy_from_slice(&(MAX_DATAGRAM as u16).to_be_bytes());
        }
        let n = match transact(
            &mut self.pipe,
            &request[..HEADER + data.len()],
            reply,
            left.min(1000),
        ) {
            Ok(n) => n,
            Err(e) => {
                self.live = false;
                return Err(if e == -110 && self.pipe.now_ms() >= deadline {
                    Error::Timeout
                } else {
                    Error::Channel(e)
                });
            }
        };
        let length = u16::from_be_bytes(reply[26..28].try_into().unwrap()) as usize;
        if reply[2] == 0 {
            if (op == feedback::FEEDBACK
                && (n != HEADER + feedback::WIRE_LEN
                    || length != feedback::WIRE_LEN
                    || reply[4..26] != [0; 22]
                    || feedback::Observation::decode(&reply[HEADER..n]).is_none()))
                || (op == SEND && (n != HEADER || reply[4..HEADER] != [0; HEADER - 4]))
                || (op == RECEIVE
                    && (length > MAX_DATAGRAM
                        || n != HEADER + length
                        || reply[4..20] != self.peer.ip
                        || reply[20..24] != self.peer.scope.to_be_bytes()
                        || reply[24..26] != self.peer.port.to_be_bytes()))
            {
                self.live = false;
                return Err(Error::Malformed);
            }
            return Ok(n);
        }
        if n != HEADER || reply[4..26] != [0; 22] || (reply[2] != 7 && length != 0) {
            self.live = false;
            return Err(Error::Malformed);
        }
        if op == feedback::FEEDBACK && !matches!(reply[2], 4 | 6 | 8..=11) {
            self.live = false;
            return Err(Error::Malformed);
        }
        let error = match reply[2] {
            1 => DatagramError::Invalid,
            2 => DatagramError::Denied,
            3 => DatagramError::InUse,
            4 => DatagramError::Exhausted,
            5 => DatagramError::Oversize,
            6 => DatagramError::Again,
            7 if length <= MAX_DATAGRAM => DatagramError::TooSmall { needed: length },
            8 => DatagramError::Stale,
            9 => DatagramError::LinkDown,
            10 => DatagramError::DeviceFailed,
            11 => DatagramError::LinkUnknown,
            _ => {
                self.live = false;
                return Err(Error::Malformed);
            }
        };
        if matches!(
            error,
            DatagramError::Stale
                | DatagramError::LinkDown
                | DatagramError::DeviceFailed
                | DatagramError::LinkUnknown
        ) {
            self.live = false;
        }
        Err(Error::Transport(error))
    }
}

impl<P: Pipe> Transport for Datagram<P> {
    fn now_ms(&self) -> u64 {
        self.pipe.now_ms()
    }
    fn pause(&mut self, ms: u64) {
        (self.pause)(ms);
    }
    fn send(&mut self, bytes: &[u8], deadline: u64) -> Result<(), Error> {
        self.call(SEND, bytes, deadline, &mut [0; MAX_MESSAGE])
            .map(|_| ())
    }
    fn receive(
        &mut self,
        bytes: &mut [u8; crate::datagram::MAX_DATAGRAM],
        deadline: u64,
    ) -> Result<Option<usize>, Error> {
        let mut reply = [0; MAX_MESSAGE];
        if self.feedback {
            match self.call(feedback::FEEDBACK, &[], deadline, &mut reply) {
                Ok(n) => {
                    let observation =
                        feedback::Observation::decode(&reply[HEADER..n]).ok_or(Error::Malformed)?;
                    if observation.kind == 1 {
                        return Err(Error::Ipv6Feedback(observation));
                    }
                    // Advice does not alter packets, retry policy or the
                    // original deadline. Receive once after consuming it.
                }
                Err(Error::Transport(DatagramError::Again)) => {}
                Err(e) => return Err(e),
            }
        }
        match self.call(RECEIVE, &[], deadline, &mut reply) {
            Ok(n) => {
                bytes[..n - HEADER].copy_from_slice(&reply[HEADER..n]);
                Ok(Some(n - HEADER))
            }
            Err(Error::Transport(DatagramError::Again)) => Ok(None),
            Err(Error::Transport(DatagramError::TooSmall { .. } | DatagramError::Oversize)) => {
                Err(Error::TooLarge)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod feedback_tests;
