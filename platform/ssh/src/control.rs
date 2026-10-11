//! The session control protocol: what sshd and an interactive session's
//! shell say to each other on the session control channel (startup roles
//! 16 and 17, the runtime's `absd_runtime::session`), beside the session's
//! standard streams. Pure and platform-independent; `/bin/absd-sh`
//! includes this file by path.
//!
//! A frame is `u8 kind, u16 length (little-endian), length bytes`, at most
//! [`MAX_PAYLOAD`] bytes of payload.
//!
//! sshd to the shell (the events pipe):
//!
//! * [`INTERRUPT`]: ^C was typed on the session's terminal (no payload).
//!   The shell acts on it while a command line runs; one that waits in the
//!   channel when the shell reads its next line was typed at the prompt,
//!   and the shell discards it.
//! * [`REPLY`]: the answer to the shell's request, `u8 status` then text.
//! * [`END`]: the session has ended (the client went away, the idle
//!   timeout passed, or the system is going down) (no payload). The shell
//!   kills and reaps every command it is running and exits; sshd gives it
//!   a bounded time to do so before it kills the shell itself.
//!
//! The shell to sshd (the requests pipe), one at a time, each answered by
//! one [`REPLY`]:
//!
//! * [`MACHINE`]: the words of a `shutdown` or `reboot` command, decided by
//!   sshd exactly as the same `exec` would be;
//! * [`LIST`]: this session's processes (no payload). The channel names
//!   the session: there is no way to ask about another.
//!
//! A malformed frame ends the conversation: the reader stops using the
//! channel.

pub const INTERRUPT: u8 = 1;
pub const REPLY: u8 = 2;
pub const END: u8 = 3;
pub const MACHINE: u8 = 16;
pub const LIST: u8 = 17;

/// Kinds sshd sends.
pub const EVENTS: &[u8] = &[INTERRUPT, REPLY, END];
/// Kinds the shell sends.
pub const REQUESTS: &[u8] = &[MACHINE, LIST];

pub const MAX_PAYLOAD: usize = 4096;
const HEADER: usize = 3;

pub fn encode(kind: u8, payload: &[u8]) -> Vec<u8> {
    let length = payload.len().min(MAX_PAYLOAD);
    let mut frame = Vec::with_capacity(HEADER + length);
    frame.push(kind);
    frame.extend_from_slice(&(length as u16).to_le_bytes());
    frame.extend_from_slice(&payload[..length]);
    frame
}

pub fn interrupt() -> Vec<u8> {
    encode(INTERRUPT, b"")
}

pub fn end() -> Vec<u8> {
    encode(END, b"")
}

pub fn reply(status: u8, text: &str) -> Vec<u8> {
    let mut payload = vec![status];
    // Cut on a character boundary so the text stays UTF-8.
    let mut end = text.len().min(MAX_PAYLOAD - 1);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    payload.extend_from_slice(&text.as_bytes()[..end]);
    encode(REPLY, &payload)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Interrupt,
    Reply { status: u8, text: String },
    End,
    Machine(String),
    List,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

/// Reassembles frames from a byte stream (a pipe delivers them in pieces)
/// and accepts only the kinds one direction may carry.
pub struct Decoder {
    allowed: &'static [u8],
    buffer: Vec<u8>,
}

impl Decoder {
    pub fn new(allowed: &'static [u8]) -> Self {
        Decoder { allowed, buffer: Vec::new() }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next whole frame, `Ok(None)` until one has arrived.
    pub fn next(&mut self) -> Result<Option<Frame>, Malformed> {
        if self.buffer.len() < HEADER {
            return Ok(None);
        }
        let kind = self.buffer[0];
        let length = u16::from_le_bytes([self.buffer[1], self.buffer[2]]) as usize;
        if !self.allowed.contains(&kind) || length > MAX_PAYLOAD {
            return Err(Malformed);
        }
        if self.buffer.len() < HEADER + length {
            return Ok(None);
        }
        let payload: Vec<u8> = self.buffer.drain(..HEADER + length).skip(HEADER).collect();
        let text = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).map_err(|_| Malformed);
        match kind {
            INTERRUPT if payload.is_empty() => Ok(Some(Frame::Interrupt)),
            END if payload.is_empty() => Ok(Some(Frame::End)),
            REPLY => {
                let (&status, rest) = payload.split_first().ok_or(Malformed)?;
                Ok(Some(Frame::Reply { status, text: text(rest)? }))
            }
            MACHINE => Ok(Some(Frame::Machine(text(&payload)?))),
            LIST if payload.is_empty() => Ok(Some(Frame::List)),
            _ => Err(Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_in_pieces() {
        let mut stream = interrupt();
        stream.extend(reply(0, "session 1\n"));
        stream.extend(interrupt());
        stream.extend(end());
        let mut decoder = Decoder::new(EVENTS);
        let mut seen = Vec::new();
        for byte in stream {
            decoder.push(&[byte]);
            while let Some(frame) = decoder.next().unwrap() {
                seen.push(frame);
            }
        }
        assert_eq!(
            seen,
            [
                Frame::Interrupt,
                Frame::Reply { status: 0, text: "session 1\n".into() },
                Frame::Interrupt,
                Frame::End,
            ]
        );
        let mut decoder = Decoder::new(REQUESTS);
        decoder.push(&encode(MACHINE, b"shutdown -r now"));
        decoder.push(&encode(LIST, b""));
        assert_eq!(decoder.next(), Ok(Some(Frame::Machine("shutdown -r now".into()))));
        assert_eq!(decoder.next(), Ok(Some(Frame::List)));
        assert_eq!(decoder.next(), Ok(None));
    }

    #[test]
    fn each_direction_refuses_the_other_and_garbage() {
        let mut decoder = Decoder::new(REQUESTS);
        decoder.push(&interrupt());
        assert_eq!(decoder.next(), Err(Malformed));
        let mut decoder = Decoder::new(EVENTS);
        decoder.push(&encode(LIST, b""));
        assert_eq!(decoder.next(), Err(Malformed));
        let mut decoder = Decoder::new(REQUESTS);
        decoder.push(&end());
        assert_eq!(decoder.next(), Err(Malformed));
        for bad in [
            encode(INTERRUPT, b"x"),
            encode(END, b"x"),
            encode(REPLY, b""),
            encode(REPLY, b"\x00\xff"),
            vec![REPLY, 0xff, 0xff],
        ] {
            let mut decoder = Decoder::new(EVENTS);
            decoder.push(&bad);
            assert_eq!(decoder.next(), Err(Malformed), "{bad:?}");
        }
        let mut decoder = Decoder::new(REQUESTS);
        decoder.push(&encode(LIST, b"x"));
        assert_eq!(decoder.next(), Err(Malformed));
    }

    #[test]
    fn long_replies_are_cut_on_a_character() {
        let text = "\u{e9}".repeat(MAX_PAYLOAD);
        let mut decoder = Decoder::new(EVENTS);
        decoder.push(&reply(3, &text));
        match decoder.next() {
            Ok(Some(Frame::Reply { status: 3, text })) => assert!(text.len() < MAX_PAYLOAD),
            other => panic!("{other:?}"),
        }
    }
}
