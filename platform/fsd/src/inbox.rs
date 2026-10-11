//! One channel's bytes as the loop has read them so far, and the decision
//! the loop takes on them. The pipe reads are the loop's
//! (`ssh/src/fsd_server.rs`); this part the host can test. The client
//! reads replies with the same type (`runtime/src/fsd.rs`).
//!
//! A frame is bound to the holder that wrote it (`proto`: magic, length,
//! the holder's sequence word, a check over the whole frame). Bytes a
//! holder left when it died mid-frame cannot be completed by the next
//! holder's bytes: the hybrid fails its check and is dropped, and the next
//! holder's whole frame is found behind it, at the boundary it was written
//! at. Bytes that are no frame (`fsd-probe garbage`) are dropped the same
//! way. Nothing is dropped while the frame at the head may still complete:
//! only [`Inbox::idle`], called once the pipe has gone quiet, gives a head
//! up, and only for a whole valid frame found behind it, so a slow holder
//! is never given up on.
//!
//! Bytes a client wrote while its binding was live are that binding's
//! work: a release closes the session's files and withdraws its authority
//! but discards nothing already sent; each whole request found is answered
//! as the channel now stands (refused, `-13`). A head that can never
//! complete on a released channel is discarded by the loop once the
//! channel is quiet. A new binding discards whatever predates it, buffered
//! here or still waiting in the pipe, so no request of an earlier binding
//! runs under the new one.

use alloc::vec::Vec;

use crate::proto;

/// What the bytes read so far amount to.
#[derive(Debug, PartialEq, Eq)]
pub enum Taken {
    /// No whole frame yet.
    Nothing,
    /// One whole verified frame: the sender's sequence word and the body.
    Frame { seq: u64, body: Vec<u8> },
}

enum Head {
    /// Fewer bytes than a header.
    Short,
    /// The bytes at the head are no header.
    Garbage,
    /// A header whose frame is not all here yet: `total` bytes when it is.
    Partial(usize),
    /// A whole frame is here, not yet verified.
    Whole(usize, u64),
}

#[derive(Debug, Default)]
pub struct Inbox {
    input: Vec<u8>,
}

impl Inbox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    /// Bytes read from the pipe and not yet taken: waiting work, like
    /// bytes still in the pipe (the binding checks count both).
    pub fn len(&self) -> usize {
        self.input.len()
    }

    fn head_at(&self, at: usize) -> Head {
        let bytes = &self.input[at..];
        if bytes.len() < proto::HEADER {
            return Head::Short;
        }
        match proto::parse_header(bytes) {
            None => Head::Garbage,
            Some((length, seq)) => {
                let total = proto::HEADER + length + proto::TRAILER;
                if bytes.len() >= total {
                    Head::Whole(total, seq)
                } else {
                    Head::Partial(total)
                }
            }
        }
    }

    /// Whether another read is wanted: while the frame at the head is not
    /// all here, and never past the largest frame.
    pub fn wants_more(&self) -> bool {
        self.input.len() < proto::MAX_FRAME
            && matches!(self.head_at(0), Head::Short | Head::Partial(_))
    }

    /// Bytes the buffer can hold without growing (for the capacity rule's
    /// test).
    pub fn capacity(&self) -> usize {
        self.input.capacity()
    }

    /// Bytes read from the pipe. The buffer grows to exactly what the head's
    /// header announces, never by doubling: a channel that once carried a
    /// frame over 64 KiB would otherwise keep a 128 KiB buffer for the boot,
    /// one mapped-page step per channel at whatever moment its first such
    /// frame arrived.
    pub fn push(&mut self, bytes: &[u8]) {
        let needed = self.input.len() + bytes.len();
        if needed > self.input.capacity() {
            let want = match self.head_at(0) {
                Head::Partial(total) => total.max(needed),
                _ => needed,
            };
            self.input.reserve_exact(want - self.input.len());
        }
        self.input.extend_from_slice(bytes);
    }

    /// Once nothing is buffered, a large buffer goes back to the allocator
    /// for any channel's next frame.
    fn release_buffer(&mut self) {
        if self.input.is_empty() && self.input.capacity() > 4096 {
            self.input = Vec::new();
        }
    }

    /// The next whole verified frame, or nothing yet. Garbage at the head,
    /// and a whole frame that fails its check, are dropped up to the next
    /// place a frame could start.
    pub fn take(&mut self) -> Taken {
        loop {
            match self.head_at(0) {
                Head::Short | Head::Partial(_) => return Taken::Nothing,
                Head::Garbage => self.resync(1),
                Head::Whole(total, seq) => {
                    if proto::verify(&self.input[..total]) {
                        let body = self.input[proto::HEADER..total - proto::TRAILER].to_vec();
                        self.input.drain(..total);
                        self.release_buffer();
                        return Taken::Frame { seq, body };
                    }
                    self.resync(1);
                }
            }
        }
    }

    /// The next whole frame carrying `seq`; frames addressed to another
    /// sequence word (an earlier holder's replies) are dropped.
    pub fn take_for(&mut self, seq: u64) -> Option<Vec<u8>> {
        loop {
            match self.take() {
                Taken::Frame { seq: found, body } if found == seq => return Some(body),
                Taken::Frame { .. } => continue,
                Taken::Nothing => return None,
            }
        }
    }

    /// The pipe has gone quiet with these bytes. A head that is not all
    /// here may be a dead holder's and never complete: if a whole valid
    /// frame lies behind it, the head is given up and that frame is next.
    /// Otherwise nothing changes.
    pub fn idle(&mut self) {
        if !matches!(self.head_at(0), Head::Partial(_)) {
            return;
        }
        if let Some(at) = self.whole_frame_from(1) {
            self.input.drain(..at);
        }
    }

    /// The first offset at or after `from` where a whole frame that
    /// verifies begins.
    fn whole_frame_from(&self, from: usize) -> Option<usize> {
        let mut at = from;
        while at + proto::HEADER <= self.input.len() {
            if let Head::Whole(total, _) = self.head_at(at)
                && proto::verify(&self.input[at..at + total])
            {
                return Some(at);
            }
            at += 1;
        }
        None
    }

    /// Drops bytes up to the next possible frame start at or after `from`
    /// (the magic), keeping only the last bytes that could begin one if
    /// there is none.
    fn resync(&mut self, from: usize) {
        let next = (from..self.input.len().saturating_sub(proto::MAGIC.len() - 1))
            .find(|&at| self.input[at..at + proto::MAGIC.len()] == proto::MAGIC);
        match next {
            Some(at) => {
                self.input.drain(..at);
            }
            None => {
                let keep = self.input.len().saturating_sub(proto::MAGIC.len() - 1).max(from);
                self.input.drain(..keep.min(self.input.len()));
            }
        }
    }

    /// A new binding of the channel, or a released channel gone quiet:
    /// what is buffered is dropped. The caller drains what still waits in
    /// the pipe when it is a new binding.
    pub fn discard(&mut self) {
        self.input.clear();
        self.release_buffer();
    }
}
