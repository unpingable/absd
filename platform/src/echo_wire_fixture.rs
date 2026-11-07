//! Private qualification-only observer; no production Link or Echo changes.
#[cfg(test)]
use crate::{FRAME_MAX, Link, LinkReading};
#[cfg(not(test))]
use absd_net::{FRAME_MAX, Link, LinkReading};
use std::{cell::RefCell, rc::Rc, vec::Vec};
pub const LOCAL: [u8; 4] = [192, 0, 2, 100];
pub const PEER: [u8; 4] = [192, 0, 2, 1];
pub const CASES: [&str; 9] = [
    "wrong-peer",
    "wrong-type",
    "wrong-code",
    "wrong-identifier",
    "wrong-sequence",
    "wrong-body",
    "wrong-epoch",
    "wrong-nonce",
    "bad-checksum",
];
pub const WHOLE_MS: u64 = 20_000;
#[derive(Clone, Debug)]
pub struct Frame {
    pub tx: bool,
    pub ordinal: usize,
    pub phase: usize,
    pub at_ms: u64,
    pub bytes: Vec<u8>,
}
#[derive(Default)]
pub struct Trace {
    pub frames: Vec<Frame>,
    pub rx: usize,
    pub tx: usize,
    pub phase: usize,
}
impl Trace {
    fn push(&mut self, tx: bool, at_ms: u64, bytes: &[u8]) -> Result<(), i64> {
        if bytes.len() > FRAME_MAX || (if tx { self.tx >= 16 } else { self.rx >= 32 }) {
            return Err(-5);
        }
        if tx {
            self.tx += 1;
        } else {
            self.rx += 1;
        }
        self.frames.push(Frame {
            tx,
            ordinal: if tx { self.tx } else { self.rx },
            phase: self.phase,
            at_ms,
            bytes: bytes.to_vec(),
        });
        Ok(())
    }
    pub fn requests(&self, phase: usize) -> usize {
        self.frames
            .iter()
            .filter(|f| f.phase == phase && f.tx && is_request(&f.bytes))
            .count()
    }
    pub fn request(&self, phase: usize) -> Option<&[u8]> {
        self.frames
            .iter()
            .find(|f| f.phase == phase && f.tx && is_request(&f.bytes))
            .map(|f| f.bytes.as_slice())
    }
}
pub fn is_request(frame: &[u8]) -> bool {
    frame.len() == 74
        && frame[12..14] == [8, 0]
        && frame[14] == 0x45
        && frame[23] == 1
        && frame[34..36] == [8, 0]
}
pub struct ReceiptLink<L> {
    pub inner: L,
    pub trace: Rc<RefCell<Trace>>,
}
impl<L: Link> Link for ReceiptLink<L> {
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn pause(&self, ms: u64) {
        self.inner.pause(ms)
    }
    fn link_up(&self) -> bool {
        self.inner.link_up()
    }
    fn disabled(&self) -> bool {
        self.inner.disabled()
    }
    fn read(&self) -> Option<LinkReading> {
        self.inner.read()
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), i64> {
        // Only successful local submissions enter this transcript. An Err
        // remains a failure; absence here never proves absence of wire effect.
        self.inner.send(bytes)?;
        self.trace
            .borrow_mut()
            .push(true, self.inner.now_ms(), bytes)
    }
    fn receive(&mut self, bytes: &mut [u8; FRAME_MAX], timeout: u64) -> Result<Option<usize>, i64> {
        let result = self.inner.receive(bytes, timeout)?;
        if let Some(n) = result {
            if n > FRAME_MAX {
                return Err(-5);
            }
            self.trace
                .borrow_mut()
                .push(false, self.inner.now_ms(), &bytes[..n])?;
        }
        Ok(result)
    }
}
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += (u16::from(pair[0]) << 8 | u16::from(*pair.get(1).unwrap_or(&0))) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
/// Exact selected input contract, derived from the actual successful request.
/// This describes a substitution fixture, not authenticated origin or history.
pub fn selected_reply(request: &[u8], index: usize) -> Result<Vec<u8>, &'static str> {
    if index >= CASES.len()
        || !is_request(request)
        || request[26..30] != LOCAL
        || request[30..34] != PEER
        || request[16..18] != [0, 60]
        || checksum(&request[14..34]) != 0
        || checksum(&request[34..]) != 0
    {
        return Err("not exact submitted request");
    }
    let mut frame = request.to_vec();
    frame[..6].copy_from_slice(&request[6..12]);
    frame[6..12].copy_from_slice(&request[..6]);
    frame[26..30].copy_from_slice(&PEER);
    frame[30..34].copy_from_slice(&LOCAL);
    frame[34] = 0;
    match index {
        0 => frame[29] = 2,
        1 => frame[34] = 3,
        2 => frame[35] = 1,
        3 => frame[38] ^= 1,
        4 => frame[40] ^= 1,
        5 => frame[42] ^= 1,
        6 => frame[58] ^= 1,
        7 => frame[66] ^= 1,
        8 => {}
        _ => unreachable!(),
    }
    frame[24..26].fill(0);
    let value = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&value.to_be_bytes());
    frame[36..38].fill(0);
    let value = checksum(&frame[34..]);
    frame[36..38].copy_from_slice(&value.to_be_bytes());
    if index == 8 {
        frame[36] ^= 1;
    }
    Ok(frame)
}
pub fn matches_case(request: &[u8], received: &[u8], index: usize) -> bool {
    selected_reply(request, index).is_ok_and(|expected| expected == received)
}
pub fn clock(last: &mut u64, until: u64, now: u64) -> Result<(), &'static str> {
    if now < *last || now >= until {
        return Err("wire fixture clock/deadline");
    }
    *last = now;
    Ok(())
}
