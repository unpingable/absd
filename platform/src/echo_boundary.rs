//! Private finite qualification helpers. No production Echo authority changes.
#[cfg(test)]
use crate::{
    FRAME_MAX, Link, LinkReading,
    echo::{self, Endpoint, Owner, Pipe},
};
#[cfg(not(test))]
use absd_net::{
    FRAME_MAX, Link, LinkReading,
    echo::{self, Endpoint, Owner, Pipe},
};
use std::{cell::Cell, rc::Rc, vec::Vec};

pub const WHOLE_MS: u64 = 20_000;
pub const PEER: [u8; 4] = [192, 0, 2, 1];
pub const REQUESTS: [[u8; 8]; 7] = [
    [0, 1, 0, 0, 192, 0, 2, 1],
    [1, 127, 0, 0, 192, 0, 2, 1],
    [1, 1, 1, 0, 192, 0, 2, 1],
    [1, 1, 0, 1, 192, 0, 2, 1],
    [1, 1, 0, 0, 192, 0, 2, 2],
    [1, 2, 0, 0, 192, 0, 2, 2],
    [1, 3, 0, 0, 192, 0, 2, 2],
];
pub const CODES: [u8; 7] = [1, 1, 1, 1, 2, 2, 2];
pub fn reply(index: usize) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[..4].copy_from_slice(&[1, REQUESTS[index][1], CODES[index], 0]);
    bytes
}
pub fn ledger_matches(input: &[u8], output: &[u8]) -> bool {
    input.len() == 57
        && input[..56] == REQUESTS.concat()
        && input[56] == 0
        && output == (0..7).flat_map(reply).collect::<Vec<_>>()
}
pub fn clock(last: &mut u64, until: u64, now: u64) -> Result<(), &'static str> {
    if now < *last || now >= until {
        return Err("boundary clock/deadline");
    }
    *last = now;
    Ok(())
}
pub fn before_frame(pre_poll: u64, until: u64, now: u64) -> bool {
    now >= pre_poll
        && now < until
        && pre_poll
            .checked_add(echo::FRAME_MS)
            .is_some_and(|end| now < end)
}

pub struct CountedLink<L> {
    pub inner: L,
    pub sends: Rc<Cell<u64>>,
}
impl<L: Link> Link for CountedLink<L> {
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
        self.sends.set(self.sends.get().saturating_add(1));
        self.inner.send(bytes)
    }
    fn receive(
        &mut self,
        buffer: &mut [u8; FRAME_MAX],
        timeout: u64,
    ) -> Result<Option<usize>, i64> {
        self.inner.receive(buffer, timeout)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadStamp {
    pub before: u64,
    pub after: u64,
    pub bytes: usize,
}
pub struct ObservedPipe<P> {
    pub inner: P,
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub prefix: Option<ReadStamp>,
    pub eof: Option<ReadStamp>,
    pub prefix_at: Option<usize>,
}
impl<P: Pipe> ObservedPipe<P> {
    pub fn new(inner: P, prefix_at: Option<usize>) -> Self {
        Self {
            inner,
            input: Vec::new(),
            output: Vec::new(),
            prefix: None,
            eof: None,
            prefix_at,
        }
    }
}
impl<P: Pipe> Pipe for ObservedPipe<P> {
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        let before = self.inner.now_ms();
        let result = self.inner.read(bytes)?;
        let after = self.inner.now_ms();
        if let Some(n) = result {
            if n > bytes.len() || self.input.len().saturating_add(n) > 65_536 {
                return Err(-5);
            }
            let stamp = ReadStamp {
                before,
                after,
                bytes: n,
            };
            if n == 0 && self.eof.is_none() {
                self.eof = Some(stamp);
            }
            if n > 0 && self.prefix_at == Some(self.input.len()) {
                self.prefix = Some(stamp);
            }
            self.input.extend_from_slice(&bytes[..n]);
        }
        Ok(result)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        let result = self.inner.write(bytes)?;
        if let Some(n) = result {
            if n > bytes.len() || self.output.len().saturating_add(n) > 65_536 {
                return Err(-5);
            }
            self.output.extend_from_slice(&bytes[..n]);
        }
        Ok(result)
    }
}
/// The same sequence is used by the native parent and real Owner host controls.
/// The successful constructor grant is closed here, without START or poll.
pub fn constructors<L: Link>(
    owner: &mut Owner<L>,
    now: u64,
    until: u64,
    mut entropy: impl FnMut(&mut [u8]) -> Result<(), i64>,
) -> Result<(Vec<(&'static str, u8, usize)>, Endpoint), &'static str> {
    let mut rows = Vec::new();
    for (name, peer) in [
        ("unspecified", [0, 0, 0, 0]),
        ("loopback", [127, 0, 0, 1]),
        ("multicast", [224, 0, 0, 1]),
        ("local", [192, 0, 2, 100]),
        ("subnet", [192, 0, 2, 0]),
        ("broadcast", [192, 0, 2, 255]),
        ("off-link", [192, 0, 3, 1]),
    ] {
        let err = owner
            .grant(peer, until, &mut entropy)
            .err()
            .ok_or("invalid peer accepted")?;
        if err != echo::Error::Denied || owner.socket_count() != 0 {
            return Err("peer refusal");
        }
        rows.push((name, err.code(), owner.socket_count()));
    }
    for (name, deadline) in [
        ("expired", now),
        ("too-long", now.checked_add(16_000).ok_or("overflow")?),
    ] {
        let err = owner
            .grant(PEER, deadline, &mut entropy)
            .err()
            .ok_or("invalid lifetime accepted")?;
        if err != echo::Error::Invalid || owner.socket_count() != 0 {
            return Err("lifetime refusal");
        }
        rows.push((name, err.code(), owner.socket_count()));
    }
    for (name, zero) in [("entropy-error", false), ("entropy-zero", true)] {
        let err = owner
            .grant(PEER, until, |b| {
                b.fill(0);
                if zero { Ok(()) } else { Err(-5) }
            })
            .err()
            .ok_or("bad entropy accepted")?;
        if err != echo::Error::Entropy || owner.socket_count() != 0 {
            return Err("entropy refusal");
        }
        rows.push((name, err.code(), owner.socket_count()));
    }
    let old = owner
        .grant(PEER, until, &mut entropy)
        .map_err(|_| "constructor grant")?;
    let err = owner
        .grant(PEER, until, &mut entropy)
        .err()
        .ok_or("second grant accepted")?;
    if err != echo::Error::Exhausted || owner.socket_count() != 1 {
        return Err("slot refusal");
    }
    rows.push(("second-grant", err.code(), owner.socket_count()));
    owner.close(old).map_err(|_| "constructor close")?;
    let err = owner
        .start(old, PEER)
        .err()
        .ok_or("closed endpoint started")?;
    if err != echo::Error::Stale || owner.socket_count() != 0 {
        return Err("closed stale");
    }
    rows.push(("closed-stale", err.code(), owner.socket_count()));
    Ok((rows, old))
}
