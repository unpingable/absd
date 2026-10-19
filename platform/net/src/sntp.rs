//! Foreground observation only: no clock discipline, UTC trust or TLS input.
//! RFC 5905 packet fields; random transmit/origin correlation per RFC 8915 §9.2.
use crate::{
    datagram,
    dns::{self, Transport},
};

pub const ATTEMPTS: usize = 3;
pub const ATTEMPT_MS: u64 = 2000;
pub const TOTAL_MS: u64 = 8000;
pub const MIN_UNIX: u64 = 1_767_225_600; // 2026-01-01T00:00:00Z
pub const MAX_UNIX: u64 = 2_082_758_340; // 2035-12-31T23:59:00Z, inclusive
const NTP_UNIX: u64 = 2_208_988_800;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Length,
    Header,
    Leap,
    KoD,
    Stratum,
    Origin,
    Zero,
    Reversed,
    Duplicate,
    EraUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Refused(Refusal),
    Entropy,
    Clock,
    Timeout,
    Late,
    Retired,
    Transport(dns::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub unix_seconds: u64,
    pub fraction_2p32: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub claim: Claim,
    pub rtc: Result<u64, i64>,
    pub boot_sent_ms: u64,
    pub boot_received_ms: u64,
    pub boot_rtt_ms: u64,
    pub attempt: u8,
}
impl Observation {
    /// Whole-second subtraction only, never an NTP clock offset or accuracy bound.
    pub fn unauthenticated_difference(&self) -> Option<i128> {
        self.rtc
            .ok()
            .map(|rtc| i128::from(self.claim.unix_seconds) - i128::from(rtc))
    }
}
fn stamp(packet: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(packet[at..at + 8].try_into().unwrap())
}
/// Pure, narrow reply parser. Correlation supplies no server authentication.
pub fn parse_reply(packet: &[u8], nonce: [u8; 8]) -> Result<Claim, Refusal> {
    if packet.len() != 48 {
        return Err(Refusal::Length);
    }
    if packet[24..32] != nonce || nonce == [0; 8] {
        return Err(Refusal::Origin);
    }
    if packet[0] & 0x3f != 0x24 {
        return Err(Refusal::Header);
    }
    if packet[0] >> 6 != 0 {
        return Err(Refusal::Leap);
    }
    if packet[1] == 0 {
        return Err(Refusal::KoD);
    }
    if packet[1] > 15 {
        return Err(Refusal::Stratum);
    }
    let reference = stamp(packet, 16);
    let received = stamp(packet, 32);
    let transmitted = stamp(packet, 40);
    if reference == 0 || received == 0 || transmitted == 0 {
        return Err(Refusal::Zero);
    }
    if reference == received || reference == transmitted || received == transmitted {
        return Err(Refusal::Duplicate);
    }
    if reference > received || received > transmitted {
        return Err(Refusal::Reversed);
    }
    let seconds = (transmitted >> 32)
        .checked_sub(NTP_UNIX)
        .ok_or(Refusal::EraUnknown)?;
    let fraction = transmitted as u32;
    if !(MIN_UNIX..=MAX_UNIX).contains(&seconds) || (seconds == MAX_UNIX && fraction != 0) {
        return Err(Refusal::EraUnknown);
    }
    Ok(Claim {
        unix_seconds: seconds,
        fraction_2p32: fraction,
    })
}

/// Owns one exact delegated UDP transport for one invocation. No reply accepted
/// after success/failure, and no transport is returned to a subsequent query.
pub struct Query<T: Transport> {
    transport: T,
    spent: bool,
    last_ms: u64,
    until: Option<u64>,
}
impl<T: Transport> Query<T> {
    pub fn new(transport: T) -> Self {
        let started_ms = transport.now_ms();
        Self::with_start(transport, started_ms, started_ms)
    }
    /// Includes native startup/pipe admission in the same boot-domain budget.
    pub fn with_start(transport: T, started_ms: u64, last_ms: u64) -> Self {
        Self {
            transport,
            spent: false,
            last_ms,
            until: (last_ms >= started_ms)
                .then(|| started_ms.checked_add(TOTAL_MS))
                .flatten(),
        }
    }
    fn now(&mut self, deadline: u64) -> Result<u64, Error> {
        let now = self.transport.now_ms();
        if now < self.last_ms {
            return Err(Error::Clock);
        }
        self.last_ms = now;
        if now >= deadline {
            return Err(Error::Timeout);
        }
        Ok(now)
    }
    pub fn observe<E>(
        &mut self,
        entropy: impl FnMut(&mut [u8]) -> Result<(), E>,
        rtc: impl FnMut() -> Result<u64, i64>,
    ) -> Result<Observation, Error> {
        if self.spent {
            return Err(Error::Retired);
        }
        self.spent = true;
        self.inner(entropy, rtc)
    }
    fn inner<E>(
        &mut self,
        mut entropy: impl FnMut(&mut [u8]) -> Result<(), E>,
        mut rtc: impl FnMut() -> Result<u64, i64>,
    ) -> Result<Observation, Error> {
        let until = self.until.ok_or(Error::Clock)?;
        self.now(until)?;
        let mut nonces = [[0; 8]; ATTEMPTS];
        for attempt in 0..ATTEMPTS {
            let start = self.now(until)?;
            let deadline = start
                .checked_add(ATTEMPT_MS)
                .ok_or(Error::Clock)?
                .min(until);
            let mut nonce = [0; 8];
            entropy(&mut nonce).map_err(|_| Error::Entropy)?;
            self.now(deadline)?;
            if nonce == [0; 8] || nonces[..attempt].contains(&nonce) {
                return Err(Error::Entropy);
            }
            nonces[attempt] = nonce;
            let mut request = [0; 48];
            request[0] = 0x23; // LI=0, VN=4, mode=3; transmit is a nonce, not UTC.
            request[40..48].copy_from_slice(&nonce);
            let sent = self.now(deadline)?;
            // An uncertain IPC send retires the invocation, never retransmits it.
            self.transport
                .send(&request, deadline)
                .map_err(Error::Transport)?;
            self.now(deadline)
                .map_err(|e| if e == Error::Timeout { Error::Late } else { e })?;
            loop {
                match self.now(deadline) {
                    Ok(_) => {}
                    Err(Error::Timeout) => break,
                    Err(error) => return Err(error),
                }
                let mut packet = [0; datagram::MAX_DATAGRAM];
                let received = self
                    .transport
                    .receive(&mut packet, deadline)
                    .map_err(Error::Transport)?;
                let after = match self.now(deadline) {
                    Ok(now) => now,
                    Err(Error::Timeout) if received.is_none() => break,
                    Err(Error::Timeout) => return Err(Error::Late),
                    Err(error) => return Err(error),
                };
                if let Some(length) = received {
                    let packet = packet
                        .get(..length)
                        .ok_or(Error::Refused(Refusal::Length))?;
                    let claim = parse_reply(packet, nonce).map_err(Error::Refused)?;
                    let rtc = rtc();
                    self.now(deadline)
                        .map_err(|e| if e == Error::Timeout { Error::Late } else { e })?;
                    return Ok(Observation {
                        claim,
                        rtc,
                        boot_sent_ms: sent,
                        boot_received_ms: after,
                        boot_rtt_ms: after.checked_sub(sent).ok_or(Error::Clock)?,
                        attempt: (attempt + 1) as u8,
                    });
                }
                self.transport.pause(1);
            }
        }
        Err(Error::Timeout)
    }
}
#[cfg(test)]
mod tests;
