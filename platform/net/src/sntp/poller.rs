//! Nonblocking SNTP observation state for an existing NIC-owner poll loop.
//! One step consumes at most one reply; no civil clock enters deadlines.
use super::{ATTEMPT_MS, ATTEMPTS, Claim, Error, TOTAL_MS, parse_reply};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    None,
    Send([u8; 48]),
    Accepted { claim: Claim, rtt_ms: u64 },
    Failed(Error),
}
pub struct Poller {
    active: bool,
    attempt: usize,
    nonces: [[u8; 8]; ATTEMPTS],
    last: u64,
    sent: u64,
    deadline: u64,
    until: u64,
}
impl Default for Poller {
    fn default() -> Self {
        Self::new()
    }
}
impl Poller {
    pub const fn new() -> Self {
        Self {
            active: false,
            attempt: 0,
            nonces: [[0; 8]; ATTEMPTS],
            last: 0,
            sent: 0,
            deadline: 0,
            until: 0,
        }
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn start(&mut self, now: u64, entropy: impl FnMut(&mut [u8]) -> Result<(), ()>) -> Action {
        if self.active {
            return Action::None;
        }
        self.attempt = 0;
        self.nonces = [[0; 8]; ATTEMPTS];
        self.last = now;
        let Some(until) = now.checked_add(TOTAL_MS) else {
            return Action::Failed(Error::Clock);
        };
        self.until = until;
        self.active = true;
        self.send(now, entropy)
    }
    fn fail(&mut self, error: Error) -> Action {
        self.active = false;
        Action::Failed(error)
    }
    fn send(&mut self, now: u64, mut entropy: impl FnMut(&mut [u8]) -> Result<(), ()>) -> Action {
        let mut nonce = [0; 8];
        if entropy(&mut nonce).is_err()
            || nonce == [0; 8]
            || self.nonces[..self.attempt].contains(&nonce)
        {
            return self.fail(Error::Entropy);
        }
        self.nonces[self.attempt] = nonce;
        self.attempt += 1;
        self.sent = now;
        self.deadline = now.saturating_add(ATTEMPT_MS).min(self.until);
        let mut packet = [0; 48];
        packet[0] = 0x23;
        packet[40..48].copy_from_slice(&nonce);
        Action::Send(packet)
    }
    pub fn step(
        &mut self,
        now: u64,
        packet: Option<&[u8]>,
        entropy: impl FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Action {
        if !self.active {
            return Action::None;
        }
        if now < self.last {
            return self.fail(Error::Clock);
        }
        self.last = now;
        if now >= self.until {
            return self.fail(Error::Timeout);
        }
        if now >= self.deadline {
            if packet.is_some() {
                return self.fail(Error::Late);
            }
            if self.attempt >= ATTEMPTS {
                return self.fail(Error::Timeout);
            }
            return self.send(now, entropy);
        }
        if let Some(bytes) = packet {
            match parse_reply(bytes, self.nonces[self.attempt - 1]) {
                Ok(claim) => {
                    self.active = false;
                    Action::Accepted {
                        claim,
                        rtt_ms: now - self.sent,
                    }
                }
                Err(reason) => self.fail(Error::Refused(reason)),
            }
        } else {
            Action::None
        }
    }
    pub fn cancel(&mut self) {
        self.active = false;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sntp::Refusal;
    fn entropy(out: &mut [u8]) -> Result<(), ()> {
        out.fill(1);
        Ok(())
    }
    fn reply(nonce: &[u8]) -> [u8; 48] {
        let mut p = [0; 48];
        p[0] = 0x24;
        p[1] = 2;
        p[24..32].copy_from_slice(nonce);
        for (at, n) in [
            (16, 3_976_214_400u64),
            (32, 3_976_214_401),
            (40, 3_976_214_402),
        ] {
            p[at..at + 8].copy_from_slice(&(n << 32).to_be_bytes());
        }
        p
    }
    #[test]
    fn nonce_reply_is_accepted_once_and_deadline_is_boot_domain() {
        let mut p = Poller::new();
        let Action::Send(request) = p.start(10, entropy) else {
            panic!()
        };
        let packet = reply(&request[40..48]);
        assert!(matches!(
            p.step(20, Some(&packet), entropy),
            Action::Accepted { rtt_ms: 10, .. }
        ));
        assert_eq!(p.step(21, Some(&packet), entropy), Action::None);
    }
    #[test]
    fn late_regressed_wrong_origin_and_zero_entropy_refuse() {
        let mut p = Poller::new();
        p.start(10, entropy);
        assert_eq!(p.step(9, None, entropy), Action::Failed(Error::Clock));
        p.start(10, entropy);
        assert_eq!(
            p.step(2010, Some(&[0; 48]), entropy),
            Action::Failed(Error::Late)
        );
        p.start(10, entropy);
        assert_eq!(
            p.step(11, Some(&reply(&[9; 8])), entropy),
            Action::Failed(Error::Refused(Refusal::Origin))
        );
        assert_eq!(
            p.start(10, |o| {
                o.fill(0);
                Ok(())
            }),
            Action::Failed(Error::Entropy)
        );
    }
    #[test]
    fn bounded_retry_cannot_reuse_nonce_or_wait_forever() {
        let mut p = Poller::new();
        p.start(0, entropy);
        assert_eq!(p.step(2000, None, entropy), Action::Failed(Error::Entropy));
        let mut n = 0u8;
        let mut random = |out: &mut [u8]| {
            n += 1;
            out.fill(n);
            Ok(())
        };
        p.start(0, &mut random);
        assert!(matches!(p.step(2000, None, &mut random), Action::Send(_)));
        assert!(matches!(p.step(4000, None, &mut random), Action::Send(_)));
        assert_eq!(
            p.step(6000, None, &mut random),
            Action::Failed(Error::Timeout)
        );
    }
}
