//! Private native routed-DNS fixture schema; these bytes never grant authority.
pub const TOTAL_MS: u64 = 12_000;
pub const BOOTSTRAP_LEN: usize = 48;
pub const LOCAL: [u8; 16] = [0xfd, 0, 0xab, 0x5d, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x15];
pub const ROUTER: [u8; 16] = [0xfd, 0, 0xab, 0x5d, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
pub const PEER: [u8; 16] = [0xfd, 0, 0xab, 0x5d, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
pub const SCOPE: u32 = 1;
pub const PORT: u16 = 42010;
pub const LOCAL_PORT: u16 = 7002;

pub fn bootstrap(start: u64) -> Result<[u8; BOOTSTRAP_LEN], &'static str> {
    let stop = start
        .checked_add(TOTAL_MS)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or("budget overflow")?;
    let mut b = [0; BOOTSTRAP_LEN];
    b[..4].copy_from_slice(&[1, 6, 0, 0]);
    b[4..20].copy_from_slice(&PEER);
    b[20..24].copy_from_slice(&SCOPE.to_be_bytes());
    b[24..26].copy_from_slice(&PORT.to_be_bytes());
    b[32..40].copy_from_slice(&start.to_be_bytes());
    b[40..48].copy_from_slice(&stop.to_be_bytes());
    Ok(b)
}
pub fn decode(
    b: &[u8; BOOTSTRAP_LEN],
    expected_start: u64,
    expected_stop: u64,
) -> Result<(), &'static str> {
    if *b != bootstrap(expected_start)?
        || u64::from_be_bytes(b[40..48].try_into().unwrap()) != expected_stop
    {
        return Err("bootstrap policy/startup disagreement");
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Clock,
    Expired,
    Fault,
}
pub struct Budget {
    last: u64,
    stop: u64,
    error: Option<Error>,
}
impl Budget {
    pub fn new(start: u64, stop: u64) -> Result<Self, &'static str> {
        if start.checked_add(TOTAL_MS) != Some(stop) || stop > i64::MAX as u64 {
            return Err("budget identity");
        }
        Ok(Self {
            last: start,
            stop,
            error: None,
        })
    }
    pub fn check(&mut self, now: u64) -> Result<u64, Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let error = if now < self.last || now > i64::MAX as u64 {
            Some(Error::Clock)
        } else if now >= self.stop {
            Some(Error::Expired)
        } else {
            None
        };
        self.last = now;
        if let Some(error) = error {
            self.error = Some(error);
            return Err(error);
        }
        Ok(self.stop - now)
    }
    pub fn fault(&mut self) {
        self.error.get_or_insert(Error::Fault);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_bootstrap_and_every_policy_byte_are_fixed() {
        let golden = [
            1, 6, 0, 0, 253, 0, 171, 93, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 1, 164, 26,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 47, 68,
        ];
        assert_eq!(bootstrap(100).unwrap(), golden);
        assert_eq!(decode(&golden, 100, 12100), Ok(()));
        for i in 0..BOOTSTRAP_LEN {
            let mut b = golden;
            b[i] ^= 1;
            assert!(decode(&b, 100, 12100).is_err(), "{i}");
        }
        assert!(decode(&golden, 101, 12101).is_err());
    }
    #[test]
    fn overflow_and_changed_original_deadlines_are_refused() {
        for start in [u64::MAX, i64::MAX as u64, i64::MAX as u64 - TOTAL_MS + 1] {
            assert!(bootstrap(start).is_err());
        }
        assert!(Budget::new(100, 12101).is_err());
        assert!(Budget::new(100, 12099).is_err());
    }
    #[test]
    fn rewind_expiry_and_fault_are_sticky_without_new_authority() {
        for which in 0..3 {
            let mut b = Budget::new(100, 12100).unwrap();
            assert_eq!(b.check(101), Ok(11999));
            let error = match which {
                0 => {
                    assert_eq!(b.check(100), Err(Error::Clock));
                    Error::Clock
                }
                1 => {
                    assert_eq!(b.check(12100), Err(Error::Expired));
                    Error::Expired
                }
                _ => {
                    b.fault();
                    Error::Fault
                }
            };
            assert_eq!(b.check(102), Err(error));
            b.fault();
            assert_eq!(b.check(103), Err(error));
        }
    }
}
