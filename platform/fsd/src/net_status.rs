//! Fixed owner-written static-network sample. Bytes and common vectors are
//! specified in docs/net-status/RECORD.md. This is not a kernel or config ABI.

pub const PATH: &str = "/var/log/network-status";
pub const BYTES: usize = 512;
// Approximately hourly on the pinned x86 PIT; transitions publish sooner.
pub const PERIOD_TICKS: u64 = 3_600_000;
pub const MAX_AGE_TICKS: u64 = PERIOD_TICKS + 15_000;
const CHECK: usize = 504;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Carrier {
    Unknown,
    Down,
    Up,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    Defaults,
    File,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Listener {
    Listening,
    Fault,
    Draining,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    pub boot: [u8; 32],
    pub recovery: u64,
    pub start: u64,
    pub end: u64,
    pub address: [u8; 4],
    pub prefix: u8,
    pub gateway: Option<[u8; 4]>,
    pub carrier: Carrier,
    pub disabled: Option<bool>,
    pub origin: Origin,
    pub listener: Listener,
    pub port: u16,
}

fn check(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
    }
    hash
}

impl Record {
    fn valid(&self) -> bool {
        if self.recovery == 0
            || self.start > self.end
            || self.port == 0
            || !self
                .boot
                .iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
            || !(1..=30).contains(&self.prefix)
            || (self.carrier == Carrier::Unknown) != self.disabled.is_none()
        {
            return false;
        }
        // The exact static startup parser's usable-host and on-link rules.
        let mask = u32::MAX << (32 - self.prefix);
        let address = u32::from_be_bytes(self.address);
        let host = address & !mask;
        if host == 0 || host == !mask || matches!(self.address[0], 0 | 127 | 224..=255) {
            return false;
        }
        self.gateway.is_none_or(|g| {
            let gateway = u32::from_be_bytes(g);
            gateway != address
                && gateway & mask == address & mask
                && gateway & !mask != 0
                && gateway & !mask != !mask
        })
    }

    pub fn encode(&self) -> Option<[u8; BYTES]> {
        if !self.valid() {
            return None;
        }
        let mut out = [0u8; BYTES];
        out[..8].copy_from_slice(b"ABSDNET1");
        out[8..40].copy_from_slice(&self.boot);
        for (offset, value) in [(40, self.recovery), (48, self.start), (56, self.end)] {
            out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        out[64..68].copy_from_slice(&self.address);
        out[68] = self.prefix;
        if let Some(gateway) = self.gateway {
            out[69] = 1;
            out[70..74].copy_from_slice(&gateway);
        }
        out[74] = match self.carrier {
            Carrier::Unknown => 0,
            Carrier::Down => 1,
            Carrier::Up => 2,
        };
        out[75] = match self.disabled {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        };
        out[76] = match self.origin {
            Origin::Defaults => 0,
            Origin::File => 1,
        };
        out[77] = match self.listener {
            Listener::Listening => 0,
            Listener::Fault => 1,
            Listener::Draining => 2,
        };
        out[78..80].copy_from_slice(&self.port.to_le_bytes());
        let sum = check(&out[..CHECK]);
        out[CHECK..].copy_from_slice(&sum.to_le_bytes());
        Some(out)
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; BYTES] = bytes.try_into().ok()?;
        if &bytes[..8] != b"ABSDNET1"
            || bytes[80..CHECK].iter().any(|&b| b != 0)
            || check(&bytes[..CHECK]).to_le_bytes() != bytes[CHECK..]
        {
            return None;
        }
        let u64_at =
            |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed interval"));
        let gateway = match bytes[69] {
            0 if bytes[70..74] == [0; 4] => None,
            1 => Some(bytes[70..74].try_into().expect("fixed address")),
            _ => return None,
        };
        let record = Self {
            boot: bytes[8..40].try_into().expect("fixed boot"),
            recovery: u64_at(40),
            start: u64_at(48),
            end: u64_at(56),
            address: bytes[64..68].try_into().expect("fixed address"),
            prefix: bytes[68],
            gateway,
            carrier: match bytes[74] {
                0 => Carrier::Unknown,
                1 => Carrier::Down,
                2 => Carrier::Up,
                _ => return None,
            },
            disabled: match bytes[75] {
                0 => None,
                1 => Some(false),
                2 => Some(true),
                _ => return None,
            },
            origin: match bytes[76] {
                0 => Origin::Defaults,
                1 => Origin::File,
                _ => return None,
            },
            listener: match bytes[77] {
                0 => Listener::Listening,
                1 => Listener::Fault,
                2 => Listener::Draining,
                _ => return None,
            },
            port: u16::from_le_bytes(bytes[78..80].try_into().expect("fixed port")),
        };
        record.valid().then_some(record)
    }

    /// A retained log projection supplies recovery, not proof of latest PID.
    pub fn bind(
        &self,
        boot: Option<&[u8; 32]>,
        recovery: Option<u64>,
        start: u64,
        end: u64,
    ) -> View {
        let Some(boot) = boot else {
            return View::BootUnavailable;
        };
        if boot != &self.boot {
            return View::WrongBoot;
        }
        let Some(recovery) = recovery else {
            return View::RecoveryUnavailable;
        };
        if recovery != self.recovery {
            return View::Stale;
        }
        if start > end || self.start > self.end || self.end > end {
            return View::MalformedInterval;
        }
        let age = end - self.end;
        if age > MAX_AGE_TICKS {
            View::Stale
        } else {
            View::Retained { age }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum View {
    Retained { age: u64 },
    Stale,
    WrongBoot,
    BootUnavailable,
    RecoveryUnavailable,
    MalformedInterval,
}

/// Latest complete retained recovery projection, not a current server PID.
/// A later start without its recovery line invalidates an earlier summary.
/// Health v1's existing first-generation projection is deliberately unchanged.
pub fn recovery_seq(rotated: &[u8], current: &[u8], boot: &[u8; 32]) -> Option<u64> {
    if [rotated, current]
        .iter()
        .any(|b| !b.is_empty() && !b.ends_with(b"\n"))
    {
        return None;
    }
    let boot = core::str::from_utf8(boot).ok()?;
    let expected = alloc::format!("started: boot {boot}, ");
    let mut start = None;
    let mut recovery = None;
    for raw in rotated
        .split(|&b| b == b'\n')
        .chain(current.split(|&b| b == b'\n'))
    {
        if raw.is_empty() {
            continue;
        }
        let line = core::str::from_utf8(raw).ok()?;
        let Some((_, text)) = line.split_once(" fsd: ") else {
            continue;
        };
        if text.starts_with("started: boot ") {
            start = text.starts_with(&expected).then_some(raw);
            recovery = None;
        } else if start.is_some() && text.starts_with("FSD RECOVERY ") {
            if recovery.is_some() {
                return None;
            }
            recovery = Some(raw);
        }
    }
    crate::log::generation(start?, recovery?, boot)
        .ok()
        .map(|g| g.seq)
        .filter(|&seq| seq > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_exact_vectors() {
        for line in include_str!("../../docs/net-status/VECTORS.tsv")
            .lines()
            .filter(|l| !l.starts_with('#'))
        {
            let mut parts = line.split('\t');
            let name = parts.next().unwrap();
            let accept = parts.next().unwrap() == "accept";
            let hex = parts.next().unwrap();
            assert!(parts.next().is_none());
            let bytes: alloc::vec::Vec<u8> = hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            let parsed = Record::parse(&bytes);
            assert_eq!(parsed.is_some(), accept, "{name}");
            if let Some(record) = parsed {
                assert_eq!(&record.encode().unwrap()[..], bytes, "{name}");
            }
        }
    }

    fn record() -> Record {
        Record {
            boot: *b"0123456789abcdef0123456789abcdef",
            recovery: 7,
            start: 1000,
            end: 1001,
            address: [10, 0, 2, 15],
            prefix: 24,
            gateway: Some([10, 0, 2, 2]),
            carrier: Carrier::Up,
            disabled: Some(false),
            origin: Origin::Defaults,
            listener: Listener::Listening,
            port: 22,
        }
    }

    #[test]
    fn lifetime_and_exact_age_bound() {
        let r = record();
        assert_eq!(
            r.bind(
                Some(&r.boot),
                Some(7),
                1000 + MAX_AGE_TICKS,
                1001 + MAX_AGE_TICKS
            ),
            View::Retained { age: MAX_AGE_TICKS }
        );
        assert_eq!(
            r.bind(
                Some(&r.boot),
                Some(7),
                1001 + MAX_AGE_TICKS,
                1002 + MAX_AGE_TICKS
            ),
            View::Stale
        );
        assert_eq!(r.bind(Some(&r.boot), Some(8), 1001, 1001), View::Stale);
        assert_eq!(
            r.bind(
                Some(b"1123456789abcdef0123456789abcdef"),
                Some(7),
                1001,
                1001
            ),
            View::WrongBoot
        );
        assert_eq!(r.bind(None, Some(7), 1001, 1001), View::BootUnavailable);
        assert_eq!(
            r.bind(Some(&r.boot), None, 1001, 1001),
            View::RecoveryUnavailable
        );
        assert_eq!(
            r.bind(Some(&r.boot), Some(7), 999, 1000),
            View::MalformedInterval
        );
        assert_eq!(
            r.bind(Some(&r.boot), Some(7), 1002, 1001),
            View::MalformedInterval
        );
    }

    #[test]
    fn same_boot_recovery_projection_tracks_supersession() {
        let r = record();
        let old = alloc::format!(
            "time fsd: started: boot {}, other\ntime fsd: FSD RECOVERY seq=7 streak=0 previous=none\n",
            core::str::from_utf8(&r.boot).unwrap()
        );
        let next = alloc::format!(
            "time fsd: started: boot {}, other\ntime fsd: FSD RECOVERY seq=8 streak=1 previous=failed\n",
            core::str::from_utf8(&r.boot).unwrap()
        );
        assert_eq!(
            recovery_seq(old.as_bytes(), next.as_bytes(), &r.boot),
            Some(8)
        );
        assert_eq!(
            recovery_seq(
                old.as_bytes(),
                next.lines().next().unwrap().as_bytes(),
                &r.boot
            ),
            None
        );
        let start_only = alloc::format!("{}\n", next.lines().next().unwrap());
        assert_eq!(
            recovery_seq(old.as_bytes(), start_only.as_bytes(), &r.boot),
            None
        );
        assert_eq!(r.bind(Some(&r.boot), Some(8), 1001, 1001), View::Stale);
    }
}
