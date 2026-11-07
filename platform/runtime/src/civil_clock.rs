//! Boot-local software civil time; monotonic deadlines use ticks separately.
pub const INFO_BYTES: usize = 96;
pub const NS: u64 = 1_000_000_000;
/// Fixed reproducible RTC bootstrap floor, not a host build timestamp.
pub const MIN_RTC_UNIX_SECONDS: u64 = 1_767_225_600; // 2026-01-01T00:00:00Z
pub const RTC: u32 = 1;
pub const MANUAL: u32 = 2;
pub const SNTP_UNAUTHENTICATED: u32 = 3;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    pub flags: u32,
    pub source: u32,
    pub attempt_source: u32,
    pub unix_ns: Option<u64>,
    pub sample_tick: u64,
    pub now_tick: u64,
    pub age_ticks: u64,
    pub generation: u64,
    pub last_attempt_tick: u64,
    pub last_error: i64,
    pub peer: u32,
    pub rtt_ms: u32,
    pub max_age_ticks: u64,
    pub attempt_peer: u32,
    pub peer_port: u16,
    pub attempt_peer_port: u16,
}
impl Info {
    pub fn stale(&self) -> bool {
        self.flags & 2 != 0
    }
    pub fn source_name(&self) -> &'static str {
        source_name(self.source)
    }
}
/// Common status renderer for date and the authenticated owner's clock status.
pub struct Status<'a> {
    info: &'a Info,
    raw_rtc: Result<u64, i64>,
}
impl Info {
    pub fn status(&self, raw_rtc: Result<u64, i64>) -> Status<'_> {
        Status {
            info: self,
            raw_rtc,
        }
    }
}
struct Peer(u32, u16);
impl core::fmt::Display for Peer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.1 == 0 {
            return f.write_str("none");
        }
        let ip = self.0.to_be_bytes();
        write!(f, "{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], self.1)
    }
}
impl core::fmt::Display for Status<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let i = self.info;
        let synchronization = if i.unix_ns.is_none() {
            "unavailable"
        } else if i.source != SNTP_UNAUTHENTICATED {
            "unsynchronized"
        } else if i.stale() {
            "stale"
        } else {
            "unauthenticated-estimate-current"
        };
        write!(
            f,
            "source={} known={} synchronization={} stale={} age_ticks=",
            i.source_name(),
            i.unix_ns.is_some(),
            synchronization,
            i.stale()
        )?;
        if i.age_ticks == u64::MAX {
            f.write_str("unknown")?;
        } else {
            write!(f, "{}", i.age_ticks)?;
        }
        write!(
            f,
            " generation={} utc_uncertainty=unknown last_attempt_tick={} last_error={} last_attempt_source={} last_success_tick=",
            i.generation,
            i.last_attempt_tick,
            i.last_error,
            source_name(i.attempt_source)
        )?;
        if i.unix_ns.is_some() {
            write!(f, "{}", i.sample_tick)?;
        } else {
            f.write_str("unknown")?;
        }
        write!(
            f,
            " last_success_rtt_ms={} peer={} attempt_peer={}",
            i.rtt_ms,
            Peer(i.peer, i.peer_port),
            Peer(i.attempt_peer, i.attempt_peer_port)
        )?;
        if i.attempt_source == RTC && i.last_error == -116 {
            f.write_str(" last_error_reason=rtc-before-build-floor")?;
        }
        match self.raw_rtc {
            Ok(raw) => {
                write!(f, " raw_rtc_seconds={raw} civil_minus_raw_rtc_ns=")?;
                if let Some(ns) = i.unix_ns {
                    write!(f, "{}", i128::from(ns) - i128::from(raw) * i128::from(NS))?;
                } else {
                    f.write_str("unknown")?;
                }
                f.write_str(" raw_rtc_error=0")?;
            }
            Err(error) => write!(
                f,
                " raw_rtc_seconds=unknown civil_minus_raw_rtc_ns=unknown raw_rtc_error={error}"
            )?,
        }
        // This describes only the raw RTC reading's lower-bound check. It
        // neither authenticates a source nor rejects an explicit operator date.
        let rtc_bootstrap = match self.raw_rtc {
            Ok(raw) if raw < MIN_RTC_UNIX_SECONDS => "before-build-floor",
            Ok(_) => "not-before-build-floor",
            Err(_) => "unavailable",
        };
        write!(
            f,
            " rtc_bootstrap_floor_seconds={MIN_RTC_UNIX_SECONDS} raw_rtc_bootstrap={rtc_bootstrap}"
        )?;
        f.write_str(" rtc_comparison=adjacent-second-samples")
    }
}
pub fn source_name(source: u32) -> &'static str {
    match source {
        RTC => "rtc-unverified",
        MANUAL => "operator-asserted",
        SNTP_UNAUTHENTICATED => "sntp-unauthenticated-estimate",
        _ => "unknown",
    }
}
pub fn decode(b: &[u8; INFO_BYTES]) -> Result<Info, i64> {
    let word = |at| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let n = |at| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    if n(0) != 1 || n(4) & !3 != 0 || n(8) > 3 || n(12) > 3 {
        return Err(-22);
    }
    if n(4) & 1 != 0
        && (n(8) == 0 || word(48) == 0 || word(24) > word(32) || word(40) != word(32) - word(24))
    {
        return Err(-22);
    }
    if n(4) & 1 == 0 && word(16) != u64::MAX {
        return Err(-22);
    }
    let port = u16::from_le_bytes(b[92..94].try_into().unwrap());
    let attempt_port = u16::from_le_bytes(b[94..96].try_into().unwrap());
    if (n(8) != 3 && port != 0)
        || (n(12) != 3 && attempt_port != 0)
        || (n(8) == 3 && port == 0)
        || (n(12) == 3 && attempt_port == 0)
        || n(76) > 8000
    {
        return Err(-22);
    }
    let unix_ns = if n(4) & 1 != 0 {
        if word(16) == u64::MAX {
            return Err(-22);
        }
        Some(word(16))
    } else {
        None
    };
    Ok(Info {
        flags: n(4),
        source: n(8),
        attempt_source: n(12),
        unix_ns,
        sample_tick: word(24),
        now_tick: word(32),
        age_ticks: word(40),
        generation: word(48),
        last_attempt_tick: word(56),
        last_error: word(64) as i64,
        peer: n(72),
        rtt_ms: n(76),
        max_age_ticks: word(80),
        attempt_peer: n(88),
        peer_port: port,
        attempt_peer_port: attempt_port,
    })
}
pub fn info() -> Result<Info, i64> {
    let mut b = [0; INFO_BYTES];
    let r = unsafe { crate::syscall3(0x7fb0, b.as_mut_ptr() as u64, 0, 0) };
    if r < 0 { Err(r) } else { decode(&b) }
}
pub fn set_request(
    unix_ns: u64,
    sample_tick: u64,
    source: u32,
    peer: [u8; 4],
    peer_port: u16,
    rtt_ms: u64,
    max_age_ticks: u64,
) -> [u8; 64] {
    let mut b = [0u8; 64];
    b[..4].copy_from_slice(&1u32.to_le_bytes());
    b[4] = 1;
    b[8..12].copy_from_slice(&source.to_le_bytes());
    b[12..16].copy_from_slice(&u32::from_be_bytes(peer).to_le_bytes());
    for (at, n) in [
        (16, unix_ns),
        (24, sample_tick),
        (32, max_age_ticks),
        (40, rtt_ms),
    ] {
        b[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    b[56..58].copy_from_slice(&peer_port.to_le_bytes());
    b
}

pub fn set_sample(
    unix_ns: u64,
    sample_tick: u64,
    source: u32,
    peer: [u8; 4],
    peer_port: u16,
    rtt_ms: u64,
    max_age_ticks: u64,
) -> Result<(), i64> {
    let b = set_request(
        unix_ns,
        sample_tick,
        source,
        peer,
        peer_port,
        rtt_ms,
        max_age_ticks,
    );
    apply(&b)
}
pub fn failure(peer: [u8; 4], peer_port: u16, error: i64) -> Result<(), i64> {
    let mut b = [0; 64];
    b[..4].copy_from_slice(&1u32.to_le_bytes());
    b[4] = 2;
    b[8] = 3;
    b[12..16].copy_from_slice(&u32::from_be_bytes(peer).to_le_bytes());
    b[48..56].copy_from_slice(&error.to_le_bytes());
    b[56..58].copy_from_slice(&peer_port.to_le_bytes());
    apply(&b)
}
fn apply(b: &[u8; 64]) -> Result<(), i64> {
    let r = unsafe { crate::syscall3(0x7fb1, crate::clock_owner_handle(), b.as_ptr() as u64, 0) };
    if r < 0 { Err(r) } else { Ok(()) }
}
