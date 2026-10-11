//! Decoding of the PC CMOS real-time clock (MC146818-compatible).
//!
//! The RTC keeps a calendar date and time of day to one second. It carries
//! no time zone and no century (the century byte some firmware keeps is at
//! an ACPI-described CMOS offset this kernel does not parse), so ABSD reads
//! the two-digit year as 2000..=2099 and declares the clock to hold UTC.
//! QEMU seeds its emulated RTC from the host in UTC by default
//! (`-rtc base=utc`). A physical machine's RTC holds whatever its firmware or
//! last operating system wrote: often UTC, but local time on machines set up
//! by Windows, and it drifts, uncorrected, by seconds a day. ABSD cannot tell
//! these apart; it reports the clock's own reading and never adjusts it.
//!
//! This module is the pure part: the register snapshot to Unix seconds, with
//! every field validated. The port I/O lives with the syscall.

/// CMOS register indices.
pub const SECONDS: u8 = 0x00;
pub const MINUTES: u8 = 0x02;
pub const HOURS: u8 = 0x04;
pub const DAY: u8 = 0x07;
pub const MONTH: u8 = 0x08;
pub const YEAR: u8 = 0x09;
pub const STATUS_A: u8 = 0x0a;
pub const STATUS_B: u8 = 0x0b;
/// Status A: an update cycle is in progress (the time registers may be
/// changing within the next 244 microseconds).
pub const UPDATE_IN_PROGRESS: u8 = 0x80;
/// Status B: registers are binary rather than BCD.
pub const BINARY: u8 = 0x04;
/// Status B: hours are 0..=23 rather than 1..=12 with a PM flag.
pub const HOURS_24: u8 = 0x02;
/// The PM flag in the hours register in 12-hour mode.
pub const PM: u8 = 0x80;

/// One consistent read of the time registers and status B.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub seconds: u8,
    pub minutes: u8,
    pub hours: u8,
    pub day: u8,
    pub month: u8,
    pub year: u8,
    pub status_b: u8,
}

fn from_bcd(value: u8) -> Option<u8> {
    let (high, low) = (value >> 4, value & 0x0f);
    (high <= 9 && low <= 9).then_some(high * 10 + low)
}

const fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

const fn days_in_month(year: u64, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        _ => 28,
    }
}

/// Days from 1970-01-01 to the given proleptic Gregorian date (year >= 1970).
fn days_since_epoch(year: u64, month: u8, day: u8) -> u64 {
    let mut days = 0u64;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        days += u64::from(days_in_month(year, m));
    }
    days + u64::from(day) - 1
}

/// Unix seconds (UTC by ABSD's declaration) for one snapshot, or `None` if
/// any field is not a valid BCD/binary value or not a real calendar instant.
pub fn unix_seconds(snapshot: Snapshot) -> Option<u64> {
    let binary = snapshot.status_b & BINARY != 0;
    let field = |value: u8| if binary { Some(value) } else { from_bcd(value) };
    let seconds = field(snapshot.seconds)?;
    let minutes = field(snapshot.minutes)?;
    let day = field(snapshot.day)?;
    let month = field(snapshot.month)?;
    let year = 2000 + u64::from(field(snapshot.year)?);
    let hours = if snapshot.status_b & HOURS_24 != 0 {
        field(snapshot.hours)?
    } else {
        let pm = snapshot.hours & PM != 0;
        let hour = field(snapshot.hours & !PM)?;
        if !(1..=12).contains(&hour) {
            return None;
        }
        (hour % 12) + if pm { 12 } else { 0 }
    };
    if seconds > 59
        || minutes > 59
        || hours > 23
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
    {
        return None;
    }
    let days = days_since_epoch(year, month, day);
    Some(days * 86_400 + u64::from(hours) * 3_600 + u64::from(minutes) * 60 + u64::from(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bcd(seconds: u8, minutes: u8, hours: u8, day: u8, month: u8, year: u8) -> Snapshot {
        Snapshot {
            seconds,
            minutes,
            hours,
            day,
            month,
            year,
            status_b: HOURS_24,
        }
    }

    #[test]
    fn bcd_24_hour_matches_known_instants() {
        // 2000-01-01T00:00:00Z
        assert_eq!(
            unix_seconds(bcd(0x00, 0x00, 0x00, 0x01, 0x01, 0x00)),
            Some(946_684_800)
        );
        // 2026-09-25T18:38:08Z
        assert_eq!(
            unix_seconds(bcd(0x08, 0x38, 0x18, 0x25, 0x09, 0x26)),
            Some(1_790_361_488)
        );
        // 2024-02-29T23:59:59Z, a leap day
        assert_eq!(
            unix_seconds(bcd(0x59, 0x59, 0x23, 0x29, 0x02, 0x24)),
            Some(1_709_251_199)
        );
        // 2099-12-31T23:59:59Z, the last representable second
        assert_eq!(
            unix_seconds(bcd(0x59, 0x59, 0x23, 0x31, 0x12, 0x99)),
            Some(4_102_444_799)
        );
    }

    #[test]
    fn binary_and_12_hour_modes_decode() {
        let binary = Snapshot {
            seconds: 8,
            minutes: 38,
            hours: 18,
            day: 25,
            month: 9,
            year: 26,
            status_b: HOURS_24 | BINARY,
        };
        assert_eq!(unix_seconds(binary), Some(1_790_361_488));
        let pm = Snapshot {
            hours: PM | 0x06,
            status_b: 0,
            ..bcd(0x08, 0x38, 0, 0x25, 0x09, 0x26)
        };
        assert_eq!(unix_seconds(pm), Some(1_790_361_488));
        let midnight = Snapshot {
            hours: 0x12,
            status_b: 0,
            ..bcd(0, 0, 0, 0x01, 0x01, 0x00)
        };
        assert_eq!(unix_seconds(midnight), Some(946_684_800));
        let noon = Snapshot {
            hours: PM | 0x12,
            status_b: 0,
            ..bcd(0, 0, 0, 0x01, 0x01, 0x00)
        };
        assert_eq!(unix_seconds(noon), Some(946_684_800 + 12 * 3_600));
    }

    #[test]
    fn impossible_readings_are_refused() {
        assert_eq!(unix_seconds(bcd(0x60, 0, 0, 0x01, 0x01, 0)), None);
        assert_eq!(unix_seconds(bcd(0x0a, 0, 0, 0x01, 0x01, 0)), None);
        assert_eq!(unix_seconds(bcd(0, 0, 0x24, 0x01, 0x01, 0)), None);
        assert_eq!(unix_seconds(bcd(0, 0, 0, 0x00, 0x01, 0)), None);
        assert_eq!(unix_seconds(bcd(0, 0, 0, 0x29, 0x02, 0x25)), None);
        assert_eq!(unix_seconds(bcd(0, 0, 0, 0x31, 0x04, 0x25)), None);
        assert_eq!(unix_seconds(bcd(0, 0, 0, 0x01, 0x13, 0x25)), None);
        assert_eq!(unix_seconds(bcd(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)), None);
        let zero_hour = Snapshot {
            hours: 0x00,
            status_b: 0,
            ..bcd(0, 0, 0, 0x01, 0x01, 0)
        };
        assert_eq!(unix_seconds(zero_hour), None);
    }
}
