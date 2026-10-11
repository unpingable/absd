//! Civil time from the RTC's seconds: the proleptic Gregorian calendar in
//! UTC, whole seconds, no leap seconds and no time zones (the kernel's
//! `wall_clock` declares the RTC UTC). Used by `date`, and by the file
//! server and sshd to stamp their log lines.

use core::fmt;

/// One instant, broken down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utc {
    pub year: i64,
    /// 1 to 12.
    pub month: u32,
    /// 1 to 31.
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// 0 is Sunday.
    pub weekday: u32,
}

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

impl Utc {
    /// Seconds since 1970-01-01T00:00:00Z.
    pub fn from_unix(seconds: u64) -> Self {
        let days = (seconds / 86_400) as i64;
        let rest = seconds % 86_400;
        // Howard Hinnant's days_from_civil inverse (civil_from_days).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let year = yoe + era * 400 + i64::from(month <= 2);
        Utc {
            year,
            month,
            day,
            hour: (rest / 3600) as u32,
            minute: (rest % 3600 / 60) as u32,
            second: (rest % 60) as u32,
            // 1970-01-01 was a Thursday.
            weekday: ((days + 4).rem_euclid(7)) as u32,
        }
    }

    /// ISO 8601, `2026-09-27T05:34:12Z`.
    pub fn iso(self) -> Iso {
        Iso(self)
    }
}

/// `date`'s form, as BSD `date -u` prints it: `Sun Sep 27 05:34:12 UTC 2026`.
impl fmt::Display for Utc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {:2} {:02}:{:02}:{:02} UTC {}",
            DAYS[self.weekday as usize],
            MONTHS[(self.month - 1) as usize],
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.year
        )
    }
}

pub struct Iso(Utc);

impl fmt::Display for Iso {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.0;
        write!(f, "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", t.year, t.month, t.day, t.hour, t.minute, t.second)
    }
}

/// `ls -l`'s time column for an `mtime`: `2026-09-27 05:34` (UTC, to the
/// minute), or `-` for 0, which is unknown rather than 1970.
pub fn mtime_column(seconds: u64) -> alloc::string::String {
    if seconds == 0 {
        return alloc::string::String::from("-");
    }
    let t = Utc::from_unix(seconds);
    alloc::format!("{:04}-{:02}-{:02} {:02}:{:02}", t.year, t.month, t.day, t.hour, t.minute)
}
