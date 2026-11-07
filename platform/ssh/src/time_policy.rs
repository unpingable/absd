//! Pure operator syntax and maximum-step policy; no clock or network authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    Status,
    Set(u64),
    Sync,
}
pub fn request(words: &str) -> Result<Request, &'static str> {
    let words: Vec<&str> = words.split_ascii_whitespace().collect();
    match words.as_slice() {
        [] | ["status"] => Ok(Request::Status),
        ["sync"] => Ok(Request::Sync),
        ["set", text] if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            let s = text
                .parse::<u64>()
                .map_err(|_| "clock: invalid Unix seconds\n")?;
            if s > 4_102_444_799 {
                return Err("clock: supported civil range is 1970..2099\n");
            }
            Ok(Request::Set(s * 1_000_000_000))
        }
        _ => Err("usage: clock [status | set UNIX_SECONDS | sync]\n"),
    }
}
/// First network synchronization may replace an unverified RTC without the
/// step bound. Network corrections relative to operator assertions and prior
/// network estimates remain bounded; explicit manual assertions do not use
/// this helper and are not themselves step-bounded. The caller classifies
/// the runtime source; this pure policy does not depend on a target runtime.
pub fn accepts_step(
    previous: Option<u64>,
    unverified_rtc: bool,
    estimate: u64,
    maximum_seconds: u64,
) -> bool {
    let Some(limit) = maximum_seconds.checked_mul(1_000_000_000) else {
        return false;
    };
    unverified_rtc || previous.is_none_or(|old| old.abs_diff(estimate) <= limit)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operator_requests_are_exact_and_bounded() {
        assert_eq!(request(""), Ok(Request::Status));
        assert_eq!(request("set 100"), Ok(Request::Set(100_000_000_000)));
        for bad in [
            "set -1",
            "set +1",
            "set 4102444800",
            "set 999999999999999999999999",
            "set 1 2",
            "sync now",
            "trust yes",
        ] {
            assert!(request(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn step_bound_allows_unknown_bootstrap_but_refuses_disagreement_and_overflow() {
        assert!(accepts_step(None, false, 1_800_000_000_000_000_000, 1));
        assert!(accepts_step(Some(100_000_000_000), false, 101_000_000_000, 1));
        assert!(!accepts_step(Some(100_000_000_000), false, 101_000_000_001, 1));
        assert!(!accepts_step(Some(200_000_000_000), false, 100_000_000_000, 1));
        assert!(!accepts_step(None, false, 1, u64::MAX));
        assert!(accepts_step(
            Some(946_684_800_000_000_000),
            true,
            1_800_000_000_000_000_000,
            1
        ));
        assert!(!accepts_step(
            Some(946_684_800_000_000_000),
            false,
            1_800_000_000_000_000_000,
            1
        ));
        assert!(!accepts_step(
            Some(946_684_800_000_000_000),
            false,
            1_800_000_000_000_000_000,
            1
        ));
    }
}
