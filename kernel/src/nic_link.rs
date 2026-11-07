//! Plain-text NIC link reporting: which line, if any, a link reading calls for.

pub const LINK_UNSEEN: u8 = 0;
pub const LINK_DOWN: u8 = 1;
pub const LINK_UP: u8 = 2;

/// The line to print for a link reading, when it differs from the last one.
pub fn link_line(last: u8, up: bool) -> Option<&'static str> {
    match (last, up) {
        (LINK_UP, true) | (LINK_DOWN, false) => None,
        (_, true) => Some("NIC LINK up\n"),
        (_, false) => Some("NIC LINK down\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_lines_report_the_first_reading_and_each_change_only() {
        assert_eq!(link_line(LINK_UNSEEN, false), Some("NIC LINK down\n"));
        assert_eq!(link_line(LINK_UNSEEN, true), Some("NIC LINK up\n"));
        assert_eq!(link_line(LINK_DOWN, true), Some("NIC LINK up\n"));
        assert_eq!(link_line(LINK_UP, false), Some("NIC LINK down\n"));
        assert_eq!(link_line(LINK_UP, true), None);
        assert_eq!(link_line(LINK_DOWN, false), None);
    }
}
