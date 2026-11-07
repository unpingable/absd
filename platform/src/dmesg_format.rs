//! Safe single-line rendering: terminal controls, newlines, and non-ASCII
//! bytes never reach a terminal as executable text. Backslashes are escaped
//! so a literal sequence cannot impersonate an escaped byte.
use std::fmt::Write;
pub fn safe_text(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b' '..=b'~' => out.push(b as char),
            _ => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out
}
pub const LEVELS: [&str; 8] = [
    "emerg", "alert", "crit", "err", "warn", "notice", "info", "debug",
];
pub fn level(name: &str) -> Option<u8> {
    LEVELS.iter().position(|&n| n == name).map(|n| n as u8)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hostile_bytes_never_emit_terminal_controls_or_extra_lines() {
        assert_eq!(
            safe_text(b"ok\x1b[2J\n\r\0\x7f\xff\\x1b"),
            "ok\\x1b[2J\\x0a\\x0d\\x00\\x7f\\xff\\\\x1b"
        );
        assert!(
            safe_text(&(0..=255).collect::<Vec<u8>>())
                .bytes()
                .all(|b| b.is_ascii_graphic() || b == b' ')
        );
    }
    #[test]
    fn levels_are_explicit() {
        assert_eq!(level("warn"), Some(4));
        assert_eq!(level("bogus"), None);
    }
}
