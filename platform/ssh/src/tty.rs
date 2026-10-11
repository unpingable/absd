//! The terminal of a PTY session: a small line discipline in sshd, between
//! the channel and the child's pipes. Platform-independent and pure.
//!
//! What a client that asked for a PTY (OpenSSH: `pty-req`, then its own
//! terminal in raw mode) needs and nothing more:
//!
//! * Input is edited a line at a time and echoed. CR or LF ends a line,
//!   which reaches the child as `text\n`. DEL or BS erases one character,
//!   ^U the whole line. Escape sequences (`ESC [ ... final`, `ESC O x`,
//!   and `ESC x` for an ASCII x: arrow, function, and Alt keys) are
//!   dropped whole, neither echoed nor typed, since nothing here moves a
//!   cursor; a control character or a non-ASCII byte ends a sequence
//!   early and is handled as itself (ESC Enter still enters the line, Alt
//!   with a non-ASCII key keeps the character whole). Other control
//!   characters are kept and echoed as `^X`. A line holds at most
//!   `MAX_LINE` bytes; more are dropped.
//! * ^D on an empty line is end of input: the child's stdin is closed (a
//!   pipe has no one-shot EOF, so this is the end of input for the whole
//!   session). ^D after text hands that text over without a newline.
//! * ^C discards the line being typed and is reported to the caller, which
//!   decides what it may end (see conn.rs).
//! * Output: LF becomes CR LF.
//!
//! The control characters are fixed: the terminal modes the client sends
//! with `pty-req`, TERM, and the window size are not used by anything here
//! or in the session, so they are not read. There is no termios, raw mode,
//! process group, or job control.

/// Longest line held for editing (as a terminal's canonical buffer).
pub const MAX_LINE: usize = 4095;

const CTRL_C: u8 = 0x03;
const CTRL_D: u8 = 0x04;
const BS: u8 = 0x08;
const CTRL_U: u8 = 0x15;
const ESC: u8 = 0x1b;
const DEL: u8 = 0x7f;

/// Where in an escape sequence the input stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Escape {
    #[default]
    None,
    /// ESC seen: the next byte says which kind.
    Esc,
    /// `ESC [`: parameter and intermediate bytes until a final 0x40..=0x7e;
    /// `first` until one byte has followed (`ESC [ [ x`, the Linux
    /// console's F1 to F5, takes one more byte like `ESC O`).
    Csi { first: bool },
    /// `ESC O`: one more byte.
    Ss3,
}

/// What one batch of input asked for beyond bytes and echo.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Events {
    /// ^C was typed (the line being typed was discarded).
    pub interrupt: bool,
    /// ^D on an empty line: end of input.
    pub eof: bool,
}

#[derive(Debug, Default)]
pub struct LineDiscipline {
    line: Vec<u8>,
    eof: bool,
    escape: Escape,
}

/// Columns a stored character occupied when echoed.
fn width(ch: &[u8]) -> usize {
    match ch {
        [c] if *c < 0x20 && *c != b'\t' => 2,
        _ => 1,
    }
}

impl LineDiscipline {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether end of input has been typed.
    pub fn at_eof(&self) -> bool {
        self.eof
    }

    /// Takes client keystrokes. Completed input is appended to `to_child`,
    /// what the user should see to `echo`. After end of input only ^C is
    /// still recognised.
    pub fn input(&mut self, data: &[u8], to_child: &mut Vec<u8>, echo: &mut Vec<u8>) -> Events {
        let mut events = Events::default();
        for &b in data {
            if b == CTRL_C {
                self.line.clear();
                self.escape = Escape::None;
                echo.extend_from_slice(b"^C\r\n");
                events.interrupt = true;
                continue;
            }
            if self.eof {
                continue;
            }
            let in_sequence = match self.escape {
                Escape::None => false,
                // A control or a non-ASCII byte ends the sequence and is
                // handled as itself (another ESC starts over).
                _ if b < 0x20 || b >= DEL => {
                    self.escape = Escape::None;
                    false
                }
                Escape::Esc => {
                    self.escape = match b {
                        b'[' => Escape::Csi { first: true },
                        b'O' => Escape::Ss3,
                        _ => Escape::None,
                    };
                    true
                }
                Escape::Csi { first } => {
                    self.escape = if first && b == b'[' {
                        Escape::Ss3
                    } else if (0x40..=0x7e).contains(&b) {
                        Escape::None
                    } else {
                        Escape::Csi { first: false }
                    };
                    true
                }
                Escape::Ss3 => {
                    self.escape = Escape::None;
                    true
                }
            };
            if in_sequence {
                continue;
            }
            if b == ESC {
                self.escape = Escape::Esc;
                continue;
            }
            match b {
                b'\r' | b'\n' => {
                    to_child.append(&mut self.line);
                    to_child.push(b'\n');
                    echo.extend_from_slice(b"\r\n");
                }
                CTRL_D if self.line.is_empty() => {
                    self.eof = true;
                    events.eof = true;
                }
                CTRL_D => to_child.append(&mut self.line),
                DEL | BS => {
                    self.erase_char(echo);
                }
                CTRL_U => while self.erase_char(echo) {},
                _ if self.line.len() >= MAX_LINE => {}
                c if c < 0x20 && c != b'\t' => {
                    self.line.push(c);
                    echo.extend_from_slice(&[b'^', c + 0x40]);
                }
                c => {
                    self.line.push(c);
                    echo.push(c);
                }
            }
        }
        events
    }

    /// Erases the last character (a whole UTF-8 sequence) from the line
    /// and the screen. Returns whether there was one.
    fn erase_char(&mut self, echo: &mut Vec<u8>) -> bool {
        let Some(mut start) = self.line.len().checked_sub(1) else { return false };
        while start > 0 && self.line[start] & 0xc0 == 0x80 {
            start -= 1;
        }
        for _ in 0..width(&self.line[start..]) {
            echo.extend_from_slice(b"\x08 \x08");
        }
        self.line.truncate(start);
        true
    }
}

/// Output post-processing: every LF becomes CR LF. At most doubles `data`.
pub fn output(data: &[u8], out: &mut Vec<u8>) {
    for &b in data {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(ld: &mut LineDiscipline, data: &[u8]) -> (Vec<u8>, Vec<u8>, Events) {
        let (mut child, mut echo) = (Vec::new(), Vec::new());
        let ev = ld.input(data, &mut child, &mut echo);
        (child, echo, ev)
    }

    #[test]
    fn line_editing_and_echo() {
        let mut ld = LineDiscipline::new();
        let (child, echo, ev) = feed(&mut ld, b"lx\x7fs /\r");
        assert_eq!(child, b"ls /\n");
        assert_eq!(echo, b"lx\x08 \x08s /\r\n");
        assert_eq!(ev, Events::default());
        let (child, echo, _) = feed(&mut ld, b"ab\x08c\n");
        assert_eq!((child.as_slice(), echo.as_slice()), (&b"ac\n"[..], &b"ab\x08 \x08c\r\n"[..]));
    }

    #[test]
    fn partial_lines_stay_until_the_end_of_line() {
        let mut ld = LineDiscipline::new();
        let (child, _, _) = feed(&mut ld, b"pw");
        assert!(child.is_empty());
        let (child, _, _) = feed(&mut ld, b"d\r");
        assert_eq!(child, b"pwd\n");
    }

    #[test]
    fn erase_line_utf8_and_control_characters() {
        let mut ld = LineDiscipline::new();
        let (child, echo, _) = feed(&mut ld, "é\x01x\x15ok\r".as_bytes());
        assert_eq!(child, b"ok\n");
        // é: one column; ^A two; x one.
        assert_eq!(echo, [&"é^Ax".as_bytes()[..], &b"\x08 \x08".repeat(4), b"ok\r\n"].concat());
        let (_, echo, _) = feed(&mut ld, b"\x7f\x15");
        assert!(echo.is_empty(), "nothing to erase");
    }

    #[test]
    fn end_of_input() {
        let mut ld = LineDiscipline::new();
        let (child, _, ev) = feed(&mut ld, b"abc\x04");
        assert_eq!((child.as_slice(), ev.eof), (&b"abc"[..], false));
        let (child, echo, ev) = feed(&mut ld, b"\x04more\r");
        assert!(ev.eof && ld.at_eof() && child.is_empty() && echo.is_empty());
        let (_, echo, ev) = feed(&mut ld, b"\x03");
        assert!(ev.interrupt && !ev.eof);
        assert_eq!(echo, b"^C\r\n");
    }

    #[test]
    fn interrupt_discards_the_line() {
        let mut ld = LineDiscipline::new();
        let (child, echo, ev) = feed(&mut ld, b"sleep\x03ok\r");
        assert!(ev.interrupt);
        assert_eq!(child, b"ok\n");
        assert_eq!(echo, b"sleep^C\r\nok\r\n");
    }

    #[test]
    fn escape_sequences_are_dropped_whole() {
        let mut ld = LineDiscipline::new();
        // Up arrow mid-word, a function key, Alt-x, and a parameterised
        // sequence (ctrl-right): none reaches the line or the screen.
        let (child, echo, ev) = feed(&mut ld, b"ec\x1b[Aho\x1bOP\x1bx\x1b[1;5C hi\r");
        assert_eq!((child.as_slice(), echo.as_slice()), (&b"echo hi\n"[..], &b"echo hi\r\n"[..]));
        assert_eq!(ev, Events::default());
        // Split across batches at every point of the sequence.
        let (child, echo, _) = feed(&mut ld, b"a\x1b");
        assert!(child.is_empty() && echo == b"a");
        let (child, echo, _) = feed(&mut ld, b"[");
        assert!(child.is_empty() && echo.is_empty());
        let (child, echo, _) = feed(&mut ld, b"Db\r");
        assert_eq!((child.as_slice(), echo.as_slice()), (&b"ab\n"[..], &b"b\r\n"[..]));
        // ^C inside a sequence still interrupts; the sequence is abandoned.
        let (child, echo, ev) = feed(&mut ld, b"x\x1b[\x03y\r");
        assert!(ev.interrupt);
        assert_eq!((child.as_slice(), echo.as_slice()), (&b"y\n"[..], &b"x^C\r\ny\r\n"[..]));
        // A control or non-ASCII byte ends a sequence early and counts as
        // itself: ESC Enter enters the line, Alt-é keeps é whole, ^D inside
        // a sequence hands the text over, ESC ESC [ A is one dropped key,
        // ESC [ [ A (Linux console F1) too.
        let (child, echo, _) = feed(&mut ld, "a\x1b\r\x1bé\x1b[\x04\x1b\x1b[Ab\x1b[[Ac\r".as_bytes());
        assert_eq!(String::from_utf8(child).unwrap(), "a\nébc\n");
        assert_eq!(String::from_utf8(echo).unwrap(), "a\r\nébc\r\n");
        assert_eq!(ld.escape, Escape::None);
    }

    #[test]
    fn long_lines_are_capped() {
        let mut ld = LineDiscipline::new();
        let (child, echo, _) = feed(&mut ld, &[b'a'; MAX_LINE + 10]);
        assert!(child.is_empty());
        assert_eq!(echo.len(), MAX_LINE);
        let (child, _, _) = feed(&mut ld, b"\r");
        assert_eq!(child.len(), MAX_LINE + 1);
    }

    #[test]
    fn output_translation() {
        let mut out = Vec::new();
        output(b"a\nb\r\n\n", &mut out);
        assert_eq!(out, b"a\r\nb\r\r\n\r\n");
    }
}
