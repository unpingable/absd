//! Bounded maintenance reader. Rendering never appends to the log it reads.
use super::{console_text, log};
use core::fmt::Write;

pub struct Snapshot {
    cursor: u64,
    failure_reported: bool,
    producer_dropped: Option<u64>,
}
impl Snapshot {
    pub const fn new() -> Self {
        Self {
            cursor: 0,
            failure_reported: false,
            producer_dropped: None,
        }
    }
    pub fn restart(&mut self) {
        *self = Self::new();
    }

    /// At most eight reads per pass; failures are visible once per explicitly
    /// requested snapshot, while later passes may recover from transient busy.
    pub fn step(
        &mut self,
        mut read: impl FnMut(u64) -> Result<log::Read, i64>,
        mut write: impl FnMut(&[u8]),
    ) {
        for _ in 0..8 {
            let result = match read(self.cursor) {
                Ok(result) => result,
                Err(code) => {
                    if !self.failure_reported {
                        let mut line = Line::new();
                        let _ = writeln!(
                            line,
                            "[kernel log read failed: code={code}; further failures suppressed until Ctrl-] k]"
                        );
                        write(line.bytes());
                        self.failure_reported = true;
                    }
                    return;
                }
            };
            self.cursor = result.next;
            let mut line = Line::new();
            if self.producer_dropped != Some(result.producer_dropped) {
                if result.producer_dropped != 0 || self.producer_dropped.is_some() {
                    let _ = write!(
                        line,
                        "[kernel log producer_dropped={}",
                        result.producer_dropped
                    );
                    if let Some(previous) = self.producer_dropped {
                        if let Some(delta) = result.producer_dropped.checked_sub(previous) {
                            let _ = write!(line, " delta={delta}");
                        } else {
                            let _ = line.write_str(" counter_changed");
                        }
                    }
                    let _ = line.write_str("]\n");
                }
                self.producer_dropped = Some(result.producer_dropped);
            }
            if result.lost != 0 {
                let _ = writeln!(
                    line,
                    "[kernel log gap: lost={} oldest={} end={}]",
                    result.lost, result.oldest, result.end
                );
            }
            write(line.bytes());
            let Some(record) = result.record else {
                return;
            };
            let mut line = Line::new();
            let _ = write!(line, "[seq={} ticks=", record.sequence);
            match record.ticks {
                Some(ticks) => {
                    let _ = write!(line, "{ticks}");
                }
                None => {
                    let _ = line.write_str("unavailable");
                }
            }
            let _ = write!(line, " severity={} source=", record.severity);
            let mut source = [0u8; 64];
            let n = console_text::render(record.source(), &mut source);
            let _ = line.write_str(core::str::from_utf8(&source[..n]).unwrap_or("invalid"));
            let _ = write!(line, " flags={}", record.flags);
            for (flag, name) in [
                (log::TRUNCATED, "truncated"),
                (log::PARTIAL, "partial"),
                (log::EMERGENCY, "emergency"),
                (log::INFERRED, "inferred"),
                (log::LOSS, "loss"),
            ] {
                if record.flags & flag != 0 {
                    let _ = write!(line, " {name}");
                }
            }
            let _ = line.write_str("] ");
            write(line.bytes());
            let mut text = [0u8; 1920];
            let n = console_text::render(record.text(), &mut text);
            write(&text[..n]);
            write(b"\n");
        }
    }
}

struct Line {
    bytes: [u8; 320],
    len: usize,
}
impl Line {
    const fn new() -> Self {
        Self {
            bytes: [0; 320],
            len: 0,
        }
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl Write for Line {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        if text.len() > self.bytes.len() - self.len {
            return Err(core::fmt::Error);
        }
        self.bytes[self.len..self.len + text.len()].copy_from_slice(text.as_bytes());
        self.len += text.len();
        Ok(())
    }
}

#[cfg(test)]
#[path = "console_snapshot_tests.rs"]
mod tests;
