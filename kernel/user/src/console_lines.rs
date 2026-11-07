//! Init's presentation arbiter for captured child output, not a readiness parser.
//! Only init calls this module. Kernel emergency output and the owned terminal
//! remain direct console users; no global physical-console exclusion is claimed.
use crate::Console;

pub const WRITE_BYTES: usize = crate::MAX_WRITE;
const PAYLOAD_BYTES: usize = 224;
pub const LOGD: usize = 0;
pub const FSD_STDOUT: usize = 1;
pub const FSD_STDERR: usize = 2;
const CONTINUED: &[u8] = b" [console limit; continued]\n";
const PARTIAL: &[u8] = b" [console partial]\n";
const _: () = assert!(PAYLOAD_BYTES + CONTINUED.len() <= WRITE_BYTES);

struct Line {
    bytes: [u8; WRITE_BYTES],
    length: usize,
    source_boundary: bool,
}
impl Line {
    const fn new() -> Self {
        Self {
            bytes: [0; WRITE_BYTES],
            length: 0,
            source_boundary: true,
        }
    }
}

struct Arbiter {
    lines: [Line; 3],
    failed: bool,
}
impl Arbiter {
    const fn new() -> Self {
        Self {
            lines: [Line::new(), Line::new(), Line::new()],
            failed: false,
        }
    }
    fn write(&mut self, console: Console, bytes: &[u8]) -> Result<(), &'static str> {
        if self.failed {
            return Err("init console publication retired");
        }
        if bytes.is_empty()
            || bytes.len() > WRITE_BYTES
            || bytes.last() != Some(&b'\n')
            || console.write_once(bytes) != Ok(bytes.len())
        {
            // A short/error write may already be visible. Never replay it or
            // publish a successful worker END after that uncertain prefix.
            self.failed = true;
            return Err("init console line publication");
        }
        Ok(())
    }
    fn flush(
        &mut self,
        console: Console,
        stream: usize,
        suffix: &[u8],
    ) -> Result<(), &'static str> {
        if self.failed {
            return Err("init console publication retired");
        }
        let line = &mut self.lines[stream];
        if line.length == 0 {
            return Ok(());
        }
        let mut bytes = [0; WRITE_BYTES];
        let n = line.length;
        bytes[..n].copy_from_slice(&line.bytes[..n]);
        bytes[n..n + suffix.len()].copy_from_slice(suffix);
        self.write(console, &bytes[..n + suffix.len()])?;
        self.lines[stream].length = 0;
        // Display continuation/EOF does not supply a missing SOURCE newline.
        Ok(())
    }
    fn forward(
        &mut self,
        console: Console,
        stream: usize,
        bytes: &[u8],
    ) -> Result<(), &'static str> {
        if self.failed {
            return Err("init console publication retired");
        }
        for &byte in bytes {
            self.lines[stream].source_boundary = byte == b'\n';
            let escaped = [
                b'\\',
                b'x',
                b"0123456789abcdef"[(byte >> 4) as usize],
                b"0123456789abcdef"[(byte & 15) as usize],
            ];
            let plain = [byte];
            let token: &[u8] = if (32..127).contains(&byte) || byte == b'\n' {
                &plain
            } else {
                &escaped
            };
            // Count rendered bytes, and never cut an escape sequence.
            if self.lines[stream].length + token.len() > PAYLOAD_BYTES {
                self.flush(console, stream, CONTINUED)?;
            }
            let line = &mut self.lines[stream];
            line.bytes[line.length..line.length + token.len()].copy_from_slice(token);
            line.length += token.len();
            if byte == b'\n' {
                self.flush(console, stream, b"")?;
            } else if line.length == PAYLOAD_BYTES {
                self.flush(console, stream, CONTINUED)?;
            }
        }
        Ok(())
    }
    fn boundary(&mut self, console: Console) -> Result<(), &'static str> {
        if self.failed {
            return Err("init console publication retired");
        }
        for stream in 0..self.lines.len() {
            self.flush(console, stream, PARTIAL)?;
        }
        Ok(())
    }
}

// Single init task, never accessed by kernel writers or another process.
static mut ARBITER: Arbiter = Arbiter::new();
pub fn forward(console: Console, stream: usize, bytes: &[u8]) -> Result<(), &'static str> {
    unsafe { (*core::ptr::addr_of_mut!(ARBITER)).forward(console, stream, bytes) }
}
pub fn finish(console: Console, stream: usize) -> Result<(), &'static str> {
    unsafe { (*core::ptr::addr_of_mut!(ARBITER)).flush(console, stream, PARTIAL) }
}
pub fn boundary(console: Console) -> Result<(), &'static str> {
    unsafe { (*core::ptr::addr_of_mut!(ARBITER)).boundary(console) }
}
pub fn frame(console: Console, bytes: &[u8]) -> Result<(), &'static str> {
    boundary(console)?;
    unsafe { (*core::ptr::addr_of_mut!(ARBITER)).write(console, bytes) }
}
pub fn source_boundary(stream: usize) -> bool {
    unsafe { (*core::ptr::addr_of!(ARBITER)).lines[stream].source_boundary }
}
pub fn start(console: Console, stream: usize) -> Result<(), &'static str> {
    finish(console, stream)?;
    unsafe {
        (*core::ptr::addr_of_mut!(ARBITER)).lines[stream].source_boundary = true;
    }
    Ok(())
}
#[cfg(test)]
pub fn reset() {
    unsafe {
        *core::ptr::addr_of_mut!(ARBITER) = Arbiter::new();
    }
}
