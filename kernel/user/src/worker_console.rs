//! Per-worker bounded line publication for the console projection only.
use absd_user::Console;

pub const LINE_BYTES: usize = 1024;
const _: () = assert!(LINE_BYTES == 1024);

struct Pending {
    bytes: [u8; LINE_BYTES],
    length: usize,
}
impl Pending {
    const fn new() -> Self {
        Self {
            bytes: [0; LINE_BYTES],
            length: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub enum Split {
    Limit,
    Eof,
    ReadError,
    PrePrompt,
    Abort,
}
impl Split {
    pub fn name(self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::Eof => "eof",
            Self::ReadError => "read-error",
            Self::PrePrompt => "pre-prompt",
            Self::Abort => "abort",
        }
    }
}

pub struct Output {
    console: Console,
    pending: [Pending; 2],
    offset: usize,
    digest: u32,
    failed: bool,
    finished: bool,
}
const _: () = assert!(core::mem::size_of::<Output>() <= 2200);
impl Output {
    pub fn new(console: Console, offset: usize, digest: u32) -> Self {
        Self {
            console,
            pending: [Pending::new(), Pending::new()],
            offset,
            digest,
            failed: false,
            finished: false,
        }
    }

    fn open(&self) -> Result<(), &'static str> {
        if self.failed || self.finished {
            Err("external console output retired")
        } else {
            Ok(())
        }
    }

    fn publish(&mut self, stream: usize, split: Option<Split>) -> Result<(), &'static str> {
        self.open()?;
        let length = self.pending[stream].length;
        if length == 0 {
            return Ok(());
        }
        let Some(next) = self.offset.checked_add(length) else {
            self.failed = true;
            return Err("external console offset overflow");
        };
        let result = super::external_chunk(
            self.console,
            self.offset,
            &self.pending[stream].bytes[..length],
        )
        .and_then(|()| match split {
            Some(reason) => {
                super::external_split_notice(self.console, stream, reason, self.offset, length)
            }
            None => Ok(()),
        });
        if result.is_err() {
            // Some frames may already be visible. Never retry an indeterminate
            // write from Drop or produce a successful end record afterward.
            self.failed = true;
            return result;
        }
        for &byte in &self.pending[stream].bytes[..length] {
            self.digest = (self.digest ^ u32::from(byte)).wrapping_mul(0x0100_0193);
        }
        self.offset = next;
        self.pending[stream].length = 0;
        Ok(())
    }

    pub fn push(&mut self, stream: usize, bytes: &[u8]) -> Result<(), &'static str> {
        self.open()?;
        if stream >= self.pending.len() {
            return Err("external console stream");
        }
        for &byte in bytes {
            let line = &mut self.pending[stream];
            line.bytes[line.length] = byte;
            line.length += 1;
            if byte == b'\n' {
                self.publish(stream, None)?;
            } else if line.length == LINE_BYTES {
                self.publish(stream, Some(Split::Limit))?;
            }
        }
        Ok(())
    }

    pub fn finish_stream(&mut self, stream: usize) -> Result<(), &'static str> {
        if stream >= self.pending.len() {
            return Err("external console stream");
        }
        self.publish(stream, Some(Split::Eof))
    }

    pub fn read_error_stream(&mut self, stream: usize) -> Result<(), &'static str> {
        if stream >= self.pending.len() {
            return Err("external console stream");
        }
        self.publish(stream, Some(Split::ReadError))
    }

    fn flush(&mut self, reason: Split) -> Result<(), &'static str> {
        for stream in 0..self.pending.len() {
            self.publish(stream, Some(reason))?;
        }
        Ok(())
    }

    pub fn before_handoff(&mut self) -> Result<(), &'static str> {
        self.flush(Split::PrePrompt)
    }

    pub fn omit(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        self.open()?;
        if self.pending.iter().any(|line| line.length != 0) {
            return Err("external hidden output has pending bytes");
        }
        let Some(next) = self.offset.checked_add(bytes.len()) else {
            self.failed = true;
            return Err("external console offset overflow");
        };
        self.offset = next;
        for &byte in bytes {
            self.digest = (self.digest ^ u32::from(byte)).wrapping_mul(0x0100_0193);
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), &'static str> {
        self.flush(Split::Eof)?;
        self.finished = true;
        Ok(())
    }

    pub fn position(&self) -> (usize, u32) {
        (self.offset, self.digest)
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        if !self.finished && !self.failed {
            // A producer/read failure must not silently discard bytes already
            // accepted from either pipe. The caller's failure stays a failure.
            let _ = self.flush(Split::Abort);
        }
    }
}
