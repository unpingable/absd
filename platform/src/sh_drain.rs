//! File endpoint buffering and the shell's bounded output copier.
use std::io::{self, BufWriter, Write};
pub const FILE_BUFFER_BYTES: usize = 4096;
/// Checked between IO operations; synchronous filesystem waits are unchanged.
pub const MAX_BUFFER_TICKS: u64 = 16;

struct BytesOnly<W>(W);
impl<W: Write> Write for BytesOnly<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Failure {
    kind: io::ErrorKind,
    raw: Option<i32>,
    text: String,
}
impl Failure {
    fn save(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw: error.raw_os_error(),
            text: error.to_string(),
        }
    }
    fn restore(&self) -> io::Error {
        self.raw.map_or_else(
            || io::Error::new(self.kind, self.text.clone()),
            io::Error::from_raw_os_error,
        )
    }
}
/// Exactly one instance per opened file, owned inside SharedSink. Aliases
/// share byte order, pending age, and the first terminal write/sync failure.
pub struct BufferedFile<W: Write, C: Fn() -> u64> {
    writer: Option<BufWriter<BytesOnly<W>>>,
    clock: C,
    since: Option<u64>,
    failure: Option<Failure>,
}
impl<W: Write, C: Fn() -> u64> BufferedFile<W, C> {
    pub fn new(writer: W, clock: C) -> Self {
        Self {
            writer: Some(BufWriter::with_capacity(
                FILE_BUFFER_BYTES,
                BytesOnly(writer),
            )),
            clock,
            since: None,
            failure: None,
        }
    }
    fn usable(&self) -> io::Result<()> {
        match &self.failure {
            Some(e) => Err(e.restore()),
            None => Ok(()),
        }
    }
    fn observed<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if let Err(error) = &result {
            // Write::write_all retries Interrupted; caching it would make
            // that standard retry loop permanent across every alias.
            if error.kind() != io::ErrorKind::Interrupted {
                self.failure.get_or_insert_with(|| Failure::save(error));
            }
        }
        result
    }
    pub fn flush_pending(&mut self, force: bool) -> io::Result<bool> {
        self.usable()?;
        let len = self.writer.as_ref().unwrap().buffer().len();
        let due = self
            .since
            .is_some_and(|s| (self.clock)().saturating_sub(s) >= MAX_BUFFER_TICKS);
        if len == 0 || (!force && len < FILE_BUFFER_BYTES && !due) {
            return Ok(false);
        }
        let result = self.writer.as_mut().unwrap().flush();
        self.observed(result)?;
        self.since = None;
        Ok(true)
    }
    pub fn wait_limit(&self, ticks: u64) -> u64 {
        self.since.map_or(ticks, |since| {
            ticks.min(
                MAX_BUFFER_TICKS
                    .saturating_sub((self.clock)().saturating_sub(since))
                    .max(1),
            )
        })
    }
}
impl<W: Write, C: Fn() -> u64> Write for BufferedFile<W, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.usable()?;
        self.flush_pending(false)?;
        let now = (self.clock)();
        let result = self.writer.as_mut().unwrap().write(bytes);
        let n = self.observed(result)?;
        if n == 0 && !bytes.is_empty() {
            return self.observed(Err(io::ErrorKind::WriteZero.into()));
        }
        if self.writer.as_ref().unwrap().buffer().is_empty() {
            self.since = None;
        } else if n != 0 {
            self.since.get_or_insert(now);
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.usable()?;
        self.flush_pending(true)?;
        let result = self.writer.as_mut().unwrap().get_mut().0.flush();
        self.observed(result)
    }
}
impl<W: Write, C: Fn() -> u64> Drop for BufferedFile<W, C> {
    fn drop(&mut self) {
        // Normal owners finish explicitly and can report errors. Never let
        // BufWriter's destructor retry a retained suffix after a failure.
        let (destination, pending) = self.writer.take().unwrap().into_parts();
        drop(pending);
        drop(destination);
    }
}
pub trait Target: Write {
    fn flush_pending(&mut self, force: bool) -> io::Result<bool>;
    fn wait_limit(&self, ticks: u64) -> u64;
    fn finish(&mut self, durable: bool) -> io::Result<()>;
}
pub enum Step {
    Pending,
    Moved,
    Done,
    Failed(io::Error),
}
pub struct Drain<R, T: Target> {
    pub stage: usize,
    from: R,
    target: T,
    finished: bool,
    failed: bool,
}
impl<R, T: Target> Drain<R, T> {
    pub fn new(stage: usize, from: R, target: T) -> Self {
        Self {
            stage,
            from,
            target,
            finished: false,
            failed: false,
        }
    }
    fn fail(&mut self, e: io::Error) -> Step {
        self.failed = true;
        Step::Failed(e)
    }
    pub fn step(
        &mut self,
        ticks: u64,
        mut read: impl FnMut(&mut R, &mut [u8], u64) -> io::Result<Option<usize>>,
    ) -> Step {
        if self.failed {
            return Step::Failed(io::Error::other("redirection already failed"));
        }
        if self.finished {
            return Step::Done;
        }
        let moved = match self.target.flush_pending(false) {
            Ok(n) => n,
            Err(e) => return self.fail(e),
        };
        let wait = self.target.wait_limit(ticks);
        let mut buffer = [0; 256];
        match read(&mut self.from, &mut buffer, wait) {
            Ok(Some(0)) => match self.finish(true) {
                Ok(()) => Step::Done,
                Err(e) => Step::Failed(e),
            },
            Ok(Some(n)) if n <= buffer.len() => {
                if let Err(e) = self.target.write_all(&buffer[..n]) {
                    return self.fail(e);
                }
                match self.target.flush_pending(false) {
                    Ok(_) => Step::Moved,
                    Err(e) => self.fail(e),
                }
            }
            Ok(None) => match self.target.flush_pending(true) {
                Ok(n) if n || moved => Step::Moved,
                Ok(_) => Step::Pending,
                Err(e) => self.fail(e),
            },
            outcome => {
                let e = match outcome {
                    Err(e) => e,
                    _ => io::Error::new(io::ErrorKind::InvalidData, "pipe returned too many bytes"),
                };
                let _ = self.target.flush_pending(true);
                self.fail(e)
            }
        }
    }
    pub fn finish(&mut self, durable: bool) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("redirection already failed"));
        }
        if self.finished {
            return Ok(());
        }
        match self.target.finish(durable) {
            Ok(()) => {
                self.finished = true;
                Ok(())
            }
            Err(e) => {
                self.failed = true;
                Err(e)
            }
        }
    }
}
