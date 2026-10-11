//! sshd's diagnostics. Every line goes to stderr as before (in a boot,
//! init relays it to the serial console as framed output); on ABSD it is
//! also appended to `/var/log/sshd` through the file server's control
//! channel, stamped with the RTC's UTC second (`absd_fsd::log`: bounded by
//! rotation to `/var/log/sshd.0`; a refused write drops lines and says how
//! many). sshd writes it itself: there is no log daemon. Lines wait in
//! memory until the main loop calls [`flush`]; at most 16
//! KiB wait (`QUEUE_LIMIT`), and lines beyond that are dropped and
//! counted.

/// Logs one line (`say!`).
pub fn line(text: String) {
    eprintln!("{text}");
    #[cfg(target_os = "absd")]
    file::queue(&text);
}

#[cfg(target_os = "absd")]
pub use file::{flush, notice, open};

#[cfg(target_os = "absd")]
mod file {
    use std::cell::RefCell;
    use std::fs::{File, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};

    use absd_fsd::log::{self as policy};
    use absd_fsd::proto::{Frame, MAX_NOTICE, op};

    pub const PATH: &str = "/var/log/sshd";
    const QUEUE_LIMIT: usize = 16 * 1024;

    struct Writer {
        file: Option<File>,
        size: u64,
        opened: bool,
        pending: Vec<u8>,
        dropped: u64,
    }

    thread_local! {
        static WRITER: RefCell<Writer> =
            const { RefCell::new(Writer { file: None, size: 0, opened: false, pending: Vec::new(), dropped: 0 }) };
    }

    pub fn queue(text: &str) {
        let text = text.strip_prefix("sshd: ").unwrap_or(text);
        let line = policy::line(absd_runtime::wall_clock_seconds().ok(), "sshd", text);
        WRITER.with_borrow_mut(|w| {
            if w.pending.len() + line.len() > QUEUE_LIMIT {
                w.dropped += 1;
            } else {
                w.pending.extend_from_slice(&line);
            }
        });
    }

    /// Starts writing the file (after the control channel is known good).
    pub fn open() {
        WRITER.with_borrow_mut(|w| w.opened = true);
        flush();
    }

    fn reopen(w: &mut Writer, rotate: bool) -> std::io::Result<()> {
        w.file = None;
        if rotate {
            std::fs::rename(PATH, format!("{PATH}.0"))?;
        }
        let mut file = OpenOptions::new().write(true).create(true).open(PATH)?;
        w.size = file.seek(SeekFrom::End(0))?;
        w.file = Some(file);
        Ok(())
    }

    fn write(w: &mut Writer, bytes: &[u8]) -> std::io::Result<()> {
        if w.file.is_none() {
            reopen(w, false)?;
        }
        if policy::must_rotate(w.size, bytes.len()) {
            reopen(w, true)?;
        }
        let file = w.file.as_mut().expect("opened");
        file.write_all(bytes)?;
        w.size += bytes.len() as u64;
        Ok(())
    }

    /// Writes what waits. Cheap when nothing does.
    pub fn flush() {
        WRITER.with_borrow_mut(|w| {
            if !w.opened || (w.pending.is_empty() && w.dropped == 0) {
                return;
            }
            let mut out = Vec::new();
            if w.dropped > 0 {
                out = policy::line(
                    absd_runtime::wall_clock_seconds().ok(),
                    "sshd",
                    &format!("log: {} lines dropped", w.dropped),
                );
            }
            out.append(&mut w.pending);
            match write(w, &out) {
                Ok(()) => w.dropped = 0,
                Err(error) => {
                    // Dropped, and counted by line; the file is opened
                    // again next time.
                    w.dropped += out.iter().filter(|&&b| b == b'\n').count() as u64;
                    w.file = None;
                    eprintln!("sshd: {PATH}: {error}; lines dropped");
                }
            }
        });
    }

    /// A line for the machine's console, which only the file server has
    /// (its `NOTICE`, control channel only); logged as well.
    pub fn notice(text: &str) {
        super::line(text.to_string());
        let bytes = &text.as_bytes()[..text.len().min(MAX_NOTICE)];
        let _ = absd_runtime::fsd::request_on(0, Frame::request(op::NOTICE).bytes(bytes).finish());
    }
}
