//! One bounded overwritten sample; no oplog, console, history or sync promise.
use absd_fsd::net_status::{BYTES, Listener, PERIOD_TICKS, Record};
use std::fs::OpenOptions;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

const RETRY_TICKS: u64 = 5000;

struct Attempt {
    end: u64,
    phase: Listener,
    write_ok: bool,
}

#[derive(Default)]
pub struct SampleFile {
    attempted: Option<Attempt>,
}

impl SampleFile {
    /// Call only after a fresh NIC read. A local phase change must not wait
    /// for the stable interval. Failed attempts use a bounded five-second retry.
    pub fn publish_fresh_at(
        &mut self,
        path: &Path,
        record: &Record,
        device_changed: bool,
    ) -> io::Result<bool> {
        if !device_changed
            && self.attempted.as_ref().is_some_and(|previous| {
                let period = if previous.write_ok {
                    PERIOD_TICKS
                } else {
                    RETRY_TICKS
                };
                previous.phase == record.listener
                    && record
                        .end
                        .checked_sub(previous.end)
                        .is_some_and(|age| age < period)
            })
        {
            return Ok(false);
        }
        self.attempted = Some(Attempt {
            end: record.end,
            phase: record.listener,
            write_ok: false,
        });
        self.publish_at(path, record)?;
        self.attempted.as_mut().expect("attempt recorded").write_ok = true;
        Ok(true)
    }

    pub fn publish_at(&mut self, path: &Path, record: &Record) -> io::Result<()> {
        let bytes = record
            .encode()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "network sample fields"))?;
        // Keep no FSD handle between samples: sshd's control log is its
        // only persistent open. Failed operations also drop this local file.
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        file.set_len(BYTES as u64)?;
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(&bytes))
    }
}
