//! Bounded collector shared by logd's private RPC store and the guarded local finalizer.
//! Reading the kernel ring never consumes another diagnostic reader's records.
use absd_fs::OpenFlags;
use absd_fsd::journal::Store;
use absd_fsd::journal::{HealthPublisher, Journal};
use absd_runtime::kernel_log::{self, Cursor};
pub struct Collector {
    pub journal: Journal,
    cursor: Cursor,
    health: HealthPublisher,
    announced_error: bool,
    started: bool,
    start_retry: u64,
    legacy: absd_fsd::log::LogFile,
    legacy_lines: absd_fsd::log::LegacyProjection,
    notice_kernel: Option<u64>,
    notice_tick: Option<u64>,
}
impl Collector {
    pub fn new<S: Store>(fs: &mut S, boot: [u8; 32]) -> Self {
        let mut journal = Journal::new(boot);
        journal.collector_pid = Some(std::process::id() as u64);
        journal.sample_ticks = absd_runtime::ticks();
        let started = match journal.open(fs) {
            Ok(()) => true,
            Err(e) => {
                journal.sink_error = Some(e);
                false
            }
        };
        // Restart skips only the persisted kernel sequence. Suppressed or
        // unwritten records may be replayed; boot+kernel sequence identifies
        // those duplicates, and the resumed lifecycle record declares it.
        let cursor = journal
            .resumed_kernel
            .map(|n| Cursor::at(n.saturating_add(1)))
            .unwrap_or_default();
        // Fixed journal objects exist before FSD READY/capacity sampling.
        // Rotation changes identity but cannot grow the object population.
        for path in [
            b"/var/log/journal/current.0".as_slice(),
            b"/var/log/journal/previous".as_slice(),
            b"/var/log/journal/previous.0".as_slice(),
            b"/var/log/sshd".as_slice(),
            b"/var/log/journal-health".as_slice(),
        ] {
            if let Ok(h) = fs.open(
                path,
                OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                },
            ) {
                let _ = fs.close(h);
            }
        }
        let mut collector = Self {
            journal,
            cursor,
            health: HealthPublisher::new(),
            announced_error: false,
            started,
            start_retry: absd_runtime::ticks().saturating_add(1000),
            legacy: absd_fsd::log::LogFile::new(b"/var/log/sshd", "sshd"),
            legacy_lines: Default::default(),
            notice_kernel: None,
            notice_tick: None,
        };
        if started {
            collector.event(
            fs,
            b"collector started/restarted; per-generation counters; replay possible after last persisted kernel sequence",
        );
        }
        collector
    }
    pub fn event<S: Store>(&mut self, fs: &mut S, text: &[u8]) {
        if !self.started {
            return;
        }
        self.journal
            .capture(absd_runtime::ticks(), "collector", 5, None, 0, text);
        self.flush_one(fs);
    }
    fn flush_one<S: Store>(&mut self, fs: &mut S) {
        let Ok(Some(record)) = self.journal.flush_one(fs, absd_runtime::ticks()) else {
            return;
        };
        if record.source != "service.sshd" {
            return;
        }
        let message = if record.flags & absd_fsd::journal::SUPPRESSED != 0 {
            record
                .message
                .split_once("] ")
                .map_or(record.message.as_str(), |(_, rest)| rest)
        } else {
            &record.message
        };
        let Some(bytes) = absd_fsd::journal::decode_text(message) else {
            return;
        };
        for text in self.legacy_lines.push(&bytes) {
            let text = String::from_utf8_lossy(&text);
            let text = text.strip_prefix("sshd: ").unwrap_or(&text);
            let line = absd_fsd::log::line(absd_runtime::wall_clock_seconds().ok(), "sshd", text);
            let _ = self
                .legacy
                .append(fs, absd_runtime::wall_clock_seconds().ok(), &line);
        }
    }
    /// At most eight records per loop pass; a flood cannot monopolize FSD.
    pub fn poll<S: Store>(&mut self, fs: &mut S) -> bool {
        if !self.started {
            if absd_runtime::ticks() < self.start_retry {
                return false;
            }
            self.start_retry = absd_runtime::ticks().saturating_add(1000);
            // Do not assign sequence IDs before recovering the existing file.
            // The kernel ring remains the bounded acquisition buffer meanwhile.
            if let Err(e) = self.journal.open(fs) {
                self.journal.sink_error = Some(e);
                return false;
            }
            self.cursor = self
                .journal
                .resumed_kernel
                .map(|n| Cursor::at(n.saturating_add(1)))
                .unwrap_or_default();
            self.started = true;
            self.event(
                fs,
                b"collector started after storage recovery; per-generation counters",
            );
        }
        let written_before = self.journal.written;
        self.flush_one(fs);
        let mut health_written = false;
        for _ in 0..8 {
            let initial = self.cursor.next() == 0;
            match kernel_log::read(&mut self.cursor) {
                Ok(read) => {
                    if read.producer_dropped > self.journal.kernel_producer_dropped {
                        self.journal.kernel_producer_dropped = read.producer_dropped;
                        self.event(
                            fs,
                            format!("kernel producers dropped total={}", read.producer_dropped)
                                .as_bytes(),
                        );
                    }
                    let lost = if initial {
                        read.oldest.saturating_sub(1).max(read.lost)
                    } else {
                        read.lost
                    };
                    self.journal.kernel_lost = self.journal.kernel_lost.saturating_add(lost);
                    if lost > 0 {
                        self.event(
                            fs,
                            format!(
                                "kernel cursor gap lost={} producer_dropped={}",
                                lost, read.producer_dropped
                            )
                            .as_bytes(),
                        );
                    }
                    let Some(r) = read.record else { break };
                    // Kernel metadata is copied separately from producer text.
                    // Streamed kernel text has a first-word hint, not an
                    // independent managed producer. Preserve its exact text
                    // and flags while grouping it for bounded admission/rate.
                    // Damaged LOSS records retain their unknown attribution.
                    let source =
                        if r.flags & kernel_log::INFERRED != 0 && r.flags & kernel_log::LOSS == 0 {
                            "kernel"
                        } else {
                            std::str::from_utf8(r.source()).unwrap_or("unknown")
                        };
                    self.journal.capture(
                        r.ticks.unwrap_or_else(absd_runtime::ticks),
                        source,
                        r.severity,
                        Some(r.sequence),
                        r.flags as u64
                            | if r.ticks.is_none() {
                                absd_fsd::journal::ACQUISITION_TIME
                            } else {
                                0
                            },
                        r.text(),
                    );
                    self.flush_one(fs);
                }
                Err(-11) => break,
                Err(e) => {
                    self.event(
                        fs,
                        format!("kernel cursor unavailable error={e}").as_bytes(),
                    );
                    break;
                }
            }
        }
        let now = absd_runtime::ticks();
        match self.health.publish(&mut self.journal, fs, now) {
            Ok(changed) => health_written = changed,
            Err(error) => self.journal.sink_error = Some(error),
        }
        let unhealthy = self.journal.sink_error.is_some();
        if unhealthy != self.announced_error {
            eprintln!("{}", self.journal.health().trim_end());
            self.announced_error = unhealthy;
        }
        health_written || self.journal.written != written_before
    }
    /// Credit requires this generation to acquire a kernel record and have
    /// its ordered append covered by a successful sync, not merely open old history.
    pub fn confirmed_acquisition_notice<S: Store>(&mut self, fs: &mut S) -> Option<String> {
        if self.journal.sink_error.is_some() || self.journal.sink_lost != 0 {
            return None;
        }
        let now = absd_runtime::ticks();
        if self
            .notice_tick
            .is_some_and(|tick| now.saturating_sub(tick) < 60000)
        {
            return None;
        }
        let record = self.journal.recent().iter().rev().find(|r| {
            r.sequence <= self.journal.written
                && r.kernel_sequence
                    .is_some_and(|seq| self.notice_kernel.is_none_or(|old| seq > old))
        })?;
        let boot = record.boot;
        let kernel = record.kernel_sequence?;
        self.journal.sync(fs).ok()?;
        self.notice_kernel = Some(kernel);
        self.notice_tick = Some(absd_runtime::ticks());
        Some(format!(
            "LOGD COLLECTED boot={} written={} flushed={}\n",
            std::str::from_utf8(&boot).ok()?,
            self.journal.written,
            self.journal.flushed
        ))
    }
    /// Bounded acquisition drain. Block-device calls retain the existing
    /// init/liveness stop bound; no retry loop extends orderly shutdown.
    pub fn drain<S: Store>(&mut self, fs: &mut S) {
        let now = absd_runtime::ticks();
        let deadline = now.saturating_add(1000);
        self.start_retry = self.start_retry.min(now);
        self.journal.retry_now(now);
        for _ in 0..16 {
            if absd_runtime::ticks() >= deadline {
                break;
            }
            let before = (self.cursor.next(), self.journal.written);
            self.poll(fs);
            if before == (self.cursor.next(), self.journal.written) {
                break;
            }
        }
        self.event(fs, b"collector orderly drain finished; sync follows");
        let result = self.journal.sync(fs);
        println!(
            "JOURNAL DRAIN disposition={} {}",
            if result == Err(absd_fs::Error::Device(-110))
                || self.journal.sink_error == Some(absd_fs::Error::Device(-110))
            {
                "unconfirmed"
            } else if result.is_err() || self.journal.sink_error.is_some() {
                "failed"
            } else if self.journal.sink_lost > 0 || self.journal.pending() > 0 {
                "partial"
            } else {
                "flushed"
            },
            self.journal.health().trim_end()
        );
    }
}
