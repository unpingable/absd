use absd_fsd::journal::{Journal, MAX_RECORD, MEMORY_LIMIT, Record, decode_text, escape_text};

#[test]
fn hostile_text_round_trips_without_terminal_controls_or_forged_metadata() {
    let text = b"\x1b[2J\nJ1 forged kernel authentication\r\0\xff\\";
    let escaped = escape_text(text);
    assert!(!escaped.bytes().any(|b| b < 32 || b == 127));
    assert_eq!(decode_text(&escaped).unwrap(), text);
    let mut j = Journal::new(*b"0123456789abcdef0123456789abcdef");
    let r = j.capture(12, "service.sshd", 6, Some(7), 0, text).unwrap();
    let parsed = Record::parse(&r.encode()).unwrap();
    assert_eq!(parsed.source, "service.sshd");
    assert_eq!(parsed.message, escaped);
}

#[test]
fn flood_and_idle_reader_are_bounded_and_loss_is_visible() {
    let mut j = Journal::new(*b"0123456789abcdef0123456789abcdef");
    for n in 0..20000 {
        j.capture(1, "service.noisy", 6, Some(n), 0, &[0x1b; 4000]);
    }
    assert!(j.suppressed > 0);
    assert!(j.memory_bytes() <= MEMORY_LIMIT / 4);
    assert!(j.recent().iter().all(|r| r.encode().len() <= MAX_RECORD));
    assert!(
        j.capture(2, "service.quiet", 3, None, 0, b"unrelated failure")
            .is_some()
    );
    let r = j
        .capture(2000, "service.noisy", 6, None, 0, b"after flood")
        .unwrap();
    assert!(r.flags & absd_fsd::journal::SUPPRESSED != 0);
}

use absd_fs::{Device, Error, Fs, SECTOR};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
};
#[derive(Clone)]
struct Disk {
    sectors: Rc<RefCell<BTreeMap<u64, [u8; SECTOR]>>>,
    fail: Rc<RefCell<bool>>,
    flushes: Rc<Cell<usize>>,
}
impl Device for Disk {
    fn sectors(&self) -> u64 {
        16384
    }
    fn read(&mut self, n: u64, b: &mut [u8; SECTOR]) -> Result<(), Error> {
        *b = self
            .sectors
            .borrow()
            .get(&n)
            .copied()
            .unwrap_or([0; SECTOR]);
        Ok(())
    }
    fn write(&mut self, n: u64, b: &[u8; SECTOR]) -> Result<(), Error> {
        if *self.fail.borrow() {
            return Err(Error::Device(-5));
        }
        self.sectors.borrow_mut().insert(n, *b);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.flushes.set(self.flushes.get() + 1);
        if *self.fail.borrow() {
            Err(Error::Device(-5))
        } else {
            Ok(())
        }
    }
}
fn disk() -> Disk {
    Disk {
        sectors: Default::default(),
        fail: Default::default(),
        flushes: Default::default(),
    }
}
fn setup() -> (Disk, Fs<Disk>) {
    let mut d = disk();
    absd_fs::format(&mut d, 7).unwrap();
    let mut fs = Fs::mount(d.clone(), true).unwrap();
    fs.mkdir(b"/var").unwrap();
    fs.mkdir(b"/var/log").unwrap();
    (d, fs)
}
#[test]
fn two_service_streams_rotation_restart_and_orderly_previous_boot_history() {
    use absd_fsd::journal::{FILE_LIMIT, FILES, read_bounded};
    let (d, mut fs) = setup();
    let first = *b"0123456789abcdef0123456789abcdef";
    let mut j = Journal::new(first);
    j.open(&mut fs).unwrap();
    for i in 0..1800 {
        let source = if i % 2 == 0 {
            "service.sshd"
        } else {
            "service.fsd"
        };
        let record = j
            .capture(
                i * 1000,
                source,
                if i % 2 == 0 { 6 } else { 3 },
                Some(i),
                0,
                b"pid=7 stream=stderr failure retained",
            )
            .unwrap();
        j.persist(&mut fs, &record);
    }
    assert!(j.rotations > 0);
    j.sync(&mut fs).unwrap();
    assert_eq!(j.flushed, j.written);
    for f in FILES {
        if let Ok(a) = fs.stat(format!("/var/log/journal/{f}").as_bytes()) {
            assert!(a.size <= FILE_LIMIT);
        }
    }
    drop(j);
    drop(fs);
    let mut fs = Fs::mount(d.clone(), true).unwrap();
    let mut resumed = Journal::new(first);
    resumed.open(&mut fs).unwrap();
    assert_eq!(resumed.resumed_kernel, Some(1799));
    let record = resumed
        .capture(
            2_000_000,
            "service.sshd",
            3,
            Some(1800),
            0,
            b"collector resumed",
        )
        .unwrap();
    assert_eq!(record.sequence, 1801);
    resumed.persist(&mut fs, &record);
    resumed.sync(&mut fs).unwrap();
    drop(resumed);
    drop(fs);
    let mut fs = Fs::mount(d, true).unwrap();
    let mut next = Journal::new(*b"fedcba9876543210fedcba9876543210");
    next.open(&mut fs).unwrap();
    let previous = read_bounded(&mut fs, b"/var/log/journal/previous").unwrap();
    assert!(
        previous
            .split(|b| *b == b'\n')
            .filter_map(Record::parse)
            .any(|r| r.boot == first && r.message == "collector resumed")
    );
    assert_eq!(next.resumed_kernel, None);
}
#[test]
fn readonly_sink_backoff_is_bounded_and_failed_device_keeps_emergency_records() {
    let (d, mut fs) = setup();
    let mut j = Journal::new(*b"0123456789abcdef0123456789abcdef");
    j.open(&mut fs).unwrap();
    fs.set_readonly_path(b"/var/log/journal/current", true)
        .unwrap();
    for i in 0..100 {
        let r = j
            .capture(i * 40, "service.sshd", 3, None, 0, b"sink unavailable")
            .unwrap();
        j.persist(&mut fs, &r);
    }
    assert_eq!(j.sink_lost, 0, "retained pending records are not lost");
    assert_eq!(j.pending(), 100);
    assert!(j.health().contains("persistence=volatile"));
    assert!(j.memory_bytes() <= MEMORY_LIMIT);
    fs.set_readonly_path(b"/var/log/journal/current", false)
        .unwrap();
    let r = j
        .capture(10000, "service.fsd", 3, None, 0, b"sink recovered")
        .unwrap();
    j.persist(&mut fs, &r);
    assert!(j.sink_error.is_none());
    *d.fail.borrow_mut() = true;
    assert!(j.sync(&mut fs).is_err());
    assert!(!j.recent().is_empty());
}

#[test]
fn incomplete_tail_is_counted_and_repaired_before_append() {
    use absd_fs::OpenFlags;
    let (_, mut fs) = setup();
    let boot = *b"0123456789abcdef0123456789abcdef";
    let mut j = Journal::new(boot);
    j.open(&mut fs).unwrap();
    let r = j
        .capture(1, "service.fsd", 5, Some(1), 0, b"complete")
        .unwrap();
    j.persist(&mut fs, &r);
    j.sync(&mut fs).unwrap();
    let h = fs
        .open(
            absd_fsd::journal::CURRENT,
            OpenFlags {
                write: true,
                ..Default::default()
            },
        )
        .unwrap();
    let size = fs.fstat(h).unwrap().size;
    fs.write_at(h, size, b"J1 incomplete").unwrap();
    fs.close(h).unwrap();
    let mut next = Journal::new(boot);
    next.open(&mut fs).unwrap();
    assert_eq!(next.partial_tail, 13);
    assert_eq!(next.resumed_kernel, Some(1));
    let r = next
        .capture(2, "service.fsd", 5, Some(2), 0, b"after restart")
        .unwrap();
    next.persist(&mut fs, &r);
    let data = absd_fsd::journal::read_bounded(&mut fs, absd_fsd::journal::CURRENT).unwrap();
    assert_eq!(
        data.split_inclusive(|b| *b == b'\n')
            .filter_map(Record::parse)
            .count(),
        2
    );
}
#[test]
fn full_sink_retains_pending_work_without_unbounded_queue_or_retry() {
    use absd_fs::OpenFlags;
    let (_, mut fs) = setup();
    let mut j = Journal::new(*b"0123456789abcdef0123456789abcdef");
    j.open(&mut fs).unwrap();
    let h = fs
        .open(
            b"/fill",
            OpenFlags {
                write: true,
                create: true,
                ..Default::default()
            },
        )
        .unwrap();
    // Consume real filesystem data blocks, preserving metadata headroom.
    let mut offset = 0;
    let data = [0u8; 4096];
    loop {
        match fs.write_at(h, offset, &data) {
            Ok(n) => offset += n as u64,
            Err(Error::NoSpace) => break,
            Err(e) => panic!("unexpected fill failure {e:?}"),
        }
    }
    fs.close(h).unwrap();
    for n in 0..100 {
        if let Some(r) = j.capture(n * 40, "service.sshd", 3, None, 0, b"full sink") {
            j.persist(&mut fs, &r);
        }
    }
    assert_eq!(j.sink_lost, 0);
    assert!(j.pending() > 0);
    assert_eq!(j.sink_error, Some(Error::NoSpace));
    assert!(j.memory_bytes() <= MEMORY_LIMIT);
}

#[test]
fn idle_health_publishing_does_not_commit_or_rewrite_the_sample() {
    use absd_fsd::journal::{HealthPublisher, read_bounded};
    let (disk, mut fs) = setup();
    let mut journal = Journal::new(*b"0123456789abcdef0123456789abcdef");
    journal.open(&mut fs).unwrap();
    let record = journal
        .capture(1, "service.fsd", 5, Some(7), 0, b"one record")
        .unwrap();
    journal.persist(&mut fs, &record);
    let mut publisher = HealthPublisher::new();
    assert!(publisher.publish(&mut journal, &mut fs, 1000).unwrap());
    let original = read_bounded(&mut fs, b"/var/log/journal-health").unwrap();
    let stats = fs.write_stats();
    let flushes = disk.flushes.get();
    for now in (2000..=120000).step_by(1000) {
        assert!(!publisher.publish(&mut journal, &mut fs, now).unwrap());
    }
    assert_eq!(fs.write_stats(), stats);
    assert_eq!(
        disk.flushes.get(),
        flushes,
        "idle polls issued actual device flushes"
    );
    assert_eq!(
        read_bounded(&mut fs, b"/var/log/journal-health").unwrap(),
        original
    );
    journal.suppressed += 1;
    assert!(publisher.publish(&mut journal, &mut fs, 121000).unwrap());
    assert!(fs.write_stats().commits > stats.commits);
    assert!(
        String::from_utf8(read_bounded(&mut fs, b"/var/log/journal-health").unwrap())
            .unwrap()
            .contains("suppressed=1")
    );
    assert_eq!(journal.flushed, journal.written);
}

#[test]
fn compatibility_projection_does_not_join_lifecycle_or_process_instances() {
    let mut view = absd_fsd::log::LegacyProjection::default();
    assert!(view.push(b"pid=4 stream=stderr old tail").is_empty());
    assert!(
        view.push(b"pid=4 stream=lifecycle ended status=0")
            .is_empty()
    );
    assert_eq!(
        view.push(b"pid=5 stream=stdout new\n"),
        vec![
            b"pid=4 stream=stderr partial: old tail".to_vec(),
            b"new".to_vec()
        ]
    );
    assert_eq!(
        view.push(b"pid=5 stream=stderr error\n"),
        vec![b"error".to_vec()]
    );
}

#[test]
fn reserved_admission_keeps_the_same_source_rate_and_memory_bounds() {
    use absd_fsd::journal::{
        MAX_SOURCES, RESERVED_SOURCES, SOURCE_RECORDS, SOURCE_WINDOW, SUPPRESSED,
    };
    assert_eq!(MAX_SOURCES, 16);
    assert_eq!(SOURCE_RECORDS, 32);
    assert_eq!(SOURCE_WINDOW, 1000);
    let mut journal = Journal::new(*b"0123456789abcdef0123456789abcdef");
    let mut admitted = 0;
    for number in 0..MAX_SOURCES + 8 {
        admitted += usize::from(
            journal
                .capture(1, &format!("other{number}"), 6, None, 0, b"typed record")
                .is_some(),
        );
    }
    assert_eq!(admitted, MAX_SOURCES - RESERVED_SOURCES.len());
    for source in RESERVED_SOURCES {
        assert!(
            journal
                .capture(1, source, 6, None, 0, b"managed record")
                .is_some(),
            "{source}"
        );
    }
    let names: std::collections::BTreeSet<_> = journal
        .recent()
        .iter()
        .map(|record| record.source.as_str())
        .collect();
    assert_eq!(names.len(), MAX_SOURCES);
    for _ in 1..SOURCE_RECORDS {
        assert!(
            journal
                .capture(1, "service.sshd", 6, None, 0, b"within budget")
                .is_some()
        );
    }
    assert!(
        journal
            .capture(1, "service.sshd", 6, None, 0, b"over budget")
            .is_none()
    );
    let after = journal
        .capture(SOURCE_WINDOW, "service.sshd", 6, None, 0, b"next window")
        .unwrap();
    assert_ne!(after.flags & SUPPRESSED, 0);
    assert!(after.message.starts_with("[suppressed=1]"));
    assert!(journal.memory_bytes() <= MEMORY_LIMIT);
}

#[test]
fn only_unacknowledged_memory_evictions_count_as_unconfirmed_sink_loss() {
    let mut j = Journal::new(*b"0123456789abcdef0123456789abcdef");
    for n in 0..1000 {
        j.capture(n * 1000, "service.sshd", 3, Some(n), 0, &[b'x'; 320])
            .unwrap();
    }
    assert!(j.evicted > 0);
    assert_eq!(j.sink_lost, j.evicted);
    assert!(j.pending() > 0);
    assert!(j.memory_bytes() <= MEMORY_LIMIT / 4);
}
