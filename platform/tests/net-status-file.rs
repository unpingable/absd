#[path = "../src/net_status_read.rs"]
mod reader;

#[path = "../src/net_status_file.rs"]
mod file;

use absd_fsd::net_status::{BYTES, Carrier, Listener, Origin, PERIOD_TICKS, Record};
use std::fs;

#[test]
fn one_day_of_publications_preserves_startup_logs_and_file_size() {
    let dir = std::env::temp_dir().join(format!("absd-net-status-file-{}", std::process::id()));
    fs::create_dir(&dir).expect("fresh test directory");
    let startup = b"sshd: network 10.0.2.15/24 gateway 10.0.2.2\nsshd: host key public fixture\n";
    let path = dir.join("network-status");
    fs::write(dir.join("sshd"), startup).unwrap();
    let mut writer = file::SampleFile::default();
    let mut record = sample();
    // 18,000 periodic writes plus readiness conservatively cover 24h at
    // the pinned PIT divisor 1193 / 1193181.67 Hz. Count-only simulation;
    // no native 24-hour runtime or timer-accuracy result is claimed.
    for publication in 0..=18_000 {
        let tick = publication * PERIOD_TICKS;
        record.start = tick;
        record.end = tick;
        writer.publish_at(&path, &record).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), BYTES as u64);
    }
    assert_eq!(fs::read(dir.join("sshd")).unwrap(), startup);
    assert!(!dir.join("sshd.0").exists());
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
    assert_eq!(Record::parse(&fs::read(&path).unwrap()), Some(record));
    drop(writer);
    fs::remove_file(path).unwrap();
    fs::remove_file(dir.join("sshd")).unwrap();
    fs::remove_dir(dir).unwrap();
}

fn sample() -> Record {
    Record {
        boot: *b"0123456789abcdef0123456789abcdef",
        recovery: 7,
        start: 0,
        end: 0,
        address: [10, 0, 2, 15],
        prefix: 24,
        gateway: Some([10, 0, 2, 2]),
        carrier: Carrier::Up,
        disabled: Some(false),
        origin: Origin::Defaults,
        listener: Listener::Listening,
        port: 22,
    }
}

#[test]
fn draining_publishes_before_period_with_unchanged_carrier() {
    let dir = std::env::temp_dir().join(format!("absd-net-status-phase-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("network-status");
    let mut writer = file::SampleFile::default();
    let mut record = sample();
    record.start = 1000;
    record.end = 1000;
    assert!(writer.publish_fresh_at(&path, &record, false).unwrap());
    record.start = 1100;
    record.end = 1100;
    assert!(!writer.publish_fresh_at(&path, &record, false).unwrap());
    assert_eq!(Record::parse(&fs::read(&path).unwrap()).unwrap().end, 1000);
    record.start = 1200;
    record.end = 1200;
    record.listener = Listener::Draining;
    assert!(writer.publish_fresh_at(&path, &record, false).unwrap());
    let retained = Record::parse(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(retained, record);
    assert_eq!(retained.carrier, Carrier::Up);
    record.start = 1300;
    record.end = 1300;
    assert!(!writer.publish_fresh_at(&path, &record, false).unwrap());
    assert_eq!(Record::parse(&fs::read(&path).unwrap()), Some(retained));
    drop(writer);
    fs::remove_file(path).unwrap();
    fs::remove_dir(dir).unwrap();
}

#[test]
fn failed_publication_consumes_retry_interval_without_rejuvenating_file() {
    let dir = std::env::temp_dir().join(format!("absd-net-status-retry-{}", std::process::id()));
    let path = dir.join("network-status");
    assert!(!dir.exists());
    let mut writer = file::SampleFile::default();
    let mut record = sample();
    record.start = 1000;
    record.end = 1000;
    assert!(writer.publish_fresh_at(&path, &record, false).is_err());
    fs::create_dir(&dir).unwrap();
    record.start = 1001;
    record.end = 1001;
    assert!(!writer.publish_fresh_at(&path, &record, false).unwrap());
    assert!(!path.exists());
    record.start = 6000;
    record.end = record.start;
    assert!(writer.publish_fresh_at(&path, &record, false).unwrap());
    assert_eq!(Record::parse(&fs::read(&path).unwrap()), Some(record));
    drop(writer);
    fs::remove_file(path).unwrap();
    fs::remove_dir(dir).unwrap();
}

#[test]
fn stable_fresh_reads_limit_successful_writes_to_hourly_heartbeat() {
    let dir =
        std::env::temp_dir().join(format!("absd-net-status-heartbeat-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("network-status");
    let mut writer = file::SampleFile::default();
    let mut record = sample();
    let mut publications = 0;
    // More than a nominal day at the pinned PIT rate, with frequent fresh reads.
    for tick in (0..=90_000_000).step_by(200) {
        record.start = tick;
        record.end = tick;
        if writer.publish_fresh_at(&path, &record, false).unwrap() {
            publications += 1;
        }
    }
    assert_eq!(publications, 26); // readiness + 25 hourly heartbeats
    assert_eq!(Record::parse(&fs::read(&path).unwrap()), Some(record));
    drop(writer);
    fs::remove_file(path).unwrap();
    fs::remove_dir(dir).unwrap();
}

fn acquisition_fixture(kind: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "absd-net-status-read-{}-{}",
        kind,
        std::process::id()
    ));
    fs::create_dir(&dir).unwrap();
    let mut bytes = absd_fsd::recovery::format_ledger(&absd_fsd::recovery::Ledger {
        seq: 7, boot: *b"0123456789abcdef0123456789abcdef", streak: 0,
    });
    bytes.resize(absd_fsd::recovery::LEDGER_BYTES, 0);
    fs::write(dir.join("network-recovery"), bytes).unwrap();
    dir
}

fn projection(seq: u64, boot: [u8; 32]) -> Vec<u8> {
    let mut bytes = absd_fsd::recovery::format_ledger(&absd_fsd::recovery::Ledger {
        seq, boot, streak: 0,
    });
    bytes.resize(absd_fsd::recovery::LEDGER_BYTES, 0);
    bytes
}

fn remove_fixture(dir: &std::path::Path) {
    for entry in fs::read_dir(dir).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    fs::remove_dir(dir).unwrap();
}

#[test]
fn recovery_binding_survives_both_startup_logs_being_rotated_away() {
    let dir = acquisition_fixture("rotated");
    let record = sample();
    fs::write(dir.join("network-status"), record.encode().unwrap()).unwrap();
    let before = fs::read(dir.join("network-recovery")).unwrap();
    for _ in 0..4 {
        fs::write(dir.join("fsd"), vec![b'x'; 64 * 1024]).unwrap();
        fs::write(dir.join("fsd.0"), vec![b'y'; 64 * 1024]).unwrap();
        let retained = reader::acquire(&dir, &record.boot, 2000, || 2001).unwrap();
        assert_eq!(retained.record, record);
        assert_eq!(retained.age, 2001);
        assert_eq!(fs::read(dir.join("network-recovery")).unwrap(), before);
    }
    remove_fixture(&dir);
}

#[test]
fn missing_projection_does_not_fall_back_to_retained_logs() {
    let dir = acquisition_fixture("no-projection");
    let record = sample();
    fs::remove_file(dir.join("network-recovery")).unwrap();
    fs::write(dir.join("network-status"), record.encode().unwrap()).unwrap();
    fs::write(dir.join("fsd"),b"time fsd: started: boot 0123456789abcdef0123456789abcdef, other\ntime fsd: FSD RECOVERY seq=7 streak=0 previous=none\n").unwrap();
    assert!(matches!(reader::acquire(&dir, &record.boot, 2000, || 2001), Err("recovery_unavailable")));
    remove_fixture(&dir);
}

#[test]
fn malformed_wrong_boot_and_oversized_projections_refuse_the_join() {
    let dir = acquisition_fixture("bad-projection");
    let record = sample();
    fs::write(dir.join("network-status"), record.encode().unwrap()).unwrap();
    let valid = projection(7, record.boot);
    let mut bad_check = valid.clone();
    bad_check[21] = b'8';
    let mut bad_padding = valid.clone();
    bad_padding[127] = b'x';
    let mut oversized = valid.clone();
    oversized.push(0);
    for (bytes, reason) in [
        (bad_check, "recovery_malformed"),
        (bad_padding, "recovery_malformed"),
        (valid[..127].to_vec(), "recovery_malformed"),
        (projection(0, record.boot), "recovery_malformed"),
        (projection(7, *b"00000000000000000000000000000000"), "recovery_wrong_boot"),
        (oversized, "recovery_unavailable"),
    ] {
        fs::write(dir.join("network-recovery"), bytes).unwrap();
        let result = reader::acquire(&dir, &record.boot, 2000, || 2001);
        assert!(matches!(result, Err(found) if found == reason), "{reason}");
    }
    remove_fixture(&dir);
}

#[test]
fn a_superseded_sample_cannot_bind_to_the_current_projection() {
    let dir = acquisition_fixture("superseded");
    let record = sample();
    fs::write(dir.join("network-status"), record.encode().unwrap()).unwrap();
    fs::write(dir.join("network-recovery"), projection(8, record.boot)).unwrap();
    assert!(matches!(reader::acquire(&dir, &record.boot, 2000, || 2001), Err("stale")));
    remove_fixture(&dir);
}

#[cfg(target_os = "linux")]
#[test]
fn projection_change_during_real_file_acquisition_is_refused() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{Duration, Instant};
    let dir = acquisition_fixture("concurrent-projection");
    let record = sample();
    let fifo = dir.join("network-status");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let read_dir = dir.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        assert!(send.send(reader::acquire(&read_dir, &record.boot, 2000, || 2001)).is_ok());
    });
    // Linux O_NONBLOCK: opening for writing succeeds only once the reader
    // reached the FIFO, after its first recovery acquisition. Keep it open
    // without bytes until the alternate current sequence is in place.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut writer = loop {
        match fs::OpenOptions::new().write(true).custom_flags(0x800).open(&fifo) {
            Ok(file) => break file,
            Err(error) if error.raw_os_error() == Some(6) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("FIFO writer rendezvous: {error}"),
        }
    };
    fs::write(dir.join("network-recovery"), projection(8, record.boot)).unwrap();
    writer.write_all(&record.encode().unwrap()).unwrap();
    drop(writer);
    let result = receive.recv_timeout(Duration::from_secs(30)).unwrap();
    reader.join().unwrap();
    assert!(matches!(result, Err("recovery_changed_during_acquisition")));
    remove_fixture(&dir);
}

#[test]
fn reader_acquisition_reports_missing_owner_file() {
    let dir = acquisition_fixture("missing");
    let result = reader::acquire(&dir, b"0123456789abcdef0123456789abcdef", 2000, || 2001);
    assert!(matches!(result, Err("sample_unavailable")));
    fs::remove_file(dir.join("network-recovery")).unwrap();
    fs::remove_dir(dir).unwrap();
}

#[test]
fn reader_acquisition_reports_stale_shared_record() {
    let dir = acquisition_fixture("stale");
    let hex = include_str!("../docs/net-status/VECTORS.tsv")
        .lines()
        .find(|line| line.starts_with("defaults-up\t"))
        .unwrap()
        .split('\t')
        .nth(2)
        .unwrap();
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    fs::write(dir.join("network-status"), bytes).unwrap();
    let now = 1002 + absd_fsd::net_status::MAX_AGE_TICKS;
    let result = reader::acquire(&dir, b"0123456789abcdef0123456789abcdef", now, || now);
    assert!(matches!(result, Err("stale")));
    fs::remove_file(dir.join("network-status")).unwrap();
    fs::remove_file(dir.join("network-recovery")).unwrap();
    fs::remove_dir(dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn publications_release_the_sample_handle_before_returning() {
    let dir = std::env::temp_dir().join(format!("absd-net-status-close-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let path = dir.canonicalize().unwrap().join("network-status");
    let open_samples = || {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
            .filter(|target| target == &path)
            .count()
    };
    let mut writer = file::SampleFile::default();
    let mut record = sample();
    assert_eq!(open_samples(), 0);
    for tick in [0, PERIOD_TICKS, 2 * PERIOD_TICKS] {
        record.start = tick;
        record.end = tick;
        assert!(writer.publish_fresh_at(&path, &record, false).unwrap());
        assert_eq!(open_samples(), 0, "publication retained the sample handle");
        assert_eq!(fs::read(&path).unwrap(), record.encode().unwrap());
        assert!(!writer.publish_fresh_at(&path, &record, false).unwrap());
        assert_eq!(open_samples(), 0, "skipped publication retained a handle");
    }
    record.listener = Listener::Draining;
    assert!(writer.publish_fresh_at(&path, &record, false).unwrap());
    assert_eq!(open_samples(), 0, "phase publication retained a handle");
    // Encoding failure must leave the last valid sample intact and no handle.
    let retained = fs::read(&path).unwrap();
    record.prefix = 33;
    assert!(writer.publish_at(&path, &record).is_err());
    assert_eq!(open_samples(), 0);
    assert_eq!(fs::read(&path).unwrap(), retained);
    drop(writer);
    fs::remove_file(path).unwrap();
    fs::remove_dir(dir).unwrap();
}
