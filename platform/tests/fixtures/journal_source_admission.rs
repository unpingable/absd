include!("journal_support.rs");
use std::collections::BTreeSet;

#[test]
fn actual_boot_and_typed_saturation_cannot_starve_managed_capture_or_legacy_projection() {
    // Actual producer framing, not invented wire fixtures: more distinct boot
    // labels than the complete journal source limit, then typed saturation.
    for i in 0..24 {
        let text = format!("BOOT{i:02} detail kept exactly");
        for byte in text.bytes().chain([b'\n']) {
            PRODUCER.byte(byte, Some(1000));
        }
    }
    for i in 0..20 {
        assert!(PRODUCER.emit(
            format!("typed{i:02}").as_bytes(),
            6,
            Some(1000),
            b"unrelated typed record",
            0
        ));
    }
    service(1, 71, b"sshd: managed SSH stream survived\n");
    service(2, 72, b"managed FSD stream survived\n");
    service(3, 73, b"managed logd stream survived\n");
    // Actual one-shot producer damage path must remain unknown/LOSS, not gain
    // a confident inferred-subsystem label during normalization.
    for byte in b"damaged" {
        PRODUCER.byte(*byte, None);
    }
    PRODUCER.test_while_locked(|| PRODUCER.byte(b'X', None));
    PRODUCER.byte(b'\n', None);
    let mut disk = Disk(Default::default());
    absd_fs::format(&mut disk, 7).unwrap();
    let mut fs = Fs::mount(disk, true).unwrap();
    fs.mkdir(b"/var").unwrap();
    fs.mkdir(b"/var/log").unwrap();
    let mut server = Server::new(fs, 6, Vec::new());
    assert!(server.attach_logger(6));
    let boot = *b"0123456789abcdef0123456789abcdef";
    let (written, flushed, suppressed);
    {
        let mut store = RpcStore::new(|frame| Ok(request(&mut server, frame)));
        store.begin().unwrap();
        let mut collector = collector::Collector::new(&mut store, boot);
        let before = collector.journal.written;
        for _ in 0..8 {
            collector.poll(&mut store);
        }
        for source in ["service.sshd", "service.fsd", "service.logd"] {
            assert!(
                collector
                    .journal
                    .recent()
                    .iter()
                    .any(|record| record.source == source),
                "managed source starved: {source}"
            );
        }
        let inferred: Vec<_> = collector
            .journal
            .recent()
            .iter()
            .filter(|r| r.source == "kernel" && r.flags & wire::INFERRED as u64 != 0)
            .collect();
        assert_eq!(
            inferred.len(),
            24,
            "boot hints must share a bounded canonical source"
        );
        for (i, record) in inferred.iter().enumerate() {
            assert_eq!(
                journal::decode_text(&record.message).unwrap(),
                format!("BOOT{i:02} detail kept exactly").as_bytes()
            );
            assert_eq!(record.flags, wire::INFERRED as u64);
        }
        let unknown = collector
            .journal
            .recent()
            .iter()
            .find(|r| r.source == "unknown")
            .expect("LOSS classification must remain unknown");
        assert_eq!(
            unknown.flags,
            (wire::INFERRED | wire::LOSS) as u64 | journal::ACQUISITION_TIME
        );
        assert_eq!(journal::decode_text(&unknown.message).unwrap(), b"damaged");
        assert_eq!(collector.journal.kernel_producer_dropped, 1);
        let names: BTreeSet<_> = collector
            .journal
            .recent()
            .iter()
            .map(|record| record.source.as_str())
            .collect();
        assert_eq!(journal::MAX_SOURCES, 16);
        assert_eq!(names.len(), 16);
        assert!(collector.journal.suppressed >= 10);
        assert!(collector.journal.memory_bytes() <= journal::MEMORY_LIMIT);
        collector.journal.sync(&mut store).unwrap();
        written = collector.journal.written;
        flushed = collector.journal.flushed;
        suppressed = collector.journal.suppressed;
        assert!(written > before);
        assert_eq!(written, flushed);
    }
    // Check actual RPC-written filesystem bytes, not only the RAM view.
    let bytes = journal::read_bounded(&mut server.fs, journal::CURRENT).unwrap();
    let records: Vec<_> = bytes
        .split_inclusive(|b| *b == b'\n')
        .filter_map(Record::parse)
        .collect();
    for source in ["service.sshd", "service.fsd", "service.logd"] {
        assert!(records.iter().any(|r| r.source == source));
    }
    let legacy = journal::read_bounded(&mut server.fs, b"/var/log/sshd").unwrap();
    assert!(
        legacy
            .windows(b"managed SSH stream survived".len())
            .any(|s| s == b"managed SSH stream survived")
    );
    println!(
        "JOURNAL SOURCE ADMISSION written={written} flushed={flushed} suppressed={suppressed} legacy_bytes={} sources=16",
        legacy.len()
    );
}

#[test]
fn actual_service_stream_priorities_survive_collector_and_legacy_projection() {
    service_stream(1, 83, 1, b"sshd: priority-info-");
    service_stream(1, 83, 1, b"routine\n");
    service_stream(1, 83, 2, b"sshd: priority-warning-refused\n");
    let mut disk = Disk(Default::default());
    absd_fs::format(&mut disk, 7).unwrap();
    let mut fs = Fs::mount(disk, true).unwrap();
    fs.mkdir(b"/var").unwrap();
    fs.mkdir(b"/var/log").unwrap();
    let mut server = Server::new(fs, 6, Vec::new());
    assert!(server.attach_logger(6));
    {
        let mut store = RpcStore::new(|frame| Ok(request(&mut server, frame)));
        store.begin().unwrap();
        let mut collector = collector::Collector::new(&mut store, *b"0123456789abcdef0123456789abcdef");
        for _ in 0..32 { collector.poll(&mut store); }
        collector.journal.sync(&mut store).unwrap();
    }
    let bytes = journal::read_bounded(&mut server.fs, journal::CURRENT).unwrap();
    let records: Vec<_> = bytes.split_inclusive(|b| *b == b'\n').filter_map(Record::parse).collect();
    for (text, severity) in [("pid=83 stream=stdout sshd: priority-info-", 6), ("pid=83 stream=stdout routine", 6), ("pid=83 stream=stderr sshd: priority-warning-refused", 4)] {
        let found = records.iter().find(|r| journal::decode_text(&r.message).unwrap().starts_with(text.as_bytes())).expect("actual service bytes not persisted");
        assert_eq!(found.source, "service.sshd");
        assert_eq!(found.severity, severity);
    }
    let legacy = journal::read_bounded(&mut server.fs, b"/var/log/sshd").unwrap();
    let text = String::from_utf8(legacy).unwrap();
    assert!(text.contains("priority-info-routine"));
    assert!(text.contains("priority-warning-refused"));
}
