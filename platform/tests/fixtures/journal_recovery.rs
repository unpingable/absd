include!("journal_support.rs");

// Fail before applying one write, or lose one reply AFTER the real private
// RPC/FSD operation. The latter models an unknown outcome, not a failed disk.
struct StoreFaults<S> {
    inner: S,
    fail_write: bool,
    lose_write_reply: bool,
    lose_sync_reply: bool,
}
impl<S: journal::Store> journal::Store for StoreFaults<S> {
    fn mkdir(&mut self, p: &[u8]) -> Result<(), Error> {
        self.inner.mkdir(p)
    }
    fn open(&mut self, p: &[u8], f: absd_fs::OpenFlags) -> Result<u64, Error> {
        self.inner.open(p, f)
    }
    fn close(&mut self, h: u64) -> Result<(), Error> {
        self.inner.close(h)
    }
    fn fstat(&mut self, h: u64) -> Result<absd_fs::Attr, Error> {
        self.inner.fstat(h)
    }
    fn read_at(&mut self, h: u64, o: u64, b: &mut [u8]) -> Result<usize, Error> {
        self.inner.read_at(h, o, b)
    }
    fn write_at(&mut self, h: u64, o: u64, b: &[u8]) -> Result<usize, Error> {
        if core::mem::take(&mut self.fail_write) {
            return Err(Error::Device(-110));
        }
        let result = self.inner.write_at(h, o, b)?;
        if core::mem::take(&mut self.lose_write_reply) {
            return Err(Error::Device(-110));
        }
        Ok(result)
    }
    fn set_len(&mut self, h: u64, n: u64) -> Result<(), Error> {
        self.inner.set_len(h, n)
    }
    fn rename(&mut self, a: &[u8], b: &[u8], n: bool) -> Result<(), Error> {
        self.inner.rename(a, b, n)
    }
    fn unlink(&mut self, p: &[u8]) -> Result<(), Error> {
        self.inner.unlink(p)
    }
    fn sync(&mut self) -> Result<(), Error> {
        self.inner.sync()?;
        if core::mem::take(&mut self.lose_sync_reply) {
            return Err(Error::Device(-110));
        }
        Ok(())
    }
}

#[test]
fn actual_collector_retains_transient_failure_and_unknown_completion_without_skipping() {
    use std::sync::atomic::Ordering::Relaxed;
    for i in 0..200u64 {
        assert!(PRODUCER.emit(
            b"service.fsd",
            6,
            Some(i * 1000),
            format!("early{i}").as_bytes(),
            0
        ));
    }
    let mut disk = Disk(Default::default());
    absd_fs::format(&mut disk, 7).unwrap();
    let mut fs = Fs::mount(disk, true).unwrap();
    fs.mkdir(b"/var").unwrap();
    fs.mkdir(b"/var/log").unwrap();
    let mut server = Server::new(fs, 6, Vec::new());
    assert!(server.attach_logger(6));
    let boot = *b"0123456789abcdef0123456789abcdef";
    let (first, initial_lost, transient_lost, before_restart, sync_unknown);
    {
        NOW.store(300_000, Relaxed);
        let mut store = StoreFaults {
            inner: RpcStore::new(|f| Ok(request(&mut server, f))),
            fail_write: false,
            lose_write_reply: false,
            lose_sync_reply: false,
        };
        store.inner.begin().unwrap();
        let mut c = collector::Collector::new(&mut store, boot);
        for _ in 0..40 {
            c.poll(&mut store);
        }
        first = c
            .journal
            .recent()
            .iter()
            .find_map(|r| r.kernel_sequence)
            .unwrap();
        initial_lost = c.journal.kernel_lost;
        store.fail_write = true;
        for i in 0..10 {
            service(1, 9, format!("sshd: burst{i}\n").as_bytes());
        }
        NOW.store(400_020, Relaxed);
        for _ in 0..4 {
            c.poll(&mut store);
        }
        NOW.store(401_600, Relaxed);
        assert!(PRODUCER.emit(
            b"service.fsd",
            6,
            Some(401_500),
            b"pid=8 stream=stderr later record",
            0
        ));
        for _ in 0..24 {
            c.poll(&mut store);
        }
        transient_lost = c.journal.sink_lost;
        let persisted = journal::read_bounded(&mut store, journal::CURRENT).unwrap();
        before_restart = persisted
            .split_inclusive(|b| *b == b'\n')
            .filter_map(Record::parse)
            .filter(|r| r.source == "service.sshd" && r.message.contains("burst"))
            .count();
        store.inner.begin().unwrap();
        NOW.store(500_000, Relaxed);
        let mut c = collector::Collector::new(&mut store, boot);
        for _ in 0..4 {
            c.poll(&mut store);
        }
        store.lose_write_reply = true;
        service(2, 8, b"late-ack record");
        NOW.store(501_000, Relaxed);
        for _ in 0..2 {
            c.poll(&mut store);
        }
        NOW.store(503_000, Relaxed);
        for _ in 0..8 {
            c.poll(&mut store);
        }
        store.lose_sync_reply = true;
        assert_eq!(c.journal.sync(&mut store), Err(Error::Device(-110)));
        sync_unknown = c.journal.health().contains("persistence=unconfirmed");
        c.journal.sync(&mut store).unwrap();
    }
    let bytes = journal::read_bounded(&mut server.fs, journal::CURRENT).unwrap();
    let records: Vec<_> = bytes
        .split_inclusive(|b| *b == b'\n')
        .filter_map(Record::parse)
        .collect();
    let burst = records
        .iter()
        .filter(|r| r.source == "service.sshd" && r.message.contains("burst"))
        .count();
    let late = records
        .iter()
        .filter(|r| r.message.contains("late-ack record"))
        .count();
    let legacy = journal::read_bounded(&mut server.fs, b"/var/log/sshd").unwrap();
    let legacy = String::from_utf8_lossy(&legacy);
    let legacy_burst = legacy.lines().filter(|line| line.contains("burst")).count();
    println!(
        "JOURNAL RECOVERY first={first} initial_lost={initial_lost} transient_lost={transient_lost} before_restart={before_restart}/10 burst={burst}/10 legacy={legacy_burst}/10 late_ack={late} sync_unconfirmed={sync_unknown}"
    );
    assert_eq!(
        initial_lost,
        first - 1,
        "initial ring overrun must be reported"
    );
    assert_eq!(
        before_restart, 10,
        "retained records must recover even without a collector restart"
    );
    assert_eq!(
        burst, 10,
        "a transient write failure cannot skip retained records"
    );
    assert_eq!(
        legacy_burst, 10,
        "legacy projection must follow recovered records too"
    );
    assert_eq!(
        transient_lost, 0,
        "backoff and retry are not confirmed record losses"
    );
    assert_eq!(
        late, 1,
        "unknown write completion must not duplicate the record"
    );
    assert!(
        sync_unknown,
        "a COMMIT timeout cannot claim definite persistence failure"
    );
}

fn fresh_server() -> Server<Disk> {
    let mut disk = Disk(Default::default());
    absd_fs::format(&mut disk, 7).unwrap();
    let mut fs = Fs::mount(disk, true).unwrap();
    fs.mkdir(b"/var").unwrap();
    fs.mkdir(b"/var/log").unwrap();
    let mut server = Server::new(fs, 6, Vec::new());
    assert!(server.attach_logger(6));
    server
}
#[test]
fn unknown_open_outcome_requires_new_attachment_before_more_operations() {
    use journal::Store;
    let server = Rc::new(RefCell::new(fresh_server()));
    server.borrow_mut().fs.mkdir(journal::DIR).unwrap();
    for episode in 0..80 {
        let mut lose = true;
        let mut store = RpcStore::new(|frame: Vec<u8>| {
            let opcode = frame[proto::HEADER];
            let reply = request(&mut server.borrow_mut(), frame);
            if opcode == proto::op::OPEN && core::mem::take(&mut lose) {
                return Err(-110);
            }
            Ok(reply)
        });
        store.begin().unwrap();
        assert_eq!(server.borrow().logger_opens(), 0);
        assert_eq!(
            store.open(
                journal::CURRENT,
                absd_fs::OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                }
            ),
            Err(Error::Device(-110))
        );
        assert_eq!(server.borrow().logger_opens(), 1);
        assert!(
            store.sync().is_err(),
            "episode={episode}: must fence until fresh attachment"
        );
    }
    let mut store = RpcStore::new(|frame| Ok(request(&mut server.borrow_mut(), frame)));
    store.begin().unwrap();
    assert_eq!(server.borrow().logger_opens(), 0);
    let mut c = collector::Collector::new(&mut store, *b"0123456789abcdef0123456789abcdef");
    service(2, 8, b"generation-recovery-event");
    for _ in 0..40 {
        c.poll(&mut store);
    }
    c.journal.sync(&mut store).unwrap();
    assert!(c.journal.flushed > 0);
    assert_eq!(c.journal.pending(), 0);
    let bytes = journal::read_bounded(&mut store, journal::CURRENT).unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("generation-recovery-event"));
    println!("80 lost OPEN ACK generations bounded at one leaked handle; persistence recovered");
}
#[test]
fn actual_budget_allows_115_tick_commit_but_bounds_ordinary_operations_and_drain() {
    use absd_fsd::journal_rpc::bounded_request;
    use std::sync::atomic::Ordering::Relaxed;
    let mut server = fresh_server();
    NOW.store(600000, Relaxed);
    let deadline = std::cell::Cell::new(604000);
    let mut store = RpcStore::new(|frame: Vec<u8>| {
        bounded_request(frame, ticks(), deadline.get(), |frame, budget| {
            let commit = frame[proto::HEADER] == proto::op::COMMIT;
            let reply = request(&mut server, frame);
            if commit {
                NOW.fetch_add(115.min(budget), Relaxed);
                if budget < 115 {
                    return Err(-110);
                }
            }
            Ok(reply)
        })
    });
    store.begin().unwrap();
    let mut c = collector::Collector::new(&mut store, *b"0123456789abcdef0123456789abcdef");
    c.poll(&mut store);
    assert!(
        c.journal.flushed > 0,
        "a healthy 115 tick COMMIT must flush"
    );
    let ordinary = proto::Frame::request(proto::op::MKDIR)
        .bytes(b"/x")
        .finish();
    let commit = proto::Frame::request(proto::op::COMMIT).finish();
    assert_eq!(
        bounded_request(ordinary, 10, 4010, |_, budget| Ok((budget as i64, vec![])))
            .unwrap()
            .0,
        100
    );
    assert_eq!(
        bounded_request(commit.clone(), 10, 4010, |_, budget| Ok((
            budget as i64,
            vec![]
        )))
        .unwrap()
        .0,
        1000
    );
    assert_eq!(
        bounded_request(commit.clone(), 995, 1000, |_, budget| Ok((
            budget as i64,
            vec![]
        )))
        .unwrap()
        .0,
        5
    );
    assert_eq!(
        bounded_request(commit, 1000, 1000, |_, _| panic!(
            "deadline must stop transport"
        )),
        Err(-110)
    );
    c.event(&mut store, b"finite commit negative control");
    let flushed = c.journal.flushed;
    assert!(c.journal.written > flushed);
    deadline.set(ticks() + 100);
    assert_eq!(c.journal.sync(&mut store), Err(Error::Device(-110)));
    assert_eq!(
        c.journal.flushed, flushed,
        "an insufficient whole-pass remainder cannot claim sync success"
    );
    deadline.set(ticks() + 1000);
    c.drain(&mut store);
    assert_eq!(c.journal.written, c.journal.flushed);
}
#[test]
fn drain_immediately_retries_pending_backoff_once_then_stops_on_no_progress() {
    use std::sync::atomic::Ordering::Relaxed;
    let mut server = fresh_server();
    NOW.store(700000, Relaxed);
    let mut store = StoreFaults {
        inner: RpcStore::new(|frame| Ok(request(&mut server, frame))),
        fail_write: false,
        lose_write_reply: false,
        lose_sync_reply: false,
    };
    store.inner.begin().unwrap();
    let mut c = collector::Collector::new(&mut store, *b"0123456789abcdef0123456789abcdef");
    for _ in 0..40 {
        c.poll(&mut store);
    }
    store.fail_write = true;
    for n in 0..5 {
        service(2, 8, format!("drain-backoff-marker{n}").as_bytes());
    }
    c.poll(&mut store);
    assert!(c.journal.pending() > 0);
    NOW.fetch_add(10, Relaxed);
    c.drain(&mut store);
    assert_eq!(
        c.journal.pending(),
        0,
        "healthy FSD should drain retained pending work without waiting through backoff"
    );
    let bytes = journal::read_bounded(&mut store, journal::CURRENT).unwrap();
    assert_eq!(
        bytes
            .split_inclusive(|b| *b == b'\n')
            .filter_map(Record::parse)
            .filter(|r| r.message.contains("drain-backoff-marker"))
            .count(),
        5
    );
}

#[test]
fn lifecycle_golden_binds_actual_kernel_policy_and_platform_exit() {
    let platform = include_str!("logd-lifecycle-v1.txt")
        .trim()
        .parse::<i64>()
        .unwrap();
    assert_eq!(platform, kernel_policy::REATTACH_EXIT_STATUS);
    assert_eq!(platform, absd_fsd::journal_rpc::REATTACH_EXIT_STATUS as i64);
}
#[test]
fn uncertain_close_begin_and_handle_quota_fence_transport_until_successful_begin() {
    use journal::Store;
    for lost_op in [proto::op::CLOSE, proto::op::LOGGER_BEGIN] {
        let server = Rc::new(RefCell::new(fresh_server()));
        server.borrow_mut().fs.mkdir(journal::DIR).unwrap();
        let lost = std::cell::Cell::new(false);
        let calls = std::cell::Cell::new(0);
        let mut store = RpcStore::new(|frame: Vec<u8>| {
            calls.set(calls.get() + 1);
            let opcode = frame[proto::HEADER];
            let reply = request(&mut server.borrow_mut(), frame);
            if opcode == lost_op && lost.replace(false) {
                return Err(-110);
            }
            Ok(reply)
        });
        store.begin().unwrap();
        let h = store
            .open(
                journal::CURRENT,
                absd_fs::OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .unwrap();
        lost.set(true);
        let result = if lost_op == proto::op::CLOSE {
            store.close(h)
        } else {
            store.begin()
        };
        assert_eq!(result, Err(Error::Device(-110)));
        assert!(store.needs_reattachment());
        let before = calls.get();
        assert!(store.sync().is_err());
        assert_eq!(calls.get(), before, "fenced operation cannot reach server");
        store.begin().unwrap();
        assert!(!store.needs_reattachment());
        assert_eq!(server.borrow().logger_opens(), 0);
        store.sync().unwrap();
    }
    let server = Rc::new(RefCell::new(fresh_server()));
    server.borrow_mut().fs.mkdir(journal::DIR).unwrap();
    let mut store = RpcStore::new(|frame| Ok(request(&mut server.borrow_mut(), frame)));
    store.begin().unwrap();
    for _ in 0..64 {
        store
            .open(
                journal::CURRENT,
                absd_fs::OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .unwrap();
    }
    assert_eq!(
        store.open(journal::CURRENT, Default::default()),
        Err(Error::Device(-24))
    );
    assert!(store.needs_reattachment());
    assert!(store.sync().is_err());
    store.begin().unwrap();
    assert_eq!(server.borrow().logger_opens(), 0);
    store.sync().unwrap();
}
#[test]
fn drain_stops_after_one_failed_immediate_retry_without_spinning_through_backoff() {
    use std::sync::atomic::Ordering::Relaxed;
    let mut server = fresh_server();
    NOW.store(800000, Relaxed);
    let broken = std::cell::Cell::new(false);
    let writes = std::cell::Cell::new(0);
    let mut store = RpcStore::new(|frame: Vec<u8>| {
        if broken.get() && frame[proto::HEADER] == proto::op::WRITE_AT {
            writes.set(writes.get() + 1);
            return Err(-110);
        }
        Ok(request(&mut server, frame))
    });
    store.begin().unwrap();
    let mut c = collector::Collector::new(&mut store, *b"0123456789abcdef0123456789abcdef");
    for _ in 0..40 {
        c.poll(&mut store);
    }
    broken.set(true);
    service(2, 8, b"drain-still-broken");
    c.poll(&mut store);
    assert!(c.journal.pending() > 0);
    writes.set(0);
    let before = c.journal.written;
    c.drain(&mut store);
    assert_eq!(
        writes.get(),
        1,
        "no progress must stop rather than repeatedly bypassing backoff"
    );
    assert_eq!(c.journal.written, before);
    assert!(c.journal.pending() > 0);
    assert!(c.journal.sink_error.is_some());
}

#[test]
fn premain_logger_version_timeout_stays_transient_and_below_watchdog_but_other_refusals_do_not() {
    use absd_fsd::{client_startup, proto, version};
    for _ in 0..30 {
        let result = client_startup::check(b"logd", false, |frame, ticks| {
            assert_eq!(frame[proto::HEADER], proto::op::VERSION);
            assert_eq!(
                ticks, 1000,
                "logger cannot enter the generic 60000 tick pre-main wait"
            );
            Err(version::TIMEOUT)
        });
        assert_eq!(result, Err((version::Refusal::NoAnswer, 75)));
    }
}
#[test]
fn actual_kernel_logger_record_names_the_real_runtime_consumer() {
    let mut bytes = [0; 128];
    let used = kernel_startup::logd_startup_record(&mut bytes).unwrap();
    let hex = include_str!("logd-startup-v1.hex").trim();
    let golden: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect();
    assert_eq!(&bytes[..used], golden);
    let startup = absd_broker::parse_startup(&bytes[..used], 7).unwrap();
    assert_eq!(startup.name, b"logd");
    assert_eq!(startup.cwd, b"/");
}

#[test]
fn premain_protocol_failures_are_not_free_retries_and_generic_clients_keep_startup_allowance() {
    use absd_fsd::{client_startup, version};
    for failure in [Err(-9), Ok((-110, vec![])), Ok((0, vec![1, 2, 3]))] {
        assert_eq!(
            client_startup::check(b"logd", false, |_, _| failure)
                .unwrap_err()
                .1,
            104
        );
    }
    let mut mismatched = version::compiled();
    mismatched.fsd_protocol += 1;
    assert_eq!(
        client_startup::check(b"logd", false, |_, _| Ok((0, version::encode(&mismatched))))
            .unwrap_err()
            .1,
        104
    );
    for name in [b"sshd".as_slice(), b"absd-std-probe", b"/bin/logd"] {
        let refusal = client_startup::check(name, false, |_, ticks| {
            assert_eq!(ticks, 60000);
            Err(-110)
        })
        .unwrap_err();
        assert_eq!(refusal.1, 104);
    }
    let compiled = version::compiled();
    assert_eq!(
        client_startup::check(b"logd", false, |_, ticks| {
            assert_eq!(ticks, 1000);
            Ok((0, version::encode(&compiled)))
        }),
        Ok(compiled)
    );
}

#[test]
fn only_new_kernel_acquisition_with_successful_sync_credits_the_current_generation() {
    let mut server = fresh_server();
    let mut store = StoreFaults {
        inner: RpcStore::new(|frame| Ok(request(&mut server, frame))),
        fail_write: false,
        lose_write_reply: false,
        lose_sync_reply: false,
    };
    store.inner.begin().unwrap();
    let boot = *b"0123456789abcdef0123456789abcdef";
    let mut first = collector::Collector::new(&mut store, boot);
    service(2, 8, b"last-before-reattach-credit");
    for _ in 0..40 {
        first.poll(&mut store);
    }
    assert!(first.confirmed_acquisition_notice(&mut store).is_some());
    store.inner.begin().unwrap();
    let mut next = collector::Collector::new(&mut store, boot);
    assert!(next.journal.written > 0, "old persisted prefix exists");
    for _ in 0..3 {
        next.poll(&mut store);
    }
    assert!(
        !next.confirmed_acquisition_notice(&mut store).is_some(),
        "READY and old-prefix sync are not new collection"
    );
    service(2, 8, b"fresh-after-reattach-credit");
    for _ in 0..3 {
        next.poll(&mut store);
    }
    store.lose_sync_reply = true;
    assert!(
        !next.confirmed_acquisition_notice(&mut store).is_some(),
        "unknown sync completion earns no credit"
    );
    next.journal.sync(&mut store).unwrap();
    let notice = next.confirmed_acquisition_notice(&mut store).unwrap();
    let mut probe = kernel_policy::Collected::new();
    assert!(
        probe.push(notice.as_bytes()),
        "actual collector notice must reach init's exact parser"
    );
}

#[test]
fn actual_supervisor_formatter_kernel_lifecycle_and_health_consumer_share_conformance() {
    let golden = include_str!("logd-supervision-v1.txt");
    let expected: Vec<&str> = golden.lines().collect();
    let mut probe = kernel_policy::Collected::new();
    assert!(probe.push(format!("{}\n", expected[0]).as_bytes()));
    for (index, retrying, count, ticks) in [(1, true, 17, 60000), (2, false, 0, 0)] {
        let mut text = String::new();
        kernel_policy::write_observation(&mut text, retrying, count, 1, ticks).unwrap();
        assert_eq!(text, expected[index]);
        let mut request = [0; 296];
        for (at, value) in [(0, 1u64), (8, 1), (16, 3), (24, 3), (32, text.len() as u64)] {
            request[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        request[40..40 + text.len()].copy_from_slice(text.as_bytes());
        let produced = kernel_producer::service_request(&request, 0).unwrap();
        let record = Record {
            boot: *b"0123456789abcdef0123456789abcdef",
            sequence: 99,
            ticks: 1000,
            severity: 5,
            source: std::str::from_utf8(produced.source).unwrap().into(),
            kernel_sequence: Some(99),
            flags: 0,
            message: std::str::from_utf8(&produced.message[..produced.len])
                .unwrap()
                .into(),
        };
        assert!(logs::supervisor_record(&record).is_some());
    }
}

#[test]
fn a_thirty_second_storage_outage_reaches_healing_without_charging_a_crash() {
    use absd_fsd::{client_startup, version};
    let mut policy = kernel_policy::Policy::new();
    let mut now = 0;
    let mut attempts = 0;
    loop {
        assert!(policy.begin(now));
        policy.spawned();
        attempts += 1;
        let result = client_startup::check(b"logd", false, |_, budget| {
            assert_eq!(budget, 1000);
            if now < 30000 {
                now += budget;
                Err(-110)
            } else {
                Ok((0, version::encode(&version::compiled())))
            }
        });
        match result {
            Ok(_) => break,
            Err((version::Refusal::NoAnswer, 75)) => {
                policy.ended(now, 75);
                now = policy.due;
            }
            other => panic!("unexpected disposition {other:?}"),
        }
    }
    assert_eq!(attempts, 6);
    assert_eq!(now, 36000);
    assert_eq!(policy.restarts, 0);
    assert_eq!(
        policy.unproductive, 5,
        "VERSION success is not collection credit"
    );
}

#[test]
fn repeated_collection_notices_require_both_a_minute_and_newly_synced_kernel_data() {
    use std::sync::atomic::Ordering::Relaxed;
    NOW.store(900000, Relaxed);
    let mut server = fresh_server();
    let mut store = StoreFaults {
        inner: RpcStore::new(|frame| Ok(request(&mut server, frame))),
        fail_write: false,
        lose_write_reply: false,
        lose_sync_reply: false,
    };
    store.inner.begin().unwrap();
    let mut c = collector::Collector::new(&mut store, *b"0123456789abcdef0123456789abcdef");
    service(2, 8, b"productivity-first");
    for _ in 0..40 {
        c.poll(&mut store);
    }
    assert!(c.confirmed_acquisition_notice(&mut store).is_some());
    NOW.store(960000, Relaxed);
    assert!(
        c.confirmed_acquisition_notice(&mut store).is_none(),
        "lifetime and old prefix are not fresh sync evidence"
    );
    assert!(PRODUCER.emit(b"service.fsd", 6, Some(960000), b"fresh-minute-sync", 0));
    for _ in 0..4 {
        c.poll(&mut store);
    }
    store.lose_sync_reply = true;
    assert!(
        c.confirmed_acquisition_notice(&mut store).is_none(),
        "unknown fresh sync gets no marker"
    );
    c.journal.sync(&mut store).unwrap();
    assert!(c.confirmed_acquisition_notice(&mut store).is_some());
    NOW.store(960001, Relaxed);
    assert!(PRODUCER.emit(
        b"service.fsd",
        6,
        Some(960001),
        b"fresh-but-not-a-minute",
        0
    ));
    for _ in 0..4 {
        c.poll(&mut store);
    }
    assert!(
        c.confirmed_acquisition_notice(&mut store).is_none(),
        "new data alone cannot create marker wallpaper"
    );
    NOW.store(1020000, Relaxed);
    assert!(c.confirmed_acquisition_notice(&mut store).is_some());
}

#[test]
fn terminal_notices_from_the_actual_kernel_policy_reach_the_health_consumer() {
    let golden: Vec<&str> = include_str!("logd-supervision-v1.txt").lines().collect();
    for (index, text) in [
        (3, kernel_policy::EXHAUSTED_NOTICE),
        (4, kernel_policy::QUARANTINED_NOTICE),
        (5, kernel_policy::UNCONFIRMED_NOTICE),
    ] {
        assert_eq!(text, golden[index]);
        let mut request = [0; 296];
        for (at, value) in [(0, 1u64), (8, 1), (16, 3), (24, 3), (32, text.len() as u64)] {
            request[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        request[40..40 + text.len()].copy_from_slice(text.as_bytes());
        let produced = kernel_producer::service_request(&request, 0).unwrap();
        let record = Record {
            boot: *b"0123456789abcdef0123456789abcdef",
            sequence: 100,
            ticks: 1000,
            severity: 3,
            source: std::str::from_utf8(produced.source).unwrap().into(),
            kernel_sequence: Some(100),
            flags: 0,
            message: std::str::from_utf8(&produced.message[..produced.len])
                .unwrap()
                .into(),
        };
        assert!(logs::supervisor_record(&record).is_some());
    }
}
