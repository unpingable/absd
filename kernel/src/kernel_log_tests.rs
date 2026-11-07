use crate::handle::{Object, RIGHT_READ, RIGHT_WRITE};
use crate::kernel_log::{
    CAPACITY, EMERGENCY, Log, MAX_MESSAGE, PARTIAL, TRUNCATED, reader_authorized,
};
use std::vec::Vec;

#[test]
fn independent_cursors_and_wraparound_report_exact_loss() {
    let log = Log::new();
    for _ in 0..CAPACITY + 7 {
        assert!(log.emit(b"nic", 6, Some(4), b"carrier up", 0));
    }
    let a = log.read(1).unwrap();
    let b = log.read(1).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.lost, 7);
    assert_eq!(a.oldest, 8);
    assert_eq!(a.record.unwrap().sequence, 8);
    assert_eq!(log.read(0).unwrap().lost, 0);
    assert_eq!(log.read(a.next).unwrap().record.unwrap().sequence, 9);
    assert_eq!(log.read(a.end).unwrap().record, None);
    assert!(log.read(a.end + 1).is_err());
}

#[test]
fn fragmented_lines_remain_complete_and_long_lines_are_explicitly_truncated() {
    let log = Log::new();
    for &b in b"RTL8125 carrier " {
        log.byte(b, None);
    }
    assert!(log.read(0).unwrap().record.is_none());
    for &b in b"up\n" {
        log.byte(b, Some(9));
    }
    let a = log.read(0).unwrap().record.unwrap();
    assert_eq!(a.text(), b"RTL8125 carrier up");
    assert_eq!(a.source(), b"RTL8125");
    assert_eq!(a.ticks, None); // first fragment determines timestamp
    for _ in 0..MAX_MESSAGE + 91 {
        log.byte(b'x', Some(10));
    }
    log.byte(b'\n', Some(10));
    let a = log.read(2).unwrap().record.unwrap();
    assert_eq!(a.text().len(), MAX_MESSAGE);
    assert_ne!(a.flags & TRUNCATED, 0);
    log.byte(b'p', None);
    log.flush();
    assert_ne!(log.read(3).unwrap().record.unwrap().flags & PARTIAL, 0);
}

#[test]
fn source_message_and_emergency_work_are_bounded() {
    let log = Log::new();
    log.emit(
        b"source-that-is-over-sixteen",
        3,
        None,
        &[1; MAX_MESSAGE + 20],
        EMERGENCY,
    );
    let a = log.read(0).unwrap().record.unwrap();
    assert_eq!(a.source().len(), 16);
    assert_eq!(a.text().len(), MAX_MESSAGE);
    assert_eq!(a.flags, TRUNCATED | EMERGENCY);
}

#[test]
fn diagnostic_authority_refuses_wrong_object_or_missing_right() {
    assert!(reader_authorized(Object::Console, RIGHT_WRITE, true));
    assert!(!reader_authorized(Object::Console, RIGHT_READ, true));
    assert!(!reader_authorized(Object::None, RIGHT_WRITE, true));
    assert!(!reader_authorized(Object::Machine, RIGHT_WRITE, true));
}

#[test]
fn concurrent_writers_readers_never_publish_torn_records() {
    let log = std::sync::Arc::new(Log::new());
    let threads: Vec<_> = (0..4)
        .map(|n| {
            let log = log.clone();
            std::thread::spawn(move || {
                for _ in 0..10_000 {
                    log.emit(b"test", 6, Some(n), &[b'A' + n as u8; 100], 0);
                }
            })
        })
        .collect();
    for _ in 0..10_000 {
        if let Ok(r) = log.read(0)
            && let Some(r) = r.record
        {
            assert_eq!(r.text(), &[b'A' + r.ticks.unwrap() as u8; 100]);
        }
    }
    for thread in threads {
        thread.join().unwrap();
    }
    let r = loop {
        if let Ok(r) = log.read(0) {
            break r;
        }
    };
    assert!(r.end > 1);
    // Scheduling need not cause contention; the held-lock test proves loss accounting.
}

#[test]
fn closed_capability_cannot_read_diagnostics() {
    use crate::handle::HandleTable;
    let mut handles = HandleTable::new(123);
    let handle = handles.insert(Object::Console, RIGHT_WRITE).unwrap();
    handles.close(handle).unwrap();
    assert!(handles.lookup(handle).is_err());
}
#[test]
fn held_lock_refuses_nested_reader_and_counts_dropped_writer_without_waiting() {
    // This deterministic same-context reentry control uses the real lock.
    let log = Log::new();
    log.test_while_locked(|| {
        assert_eq!(log.read(0), Err(-11));
        assert!(!log.emit(b"irq", 3, None, b"interrupt reentry", 0));
    });
    assert_eq!(log.read(0).unwrap().producer_dropped, 1);
    assert!(log.emit(b"recovered", 6, None, b"ordinary write continues", 0));
}
#[test]
fn v1_wire_matches_shared_golden() {
    let log = Log::new();
    log.emit(b"nic", 4, Some(12), b"x\ny", TRUNCATED);
    let actual = log.read(0).unwrap().encode();
    let hex = include_str!("../tests/fixtures/kernel-log-v1.hex").trim();
    let expected: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(actual.as_slice(), expected);
}

#[test]
fn stdout_pipe_does_not_mint_diagnostic_authority_but_owned_console_resolves_zero() {
    use crate::handle::{HandleError, HandleTable};
    use crate::kernel_log::authorize_reader_for;
    let mut handles = HandleTable::new(999);
    assert_eq!(
        authorize_reader_for(&handles, 0, true),
        Err(HandleError::Rights)
    );
    let wrong = handles.insert(Object::Machine, RIGHT_WRITE).unwrap();
    assert_eq!(
        authorize_reader_for(&handles, wrong, true),
        Err(HandleError::Rights)
    );
    assert_eq!(
        authorize_reader_for(&handles, 0, true),
        Err(HandleError::Rights)
    );
    let readonly = handles.insert(Object::Console, RIGHT_READ).unwrap();
    assert_eq!(
        authorize_reader_for(&handles, readonly, true),
        Err(HandleError::Rights)
    );
    let console = handles.insert(Object::Console, RIGHT_WRITE).unwrap();
    assert_eq!(authorize_reader_for(&handles, 0, true), Ok(()));
    handles.close(console).unwrap();
    assert_eq!(
        authorize_reader_for(&handles, console, true),
        Err(HandleError::Invalid)
    );
    assert_eq!(
        authorize_reader_for(&handles, 0, true),
        Err(HandleError::Rights)
    );
}

#[test]
fn static_retention_is_smaller_than_eighty_kib() {
    assert!(core::mem::size_of::<Log>() < 80 * 1024);
}

#[test]
fn real_spawn_transfer_installation_retires_console_and_preserves_only_diagnostics_read() {
    use crate::handle::{HandleError, HandleTable};
    use crate::kernel_log::authorize_reader_for;
    let pipe = Object::Pipe(crate::object::PipeId::for_tests(1));
    // Reproduce the rejected path with the real transfer installer: a
    // replacement stdout pipe alone has no remaining Console authority.
    let mut no_grant = HandleTable::new(32);
    let old = no_grant
        .insert(Object::Console, RIGHT_READ | RIGHT_WRITE)
        .unwrap();
    no_grant
        .install_spawn_transfers(Some(old), &[(pipe, RIGHT_WRITE)], &mut [0])
        .unwrap();
    assert_eq!(
        authorize_reader_for(&no_grant, 0, false),
        Err(HandleError::Rights)
    );
    let mut child = HandleTable::new(33);
    let default = child
        .insert(Object::Console, RIGHT_READ | RIGHT_WRITE)
        .unwrap();
    let mut issued = [0; 2];
    child
        .install_spawn_transfers(
            Some(default),
            &[(pipe, RIGHT_WRITE), (Object::Diagnostics, RIGHT_READ)],
            &mut issued,
        )
        .unwrap();
    assert_eq!(child.lookup(default), Err(HandleError::Invalid));
    assert_eq!(child.console_rights(), 0);
    assert_eq!(authorize_reader_for(&child, 0, false), Ok(()));
    assert_eq!(
        authorize_reader_for(&child, issued[0], false),
        Err(HandleError::Rights)
    );
    assert_eq!(
        child.duplicate(issued[1], RIGHT_WRITE),
        Err(HandleError::Rights)
    );
    assert!(!child.has_bsp_authority());
    assert_eq!(
        child.console(issued[1], RIGHT_READ),
        Err(HandleError::Invalid)
    );
    assert_eq!(
        child.insert(Object::Diagnostics, RIGHT_WRITE),
        Err(HandleError::Rights)
    );
    child.close(issued[1]).unwrap();
    assert_eq!(
        authorize_reader_for(&child, 0, false),
        Err(HandleError::Rights)
    );
}
#[test]
fn root_init_role_excludes_reparented_init_image_and_child_mint() {
    use crate::kernel_log::root_init_role;
    assert!(root_init_role(1, 0, crate::program::INIT as usize));
    assert!(!root_init_role(8, 0, crate::program::INIT as usize));
    assert!(!root_init_role(1, 8, crate::program::INIT as usize));
    assert!(!root_init_role(1, 0, crate::program::INIT as usize + 1));
}
#[test]
fn streamed_metadata_is_inferred_and_contention_marks_damaged_records_unknown() {
    use crate::kernel_log::{INFERRED, LOSS};
    let log = Log::new();
    for &b in b"NIC carrier" {
        log.byte(b, None);
    }
    log.test_while_locked(|| log.byte(b'\n', None));
    for &b in b"STORAGE ERROR\n" {
        log.byte(b, None);
    }
    let r = log.read(0).unwrap().record.unwrap();
    assert_eq!(r.flags & (INFERRED | LOSS), INFERRED | LOSS);
    assert_eq!(r.source(), b"unknown");
    assert_eq!(r.severity, 6);
    log.emit(b"typed", 3, None, b"typed", 0);
    assert_eq!(log.read(2).unwrap().record.unwrap().flags, 0);
}
#[test]
fn real_read_request_parser_rejects_clear_reserved_garbage_and_version() {
    use crate::kernel_log::{FRAME_BYTES, read_request};
    let mut b = [0; FRAME_BYTES];
    b[..4].copy_from_slice(&1u32.to_le_bytes());
    b[8..16].copy_from_slice(&7u64.to_le_bytes());
    assert_eq!(read_request(&b, 0), Ok(7));
    assert_eq!(read_request(&b, 1), Err(-22));
    b[4] = 1;
    assert_eq!(read_request(&b, 0), Err(-22));
    b[4] = 0;
    b[568] = 1;
    assert_eq!(read_request(&b, 0), Err(-22));
    b[568] = 0;
    b[0] = 2;
    assert_eq!(read_request(&b, 0), Err(-22));
}

#[test]
fn real_service_parser_rejects_forged_layout_and_assigns_fixed_attribution() {
    use crate::kernel_log::service_request;
    let mut b = [0; 296];
    for (at, n) in [(0, 1u64), (8, 55), (16, 2), (24, 2), (32, 3)] {
        b[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    b[40..43].copy_from_slice(b"x\ny");
    let r = service_request(&b, 0).unwrap();
    assert_eq!(r.source, b"service.fsd");
    assert_eq!(r.severity, 4);
    assert_eq!(&r.message[..r.len], b"pid=55 stream=stderr x\ny");
    assert!(service_request(&b, 1).is_err());
    b[295] = 1;
    assert!(service_request(&b, 0).is_err());
    b[295] = 0;
    b[32..40].copy_from_slice(&257u64.to_le_bytes());
    assert!(service_request(&b, 0).is_err());
    b[32..40].copy_from_slice(&3u64.to_le_bytes());
    b[16] = 3;
    let collector = service_request(&b, 0).unwrap();
    assert_eq!(collector.source, b"service.logd");
    assert_eq!(
        &collector.message[..collector.len],
        b"pid=55 stream=stderr x\ny"
    );
    b[16] = 4;
    assert!(service_request(&b, 0).is_err());
    b[16] = 2;
    b[24] = 3;
    let lifecycle = service_request(&b, 0).unwrap();
    assert_eq!(lifecycle.severity, 5);
    b[24] = 4;
    assert!(service_request(&b, 0).is_err());
    b[24] = 2;
    b[0] = 2;
    assert!(service_request(&b, 0).is_err());
}

#[test]
fn init_collector_exhaustion_notice_is_retained_without_a_logger() {
    let message = b"init: restart budget exhausted";
    let mut frame = [0u8; 296];
    for (at, word) in [
        (0, 1u64),
        (8, 1),
        (16, 3),
        (24, 3),
        (32, message.len() as u64),
    ] {
        frame[at..at + 8].copy_from_slice(&word.to_le_bytes());
    }
    frame[40..40 + message.len()].copy_from_slice(message);
    let parsed = crate::kernel_log::service_request(&frame, 0).unwrap();
    let log = Log::new();
    assert!(log.emit(
        parsed.source,
        parsed.severity,
        Some(123),
        &parsed.message[..parsed.len],
        0
    ));
    let retained = log.read(0).unwrap().record.unwrap();
    assert_eq!(retained.source(), b"service.logd");
    assert_eq!(retained.severity, 5);
    assert_eq!(
        retained.text(),
        b"pid=1 stream=lifecycle init: restart budget exhausted"
    );
    // PID zero remains invalid: a missing incarnation is never fabricated.
    frame[8..16].fill(0);
    assert!(crate::kernel_log::service_request(&frame, 0).is_err());
}
