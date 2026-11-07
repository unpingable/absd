use super::*;
use std::{string::String, vec::Vec};

fn empty(dropped: u64) -> log::Read {
    log::Read {
        record: None,
        next: 1,
        oldest: 1,
        end: 1,
        lost: 0,
        producer_dropped: dropped,
    }
}
#[test]
fn failed_reads_are_visible_once_and_a_new_snapshot_rearms_reporting() {
    let mut snapshot = Snapshot::new();
    let mut output = Vec::new();
    snapshot.step(|_| Err(-13), |bytes| output.extend_from_slice(bytes));
    snapshot.step(|_| Err(-11), |bytes| output.extend_from_slice(bytes));
    let text = String::from_utf8(output.clone()).unwrap();
    assert_eq!(text.matches("read failed").count(), 1);
    assert!(text.contains("code=-13"));
    snapshot.restart();
    snapshot.step(|_| Err(-11), |bytes| output.extend_from_slice(bytes));
    assert_eq!(
        String::from_utf8(output)
            .unwrap()
            .matches("read failed")
            .count(),
        2
    );
}
#[test]
fn producer_loss_changes_are_reported_even_with_no_record_and_do_not_repeat() {
    let mut snapshot = Snapshot::new();
    let mut output = Vec::new();
    for count in [0, 3, 3, 8, 8] {
        snapshot.step(
            |_| Ok(empty(count)),
            |bytes| output.extend_from_slice(bytes),
        );
    }
    let text = String::from_utf8(output).unwrap();
    assert_eq!(text.matches("producer_dropped=").count(), 2);
    assert!(text.contains("producer_dropped=3 delta=3"));
    assert!(text.contains("producer_dropped=8 delta=5"));
}
#[test]
fn metadata_and_text_are_decoded_from_real_kernel_wire_and_safely_rendered() {
    let ring = crate::kernel_log::Log::new();
    assert!(ring.emit(b"src\x1b", 4, None, b"text\r\n\x1b[2J\\", 31));
    let mut frame = ring.read(0).unwrap().encode();
    frame[32..40].copy_from_slice(&7u64.to_le_bytes());
    frame[40..48].copy_from_slice(&11u64.to_le_bytes());
    let decoded = log::decode(&frame).unwrap();
    let mut snapshot = Snapshot::new();
    let mut output = Vec::new();
    let mut calls = 0;
    snapshot.step(
        |cursor| {
            calls += 1;
            if cursor == 0 {
                Ok(decoded.clone())
            } else {
                let mut e = empty(11);
                e.next = 2;
                e.oldest = 1;
                e.end = 2;
                Ok(e)
            }
        },
        |bytes| output.extend_from_slice(bytes),
    );
    let text = String::from_utf8(output).unwrap();
    for expected in [
        "seq=1",
        "ticks=unavailable",
        "severity=4",
        "source=src\\x1b",
        "flags=31 truncated partial emergency inferred loss",
        "lost=7 oldest=1 end=2",
        "producer_dropped=11",
        "text\\x0d\\x0a\\x1b[2J\\\\",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in {text:?}");
    }
    assert!(!text.as_bytes().contains(&0x1b));
    assert_eq!(calls, 2);
}
#[test]
fn each_pass_has_eight_reads_and_transient_failure_can_recover_without_reset() {
    let ring = crate::kernel_log::Log::new();
    for _ in 0..16 {
        assert!(ring.emit(b"kernel", 6, Some(3), b"ok", 0));
    }
    let mut snapshot = Snapshot::new();
    let mut count = 0;
    snapshot.step(|_| Err(-11), |_| {});
    snapshot.step(
        |cursor| {
            count += 1;
            log::decode(&ring.read(cursor).unwrap().encode())
        },
        |_| {},
    );
    assert_eq!(count, 8);
    assert_eq!(snapshot.cursor, 9);
    snapshot.step(
        |cursor| {
            count += 1;
            log::decode(&ring.read(cursor).unwrap().encode())
        },
        |_| {},
    );
    assert_eq!(count, 16);
    assert_eq!(snapshot.cursor, 17);
}
#[test]
fn malformed_frame_is_a_reported_decode_failure() {
    let ring = crate::kernel_log::Log::new();
    let mut frame = ring.read(0).unwrap().encode();
    frame[0] = 2;
    let mut snapshot = Snapshot::new();
    let mut output = Vec::new();
    snapshot.step(
        |_| log::decode(&frame),
        |bytes| output.extend_from_slice(bytes),
    );
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("read failed: code=-22")
    );
}
