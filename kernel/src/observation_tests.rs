use super::*;
use crate::handle::{Object, RIGHT_WRITE};
use crate::observation;
use crate::process::{Process, ProcessState, WaitKind};

fn word(record: &[u8; BYTES], at: usize) -> u64 {
    u64::from_le_bytes(record[at * 8..at * 8 + 8].try_into().unwrap())
}

#[test]
fn readable_wait_adds_code_nine_without_renumbering_existing_waits() {
    for (kind, code) in [
        (WaitKind::None, 0),
        (WaitKind::Child, 1),
        (WaitKind::Cell, 2),
        (WaitKind::Pipe, 3),
        (WaitKind::Console, 4),
        (WaitKind::Sleep, 5),
        (WaitKind::RtRelease, 6),
        (WaitKind::Nic, 7),
        (WaitKind::StopFence, 8),
        (WaitKind::Readable, 9),
    ] {
        let process = Process {
            wait_kind: kind,
            ..Process::EMPTY
        };
        assert_eq!(word(&process_record(&process, 0, 0), 8), code);
    }
}

#[test]
fn current_process_state_is_observed_without_exporting_fault_addresses() {
    let mut process = Process::EMPTY;
    process.pid = 47;
    process.parent = 2;
    process.state = ProcessState::Waiting;
    process.wait_kind = WaitKind::Pipe;
    process.program = 30;
    process.fault_address = 0xdeadbeef;
    process
        .handles
        .insert(Object::Console, RIGHT_WRITE)
        .unwrap();
    let record = observation::process_record(&process, 900, 3);
    assert_eq!(word(&record, 0), 1);
    assert_eq!(word(&record, 1), 1);
    assert_eq!(word(&record, 2), 900);
    assert_eq!(word(&record, 3), 3);
    assert_eq!(word(&record, 4), 47);
    assert_eq!(word(&record, 5), 2);
    assert_eq!(word(&record, 7), 4);
    assert_eq!(word(&record, 8), 3);
    assert_eq!(word(&record, 9), 1);
    assert!(
        !record
            .windows(8)
            .any(|bytes| bytes == 0xdeadbeefu64.to_le_bytes())
    );
}

#[test]
fn terminal_process_outcomes_are_distinct_from_a_running_process() {
    let mut process = Process::EMPTY;
    process.pid = 48;
    process.state = ProcessState::Exited;
    process.exit_status = -4;
    let record = observation::process_record(&process, 901, 5);
    assert_eq!(word(&record, 7), 5);
    assert_eq!(word(&record, 10) as i64, -4);
    process.state = ProcessState::Faulted;
    process.fault_vector = 14;
    let record = observation::process_record(&process, 902, 5);
    assert_eq!(word(&record, 7), 6);
    assert_eq!(word(&record, 11), 14);
}

#[test]
fn no_cpu_claim_is_explicitly_unknown() {
    let record = observation::process_record(&Process::EMPTY, 0, 0);
    assert_eq!(word(&record, 12), u64::MAX);
    assert!(record[15 * 8..].iter().all(|byte| *byte == 0));
}

fn golden(text: &str) -> [u8; BYTES] {
    let text = text.trim();
    assert_eq!(text.len(), BYTES * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}

#[test]
fn process_encoder_matches_platform_shared_vector() {
    let mut process = Process::EMPTY;
    process.pid = 47;
    process.parent = 2;
    process.program = 30;
    process.state = ProcessState::Waiting;
    process.wait_kind = WaitKind::Pipe;
    process.may_spawn = false;
    process
        .handles
        .insert(Object::Console, RIGHT_WRITE)
        .unwrap();
    assert_eq!(
        process_record(&process, 900, 3),
        golden(include_str!("../tests/fixtures/observation-process-v1.hex"))
    );
}

#[test]
fn nic_encoder_matches_platform_shared_vectors() {
    let info = crate::nic::NicInfo {
        mac: [2, 0, 0, 0x12, 0x34, 0x56],
        flags: crate::nic::NIC_FLAG_LINK_UP,
        rx_frames: 11,
        rx_refused: 12,
        rx_missed: 13,
        tx_frames: 14,
        tx_refused: 15,
        tx_errors: 16,
    };
    let identity = Some((0x219, info.mac));
    assert_eq!(
        nic_record(3, true, identity, Some(info), 900, 901),
        golden(include_str!("../tests/fixtures/observation-nic-v1.hex"))
    );
    assert_eq!(
        nic_record(3, false, None, None, 900, 901),
        golden(include_str!(
            "../tests/fixtures/observation-nic-unavailable-v1.hex"
        ))
    );
    let disabled = crate::nic::NicInfo {
        flags: info.flags | crate::nic::NIC_FLAG_DISABLED,
        ..info
    };
    let record = nic_record(3, true, identity, Some(disabled), 900, 901);
    assert_eq!(word(&record, 5), 1);
    assert_eq!(
        word(&record, 6),
        u64::MAX,
        "disabled never reports a stale UP state"
    );
    assert_eq!(word(&record, 11), 11);
}

#[test]
fn candidate_encoder_matches_platform_shared_vector() {
    assert_eq!(
        candidate_record(0, 0x219, 0x10ec, 0x8125, true, 7, 902),
        golden(include_str!(
            "../tests/fixtures/observation-candidate-v1.hex"
        ))
    );
    assert_eq!(
        candidate_record(0, 0x219, 0x10ec, 0x8125, false, 7, 902),
        golden(include_str!(
            "../tests/fixtures/observation-candidate-inactive-v1.hex"
        ))
    );
}

#[test]
fn capacity_record_reports_actual_tables_without_changing_the_spawn_vector() {
    let record = capacity_record(7);
    assert_eq!(
        (word(&record, 0), word(&record, 1), word(&record, 2)),
        (1, 4, 7)
    );
    assert_eq!(
        (
            word(&record, 3),
            word(&record, 4),
            word(&record, 5),
            word(&record, 6),
            word(&record, 7)
        ),
        (32, 128, 64, 128, 32)
    );
    assert!(record[64..].iter().all(|b| *b == 0));
    let hex = include_str!("../tests/fixtures/capacity-v1.hex").trim();
    let bytes: std::vec::Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(capacity_record(0).as_slice(), bytes);
}
