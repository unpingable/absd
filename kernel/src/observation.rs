//! Private operator observation frames. Versioned bytes, never native layout.
//! A PID is boot scoped; table slot positions are traversal cursors, not identity.
use crate::process::{Process, ProcessState, WaitKind};

pub const BYTES: usize = 256;
pub const SYS_OBSERVATION: u64 = 0x7fc1;
pub const QUERY_NIC: u64 = 256;
pub const QUERY_CAPACITY: u64 = 257;

pub fn put(record: &mut [u8; BYTES], at: usize, value: u64) {
    record[at * 8..at * 8 + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn process_record(process: &Process, ticks: u64, slot: usize) -> [u8; BYTES] {
    let mut record = [0; BYTES];
    let state = match process.state {
        ProcessState::Empty => 0,
        ProcessState::Created => 1,
        ProcessState::Runnable => 2,
        ProcessState::Running => 3,
        ProcessState::Waiting => 4,
        ProcessState::Exited => 5,
        ProcessState::Faulted => 6,
        ProcessState::Killed => 7,
    };
    let wait = match process.wait_kind {
        WaitKind::None => 0,
        WaitKind::Child => 1,
        WaitKind::Cell => 2,
        WaitKind::Pipe => 3,
        WaitKind::Console => 4,
        WaitKind::Sleep => 5,
        WaitKind::RtRelease => 6,
        WaitKind::Nic => 7,
        WaitKind::StopFence => 8,
        WaitKind::Readable => 9,
    };
    for (at, value) in [
        1,
        1,
        ticks,
        slot as u64,
        process.pid,
        process.parent,
        process.program as u64,
        state,
        wait,
        process.handles.live_count() as u64,
        process.exit_status as i64 as u64,
        process.fault_vector,
        process
            .cpu_owner
            .map_or(u64::MAX, |claim| u64::from(claim.cpu)),
        process.claim_epoch,
        u64::from(process.may_spawn),
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut record, at, value);
    }
    record
}

/// Fixed v1 readout bytes; device access stays with the serialized caller.
pub fn nic_record(
    driver: u64,
    initialized: bool,
    identity: Option<(u64, [u8; 6])>,
    info: Option<crate::nic::NicInfo>,
    before: u64,
    after: u64,
) -> [u8; BYTES] {
    let mut record = [0; BYTES];
    for (at, value) in [
        1,
        2,
        before,
        driver,
        u64::from(initialized),
        u64::MAX,
        u64::MAX,
        u64::MAX,
        identity.map_or(u64::MAX, |(pci, _)| pci),
        after,
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut record, at, value);
    }
    if let Some((_, mac)) = identity {
        record[80..86].copy_from_slice(&mac);
    }
    if let Some(info) = info {
        let disabled = info.flags & crate::nic::NIC_FLAG_DISABLED != 0;
        put(&mut record, 5, u64::from(disabled));
        put(
            &mut record,
            6,
            if disabled {
                u64::MAX
            } else {
                u64::from(info.flags & crate::nic::NIC_FLAG_LINK_UP != 0)
            },
        );
        for (index, value) in [
            info.rx_frames,
            info.rx_refused,
            info.rx_missed,
            info.tx_frames,
            info.tx_refused,
            info.tx_errors,
        ]
        .into_iter()
        .enumerate()
        {
            put(&mut record, 11 + index, value);
        }
    }
    // Negotiated speed and duplex are not established by these drivers.
    put(&mut record, 17, u64::MAX);
    put(&mut record, 18, u64::MAX);
    record
}

pub fn candidate_record(
    index: usize,
    pci: u64,
    vendor: u16,
    device: u16,
    selected: bool,
    revision: u8,
    ticks: u64,
) -> [u8; BYTES] {
    let mut record = [0; BYTES];
    for (at, value) in [
        1,
        3,
        ticks,
        index as u64,
        pci,
        u64::from(vendor),
        u64::from(device),
        u64::from(selected),
        u64::from(revision),
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut record, at, value);
    }
    record
}

/// Kind4 is the actual finite kernel table profile; kind3 is PCI candidates.
pub fn capacity_record(ticks: u64) -> [u8; BYTES] {
    let mut record = [0; BYTES];
    for (at, value) in [
        1,
        4,
        ticks,
        crate::process::MAX_PROCESSES as u64,
        crate::handle::MAX_HANDLES as u64,
        crate::syscall::MAX_SPAWN_HANDLES as u64,
        crate::object::MAX_PIPES as u64,
        crate::object::MAX_CELLS as u64,
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut record, at, value);
    }
    record
}

#[cfg(test)]
#[path = "observation_tests.rs"]
mod tests;
