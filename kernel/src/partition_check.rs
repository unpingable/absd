//! The GPT partition qualification boot (`block-partition-qualify`,
//! docs/hardware/GPT-PARTITION.md), run through the ordinary block layer
//! before init starts. It reads the partition's first and last sectors and
//! prints their digests (the host seeded them, so the digests show which
//! device sectors the partition's LBAs reached), reads one run through the
//! multi-sector path, and checks that every request at or past the
//! partition's length is refused by the block layer without a device
//! command. Nothing is written: on a read-only partition a write and a
//! flush must be refused; on a writable one only out-of-range writes are
//! attempted, and they must be refused.

use absd_kernel::syscall::BLOCK_SECTOR_BYTES;

use crate::ahci_block;
use crate::block::{self, Backend, BlockError, MAX_TRANSFER_SECTORS};
use crate::serial;

fn fail(what: &str, lba: u64) -> ! {
    serial::write("BLOCK PARTITION QUALIFY FAILED ");
    serial::write(what);
    serial::write(" lba=");
    serial::decimal(lba);
    serial::write("\n");
    crate::exit_qemu(1)
}

/// Commands the AHCI backend has completed; other backends report none,
/// and their bounds are the block layer's alone.
fn device_commands() -> u64 {
    match block::backend() {
        Some(Backend::Ahci) => ahci_block::completed().0,
        _ => 0,
    }
}

pub fn run() -> ! {
    let Some(sectors) = block::sector_count() else {
        fail("no device", 0);
    };
    if !block::partitioned() {
        fail("no partition", 0);
    }
    if sectors < MAX_TRANSFER_SECTORS as u64 {
        fail("partition too small", sectors);
    }
    let mut first = [0u8; BLOCK_SECTOR_BYTES];
    let mut sector = [0u8; BLOCK_SECTOR_BYTES];
    for lba in [0, sectors - 1] {
        let target = if lba == 0 { &mut first } else { &mut sector };
        if block::read_sector(lba, target).is_err() {
            fail("read", lba);
        }
        serial::write("BLOCK PARTITION READ OK lba=");
        serial::decimal(lba);
        serial::write(" fnv1a=");
        serial::hex(block::fnv1a(target));
        serial::write("\n");
    }
    let mut run = [0u8; BLOCK_SECTOR_BYTES * MAX_TRANSFER_SECTORS];
    if block::read_sectors(0, &mut run).is_err() || run[..BLOCK_SECTOR_BYTES] != first {
        fail("multi-sector read", 0);
    }
    let commands = device_commands();
    let tail = sectors - (MAX_TRANSFER_SECTORS as u64 / 2);
    if block::read_sector(sectors, &mut sector) != Err(BlockError::OutOfRange)
        || block::read_sector(u64::MAX, &mut sector) != Err(BlockError::OutOfRange)
        || block::read_sectors(tail, &mut run) != Err(BlockError::OutOfRange)
        || block::read_sectors(u64::MAX - 1, &mut run) != Err(BlockError::OutOfRange)
        || block::write_sector(sectors, &first) != Err(BlockError::OutOfRange)
        || block::write_sectors(tail, &run) != Err(BlockError::OutOfRange)
        || device_commands() != commands
    {
        fail("bounds", sectors);
    }
    serial::write("BLOCK PARTITION BOUNDS OK lba=");
    serial::decimal(sectors);
    serial::write(" kernel=OutOfRange device_commands=unchanged\n");
    if !block::writable() {
        if block::write_sector(0, &first) != Err(BlockError::ReadOnly)
            || block::write_sectors(0, &run) != Err(BlockError::ReadOnly)
            || block::flush() != Err(BlockError::ReadOnly)
            || device_commands() != commands
        {
            fail("read-only", 0);
        }
        serial::write("BLOCK PARTITION READ ONLY OK\n");
    }
    crate::exit_qemu(0)
}
