//! Kernel-level AHCI qualification boots, run through the ordinary block
//! layer before init starts (QEMU only: `ich9-ahci` with `ide-hd` disks).
//!
//! `ahci-qualify-write ahci-write=SERIAL` writes a known pattern to single
//! sectors and one eight-sector run, reads each back, flushes, and checks
//! the kernel's and the device's refusals at the end of the disk.
//! `ahci-qualify-verify ahci-disk=SERIAL` boots fresh over the same image,
//! reads the pattern back and checks that writes and flushes are refused
//! without a command. The fault boots: `ahci-qualify-device-error` (QEMU
//! blkdebug fails one read) recovers and keeps serving;
//! `ahci-qualify-timeout` and `ahci-qualify-stuck-stop` drive the retirement
//! paths through the backend's fixtures. The host independently reads the
//! image files between and after the boots (`scripts/ahci-image-check.py`).

use absd_kernel::ahci_command::Completion;
use absd_kernel::syscall::BLOCK_SECTOR_BYTES;

use crate::ahci_block::{self, AhciError};
use crate::block::{self, Backend, BlockError};
use crate::{pci, serial};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Write,
    Verify,
    DeviceError,
    Timeout,
    StuckStop,
}

/// The mode words that select each phase.
pub const PHASES: [(&[u8], Phase); 5] = [
    (b"ahci-qualify-write", Phase::Write),
    (b"ahci-qualify-verify", Phase::Verify),
    (b"ahci-qualify-device-error", Phase::DeviceError),
    (b"ahci-qualify-timeout", Phase::Timeout),
    (b"ahci-qualify-stuck-stop", Phase::StuckStop),
];

/// Single written sectors, as offsets from the start or (negative) the end.
const LBAS: [i64; 5] = [0, 1, 7, 2048, -1];
/// One eight-sector WRITE DMA EXT and READ DMA EXT (a whole bounce page).
const RUN: u64 = 1024;
const RUN_SECTORS: usize = 8;
/// Never written: must read as the zero-filled image.
const UNTOUCHED: u64 = 2;
/// The sector the device-error boot's blkdebug rule fails once, and the
/// one it then writes.
const INJECTED: u64 = 100;
const AFTER_ERROR: u64 = 5;

fn lbas(sectors: u64) -> [u64; 5] {
    LBAS.map(|offset| {
        if offset < 0 {
            sectors - offset.unsigned_abs()
        } else {
            offset as u64
        }
    })
}

/// The pattern for one LBA; `scripts/ahci-image-check.py` computes the same.
pub fn pattern(lba: u64) -> [u8; BLOCK_SECTOR_BYTES] {
    let mut sector = [0u8; BLOCK_SECTOR_BYTES];
    for (index, byte) in sector.iter_mut().enumerate() {
        let index = index as u64;
        *byte = (lba.wrapping_mul(37) + index * 11 + (index >> 8)) as u8;
    }
    let header = b"ABSD AHCI QUALIFY lba=";
    sector[..header.len()].copy_from_slice(header);
    let mut digits = [b'0'; 20];
    let mut rest = lba;
    for digit in digits.iter_mut().rev() {
        *digit = b'0' + (rest % 10) as u8;
        rest /= 10;
    }
    sector[header.len()..header.len() + 20].copy_from_slice(&digits);
    sector
}

fn run_pattern() -> [u8; RUN_SECTORS * BLOCK_SECTOR_BYTES] {
    let mut run = [0u8; RUN_SECTORS * BLOCK_SECTOR_BYTES];
    for index in 0..RUN_SECTORS {
        run[index * BLOCK_SECTOR_BYTES..(index + 1) * BLOCK_SECTOR_BYTES]
            .copy_from_slice(&pattern(RUN + index as u64));
    }
    run
}

fn fail(what: &str, lba: u64) -> ! {
    serial::write("AHCI QUALIFY FAILED ");
    serial::write(what);
    serial::write(" lba=");
    serial::decimal(lba);
    serial::write("\n");
    crate::exit_qemu(1)
}

fn dma_word() -> &'static str {
    match ahci_block::function() {
        Some(function) if pci::bus_master(function) => "dma=on",
        _ => "dma=off",
    }
}

pub fn run(phase: Phase) -> ! {
    // Its LBAs, and the backend-level reads it makes, are device LBAs:
    // never run over a GPT partition (docs/hardware/GPT-PARTITION.md).
    if block::partitioned() {
        fail("block-partition selected", 0);
    }
    let (Some(Backend::Ahci), Some(sectors)) = (block::backend(), block::sector_count()) else {
        fail("no ahci backend", 0);
    };
    if sectors <= 2048 {
        fail("disk too small", sectors);
    }
    let mut sector = [0u8; BLOCK_SECTOR_BYTES];
    if phase != Phase::Verify && !block::writable() {
        fail("disk not selected writable", 0);
    }
    match phase {
        Phase::Write => write(sectors),
        Phase::Verify => verify(sectors),
        Phase::DeviceError => {
            let (_, _, recovered) = ahci_block::completed();
            let tfd = match ahci_block::read_unchecked(INJECTED) {
                Err(AhciError::Command(Completion::TaskFile { tfd })) => tfd,
                _ => fail("injected read error not reported", INJECTED),
            };
            if ahci_block::completed().2 != recovered + 1 || ahci_block::retired().0 {
                fail("port did not recover", INJECTED);
            }
            if block::read_sector(INJECTED + 1, &mut sector).is_err()
                || block::write_sector(AFTER_ERROR, &pattern(AFTER_ERROR)).is_err()
                || block::read_sector(AFTER_ERROR, &mut sector).is_err()
                || sector != pattern(AFTER_ERROR)
                || block::flush().is_err()
            {
                fail("service after the device error", AFTER_ERROR);
            }
            serial::write("AHCI DEVICE ERROR OK tfd=0x");
            serial::hex_digits(u64::from(tfd), 8);
            serial::write(" recovered=1 then=read,write,flush\n");
        }
        Phase::Timeout | Phase::StuckStop => {
            ahci_block::pretend_timeout();
            if phase == Phase::StuckStop {
                ahci_block::pretend_stuck_stop();
            }
            if block::read_sector(0, &mut sector) != Err(BlockError::Device) {
                fail("pretended timeout not reported", 0);
            }
            let (completed, _, _) = ahci_block::completed();
            let (retired, buffers_retired) = ahci_block::retired();
            if !retired || buffers_retired != (phase == Phase::StuckStop) {
                fail("port not retired as the rule says", 0);
            }
            if dma_word() != "dma=off" {
                fail("bus mastering still on after retirement", 0);
            }
            if block::read_sector(0, &mut sector) != Err(BlockError::Device)
                || block::write_sector(0, &pattern(0)) != Err(BlockError::Device)
                || block::flush() != Err(BlockError::Device)
                || ahci_block::completed().0 != completed
            {
                fail("retired port still served", 0);
            }
            let reprobe = ahci_block::probe(absd_kernel::ahci_command::Selection {
                serial: b"absd",
                writable: true,
            });
            if !matches!(reprobe, Err(AhciError::Retired)) {
                fail("retired backend probed again", 0);
            }
            serial::write(if phase == Phase::Timeout {
                "AHCI TIMEOUT OK retired=yes buffers=reusable "
            } else {
                "AHCI STUCK STOP OK retired=yes buffers=retired "
            });
            serial::write(dma_word());
            serial::write(" later=refused reprobe=refused\n");
        }
    }
    crate::exit_qemu(0)
}

fn write(sectors: u64) {
    let targets = lbas(sectors);
    let mut sector = [0u8; BLOCK_SECTOR_BYTES];
    if block::read_sector(UNTOUCHED, &mut sector).is_err() || sector != [0; BLOCK_SECTOR_BYTES] {
        fail("fresh image not zero", UNTOUCHED);
    }
    for &lba in &targets {
        if block::write_sector(lba, &pattern(lba)).is_err() {
            fail("write", lba);
        }
    }
    let run = run_pattern();
    if block::write_sectors(RUN, &run).is_err() {
        fail("eight-sector write", RUN);
    }
    for &lba in &targets {
        if block::read_sector(lba, &mut sector).is_err() || sector != pattern(lba) {
            fail("read back", lba);
        }
    }
    let mut back = [0u8; RUN_SECTORS * BLOCK_SECTOR_BYTES];
    if block::read_sectors(RUN, &mut back).is_err() || back != run {
        fail("eight-sector read back", RUN);
    }
    serial::write("AHCI BLOCK OK lbas=");
    serial::decimal((targets.len() + RUN_SECTORS) as u64);
    serial::write(" sectors=");
    serial::decimal(sectors);
    serial::write("\n");

    let (_, flushes, _) = ahci_block::completed();
    let counted = block::stats().flushes;
    if block::flush().is_err()
        || ahci_block::completed().1 != flushes + 1
        || block::stats().flushes != counted + 1
    {
        fail("flush", 0);
    }
    serial::write("AHCI FLUSH OK flush_commands=");
    serial::decimal(ahci_block::completed().1);
    serial::write("\n");

    // The kernel refuses past the disk without a command; the device
    // refuses the same LBA on its own, and the port keeps serving.
    let (commands, _, recovered) = ahci_block::completed();
    if block::read_sector(sectors, &mut sector) != Err(BlockError::OutOfRange)
        || block::write_sector(sectors, &pattern(0)) != Err(BlockError::OutOfRange)
        || block::write_sectors(sectors - 4, &run) != Err(BlockError::OutOfRange)
        || ahci_block::completed().0 != commands
    {
        fail("kernel bound", sectors);
    }
    let tfd = match ahci_block::read_unchecked(sectors) {
        Err(AhciError::Command(Completion::TaskFile { tfd })) => tfd,
        _ => fail("device bound", sectors),
    };
    if ahci_block::completed().2 != recovered + 1
        || block::read_sector(0, &mut sector).is_err()
        || sector != pattern(0)
    {
        fail("read after device refusal", 0);
    }
    serial::write("AHCI BOUNDS OK kernel=OutOfRange device_tfd=0x");
    serial::hex_digits(u64::from(tfd), 8);
    serial::write(" recovered=1\n");
}

fn verify(sectors: u64) {
    let targets = lbas(sectors);
    let mut sector = [0u8; BLOCK_SECTOR_BYTES];
    if block::writable() {
        fail("disk writable without ahci-write", 0);
    }
    for &lba in &targets {
        if block::read_sector(lba, &mut sector).is_err() || sector != pattern(lba) {
            fail("pattern after fresh boot", lba);
        }
    }
    let mut back = [0u8; RUN_SECTORS * BLOCK_SECTOR_BYTES];
    if block::read_sectors(RUN, &mut back).is_err() || back != run_pattern() {
        fail("eight-sector pattern after fresh boot", RUN);
    }
    serial::write("AHCI REINIT OK lbas=");
    serial::decimal((targets.len() + RUN_SECTORS) as u64);
    serial::write("\n");
    let (commands, _, _) = ahci_block::completed();
    if block::write_sector(1, &[0; BLOCK_SECTOR_BYTES]) != Err(BlockError::ReadOnly)
        || block::write_sectors(RUN, &[0; RUN_SECTORS * BLOCK_SECTOR_BYTES])
            != Err(BlockError::ReadOnly)
        || block::flush() != Err(BlockError::ReadOnly)
        || ahci_block::completed().0 != commands
    {
        fail("read-only refusal", 1);
    }
    serial::write("AHCI READ ONLY OK\n");
}
