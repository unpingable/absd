//! Kernel-level NVMe qualification boots, run through the ordinary block
//! layer before init starts.
//!
//! `nvme-qualify-write nvme-write=SERIAL` writes a known pattern to a few
//! LBAs, reads each back, flushes, and checks refusals at the namespace
//! boundary. `nvme-qualify-verify` (no write option) boots fresh over the
//! same image, reads the pattern back after a new controller reset, and
//! checks that writes and flushes are refused. The host independently reads
//! the image file between and after the boots (`scripts/nvme-image-check.py`).

use absd_kernel::syscall::BLOCK_SECTOR_BYTES;

use crate::block::{self, Backend, BlockError};
use crate::nvme;
use crate::serial;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Write,
    Verify,
}

/// Written LBAs, as offsets from the start or (negative) the end.
const LBAS: [i64; 5] = [0, 1, 7, 2048, -1];
/// Never written: must read as the zero-filled image.
const UNTOUCHED: u64 = 2;

fn lbas(sectors: u64) -> [u64; 5] {
    LBAS.map(|offset| {
        if offset < 0 {
            sectors - offset.unsigned_abs()
        } else {
            offset as u64
        }
    })
}

/// The pattern for one LBA; `scripts/nvme-image-check.py` computes the same.
pub fn pattern(lba: u64) -> [u8; BLOCK_SECTOR_BYTES] {
    let mut sector = [0u8; BLOCK_SECTOR_BYTES];
    for (index, byte) in sector.iter_mut().enumerate() {
        let index = index as u64;
        *byte = (lba.wrapping_mul(37) + index * 11 + (index >> 8)) as u8;
    }
    let header = b"ABSD NVME QUALIFY lba=";
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

fn fail(what: &str, lba: u64) -> ! {
    serial::write("NVME QUALIFY FAILED ");
    serial::write(what);
    serial::write(" lba=");
    serial::decimal(lba);
    serial::write("\n");
    crate::exit_qemu(1)
}

pub fn run(phase: Phase) -> ! {
    let (Some(Backend::Nvme), Some(sectors)) = (block::backend(), block::sector_count()) else {
        fail("no nvme backend", 0);
    };
    if sectors <= 2048 {
        fail("namespace too small", sectors);
    }
    let targets = lbas(sectors);
    let mut sector = [0u8; BLOCK_SECTOR_BYTES];
    match phase {
        Phase::Write => {
            if !block::writable() {
                fail("namespace not selected writable", 0);
            }
            if block::read_sector(UNTOUCHED, &mut sector).is_err()
                || sector != [0; BLOCK_SECTOR_BYTES]
            {
                fail("fresh image not zero", UNTOUCHED);
            }
            for &lba in &targets {
                if block::write_sector(lba, &pattern(lba)).is_err() {
                    fail("write", lba);
                }
            }
            for &lba in &targets {
                if block::read_sector(lba, &mut sector).is_err() || sector != pattern(lba) {
                    fail("read back", lba);
                }
            }
            serial::write("NVME BLOCK OK lbas=");
            serial::decimal(targets.len() as u64);
            serial::write(" sectors=");
            serial::decimal(sectors);
            serial::write("\n");

            let (_, flushes_before) = nvme::completed();
            let counted_before = block::stats().flushes;
            if block::flush().is_err()
                || nvme::completed().1 != flushes_before + 1
                || block::stats().flushes != counted_before + 1
            {
                fail("flush", 0);
            }
            serial::write("NVME FLUSH OK flush_commands=");
            serial::decimal(nvme::completed().1);
            serial::write("\n");

            // The kernel refuses past the namespace without a command; the
            // device refuses the same LBA on its own, and the queue keeps
            // working afterwards.
            let (commands, _) = nvme::completed();
            if block::read_sector(sectors, &mut sector) != Err(BlockError::OutOfRange)
                || block::write_sector(sectors, &pattern(0)) != Err(BlockError::OutOfRange)
                || nvme::completed().0 != commands
            {
                fail("kernel bound", sectors);
            }
            let device_status = match nvme::read_unchecked(sectors) {
                Err(nvme::NvmeError::Command { status, .. }) => status,
                _ => fail("device bound", sectors),
            };
            if block::read_sector(0, &mut sector).is_err() || sector != pattern(0) {
                fail("read after device refusal", 0);
            }
            serial::write("NVME BOUNDS OK kernel=OutOfRange device_status=0x");
            serial::hex_digits(u64::from(device_status), 4);
            serial::write("\n");
        }
        Phase::Verify => {
            if block::writable() {
                fail("namespace writable without nvme-write", 0);
            }
            for &lba in &targets {
                if block::read_sector(lba, &mut sector).is_err() || sector != pattern(lba) {
                    fail("pattern after fresh boot", lba);
                }
            }
            serial::write("NVME REINIT OK lbas=");
            serial::decimal(targets.len() as u64);
            serial::write("\n");
            let (commands, _) = nvme::completed();
            if block::write_sector(1, &[0; BLOCK_SECTOR_BYTES]) != Err(BlockError::ReadOnly)
                || block::flush() != Err(BlockError::ReadOnly)
                || nvme::completed().0 != commands
            {
                fail("read-only refusal", 1);
            }
            serial::write("NVME READ ONLY OK\n");
        }
    }
    crate::exit_qemu(0)
}
