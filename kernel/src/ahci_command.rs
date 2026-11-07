//! The AHCI block backend's pure rules (coordination record #45, #123 step 3): which
//! disk a boot selects, the command FIS and header for each ATA command the
//! backend issues, how a finished command is judged, and what follows a
//! failed one. Host-tested here; src/ahci_block.rs does the register and
//! DMA work and asks these functions every decision.
//!
//! The backend issues four commands and nothing else: IDENTIFY DEVICE (0xEC)
//! to find the declared disk, READ DMA EXT (0x25), WRITE DMA EXT (0x35) and
//! FLUSH CACHE EXT (0xEA). One command slot, one PRDT entry, no NCQ.

pub const ATA_IDENTIFY_DEVICE: u8 = 0xec;
pub const ATA_READ_DMA_EXT: u8 = 0x25;
pub const ATA_WRITE_DMA_EXT: u8 = 0x35;
pub const ATA_FLUSH_CACHE_EXT: u8 = 0xea;

/// Installer census: an implemented port may have a device even before its
/// link is ready or its signature is available. Only DET=0 proves absence.
pub fn installer_port_present(ssts: u32) -> bool {
    ssts & 0xf != 0
}

pub const SECTOR_BYTES: u32 = 512;
/// The bounce buffer is one page: at most eight sectors per command.
pub const MAX_SECTORS: u32 = 8;
const LBA48_LIMIT: u64 = 1 << 48;

/// PxIS.TFES, and the PxTFD status bits the backend reads.
pub const IS_TFES: u32 = 1 << 30;
pub const TFD_ERR: u32 = 1;
pub const TFD_DRQ: u32 = 1 << 3;
/// Device Fault: independent of ERR, and never a success.
pub const TFD_DF: u32 = 1 << 5;
pub const TFD_BSY: u32 = 1 << 7;

/// Which disk this boot uses: the `ahci-disk=SERIAL` (read-only) or
/// `ahci-write=SERIAL` (read-write) boot option. Without either the AHCI
/// backend is never probed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection<'a> {
    pub serial: &'a [u8],
    pub writable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionError {
    /// The option was present with an empty or all-blank value.
    EmptySerial,
    /// `ahci-disk=` and `ahci-write=` named different disks.
    Conflict,
}

/// The selection from the two options. `writes_built` is false in the
/// `block-read-only` build, where `ahci-write=` names the disk read-only.
pub fn select<'a>(
    disk: Option<&'a [u8]>,
    write: Option<&'a [u8]>,
    writes_built: bool,
) -> Result<Option<Selection<'a>>, SelectionError> {
    let disk = disk.map(trim);
    let write = write.map(trim);
    if disk.is_some_and(<[u8]>::is_empty) || write.is_some_and(<[u8]>::is_empty) {
        return Err(SelectionError::EmptySerial);
    }
    match (disk, write) {
        (None, None) => Ok(None),
        (Some(a), Some(b)) if a != b => Err(SelectionError::Conflict),
        (_, Some(serial)) => Ok(Some(Selection {
            serial,
            writable: writes_built,
        })),
        (Some(serial), None) => Ok(Some(Selection {
            serial,
            writable: false,
        })),
    }
}

/// ATA serial numbers are space padded on either side (QEMU pads on the
/// right, many drives on the left); NUL padding is treated the same.
pub fn trim(field: &[u8]) -> &[u8] {
    let start = field
        .iter()
        .position(|&byte| byte != b' ' && byte != 0)
        .unwrap_or(field.len());
    let end = field
        .iter()
        .rposition(|&byte| byte != b' ' && byte != 0)
        .map_or(start, |last| last + 1);
    &field[start..end]
}

/// Whether an IDENTIFY serial is the selected one. A blank serial never
/// matches anything.
pub fn serial_matches(identified: &[u8], selected: &[u8]) -> bool {
    let identified = trim(identified);
    !identified.is_empty() && identified == trim(selected)
}

/// Why an identified ATA device cannot be the block device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceRefusal {
    /// IDENTIFY word 0 bit 2: power-up in standby, the words are partial.
    Incomplete,
    /// No 48-bit address feature set: READ/WRITE DMA EXT are not available.
    NoLba48,
    /// Logical sectors other than 512 bytes (or an impossible size).
    SectorSize(Option<u32>),
    NoSectors,
}

/// Checks the facts the backend needs from IDENTIFY: complete words, LBA48,
/// 512-byte logical sectors and a nonzero capacity. Returns the capacity.
pub fn admit_device(words: &[u16; 256]) -> Result<u64, DeviceRefusal> {
    use crate::survey_facts as facts;
    if facts::ata_identify_incomplete(words) {
        return Err(DeviceRefusal::Incomplete);
    }
    if !facts::ata_identify_lba48(words) {
        return Err(DeviceRefusal::NoLba48);
    }
    match facts::ata_identify_logical_sector_bytes(words) {
        Some(512) => {}
        other => return Err(DeviceRefusal::SectorSize(other)),
    }
    match facts::ata_identify_sectors(words) {
        0 => Err(DeviceRefusal::NoSectors),
        sectors => Ok(sectors),
    }
}

/// One command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Op {
    Identify,
    Read { lba: u64, sectors: u32 },
    Write { lba: u64, sectors: u32 },
    Flush,
}

impl Op {
    pub fn command(self) -> u8 {
        match self {
            Op::Identify => ATA_IDENTIFY_DEVICE,
            Op::Read { .. } => ATA_READ_DMA_EXT,
            Op::Write { .. } => ATA_WRITE_DMA_EXT,
            Op::Flush => ATA_FLUSH_CACHE_EXT,
        }
    }

    /// Bytes the one PRDT entry describes (0: no data phase).
    pub fn bytes(self) -> u32 {
        match self {
            Op::Identify => SECTOR_BYTES,
            Op::Read { sectors, .. } | Op::Write { sectors, .. } => sectors * SECTOR_BYTES,
            Op::Flush => 0,
        }
    }

    /// Whether the read-only build may issue it.
    pub fn reads_only(self) -> bool {
        matches!(self, Op::Identify | Op::Read { .. })
    }

    /// A transfer of 1..=8 sectors inside the 48-bit address space.
    pub fn valid(self) -> bool {
        match self {
            Op::Read { lba, sectors } | Op::Write { lba, sectors } => {
                (1..=MAX_SECTORS).contains(&sectors)
                    && lba
                        .checked_add(u64::from(sectors))
                        .is_some_and(|end| end <= LBA48_LIMIT)
            }
            Op::Identify | Op::Flush => true,
        }
    }
}

/// Command header dword 0: CFL = 5 dwords (a register H2D FIS), W for a
/// write, PRDTL = 1 when there is a data phase. Port multiplier 0.
pub fn header_dw0(op: Op) -> u32 {
    let write = if matches!(op, Op::Write { .. }) {
        1 << 6
    } else {
        0
    };
    let prdtl = if op.bytes() == 0 { 0 } else { 1 << 16 };
    5 | write | prdtl
}

/// PRDT entry dword 3: DBC, the zero-based byte count (I clear: no
/// interrupt on completion of the entry). None without a data phase.
pub fn prdt_dbc(op: Op) -> Option<u32> {
    op.bytes().checked_sub(1)
}

/// Page size of the backend's buffers.
pub const PAGE_BYTES: u64 = 4096;

/// Whether a raw READ DMA EXT (the AMD-Vi self-check and oracle, #123) may
/// be issued: 1..=8 sectors, a dword-aligned data base address (one PRDT
/// entry, AHCI 1.3 §4.2.3.3 DBA), and a transfer that stays inside the page
/// the address starts in. Nothing about whether the address is granted:
/// that is the domain's decision alone.
pub fn raw_read_shape(sectors: u32, dba: u64) -> bool {
    (1..=MAX_SECTORS).contains(&sectors)
        && dba & 3 == 0
        && (dba & (PAGE_BYTES - 1)) + u64::from(sectors) * u64::from(SECTOR_BYTES) <= PAGE_BYTES
}

/// The 20-byte register host-to-device FIS: type 0x27, C set, the command,
/// LBA mode with the 48-bit address and count for the EXT commands.
pub fn register_fis(op: Op) -> [u8; 20] {
    let mut fis = [0u8; 20];
    fis[0] = 0x27;
    fis[1] = 1 << 7;
    fis[2] = op.command();
    if let Op::Read { lba, sectors } | Op::Write { lba, sectors } = op {
        let lba = lba.to_le_bytes();
        fis[4] = lba[0];
        fis[5] = lba[1];
        fis[6] = lba[2];
        fis[7] = 1 << 6;
        fis[8] = lba[3];
        fis[9] = lba[4];
        fis[10] = lba[5];
        fis[12] = sectors as u8;
        fis[13] = (sectors >> 8) as u8;
    }
    fis
}

/// How a command ended, from the port registers once the poll stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    Done,
    /// PxIS.TFES, PxTFD.ERR or PxTFD.DF: the device reported an error or
    /// a fault. `tfd` is PxTFD (status in bits 7:0, error in bits 15:8).
    TaskFile {
        tfd: u32,
    },
    /// The slot completed but moved a different byte count (PRDBC).
    ShortTransfer {
        moved: u32,
        wanted: u32,
    },
    /// PxCI still set at the bound.
    Timeout,
}

/// `issued_clear`: PxCI bit 0 read clear before the bound; `is`/`tfd`: PxIS
/// and PxTFD after the poll; `prdbc`: command header dword 1.
pub fn judge(op: Op, issued_clear: bool, is: u32, tfd: u32, prdbc: u32) -> Completion {
    if is & IS_TFES != 0 || (issued_clear && tfd & (TFD_ERR | TFD_DF) != 0) {
        return Completion::TaskFile { tfd };
    }
    if !issued_clear {
        return Completion::Timeout;
    }
    if prdbc != op.bytes() {
        return Completion::ShortTransfer {
            moved: prdbc,
            wanted: op.bytes(),
        };
    }
    Completion::Done
}

/// Whether the port's engine was shown stopped after a failed command:
/// PxCMD.CR read clear within the bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stop {
    Confirmed,
    Failed,
}

/// What follows a failed command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recovery {
    /// Engine stopped, errors cleared, device idle: start the engine again
    /// and keep serving. This command still fails.
    Restart,
    /// Out of service for the rest of the boot, bus mastering off at once.
    /// `buffers_reusable` false: the engine may still own the command list,
    /// FIS area and bounce page, which nothing may hand to a device again.
    Retire { buffers_reusable: bool },
}

/// The recovery rule (the census's `ahci_after_stop`, applied to a serving
/// port). A failed stop retires the port and its buffers. A timeout retires
/// the port even after a confirmed stop: what the device did with the
/// command is unknown, and so does a Device Fault. A device error on an
/// engine shown stopped restarts only if the device is idle (PxTFD BSY and
/// DRQ clear) and reports no fault; otherwise recovery would need a
/// COMRESET, which this backend does not issue.
pub fn recover(completion: Completion, stop: Stop, tfd_after_stop: u32) -> Recovery {
    if stop == Stop::Failed {
        return Recovery::Retire {
            buffers_reusable: false,
        };
    }
    match completion {
        Completion::Timeout => Recovery::Retire {
            buffers_reusable: true,
        },
        Completion::TaskFile { tfd } if tfd & TFD_DF != 0 => Recovery::Retire {
            buffers_reusable: true,
        },
        Completion::TaskFile { .. } | Completion::ShortTransfer { .. }
            if tfd_after_stop & (TFD_BSY | TFD_DRQ | TFD_DF) == 0 =>
        {
            Recovery::Restart
        }
        _ => Recovery::Retire {
            buffers_reusable: true,
        },
    }
}

/// What a port's firmware state allows before the controller's bus
/// mastering is armed, from PxCMD, PxCI and PxSACT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortState {
    /// Command engine and FIS receive off, nothing issued.
    Idle,
    /// An engine (command list or FIS receive) left running with nothing
    /// issued: idle, so safely relinquished. Stopped once the whole
    /// controller is shown eligible, with bus mastering off, and left
    /// stopped (its command list and FIS area are firmware memory).
    Running,
    /// A command issued (PxCI) or queued (PxSACT): not idle, so the whole
    /// controller is refused before anything controller-wide is written.
    Pending,
}

pub const CMD_ST: u32 = 1;
pub const CMD_FRE: u32 = 1 << 4;
pub const CMD_FR: u32 = 1 << 14;
pub const CMD_CR: u32 = 1 << 15;

pub fn port_state(cmd: u32, ci: u32, sact: u32) -> PortState {
    if ci != 0 || sact != 0 {
        PortState::Pending
    } else if cmd & (CMD_ST | CMD_CR | CMD_FRE | CMD_FR) != 0 {
        PortState::Running
    } else {
        PortState::Idle
    }
}

/// QEMU's emulated ICH9 AHCI controller: vendor:device 8086:2922 with
/// QEMU's subsystem (PCI 0x2c = 0x11001af4: 1af4:1100).
pub const EMULATED_CONTROLLER: (u16, u16, u32) = (0x8086, 0x2922, 0x1100_1af4);
/// The model QEMU's `ide-hd` reports.
pub const EMULATED_MODEL: &[u8] = b"QEMU HARDDISK";

/// Whether the controller is QEMU's emulated one: in this slice, the only
/// controller the backend takes over in either access mode, checked from
/// PCI configuration reads before anything is written, so neither a
/// physical controller nor one passed through to a VM gets bus mastering
/// before AMD-Vi containment (#123). Identity fields can be forged; this
/// stops operator error, not an adversary.
pub fn emulated_controller(vendor: u16, device: u16, subsystem: u32) -> bool {
    (vendor, device, subsystem) == EMULATED_CONTROLLER
}

/// Whether a disk is QEMU's `ide-hd`: required, as well, before a disk is
/// served writable.
pub fn emulated_disk(model: &[u8]) -> bool {
    trim(model) == EMULATED_MODEL
}

/// Whether `ahci-write=` may serve this disk writable. A physical disk only
/// from inside a live containment domain for its controller, and the owner names
/// it by serial (the explicitly selected test disk).
pub fn write_admitted(model: &[u8], contained: bool) -> bool {
    emulated_disk(model) || contained || cfg!(absd_mutant_ahci_write_uncontained)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_needs_a_serial_and_one_disk() {
        assert_eq!(select(None, None, true), Ok(None));
        assert_eq!(
            select(Some(b"absd"), None, true),
            Ok(Some(Selection {
                serial: b"absd",
                writable: false
            }))
        );
        assert_eq!(
            select(None, Some(b"absd"), true),
            Ok(Some(Selection {
                serial: b"absd",
                writable: true
            }))
        );
        assert_eq!(
            select(Some(b"absd"), Some(b" absd "), true),
            Ok(Some(Selection {
                serial: b"absd",
                writable: true
            }))
        );
        // The read-only build names the disk but never makes it writable.
        assert_eq!(
            select(None, Some(b"absd"), false),
            Ok(Some(Selection {
                serial: b"absd",
                writable: false
            }))
        );
        assert_eq!(
            select(Some(b"one"), Some(b"two"), true),
            Err(SelectionError::Conflict)
        );
        assert_eq!(
            select(Some(b""), None, true),
            Err(SelectionError::EmptySerial)
        );
        assert_eq!(
            select(None, Some(b"   "), true),
            Err(SelectionError::EmptySerial)
        );
    }

    #[test]
    fn raw_reads_stay_in_one_page_and_dword_aligned() {
        assert!(raw_read_shape(1, 0x10_0000));
        assert!(raw_read_shape(8, 0x10_0000));
        assert!(raw_read_shape(1, 0x10_0e00));
        assert!(raw_read_shape(4, 0x10_0604));
        assert!(!raw_read_shape(4, 0x10_0804));
        assert!(!raw_read_shape(0, 0x10_0000));
        assert!(!raw_read_shape(9, 0x10_0000));
        assert!(!raw_read_shape(2, 0x10_0e04));
        assert!(!raw_read_shape(8, 0x10_0004));
        assert!(!raw_read_shape(1, 0x10_0002));
        assert!(!raw_read_shape(1, 0x10_0001));
    }

    #[test]
    fn serials_match_exactly_after_padding() {
        assert!(serial_matches(b"absd                ", b"absd"));
        assert!(serial_matches(b"      S3Z9NB0K123456", b"S3Z9NB0K123456"));
        assert!(!serial_matches(b"absd2", b"absd"));
        assert!(!serial_matches(b"absd", b"absd2"));
        assert!(!serial_matches(b"not-absd", b"absd"));
        assert!(!serial_matches(b"ABSD", b"absd"));
        assert!(!serial_matches(b"                    ", b""));
        assert!(!serial_matches(b"", b""));
    }

    fn identify(lba48: bool, sectors: u64, w106: u16, words_per_sector: u32) -> [u16; 256] {
        let mut words = [0u16; 256];
        words[83] = if lba48 { 0x4000 | (1 << 10) } else { 0x4000 };
        for i in 0..4 {
            words[100 + i] = (sectors >> (16 * i)) as u16;
        }
        words[60] = sectors as u16;
        words[61] = (sectors >> 16) as u16;
        words[106] = w106;
        words[117] = words_per_sector as u16;
        words[118] = (words_per_sector >> 16) as u16;
        words
    }

    #[test]
    fn device_admission() {
        assert_eq!(admit_device(&identify(true, 4096, 0, 0)), Ok(4096));
        assert_eq!(
            admit_device(&identify(false, 4096, 0, 0)),
            Err(DeviceRefusal::NoLba48)
        );
        assert_eq!(
            admit_device(&identify(true, 0, 0, 0)),
            Err(DeviceRefusal::NoSectors)
        );
        // Word 106 valid with the long-logical-sector bit: 2048 words.
        assert_eq!(
            admit_device(&identify(true, 4096, 0x5000, 2048)),
            Err(DeviceRefusal::SectorSize(Some(4096)))
        );
        assert_eq!(
            admit_device(&identify(true, 4096, 0x5000, 16)),
            Err(DeviceRefusal::SectorSize(None))
        );
        let mut standby = identify(true, 4096, 0, 0);
        standby[0] = 1 << 2;
        assert_eq!(admit_device(&standby), Err(DeviceRefusal::Incomplete));
    }

    #[test]
    fn command_encoding() {
        let read = Op::Read {
            lba: 0x0000_1234_5678_9abc,
            sectors: 8,
        };
        let fis = register_fis(read);
        assert_eq!(
            fis[..14],
            [
                0x27, 0x80, 0x25, 0, 0xbc, 0x9a, 0x78, 0x40, 0x56, 0x34, 0x12, 0, 8, 0
            ]
        );
        assert!(fis[14..].iter().all(|&b| b == 0));
        assert_eq!(header_dw0(read), 5 | (1 << 16));
        assert_eq!(prdt_dbc(read), Some(4095));

        let write = Op::Write { lba: 7, sectors: 1 };
        assert_eq!(register_fis(write)[2], 0x35);
        assert_eq!(register_fis(write)[7], 0x40);
        assert_eq!(header_dw0(write), 5 | (1 << 6) | (1 << 16));
        assert_eq!(prdt_dbc(write), Some(511));

        assert_eq!(register_fis(Op::Flush)[..4], [0x27, 0x80, 0xea, 0]);
        assert_eq!(register_fis(Op::Flush)[7], 0);
        assert_eq!(header_dw0(Op::Flush), 5);
        assert_eq!(prdt_dbc(Op::Flush), None);

        assert_eq!(register_fis(Op::Identify)[2], 0xec);
        assert_eq!(header_dw0(Op::Identify), 5 | (1 << 16));
    }

    #[test]
    fn transfer_bounds() {
        assert!(Op::Read { lba: 0, sectors: 1 }.valid());
        assert!(Op::Write { lba: 0, sectors: 8 }.valid());
        assert!(!Op::Write { lba: 0, sectors: 9 }.valid());
        assert!(!Op::Read { lba: 0, sectors: 0 }.valid());
        assert!(
            Op::Read {
                lba: LBA48_LIMIT - 8,
                sectors: 8
            }
            .valid()
        );
        assert!(
            !Op::Read {
                lba: LBA48_LIMIT - 7,
                sectors: 8
            }
            .valid()
        );
        assert!(
            !Op::Read {
                lba: u64::MAX,
                sectors: 1
            }
            .valid()
        );
        assert!(Op::Read { lba: 0, sectors: 1 }.reads_only());
        assert!(Op::Identify.reads_only());
        assert!(!Op::Write { lba: 0, sectors: 1 }.reads_only());
        assert!(!Op::Flush.reads_only());
    }

    #[test]
    fn completion_judgement() {
        let read = Op::Read { lba: 0, sectors: 2 };
        assert_eq!(judge(read, true, 0, 0x50, 1024), Completion::Done);
        assert_eq!(
            judge(read, true, 0, 0x50, 512),
            Completion::ShortTransfer {
                moved: 512,
                wanted: 1024
            }
        );
        assert_eq!(judge(read, false, 0, 0x80, 0), Completion::Timeout);
        // TFES wins over a still-set PxCI: the HBA stopped on the error.
        assert_eq!(
            judge(read, false, IS_TFES, 0x0451, 0),
            Completion::TaskFile { tfd: 0x0451 }
        );
        assert_eq!(
            judge(read, true, 0, 0x0451, 1024),
            Completion::TaskFile { tfd: 0x0451 }
        );
        assert_eq!(judge(Op::Flush, true, 0, 0x50, 0), Completion::Done);
        // Device Fault without ERR or TFES is still a failure, above all
        // for a flush, which has no byte count to catch it.
        assert_eq!(
            judge(Op::Flush, true, 0, 0x70, 0),
            Completion::TaskFile { tfd: 0x70 }
        );
        assert_eq!(
            judge(read, true, 0, 0x70, 1024),
            Completion::TaskFile { tfd: 0x70 }
        );
    }

    #[test]
    fn only_the_emulated_target_is_taken() {
        assert!(emulated_controller(0x8086, 0x2922, 0x1100_1af4));
        // hardware_fixture's FCH SATA, a passed-through Intel part.
        assert!(!emulated_controller(0x1022, 0x7901, 0x1100_1af4));
        assert!(!emulated_controller(0x1022, 0x7901, 0x7901_1022));
        assert!(!emulated_controller(0x8086, 0x2922, 0x2922_8086));
        assert!(emulated_disk(b"QEMU HARDDISK"));
        assert!(emulated_disk(b"QEMU HARDDISK   "));
        assert!(!emulated_disk(b"Samsung SSD 870 EVO"));
        assert!(!emulated_disk(b"QEMU HARDDISK2"));
    }

    #[test]
    fn a_real_disk_is_writable_only_inside_a_live_containment_domain() {
        assert!(write_admitted(b"QEMU HARDDISK", false));
        assert!(write_admitted(b"QEMU HARDDISK", true));
        assert!(write_admitted(b"Samsung SSD 870 EVO", true));
        assert!(!write_admitted(b"Samsung SSD 870 EVO", false));
    }

    #[test]
    fn port_admission() {
        assert_eq!(port_state(0, 0, 0), PortState::Idle);
        assert_eq!(port_state(CMD_FRE | CMD_FR, 0, 0), PortState::Running);
        assert_eq!(port_state(CMD_FR, 0, 0), PortState::Running);
        // SeaBIOS leaves an idle port like this (cmd=0000c017).
        assert_eq!(port_state(0xc017, 0, 0), PortState::Running);
        assert_eq!(port_state(CMD_CR, 0, 0), PortState::Running);
        assert_eq!(port_state(CMD_ST | CMD_FRE, 1, 0), PortState::Pending);
        assert_eq!(port_state(0, 1 << 5, 0), PortState::Pending);
        assert_eq!(port_state(CMD_ST, 0, 1), PortState::Pending);
    }

    #[test]
    fn recovery_never_reuses_after_a_failed_stop() {
        let error = Completion::TaskFile { tfd: 0x0451 };
        assert_eq!(recover(error, Stop::Confirmed, 0x51), Recovery::Restart);
        assert_eq!(
            recover(error, Stop::Confirmed, 0x51 | TFD_BSY),
            Recovery::Retire {
                buffers_reusable: true
            }
        );
        assert_eq!(
            recover(error, Stop::Confirmed, 0x58),
            Recovery::Retire {
                buffers_reusable: true
            }
        );
        assert_eq!(
            recover(Completion::Timeout, Stop::Confirmed, 0x50),
            Recovery::Retire {
                buffers_reusable: true
            }
        );
        let fault = Completion::TaskFile { tfd: 0x71 };
        assert_eq!(
            recover(fault, Stop::Confirmed, 0x50),
            Recovery::Retire {
                buffers_reusable: true
            }
        );
        assert_eq!(
            recover(error, Stop::Confirmed, 0x51 | TFD_DF),
            Recovery::Retire {
                buffers_reusable: true
            }
        );
        let short = Completion::ShortTransfer {
            moved: 0,
            wanted: 512,
        };
        assert_eq!(recover(short, Stop::Confirmed, 0x50), Recovery::Restart);
        for completion in [error, short, Completion::Timeout, Completion::Done] {
            assert_eq!(
                recover(completion, Stop::Failed, 0x50),
                Recovery::Retire {
                    buffers_reusable: false
                }
            );
        }
    }
}
