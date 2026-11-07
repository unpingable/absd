use crate::native_installer::{self as installer, Device, Disk, IoError, Outcome};
use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

#[derive(Default)]
struct MemoryDisk {
    data: BTreeMap<u64, [u8; 512]>,
    writes: usize,
    write_order: Vec<u64>,
    flushes: usize,
    fail_write: bool,
    fail_flush: bool,
    corrupt_readback: bool,
}
impl Disk for MemoryDisk {
    fn read(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), IoError> {
        for (i, sector) in bytes.as_chunks_mut::<512>().0.iter_mut().enumerate() {
            sector.copy_from_slice(self.data.get(&(lba + i as u64)).unwrap_or(&[0; 512]));
        }
        if self.corrupt_readback && self.writes > 0 {
            bytes[0] ^= 1;
        }
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &[u8]) -> Result<(), IoError> {
        self.writes += 1;
        self.write_order.push(lba);
        if self.fail_write {
            return Err(IoError);
        }
        for (i, sector) in bytes.as_chunks::<512>().0.iter().enumerate() {
            self.data.insert(lba + i as u64, *sector);
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), IoError> {
        self.flushes += 1;
        if self.fail_flush {
            Err(IoError)
        } else {
            Ok(())
        }
    }
}
fn device() -> Device<'static> {
    Device {
        serial: b"test",
        model: b"QEMU HARDDISK",
        sectors: installer::MIN_SECTORS,
        unique: true,
        writable: true,
    }
}
fn payload() -> Vec<u8> {
    let mut p = vec![0; 128];
    p[..8].copy_from_slice(b"ABSDINS1");
    p[8..16].copy_from_slice(&installer::MIN_SECTORS.to_le_bytes());
    p[16..20].copy_from_slice(&2u32.to_le_bytes());
    p[20..24].copy_from_slice(b"test");
    p[40..53].copy_from_slice(b"QEMU HARDDISK");
    // Sorted head and tail records. The primary GPT is committed last.
    for lba in [0, installer::MIN_SECTORS - 1] {
        p.extend_from_slice(&lba.to_le_bytes());
        p.extend_from_slice(&512u32.to_le_bytes());
        p.extend_from_slice(&[0; 4]);
        p.extend_from_slice(&[0x5a; 512]);
    }
    p
}
fn run(d: &mut MemoryDisk, p: &[u8], dev: Device<'_>) -> Outcome {
    installer::install(d, p, dev, Some(crate::gpt::crc32(p)))
}
#[test]
fn no_consent_is_no_io_or_write() {
    let mut d = MemoryDisk::default();
    assert_eq!(
        installer::install(&mut d, &payload(), device(), None),
        Outcome::Refused("consent")
    );
    assert_eq!((d.writes, d.flushes), (0, 0));
}
#[test]
fn installs_flushes_and_rejects_repeat() {
    let mut d = MemoryDisk::default();
    assert_eq!(run(&mut d, &payload(), device()), Outcome::Installed);
    assert_eq!((d.writes, d.flushes), (2, 2));
    let before = d.data.clone();
    assert_eq!(
        run(&mut d, &payload(), device()),
        Outcome::Refused("not-blank")
    );
    assert_eq!(d.data, before);
}
#[test]
fn rejects_wrong_identity_geometry_ambiguity_and_readonly_before_write() {
    let p = payload();
    for dev in [
        Device {
            serial: b"other",
            ..device()
        },
        Device {
            model: b"other",
            ..device()
        },
        Device {
            sectors: device().sectors + 1,
            ..device()
        },
        Device {
            unique: false,
            ..device()
        },
        Device {
            writable: false,
            ..device()
        },
    ] {
        let mut d = MemoryDisk::default();
        assert!(matches!(run(&mut d, &p, dev), Outcome::Refused(_)));
        assert_eq!(d.writes, 0);
    }
}
#[test]
fn detects_corrupt_payload_and_wrong_consent() {
    let mut d = MemoryDisk::default();
    let p = payload();
    let mut bad = p.clone();
    bad[150] ^= 1;
    assert_eq!(
        installer::install(&mut d, &bad, device(), Some(crate::gpt::crc32(&p))),
        Outcome::Refused("payload-crc")
    );
    assert_eq!(d.writes, 0);
}
#[test]
fn refuses_nonempty_bytes_outside_first_mib_and_in_unallocated_space() {
    for lba in [
        2048,
        installer::ABSD_FIRST + 77,
        installer::MIN_SECTORS - 34,
    ] {
        let mut d = MemoryDisk::default();
        d.data.insert(lba, [1; 512]);
        assert_eq!(
            run(&mut d, &payload(), device()),
            Outcome::Refused("not-blank")
        );
        assert_eq!(d.writes, 0);
    }
}
#[test]
fn write_flush_and_readback_failures_are_incomplete() {
    for mut d in [
        MemoryDisk {
            fail_write: true,
            ..Default::default()
        },
        MemoryDisk {
            fail_flush: true,
            ..Default::default()
        },
        MemoryDisk {
            corrupt_readback: true,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            run(&mut d, &payload(), device()),
            Outcome::Incomplete(_)
        ));
    }
}
#[test]
fn refuses_truncation_trailing_bytes_overlap_out_of_bounds_and_state_writes() {
    let p = payload();
    let mut variants = vec![p[..p.len() - 1].to_vec(), [p.as_slice(), &[0]].concat()];
    for lba in [0, installer::ABSD_FIRST, installer::MIN_SECTORS] {
        let mut bad = p.clone();
        bad[656..664].copy_from_slice(&lba.to_le_bytes());
        variants.push(bad);
    }
    let mut bad = p.clone();
    bad[136..140].copy_from_slice(&u32::MAX.to_le_bytes());
    variants.push(bad);
    for bad in variants {
        let mut d = MemoryDisk::default();
        assert!(matches!(run(&mut d, &bad, device()), Outcome::Refused(_)));
        assert_eq!(d.writes, 0);
    }
}

#[test]
fn shared_v1_golden_vector_matches_native_fixture() {
    let hex = include_str!("../tests/native-installer-v1.hex")
        .split_whitespace()
        .collect::<std::string::String>();
    let bytes = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<u8>>();
    assert_eq!(bytes, payload());
}

#[test]
fn protective_mbr_is_last_even_in_a_multisector_primary_record() {
    let mut p = payload();
    // Extend the first record to include the primary GPT header and entries.
    p[136..140].copy_from_slice(&4096u32.to_le_bytes());
    p.splice(656..656, [0x5a; 3584]);
    let mut disk = MemoryDisk::default();
    assert_eq!(run(&mut disk, &p, device()), Outcome::Installed);
    assert_eq!(disk.write_order, [installer::MIN_SECTORS - 1, 1, 0]);
    assert_eq!(disk.flushes, 2);
}

#[test]
fn census_counts_every_nonzero_det_without_a_signature_requirement() {
    for det in 0..16 {
        for upper in [0, 0x130, 0xffff_fff0] {
            assert_eq!(
                crate::ahci_command::installer_port_present(upper | det),
                det != 0
            );
        }
    }
}
