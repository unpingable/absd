extern crate std;
use super::*;
use std::vec;
use std::vec::Vec;

const ESP_TYPE: &[u8] = b"C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
const DISK_GUID: &[u8] = b"3e7d9a1b-2c4f-4b6e-8a0d-1f3c5e7a9b2d";
const ESP_UNIQUE: &[u8] = b"0f6a2e4c-8b1d-4f3a-a5c7-9e2b4d6f8a1c";
const ABSD_UNIQUE: &[u8] = b"5a8b3c2d-1e4f-4a6b-8c9d-0e1f2a3b4c5d";

fn guid(text: &[u8]) -> Guid {
    Guid::parse(text).unwrap()
}

#[test]
fn crc32_known_vectors() {
    assert_eq!(crc32(b""), 0);
    assert_eq!(crc32(b"a"), 0xE8B7_BE43);
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(
        crc32(b"The quick brown fox jumps over the lazy dog"),
        0x414F_A339
    );
    let mut split = Crc32::new();
    split.update(b"1234");
    split.update(b"56789");
    assert_eq!(split.finish(), 0xCBF4_3926);
}

#[test]
fn guid_byte_order_and_text() {
    let esp = guid(ESP_TYPE);
    assert_eq!(
        esp.0,
        [
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
            0xC9, 0x3B
        ]
    );
    assert_eq!(&esp.text(), b"c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    assert_eq!(
        guid(b"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
        esp,
        "case-insensitive"
    );
    for bad in [
        &b""[..],
        b"{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}",
        b"c12a7328f81f11d2ba4b00a0c93ec93b",
        b"c12a7328-f81f-11d2-ba4b-00a0c93ec93",
        b"c12a7328-f81f-11d2-ba4b-00a0c93ec93bb",
        b"c12a7328-f81f-11d2-ba4b_00a0c93ec93b",
        b"g12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        b"c12a7328-f81f-11d2-ba4b-00a0c93ec9-b",
    ] {
        assert_eq!(Guid::parse(bad), None, "{:?}", core::str::from_utf8(bad));
    }
}

type Located = Result<Partition, Refusal<()>>;
type Corruption = (&'static str, fn(&mut Disk));

/// A test disk: protective MBR, primary header and entry array, backup
/// entry array and header, laid out as sgdisk lays out a whole disk.
struct Disk {
    bytes: Vec<u8>,
    entries: Vec<(Guid, Guid, u64, u64)>,
    entry_count: u32,
    entry_bytes: u32,
    first_usable: u64,
    last_usable: u64,
}

impl Disk {
    fn new(sectors: u64) -> Self {
        Self {
            bytes: vec![0; sectors as usize * SECTOR_BYTES],
            entries: Vec::new(),
            entry_count: 128,
            entry_bytes: 128,
            first_usable: 34,
            last_usable: sectors - 34,
        }
    }

    fn sectors(&self) -> u64 {
        (self.bytes.len() / SECTOR_BYTES) as u64
    }

    /// The default layout: an ESP and the ABSD partition.
    fn standard() -> Self {
        let mut disk = Self::new(8192);
        disk.entries
            .push((guid(ESP_TYPE), guid(ESP_UNIQUE), 2048, 4095));
        disk.entries
            .push((ABSD_TYPE, guid(ABSD_UNIQUE), 4096, 8192 - 34));
        disk
    }

    fn array(&self) -> Vec<u8> {
        let size = self.entry_bytes as usize;
        let mut array = vec![0u8; self.entry_count as usize * size];
        for (index, (kind, unique, first, last)) in self.entries.iter().enumerate() {
            let entry = &mut array[index * size..(index + 1) * size];
            entry[0..16].copy_from_slice(&kind.0);
            entry[16..32].copy_from_slice(&unique.0);
            entry[32..40].copy_from_slice(&first.to_le_bytes());
            entry[40..48].copy_from_slice(&last.to_le_bytes());
        }
        array
    }

    fn array_sectors(&self) -> u64 {
        (u64::from(self.entry_count) * u64::from(self.entry_bytes)).div_ceil(SECTOR_BYTES as u64)
    }

    fn backup_lba(&self) -> u64 {
        self.sectors() - 1
    }

    fn header_at(&mut self, lba: u64, mine: u64, alternate: u64, entries: u64, crc: u32) {
        let (first_usable, last_usable) = (self.first_usable, self.last_usable);
        let (count, size) = (self.entry_count, self.entry_bytes);
        let start = lba as usize * SECTOR_BYTES;
        let header = &mut self.bytes[start..start + 92];
        header[0..8].copy_from_slice(b"EFI PART");
        header[8..12].copy_from_slice(&REVISION.to_le_bytes());
        header[12..16].copy_from_slice(&92u32.to_le_bytes());
        header[24..32].copy_from_slice(&mine.to_le_bytes());
        header[32..40].copy_from_slice(&alternate.to_le_bytes());
        header[40..48].copy_from_slice(&first_usable.to_le_bytes());
        header[48..56].copy_from_slice(&last_usable.to_le_bytes());
        header[56..72].copy_from_slice(&guid(DISK_GUID).0);
        header[72..80].copy_from_slice(&entries.to_le_bytes());
        header[80..84].copy_from_slice(&count.to_le_bytes());
        header[84..88].copy_from_slice(&size.to_le_bytes());
        header[88..92].copy_from_slice(&crc.to_le_bytes());
        self.reseal(lba);
    }

    fn write(&mut self) -> &mut Self {
        let size = (self.sectors() - 1).min(0xFFFF_FFFF) as u32;
        let mbr = &mut self.bytes[..SECTOR_BYTES];
        mbr[446 + 4] = 0xEE;
        mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&size.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        let array = self.array();
        let crc = crc32(&array);
        let backup = self.backup_lba();
        let backup_array = backup - self.array_sectors();
        for lba in [2, backup_array] {
            let start = lba as usize * SECTOR_BYTES;
            self.bytes[start..start + array.len()].copy_from_slice(&array);
        }
        self.header_at(1, 1, backup, 2, crc);
        self.header_at(backup, backup, 1, backup_array, crc);
        self
    }

    /// The protective record's size for the disk's current length.
    fn fix_mbr(&mut self) {
        let size = (self.sectors() - 1).min(0xFFFF_FFFF) as u32;
        self.bytes[446 + 12..446 + 16].copy_from_slice(&size.to_le_bytes());
    }

    /// Recomputes the CRC of the header at `lba` (92 bytes).
    fn reseal(&mut self, lba: u64) {
        let start = lba as usize * SECTOR_BYTES;
        let header = &mut self.bytes[start..start + 92];
        header[16..20].fill(0);
        let crc = crc32(header);
        header[16..20].copy_from_slice(&crc.to_le_bytes());
    }

    fn reseal_header(&mut self) {
        self.reseal(1);
    }

    /// Byte `offset` of the backup header.
    fn backup_byte(&mut self, offset: usize) -> &mut u8 {
        let start = self.backup_lba() as usize * SECTOR_BYTES;
        &mut self.bytes[start + offset]
    }

    fn locate(&self, target: &[u8]) -> Located {
        self.locate_reads(target).0
    }

    /// The result and every (lba, sectors) read.
    fn locate_reads(&self, target: &[u8]) -> (Located, Vec<(u64, usize)>) {
        let mut reads = Vec::new();
        let result = locate(self.sectors(), &guid(target), |lba, buffer: &mut [u8]| {
            assert!(buffer.len().is_multiple_of(SECTOR_BYTES));
            assert!(buffer.len() <= RUN_BYTES);
            reads.push((lba, buffer.len() / SECTOR_BYTES));
            let start = lba as usize * SECTOR_BYTES;
            let source = self.bytes.get(start..start + buffer.len()).ok_or(())?;
            buffer.copy_from_slice(source);
            Ok(())
        });
        (result, reads)
    }
}

#[test]
fn finds_the_partition() {
    let mut disk = Disk::standard();
    disk.write();
    let (found, reads) = disk.locate_reads(ABSD_UNIQUE);
    assert_eq!(
        found,
        Ok(Partition {
            guid: guid(ABSD_UNIQUE),
            first_lba: 4096,
            sectors: 8192 - 34 - 4096 + 1,
            index: 1,
        })
    );
    // LBA 0, LBA 1, the 16 KiB primary array in 8-sector runs, the backup
    // header at the last LBA, then each backup run with the same primary
    // run read again beside it.
    let pass = [(2, 8), (10, 8), (18, 8), (26, 8)];
    let mut expected = vec![(0, 1), (1, 1)];
    expected.extend(pass);
    expected.push((8191, 1));
    for (backup, primary) in [8159, 8167, 8175, 8183].into_iter().zip(pass) {
        expected.push((backup, 8));
        expected.push(primary);
    }
    assert_eq!(reads, expected);
    assert_eq!(
        disk.locate(&ABSD_UNIQUE.to_ascii_uppercase())
            .map(|found| found.first_lba),
        Ok(4096)
    );
}

#[test]
fn odd_entry_geometry() {
    // 4 entries of 256 bytes: a 1 KiB array, one two-sector read per pass.
    let mut disk = Disk::standard();
    disk.entry_count = 4;
    disk.entry_bytes = 256;
    disk.write();
    let (found, reads) = disk.locate_reads(ABSD_UNIQUE);
    assert_eq!(found.map(|found| found.index), Ok(1));
    assert_eq!(
        reads,
        vec![(0, 1), (1, 1), (2, 2), (8191, 1), (8189, 2), (2, 2)]
    );
    // 5 entries of 128 bytes: 640 bytes, the CRC over exactly those.
    let mut disk = Disk::standard();
    disk.entry_count = 5;
    disk.write();
    assert_eq!(disk.locate(ABSD_UNIQUE).map(|found| found.index), Ok(1));
}

#[test]
fn refuses_by_name() {
    let mut disk = Disk::standard();
    disk.write();
    assert_eq!(
        disk.locate(b"11111111-2222-3333-4444-555555555555"),
        Err(Refusal::NotFound)
    );

    let mut no_mbr = Disk::standard();
    no_mbr.write();
    no_mbr.bytes[510] = 0;
    assert_eq!(no_mbr.locate(ABSD_UNIQUE), Err(Refusal::NoProtectiveMbr));
    let mut no_ee = Disk::standard();
    no_ee.write();
    no_ee.bytes[446 + 4] = 0x83;
    assert_eq!(no_ee.locate(ABSD_UNIQUE), Err(Refusal::NoProtectiveMbr));

    let mut header_crc = Disk::standard();
    header_crc.write();
    header_crc.bytes[SECTOR_BYTES + 16] ^= 1;
    assert_eq!(header_crc.locate(ABSD_UNIQUE), Err(Refusal::HeaderCrc));
    // A changed field without a resealed CRC is a CRC refusal too.
    let mut field = Disk::standard();
    field.write();
    field.bytes[SECTOR_BYTES + 40] ^= 1;
    assert_eq!(field.locate(ABSD_UNIQUE), Err(Refusal::HeaderCrc));

    let mut entries_crc = Disk::standard();
    entries_crc.write();
    entries_crc.bytes[2 * SECTOR_BYTES + 128 + 32] ^= 1;
    assert_eq!(entries_crc.locate(ABSD_UNIQUE), Err(Refusal::EntriesCrc));

    let mut duplicate = Disk::standard();
    duplicate
        .entries
        .push((ABSD_TYPE, guid(ABSD_UNIQUE), 100, 200));
    duplicate.write();
    assert_eq!(
        duplicate.locate(ABSD_UNIQUE),
        Err(Refusal::Duplicate { a: 1, b: 2 })
    );

    let mut overlap = Disk::standard();
    overlap.entries[0].3 = 4096;
    overlap.write();
    assert_eq!(
        overlap.locate(ABSD_UNIQUE),
        Err(Refusal::EntryOverlap { a: 0, b: 1 })
    );
    // Touching is not overlapping; an unused entry is never compared.
    let mut unused = Disk::standard();
    unused
        .entries
        .push((Guid::ZERO, guid(ESP_UNIQUE), 4096, 5000));
    unused.write();
    assert!(unused.locate(ABSD_UNIQUE).is_ok());
    // An unused entry carrying the GUID is not a match.
    let mut unused_match = Disk::standard();
    unused_match.entries[1].0 = Guid::ZERO;
    unused_match.write();
    assert_eq!(unused_match.locate(ABSD_UNIQUE), Err(Refusal::NotFound));

    for (first, last) in [(5000, 4999), (33, 4000), (4096, 8192 - 33), (4096, 9000)] {
        let mut range = Disk::standard();
        range.entries[1].2 = first;
        range.entries[1].3 = last;
        range.write();
        assert_eq!(
            range.locate(ABSD_UNIQUE),
            Err(Refusal::EntryRange { index: 1 }),
            "{first}..={last}"
        );
    }
}

#[test]
fn refuses_bad_headers() {
    let cases: [Corruption; 15] = [
        ("signature", |disk| disk.bytes[SECTOR_BYTES] = b'X'),
        ("revision", |disk| disk.bytes[SECTOR_BYTES + 10] = 2),
        ("header-size", |disk| disk.bytes[SECTOR_BYTES + 12] = 91),
        ("my-lba", |disk| disk.bytes[SECTOR_BYTES + 24] = 2),
        ("entry-size", |disk| disk.bytes[SECTOR_BYTES + 84] = 136),
        ("entry-count", |disk| {
            disk.bytes[SECTOR_BYTES + 80..SECTOR_BYTES + 84].copy_from_slice(&0u32.to_le_bytes())
        }),
        ("entries-lba", |disk| disk.bytes[SECTOR_BYTES + 72] = 1),
        ("entries-lba", |disk| disk.bytes[SECTOR_BYTES + 40] = 33),
        ("usable-range", |disk| {
            disk.bytes[SECTOR_BYTES + 48..SECTOR_BYTES + 56].copy_from_slice(&33u64.to_le_bytes())
        }),
        // Past the device, the backup header, and the backup array's first
        // sector (8191 - 32).
        ("last-usable", |disk| {
            disk.bytes[SECTOR_BYTES + 48..SECTOR_BYTES + 56].copy_from_slice(&8192u64.to_le_bytes())
        }),
        ("last-usable", |disk| {
            disk.bytes[SECTOR_BYTES + 48..SECTOR_BYTES + 56].copy_from_slice(&8191u64.to_le_bytes())
        }),
        ("last-usable", |disk| {
            disk.bytes[SECTOR_BYTES + 48..SECTOR_BYTES + 56].copy_from_slice(&8159u64.to_le_bytes())
        }),
        // The backup header is not the device's last sector.
        ("alternate-lba", |disk| {
            disk.bytes[SECTOR_BYTES + 32..SECTOR_BYTES + 40].copy_from_slice(&8190u64.to_le_bytes())
        }),
        ("alternate-lba", |disk| {
            disk.bytes[SECTOR_BYTES + 32..SECTOR_BYTES + 40].copy_from_slice(&8192u64.to_le_bytes())
        }),
        ("alternate-lba", |disk| {
            disk.bytes[SECTOR_BYTES + 32..SECTOR_BYTES + 40].copy_from_slice(&0u64.to_le_bytes())
        }),
    ];
    for (field, corrupt) in cases {
        let mut disk = Disk::standard();
        disk.write();
        corrupt(&mut disk);
        disk.reseal_header();
        let refusal = disk.locate(ABSD_UNIQUE).unwrap_err();
        assert_eq!(refusal, Refusal::BadHeader(field));
        assert_eq!(refusal.name(), "bad-header");
        assert_eq!(refusal.detail(), Some(field));
    }
    let mut count = Disk::standard();
    count.entry_count = MAX_ENTRIES + 1;
    count.write();
    assert_eq!(
        count.locate(ABSD_UNIQUE),
        Err(Refusal::BadHeader("entry-count"))
    );
}

#[test]
fn read_failures_and_tiny_devices() {
    let mut disk = Disk::standard();
    disk.write();
    let result = locate(disk.sectors(), &guid(ABSD_UNIQUE), |lba, _: &mut [u8]| {
        if lba == 2 { Err(7u8) } else { Ok(()) }
    });
    // LBA 0 reads as zeros here, so the MBR refusal comes first.
    assert_eq!(result, Err(Refusal::NoProtectiveMbr));
    let result = locate(
        disk.sectors(),
        &guid(ABSD_UNIQUE),
        |lba, buffer: &mut [u8]| {
            if lba == 10 {
                return Err(7u8);
            }
            let start = lba as usize * SECTOR_BYTES;
            buffer.copy_from_slice(&disk.bytes[start..start + buffer.len()]);
            Ok(())
        },
    );
    assert_eq!(result, Err(Refusal::Read(7)));
    assert_eq!(result.unwrap_err().name(), "read-failed");
    assert_eq!(
        locate(2, &guid(ABSD_UNIQUE), |_, _: &mut [u8]| Ok::<(), ()>(())),
        Err(Refusal::DeviceTooSmall)
    );
}

#[test]
fn second_pass_disagreement_is_refused() {
    // A device whose array changes between the passes.
    let mut disk = Disk::standard();
    disk.write();
    let mut passes = 0;
    let result = locate(
        disk.sectors(),
        &guid(ABSD_UNIQUE),
        |lba, buffer: &mut [u8]| {
            let start = lba as usize * SECTOR_BYTES;
            buffer.copy_from_slice(&disk.bytes[start..start + buffer.len()]);
            if lba == 2 {
                passes += 1;
                if passes == 2 {
                    buffer[200] ^= 1;
                }
            }
            Ok::<(), ()>(())
        },
    );
    // The primary array read again beside the backup no longer matches it.
    assert_eq!(result, Err(Refusal::BackupEntriesDiffer));
}

/// Cross-check with scripts/gpt-partition-test.py's images (`--self-test
/// --rust`): with `ABSD_GPT_IMAGE=path` and `ABSD_GPT_EXPECT` (either
/// `first_lba:sectors` or the refusal as the kernel prints it, e.g.
/// `bad-backup field=signature`), the image is parsed for the ABSD
/// partition. Without them, nothing runs.
#[test]
fn external_image() {
    let (Ok(path), Ok(expect)) = (
        std::env::var("ABSD_GPT_IMAGE"),
        std::env::var("ABSD_GPT_EXPECT"),
    ) else {
        return;
    };
    let bytes = std::fs::read(path).unwrap();
    let sectors = (bytes.len() / SECTOR_BYTES) as u64;
    let result = locate(sectors, &guid(ABSD_UNIQUE), |lba, buffer: &mut [u8]| {
        let start = lba as usize * SECTOR_BYTES;
        buffer.copy_from_slice(&bytes[start..start + buffer.len()]);
        Ok::<(), ()>(())
    });
    let found = match result {
        Ok(found) => std::format!("{}:{}", found.first_lba, found.sectors),
        Err(refusal) => std::format!("{refusal}"),
    };
    assert_eq!(found, expect);
}

/// The review's counterexample: an 8192-sector disk whose CRC-valid
/// primary header declares usable LBAs 34..=8191 and a partition at
/// 4096..=8191, so partition LBA 4095 would be the backup header.
#[test]
fn usable_range_may_not_reach_the_backup_gpt() {
    let mut disk = Disk::new(8192);
    disk.last_usable = 8191;
    disk.entries
        .push((guid(ESP_TYPE), guid(ESP_UNIQUE), 2048, 4095));
    disk.entries
        .push((ABSD_TYPE, guid(ABSD_UNIQUE), 4096, 8191));
    disk.write();
    assert_eq!(
        disk.locate(ABSD_UNIQUE),
        Err(Refusal::BadHeader("last-usable"))
    );
    // Every last-usable from the backup array's first sector on is refused;
    // the sector before it is the largest accepted (the standard layout).
    for last in 8159..=8191 {
        let mut disk = Disk::standard();
        disk.last_usable = last;
        disk.entries[1].3 = last;
        disk.write();
        assert_eq!(
            disk.locate(ABSD_UNIQUE),
            Err(Refusal::BadHeader("last-usable")),
            "{last}"
        );
    }
    let mut disk = Disk::standard();
    disk.write();
    assert_eq!(
        disk.locate(ABSD_UNIQUE)
            .map(|found| found.first_lba + found.sectors),
        Ok(8159)
    );
    // A two-sector array (5 entries): the backup array is 8189..=8190.
    for (last, accepted) in [(8188, true), (8189, false)] {
        let mut disk = Disk::standard();
        disk.entry_count = 5;
        disk.last_usable = last;
        disk.write();
        assert_eq!(disk.locate(ABSD_UNIQUE).is_ok(), accepted, "{last}");
    }
    // An array larger than the space before AlternateLBA: the subtraction
    // is checked, not wrapped. A 20-sector device, AlternateLBA 19, a
    // 32-sector array.
    let mut tiny = Disk::new(64);
    tiny.write();
    tiny.bytes.truncate(20 * SECTOR_BYTES);
    tiny.fix_mbr();
    tiny.bytes[SECTOR_BYTES + 32..SECTOR_BYTES + 40].copy_from_slice(&19u64.to_le_bytes());
    tiny.bytes[SECTOR_BYTES + 48..SECTOR_BYTES + 56].copy_from_slice(&40u64.to_le_bytes());
    tiny.reseal_header();
    assert_eq!(
        tiny.locate(ABSD_UNIQUE),
        Err(Refusal::BadHeader("last-usable"))
    );
}

#[test]
fn backup_header_must_be_the_last_sector() {
    let mut disk = Disk::standard();
    disk.write();
    // The same header on a device one sector longer: AlternateLBA is no
    // longer its last sector.
    disk.bytes.extend_from_slice(&[0; SECTOR_BYTES]);
    disk.fix_mbr();
    assert_eq!(
        disk.locate(ABSD_UNIQUE),
        Err(Refusal::BadHeader("alternate-lba"))
    );
}

#[test]
fn absd_type_constant() {
    assert_eq!(ABSD_TYPE, guid(ABSD_TYPE_TEXT));
    assert_eq!(ABSD_TYPE, guid(b"7AF614A7-2C5B-4EBA-B8F6-217AEC90357A"));
    assert_eq!(&ABSD_TYPE.text(), b"7af614a7-2c5b-4eba-b8f6-217aec90357a");
}

const ABSD_TYPE_TEXT: &[u8] = b"7af614a7-2c5b-4eba-b8f6-217aec90357a";

#[test]
fn selection_is_by_unique_guid_and_requires_the_absd_type() {
    let mut disk = Disk::standard();
    disk.write();
    // The right unique GUID on a partition of another type (the ESP's).
    assert_eq!(disk.locate(ESP_UNIQUE), Err(Refusal::WrongType));
    assert_eq!(Refusal::<()>::WrongType.name(), "wrong-type");
    // The ABSD partition with any other type.
    let mut linux = Disk::standard();
    linux.entries[1].0 = guid(b"0FC63DAF-8483-4772-8E79-3D69D8477DE4");
    linux.write();
    assert_eq!(linux.locate(ABSD_UNIQUE), Err(Refusal::WrongType));
    // The right type, but no entry with the unique GUID asked for; the
    // type GUID itself is never a selector.
    let mut other = Disk::standard();
    other.entries[1].1 = guid(b"5a8b3c2d-1e4f-4a6b-8c9d-0e1f2a3b4c5e");
    other.write();
    assert_eq!(other.locate(ABSD_UNIQUE), Err(Refusal::NotFound));
    assert_eq!(other.locate(ABSD_TYPE_TEXT), Err(Refusal::NotFound));
}

type BackupCorruption = (Refusal<()>, fn(&mut Disk));

#[test]
fn both_copies_are_validated() {
    let cases: [BackupCorruption; 13] = [
        // A corrupt backup header and a corrupt backup array.
        (Refusal::BackupHeaderCrc, |disk| *disk.backup_byte(16) ^= 1),
        (Refusal::BackupHeaderCrc, |disk| *disk.backup_byte(60) ^= 1),
        (Refusal::BackupEntriesCrc, |disk| {
            let start = (disk.backup_lba() - 32) as usize * SECTOR_BYTES;
            disk.bytes[start + 128 + 60] ^= 1;
        }),
        // Missing (all zero), or moved one sector down: nothing at the
        // last LBA.
        (Refusal::BadBackup("signature"), |disk| {
            let start = disk.backup_lba() as usize * SECTOR_BYTES;
            disk.bytes[start..start + SECTOR_BYTES].fill(0);
        }),
        (Refusal::BadBackup("signature"), |disk| {
            let start = disk.backup_lba() as usize * SECTOR_BYTES;
            disk.bytes
                .copy_within(start..start + SECTOR_BYTES, start - SECTOR_BYTES);
            disk.bytes[start..start + SECTOR_BYTES].fill(0);
        }),
        // CRC-valid but disagreeing with the primary, field by field.
        (Refusal::BadBackup("my-lba"), |disk| {
            *disk.backup_byte(24) ^= 1;
            disk.reseal(disk.backup_lba());
        }),
        (Refusal::BadBackup("alternate-lba"), |disk| {
            *disk.backup_byte(32) = 2;
            disk.reseal(disk.backup_lba());
        }),
        (Refusal::BadBackup("first-usable"), |disk| {
            *disk.backup_byte(40) += 1;
            disk.reseal(disk.backup_lba());
        }),
        (Refusal::BadBackup("last-usable"), |disk| {
            *disk.backup_byte(48) -= 1;
            disk.reseal(disk.backup_lba());
        }),
        (Refusal::BadBackup("disk-guid"), |disk| {
            *disk.backup_byte(60) ^= 1;
            disk.reseal(disk.backup_lba());
        }),
        (Refusal::BadBackup("entry-count"), |disk| {
            *disk.backup_byte(80) = 127;
            disk.reseal(disk.backup_lba());
        }),
        (Refusal::BadBackup("entries-crc"), |disk| {
            *disk.backup_byte(88) ^= 1;
            disk.reseal(disk.backup_lba());
        }),
        // The array not adjacent to the header (moved one sector down,
        // with the header pointing at it: CRC-valid and self-consistent).
        (Refusal::BadBackup("entries-lba"), |disk| {
            let header = disk.backup_lba();
            let start = (header - 32) as usize * SECTOR_BYTES;
            disk.bytes
                .copy_within(start..start + 32 * SECTOR_BYTES, start - SECTOR_BYTES);
            *disk.backup_byte(72) -= 1;
            disk.reseal(header);
        }),
    ];
    for (expected, corrupt) in cases {
        let mut disk = Disk::standard();
        disk.write();
        corrupt(&mut disk);
        // The primary is untouched and valid in every case.
        assert!(
            header::<()>(
                &disk.bytes[SECTOR_BYTES..2 * SECTOR_BYTES]
                    .try_into()
                    .unwrap(),
                8192
            )
            .is_ok()
        );
        let refusal = disk.locate(ABSD_UNIQUE).unwrap_err();
        assert_eq!(refusal, expected);
        if let Refusal::BadBackup(field) = expected {
            assert_eq!(refusal.name(), "bad-backup");
            assert_eq!(refusal.detail(), Some(field));
        }
    }
    assert_eq!(
        Refusal::<()>::BackupHeaderCrc.name(),
        "backup-header-crc-mismatch"
    );
    assert_eq!(
        Refusal::<()>::BackupEntriesCrc.name(),
        "backup-entries-crc-mismatch"
    );
    // The backup is checked before the selection: a missing backup is
    // refused even for a GUID no entry carries.
    let mut disk = Disk::standard();
    disk.write();
    let start = disk.backup_lba() as usize * SECTOR_BYTES;
    disk.bytes[start..start + SECTOR_BYTES].fill(0);
    assert_eq!(
        disk.locate(b"11111111-2222-3333-4444-555555555555"),
        Err(Refusal::BadBackup("signature"))
    );
}

/// The second Codex review (coordination record #123): every used entry is checked,
/// not only the selected one.
#[test]
fn every_used_entry_is_checked() {
    let with = |extra: &[(Guid, Guid, u64, u64)]| {
        let mut disk = Disk::standard();
        disk.entries.extend_from_slice(extra);
        disk.write();
        disk.locate(ABSD_UNIQUE)
    };
    let a = guid(b"aaaaaaaa-0000-4000-8000-000000000001");
    let b = guid(b"bbbbbbbb-0000-4000-8000-000000000002");
    let linux = guid(b"0FC63DAF-8483-4772-8E79-3D69D8477DE4");
    // Two unselected partitions overlapping each other (100..=199 and
    // 150..=249), beside a valid ABSD partition.
    assert_eq!(
        with(&[(linux, a, 100, 199), (linux, b, 150, 249)]),
        Err(Refusal::EntryOverlap { a: 2, b: 3 })
    );
    // Touching ranges are fine.
    assert!(with(&[(linux, a, 100, 199), (linux, b, 200, 249)]).is_ok());
    // An inverted unselected range, one below FirstUsable (over the
    // primary array), and one past LastUsable (over the backup array).
    for (first, last) in [(300, 299), (20, 40), (8150, 8160), (u64::MAX, u64::MAX)] {
        assert_eq!(
            with(&[(linux, a, first, last)]),
            Err(Refusal::EntryRange { index: 2 }),
            "{first}..={last}"
        );
    }
    // A duplicate unique GUID among unselected entries.
    assert_eq!(
        with(&[(linux, a, 100, 199), (linux, a, 200, 299)]),
        Err(Refusal::Duplicate { a: 2, b: 3 })
    );
    // A used entry with a zero unique GUID.
    assert_eq!(
        with(&[(linux, Guid::ZERO, 100, 199)]),
        Err(Refusal::ZeroGuid { index: 2 })
    );
    // An unused entry (zero type) is never checked, whatever it holds.
    assert!(
        with(&[
            (Guid::ZERO, a, 300, 299),
            (Guid::ZERO, guid(ABSD_UNIQUE), 4096, 4096)
        ])
        .is_ok()
    );
    // The table is judged even when the GUID asked for is absent.
    let mut disk = Disk::standard();
    disk.entries.push((linux, a, 100, 199));
    disk.entries.push((linux, b, 150, 249));
    disk.write();
    assert_eq!(
        disk.locate(b"11111111-2222-3333-4444-555555555555"),
        Err(Refusal::EntryOverlap { a: 2, b: 3 })
    );
    // More used entries than the table holds.
    let mut full = Disk::standard();
    full.entries.clear();
    for index in 0..=MAX_USED_ENTRIES as u64 {
        let mut unique = [0u8; 16];
        unique[..8].copy_from_slice(&(index + 1).to_le_bytes());
        full.entries
            .push((linux, Guid(unique), 100 + index * 10, 109 + index * 10));
    }
    full.entry_count = 256;
    full.first_usable = 2 + 64;
    full.last_usable = 8191 - 64 - 1;
    full.write();
    assert_eq!(full.locate(ABSD_UNIQUE), Err(Refusal::TooManyEntries));
    assert_eq!(
        std::format!("{}", Refusal::<()>::EntryOverlap { a: 2, b: 3 }),
        "entry-overlap a=2 b=3"
    );
    assert_eq!(
        std::format!("{}", Refusal::<()>::EntryRange { index: 2 }),
        "entry-range index=2"
    );
    assert_eq!(
        std::format!("{}", Refusal::<()>::Duplicate { a: 1, b: 2 }),
        "duplicate-guid a=1 b=2"
    );
    assert_eq!(
        std::format!("{}", Refusal::<()>::BadBackup("disk-guid")),
        "bad-backup field=disk-guid"
    );
    assert_eq!(
        std::format!("{}", Refusal::<u8>::Read(7)),
        "read-failed error=7"
    );
}

/// A backup array with the primary's CRC32 but other bytes: the ABSD
/// entry's FirstLBA changed and four name bytes chosen so the CRC32 stays
/// the same (CRC32 is linear, so the four bytes are solvable).
#[test]
fn same_crc_backup_with_another_mapping_is_refused() {
    let mut disk = Disk::standard();
    disk.write();
    let backup_array = (disk.backup_lba() - 32) as usize * SECTOR_BYTES;
    let array_bytes = 128 * 128;
    let original = disk.bytes[backup_array..backup_array + array_bytes].to_vec();
    let mut forged = original.clone();
    // Entry 1's FirstLBA 4096 -> 4097.
    forged[128 + 32..128 + 40].copy_from_slice(&4097u64.to_le_bytes());
    // Entry 1's name bytes 56..60 fix the CRC.
    let patch = 128 + 56;
    let fix = crc_patch(&forged, patch, crc32(&original));
    forged[patch..patch + 4].copy_from_slice(&fix);
    assert_eq!(crc32(&forged), crc32(&original));
    assert_ne!(forged, original);
    disk.bytes[backup_array..backup_array + array_bytes].copy_from_slice(&forged);
    assert_eq!(disk.locate(ABSD_UNIQUE), Err(Refusal::BackupEntriesDiffer));
    assert_eq!(
        Refusal::<()>::BackupEntriesDiffer.name(),
        "backup-entries-differ"
    );
}

/// The four bytes at `at` that make `crc32(data) == want`: try each of the
/// 32 single-bit changes of a zero patch and solve the linear system.
fn crc_patch(data: &[u8], at: usize, want: u32) -> [u8; 4] {
    let mut base = data.to_vec();
    base[at..at + 4].fill(0);
    let zero = crc32(&base);
    // Column k: the CRC change from flipping bit k of the patch.
    let mut columns = [0u32; 32];
    for (bit, column) in columns.iter_mut().enumerate() {
        let mut probe = base.clone();
        probe[at + bit / 8] ^= 1 << (bit % 8);
        *column = crc32(&probe) ^ zero;
    }
    // Gaussian elimination over GF(2): find bits whose columns XOR to
    // `want ^ zero`.
    let mut rows: Vec<(u32, u32)> = columns
        .iter()
        .enumerate()
        .map(|(bit, &column)| (column, 1u32 << bit))
        .collect();
    let mut target = (want ^ zero, 0u32);
    for pivot in 0..32 {
        let mask = 1u32 << pivot;
        let Some(found) = (pivot..32).find(|&row| rows[row].0 & mask != 0) else {
            continue;
        };
        rows.swap(pivot, found);
        let (value, bits) = rows[pivot];
        for (row, entry) in rows.iter_mut().enumerate() {
            if row != pivot && entry.0 & mask != 0 {
                entry.0 ^= value;
                entry.1 ^= bits;
            }
        }
        if target.0 & mask != 0 {
            target.0 ^= value;
            target.1 ^= bits;
        }
    }
    assert_eq!(target.0, 0, "no solution");
    target.1.to_le_bytes()
}

#[test]
fn standard_protective_mbr_only() {
    let refused = |change: fn(&mut Disk)| {
        let mut disk = Disk::standard();
        disk.write();
        change(&mut disk);
        disk.locate(ABSD_UNIQUE)
    };
    // A hybrid MBR: a second, non-empty record beside the 0xEE one.
    assert_eq!(
        refused(|disk| {
            disk.bytes[446 + 16 + 4] = 0x0C;
            disk.bytes[446 + 16 + 8..446 + 16 + 12].copy_from_slice(&2048u32.to_le_bytes());
        }),
        Err(Refusal::HybridMbr)
    );
    // Any nonzero byte in another record.
    assert_eq!(
        refused(|disk| disk.bytes[446 + 48 + 15] = 1),
        Err(Refusal::HybridMbr)
    );
    // A zero-length protective record, a short one, and a wrong start.
    assert_eq!(
        refused(|disk| disk.bytes[446 + 12..446 + 16].fill(0)),
        Err(Refusal::BadProtectiveMbr("size"))
    );
    assert_eq!(
        refused(|disk| disk.bytes[446 + 12] -= 1),
        Err(Refusal::BadProtectiveMbr("size"))
    );
    assert_eq!(
        refused(|disk| disk.bytes[446 + 8] = 2),
        Err(Refusal::BadProtectiveMbr("start-lba"))
    );
    // Status and CHS bytes are not judged; the record may sit in any slot.
    assert!(
        refused(|disk| {
            disk.bytes[446] = 0x80;
            disk.bytes[446 + 1..446 + 4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
            disk.bytes[446 + 5..446 + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        })
        .is_ok()
    );
    assert!(
        refused(|disk| {
            let record: [u8; 16] = disk.bytes[446..462].try_into().unwrap();
            disk.bytes[446..462].fill(0);
            disk.bytes[446 + 32..446 + 48].copy_from_slice(&record);
        })
        .is_ok()
    );
    // A disk past 2^32 sectors: the size saturates at 0xFFFFFFFF.
    let mut mbr = [0u8; SECTOR_BYTES];
    mbr[446 + 4] = 0xEE;
    mbr[446 + 8] = 1;
    mbr[446 + 12..446 + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    assert_eq!(protective_mbr::<()>(&mbr, 1 << 33), Ok(()));
    assert_eq!(
        protective_mbr::<()>(&mbr, 8192),
        Err(Refusal::BadProtectiveMbr("size"))
    );
    assert_eq!(
        std::format!("{}", Refusal::<()>::BadProtectiveMbr("size")),
        "bad-protective-mbr field=size"
    );
}

#[test]
fn header_reserved_word_padding_and_backup_size() {
    let mut disk = Disk::standard();
    disk.write();
    disk.bytes[SECTOR_BYTES + 20] = 1;
    disk.reseal(1);
    assert_eq!(
        disk.locate(ABSD_UNIQUE),
        Err(Refusal::BadHeader("reserved"))
    );
    let mut disk = Disk::standard();
    disk.write();
    disk.bytes[SECTOR_BYTES + 200] = 1;
    assert_eq!(
        disk.locate(ABSD_UNIQUE),
        Err(Refusal::BadHeader("header-padding"))
    );
    let mut disk = Disk::standard();
    disk.write();
    *disk.backup_byte(20) = 1;
    disk.reseal(disk.backup_lba());
    assert_eq!(
        disk.locate(ABSD_UNIQUE),
        Err(Refusal::BadBackup("reserved"))
    );
    let mut disk = Disk::standard();
    disk.write();
    *disk.backup_byte(511) = 1;
    assert_eq!(
        disk.locate(ABSD_UNIQUE),
        Err(Refusal::BadBackup("header-padding"))
    );
    // A larger backup header (96 bytes, the extra word zero and inside the
    // CRC): sealed and padded correctly, but not the primary's size.
    let mut disk = Disk::standard();
    disk.write();
    *disk.backup_byte(12) = 96;
    let start = disk.backup_lba() as usize * SECTOR_BYTES;
    disk.bytes[start + 16..start + 20].fill(0);
    let crc = crc32(&disk.bytes[start..start + 96]);
    disk.bytes[start + 16..start + 20].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(
        disk.locate(ABSD_UNIQUE),
        Err(Refusal::BadBackup("header-size"))
    );
}
