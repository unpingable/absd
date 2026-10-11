//! Deliberately small ELF64 parser for static freestanding ABSD programs.

pub const PT_LOAD: u32 = 1;
pub const PF_EXECUTE: u32 = 1;
pub const PF_WRITE: u32 = 2;
pub const PF_READ: u32 = 4;
pub const MAX_LOAD_SEGMENTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    pub offset: usize,
    pub virtual_address: u64,
    pub file_size: usize,
    pub memory_size: usize,
    pub flags: u32,
    pub alignment: u64,
}

impl LoadSegment {
    pub const EMPTY: Self = Self {
        offset: 0,
        virtual_address: 0,
        file_size: 0,
        memory_size: 0,
        flags: 0,
        alignment: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Image {
    pub entry: u64,
    pub segments: [LoadSegment; MAX_LOAD_SEGMENTS],
    pub segment_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfError {
    HeaderTooSmall,
    BadMagic,
    UnsupportedClass,
    UnsupportedEndian,
    UnsupportedType,
    UnsupportedMachine,
    UnsupportedVersion,
    InvalidProgramHeaders,
    TooManyLoadSegments,
    InvalidLoadSegment,
    UnsupportedProgramHeader,
    EntryNotExecutable,
    /// The image's memory could not be read (a `spawn_image` source).
    Unreadable,
}

/// Where the loader reads an image from: an embedded catalog slice, or a
/// range of the calling process's memory (`spawn_image`). Reads are exact:
/// a range past `len` is an error, never a short read.
pub trait ImageSource {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), ElfError>;
}

impl ImageSource for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), ElfError> {
        let end = offset
            .checked_add(out.len())
            .ok_or(ElfError::HeaderTooSmall)?;
        out.copy_from_slice(self.get(offset..end).ok_or(ElfError::HeaderTooSmall)?);
        Ok(())
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, ElfError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(ElfError::HeaderTooSmall)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ElfError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(ElfError::HeaderTooSmall)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, ElfError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(ElfError::HeaderTooSmall)?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

const HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;

pub fn parse(bytes: &[u8]) -> Result<Image, ElfError> {
    parse_source(bytes)
}

/// Parses an image read through `source`. Only the ELF header and one
/// program header at a time are copied, so the image itself never has to
/// be resident in kernel memory.
pub fn parse_source<S: ImageSource + ?Sized>(source: &S) -> Result<Image, ElfError> {
    let length = source.len();
    if length < HEADER_BYTES {
        return Err(ElfError::HeaderTooSmall);
    }
    let mut header = [0u8; HEADER_BYTES];
    source.read(0, &mut header)?;
    let bytes = &header[..];
    if &bytes[0..4] != b"\x7fELF" {
        return Err(ElfError::BadMagic);
    }
    if bytes[4] != 2 {
        return Err(ElfError::UnsupportedClass);
    }
    if bytes[5] != 1 {
        return Err(ElfError::UnsupportedEndian);
    }
    if u16_at(bytes, 16)? != 2 {
        return Err(ElfError::UnsupportedType);
    }
    if u16_at(bytes, 18)? != crate::arch::ELF_MACHINE {
        return Err(ElfError::UnsupportedMachine);
    }
    if u32_at(bytes, 20)? != 1 {
        return Err(ElfError::UnsupportedVersion);
    }
    let entry = u64_at(bytes, 24)?;
    let program_offset =
        usize::try_from(u64_at(bytes, 32)?).map_err(|_| ElfError::InvalidProgramHeaders)?;
    let entry_size = u16_at(bytes, 54)? as usize;
    let entry_count = u16_at(bytes, 56)? as usize;
    if entry_size != PROGRAM_HEADER_BYTES || entry_count == 0 {
        return Err(ElfError::InvalidProgramHeaders);
    }
    let table_bytes = entry_size
        .checked_mul(entry_count)
        .ok_or(ElfError::InvalidProgramHeaders)?;
    if program_offset
        .checked_add(table_bytes)
        .is_none_or(|end| end > length)
    {
        return Err(ElfError::InvalidProgramHeaders);
    }

    let mut image = Image {
        entry,
        segments: [LoadSegment::EMPTY; MAX_LOAD_SEGMENTS],
        segment_count: 0,
    };
    let mut program_header = [0u8; PROGRAM_HEADER_BYTES];
    for index in 0..entry_count {
        source.read(program_offset + index * entry_size, &mut program_header)?;
        let bytes = &program_header[..];
        let kind = u32_at(bytes, 0)?;
        if kind == 0 {
            continue;
        }
        if kind != PT_LOAD {
            return Err(ElfError::UnsupportedProgramHeader);
        }
        if image.segment_count == MAX_LOAD_SEGMENTS {
            return Err(ElfError::TooManyLoadSegments);
        }
        let offset =
            usize::try_from(u64_at(bytes, 8)?).map_err(|_| ElfError::InvalidLoadSegment)?;
        let virtual_address = u64_at(bytes, 16)?;
        let file_size =
            usize::try_from(u64_at(bytes, 32)?).map_err(|_| ElfError::InvalidLoadSegment)?;
        let memory_size =
            usize::try_from(u64_at(bytes, 40)?).map_err(|_| ElfError::InvalidLoadSegment)?;
        let flags = u32_at(bytes, 4)?;
        let alignment = u64_at(bytes, 48)?;
        if memory_size == 0
            || file_size > memory_size
            || offset.checked_add(file_size).is_none_or(|end| end > length)
            || virtual_address.checked_add(memory_size as u64).is_none()
            || alignment == 0
            || !alignment.is_power_of_two()
            || virtual_address % alignment != offset as u64 % alignment
            || flags & !(PF_READ | PF_WRITE | PF_EXECUTE) != 0
        {
            return Err(ElfError::InvalidLoadSegment);
        }
        image.segments[image.segment_count] = LoadSegment {
            offset,
            virtual_address,
            file_size,
            memory_size,
            flags,
            alignment,
        };
        image.segment_count += 1;
    }
    if image.segment_count == 0
        || !image.segments[..image.segment_count].iter().any(|segment| {
            segment.flags & PF_EXECUTE != 0
                && entry >= segment.virtual_address
                && entry < segment.virtual_address + segment.memory_size as u64
        })
    {
        return Err(ElfError::EntryNotExecutable);
    }
    Ok(image)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    const HELLO: &[u8] = include_bytes!(env!("ABSD_USER_HELLO_A_ELF"));
    const EXIT7: &[u8] = include_bytes!(env!("ABSD_USER_EXIT7_ELF"));
    #[test]
    fn parses_the_separately_built_static_user_programs() {
        let image = parse(HELLO).unwrap();
        assert_eq!(image.entry, crate::layout::USER_IMAGE_MIN);
        assert_eq!(image.segment_count, 2);
        assert_eq!(image.segments[0].flags, PF_READ | PF_EXECUTE);
        assert_eq!(image.segments[1].flags, PF_READ | PF_WRITE);
        // exit7 carries a zero-initialised static, so its data segment has BSS.
        let image = parse(EXIT7).unwrap();
        assert_eq!(image.segment_count, 2);
        assert_eq!(image.segments[1].flags, PF_READ | PF_WRITE);
        assert!(image.segments[1].memory_size > image.segments[1].file_size);
    }
    #[test]
    fn rejects_wrong_magic_machine_and_unsupported_headers() {
        let mut bytes = HELLO.to_vec();
        bytes[0] = 0;
        assert_eq!(parse(&bytes), Err(ElfError::BadMagic));
        bytes = HELLO.to_vec();
        bytes[18..20].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ElfError::UnsupportedMachine));
        bytes = HELLO.to_vec();
        let phoff = u64_at(&bytes, 32).unwrap() as usize;
        bytes[phoff..phoff + 4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ElfError::UnsupportedProgramHeader));
    }
    #[test]
    fn rejects_truncation_and_an_entry_outside_executable_memory() {
        let image = parse(HELLO).unwrap();
        let needed = image.segments[..image.segment_count]
            .iter()
            .map(|segment| segment.offset + segment.file_size)
            .max()
            .unwrap();
        assert_eq!(
            parse(&HELLO[..needed - 1]),
            Err(ElfError::InvalidLoadSegment)
        );
        assert_eq!(parse(&HELLO[..63]), Err(ElfError::HeaderTooSmall));
        let mut bytes = HELLO.to_vec();
        bytes[24..32].copy_from_slice(&0x10u64.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ElfError::EntryNotExecutable));
    }

    /// The adversarial ELF matrix's template (user/src/bin/elf_matrix.rs):
    /// R+X code at 0x400000 from file offset 0x1000, R+W data at 0x410000
    /// from 0x2000 with 0x10 file bytes and two pages of memory.
    fn template() -> Vec<u8> {
        let mut bytes = std::vec![0u8; 0x3000];
        bytes[0..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        put_ph(
            &mut bytes,
            0,
            PF_READ | PF_EXECUTE,
            0x1000,
            0x40_0000,
            0x10,
            0x1000,
            0x1000,
        );
        put_ph(
            &mut bytes,
            1,
            PF_READ | PF_WRITE,
            0x2000,
            0x41_0000,
            0x10,
            0x2000,
            0x1000,
        );
        bytes
    }

    #[allow(clippy::too_many_arguments)]
    fn put_ph(
        bytes: &mut [u8],
        index: usize,
        flags: u32,
        offset: u64,
        va: u64,
        filesz: u64,
        memsz: u64,
        align: u64,
    ) {
        let at = 64 + index * PROGRAM_HEADER_BYTES;
        bytes[at..at + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        for (field, value) in [
            (8, offset),
            (16, va),
            (24, va),
            (32, filesz),
            (40, memsz),
            (48, align),
        ] {
            bytes[at + field..at + field + 8].copy_from_slice(&value.to_le_bytes());
        }
    }

    fn with(mutate: impl FnOnce(&mut Vec<u8>)) -> Result<Image, ElfError> {
        let mut bytes = template();
        mutate(&mut bytes);
        parse(&bytes)
    }

    type Mutation = fn(&mut Vec<u8>);

    fn set64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Each refusal of the adversarial matrix fails the check it names, not
    /// an incidental later one (the syscall reports all of them as -8).
    #[test]
    fn adversarial_matrix_refusals_name_their_check() {
        use ElfError::*;
        assert!(with(|_| {}).is_ok());
        let cases: [(&str, Mutation, ElfError); 22] = [
            ("len-63", |b| b.truncate(63), HeaderTooSmall),
            (
                "ph-truncated",
                |b| b.truncate(64 + 56 + 10),
                InvalidProgramHeaders,
            ),
            ("class-32", |b| b[4] = 1, UnsupportedClass),
            ("endian-big", |b| b[5] = 2, UnsupportedEndian),
            ("type-dyn", |b| b[16] = 3, UnsupportedType),
            ("version-0", |b| b[20] = 0, UnsupportedVersion),
            ("phentsize-57", |b| b[54] = 57, InvalidProgramHeaders),
            ("phnum-0", |b| b[56] = 0, InvalidProgramHeaders),
            (
                "phnum-ffff",
                |b| b[56..58].copy_from_slice(&[0xff, 0xff]),
                InvalidProgramHeaders,
            ),
            (
                "phoff-overflow",
                |b| set64(b, 32, u64::MAX - 8),
                InvalidProgramHeaders,
            ),
            (
                "offset-overflow",
                |b| set64(b, 64 + 56 + 8, u64::MAX - 0xf),
                InvalidLoadSegment,
            ),
            (
                "filesz-beyond-image",
                |b| set64(b, 64 + 56 + 32, 0x1001),
                InvalidLoadSegment,
            ),
            (
                "filesz-gt-memsz",
                |b| set64(b, 64 + 56 + 32, 0x2001),
                InvalidLoadSegment,
            ),
            (
                "vaddr-overflow",
                |b| set64(b, 64 + 56 + 16, 0xffff_ffff_ffff_f000),
                InvalidLoadSegment,
            ),
            ("memsz-0", |b| set64(b, 64 + 56 + 40, 0), InvalidLoadSegment),
            ("align-0", |b| set64(b, 64 + 56 + 48, 0), InvalidLoadSegment),
            ("align-3", |b| set64(b, 64 + 56 + 48, 3), InvalidLoadSegment),
            (
                "align-2m-incongruent",
                |b| set64(b, 64 + 56 + 48, 0x20_0000),
                InvalidLoadSegment,
            ),
            (
                "vaddr-offset-incongruent",
                |b| set64(b, 64 + 56 + 16, 0x41_0004),
                InvalidLoadSegment,
            ),
            (
                "flags-unknown-bit",
                |b| b[64 + 56 + 4] = 0xe,
                InvalidLoadSegment,
            ),
            (
                "entry-in-rw",
                |b| set64(b, 24, 0x41_0000),
                EntryNotExecutable,
            ),
            (
                "entry-at-segment-end",
                |b| set64(b, 24, 0x40_1000),
                EntryNotExecutable,
            ),
        ];
        for (name, mutate, expected) in cases {
            assert_eq!(with(mutate), Err(expected), "{name}");
        }
        // Nine loads, and a PT_GNU_STACK entry.
        assert_eq!(
            with(|b| {
                b[56] = 9;
                for index in 2..9 {
                    put_ph(
                        b,
                        index,
                        PF_READ,
                        0,
                        0x42_0000 + 0x1000 * index as u64,
                        0,
                        0x1000,
                        0x1000,
                    );
                }
            }),
            Err(TooManyLoadSegments)
        );
        assert_eq!(
            with(|b| {
                b[56] = 3;
                b[64 + 2 * 56..64 + 2 * 56 + 4].copy_from_slice(&0x6474_e551u32.to_le_bytes());
            }),
            Err(UnsupportedProgramHeader)
        );
    }

    /// Cases the parser accepts and leaves to the loader: placement outside
    /// the user window, page-sharing between segments, and `vaddr + memsz`
    /// ending exactly at `u64::MAX` (no add overflow). `populate` refuses
    /// them; the QEMU matrix proves it.
    #[test]
    fn placement_is_left_to_the_loader() {
        let end_at_max = with(|b| {
            set64(b, 64 + 56 + 16, 0xffff_ffff_ffff_f000);
            set64(b, 64 + 56 + 40, 0xfff);
        })
        .unwrap();
        assert_eq!(
            end_at_max.segments[1].virtual_address + end_at_max.segments[1].memory_size as u64,
            u64::MAX
        );
        assert!(with(|b| set64(b, 64 + 56 + 16, 0x8000_0000_0000_0000)).is_ok());
        assert!(
            with(|b| {
                b[56] = 3;
                put_ph(
                    b,
                    2,
                    PF_READ | PF_WRITE,
                    0x2800,
                    0x41_1800,
                    0x10,
                    0x10,
                    0x1000,
                );
            })
            .is_ok()
        );
        // Fields the parser never reads.
        assert!(with(|b| b[6] = 0).is_ok());
        assert!(with(|b| b[52..54].copy_from_slice(&[0xff, 0xff])).is_ok());
    }
}
