//! Wire records for one negotiated S16/stereo/48kHz VirtIO Sound stream.
//! Reference: VirtIO 1.2 section 5.14.6; explicit little-endian bytes.
pub const PERIOD_BYTES: usize = 1920;
pub const BUFFER_BYTES: usize = PERIOD_BYTES * 5;
pub const OK: u32 = 0x8000;
pub const PREPARE: u32 = 0x102;
pub const RELEASE: u32 = 0x103;
pub const START: u32 = 0x104;
pub const STOP: u32 = 0x105;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Short,
    Device,
    Unsupported,
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
pub fn status(b: &[u8]) -> Result<(), Error> {
    if b.len() < 4 {
        return Err(Error::Short);
    }
    if u32_at(b, 0) != OK {
        return Err(Error::Device);
    }
    Ok(())
}
pub fn accept_info(b: &[u8]) -> Result<(), Error> {
    if b.len() != 36 {
        return Err(Error::Short);
    }
    status(b)?;
    if b[28] != 0
        || b[29] > 2
        || b[30] < 2
        || u64_at(b, 12) & (1 << 5) == 0
        || u64_at(b, 20) & (1 << 7) == 0
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}
pub fn query(stream: u32) -> [u8; 16] {
    let mut b = [0; 16];
    b[0..4].copy_from_slice(&0x100u32.to_le_bytes());
    b[4..8].copy_from_slice(&stream.to_le_bytes());
    b[8..12].copy_from_slice(&1u32.to_le_bytes());
    b[12..16].copy_from_slice(&32u32.to_le_bytes());
    b
}
pub fn command(code: u32, stream: u32) -> [u8; 8] {
    let mut b = [0; 8];
    b[0..4].copy_from_slice(&code.to_le_bytes());
    b[4..8].copy_from_slice(&stream.to_le_bytes());
    b
}
pub fn params(stream: u32) -> [u8; 24] {
    let mut b = [0; 24];
    b[..8].copy_from_slice(&command(0x101, stream));
    b[8..12].copy_from_slice(&(BUFFER_BYTES as u32).to_le_bytes());
    b[12..16].copy_from_slice(&(PERIOD_BYTES as u32).to_le_bytes());
    b[20] = 2;
    b[21] = 5;
    b[22] = 7;
    b
}
pub fn tx_status(b: &[u8]) -> Result<u32, Error> {
    if b.len() != 8 {
        return Err(Error::Short);
    }
    status(b)?;
    Ok(u32_at(b, 4))
}

/// QEMU 8.2.2 process_cmd writes PCM_INFO data then reports only hdr bytes.
/// The opt-in quirk accepts that exact query only after validating a populated
/// success payload. It does not change TX or generic queue ownership checks.
pub fn control_length(code: u32, expected: u32, reported: u32, reply: &[u8], qemu82: bool) -> bool {
    reported == expected
        || (qemu82
            && code == 0x100
            && expected == 36
            && reported == 4
            && accept_info(reply).is_ok()
            && reply[31..36] == [0; 5])
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reply() -> [u8; 36] {
        let mut r = [0u8; 36];
        r[1] = 0x80;
        r[12] = 0x20;
        r[20] = 0x80;
        r[29] = 1;
        r[30] = 2;
        r
    }
    #[test]
    fn only_offered_playback_format_is_accepted() {
        assert_eq!(accept_info(&reply()), Ok(()));
        for (offset, value) in [(1, 0), (12, 0), (20, 0), (28, 1), (29, 3), (30, 1)] {
            let mut r = reply();
            r[offset] = value;
            assert!(accept_info(&r).is_err(), "offset {offset}");
        }
        assert!(accept_info(&reply()[..35]).is_err());
    }
    #[test]
    fn qemu82_info_length_quirk_is_explicit_and_narrow() {
        let r = reply();
        assert!(!control_length(0x100, 36, 4, &r, false));
        assert!(control_length(0x100, 36, 4, &r, true));
        assert!(control_length(0x100, 36, 36, &r, false));
        assert!(!control_length(0x101, 36, 4, &r, true));
        assert!(!control_length(0x100, 36, 3, &r, true));
        assert!(!control_length(0x100, 36, 8, &r, true));
        assert!(!control_length(0x100, 36, 37, &r, true));
        let mut missing = r;
        missing[31..].fill(255);
        assert!(!control_length(0x100, 36, 4, &missing, true));
        assert!(!control_length(0x100, 36, 4, &[255; 36], true));
    }

    #[test]
    fn parameters_and_query_are_well_formed() {
        let p = params(3);
        assert_eq!(u32::from_le_bytes(p[0..4].try_into().unwrap()), 0x101);
        assert_eq!(u32::from_le_bytes(p[4..8].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(p[8..12].try_into().unwrap()), 9600);
        assert_eq!(u32::from_le_bytes(p[12..16].try_into().unwrap()), 1920);
        assert_eq!(&p[16..], &[0, 0, 0, 0, 2, 5, 7, 0]);
        assert_eq!(query(3), [0, 1, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 32, 0, 0, 0]);
    }
    #[test]
    fn tx_status_requires_complete_success_record() {
        assert_eq!(tx_status(&[0, 128, 0, 0, 128, 7, 0, 0]), Ok(1920));
        assert!(tx_status(&[3, 128, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(tx_status(&[0, 128, 0, 0]).is_err());
    }
}
