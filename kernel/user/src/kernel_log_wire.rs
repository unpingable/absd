//! Experimental log frame v1, matched by kernel src/kernel_log.rs.
pub const FRAME_BYTES: usize = 576;
pub const MAX_MESSAGE: usize = 480;
pub const TRUNCATED: u32 = 1;
pub const PARTIAL: u32 = 2;
pub const EMERGENCY: u32 = 4;
pub const INFERRED: u32 = 8;
pub const LOSS: u32 = 16;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cursor(pub u64);
impl Default for Cursor {
    fn default() -> Self {
        Self::new()
    }
}
impl Cursor {
    pub const fn new() -> Self {
        Self(0)
    }
    pub const fn at(sequence: u64) -> Self {
        Self(sequence)
    }
    pub fn next(&self) -> u64 {
        self.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub sequence: u64,
    pub ticks: Option<u64>,
    pub severity: u8,
    pub flags: u32,
    pub source: [u8; 16],
    pub source_len: usize,
    pub message: [u8; MAX_MESSAGE],
    pub len: usize,
}
impl Record {
    pub fn source(&self) -> &[u8] {
        &self.source[..self.source_len]
    }
    pub fn text(&self) -> &[u8] {
        &self.message[..self.len]
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Read {
    pub record: Option<Record>,
    pub next: u64,
    pub oldest: u64,
    pub end: u64,
    pub lost: u64,
    pub producer_dropped: u64,
}
pub fn request(cursor: Cursor) -> [u8; FRAME_BYTES] {
    let mut b = [0; FRAME_BYTES];
    b[..4].copy_from_slice(&1u32.to_le_bytes());
    b[8..16].copy_from_slice(&cursor.0.to_le_bytes());
    b
}
pub fn decode(b: &[u8; FRAME_BYTES]) -> Result<Read, i64> {
    let u64_at = |at| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let u32_at = |at| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    if u32_at(0) != 1 || u32_at(4) > 1 || b[568..].iter().any(|&b| b != 0) {
        return Err(-22);
    }
    let (next, oldest, end, lost, producer_dropped) =
        (u64_at(8), u64_at(16), u64_at(24), u64_at(32), u64_at(40));
    if oldest == 0 || oldest > end || next < oldest || next > end {
        return Err(-22);
    }
    let record = if u32_at(4) == 1 {
        let source_len = b[69] as usize;
        let len = u16::from_le_bytes(b[70..72].try_into().unwrap()) as usize;
        let sequence = u64_at(48);
        if source_len > 16
            || len > MAX_MESSAGE
            || b[68] > 7
            || u32_at(64) & !31 != 0
            || sequence < oldest
            || sequence >= end
            || sequence + 1 != next
        {
            return Err(-22);
        }
        let mut source = [0; 16];
        source.copy_from_slice(&b[72..88]);
        let mut message = [0; MAX_MESSAGE];
        message.copy_from_slice(&b[88..568]);
        Some(Record {
            sequence,
            ticks: if u64_at(56) == u64::MAX {
                None
            } else {
                Some(u64_at(56))
            },
            severity: b[68],
            flags: u32_at(64),
            source,
            source_len,
            message,
            len,
        })
    } else {
        None
    };
    Ok(Read {
        record,
        next,
        oldest,
        end,
        lost,
        producer_dropped,
    })
}
