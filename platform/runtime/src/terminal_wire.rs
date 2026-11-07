//! Private terminal observation schema v1. One Cell value is one coherent size.
//! Zero dimensions are unknown; source 1 is fixed local text, 2 SSH-reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub columns: u32,
    pub rows: u32,
    pub source: u8,
}
pub const LOCAL: u8 = 1;
pub const SSH: u8 = 2;
const LIMIT: u32 = 0xff_ffff;
impl Size {
    pub const fn local_fixed() -> Self { Self { columns: 80, rows: 25, source: LOCAL } }
    pub fn bounded(self) -> Self {
        Self { columns: if self.columns <= LIMIT { self.columns } else { 0 }, rows: if self.rows <= LIMIT { self.rows } else { 0 }, source: self.source }
    }
    pub fn encode(self) -> u64 {
        let columns = if self.columns <= LIMIT { self.columns } else { 0 };
        let rows = if self.rows <= LIMIT { self.rows } else { 0 };
        (1u64 << 56) | ((self.source as u64) << 48) | ((rows as u64) << 24) | columns as u64
    }
    pub fn decode(value: u64) -> Option<Self> {
        let source = (value >> 48) as u8;
        if value >> 56 != 1 || !matches!(source, LOCAL | SSH) { return None; }
        Some(Self { columns: (value & LIMIT as u64) as u32, rows: ((value >> 24) & LIMIT as u64) as u32, source })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn golden_and_unknowns() {
        assert_eq!(Size::local_fixed().encode().to_le_bytes(), [80,0,0,25,0,0,1,1]);
        let ssh = Size { columns: 173, rows: 51, source: SSH };
        assert_eq!(Size::decode(ssh.encode()), Some(ssh));
        assert_eq!(Size::decode(Size { columns: u32::MAX, rows: 0, source: SSH }.encode()), Some(Size { columns: 0, rows: 0, source: SSH }));
        assert_eq!(Size::decode(0), None);
        assert_eq!(Size::decode(3u64 << 48 | 1u64 << 56), None);
    }
}
