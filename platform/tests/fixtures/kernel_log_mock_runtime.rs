//! Deterministic substitution for the syscall transport only. The executable
//! under test is the shipped dmesg source and the real frame decoder.
#[path = "../../runtime/src/kernel_log_wire.rs"]
pub mod wire;
pub mod kernel_log {
    pub use crate::wire::*;
    pub fn read(cursor: &mut Cursor) -> Result<Read, i64> {
        if std::env::var_os("LOG_MOCK_DENIED").is_some() {
            return Err(-1);
        }
        let mut b = request(*cursor);
        let scenario = std::env::var("LOG_MOCK_SCENARIO").unwrap_or_default();
        let mut sequence = if cursor.0 == 0 { 1 } else { cursor.0 };
        let (mut oldest, mut end, mut lost, mut dropped) = (1u64, 3u64, 0u64, 0u64);
        if scenario == "loss" {
            if cursor.0 == 0 {
                sequence = 20;
                oldest = 20;
                end = 23;
                dropped = 1;
            } else {
                oldest = 22;
                end = 25;
                lost = oldest.saturating_sub(sequence);
                sequence = sequence.max(oldest);
                dropped = 3;
            }
        } else if scenario == "growth" && sequence >= 2 {
            end = 4;
        } else if std::env::var_os("LOG_MOCK_FOLLOW").is_some() && sequence >= 3 {
            end = 4;
        }
        for (at, n) in [(16, oldest), (24, end), (32, lost), (40, dropped)] {
            b[at..at + 8].copy_from_slice(&n.to_le_bytes());
        }
        if sequence < end {
            b[4] = 1;
            b[8..16].copy_from_slice(&(sequence + 1).to_le_bytes());
            b[48..56].copy_from_slice(&sequence.to_le_bytes());
            b[56..64].copy_from_slice(&u64::MAX.to_le_bytes());
            b[68] = if sequence == 2 { 3 } else { 6 };
            b[69] = 3;
            b[72..75].copy_from_slice(if sequence == 2 { b"ata" } else { b"nic" });
            let message: &[u8] = match sequence {
                1 | 20 => b"early marker",
                2 => b"bad\x1b[2J\ntext",
                22 => b"after gap",
                _ => b"later carrier up",
            };
            if sequence == 22 {
                b[64] = 24;
            }
            b[70..72].copy_from_slice(&(message.len() as u16).to_le_bytes());
            b[88..88 + message.len()].copy_from_slice(message);
        } else {
            b[4] = 0;
            b[8..16].copy_from_slice(&end.to_le_bytes());
        }
        let r = decode(&b)?;
        cursor.0 = r.next;
        Ok(r)
    }
}
pub fn link_anchor() {}
pub fn boot_id() -> Result<[u8; 16], i64> {
    Ok([1; 16])
}
pub fn sleep_ticks(_: u64) {
    std::thread::sleep(std::time::Duration::from_millis(1));
}
