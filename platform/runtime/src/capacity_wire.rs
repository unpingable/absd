//! Read-only observation v1 kind4, independent of per-row process snapshots.
pub const QUERY: u64 = 257;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capacity {
    pub processes: usize,
    pub handles_per_process: usize,
    pub spawn_handles: usize,
    pub pipes: usize,
    pub cells: usize,
}
pub fn decode(bytes: &[u8; 256]) -> Result<Capacity, i64> {
    let word = |at: usize| u64::from_le_bytes(bytes[at * 8..at * 8 + 8].try_into().unwrap());
    let (processes, handles, spawn, pipes, cells) = (word(3), word(4), word(5), word(6), word(7));
    if word(0) != 1
        || word(1) != 4
        || !(1..=256).contains(&processes)
        || !(1..=256).contains(&handles)
        || !(1..=64).contains(&spawn)
        || spawn > handles
        || !(1..=65536).contains(&pipes)
        || !(1..=65536).contains(&cells)
        || bytes[64..].iter().any(|b| *b != 0)
    {
        return Err(-22);
    }
    Ok(Capacity {
        processes: processes as usize,
        handles_per_process: handles as usize,
        spawn_handles: spawn as usize,
        pipes: pipes as usize,
        cells: cells as usize,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_kernel_profile_and_strict_unknowns() {
        let hex = include_str!("../fixtures/capacity-v1.hex").trim();
        let mut frame = [0; 256];
        for (at, out) in frame.iter_mut().enumerate() {
            *out = u8::from_str_radix(&hex[at * 2..at * 2 + 2], 16).unwrap();
        }
        assert_eq!(
            decode(&frame),
            Ok(Capacity {
                processes: 32,
                handles_per_process: 128,
                spawn_handles: 64,
                pipes: 128,
                cells: 32
            })
        );
        for at in [0, 8, 24, 32, 40, 48, 56, 64] {
            let mut bad = frame;
            bad[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert_eq!(decode(&bad), Err(-22));
        }
        // Kind3 remains reserved for NIC candidate observations.
        let mut bad = frame;
        bad[8] = 3;
        assert_eq!(decode(&bad), Err(-22));
    }
}
