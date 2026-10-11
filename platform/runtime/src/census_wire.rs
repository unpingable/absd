pub(crate) const SYSCALL_NUMBER: u64 = 41;

/// The five little-endian words returned by ABSD syscall 41.
pub(crate) fn decode(bytes: [u8; 40]) -> [u64; 5] {
    let mut words = [0u64; 5];
    for (index, word) in words.iter_mut().enumerate() {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
        *word = u64::from_le_bytes(raw);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::{decode, SYSCALL_NUMBER};

    #[test]
    fn resource_census_matches_cross_repository_vector() {
        assert_eq!(SYSCALL_NUMBER, 41);
        let hex = include_str!("../resource-census.vector").trim().as_bytes();
        assert_eq!(hex.len(), 80);
        let mut bytes = [0u8; 40];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let pair = &hex[index * 2..index * 2 + 2];
            *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        assert_eq!(
            decode(bytes),
            [
                0x0102_0304_0506_0708,
                0x1112_1314_1516_1718,
                0x2122_2324_2526_2728,
                0x3132_3334_3536_3738,
                0x4142_4344_4546_4748,
            ]
        );
    }
}
