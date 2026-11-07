#[path = "../src/dmesg_format.rs"]
mod format;
#[path = "../runtime/src/kernel_log_wire.rs"]
mod wire;
use wire::*;
#[test]
fn malformed_lengths_and_unsupported_version_are_refused_without_advancing() {
    let mut b = request(Cursor::new());
    assert!(decode(&b).is_err());
    b[16..24].copy_from_slice(&1u64.to_le_bytes());
    b[24..32].copy_from_slice(&2u64.to_le_bytes());
    b[8..16].copy_from_slice(&2u64.to_le_bytes());
    b[4] = 1;
    b[48] = 1;
    b[70..72].copy_from_slice(&481u16.to_le_bytes());
    assert!(decode(&b).is_err());
    b[70..72].copy_from_slice(&1u16.to_le_bytes());
    assert!(decode(&b).is_ok());
    b[0] = 2;
    assert!(decode(&b).is_err());
}
#[test]
fn complete_record_and_loss_metadata_decode() {
    let mut b = request(Cursor::at(8));
    b[4] = 1;
    b[8] = 9;
    b[16] = 8;
    b[24] = 136;
    b[32] = 7;
    b[40] = 3;
    b[48] = 8;
    b[56..64].copy_from_slice(&u64::MAX.to_le_bytes());
    b[64] = (TRUNCATED | PARTIAL | EMERGENCY) as u8;
    b[68] = 4;
    b[69] = 3;
    b[70] = 3;
    b[72..75].copy_from_slice(b"nic");
    b[88..91].copy_from_slice(b"x\ny");
    let r = decode(&b).unwrap();
    assert_eq!((r.lost, r.producer_dropped, r.next), (7, 3, 9));
    let record = r.record.unwrap();
    assert_eq!(record.ticks, None);
    assert_eq!(record.source(), b"nic");
    assert_eq!(record.text(), b"x\ny");
}

#[test]
fn shared_kernel_encoder_golden_decodes() {
    let hex = include_str!("fixtures/kernel-log-v1.hex").trim();
    let mut bytes = [0; FRAME_BYTES];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let read = decode(&bytes).unwrap();
    let record = read.record.unwrap();
    assert_eq!((read.next, read.end, read.oldest), (2, 2, 1));
    assert_eq!(
        (record.sequence, record.ticks, record.flags),
        (1, Some(12), TRUNCATED)
    );
    assert_eq!(record.source(), b"nic");
    assert_eq!(record.text(), b"x\ny");
}

#[test]
fn inferred_and_damaged_flags_decode_and_unknown_bits_refuse() {
    let hex = include_str!("fixtures/kernel-log-v1.hex").trim();
    let mut bytes = [0; FRAME_BYTES];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    bytes[64] = (INFERRED | LOSS) as u8;
    assert_eq!(
        decode(&bytes).unwrap().record.unwrap().flags,
        INFERRED | LOSS
    );
    bytes[64] = 32;
    assert!(decode(&bytes).is_err());
}
