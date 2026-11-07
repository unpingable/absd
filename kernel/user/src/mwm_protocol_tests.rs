#[path = "mwm_protocol.rs"]
mod protocol;

use protocol::{AckReader, parse_info, rectangle, wait_ack_with};

fn transport(chunks: &[&[u8]]) -> impl FnMut(&mut [u8], u64) -> Result<usize, &'static str> {
    let mut chunks = std::collections::VecDeque::from_iter(chunks.iter().copied());
    move |buffer, _| {
        let Some(bytes) = chunks.pop_front() else {
            return Err("timeout");
        };
        let count = bytes.len().min(buffer.len());
        buffer[..count].copy_from_slice(&bytes[..count]);
        Ok(count)
    }
}

#[test]
fn acknowledgement_requires_exact_bytes_across_fragmentation() {
    let mut reader = AckReader::new();
    assert!(!reader.push(b"G").unwrap());
    assert!(!reader.push(b"O").unwrap());
    assert!(reader.push(b"\n").unwrap());
    assert!(reader.push(b"unexpected").is_err());
    assert!(AckReader::new().push(b"GO\nextra").is_err());
    assert!(AckReader::new().push(b"G\n").is_err());
    let mut incomplete = AckReader::new();
    assert!(!incomplete.push(b"GO").unwrap());
    assert!(incomplete.finish().is_err());
}

#[test]
fn info_requires_the_pinned_geometry_and_reads_generation_state() {
    let mut record = [0u8; 48];
    record[0..4].copy_from_slice(&1024u32.to_le_bytes());
    record[4..8].copy_from_slice(&768u32.to_le_bytes());
    record[8..12].copy_from_slice(&4096u32.to_le_bytes());
    record[12..22].copy_from_slice(&[32, 1, 0, 0, 16, 8, 8, 8, 0, 8]);
    record[24..32].copy_from_slice(&2u64.to_le_bytes());
    record[32..40].copy_from_slice(&7u64.to_le_bytes());
    record[40..48].copy_from_slice(&65_536u64.to_le_bytes());
    let info = parse_info(&record).unwrap();
    assert_eq!((info.generation, info.high_water), (2, 7));
    record[14] = 1;
    assert!(parse_info(&record).is_err());
}

#[test]
fn acknowledgement_reset_creates_one_new_phase_consumer() {
    let mut reader = AckReader::new();
    assert!(reader.push(b"GO\n").unwrap());
    assert!(reader.push(b"GO\n").is_err());
    reader.reset();
    assert!(!reader.push(b"GO").unwrap());
    assert!(reader.push(b"\n").unwrap());
}

#[test]
fn rectangle_is_64_square_direct_color_little_endian() {
    let pixels = rectangle(0x20c080);
    assert_eq!(pixels.len(), 16_384);
    assert!(pixels.chunks_exact(4).all(|pixel| pixel == [0x80, 0xc0, 0x20, 0]));
    let other = rectangle(0xc04040);
    assert_eq!(&other[..4], &[0x40, 0x40, 0xc0, 0]);
    assert_ne!(pixels, other);
}

#[test]
fn transport_rejects_split_pipelined_acknowledgements() {
    let chunks = [b"G".as_slice(), b"O\n".as_slice(), b"GO\n".as_slice()];
    assert!(wait_ack_with(transport(&chunks), || 0, 30_000).is_err());
}

#[test]
fn transport_rejects_trailing_bytes_after_a_valid_acknowledgement() {
    let chunks = [b"GO\n".as_slice(), b"extra".as_slice()];
    assert!(wait_ack_with(transport(&chunks), || 0, 30_000).is_err());
}

#[test]
fn transport_accepts_fragmented_exact_acknowledgement() {
    let chunks = [b"G".as_slice(), b"O".as_slice(), b"\n".as_slice()];
    assert_eq!(wait_ack_with(transport(&chunks), || 0, 30_000), Ok(()));
}

#[test]
fn transport_timeout_is_bounded() {
    let now = std::rc::Rc::new(std::cell::Cell::new(0u64));
    let read_time = now.clone();
    let read = move |_: &mut [u8], ticks: u64| {
        read_time.set(read_time.get() + ticks);
        Err("timeout")
    };
    assert!(wait_ack_with(read, || now.get(), 3).is_err());
    assert_eq!(now.get(), 3);
}
