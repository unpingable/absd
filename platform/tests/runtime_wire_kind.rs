//! SPEC A13/A21 (R12): a file server attribute record whose kind word is
//! outside 1..=2 is refused with -5 by the runtime's one kind decoder,
//! which stat_kind, remote_attr (the std and C hooks' stat and fstat) and
//! read_file_into all go through; a directory listing entry of such a kind
//! is marked unknown (0) by entry_word, the readdir hook's alone, and the
//! listing goes on. scripts/check-fs-kinds.py holds that those sites call
//! them. Records are built as the server's
//! attr_bytes lays them out: kind u32, readonly u32, size, filesystem,
//! serial, links, mtime (u64 each, little-endian; 48 bytes).

#[path = "../runtime/src/wire_kind.rs"]
mod wire_kind;

use wire_kind::{ENTRY_UNKNOWN, UNKNOWN_KIND, WireKind, decode, entry_word, of_attr, word};

fn record(kind: u32) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes[..4].copy_from_slice(&kind.to_le_bytes());
    bytes[8..16].copy_from_slice(&7u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&1u64.to_le_bytes());
    bytes
}

#[test]
fn known_kinds_decode_as_themselves() {
    assert_eq!(UNKNOWN_KIND, -5);
    assert_eq!(decode(1), Ok(WireKind::File));
    assert_eq!(decode(2), Ok(WireKind::Dir));
    assert_eq!(of_attr(&record(1)), Ok(WireKind::File));
    assert_eq!(of_attr(&record(2)), Ok(WireKind::Dir));
}

#[test]
fn unknown_kinds_are_refused_never_classified() {
    for kind in [0, 3, 4, 0x100, 0x0002_0000, u32::MAX] {
        assert_eq!(decode(kind), Err(-5), "kind {kind}");
        assert_eq!(of_attr(&record(kind)), Err(-5), "record kind {kind}");
    }
}

#[test]
fn only_the_low_half_word_is_the_kind() {
    // readonly = 2 in the next word must not make kind 0 a directory
    let mut bytes = record(0);
    bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(of_attr(&bytes), Err(-5));
}

#[test]
fn a_record_too_short_for_a_kind_is_refused() {
    assert_eq!(of_attr(&[]), Err(-5));
    assert_eq!(of_attr(&[1, 0, 0]), Err(-5));
}

#[test]
fn known_kinds_keep_their_word() {
    assert_eq!(word(WireKind::File), 1);
    assert_eq!(word(WireKind::Dir), 2);
    assert_eq!(entry_word(&record(1)), 1);
    assert_eq!(entry_word(&record(2)), 2);
}

#[test]
fn an_unknown_listing_entry_is_marked_never_converted() {
    assert_eq!(ENTRY_UNKNOWN, 0);
    for kind in [0, 3, 4, 0x100, 0x0002_0000, u32::MAX] {
        let marked = entry_word(&record(kind));
        assert_eq!(marked, ENTRY_UNKNOWN, "entry kind {kind}");
        assert!(marked != 1 && marked != 2, "entry kind {kind} became a file or directory");
        // the same record for one object is still refused
        assert_eq!(of_attr(&record(kind)), Err(-5), "object kind {kind}");
    }
    assert_eq!(entry_word(&[]), ENTRY_UNKNOWN);
}
