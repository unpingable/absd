//! The object kind word of a file server's attribute record (SPEC A13,
//! A21). The server encodes exactly two kinds, 1 file and 2 directory
//! (fsd/src/server.rs attr_bytes); a word outside those is never read as
//! either. Every runtime consumer of one object refuses it with -5 (EIO,
//! the C route's answer); a directory listing alone marks such an entry
//! unknown ([`entry_word`]) so one entry neither converts nor makes the
//! directory unreadable. Dependency-free so the host test
//! (tests/runtime_wire_kind.rs) includes it as is.

/// The two kinds a file server reply may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireKind {
    File,
    Dir,
}

/// The refusal of a kind word outside 1..=2: EIO.
pub(crate) const UNKNOWN_KIND: i64 = -5;

/// `word` as a kind, or [`UNKNOWN_KIND`].
pub(crate) fn decode(word: u32) -> Result<WireKind, i64> {
    match word {
        1 => Ok(WireKind::File),
        2 => Ok(WireKind::Dir),
        _ => Err(UNKNOWN_KIND),
    }
}

/// The kind of an attribute record: its first little-endian half-word.
/// A record too short to hold one is refused like an unknown kind.
pub(crate) fn of_attr(attr: &[u8]) -> Result<WireKind, i64> {
    let word = attr.get(..4).ok_or(UNKNOWN_KIND)?;
    decode(u32::from_le_bytes(word.try_into().unwrap()))
}

/// The kind word `RawAttr` carries to std and the C kit.
pub(crate) fn word(kind: WireKind) -> u32 {
    match kind {
        WireKind::File => 1,
        WireKind::Dir => 2,
    }
}

/// The kind word of a listing entry whose kind is unknown: neither file
/// nor directory (the C kit's DT_UNKNOWN, std's unknown entry).
pub(crate) const ENTRY_UNKNOWN: u32 = 0;

/// The readdir route only: an entry's kind word, [`ENTRY_UNKNOWN`] for a
/// kind outside 1..=2. Nothing else may use this; stat and fstat refuse.
pub(crate) fn entry_word(attr: &[u8]) -> u32 {
    match of_attr(attr) {
        Ok(kind) => word(kind),
        Err(_) => ENTRY_UNKNOWN,
    }
}
