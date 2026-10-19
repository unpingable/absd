//! Exact generic runtime decoder, both output layouts and bounded writes.
#[path = "../runtime/src/wire_kind.rs"]
mod wire_kind;
include!(env!("ABSD_RUNTIME_ATTR_ITEMS"));

fn record(kind: u32, mtime: u64) -> [u8; 48] {
    let mut b = [0; 48];
    b[..4].copy_from_slice(&kind.to_le_bytes());
    b[4..8].copy_from_slice(&1u32.to_le_bytes());
    for (offset, value) in [(8, 777u64), (16, 0x123456789abcdef0), (24, 901), (32, 1), (40, mtime)] {
        b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    b
}

#[test]
fn both_layouts_are_exact() {
    use core::mem::{align_of, offset_of, size_of};
    assert_eq!((size_of::<RawAttr>(), align_of::<RawAttr>()), (40, 8));
    assert_eq!((size_of::<RawAttrV2>(), align_of::<RawAttrV2>()), (48, 8));
    assert_eq!([offset_of!(RawAttr, kind), offset_of!(RawAttr, readonly), offset_of!(RawAttr, size),
        offset_of!(RawAttr, filesystem), offset_of!(RawAttr, serial), offset_of!(RawAttr, links)], [0,4,8,16,24,32]);
    assert_eq!(offset_of!(RawAttrV2, mtime), 40);
}

#[test]
fn v1_preserves_prefix_and_never_writes_the_next_word() {
    #[repr(C)] struct Guard { attr: RawAttr, tail: [u8; 16] }
    let mut out = Guard { attr: RawAttr::default(), tail: [0xa5; 16] };
    assert_eq!(remote_attr(Ok(record(1, u64::MAX)), &mut out.attr), 0);
    assert_eq!(out.attr, RawAttr { kind: 1, readonly: 1, size: 777, filesystem: 0x123456789abcdef0, serial: 901, links: 1 });
    assert_eq!(out.tail, [0xa5; 16]);
}

#[test]
fn v2_preserves_the_full_time_domain_without_overwriting() {
    #[repr(C)] struct Guard { attr: RawAttrV2, tail: [u8; 16] }
    for time in [0, 1, 1_800_000_000, u64::MAX] {
        let mut out = Guard { attr: RawAttrV2::default(), tail: [0xa5; 16] };
        assert_eq!(remote_attr(Ok(record(2, time)), &mut out.attr), 0);
        assert_eq!((out.attr.kind, out.attr.readonly, out.attr.size, out.attr.filesystem, out.attr.serial, out.attr.links, out.attr.mtime),
                   (2, 1, 777, 0x123456789abcdef0, 901, 1, time));
        assert_eq!(out.tail, [0xa5; 16]);
    }
}

#[test]
fn unknown_kind_and_remote_errors_write_nothing_in_either_version() {
    let mut old = RawAttr { kind: 9, ..Default::default() };
    let mut new = RawAttrV2 { kind: 9, mtime: 99, ..Default::default() };
    let old_before = old; let new_before = new;
    for result in [Ok(record(0, 42)), Ok(record(3, 42)), Ok(record(u32::MAX, 42)), Err(-2), Err(-116)] {
        let expected = result.as_ref().err().copied().unwrap_or(-5);
        assert_eq!(remote_attr(result, &mut old), expected);
        assert_eq!(remote_attr(result, &mut new), expected);
        assert_eq!(old, old_before); assert_eq!(new, new_before);
    }
}

#[test]
fn listing_marks_unknown_and_keeps_the_time() {
    let mut out = RawAttrV2::default();
    entry_attr(&record(3, 1_800_000_000), &mut out);
    assert_eq!((out.kind, out.mtime), (0, 1_800_000_000));
    assert!(wire_kind::decode(out.kind).is_err());
}

#[test]
fn ledger_is_unknown_in_both_versions() {
    let mut old = RawAttr::default(); let mut new = RawAttrV2 { mtime: 99, ..Default::default() };
    ledger_attr(&mut old, false, 17); ledger_attr(&mut new, false, 17);
    assert_eq!(RawAttr::from(new), old); assert_eq!(new.mtime, 0);
}
