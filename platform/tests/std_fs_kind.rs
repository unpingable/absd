//! SPEC A21 (R12): std's FileAttr conversion on ABSD, extracted from
//! patches/rust-1.95.0-absd-std.patch by scripts/check-fs-kinds.py
//! --exercise (ABSD_STD_FS_ITEMS names the extracted items). The kinds a
//! file server encodes (1 file, 2 directory) convert as themselves; any
//! other kind word is an io::Error (the runtime's -5 refusal), so
//! std::fs::metadata, File::metadata and read_dir never report it as a
//! regular file, whatever the runtime passes. A read_dir entry of unknown
//! kind (the runtime marks it 0) stays in the listing: its file_type() is
//! that error and its metadata() is stat of its path (refused, -5).

#[allow(dead_code)]
mod absd {
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};
    include!(env!("ABSD_STD_FS_ITEMS"));

    thread_local! {
        static STATTED: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
    }

    /// The stat hook as the runtime answers an object of unknown kind: -5.
    fn stat(p: &Path) -> io::Result<FileAttr> {
        STATTED.with(|s| s.borrow_mut().push(p.to_path_buf()));
        Err(error(-5))
    }

    pub fn statted() -> Vec<PathBuf> {
        STATTED.with(|s| s.take())
    }

    /// A read_dir entry `name` under `/d` whose hook record carries `kind`.
    pub fn entry(name: &str, kind: u32) -> DirEntry {
        let raw = RawAttr { kind, readonly: 0, size: 7, filesystem: 1, serial: 2, links: 1, mtime: 0 };
        DirEntry { root: PathBuf::from("/d"), name: OsString::from(name), attr: entry_attr(raw) }
    }

    /// std's conversion of a hook's attribute record of kind `kind`.
    pub fn convert(kind: u32) -> io::Result<FileType> {
        let raw = RawAttr { kind, readonly: 0, size: 7, filesystem: 1, serial: 2, links: 1, mtime: 0 };
        FileAttr::try_from(raw).map(|attr| attr.file_type())
    }

    /// The -5 refusal as std reports it.
    pub fn refusal() -> io::Error {
        error(-5)
    }
}

use absd::{convert, entry, refusal, statted};

#[test]
fn known_kinds_convert_as_themselves() {
    let file = convert(1).unwrap();
    assert!(file.is_file() && !file.is_dir() && !file.is_symlink());
    let dir = convert(2).unwrap();
    assert!(dir.is_dir() && !dir.is_file() && !dir.is_symlink());
}

#[test]
fn unknown_kinds_are_an_error_never_a_file() {
    let expected = refusal();
    for kind in [0, 3, 4, 0x100, u32::MAX] {
        let error = convert(kind).err().unwrap_or_else(|| panic!("kind {kind} converted"));
        assert_eq!(error.kind(), expected.kind(), "kind {kind}");
        assert_eq!(error.to_string(), expected.to_string(), "kind {kind}");
    }
}

#[test]
fn known_entries_answer_from_the_listing() {
    let file = entry("f", 1);
    assert!(file.file_type().unwrap().is_file());
    assert!(file.metadata().unwrap().file_type().is_file());
    let dir = entry("sub", 2);
    assert!(dir.file_type().unwrap().is_dir());
    assert!(dir.metadata().unwrap().file_type().is_dir());
    assert!(statted().is_empty());
}

#[test]
fn an_unknown_entry_is_listed_but_never_a_file_or_directory() {
    let expected = refusal();
    for kind in [0, 3, u32::MAX] {
        let unknown = entry("x", kind);
        assert_eq!(unknown.file_name(), "x");
        let error = unknown.file_type().err().unwrap_or_else(|| panic!("entry kind {kind} has a file type"));
        assert_eq!((error.kind(), error.to_string()), (expected.kind(), expected.to_string()), "entry kind {kind}");
        let error = unknown.metadata().err().unwrap_or_else(|| panic!("entry kind {kind} has metadata"));
        assert_eq!((error.kind(), error.to_string()), (expected.kind(), expected.to_string()), "entry kind {kind}");
        assert_eq!(statted(), vec![std::path::PathBuf::from("/d/x")], "entry kind {kind}: metadata is stat of its path");
    }
}
