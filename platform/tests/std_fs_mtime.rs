//! Exact std metadata conversion and time PAL extracted from the pinned patch.
#[allow(dead_code)] mod time_pal { include!(env!("ABSD_TIME_PAL")); }
#[allow(dead_code)] mod absd {
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use super::time_pal::{SystemTime, UNIX_EPOCH};
    fn unsupported<T>() -> io::Result<T> { Err(io::ErrorKind::Unsupported.into()) }
    fn stat(_: &Path) -> io::Result<FileAttr> { Err(error(-5)) }
    include!(env!("ABSD_STD_FS_ITEMS"));
    pub fn metadata(kind: u32, mtime: u64) -> io::Result<FileAttr> {
        FileAttr::try_from(RawAttr { kind, mtime, ..Default::default() })
    }
    pub fn layout() { assert_eq!(core::mem::size_of::<RawAttr>(), 48); assert_eq!(core::mem::offset_of!(RawAttr, mtime), 40); }
}
#[unsafe(no_mangle)] extern "C" fn __absd_std_wall_clock_seconds() -> i64 { panic!("metadata must not read the clock") }
#[unsafe(no_mangle)] extern "C" fn __absd_std_ticks() -> u64 { panic!("metadata must not read ticks") }

#[test] fn std_uses_the_versioned_layout() { absd::layout(); }
#[test] fn zero_is_unsupported_never_the_epoch() {
    assert_eq!(absd::metadata(1, 0).unwrap().modified().unwrap_err().kind(), std::io::ErrorKind::Unsupported);
}
#[test] fn exact_whole_seconds_include_the_maximum_wire_value() {
    for value in [1, 1_800_000_000, u64::MAX] {
        for kind in [1, 2] {
            let time = absd::metadata(kind, value).unwrap().modified().unwrap();
            let d = time.sub_time(&time_pal::UNIX_EPOCH).unwrap();
            assert_eq!(d, std::time::Duration::from_secs(value));
        }
    }
}
#[test] fn metadata_refuses_unknown_kinds_even_with_a_time() {
    for kind in [0, 3, u32::MAX] { assert!(absd::metadata(kind, 1_800_000_000).is_err()); }
}
