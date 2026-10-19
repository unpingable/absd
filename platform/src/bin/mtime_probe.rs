#![feature(restricted_std)]
//! Qualification fixture: exact path/handle/listing mtime and V1 write boundary.
use std::io::ErrorKind;
use std::path::Path;
use std::time::UNIX_EPOCH;

unsafe extern "C" {
    fn __absd_std_fs_stat(path: *const u8, length: usize, out: *mut u8) -> i64;
}

fn seconds(meta: &std::fs::Metadata) -> Result<Option<u64>, String> {
    match meta.modified() {
        Ok(time) => time.duration_since(UNIX_EPOCH).map(|d| Some(d.as_secs())).map_err(|e| e.to_string()),
        Err(error) if error.kind() == ErrorKind::Unsupported => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn check(path: &str, expected: Option<u64>) -> Result<(), String> {
    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if seconds(&metadata)? != expected { return Err(format!("path {path}: {:?} != {expected:?}", seconds(&metadata)?)); }
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if seconds(&file.metadata().map_err(|e| e.to_string())?)? != expected { return Err(format!("handle {path}")); }
    let p = Path::new(path);
    if let (Some(parent), Some(name)) = (p.parent(), p.file_name()) {
        let entry = std::fs::read_dir(parent).map_err(|e| e.to_string())?
            .find_map(|e| e.ok().filter(|e| e.file_name() == name)).ok_or("listing entry missing")?;
        if seconds(&entry.metadata().map_err(|e| e.to_string())?)? != expected { return Err(format!("listing {path}")); }
    }
    for time in [metadata.accessed(), metadata.created()] {
        if time.as_ref().err().map(|e| e.kind()) != Some(ErrorKind::Unsupported) { return Err("access/creation time invented".into()); }
    }
    #[repr(C, align(8))] struct Guard { attr: [u8; 40], tail: [u8; 16] }
    let mut old = Guard { attr: [0; 40], tail: [0xa5; 16] };
    let code = unsafe { __absd_std_fs_stat(path.as_ptr(), path.len(), old.attr.as_mut_ptr()) };
    if code != 0 || old.tail != [0xa5; 16] { return Err(format!("V1 boundary code={code}")); }
    println!("MTIME PATH OK path={path} seconds={} routes=path,handle,entry v1_canary=ok", expected.map(|n| n.to_string()).unwrap_or_else(|| "unknown".into()));
    Ok(())
}

fn direct() -> Result<(), String> {
    absd_runtime::storage::mount(true, true).map_err(|e| format!("mount: {e:?}"))?;
    std::fs::create_dir("/mtime").map_err(|e| e.to_string())?;
    std::fs::write("/mtime/unknown", b"zero").map_err(|e| e.to_string())?;
    check("/mtime/unknown", None)?;
    for value in [1, 1_800_000_000, u64::MAX] {
        absd_runtime::storage::with_fs(|fs| fs.set_clock(Some(value))).ok_or("no direct filesystem")?;
        let path = format!("/mtime/value-{value}");
        std::fs::write(&path, b"known").map_err(|e| e.to_string())?;
        check(&path, Some(value))?;
    }
    // A directory's time is the time its entries changed.
    check("/mtime", Some(u64::MAX))?;
    println!("MTIME DIRECT OK");
    Ok(())
}

fn main() {
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = if args.is_empty() { direct() } else if args.len() == 2 {
        let expected = if args[1] == "unknown" { Ok(None) } else { args[1].parse::<u64>().map(Some).map_err(|e| e.to_string()) };
        expected.and_then(|time| check(&args[0], time))
    } else { Err("usage: mtime_probe [PATH UNIX_SECONDS|unknown]".into()) };
    if let Err(error) = outcome { eprintln!("MTIME FAILED {error}"); std::process::exit(1); }
}
