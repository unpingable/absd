#![feature(restricted_std)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{ErrorKind, Read, Write};

#[inline(never)]
fn exercise_stack_growth() -> u64 {
    let mut bytes = [0u8; 40 * 1024];
    for index in (0..bytes.len()).step_by(4096) {
        bytes[index] = (index / 4096) as u8;
    }
    std::hint::black_box(&mut bytes);
    (0..bytes.len())
        .step_by(4096)
        .map(|index| bytes[index] as u64)
        .sum()
}

fn exercise_system_allocator() {
    let layout = Layout::from_size_align(96, 4096).unwrap();
    let pointer = unsafe { System.alloc(layout) };
    assert!(!pointer.is_null());
    assert_eq!((pointer as usize) % 4096, 0);
    unsafe {
        pointer.write_bytes(0xa5, layout.size());
        System.dealloc(pointer, layout);
    }
}

fn unsupported(error: std::io::Error) {
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    absd_runtime::link_anchor();

    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args, ["absd-std-probe"]);

    assert_eq!(
        unsafe { absd_runtime::__absd_std_read(std::ptr::null_mut(), 0) },
        0
    );
    assert_eq!(
        unsafe { absd_runtime::__absd_std_write(std::ptr::null(), 0) },
        0
    );
    assert_eq!(std::io::stdin().read(&mut [])?, 0);
    assert_eq!(std::io::stdout().write(&[])?, 0);
    assert_eq!(exercise_stack_growth(), 45);
    exercise_system_allocator();

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let mut eof = [0u8; 1];
    assert_eq!(std::io::stdin().read(&mut eof)?, 0);
    let words: Vec<&str> = input.split_whitespace().collect();
    let boxed = Box::new((input.len(), words.len()));

    let mut large = Vec::with_capacity(24 * 4096);
    for index in 0..24 * 4096 {
        large.push((index % 251) as u8);
    }
    assert_eq!(large.len(), 24 * 4096);
    assert_eq!(large.iter().map(|byte| *byte as u64).sum::<u64>(), 12_280_828);

    let reusable = vec![0x5au8; 8192].into_boxed_slice();
    let first_address = reusable.as_ptr();
    drop(reusable);
    let reused = vec![0xa5u8; 8192].into_boxed_slice();
    assert_eq!(reused.as_ptr(), first_address);
    assert!(reused.iter().all(|byte| *byte == 0xa5));

    unsupported(std::thread::Builder::new().spawn(|| 7).unwrap_err());
    // The filesystem knows exactly one name, `ledger`, and only when the
    // kernel handed this process a block device; this boot has none.
    let not_found = |error: std::io::Error| assert_eq!(error.kind(), ErrorKind::NotFound);
    not_found(std::fs::File::open("not-present").unwrap_err());
    not_found(std::fs::File::open("ledger").unwrap_err());
    unsupported(std::fs::create_dir("not-present").unwrap_err());
    unsupported(std::fs::remove_file("ledger").unwrap_err());
    assert!(std::time::Instant::now().elapsed() < std::time::Duration::from_secs(1));
    // Without broker handles `Command` starts files from the filesystem
    // (kernel docs/PROCESS-STARTUP.md): a bare name has no PATH to search,
    // and this boot mounts no filesystem to read a path from.
    let spawn_error = |path: &str| std::process::Command::new(path).spawn().unwrap_err().kind();
    assert_eq!(spawn_error("not-present"), ErrorKind::InvalidInput);
    assert_eq!(spawn_error("/bin/not-present"), ErrorKind::NotFound);
    unsupported(
        std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, 9)).unwrap_err(),
    );
    assert!(std::env::var_os("ABSD_UNSET").is_none());
    // The working directory is the runtime's: `/` without a startup record.
    assert_eq!(std::env::current_dir()?, std::path::Path::new("/"));
    assert!(std::process::id() > 1);

    let report = format!(
        "args={} bytes={} words={} boxed={}:{} upper={}\n",
        args.len(),
        input.len(),
        words.len(),
        boxed.0,
        boxed.1,
        input.trim_end().to_uppercase(),
    );
    std::io::stdout().write_all(report.as_bytes())?;
    eprintln!("ABSD STD STDERR OK");
    println!("ABSD STD HEAP OK bytes={} reuse=ok", large.len());
    println!("ABSD STD UNSUPPORTED OK thread fs=ledger-only net random=panic");
    println!("ABSD STD PROCESS OK bare=refused unmounted=not-found cwd=/");
    println!("ABSD STD PROBE OK");
    Ok(())
}
