//! Private native recovery fixture, never installed by the command catalog.
use std::{io::Write, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
fn main() {
    absd_runtime::link_anchor();
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("unknown") => {
            let path=args.get(2).expect("unknown needs an owned fresh /home/operator/.time-proof-* path");
            assert!(path.starts_with("/home/operator/.time-proof-"));
            let before=absd_runtime::civil_clock::info().expect("civil status");
            assert!(before.unix_ns.is_none(),"fixture requires unknown civil time");
            let now=SystemTime::now();
            let coordinate=now.duration_since(UNIX_EPOCH).expect("bootstrap coordinate");
            assert_eq!(absd_runtime::wall_clock_seconds(),Err(-5));
            let mut file=std::fs::OpenOptions::new().write(true).create_new(true).open(path).expect("fresh owned proof file");
            file.write_all(b"unknown civil time must leave mtime unknown\n").unwrap();
            file.sync_all().unwrap();drop(file);
            let error=std::fs::metadata(path).unwrap().modified().expect_err("unknown mtime must not become bootstrap date");
            assert_eq!(error.kind(),std::io::ErrorKind::Unsupported);
            println!("TIME UNKNOWN SURVIVED bootstrap_ms={} civil_known=false mtime=unknown path={path}",coordinate.as_millis());
        }
        Some("wait") => {
            let before=absd_runtime::civil_clock::info().unwrap();
            let start=Instant::now();let ticks=absd_runtime::ticks();
            println!("TIME WAIT BEGIN generation={} ticks={ticks} duration_ms=2000",before.generation);
            std::io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_millis(2000));
            let elapsed=start.elapsed();let after=absd_runtime::civil_clock::info().unwrap();
            let end=absd_runtime::ticks();
            assert!(after.generation>before.generation,"host must step civil time during the wait");
            assert!(end-ticks>=2000,"timed wait ended before its monotonic deadline");
            assert!(elapsed>=Duration::from_millis(2000));
            println!("TIME WAIT END before_generation={} after_generation={} elapsed_ms={} ticks={}",before.generation,after.generation,elapsed.as_millis(),end-ticks);
        }
        _=>panic!("usage: private time-survival unknown OWNED_PATH | wait"),
    }
}
