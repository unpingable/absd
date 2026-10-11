#![feature(restricted_std)]
//! `sync`: returns once the file server has committed every change it has
//! accepted, from every session, and flushed the device: a durability
//! barrier for what was already written. Without it the server commits
//! when a written file is closed, when a session ends, and at most about
//! 200 ms after an unsynced write. It orders nothing still in flight in
//! another process. `sync -v` prints the commit sequence now on the
//! device. Needs the file server.

fn main() {
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verbose = match args.as_slice() {
        [] => false,
        [flag] if flag == "-v" => true,
        _ => {
            eprintln!("sync: usage: sync [-v]");
            std::process::exit(2);
        }
    };
    match absd_runtime::fsd::commit() {
        Ok(sequence) if verbose => println!("commit {sequence}"),
        Ok(_) => {}
        Err(code) => {
            let reason = match code {
                -2 => "this process has no file server channel",
                -11 => "this process's channel is lent to a running child",
                -13 => "the file server refused this channel",
                _ => "the file server could not commit",
            };
            eprintln!("sync: {reason} ({code})");
            std::process::exit(1);
        }
    }
}
