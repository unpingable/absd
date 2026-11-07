#![feature(restricted_std)]
//! Pipe-only finite refusal child. It never sends a valid START.
#[path = "../echo_boundary.rs"]
mod fixture;
use absd_net::echo::{self, KernelPipe, Pipe};
fn check(last: &mut u64, until: u64) -> Result<u64, String> {
    let now = absd_runtime::boot_millis();
    fixture::clock(last, until, now)?;
    Ok(until - now)
}
fn run() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let mut last = start;
    let mut until = start
        .checked_add(echo::MAX_LIFETIME_MS)
        .ok_or("deadline overflow")?;
    absd_runtime::link_anchor();
    let (input, output) = absd_runtime::standard_stream_handles();
    let mut bootstrap = [0; 13];
    let mut at = 0;
    while at < bootstrap.len() {
        let n = absd_runtime::read_within(
            input,
            &mut bootstrap[at..],
            check(&mut last, until)?.min(1000),
        )
        .map_err(|e| format!("bootstrap {e}"))?;
        check(&mut last, until)?;
        if n == 0 {
            return Err("bootstrap EOF".into());
        }
        at += n;
    }
    if bootstrap[..5] != [1, 192, 0, 2, 1]
        || absd_runtime::nic::handle() != 0
        || absd_runtime::nic::info(input).is_ok()
    {
        return Err("bootstrap/NIC boundary".into());
    }
    until = until.min(u64::from_be_bytes(bootstrap[5..].try_into().unwrap()));
    check(&mut last, until)?;
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    for (index, request) in fixture::REQUESTS.iter().enumerate() {
        let reply = echo::transact(&mut pipe, request, until, &mut last)
            .map_err(|e| format!("exchange {index} {e}"))?;
        if reply != fixture::reply(index) {
            return Err(format!("reply {index}"));
        }
    }
    check(&mut last, until)?;
    if pipe.write(&[0]).map_err(|e| format!("prefix {e}"))? != Some(1) {
        return Err("prefix was not one byte".into());
    }
    check(&mut last, until)?;
    loop {
        absd_runtime::sleep_ticks(1);
        check(&mut last, until)?;
    }
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ECHO BOUNDARY CHILD ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
