#![feature(restricted_std)]
//! Echoes only through the owner's preissued inbound flow capability.
use absd_net::{
    datagram::{self as d, channel::KernelPipe},
    stream::{self as s, server as v},
};
fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let until = absd_runtime::boot_millis()
        .checked_add(8000)
        .ok_or("clock overflow")?;
    let (input, output) = absd_runtime::standard_stream_handles();
    let mut boot = [0; 7];
    let mut at = 0;
    while at < boot.len() {
        let now = absd_runtime::boot_millis();
        if now >= until {
            return Err("startup deadline".into());
        }
        let n = absd_runtime::read_within(input, &mut boot[at..], (until - now).min(1000))
            .map_err(|e| format!("startup {e}"))?;
        if n == 0 {
            return Err("startup EOF".into());
        }
        at += n;
    }
    if boot[0] != v::VERSION
        || absd_runtime::nic::handle() != 0
        || absd_runtime::nic::info(input).is_ok()
    {
        return Err("startup authority".into());
    }
    let peer = d::Address {
        ip: boot[1..5].try_into().unwrap(),
        port: u16::from_be_bytes([boot[5], boot[6]]),
    };
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    let mut wrong = [0; 12];
    wrong[0] = v::VERSION;
    wrong[1] = v::LISTEN;
    wrong[3] = 4;
    wrong[4..8].copy_from_slice(&peer.ip);
    wrong[8..10].copy_from_slice(&peer.port.wrapping_add(1).to_be_bytes());
    let mut reply = [0; d::MAX_MESSAGE];
    let now = absd_runtime::boot_millis();
    let left = until
        .checked_sub(now)
        .filter(|n| *n > 0)
        .ok_or("denial deadline")?;
    let n = v::transact(&mut pipe, &wrong, &mut reply, left.min(1000))
        .map_err(|e| format!("denial {e}"))?;
    if n != 12 || reply[2] != s::Error::Denied.code() {
        return Err("peer authority expanded".into());
    }
    let mut client = v::Client::new(pipe, peer, absd_runtime::sleep_ticks);
    client.accept(until).map_err(|e| format!("accept {e:?}"))?;
    let mut total = 0;
    let mut bytes = [0; 511];
    loop {
        match client.read(&mut bytes, until) {
            Ok(n) => {
                total += n;
                if total > 4096 {
                    return Err("echo bound".into());
                }
                client
                    .write_all(&bytes[..n], until)
                    .map_err(|e| format!("echo {e:?}"))?;
            }
            Err(s::Error::Again) => absd_runtime::sleep_ticks(1),
            Err(s::Error::Eof) => break,
            Err(e) => return Err(format!("read {e:?}")),
        }
    }
    if total != 3072 {
        return Err(format!("echo bytes {total}"));
    }
    client
        .shutdown_write(until)
        .map_err(|e| format!("half-close {e:?}"))?;
    client.close(until).map_err(|e| format!("close {e:?}"))?;
    eprintln!("TCP SERVER ECHO PASS bytes=3072 denied=1 nic=0");
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("TCP SERVER ECHO ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
