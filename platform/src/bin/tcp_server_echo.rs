#![feature(restricted_std)]
//! Echoes only through the owner's preissued inbound flow capability.
use absd_net::{
    datagram::{self as d, channel::KernelPipe},
    stream::{self as s, server as v},
};

fn negative(pipe: &mut KernelPipe, peer: d::Address, until: u64) -> Result<(), String> {
    let mut listen = [3, v::LISTEN, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0];
    listen[4..8].copy_from_slice(&peer.ip);
    listen[8..10].copy_from_slice(&peer.port.to_be_bytes());
    let mut requests = [listen; 7];
    requests[0][0] = 1;
    requests[1][3] = 6;
    requests[2][2] = 1;
    requests[3][11] = 1;
    requests[4][1] = s::CONNECT;
    requests[5][1] = s::WRITE;
    requests[5][10..12].copy_from_slice(&1025u16.to_be_bytes()); // Declared length, no body.
    requests[6][8..10].copy_from_slice(&peer.port.wrapping_add(1).to_be_bytes());
    let mut reply = [0; d::MAX_MESSAGE];
    for (index, request) in requests.iter().enumerate() {
        let left = until
            .checked_sub(absd_runtime::boot_millis())
            .filter(|n| *n > 0)
            .ok_or("negative deadline")?;
        let n = v::transact(pipe, request, &mut reply, left.min(1000))
            .map_err(|e| format!("negative transact {e}"))?;
        let mut expected = listen;
        expected[1] = request[1];
        expected[2] = if index == 6 {
            s::Error::Denied.code()
        } else {
            s::Error::Invalid.code()
        };
        if n != 12 || reply[..n] != expected {
            return Err(format!("negative reply {index}"));
        }
    }
    let left = until
        .checked_sub(absd_runtime::boot_millis())
        .filter(|n| *n > 0)
        .ok_or("negative listen deadline")?;
    let n = v::transact(pipe, &listen, &mut reply, left.min(1000))
        .map_err(|e| format!("negative listen {e}"))?;
    let mut expected = [0; 13];
    expected[..12].copy_from_slice(&listen);
    expected[11] = 1;
    if n != 13 || reply[..n] != expected {
        return Err("negative LISTEN reply".into());
    }
    eprintln!("TCP SERVER NEG CHILD v=1 cases=7 listen=1 nic=0");
    let left = until
        .checked_sub(absd_runtime::boot_millis())
        .filter(|n| *n > 0)
        .ok_or("negative partial deadline")?;
    absd_runtime::write_within(pipe.reply_writer, &[0], left.min(50))
        .map_err(|e| format!("negative prefix {e}"))?;
    // The owner must observe the actual byte before interrupting this child.
    while absd_runtime::boot_millis() < until {
        absd_runtime::sleep_ticks(1);
    }
    Err("negative child was not interrupted".into())
}

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
    if std::env::args().nth(1).as_deref() == Some("--boundary-negative") {
        return negative(&mut pipe, peer, until);
    }
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
