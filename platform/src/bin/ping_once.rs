#![feature(restricted_std)]
//! One fixed probe through its startup pipe; no NIC or spawn authority.
use absd_net::echo::{self, KernelPipe};
fn budget(until: u64, last: &mut u64) -> Result<u64, String> {
    let now = absd_runtime::boot_millis();
    if now < *last || now >= until {
        return Err("invocation clock/deadline".into());
    }
    *last = now;
    Ok(until - now)
}
fn run() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let mut until = start
        .checked_add(echo::MAX_LIFETIME_MS)
        .ok_or("deadline overflow")?;
    let mut last = start;
    absd_runtime::link_anchor();
    let (input, output) = absd_runtime::standard_stream_handles();
    let mut bootstrap = [0; 13];
    let mut at = 0;
    while at < bootstrap.len() {
        let n = absd_runtime::read_within(
            input,
            &mut bootstrap[at..],
            budget(until, &mut last)?.min(1000),
        )
        .map_err(|e| format!("bootstrap {e}"))?;
        budget(until, &mut last)?;
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
    until = until.min(u64::from_be_bytes(bootstrap[5..13].try_into().unwrap()));
    budget(until, &mut last)?;
    let peer: [u8; 4] = bootstrap[1..5].try_into().unwrap();
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    let mut request = [echo::VERSION, echo::START, 0, 0, 192, 0, 2, 2];
    let denied =
        echo::transact(&mut pipe, &request, until, &mut last).map_err(|e| format!("denial {e}"))?;
    if denied[2] != echo::Error::Denied.code() {
        return Err("peer authority expanded".into());
    }
    request[4..8].copy_from_slice(&peer);
    let started = echo::transact(&mut pipe, &request, until, &mut last)
        .map_err(|e| format!("START uncertain {e}"))?;
    if started[2] != 0 {
        return Err(format!("START refused {}", started[2]));
    }
    request[1] = echo::OBSERVE;
    let observed = loop {
        let reply = echo::transact(&mut pipe, &request, until, &mut last)
            .map_err(|e| format!("OBSERVE {e}"))?;
        if reply[2] == 0 {
            break echo::decode(&reply, peer).map_err(|e| format!("observation {e:?}"))?;
        }
        if reply[2] != echo::Error::Again.code() {
            return Err(format!("OBSERVE refused {}", reply[2]));
        }
        budget(until, &mut last)?;
        absd_runtime::sleep_ticks(1);
        budget(until, &mut last)?;
    };
    request[1] = echo::CLOSE;
    let closed =
        echo::transact(&mut pipe, &request, until, &mut last).map_err(|e| format!("CLOSE {e}"))?;
    if closed[2] != 0 {
        return Err(format!("CLOSE refused {}", closed[2]));
    }
    budget(until, &mut last)?;
    eprintln!(
        "PING peer=192.0.2.1 identifier={} sequence={} instance={} epoch={} nonce={:016x} boot_rtt_ms={} auth=none denied=1 nic=0 requests=1",
        observed.identifier,
        observed.sequence,
        observed.instance,
        observed.epoch,
        observed.nonce,
        observed.boot_rtt_ms
    );
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("PING REFUSED {error}");
            std::process::ExitCode::from(1)
        }
    }
}
