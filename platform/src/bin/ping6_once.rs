#![feature(restricted_std)]
//! One fixed diagnostic via the parent's pipe. No NIC or spawn authority.
use absd_net::ipv6::{
    dad,
    echo::{self, KernelPipe},
};
fn budget(until: u64, last: &mut u64) -> Result<u64, String> {
    let now = absd_runtime::boot_millis();
    if now < *last || now >= until {
        return Err("original invocation clock/deadline".into());
    }
    *last = now;
    Ok(until - now)
}
fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    // Parent-issued startup metadata carries the same budget before bootstrap.
    let start: u64 = std::env::var("ABSD_PING6_START_MS")
        .map_err(|_| "start missing")?
        .parse()
        .map_err(|_| "start invalid")?;
    let stop: u64 = std::env::var("ABSD_PING6_STOP_MS")
        .map_err(|_| "stop missing")?
        .parse()
        .map_err(|_| "stop invalid")?;
    let until = start
        .checked_add(dad::TOTAL_MS)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or("deadline overflow")?;
    if stop <= start || stop > until {
        return Err("stop invalid".into());
    }
    let until = until.min(stop);
    let mut last = start;
    budget(until, &mut last)?;
    let (input, output) = absd_runtime::standard_stream_handles();
    if absd_runtime::nic::handle() != 0 || absd_runtime::nic::info(input).is_ok() {
        return Err("NIC authority boundary".into());
    }
    let mut bootstrap = [0; echo::BOOTSTRAP_LEN];
    let mut at = 0;
    while at < bootstrap.len() {
        let n = absd_runtime::read_within(
            input,
            &mut bootstrap[at..],
            budget(until, &mut last)?.min(250),
        )
        .map_err(|e| format!("bootstrap {e}"))?;
        budget(until, &mut last)?;
        if n == 0 {
            return Err("bootstrap EOF".into());
        }
        at += n;
    }
    let (peer, echoed_stop) =
        echo::decode_bootstrap(&bootstrap, last).map_err(|e| format!("bootstrap {e:?}"))?;
    if echoed_stop != stop || bootstrap[24..32] != start.to_be_bytes() {
        return Err("startup/bootstrap disagreement".into());
    }
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    let mut wrong = peer;
    wrong.scope += 1;
    let denied = echo::transact(
        &mut pipe,
        &echo::request(echo::START, wrong),
        until,
        &mut last,
    )
    .map_err(|e| format!("denial {e}"))?;
    if denied[2] != echo::Error::Denied.code() {
        return Err("peer scope authority expanded".into());
    }
    let started = echo::transact(
        &mut pipe,
        &echo::request(echo::START, peer),
        until,
        &mut last,
    )
    .map_err(|e| format!("START uncertain {e}"))?;
    if started[2] != 0 {
        return Err(format!("START refused {}", started[2]));
    }
    let observed = loop {
        let reply = echo::transact(
            &mut pipe,
            &echo::request(echo::OBSERVE, peer),
            until,
            &mut last,
        )
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
    let closed = echo::transact(
        &mut pipe,
        &echo::request(echo::CLOSE, peer),
        until,
        &mut last,
    )
    .map_err(|e| format!("CLOSE {e}"))?;
    if closed[2] != 0 {
        return Err(format!("CLOSE refused {}", closed[2]));
    }
    budget(until, &mut last)?;
    eprintln!("PING6 CLIENT AUTHORITY PASS nic=0 denied=1");
    eprintln!(
        "PING6 OBSERVED peer=fd00:ab5d::2 scope=1 identifier={} sequence={} instance={} epoch={} nonce={:016x} boot_elapsed_ms={} auth=none requests=1",
        observed.identifier,
        observed.sequence,
        observed.instance,
        observed.epoch,
        observed.nonce,
        observed.boot_elapsed_ms
    );
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("PING6 REFUSED {e}");
            std::process::ExitCode::from(1)
        }
    }
}
