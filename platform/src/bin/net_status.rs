#![feature(restricted_std)]
//! Static SSH owner's retained network sample. No NIC or peer operation.
use absd_fsd::net_status::{Carrier, Listener, Origin};

#[path = "../net_status_read.rs"]
mod read;

fn dotted(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn run() -> Result<i32, &'static str> {
    let start = absd_runtime::ticks();
    let boot = absd_runtime::boot_id().map_err(|_| "boot_id_unavailable")?;
    let mut id = [0u8; 32];
    for (i, b) in boot.iter().enumerate() {
        id[i * 2] = b"0123456789abcdef"[(b >> 4) as usize];
        id[i * 2 + 1] = b"0123456789abcdef"[(b & 15) as usize];
    }
    if !absd_runtime::fsd::active() {
        return Err("fsd_absent");
    }
    absd_runtime::fsd::check_server(0, false).map_err(|_| "fsd_refused")?;
    let read::Retained { record, age } = read::acquire(
        std::path::Path::new("/var/log"),
        &id,
        start,
        absd_runtime::ticks,
    )?;
    println!("network: retained owner sample (record_for_current_boot)");
    println!(
        "lifetime: boot:{}/recovery:{}",
        std::str::from_utf8(&id).expect("hex"),
        record.recovery
    );
    println!(
        "sample: ticks {}..{} age={} ticks",
        record.start, record.end, age
    );
    println!(
        "policy: heartbeat={} stale_after={} ticks (retained; not liveness)",
        absd_fsd::net_status::PERIOD_TICKS,
        absd_fsd::net_status::MAX_AGE_TICKS
    );
    println!(
        "configured: {}/{} gateway={} port={} origin={}",
        dotted(record.address),
        record.prefix,
        record.gateway.map_or_else(|| "none".to_string(), dotted),
        record.port,
        match record.origin {
            Origin::Defaults => "built-in defaults",
            Origin::File => "/etc/network.conf",
        }
    );
    println!(
        "device: carrier={} disabled={}",
        match record.carrier {
            Carrier::Unknown => "unknown",
            Carrier::Down => "down",
            Carrier::Up => "up",
        },
        match record.disabled {
            None => "unknown",
            Some(false) => "false",
            Some(true) => "true",
        }
    );
    println!(
        "listener: {} (local sample; reachability not established)",
        match record.listener {
            Listener::Listening => "listening",
            Listener::Fault => "fault pending",
            Listener::Draining => "draining",
        }
    );
    Ok(if record.carrier == Carrier::Unknown {
        1
    } else {
        0
    })
}

fn main() {
    absd_runtime::link_anchor();
    if std::env::args().len() != 1 {
        eprintln!("net-status: usage: net-status");
        std::process::exit(2);
    }
    let status = match run() {
        Ok(status) => status,
        Err(reason) => {
            println!("net-status: unavailable ({reason})");
            1
        }
    };
    std::process::exit(status);
}
