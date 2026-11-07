#![feature(restricted_std)]
//! Current NIC observation without borrowing the network owner's frame rights.
use absd_runtime::observation::{self as obs, word};
fn bdf(value: u64) -> String {
    if value == u64::MAX { "unknown".into() } else { format!("{:02x}:{:02x}.{}", value >> 8, (value >> 3) & 31, value & 7) }
}
fn flag(value: u64, yes: &str, no: &str) -> String {
    match value { 0 => no.into(), 1 => yes.into(), _ => "unknown".into() }
}
fn run() -> Result<(), i64> {
    let record = obs::read(256)?;
    let driver = match word(&record, 3) { 1 => "e1000", 2 => "i219", 3 => "rtl8125", _ => "unknown" };
    println!("interface: driver={driver} pci={} initialized={}", bdf(word(&record, 8)), flag(word(&record, 4), "yes", "no"));
    println!("sample: ticks {}..{} (fresh device query)", word(&record, 2), word(&record, 9));
    println!("state: disabled={} carrier={}", flag(word(&record, 5), "yes", "no"), flag(word(&record, 6), "up", "down"));
    if word(&record, 4) != 0 { println!("mac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", record[80], record[81], record[82], record[83], record[84], record[85]); }
    if word(&record, 5) <= 1 {
        println!("rx: delivered={} refused={} missed={}", word(&record, 11), word(&record, 12), word(&record, 13));
        println!("tx: completed={} refused={} errors={}", word(&record, 14), word(&record, 15), word(&record, 16));
    } else {
        println!("rx: unknown (device counters unavailable)");
        println!("tx: unknown (device counters unavailable)");
    }
    println!("negotiated speed/duplex: unknown; jack mapping: unknown (observe peer; PCI order is not jack order)");
    println!("configuration: net-status shows the owner's retained address/route sample; reachability requires a separate exchange");
    if word(&record, 5) == 1 { println!("recovery: driver disabled; cable reconnection does not clear quarantine; inspect dmesg for fault reason"); }
    println!("Ethernet controllers (configuration reads only):");
    for index in 0..256 {
        match obs::read(512 + index) {
            Ok(candidate) => println!("  {} {:04x}:{:04x} rev={:02x} {}", bdf(word(&candidate, 4)), word(&candidate, 5), word(&candidate, 6), word(&candidate, 8), if word(&candidate, 7) == 1 { "selected" } else { "inactive; admission/status unknown" }),
            Err(-2) => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn main() {
    absd_runtime::link_anchor();
    if std::env::args().len() != 1 { eprintln!("usage: interfaces"); std::process::exit(2); }
    if let Err(code) = run() {
        if code == -38 {
            eprintln!("interfaces: unsupported (device queries require UP/BSP execution)");
        } else {
            eprintln!("interfaces: unavailable code={code}");
        }
        std::process::exit(1);
    }
}
