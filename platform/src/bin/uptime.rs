#![feature(restricted_std)]
//! `uptime`: how long this boot has run, by the kernel's boot tick counter
//! (PIT channel 0, about 1000.15 ticks a second; it counts delivered timer
//! interrupts, so under emulation it can run slow against real time and
//! it restarts at zero every boot), and which boot this is: the kernel's
//! 16-byte boot identity, drawn once per boot and never the same twice.
//! It is not the real-time clock (see date(1)). There is no load average
//! and no user count.

fn main() {
    absd_runtime::link_anchor();
    if std::env::args().len() > 1 {
        eprintln!("uptime: usage: uptime");
        std::process::exit(2);
    }
    let ticks = absd_runtime::ticks();
    let seconds = absd_runtime::boot_millis() / 1000;
    let boot = match absd_runtime::boot_id() {
        Ok(id) => id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        Err(code) => format!("unknown (the kernel refused: {code})"),
    };
    println!(
        "up {} days {:02}:{:02}:{:02}, {ticks} ticks since boot, boot {boot}",
        seconds / 86_400,
        seconds % 86_400 / 3600,
        seconds % 3600 / 60,
        seconds % 60
    );
}
