#![feature(restricted_std)]
//! `date [-u] [+%s]`: the time now from the machine's real-time clock, as
//! the kernel reads it (`wall_clock`): whole seconds, and always UTC,
//! because ABSD declares the RTC to hold UTC and has no time zones (`-u`
//! is accepted and changes nothing). `+%s` prints seconds since the Unix
//! epoch instead. Nothing sets the clock and nothing corrects it: under
//! QEMU it starts from the host's UTC time (`-rtc base=utc`); a physical
//! machine's RTC may hold local time or drift, and `date` cannot tell.
//! Exit 1 when the kernel refuses a reading (no stable, valid RTC value):
//! no time is made up.

use absd_fsd::civil::Utc;

fn main() {
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut epoch = false;
    for arg in &args {
        match arg.as_str() {
            "-u" => {}
            "+%s" => epoch = true,
            _ => {
                eprintln!("date: usage: date [-u] [+%s] (setting the clock and other formats are not supported)");
                std::process::exit(2);
            }
        }
    }
    match absd_runtime::wall_clock_seconds() {
        Ok(seconds) if epoch => println!("{seconds}"),
        Ok(seconds) => println!("{}", Utc::from_unix(seconds)),
        Err(code) => {
            eprintln!("date: the kernel gives no real-time clock reading (error {code})");
            std::process::exit(1);
        }
    }
}
