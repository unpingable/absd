#![feature(restricted_std)]
//! `date`: ordinary software civil time and explicit source/age status.
//! The paired kernel separates this anchor from raw RTC and monotonic ticks.

use absd_fsd::civil::Utc;

fn main() {
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut epoch = false;
    let mut status = false;
    for arg in &args {
        match arg.as_str() {
            "-u" => {}
            "+%s" => epoch = true,
            "--status" => status = true,
            _ => {
                eprintln!(
                    "date: usage: date [-u] [+%s] [--status] (use shell clock set EPOCH for authorized changes)"
                );
                std::process::exit(2);
            }
        }
    }
    if status {
        match absd_runtime::civil_clock::info() {
            Ok(i) => println!(
                "{} boot_only=yes",
                i.status(absd_runtime::hardware_rtc_seconds())
            ),
            Err(e) => {
                eprintln!("date: clock status refused ({e})");
                std::process::exit(1);
            }
        }
        if !epoch {
            return;
        }
    }
    match absd_runtime::wall_clock_seconds() {
        Ok(seconds) if epoch => println!("{seconds}"),
        Ok(seconds) => println!("{}", Utc::from_unix(seconds)),
        Err(code) => {
            eprintln!("date: the kernel gives no usable software civil time (error {code})");
            std::process::exit(1);
        }
    }
}
