#![feature(restricted_std)]
//! Boot-scoped retained kernel diagnostics, without a file-server dependency.
#[path = "../dmesg_format.rs"]
mod format;
use absd_runtime::kernel_log::{self, Cursor, EMERGENCY, INFERRED, LOSS, PARTIAL, TRUNCATED};
use std::io::{self, Write};
fn usage() -> ! {
    eprintln!(
        "usage: dmesg [-w|--follow] [--level LEVEL] [--source SOURCE] [--since SEQUENCE]\nlevels: emerg alert crit err warn notice info debug (includes more severe)"
    );
    std::process::exit(2)
}
fn main() {
    absd_runtime::link_anchor();
    let (mut follow, mut ceiling, mut source, mut cursor) = (false, 7, None, Cursor::new());
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-w" | "--follow" => follow = true,
            "--level" => {
                ceiling = args
                    .next()
                    .and_then(|n| format::level(&n))
                    .unwrap_or_else(|| usage())
            }
            "--source" => source = Some(args.next().unwrap_or_else(|| usage()).into_bytes()),
            "--since" => {
                cursor = Cursor::at(
                    args.next()
                        .and_then(|n| n.parse::<u64>().ok())
                        .unwrap_or_else(|| usage()),
                )
            }
            _ => usage(),
        }
    }
    let boot = match absd_runtime::boot_id() {
        Ok(id) => id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        Err(_) => "unknown".into(),
    };
    let mut out = io::stdout().lock();
    if writeln!(
        out,
        "# kernel log boot={boot} (sequences and ticks scoped to this boot)"
    )
    .is_err()
    {
        return;
    }
    let (mut snapshot_end, mut dropped, mut first) = (None, 0, true);
    loop {
        let read = match kernel_log::read(&mut cursor) {
            Ok(r) => r,
            Err(-11) => {
                absd_runtime::sleep_ticks(10);
                continue;
            }
            Err(code) => {
                eprintln!("dmesg: kernel log read refused ({code})");
                std::process::exit(1)
            }
        };
        let end = *snapshot_end.get_or_insert(read.end);
        if first
            && read.oldest > 1
            && read.lost == 0
            && writeln!(
                out,
                "# retained history begins at sequence {}; earlier records overwritten",
                read.oldest
            )
            .is_err()
        {
            return;
        }
        if read.lost != 0
            && writeln!(
                out,
                "# lost {} overwritten records; retained oldest={}",
                read.lost, read.oldest
            )
            .is_err()
        {
            return;
        }
        if read.producer_dropped != dropped {
            dropped = read.producer_dropped;
            if writeln!(
                out,
                "# producer contention drops={dropped} (bytes or complete emit attempts)"
            )
            .is_err()
            {
                return;
            }
        }
        first = false;
        if let Some(record) = read.record {
            if !follow && record.sequence >= end {
                return;
            }
            // A damaged fragment may have lost its original severity prefix.
            // Never hide that loss merely because its fallback level is info.
            if (record.severity <= ceiling || record.flags & LOSS != 0)
                && source.as_ref().is_none_or(|s| s == record.source())
            {
                let ticks = record.ticks.map_or_else(|| "?".into(), |n| n.to_string());
                let flags = format!(
                    "{}{}{}{}{}",
                    if record.flags & TRUNCATED != 0 {
                        " truncated"
                    } else {
                        ""
                    },
                    if record.flags & PARTIAL != 0 {
                        " partial"
                    } else {
                        ""
                    },
                    if record.flags & EMERGENCY != 0 {
                        " emergency"
                    } else {
                        ""
                    },
                    if record.flags & INFERRED != 0 {
                        " inferred"
                    } else {
                        ""
                    },
                    if record.flags & LOSS != 0 {
                        " damaged"
                    } else {
                        ""
                    }
                );
                if writeln!(
                    out,
                    "{} ticks={} {} {}{}: {}",
                    record.sequence,
                    ticks,
                    format::LEVELS[record.severity as usize],
                    format::safe_text(record.source()),
                    flags,
                    format::safe_text(record.text())
                )
                .is_err()
                {
                    return;
                }
            }
        }
        if out.flush().is_err() {
            return;
        }
        if !follow && read.next >= end {
            return;
        }
        if read.next >= read.end {
            absd_runtime::sleep_ticks(100);
        }
    }
}
