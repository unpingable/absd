#![feature(restricted_std)]
//! `sysinfo`: what this machine is, and what it has left, in one screen:
//! the release the file server serves, this boot and its age, the kernel's
//! memory frames, its object census, and the filesystem's space. Every
//! number is a live answer from the kernel (`frame_stats`,
//! `resource_census`, `boot_id`, the tick counter) or the file server
//! (`VERSION`, `SPACE`), except the two ABI generations on the release
//! line, which are this command's own (the runtime checked the kernel's
//! before `main`); nothing is read from a log, and nothing is estimated.
//! A line whose source refuses says so in place, and the exit status is
//! then 1.

use absd_runtime::fsd;

fn kib(count: u64, bytes: u64) -> u64 {
    count * bytes / 1024
}

fn main() {
    absd_runtime::link_anchor();
    if std::env::args().len() > 1 {
        eprintln!("sysinfo: usage: sysinfo");
        std::process::exit(2);
    }
    let mut status = 0;

    let release = if !fsd::active() {
        status = 1;
        "no file server serves this process".to_owned()
    } else {
        match fsd::check_server(0, false) {
            Ok(server) => format!(
                "{} (kernel_abi {}, fsd_protocol {}, fs_format {}, app_abi {})",
                String::from_utf8_lossy(&server.release),
                absd_release::KERNEL_ABI,
                server.fsd_protocol,
                server.fs_format,
                absd_release::APP_ABI
            ),
            Err(refusal) => {
                status = 1;
                refusal.line()
            }
        }
    };
    println!("release: {release}");

    let seconds = absd_runtime::boot_millis() / 1000;
    let boot = match absd_runtime::boot_id() {
        Ok(id) => id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        Err(code) => {
            status = 1;
            format!("unknown (the kernel refused: {code})")
        }
    };
    println!(
        "boot: {boot}, up {} days {:02}:{:02}:{:02} ({} ticks)",
        seconds / 86_400,
        seconds % 86_400 / 3600,
        seconds % 3600 / 60,
        seconds % 60,
        absd_runtime::ticks()
    );

    match absd_runtime::frame_stats() {
        Ok(frames) => println!(
            "memory: {} KiB free, {} KiB allocated ({} + {} frames of {} bytes{})",
            kib(frames.free_frames, frames.frame_bytes),
            kib(frames.allocated_frames, frames.frame_bytes),
            frames.free_frames,
            frames.allocated_frames,
            frames.frame_bytes,
            match frames.allocation_limit {
                Some(limit) => format!(", allocation limit {limit}"),
                None => String::new(),
            }
        ),
        Err(code) => {
            status = 1;
            println!("memory: unknown (the kernel refused: {code})");
        }
    }

    match absd_runtime::resource_census() {
        Ok(census) => println!(
            "kernel: {} process slots, {} handles, {} pipes, {} cells",
            census.processes, census.handles, census.pipes, census.cells
        ),
        Err(code) => {
            status = 1;
            println!("kernel: unknown (the kernel refused: {code})");
        }
    }

    if fsd::active() {
        match fsd::space() {
            Ok(space) => {
                let block = u64::from(space.block_bytes);
                let used = u64::from(space.data_blocks - space.free_blocks);
                let percent = (used * 100).div_ceil(u64::from(space.data_blocks.max(1)));
                println!(
                    "filesystem: absd:{:016x}, {} KiB, {} KiB used ({percent}%), {} KiB free, commit {}",
                    space.filesystem_id,
                    kib(u64::from(space.data_blocks), block),
                    kib(used, block),
                    kib(u64::from(space.free_blocks), block),
                    space.commit
                );
            }
            Err(code) => {
                status = 1;
                println!("filesystem: unknown (the file server refused: {code})");
            }
        }
    } else {
        println!("filesystem: no file server channel");
        status = 1;
    }
    std::process::exit(status);
}
