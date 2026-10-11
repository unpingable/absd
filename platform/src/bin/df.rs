#![feature(restricted_std)]
//! `df`: the space of the filesystem behind this session, as the file
//! server's format counts it (data blocks, blocks in use by the committed
//! image or by accepted changes, free blocks; metadata lives in reserved
//! regions outside them), then the mounts this session's binding sees and
//! whether each is writable here. Every mount is a view of the same one
//! filesystem, and every session shares its space: there are no quotas.
//! Needs the file server: a process with its own block handle, or none,
//! is refused.

fn refusal(code: i64) -> &'static str {
    match code {
        -2 => "this process has no file server channel",
        -11 => "this process's channel is lent to a running child",
        -13 => "the file server refused this channel",
        _ => "the file server request failed",
    }
}

fn main() {
    absd_runtime::link_anchor();
    if std::env::args().len() > 1 {
        eprintln!("df: usage: df");
        std::process::exit(2);
    }
    let result = absd_runtime::fsd::space().and_then(|space| Ok((space, absd_runtime::fsd::mounts()?)));
    let (space, mut mounts) = match result {
        Ok(found) => found,
        Err(code) => {
            eprintln!("df: {} ({code})", refusal(code));
            std::process::exit(1);
        }
    };
    let kib = |blocks: u32| u64::from(blocks) * u64::from(space.block_bytes) / 1024;
    let used = space.data_blocks - space.free_blocks;
    let percent = (u64::from(used) * 100).div_ceil(u64::from(space.data_blocks.max(1)));
    println!("Filesystem        1K-blocks      Used Available Use% Commit");
    println!(
        "absd:{:016x} {:>9} {:>9} {:>9} {:>3}% {}",
        space.filesystem_id,
        kib(space.data_blocks),
        kib(used),
        kib(space.free_blocks),
        percent,
        space.commit
    );
    mounts.sort_by(|a, b| a.path.cmp(&b.path));
    println!("Mounted on        Access");
    for mount in mounts {
        println!("{:<17} {}", String::from_utf8_lossy(&mount.path), if mount.writable { "rw" } else { "ro" });
    }
}
