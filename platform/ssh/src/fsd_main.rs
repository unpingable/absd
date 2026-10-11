#![cfg_attr(target_os = "absd", feature(restricted_std))]
//! `absd-fsd`, the file server of an `fsd` durable boot (kernel
//! `docs/PROCESS-STARTUP.md`, "File server"; dispatcher and protocol in the
//! platform's `fsd/` crate). Init starts it without the spawn right, with
//! the only read-write block handle of the boot and the server ends of
//! every channel it minted: channel 0 is the control channel (sshd's), the
//! others are client slots sshd binds to sessions.
//!
//! Before serving it prepares the filesystem with its own authority:
//! `/tmp` and `/home/operator` exist, and the SSH host key seed
//! `/ssh/host_ed25519_seed` exists (drawn from RDRAND when absent,
//! or when built with `--regenerate-host-key`). No session binding can
//! include `/ssh`; sshd's control channel sees `/ssh` and `/bin` read-only.
//! Then it checks the selected release (`/absd/selected` and the record
//! `/releases/<id>/release`, `docs/RELEASE.md`) against its own compiled
//! identity, printing `RELEASE OK release=<id>` or exiting 3 after
//! `RELEASE REFUSED reason=<reason>`, and serves `/bin` and `/share` from
//! that release's tree; no channel ever reaches `/releases` itself.
//!
//! The loop polls every channel with `pipe_info` (there is no wait on
//! many), serves one complete request at a time, and writes replies as the
//! reply pipes have room. It stops, committing, when the control channel's
//! last writer is gone (sshd ended).

#[cfg(target_os = "absd")]
include!("fsd_server.rs");

#[cfg(not(target_os = "absd"))]
fn main() {
    eprintln!("absd-fsd serves an ABSD block device; it does not run elsewhere");
    std::process::exit(2);
}
