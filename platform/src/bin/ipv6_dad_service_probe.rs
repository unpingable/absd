#![feature(restricted_std)]
//! Sole NIC owner for fixed static DAD then delegated bounded DNS.
use absd_net::{
    NicLink,
    ipv6::{
        channel::KernelPipe,
        dad::{self, Owner, Policy},
    },
};
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};
struct Handle(u64);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _ = absd_runtime::close(self.0);
        }
    }
}
impl Handle {
    fn take(mut self) -> u64 {
        let h = self.0;
        self.0 = 0;
        h
    }
}

fn sys(n: u64, a: u64, b: u64, c: u64) -> i64 {
    let out: i64;
    unsafe {
        core::arch::asm!("int 0x80", inlateout("rax") n=>out,
        in("rdi") a, in("rsi") b, in("rdx") c, options(nostack,preserves_flags));
    }
    out
}
fn pipe() -> Result<(Handle, Handle), String> {
    let both = sys(16, 0, 0, 0);
    if both < 0 {
        return Err(format!("pipe {both}"));
    }
    let both = Handle(both as u64);
    let reader =
        Handle(absd_runtime::duplicate(both.0, RIGHT_READ).map_err(|e| format!("reader {e}"))?);
    let writer =
        Handle(absd_runtime::duplicate(both.0, RIGHT_WRITE).map_err(|e| format!("writer {e}"))?);
    Ok((reader, writer))
}

fn budget(until: u64, last: &mut u64) -> Result<u64, String> {
    let now = absd_runtime::boot_millis();
    if now < *last || now >= until {
        return Err("original invocation budget".into());
    }
    *last = now;
    Ok(until - now)
}
fn run() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let until = start.checked_add(dad::TOTAL_MS).ok_or("clock overflow")?;
    absd_runtime::link_anchor();
    let link = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let mut owner = Owner::acquire(link, Policy::fixture(), start, getrandom_0_2::getrandom)
        .map_err(|e| format!("DAD acquisition refused {e:?}"))?;
    owner.start_dns().map_err(|e| format!("DAD grant {e:?}"))?;
    println!("IPV6 DAD CLEAR local=fd00:ab5d::15 scope=1 auth=none uniqueness=unproven");
    let result = run_child(&mut owner, until, start);
    owner.retire();
    let last = result?;
    let mut last = last;
    budget(until, &mut last)?;
    if owner.socket_count() != 0 {
        return Err("retained socket".into());
    }
    let counts = owner.observations();
    println!(
        "IPV6 DAD SERVICE PASS child=exited sockets=0 probes={} defenses={} received={} malformed={}",
        counts.probes_submitted,
        counts.defenses_submitted,
        counts.received_frames,
        counts.malformed
    );
    Ok(())
}
fn run_child(owner: &mut Owner<NicLink>, until: u64, mut last: u64) -> Result<u64, String> {
    let image = include_bytes!(env!("ABSD_IPV6_DAD_CLIENT_ELF"));
    let (child_in, parent_out) = pipe()?;
    let (parent_in, child_out) = pipe()?;
    let (result_reader, result_writer) = pipe()?;
    let (startup_reader, startup_writer) = pipe()?;
    let copies = [
        [startup_reader.0, RIGHT_READ, 0],
        [child_in.0, RIGHT_READ, 0],
        [child_out.0, RIGHT_WRITE, 0],
        [result_writer.0, RIGHT_WRITE, 0],
        [child_out.0, RIGHT_WRITE, 1],
    ];
    let mut record = [0; absd_broker::MAX_STARTUP];
    let n = absd_broker::encode_startup(
        &[
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDOUT, 2),
            (absd_broker::role::STDERR, 3),
        ],
        core::iter::empty::<&[u8]>(),
        core::iter::empty::<&[u8]>(),
        b"/",
        b"ipv6-dad-dns-client",
        copies.len(),
        &mut record,
    )
    .map_err(|e| format!("startup {e:?}"))?;
    budget(until, &mut last)?;
    owner
        .check()
        .map_err(|e| format!("DAD before spawn {e:?}"))?;
    let req = [
        image.as_ptr() as u64,
        image.len() as u64,
        copies.as_ptr() as u64,
        copies.len() as u64,
    ];
    let process = spawn_image_raw(req.as_ptr() as u64, SPAWN_NO_SPAWN, 0);
    drop((startup_reader, child_in, child_out, result_writer));
    if process < 0 {
        return Err(format!("spawn {process}"));
    }
    let mut process = Handle(process as u64);
    let result = (|| {
        budget(until, &mut last)?;
        owner
            .check()
            .map_err(|e| format!("DAD after spawn {e:?}"))?;
        let r = absd_runtime::write_within(
            startup_writer.0,
            &record[..n],
            budget(until, &mut last)?.min(1000),
        );
        budget(until, &mut last)?;
        owner
            .check()
            .map_err(|e| format!("DAD after startup {e:?}"))?;
        r.map_err(|e| format!("startup write {e}"))?;
        drop(startup_writer);
        let bootstrap = owner
            .bootstrap()
            .map_err(|e| format!("DAD bootstrap {e:?}"))?;
        let r = absd_runtime::write_within(
            parent_out.0,
            &bootstrap,
            budget(until, &mut last)?.min(1000),
        );
        budget(until, &mut last)?;
        owner
            .check()
            .map_err(|e| format!("DAD after bootstrap {e:?}"))?;
        r.map_err(|e| format!("bootstrap write {e}"))?;
        let mut io = KernelPipe {
            request_reader: parent_in.take(),
            reply_writer: parent_out.take(),
        };
        let mut result = Vec::new();
        println!("IPV6 DAD SERVICE READY scope=1 udp=7002 peer-port=42010");
        loop {
            budget(until, &mut last)?;
            let live = owner
                .poll(&mut io)
                .map_err(|e| format!("DAD owner {e:?}"))?;
            let mut bytes = [0; 256];
            let read = absd_runtime::read_within(result_reader.0, &mut bytes, 1);
            budget(until, &mut last)?;
            if live {
                owner
                    .check()
                    .map_err(|e| format!("DAD after result read {e:?}"))?;
            }
            match read {
                Ok(n) => {
                    if result.len() + n > 4096 {
                        return Err("result overflow".into());
                    }
                    result.extend_from_slice(&bytes[..n]);
                }
                Err(-110 | -11) => {}
                Err(e) => return Err(format!("result read {e}")),
            }
            let mut outcome = [0u64; 4];
            let waited = sys(
                6,
                process.0,
                outcome.as_mut_ptr() as u64,
                if live { 1 } else { 50 },
            );
            if waited >= 0 {
                process.0 = 0;
            }
            budget(until, &mut last)?;
            if live {
                owner.check().map_err(|e| format!("DAD after wait {e:?}"))?;
            }
            if waited >= 0 {
                loop {
                    budget(until, &mut last)?;
                    let r = absd_runtime::read_within(result_reader.0, &mut bytes, 1);
                    budget(until, &mut last)?;
                    if live {
                        owner
                            .check()
                            .map_err(|e| format!("DAD during terminal drain {e:?}"))?;
                    }
                    match r {
                        Ok(0) | Err(-110 | -11) => break,
                        Ok(n) if result.len() + n <= 4096 => result.extend_from_slice(&bytes[..n]),
                        _ => return Err("result drain".into()),
                    }
                }
                let text = String::from_utf8_lossy(&result);
                if outcome[0] != 1
                    || outcome[1] != 0
                    || !text.contains("IPV6 DAD DNS A PASS")
                    || !text.contains("IPV6 DAD DNS AAAA PASS")
                    || !text.contains("IPV6 DAD CLIENT AUTHORITY PASS")
                {
                    return Err(format!("child status {}", outcome[1]));
                }
                print!("{text}");
                return Ok(last);
            }
            if !live {
                return Err("channel retired before child exit".into());
            }
            if waited != -110 {
                return Err(format!("wait {waited}"));
            }
            owner.wait().map_err(|e| format!("DAD wait {e:?}"))?;
        }
    })();
    owner.retire();
    if process.0 != 0 {
        let killed = sys(20, process.0, 0, 0);
        let mut outcome = [0u64; 4];
        let waited = sys(
            6,
            process.0,
            outcome.as_mut_ptr() as u64,
            if killed >= 0 { 0 } else { 1 },
        );
        if waited >= 0 {
            process.0 = 0;
        }
        if killed < 0 || waited < 0 {
            return Err(format!("child cleanup kill={killed} wait={waited}"));
        }
    }
    result
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("IPV6 DAD SERVICE ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
