#![feature(restricted_std)]
//! Pipe-only experimental-v4 consumer; no NIC or spawn authority is passed.
#[path = "../tcp_mtu_delegated_pipe.rs"]
mod observation;
use absd_net::{
    datagram::{
        self,
        channel::{KernelPipe, Pipe},
    },
    stream,
};
use std::{cell::RefCell, rc::Rc};

fn run(ledger: Rc<RefCell<observation::Ledger>>) -> Result<(), String> {
    absd_runtime::link_anchor();
    let (input, output) =
        absd_runtime::startup_stream_handles().ok_or("startup protocol handles absent")?;
    if input == 0
        || output == 0
        || absd_runtime::nic::handle() != 0
        || absd_runtime::nic::info(input).is_ok()
    {
        return Err("initial pipe/NIC authority".into());
    }
    let mut pipe = observation::Observed::new(
        KernelPipe {
            request_reader: input,
            reply_writer: output,
        },
        ledger.clone(),
        false,
    );
    let boot_until = absd_runtime::boot_millis()
        .checked_add(2000)
        .ok_or("bootstrap overflow")?;
    let mut last = absd_runtime::boot_millis();
    let mut boot = [0; 20];
    let mut at = 0;
    while at < boot.len() {
        let now = absd_runtime::boot_millis();
        if now < last || now >= boot_until {
            return Err("bootstrap clock/deadline".into());
        }
        last = now;
        match pipe
            .read(&mut boot[at..])
            .map_err(|e| format!("bootstrap read {e}"))?
        {
            Some(n) if n > 0 => at += n,
            None => {}
            _ => return Err("bootstrap EOF".into()),
        }
    }
    if boot[..5] != *b"MTUD\x01" || !(1..=2).contains(&boot[5]) || boot[6..10] != [198, 51, 100, 2]
    {
        return Err("bootstrap literal".into());
    }
    let child = usize::from(boot[5]);
    if std::env::args().nth(1).as_deref() != Some(if child == 1 { "1" } else { "2" }) {
        return Err("bootstrap/argument logical identity differs".into());
    }
    let phase = if child == 1 { "refusal" } else { "positive" };
    let peer = datagram::Address {
        ip: boot[6..10].try_into().unwrap(),
        port: u16::from_be_bytes(boot[10..12].try_into().unwrap()),
    };
    let until = u64::from_be_bytes(boot[12..20].try_into().unwrap());
    if peer.port != (if child == 1 { 42100 } else { 42101 }) || last >= until {
        return Err("bootstrap grant/deadline".into());
    }
    eprintln!(
        "TCP MTU DELEGATED CHILD_BEGIN v=1 child={child} phase={phase} at_ms={} until_ms={until} nic=0 bootstrap_bytes=20 bootstrap_hex={}",
        absd_runtime::boot_millis(),
        observation::hex(&boot)
    );
    let mut client = stream::Client::new_mtu_refusal(pipe, peer, absd_runtime::sleep_ticks);
    client
        .connect(until)
        .map_err(|e| format!("connect {e:?}"))?;
    eprintln!(
        "TCP MTU DELEGATED CHILD_CONNECTED v=1 child={child} phase={phase} at_ms={}",
        absd_runtime::boot_millis()
    );
    let mut answer = [0; 64];
    if child == 1 {
        let body: [u8; 1024] = core::array::from_fn(|i| (i % 251) as u8);
        if client
            .write(&body, until)
            .map_err(|e| format!("write {e:?}"))?
            != body.len()
        {
            return Err("partial negative write".into());
        }
        eprintln!(
            "TCP MTU DELEGATED CHILD_QUEUED v=1 child=1 phase=refusal at_ms={} bytes=1024",
            absd_runtime::boot_millis()
        );
        loop {
            match client.read(&mut answer, until) {
                Err(stream::Error::Again) => absd_runtime::sleep_ticks(1),
                Err(stream::Error::FragmentationNeeded { mtu: 576 }) => break,
                other => return Err(format!("negative read {other:?}")),
            }
        }
        eprintln!(
            "TCP MTU DELEGATED CHILD_REFUSED v=1 child=1 phase=refusal at_ms={} code=17 mtu=576 effects=unknown",
            absd_runtime::boot_millis()
        );
        let before = ledger.borrow().counts();
        if client.read(&mut answer, until) != Err(stream::Error::Stale)
            || client.write(&body, until) != Err(stream::Error::Stale)
        {
            return Err("fenced child client revived".into());
        }
        let after = ledger.borrow().counts();
        if before != after {
            return Err("fenced child performed pipe I/O".into());
        }
        eprintln!(
            "TCP MTU DELEGATED CHILD_FENCED v=1 child=1 phase=refusal at_ms={} read_code=8 write_code=8 request_before={} request_after={} reply_before={} reply_after={} reads_before={} reads_after={} writes_before={} writes_after={}",
            absd_runtime::boot_millis(),
            before.request_bytes,
            after.request_bytes,
            before.reply_bytes,
            after.reply_bytes,
            before.read_calls,
            after.read_calls,
            before.write_calls,
            after.write_calls
        );
    } else {
        let body: [u8; 64] = core::array::from_fn(|i| i as u8);
        if client
            .write(&body, until)
            .map_err(|e| format!("positive write {e:?}"))?
            != body.len()
        {
            return Err("partial positive write".into());
        }
        eprintln!(
            "TCP MTU DELEGATED CHILD_QUEUED v=1 child=2 phase=positive at_ms={} bytes=64",
            absd_runtime::boot_millis()
        );
        client
            .shutdown_write(until)
            .map_err(|e| format!("half-close {e:?}"))?;
        client
            .read_exact(&mut answer, until)
            .map_err(|e| format!("echo {e:?}"))?;
        if answer != body {
            return Err("positive echo differs".into());
        }
        eprintln!(
            "TCP MTU DELEGATED CHILD_OBSERVED v=1 child=2 phase=positive at_ms={} bytes=64 hex={}",
            absd_runtime::boot_millis(),
            observation::hex(&answer)
        );
        loop {
            match client.read(&mut answer, until) {
                Err(stream::Error::Again) => absd_runtime::sleep_ticks(1),
                Err(stream::Error::Eof) => break,
                other => return Err(format!("positive EOF {other:?}")),
            }
        }
        eprintln!(
            "TCP MTU DELEGATED CHILD_EOF v=1 child=2 phase=positive at_ms={} code=6",
            absd_runtime::boot_millis()
        );
        // Owner cancellation after the observed FIN/EOF is explicit below;
        // no CLOSE/TIME_WAIT success or global memory-restoration claim.
    }
    drop(client);
    if !ledger.borrow().good() {
        return Err("child pipe ledger refused".into());
    }
    eprintln!(
        "TCP MTU DELEGATED CHILD_DONE v=1 child={child} phase={phase} at_ms={} nic=0",
        absd_runtime::boot_millis()
    );
    Ok(())
}
fn main() {
    let ledger = Rc::new(RefCell::new(observation::Ledger::new()));
    let result = run(ledger.clone());
    // The child number is independently bound by the fixed startup record
    // and parent spawn receipt; this copy uses the program argument only
    // to label an already-completed byte ledger, not to select authority.
    let child = match std::env::args().nth(1).as_deref() {
        Some("1") => 1,
        Some("2") => 2,
        _ => 0,
    };
    ledger.borrow().emit(
        "child",
        child,
        if child == 1 { "refusal" } else { "positive" },
    );
    if let Err(e) = result {
        eprintln!("TCP MTU DELEGATED CHILD_FAIL v=1 child={child} error={e:?}");
        std::process::exit(1);
    }
    if child == 0 {
        std::process::exit(1);
    }
}
