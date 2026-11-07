#![feature(restricted_std)]
//! Finite native wire qualification owner. No delegated child or IPC claim.
#[path = "../echo_wire_fixture.rs"]
mod fixture;
use absd_net::{
    Config, NicLink,
    echo::{self, Owner},
};
use std::{cell::RefCell, rc::Rc};
fn check(last: &mut u64, whole: u64, until: u64) -> Result<u64, String> {
    let now = absd_runtime::boot_millis();
    fixture::clock(last, whole.min(until), now)?;
    Ok(now)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn flush(trace: &Rc<RefCell<fixture::Trace>>, cursor: &mut usize) -> Vec<fixture::Frame> {
    let frames = trace.borrow().frames[*cursor..].to_vec();
    *cursor += frames.len();
    for frame in &frames {
        println!(
            "ECHO WIRE FRAME v=1 direction={} ordinal={} phase={} at_ms={} bytes={} hex={}",
            if frame.tx { "tx" } else { "rx" },
            frame.ordinal,
            if frame.phase == 0 {
                "negative"
            } else {
                "positive"
            },
            frame.at_ms,
            frame.bytes.len(),
            hex(&frame.bytes)
        );
    }
    frames
}
fn run() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let whole = start
        .checked_add(fixture::WHOLE_MS)
        .ok_or("whole overflow")?;
    let negative_until = start
        .checked_add(echo::MAX_LIFETIME_MS)
        .ok_or("negative overflow")?;
    let mut last = start;
    absd_runtime::link_anchor();
    let trace = Rc::new(RefCell::new(fixture::Trace::default()));
    let link = fixture::ReceiptLink {
        inner: NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?,
        trace: trace.clone(),
    };
    let mut owner = Owner::open(
        link,
        Config {
            address: fixture::LOCAL.into(),
            prefix_len: 24,
            gateway: None,
            rx_buffer: 1024,
            tx_buffer: 1024,
        },
    )
    .map_err(|e| format!("owner {e:?}"))?;
    check(&mut last, whole, negative_until)?;
    println!(
        "ECHO WIRE BEGIN v=1 start_ms={start} until_ms={whole} negative_until_ms={negative_until} cases=9"
    );
    let negative = owner
        .grant(fixture::PEER, negative_until, |b| {
            getrandom_0_2::getrandom(b).map_err(|_| -5)
        })
        .map_err(|e| format!("negative grant {e:?}"))?;
    owner
        .start(negative, fixture::PEER)
        .map_err(|e| format!("negative START {e:?}"))?;
    check(&mut last, whole, negative_until)?;
    let mut cursor = 0;
    let mut index = 0;
    while index < fixture::CASES.len() {
        check(&mut last, whole, negative_until)?;
        let polled = owner.poll();
        let frames = flush(&trace, &mut cursor);
        check(&mut last, whole, negative_until)?;
        polled.map_err(|e| format!("negative poll {e:?}"))?;
        let received: Vec<_> = frames
            .iter()
            .filter(|f| !f.tx && f.bytes.get(12..14) != Some(&[8, 6]))
            .collect();
        if received.len() > 1 {
            return Err("multiple selected inputs before case acknowledgement".into());
        }
        if let Some(frame) = received.first() {
            let transcript = trace.borrow();
            let request = transcript.request(0).ok_or("input before actual request")?;
            if frame.phase != 0
                || !fixture::matches_case(request, &frame.bytes, index)
                || transcript.requests(0) != 1
            {
                return Err(format!("unexpected selected frame for case {index}"));
            }
            drop(transcript);
            let result = owner.observe(negative);
            let at = check(&mut last, whole, negative_until)?;
            if result != Err(echo::Error::Again) || owner.socket_count() != 1 {
                return Err(format!("negative observed {index} {result:?}"));
            }
            println!(
                "ECHO WIRE CASE v=1 index={index} case={} receive_ordinal={} at_ms={at} code=5 observations=0 sockets=1 requests=1",
                fixture::CASES[index],
                frame.ordinal
            );
            index += 1;
        }
        if index < fixture::CASES.len() {
            absd_runtime::sleep_ticks(1);
            check(&mut last, whole, negative_until)?;
        }
    }
    owner
        .close(negative)
        .map_err(|e| format!("negative close {e:?}"))?;
    let stale = owner
        .start(negative, fixture::PEER)
        .err()
        .ok_or("negative authority revived")?;
    let at = check(&mut last, whole, negative_until)?;
    if stale != echo::Error::Stale || owner.socket_count() != 0 || trace.borrow().requests(0) != 1 {
        return Err("negative retirement".into());
    }
    println!("ECHO WIRE RETIRED v=1 at_ms={at} stale_code=4 sockets=0 requests=1");
    trace.borrow_mut().phase = 1;
    let positive_start = check(&mut last, whole, whole)?;
    let positive_until = positive_start
        .checked_add(echo::MAX_LIFETIME_MS)
        .ok_or("positive overflow")?;
    if positive_until > whole {
        return Err("fresh positive does not fit whole bound".into());
    }
    let positive = owner
        .grant(fixture::PEER, positive_until, |b| {
            getrandom_0_2::getrandom(b).map_err(|_| -5)
        })
        .map_err(|e| format!("positive grant {e:?}"))?;
    if positive == negative || owner.socket_count() != 1 {
        return Err("positive freshness".into());
    }
    check(&mut last, whole, positive_until)?;
    println!(
        "ECHO WIRE POSITIVE v=1 start_ms={positive_start} until_ms={positive_until} fresh=1 sockets=1"
    );
    owner
        .start(positive, fixture::PEER)
        .map_err(|e| format!("positive START {e:?}"))?;
    check(&mut last, whole, positive_until)?;
    let observed = loop {
        let polled = owner.poll();
        flush(&trace, &mut cursor);
        check(&mut last, whole, positive_until)?;
        polled.map_err(|e| format!("positive poll {e:?}"))?;
        let result = owner.observe(positive);
        check(&mut last, whole, positive_until)?;
        match result {
            Ok(observation) => break observation,
            Err(echo::Error::Again) => {}
            Err(e) => return Err(format!("positive observe {e:?}")),
        }
        absd_runtime::sleep_ticks(1);
        check(&mut last, whole, positive_until)?;
    };
    let at = check(&mut last, whole, positive_until)?;
    if owner.socket_count() != 0 || trace.borrow().requests(1) != 1 {
        return Err("positive one-shot/socket".into());
    }
    println!(
        "ECHO WIRE OBSERVED v=1 at_ms={at} identifier={} sequence={} instance={} epoch={} nonce={:016x} boot_rtt_ms={} auth=none requests=1 sockets=0",
        observed.identifier,
        observed.sequence,
        observed.instance,
        observed.epoch,
        observed.nonce,
        observed.boot_rtt_ms
    );
    owner
        .close(positive)
        .map_err(|e| format!("positive close {e:?}"))?;
    if owner.start(positive, fixture::PEER) != Err(echo::Error::Stale) || owner.socket_count() != 0
    {
        return Err("final stale/socket".into());
    }
    let at = check(&mut last, whole, positive_until)?;
    println!("ECHO WIRE DONE v=1 at_ms={at} sockets=0 negative_cases=9 observations=1");
    check(&mut last, whole, positive_until)?;
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            println!("ECHO WIRE ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
