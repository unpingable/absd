#![feature(restricted_std)]
//! Native diagnostic consumer. The only network authority is its stdin /
//! stdout endpoint channel; it has neither a NIC nor a spawn grant.
use absd_net::datagram::{
    self as d,
    channel::{KernelPipe, transact},
};

fn request(op: u8, port: u16, bytes: &[u8], capacity: u16) -> Vec<u8> {
    let mut out = vec![1, op, 0, 0];
    out.extend_from_slice(if op == d::SEND {
        &[10, 0, 2, 2]
    } else {
        &[0; 4]
    });
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(
        &(if op == d::SEND {
            bytes.len() as u16
        } else {
            capacity
        })
        .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    out
}

fn run() -> Result<(), i64> {
    absd_runtime::link_anchor();
    let (input, output) = absd_runtime::standard_stream_handles();
    let mut mode = [0; 3];
    let mut at = 0;
    while at < mode.len() {
        let n = absd_runtime::read_within(input, &mut mode[at..], 1000)?;
        if n == 0 {
            return Err(-5);
        }
        at += n;
    }
    let peer_port = u16::from_be_bytes([mode[1], mode[2]]);
    let other_port = if peer_port == 42000 { 42001 } else { 42000 };
    if absd_runtime::nic::handle() != 0 || absd_runtime::nic::info(input).is_ok() {
        return Err(-1);
    }
    if mode[0] == 3 {
        return icmp_case(
            KernelPipe {
                request_reader: input,
                reply_writer: output,
            },
            peer_port,
        );
    }
    if mode[0] != 0 {
        absd_runtime::write_within(output, &[0], 50)?;
        absd_runtime::sleep_ticks(600);
        return Ok(());
    }
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    let mut reply = [0; d::MAX_MESSAGE];
    // Peer expansion is refused before any frame is queued.
    transact(
        &mut pipe,
        &request(d::SEND, other_port, b"ungranted", 0),
        &mut reply,
        1000,
    )?;
    if reply[2] != d::Error::Denied.code() {
        return Err(-1);
    }
    for length in [0, 1, 512, d::MAX_DATAGRAM] {
        let data: Vec<u8> = (0..length)
            .map(|n| (n.wrapping_mul(131) ^ (n >> 7)) as u8)
            .collect();
        transact(
            &mut pipe,
            &request(d::SEND, peer_port, &data, 0),
            &mut reply,
            1000,
        )?;
        if reply[2] != 0 {
            return Err(-2);
        }
        let end = absd_runtime::boot_millis() + 5000;
        loop {
            let n = transact(
                &mut pipe,
                &request(d::RECEIVE, 0, &[], d::MAX_DATAGRAM as u16),
                &mut reply,
                1000,
            )?;
            if reply[2] == 0 {
                if n != 12 + length
                    || reply[4..8] != [10, 0, 2, 2]
                    || reply[8..10] != peer_port.to_be_bytes()
                    || u16::from_be_bytes([reply[10], reply[11]]) as usize != length
                    || reply[12..n] != data
                {
                    return Err(-3);
                }
                break;
            }
            if reply[2] != d::Error::Again.code() || absd_runtime::boot_millis() >= end {
                return Err(-110);
            }
            absd_runtime::sleep_ticks(5);
        }
    }
    transact(&mut pipe, &request(d::CLOSE, 0, &[], 0), &mut reply, 1000)?;
    if reply[2] != 0 {
        return Err(-4);
    }
    transact(
        &mut pipe,
        &request(d::SEND, peer_port, b"stale", 0),
        &mut reply,
        1000,
    )?;
    if reply[2] != d::Error::Stale.code() {
        return Err(-5);
    }
    Ok(())
}

fn icmp_case(mut pipe: KernelPipe, peer_port: u16) -> Result<(), i64> {
    let mut reply = [0; d::MAX_MESSAGE];
    let data: Vec<u8> = (0usize..1000)
        .map(|i| (i.wrapping_mul(131) ^ (i >> 7)) as u8)
        .collect();
    transact(
        &mut pipe,
        &request(d::SEND, peer_port, &data, 0),
        &mut reply,
        1000,
    )?;
    if reply[2] != 0 {
        return Err(-2);
    }
    let end = absd_runtime::boot_millis() + 3000;
    loop {
        let n = transact(
            &mut pipe,
            &request(d::RECEIVE, 0, &[], d::MAX_DATAGRAM as u16),
            &mut reply,
            1000,
        )?;
        if reply[2] != d::Error::Again.code() {
            eprintln!(
                "ICMP UDP OBSERVED advice_bytes={n} header={:?}",
                &reply[..12]
            );
            if n != 12 || reply[..12] != [1, d::RECEIVE, 14, 0, 0, 0, 0, 0, 0, 0, 2, 64] {
                return Err(-3);
            }
            break;
        }
        if absd_runtime::boot_millis() >= end {
            return Err(-110);
        }
        absd_runtime::sleep_ticks(5);
    }
    // The granted peer is checked before the learned refusal ceiling.
    transact(
        &mut pipe,
        &request(d::SEND, peer_port + 1, &data[..549], 0),
        &mut reply,
        1000,
    )?;
    if reply[2] != d::Error::Denied.code() {
        return Err(-4);
    }
    let n = transact(
        &mut pipe,
        &request(d::SEND, peer_port, &data[..549], 0),
        &mut reply,
        1000,
    )?;
    eprintln!(
        "ICMP UDP OBSERVED refused_bytes={n} header={:?}",
        &reply[..12]
    );
    if n != 12 || reply[..12] != [1, d::SEND, 15, 0, 0, 0, 0, 0, 0, 0, 2, 36] {
        return Err(-5);
    }
    eprintln!("ICMP UDP REFUSED bytes=549 maximum=548 local_not_queued=1 wrong_peer=Denied");
    transact(
        &mut pipe,
        &request(d::SEND, peer_port, &data[..548], 0),
        &mut reply,
        1000,
    )?;
    if reply[2] != 0 {
        return Err(-6);
    }
    let end = absd_runtime::boot_millis() + 3000;
    loop {
        let n = transact(
            &mut pipe,
            &request(d::RECEIVE, 0, &[], d::MAX_DATAGRAM as u16),
            &mut reply,
            1000,
        )?;
        if reply[2] == 0 {
            eprintln!(
                "ICMP UDP OBSERVED echo_bytes={n} data_bytes={} header={:?}",
                n.saturating_sub(12),
                &reply[..12]
            );
            if n != 560
                || reply[4..8] != [10, 0, 2, 2]
                || reply[8..10] != peer_port.to_be_bytes()
                || reply[10..12] != 548u16.to_be_bytes()
                || reply[12..n] != data[..548]
            {
                return Err(-7);
            }
            break;
        }
        if reply[2] != d::Error::Again.code() || absd_runtime::boot_millis() >= end {
            return Err(-110);
        }
        absd_runtime::sleep_ticks(5);
    }
    transact(&mut pipe, &request(d::CLOSE, 0, &[], 0), &mut reply, 1000)?;
    if reply[2] != 0 {
        return Err(-8);
    }
    eprintln!("ICMP UDP COMPLETE mtu=576 maximum=548 refused=549 echoed=548 denied=1");
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::from(1),
    }
}
