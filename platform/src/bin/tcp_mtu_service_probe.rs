#![feature(restricted_std)]
//! Actual native Client/Session MTU-refusal consumer over a bounded local
//! fixture Pipe. No delegated process, kernel IPC or automatic recovery claim.
#[path = "../tcp_mtu_fixture.rs"]
mod fixture;
use absd_net::{Config, NicLink, Stack, datagram, stream};
use std::{cell::RefCell, rc::Rc};

fn grant(c: &mut fixture::Context, positive: bool) -> Result<datagram::Address, String> {
    if c.session.is_some() {
        return Err("previous session not revoked".into());
    }
    let peer = datagram::Address {
        ip: fixture::PEER,
        port: if positive { 42101 } else { 42100 },
    };
    let session = stream::Session::grant_mtu_refusal(
        &mut c.stack,
        stream::Grant {
            local_port: if positive { 7101 } else { 7100 },
            peer,
            connect_timeout_ms: 4000,
            lifetime_ms: if positive {
                fixture::POSITIVE_MS
            } else {
                fixture::REFUSAL_MS
            },
        },
    )
    .map_err(|e| format!("grant {e:?}"))?;
    c.session = Some(session);
    Ok(peer)
}
fn until(c: &Rc<RefCell<fixture::Context>>, deadline: u64) -> Result<u64, String> {
    c.borrow().time(deadline)
}
fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let trace = Rc::new(RefCell::new(fixture::Trace::default()));
    let link = fixture::ReceiptLink {
        inner: NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?,
        trace: trace.clone(),
    };
    let stack = Stack::open(
        link,
        Config {
            address: [192, 0, 2, 100].into(),
            prefix_len: 24,
            gateway: Some([192, 0, 2, 1].into()),
            rx_buffer: 2048,
            tx_buffer: 2048,
        },
    )
    .map_err(|e| format!("stack {e:?}"))?;
    let start = absd_runtime::boot_millis();
    let whole = start
        .checked_add(fixture::WHOLE_MS)
        .ok_or("whole overflow")?;
    let refusal_until = start
        .checked_add(fixture::REFUSAL_MS)
        .ok_or("refusal overflow")?;
    let context = Rc::new(RefCell::new(fixture::Context::new(
        stack,
        trace.clone(),
        whole,
        start,
    )));
    println!(
        "TCP MTU BEGIN v=1 start_ms={start} until_ms={whole} refusal_until_ms={refusal_until} guest=192.0.2.100 router=192.0.2.1 peer=198.51.100.2"
    );
    let peer = grant(&mut context.borrow_mut(), false)?;
    let mut client = stream::Client::new_mtu_refusal(
        fixture::LocalPipe::new(context.clone()),
        peer,
        fixture::pause,
    );
    client
        .connect(refusal_until)
        .map_err(|e| format!("connect {e:?}"))?;
    let at = until(&context, refusal_until)?;
    let sockets = context.borrow().stack.socket_count();
    if sockets != 1 {
        return Err(format!("connected sockets {sockets}"));
    }
    println!("TCP MTU CONNECTED v=1 at_ms={at} phase=refusal sockets={sockets}");
    let bytes: [u8; 1024] = core::array::from_fn(|i| (i % 251) as u8);
    let n = client
        .write(&bytes, refusal_until)
        .map_err(|e| format!("write {e:?}"))?;
    if n != bytes.len() {
        return Err(format!("partial write {n}"));
    }
    let at = until(&context, refusal_until)?;
    println!("TCP MTU QUEUED v=1 at_ms={at} phase=refusal bytes={n}");
    let mut buffer = [0; 64];
    loop {
        until(&context, refusal_until)?;
        match client.read(&mut buffer, refusal_until) {
            Err(stream::Error::Again) => fixture::pause(5),
            Err(stream::Error::FragmentationNeeded { mtu: 576 }) => break,
            other => return Err(format!("expected typed MTU576 refusal {other:?}")),
        }
    }
    let at = until(&context, refusal_until)?;
    let sockets = context.borrow().stack.socket_count();
    if sockets != 0 {
        return Err(format!("refusal socket retained {sockets}"));
    }
    println!(
        "TCP MTU REFUSED v=1 at_ms={at} code=17 mtu=576 sockets={sockets} until_ms={refusal_until} effects=unknown"
    );
    let rpc_before = context.borrow().rpc;
    let tx_before = trace.borrow().tx;
    if client.read(&mut buffer, refusal_until) != Err(stream::Error::Stale)
        || client.write(&bytes, refusal_until) != Err(stream::Error::Stale)
    {
        return Err("client authority revived".into());
    }
    let rpc_after = context.borrow().rpc;
    let tx_after = trace.borrow().tx;
    let at = until(&context, refusal_until)?;
    if rpc_before != rpc_after || tx_before != tx_after {
        return Err("fenced call performed IO".into());
    }
    println!(
        "TCP MTU FENCED v=1 at_ms={at} code=8 rpc_before={rpc_before} rpc_after={rpc_after} tx_before={tx_before} tx_after={tx_after}"
    );
    drop(client);
    context.borrow_mut().revoke()?;
    let at = until(&context, refusal_until)?;
    if context.borrow().stack.socket_count() != 0 {
        return Err("negative revoke socket".into());
    }
    println!("TCP MTU REVOKED v=1 at_ms={at} sockets=0");

    // Explicit owner action after terminal refusal; never an automatic retry.
    let positive_start = until(&context, whole)?;
    let positive_until = positive_start
        .checked_add(fixture::POSITIVE_MS)
        .ok_or("positive overflow")?;
    if positive_until > whole {
        return Err("fresh positive outside original whole budget".into());
    }
    context.borrow_mut().positive = true;
    trace.borrow_mut().positive = true;
    let peer = grant(&mut context.borrow_mut(), true)?;
    let mut client = stream::Client::new_mtu_refusal(
        fixture::LocalPipe::new(context.clone()),
        peer,
        fixture::pause,
    );
    println!("TCP MTU POSITIVE v=1 start_ms={positive_start} until_ms={positive_until} bytes=64");
    client
        .connect(positive_until)
        .map_err(|e| format!("positive connect {e:?}"))?;
    let at = until(&context, positive_until)?;
    if context.borrow().stack.socket_count() != 1 {
        return Err("positive connected socket".into());
    }
    println!("TCP MTU CONNECTED v=1 at_ms={at} phase=positive sockets=1");
    let positive: [u8; 64] = core::array::from_fn(|i| i as u8);
    let n = client
        .write(&positive, positive_until)
        .map_err(|e| format!("positive write {e:?}"))?;
    if n != positive.len() {
        return Err("partial positive write".into());
    }
    let at = until(&context, positive_until)?;
    println!("TCP MTU QUEUED v=1 at_ms={at} phase=positive bytes={n}");
    client
        .shutdown_write(positive_until)
        .map_err(|e| format!("positive half close {e:?}"))?;
    client
        .read_exact(&mut buffer, positive_until)
        .map_err(|e| format!("positive read {e:?}"))?;
    if buffer != positive {
        return Err("positive echo mismatch".into());
    }
    let at = until(&context, positive_until)?;
    println!(
        "TCP MTU OBSERVED v=1 at_ms={at} bytes=64 hex={} sockets={}",
        fixture::hex(&buffer),
        context.borrow().stack.socket_count()
    );
    loop {
        until(&context, positive_until)?;
        match client.read(&mut buffer, positive_until) {
            Err(stream::Error::Again) => fixture::pause(5),
            Err(stream::Error::Eof) => break,
            other => return Err(format!("positive expected EOF {other:?}")),
        }
    }
    let at = until(&context, positive_until)?;
    println!("TCP MTU EOF v=1 at_ms={at} phase=positive code=6");
    drop(client);
    context.borrow_mut().revoke()?;
    loop {
        until(&context, positive_until)?;
        context.borrow_mut().poll()?;
        if context.borrow().stack.socket_count() == 0 {
            break;
        }
        fixture::pause(5);
    }
    let at = until(&context, positive_until)?;
    trace.borrow_mut().flush();
    println!("TCP MTU DONE v=1 at_ms={at} sockets=0 negative_bytes=1024 positive_bytes=64");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("TCP MTU FAIL {error}");
        std::process::exit(1);
    }
}
