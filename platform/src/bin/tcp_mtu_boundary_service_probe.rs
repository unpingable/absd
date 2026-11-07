#![feature(restricted_std)]
//! Bounded native quote/flow isolation fixture. Injected ICMP is not a router
//! provenance claim. Local Pipe uses real codecs, not kernel IPC or children.
#[path = "../tcp_mtu_boundary_fixture.rs"]
mod fixture;
use absd_net::datagram::channel::Pipe;
use absd_net::{Config, NicLink, Stack, datagram, stream};
use std::{cell::RefCell, rc::Rc};

type Context = Rc<RefCell<fixture::Context>>;

fn grant(context: &Context, slot: usize) -> Result<datagram::Address, String> {
    let mut c = context.borrow_mut();
    if c.sessions[slot].is_some() {
        return Err("occupied session slot".into());
    }
    let at = c.time()?;
    let peer = datagram::Address {
        ip: fixture::PEER,
        port: if slot == 1 { 42101 } else { 42100 },
    };
    let local_port = if slot == 1 { 7101 } else { 7100 };
    let lifetime_ms = c.until.checked_sub(at).ok_or("grant budget")?;
    let session = stream::Session::grant_mtu_refusal(
        &mut c.stack,
        stream::Grant {
            local_port,
            peer,
            connect_timeout_ms: 4000,
            lifetime_ms,
        },
    )
    .map_err(|e| format!("grant {e:?}"))?;
    c.sessions[slot] = Some(session);
    println!(
        "TCP MTU BOUNDARY GRANT v=1 slot={} logical={} local_port={local_port} peer_port={} at_ms={at} until_ms={}",
        fixture::SLOTS[slot],
        slot + 1,
        peer.port,
        c.until
    );
    Ok(peer)
}
fn sockets(context: &Context, expected: usize) -> Result<(), String> {
    let c = context.borrow();
    c.time()?;
    let actual = c.stack.socket_count();
    if actual != expected {
        return Err(format!("expected sockets {expected}, got {actual}"));
    }
    Ok(())
}
fn control(context: &Context, index: usize) -> Result<usize, String> {
    loop {
        context.borrow_mut().poll()?;
        let controls = context.borrow().trace.borrow().controls();
        if controls.len() > index + 1 {
            return Err("batched or unexpected control".into());
        }
        if let Some(ordinal) = controls.get(index) {
            return Ok(*ordinal);
        }
        fixture::pause(5);
    }
}
fn reserved_status(context: &Context) -> Result<(), String> {
    // No CONNECT: the fresh reservation must have no transmitted TCP history.
    // This literal experimental-v4 STATUS uses the actual framed LocalPipe.
    let mut pipe = fixture::LocalPipe::new(context.clone(), 2);
    let mut request = [0u8; 12];
    request[0] = 4;
    request[1] = stream::STATUS;
    request[4..8].copy_from_slice(&fixture::PEER);
    request[8..10].copy_from_slice(&42100u16.to_be_bytes());
    let prefix = 12u16.to_be_bytes();
    for b in [&prefix[..], &request[..]] {
        if pipe.write(b) != Ok(Some(b.len())) {
            return Err("reserved framed write".into());
        }
    }
    let mut length = [0; 2];
    if pipe.read(&mut length) != Ok(Some(2)) || length != 13u16.to_be_bytes() {
        return Err("reserved reply prefix".into());
    }
    let mut reply = [0; 13];
    if pipe.read(&mut reply) != Ok(Some(13)) {
        return Err("reserved reply body".into());
    }
    let mut expected = [0; 13];
    expected[..10].copy_from_slice(&request[..10]);
    expected[11] = 1;
    if reply != expected {
        return Err(format!("reserved STATUS {}", fixture::hex(&reply)));
    }
    Ok(())
}
fn revoke(context: &Context, slot: usize, expected: usize) -> Result<(), String> {
    context.borrow_mut().revoke(slot)?;
    loop {
        context.borrow_mut().poll()?;
        if context.borrow().stack.socket_count() == expected {
            break;
        }
        fixture::pause(5);
    }
    let at = context.borrow().time()?;
    println!(
        "TCP MTU BOUNDARY REVOKED v=1 slot={} logical={} at_ms={at} sockets={expected}",
        fixture::SLOTS[slot],
        slot + 1
    );
    Ok(())
}
fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let trace = Rc::new(RefCell::new(fixture::Trace::new()));
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
    let until = start.checked_add(30_000).ok_or("budget overflow")?;
    let context = Rc::new(RefCell::new(fixture::Context::new(
        stack,
        trace.clone(),
        start,
        until,
    )));
    println!(
        "TCP MTU BOUNDARY BEGIN v=1 start_ms={start} until_ms={until} guest=192.0.2.100 router=192.0.2.1 peer=198.51.100.2"
    );
    let target_peer = grant(&context, 0)?;
    let unaffected_peer = grant(&context, 1)?;
    let mut target = stream::Client::new_mtu_refusal(
        fixture::LocalPipe::new(context.clone(), 0),
        target_peer,
        fixture::pause,
    );
    let mut unaffected = stream::Client::new_mtu_refusal(
        fixture::LocalPipe::new(context.clone(), 1),
        unaffected_peer,
        fixture::pause,
    );
    for (slot, client) in [(0, &mut target), (1, &mut unaffected)] {
        client
            .connect(until)
            .map_err(|e| format!("connect {} {e:?}", fixture::SLOTS[slot]))?;
        let expected = slot + 1;
        sockets(&context, expected)?;
        let at = context.borrow().time()?;
        println!(
            "TCP MTU BOUNDARY CONNECTED v=1 slot={} logical={} at_ms={at} sockets={expected}",
            fixture::SLOTS[slot],
            slot + 1
        );
    }
    trace.borrow_mut().phase = "cases";
    let body: [u8; 1024] = core::array::from_fn(|i| (i % 251) as u8);
    if target
        .write(&body, until)
        .map_err(|e| format!("target write {e:?}"))?
        != body.len()
    {
        return Err("partial target write".into());
    }
    let at = context.borrow().time()?;
    println!("TCP MTU BOUNDARY QUEUED v=1 slot=target logical=1 at_ms={at} bytes=1024");
    context.borrow_mut().poll()?;
    let at = context.borrow().time()?;
    println!(
        "TCP MTU BOUNDARY CONTROLS_READY v=1 at_ms={at} target_logical=1 unaffected_logical=2 sockets=2"
    );
    for (index, name) in ["bad-checksum", "wrong-sequence", "equal-mtu"]
        .into_iter()
        .enumerate()
    {
        let receive = control(&context, index)?;
        target
            .connect(until)
            .map_err(|e| format!("invalid control {name} changed target {e:?}"))?;
        sockets(&context, 2)?;
        let at = context.borrow().time()?;
        println!(
            "TCP MTU BOUNDARY CASE v=1 index={index} case={name} receive_ordinal={receive} at_ms={at} code=0 connected=1 sockets=2 logical=1 until_ms={until}"
        );
    }
    trace.borrow_mut().phase = "matching";
    let receive = control(&context, 3)?;
    if target.connect(until) != Err(stream::Error::FragmentationNeeded { mtu: 576 }) {
        return Err("matching advice did not preserve typed576 cause".into());
    }
    sockets(&context, 1)?;
    let at = context.borrow().time()?;
    println!(
        "TCP MTU BOUNDARY REFUSED v=1 at_ms={at} receive_ordinal={receive} code=17 mtu=576 sockets=1 logical=1 until_ms={until} effects=unknown"
    );
    let before_rpc = context.borrow().rpc;
    let before_tx = trace.borrow().tx;
    let mut buffer = [0; 64];
    if target.read(&mut buffer, until) != Err(stream::Error::Stale)
        || target.write(&body, until) != Err(stream::Error::Stale)
    {
        return Err("target client revived".into());
    }
    let after_rpc = context.borrow().rpc;
    let after_tx = trace.borrow().tx;
    if before_rpc != after_rpc || before_tx != after_tx {
        return Err("fenced target IO".into());
    }
    let at = context.borrow().time()?;
    println!(
        "TCP MTU BOUNDARY FENCED v=1 at_ms={at} code=8 logical=1 rpc_before={before_rpc} rpc_after={after_rpc} tx_before={before_tx} tx_after={after_tx}"
    );
    drop(target);
    revoke(&context, 0, 1)?;

    trace.borrow_mut().phase = "survivor";
    unaffected
        .connect(until)
        .map_err(|e| format!("unaffected STATUS {e:?}"))?;
    let echo: [u8; 64] = core::array::from_fn(|i| i as u8);
    if unaffected
        .write(&echo, until)
        .map_err(|e| format!("survivor write {e:?}"))?
        != echo.len()
    {
        return Err("partial survivor write".into());
    }
    let at = context.borrow().time()?;
    println!("TCP MTU BOUNDARY QUEUED v=1 slot=unaffected logical=2 at_ms={at} bytes=64");
    unaffected
        .shutdown_write(until)
        .map_err(|e| format!("survivor shutdown {e:?}"))?;
    unaffected
        .read_exact(&mut buffer, until)
        .map_err(|e| format!("survivor read {e:?}"))?;
    if buffer != echo {
        return Err("survivor echo bytes".into());
    }
    let at = context.borrow().time()?;
    println!(
        "TCP MTU BOUNDARY OBSERVED v=1 slot=unaffected logical=2 at_ms={at} bytes=64 hex={} sockets={}",
        fixture::hex(&buffer),
        context.borrow().stack.socket_count()
    );
    loop {
        context.borrow().time()?;
        match unaffected.read(&mut buffer, until) {
            Err(stream::Error::Again) => fixture::pause(5),
            Err(stream::Error::Eof) => break,
            other => return Err(format!("survivor EOF {other:?}")),
        }
    }
    let at = context.borrow().time()?;
    println!("TCP MTU BOUNDARY EOF v=1 slot=unaffected logical=2 at_ms={at} code=6");
    drop(unaffected);
    revoke(&context, 1, 0)?;

    trace.borrow_mut().phase = "reserved";
    grant(&context, 2)?;
    reserved_status(&context)?;
    sockets(&context, 0)?;
    let at = context.borrow().time()?;
    println!("TCP MTU BOUNDARY EMPTY_READY v=1 at_ms={at} logical=3 sockets=0 until_ms={until}");
    let receive = control(&context, 4)?;
    reserved_status(&context)?;
    sockets(&context, 0)?;
    let at = context.borrow().time()?;
    println!(
        "TCP MTU BOUNDARY CASE v=1 index=4 case=empty-history receive_ordinal={receive} at_ms={at} code=0 connected=0 sockets=0 logical=3 until_ms={until}"
    );
    revoke(&context, 2, 0)?;
    trace.borrow_mut().phase = "done";
    trace.borrow_mut().flush();
    let at = context.borrow().time()?;
    println!(
        "TCP MTU BOUNDARY DONE v=1 at_ms={at} sockets=0 target_bytes=1024 unaffected_bytes=64 cases=4"
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("TCP MTU BOUNDARY FAIL {error}");
        std::process::exit(1);
    }
}
