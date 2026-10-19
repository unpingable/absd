//! NIC qualification (`net-probe` boot, docs/NETWORK.md): the frame calls'
//! refusals, then a layer-2 reflector the host harness drives over QEMU's
//! `-netdev dgram`. No protocol stack: frames of the local experimental
//! EtherType 0x88b5 carry the harness's commands.
//!
//! Step 0: refusals, a broadcast hello, then reflect `E` frames byte for
//! byte (addresses swapped) until a `Q` frame. When the kernel granted the
//! NIC with the link down (`NIC LINK DOWN AT PROBE`), step 0 first checks
//! that state and waits for the harness to raise the link; nothing is
//! re-opened. Step 1 (with the kernel's `nic-ring-fault` injection): the
//! NIC must refuse every send and receive and report itself disabled.
//! Step 2 (kernel `nic-tx-hold`) and step 3 (`nic-tx-hold-stuck`): the link
//! is down at the probe and the kernel holds a descriptor posted without
//! carrier; see `tx_hold`.
#![no_std]
#![no_main]

use absd_user::{
    Console, Error, NIC_FRAME_MAX, Nic, NicInfo, RIGHT_READ, RIGHT_WRITE, Start, close, duplicate,
    sleep, time,
};

const ETHERTYPE: [u8; 2] = [0x88, 0xb5];
const COMMAND_ECHO: u8 = b'E';
const COMMAND_QUIT: u8 = b'Q';
/// The harness drives the reflector; a silent host ends the probe.
const IDLE_TICKS: u64 = 30_000;
/// How long a link that was down at the probe may take to come up.
const LINK_WAIT_TICKS: u64 = 60_000;

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    let nic = Nic::from_raw(start.handle);
    let result = match start.arg {
        1 => fail_closed(console, nic),
        2 => tx_hold(console, nic, false),
        3 => tx_hold(console, nic, true),
        _ => reflect(console, nic),
    };
    match result {
        Ok(()) => 0,
        Err(step) => {
            let _ = console.line(format_args!("NIC PROBE FAILED at {step}\n"));
            1
        }
    }
}

fn mac_text(console: Console, prefix: &str, mac: [u8; 6]) {
    let _ = console.line(format_args!(
        "{prefix}{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ));
}

/// Every refusal the frame calls promise, before any frame moves.
fn refusals(nic: Nic) -> Result<(), &'static str> {
    let frame = [0u8; NIC_FRAME_MAX + 1];
    for length in [0, 1, 13, NIC_FRAME_MAX as u64 + 1, u64::MAX] {
        if nic.send_raw(frame.as_ptr() as u64, length) != Err(Error::Invalid) {
            return Err("send length refusal");
        }
    }
    // A kernel address and an unmapped user address are refused as faults.
    if nic.send_raw(0xffff_8000_0000_0000, 60) != Err(Error::Fault)
        || nic.send_raw(0, 60) != Err(Error::Fault)
    {
        return Err("send pointer refusal");
    }
    if nic.receive_raw(0, 1) != Err(Error::Fault)
        || nic.receive_raw(0xffff_8000_0000_0000, 1) != Err(Error::Fault)
    {
        return Err("receive pointer refusal");
    }
    // A buffer whose last bytes run off the end of the stack is refused even
    // though the first page is mapped: the whole maximum frame must fit.
    let stack_top = absd_abi::layout::USER_STACK_TOP;
    if nic.receive_raw(stack_top - 100, 1) != Err(Error::Fault) {
        return Err("receive partial buffer refusal");
    }
    let mut buffer = [0u8; NIC_FRAME_MAX];
    if nic.receive(&mut buffer, 0) != Err(Error::Again) {
        return Err("receive poll on an idle link");
    }
    if nic.receive(&mut buffer, 3) != Err(Error::Timeout) {
        return Err("receive timeout on an idle link");
    }
    // Rights: read receives and reports, write sends, nothing else.
    let reader = Nic::from_raw(duplicate(nic.raw(), RIGHT_READ).map_err(|_| "dup read")?);
    let writer = Nic::from_raw(duplicate(nic.raw(), RIGHT_WRITE).map_err(|_| "dup write")?);
    if reader.send(&frame[..60]) != Err(Error::Rights)
        || writer.receive(&mut buffer, 0) != Err(Error::Rights)
        || writer.info() != Err(Error::Rights)
        || reader.info().is_err()
    {
        return Err("rights refusal");
    }
    close(reader.raw()).map_err(|_| "close read")?;
    close(writer.raw()).map_err(|_| "close write")?;
    // Same slot, another issue tag: a stale handle.
    if Nic::from_raw(nic.raw() ^ (1 << 8)).info() != Err(Error::BadHandle) {
        return Err("bad handle refusal");
    }
    Ok(())
}

fn hello_frame(mac: [u8; 6]) -> [u8; 60] {
    let mut hello = [0u8; 60];
    hello[..6].fill(0xff);
    hello[6..12].copy_from_slice(&mac);
    hello[12..14].copy_from_slice(&ETHERTYPE);
    hello[14..24].copy_from_slice(b"ABSD-HELLO");
    hello
}

/// The kernel granted the NIC with the link down: the handle works, the
/// NIC is not disabled, nothing is received, and a send is accepted (QEMU's
/// device completes the descriptor and drops the frame; the harness checks
/// that nothing reached the wire). Then the link flag turns on, with no
/// re-open, once the harness raises the link.
fn link_down(console: Console, nic: Nic, info: NicInfo) -> Result<(), &'static str> {
    if info.flags & absd_abi::nic::NIC_FLAG_DISABLED != 0 {
        return Err("disabled with link down");
    }
    let mut buffer = [0u8; NIC_FRAME_MAX];
    if nic.receive(&mut buffer, 0) != Err(Error::Again) {
        return Err("receive poll with link down");
    }
    if nic.receive(&mut buffer, 3) != Err(Error::Timeout) {
        return Err("receive timeout with link down");
    }
    nic.send(&hello_frame(info.mac))
        .map_err(|_| "send with link down")?;
    let after = nic.info().map_err(|_| "info after link-down send")?;
    if after.tx_frames != info.tx_frames + 1 || after.tx_errors != 0 {
        return Err("send counters with link down");
    }
    // Printed after the send: the harness's silence window starts here.
    mac_text(console, "NIC PROBE LINK DOWN mac=", info.mac);
    let mut waited = 0u64;
    loop {
        let now = nic.info().map_err(|_| "info while link down")?;
        if now.flags & absd_abi::nic::NIC_FLAG_DISABLED != 0 {
            return Err("disabled while link down");
        }
        if now.flags & absd_abi::nic::NIC_FLAG_LINK_UP != 0 {
            break;
        }
        if waited >= LINK_WAIT_TICKS {
            return Err("link never came up");
        }
        sleep(100);
        waited += 100;
    }
    let _ = console.write_str("NIC PROBE LINK UP\n");
    Ok(())
}

fn reflect(console: Console, nic: Nic) -> Result<(), &'static str> {
    let mut info = nic.info().map_err(|_| "info")?;
    if info.flags & absd_abi::nic::NIC_FLAG_LINK_UP == 0 {
        link_down(console, nic, info)?;
        info = nic.info().map_err(|_| "info after link up")?;
    }
    let before = info.tx_frames;
    refusals(nic)?;
    let info = nic.info().map_err(|_| "info after refusals")?;
    // No refused send reached the device; each was counted.
    if info.tx_frames != before || info.tx_refused < 5 {
        return Err("refusal counters");
    }
    let _ = console.write_str("NIC REFUSALS OK\n");
    mac_text(console, "NIC PROBE READY mac=", info.mac);

    nic.send(&hello_frame(info.mac)).map_err(|_| "hello send")?;

    let mut buffer = [0u8; NIC_FRAME_MAX];
    let mut reply = [0u8; NIC_FRAME_MAX];
    let mut echoed = 0u64;
    let mut ignored = 0u64;
    let mut largest = 0usize;
    loop {
        let length = match nic.receive(&mut buffer, IDLE_TICKS) {
            Ok(length) => length,
            Err(Error::Timeout) => return Err("host went silent"),
            Err(_) => return Err("receive"),
        };
        if length < 15 || buffer[12..14] != ETHERTYPE {
            ignored += 1;
            continue;
        }
        match buffer[14] {
            COMMAND_ECHO => {
                reply[..6].copy_from_slice(&buffer[6..12]);
                reply[6..12].copy_from_slice(&info.mac);
                reply[12..length].copy_from_slice(&buffer[12..length]);
                nic.send(&reply[..length]).map_err(|_| "echo send")?;
                echoed += 1;
                largest = largest.max(length);
            }
            COMMAND_QUIT => break,
            _ => ignored += 1,
        }
    }
    let info = nic.info().map_err(|_| "final info")?;
    let _ = console.line(format_args!(
        "NIC PROBE REFLECTED frames={echoed} largest={largest} ignored={ignored} rx_frames={} rx_refused={} tx_frames={}\n",
        info.rx_frames, info.rx_refused, info.tx_frames
    ));
    let _ = console.write_str("NIC PROBE OK\n");
    Ok(())
}

/// Kernel `nic-tx-hold` (step 2) or `nic-tx-hold-stuck` (step 3), harness
/// `nic-reflect.py --tx-hold[-stuck]`: the link is down at the probe and
/// the kernel's fixture holds a descriptor posted without carrier. The
/// first send waits out its bound and gets the link outcome (`NoCarrier`,
/// one `tx_errors`, the NIC enabled); the next is refused at once with no
/// counter moving; receive still answers. Once the harness raises the link
/// the next send goes out after the held one (released: `tx_frames` 2), or
/// the bound that then runs with carrier present disables the NIC (stuck:
/// `Io`, `tx_errors` 2). The fixture shows the driver's rule, not a device.
fn tx_hold(console: Console, nic: Nic, stuck: bool) -> Result<(), &'static str> {
    use absd_abi::nic::{NIC_FLAG_DISABLED, NIC_FLAG_LINK_UP};
    let info = nic.info().map_err(|_| "info")?;
    if info.flags & (NIC_FLAG_LINK_UP | NIC_FLAG_DISABLED) != 0
        || info.tx_frames != 0
        || info.tx_errors != 0
    {
        return Err("tx hold: a fresh NIC with the link down expected");
    }
    let mut held = hello_frame(info.mac);
    held[14..24].copy_from_slice(b"ABSD-HELD1");
    let start = time();
    if nic.send(&held) != Err(Error::NoCarrier) {
        return Err("tx hold: first send without carrier");
    }
    let held_ticks = time() - start;
    let after = nic.info().map_err(|_| "info after the bound")?;
    if after.flags & NIC_FLAG_DISABLED != 0
        || after.tx_errors != 1
        || after.tx_frames != 0
        || held_ticks < 100
    {
        return Err("tx hold: counters after the bound");
    }
    let mut refused = hello_frame(info.mac);
    refused[14..24].copy_from_slice(b"ABSD-HELD2");
    let start = time();
    if nic.send(&refused) != Err(Error::NoCarrier) {
        return Err("tx hold: second send while held");
    }
    let refused_ticks = time() - start;
    if nic.info().map_err(|_| "info after the refusal")? != after || refused_ticks >= 50 {
        return Err("tx hold: the refusal waited or counted");
    }
    let mut buffer = [0u8; NIC_FRAME_MAX];
    if nic.receive(&mut buffer, 0) != Err(Error::Again) {
        return Err("tx hold: receive while held");
    }
    let _ = console.line(format_args!(
        "NIC PROBE TX HELD held_ticks={held_ticks} refused_ticks={refused_ticks}\n"
    ));
    let mut waited = 0u64;
    while nic.info().map_err(|_| "info while held")?.flags & NIC_FLAG_LINK_UP == 0 {
        if waited >= LINK_WAIT_TICKS {
            return Err("tx hold: link never came up");
        }
        sleep(100);
        waited += 100;
    }
    let mut next = hello_frame(info.mac);
    next[14..24].copy_from_slice(b"ABSD-AFTER");
    let result = nic.send(&next);
    let last = nic.info().map_err(|_| "final info")?;
    if stuck {
        if result != Err(Error::Io)
            || last.flags & NIC_FLAG_DISABLED == 0
            || last.tx_errors != 2
            || last.tx_frames != 0
        {
            return Err("tx hold stuck: device outcome");
        }
        let _ = console.line(format_args!(
            "NIC PROBE TX STUCK DISABLED tx_errors={}\n",
            last.tx_errors
        ));
    } else {
        if result.is_err()
            || last.flags & NIC_FLAG_DISABLED != 0
            || last.tx_frames != 2
            || last.tx_errors != 1
        {
            return Err("tx hold: release");
        }
        let _ = console.line(format_args!(
            "NIC PROBE TX RELEASED tx_frames={} tx_errors={}\n",
            last.tx_frames, last.tx_errors
        ));
    }
    Ok(())
}

/// The kernel put an out-of-ring value in the receive head register before
/// init started; the first call that touches the rings must find it.
fn fail_closed(console: Console, nic: Nic) -> Result<(), &'static str> {
    let mut buffer = [0u8; NIC_FRAME_MAX];
    if nic.receive(&mut buffer, 5) != Err(Error::Io) {
        return Err("receive after ring fault");
    }
    if nic.send(&[0u8; 60]) != Err(Error::Io) {
        return Err("send after ring fault");
    }
    if nic.receive(&mut buffer, 0) != Err(Error::Io) {
        return Err("poll after ring fault");
    }
    // Argument validation must not outrank the disabled NIC: every later
    // send and receive returns Io, and no counter moves (docs/NETWORK.md).
    if nic.send_raw(buffer.as_ptr() as u64, 13) != Err(Error::Io) {
        return Err("send length refusal after disable");
    }
    if nic.receive_raw(0, 1) != Err(Error::Io) {
        return Err("receive pointer refusal after disable");
    }
    let info = nic.info().map_err(|_| "info after ring fault")?;
    if info.flags & absd_abi::nic::NIC_FLAG_DISABLED == 0
        || info.flags & absd_abi::nic::NIC_FLAG_LINK_UP != 0
        || info.tx_frames != 0
        || info.rx_frames != 0
        || info.tx_refused != 0
    {
        return Err("disabled flags");
    }
    let _ = console.write_str("NIC FAIL CLOSED OK\n");
    Ok(())
}
