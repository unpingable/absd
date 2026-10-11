//! Identical semantic workload for x86_64 and ARM64; ISA probes are in user/arch.
#![no_std]
#![no_main]
use absd_abi::syscall::*;
use absd_user::*;
absd_user::entry!(main);
static READONLY: [u64; 5] = [0x1122334455667788; 5];
fn identity(trace: &mut absd_user::semantic_trace::Trace, child: Child) {
    let info = info(Some(child)).unwrap();
    trace.record("spawn_identity", [info.pid, info.parent, info.program]);
}
fn success(trace: &mut absd_user::semantic_trace::Trace, child: Child, code: i32) {
    identity(trace, child);
    let result = wait_identified_timeout(Some(child), 0).unwrap();
    assert_eq!(result.outcome, Outcome::Exited(code));
    trace.record(
        "wait_exit",
        [result.pid, OUTCOME_EXITED, code as i64 as u64],
    );
}
fn census(trace: &mut absd_user::semantic_trace::Trace, base: ResourceCensus, phase: u64) {
    let now = resource_census().unwrap();
    trace.record("resource_accounts", [now.processes, now.handles, now.cells]);
    trace.record(
        "resource_balance",
        [
            (now.frames as i64 - base.frames as i64) as u64,
            now.pipes,
            phase,
        ],
    );
    trace.native("frame_geometry", [base.frames, now.frames, 4096]);
    assert_eq!(now, base);
}
fn refusal(trace: &mut absd_user::semantic_trace::Trace, event: &str, code: i64, expected: i64) {
    trace.record(event, [code as u64, 0, 0]);
    assert_eq!(code, expected);
}
fn main(start: Start) -> i32 {
    if getpid() != 1 {
        return worker(start);
    }
    let console = start.console;
    devices(start);
    let mut trace = absd_user::semantic_trace::Trace::new(console);
    let abi = abi_version().unwrap();
    assert_eq!(abi, absd_abi::KERNEL_ABI);
    trace.record(
        "abi",
        [abi, RESOURCE_CENSUS_BYTES as u64, OUTCOME_BYTES as u64],
    );
    refusal(
        &mut trace,
        "unknown_syscall",
        unsafe { syscall3(999, 0, 0, 0) },
        ERROR_NOT_IMPLEMENTED,
    );
    refusal(
        &mut trace,
        "pointer_refused",
        unsafe { syscall3(SYS_WRITE, console.raw(), 0x100000, 8) },
        ERROR_FAULT,
    );
    refusal(
        &mut trace,
        "handle_refused",
        unsafe { syscall3(SYS_WRITE, 0, READONLY.as_ptr() as u64, 8) },
        ERROR_BAD_HANDLE,
    );
    refusal(
        &mut trace,
        "copyout_readonly",
        unsafe { syscall3(SYS_RESOURCE_CENSUS, READONLY.as_ptr() as u64, 0, 0) },
        ERROR_FAULT,
    );
    assert_eq!(READONLY, [0x1122334455667788; 5]);
    let mapping = map(2).unwrap();
    unsafe {
        let b = core::slice::from_raw_parts_mut(mapping.add(4090), 12);
        b.copy_from_slice(b"CROSS PAGE\n\n");
        let written = console.write_once(b).unwrap();
        assert_eq!(written, 12);
        trace.record("heap_cross_page", [mapping as u64, 2, written as u64]);
    }
    unmap(mapping, 2).unwrap();
    refusal(
        &mut trace,
        "unmapped_refused",
        unsafe { syscall3(SYS_WRITE, console.raw(), mapping as u64, 8) },
        ERROR_FAULT,
    );
    console
        .write_str("PORTABLE MEMORY VALIDATION OK\n")
        .unwrap();
    let base = resource_census().unwrap();
    census(&mut trace, base, 1);
    let cell = Cell::create(0).unwrap();
    let (version, value) = cell.read().unwrap();
    trace.record("cell_created", [cell.raw(), version, value]);
    let view = duplicate(cell.raw(), RIGHT_READ).unwrap();
    trace.record("read_grant", [view, RIGHT_READ, cell.raw()]);
    let error = Cell::from_raw(view).transition(0, 1).unwrap_err();
    refusal(&mut trace, "rights_refused", error.code(), ERROR_RIGHTS);
    close(view).unwrap();
    trace.record("handle_closed", [view, 0, 0]);
    let error = Cell::from_raw(view).read().unwrap_err();
    refusal(
        &mut trace,
        "revoked_refused",
        error.code(),
        ERROR_BAD_HANDLE,
    );
    let version = cell.transition(0, 1).unwrap();
    assert_eq!(version, 1);
    trace.record("cell_transition", [version, cell.read().unwrap().1, 0]);
    let error = cell.transition(0, 2).unwrap_err();
    refusal(&mut trace, "stale_refused", error.code(), ERROR_STALE);
    assert_eq!(cell.read(), Ok((1, 1)));
    success(
        &mut trace,
        spawn_with(program::HELLO_A, 0, console.raw()).unwrap(),
        0,
    );
    let a = spawn_with(program::HELLO_A, cell.raw(), 2).unwrap();
    let b = spawn_with(program::HELLO_A, cell.raw(), 2).unwrap();
    trace.record("transfer_children", [cell.raw(), a.raw(), b.raw()]);
    success(&mut trace, a, 0);
    success(&mut trace, b, 0);
    let (version, value) = cell.read().unwrap();
    assert_eq!((version, value), (201, 201));
    trace.record("cell_final", [version, value, 0]);
    close(cell.raw()).unwrap();
    trace.record("cell_closed", [cell.raw(), 0, 0]);
    census(&mut trace, base, 2);
    console
        .write_str("PORTABLE HANDLE ISOLATION RIGHTS TRANSITIONS OK\n")
        .unwrap();
    let child = spawn(program::FAULT).unwrap();
    identity(&mut trace, child);
    let result = wait_identified_timeout(Some(child), 0).unwrap();
    let Outcome::Faulted {
        vector,
        address,
        error,
    } = result.outcome
    else {
        panic!("fault disposition");
    };
    trace.record("fault_wait", [result.pid, OUTCOME_FAULTED, 0]);
    trace.native("fault_wait", [vector, address, error]);
    success(&mut trace, spawn(program::EXIT7).unwrap(), 7);
    census(&mut trace, base, 3);
    console.write_str("PORTABLE FAULT ISOLATION OK\n").unwrap();
    let a = spawn_with(program::HELLO_A, 0, 3).unwrap();
    let b = spawn_with(program::HELLO_A, 0, 4).unwrap();
    success(&mut trace, a, 0);
    success(&mut trace, b, 0);
    console
        .write_str("PORTABLE FP SIMD PREEMPTION OK\n")
        .unwrap();
    let mut children = [None; 15];
    for slot in &mut children {
        *slot = Some(spawn_with(program::HELLO_A, 0, 5).unwrap());
    }
    let error = spawn(program::EXIT7).unwrap_err();
    refusal(&mut trace, "capacity_refused", error.code(), ERROR_AGAIN);
    for slot in children {
        let child = slot.unwrap();
        identity(&mut trace, child);
        kill(child).unwrap();
        let result = wait_identified_timeout(Some(child), 0).unwrap();
        assert_eq!(result.outcome, Outcome::Killed);
        trace.record("kill_wait", [result.pid, OUTCOME_KILLED, 0]);
    }
    for _ in 0..200 {
        success(&mut trace, spawn(program::EXIT7).unwrap(), 7);
    }
    census(&mut trace, base, 4);
    console
        .write_str("PORTABLE CAPACITY REUSE 200 REAPS OK\n")
        .unwrap();
    let view = duplicate(start.machine, MACHINE_RIGHT_RESTART).unwrap();
    trace.record(
        "machine_grant",
        [view, MACHINE_RIGHT_RESTART, start.machine],
    );
    refusal(
        &mut trace,
        "machine_stop_rights",
        machine_stop(view, STOP_CODE_MIN).code(),
        ERROR_RIGHTS,
    );
    refusal(
        &mut trace,
        "machine_recover_rights",
        machine_recover(view).code(),
        ERROR_RIGHTS,
    );
    close(view).unwrap();
    refusal(
        &mut trace,
        "machine_stop_invalid",
        machine_stop(start.machine, 0).code(),
        ERROR_INVALID,
    );
    refusal(
        &mut trace,
        "machine_stop_handle",
        machine_stop(0, STOP_CODE_MIN).code(),
        ERROR_BAD_HANDLE,
    );
    refusal(
        &mut trace,
        "machine_recover_handle",
        machine_recover(0).code(),
        ERROR_BAD_HANDLE,
    );
    refusal(
        &mut trace,
        "machine_restart_handle",
        machine_restart(0).unwrap_err().code(),
        ERROR_BAD_HANDLE,
    );
    let wrong_kind = Cell::create(0).unwrap();
    refusal(
        &mut trace,
        "machine_wrong_kind",
        machine_stop(wrong_kind.raw(), STOP_CODE_MIN).code(),
        ERROR_BAD_HANDLE,
    );
    close(wrong_kind.raw()).unwrap();
    if start.arg == 9090 {
        let ready = Cell::create(0).unwrap();
        let child = spawn_with(program::HELLO_A, ready.raw(), 6).unwrap();
        let deadline = time() + 3000;
        while ready.read().unwrap().1 != 1 {
            assert!(time() < deadline);
            yield_now();
        }
        sleep(3);
        loop {
            match kill(child) {
                Ok(()) => break,
                Err(Error::Again) => {
                    assert!(time() < deadline);
                    yield_now();
                }
                _ => panic!("cross CPU stop refusal"),
            }
        }
        assert_eq!(wait(Some(child)), Ok(Outcome::Killed));
        close(ready.raw()).unwrap();
        assert_eq!(resource_census().unwrap(), base);
        console.write_str("PORTABLE CROSS CPU STOP OK\n").unwrap();
    }
    census(&mut trace, base, 5);
    console
        .write_str("PORTABLE MACHINE AUTHORITY REFUSAL OK\nPORTABLE SEMANTICS OK\n")
        .unwrap();
    absd_user::fault_qualification::run(console);
    trace.record("terminal", [0, getpid(), abi]);
    0
}
fn worker(start: Start) -> i32 {
    if start.arg > 100 {
        assert_eq!(
            unsafe { syscall3(SYS_WRITE, start.arg, READONLY.as_ptr() as u64, 8) },
            ERROR_BAD_HANDLE
        );
        return 0;
    }
    if (10..=17).contains(&start.arg) {
        return absd_user::fault_qualification::worker(start.arg);
    }
    match start.arg {
        2 => {
            let cell = Cell::from_raw(start.handle);
            for _ in 0..100 {
                loop {
                    let (v, value) = cell.read().unwrap();
                    yield_now();
                    match cell.transition(v, value + 1) {
                        Ok(_) => break,
                        Err(Error::Stale) => continue,
                        _ => return 91,
                    }
                }
            }
            0
        }
        3 | 4 => {
            if fp_state_probe(start.arg) {
                0
            } else {
                92
            }
        }
        5 => loop {
            sleep(1000);
        },
        6 => {
            Cell::from_raw(start.handle).transition(0, 1).unwrap();
            loop {
                core::hint::spin_loop();
            }
        }
        _ => 93,
    }
}

fn devices(start: Start) {
    if start.handle != 0 {
        let block = Block::from_raw(start.handle);
        let info = block.info().unwrap();
        assert_eq!(info.sector_bytes, 512);
        assert!(info.sectors >= 4096);
        let mut sector = [0u8; 512];
        block.read_sector(0, &mut sector).unwrap();
        assert_eq!(&sector[..8], b"ABSDARM3");
        assert_eq!(
            block.read_sector(info.sectors, &mut sector),
            Err(Error::Invalid)
        );
        let result = block.write_sector(1, &[0xa5; 512]);
        if result == Err(Error::Rights) {
            assert_eq!(block.flush(), Err(Error::Rights));
            block.read_sector(1, &mut sector).unwrap();
            if sector == [0xa5; 512] {
                start
                    .console
                    .write_str("PORTABLE VIRTIO REBOOT READ OK\n")
                    .unwrap();
            } else {
                assert_eq!(sector, [0; 512]);
            }
            start
                .console
                .write_str("PORTABLE VIRTIO READONLY OK\n")
                .unwrap();
        } else {
            assert_eq!(result, Ok(()));
            block.flush().unwrap();
            block.read_sector(1, &mut sector).unwrap();
            assert_eq!(sector, [0xa5; 512]);
            start
                .console
                .write_str("PORTABLE VIRTIO WRITE FLUSH OK\n")
                .unwrap();
        }
    }
    if start.nic != 0 {
        let nic = Nic::from_raw(start.nic);
        let info = nic.info().unwrap();
        let mut frame = [0u8; 60];
        frame[..6].fill(0xff);
        frame[6..12].copy_from_slice(&info.mac);
        frame[12..14].copy_from_slice(&[0x88, 0xb5]);
        frame[14..22].copy_from_slice(b"ABSDARM3");
        assert_eq!(nic.send(&frame[..13]), Err(Error::Invalid));
        nic.send(&frame).unwrap();
        let mut received = [0u8; NIC_FRAME_MAX];
        let len = nic.receive(&mut received, 2000).unwrap();
        frame[14] = b'R';
        assert_eq!(len, 60);
        assert_eq!(&received[..60], &frame);
        let view = duplicate(nic.raw(), RIGHT_READ).unwrap();
        assert_eq!(Nic::from_raw(view).send(&frame), Err(Error::Rights));
        close(view).unwrap();
        start
            .console
            .write_str("PORTABLE VIRTIO NETWORK TX RX RIGHTS OK\n")
            .unwrap();
    }
}
