//! Closed local-VM qualification fixture. The shared page and private test
//! syscall exist only in the explicitly compiled/selected qualification boot.
#![no_std]
#![no_main]
use absd_user::{
    Cell, Child, Outcome, Pipe, Start, close, getpid, info, kill, map, sleep, spawn_with, syscall3,
    unmap, wait, yield_now,
};
use core::sync::atomic::{AtomicU64, Ordering};
absd_user::entry!(main);
#[path = "../smp_app_scale_fixture.rs"]
mod app_scale;
const PROGRAM: u64 = absd_abi::program::SMP_USER;
const ADDRESS: u64 = absd_abi::layout::USER_REGION_BASE + 0x0c00_0000;
static XMM_SENTINELS: [[u64; 2]; 2] = [
    [0x1357_9bdf_2468_ace0, 0xfedc_ba98_7654_3210],
    [0x0246_8ace_1357_9bdf, 0x0123_4567_89ab_cdef],
];
fn word(i: usize) -> &'static AtomicU64 {
    unsafe { &*(ADDRESS as *const AtomicU64).add(i) }
}
fn load(i: usize) -> u64 {
    word(i).load(Ordering::Acquire)
}
fn store(i: usize, value: u64) {
    word(i).store(value, Ordering::Release);
}
fn test(op: u64, a: u64, b: u64) -> i64 {
    unsafe { syscall3(0x7fff, op, a, b) }
}
fn cpu() -> u64 {
    (core::arch::x86_64::__cpuid(1).ebx >> 24) as u64
}
fn require(ok: bool, error: &'static str) -> Result<(), &'static str> {
    if ok { Ok(()) } else { Err(error) }
}
fn deadline() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}
fn poll(index: usize, value: u64) -> Result<(), &'static str> {
    let begin = deadline();
    while load(index) != value {
        if deadline().wrapping_sub(begin) > 1 << 34 {
            return Err("rendezvous deadline");
        }
        core::hint::spin_loop();
    }
    Ok(())
}
fn spawn(role: u64, handle: u64) -> Result<Child, &'static str> {
    spawn_with(PROGRAM, handle, role).map_err(|_| "spawn")
}
fn exited(child: Child, status: i32) -> Result<(), &'static str> {
    require(
        wait(Some(child)).map_err(|_| "wait")? == Outcome::Exited(status),
        "exit outcome",
    )
}
fn overlap() -> Result<(), &'static str> {
    let c = cpu() as usize;
    require(c <= 1 && test(0, 0, 0) == c as i64, "CPU witness")?;
    store(c, 1);
    poll(1 - c, 1)?;
    let begin = deadline();
    let mut changed = 0u64;
    let mut previous = load(3 - c);
    // No syscall, yield or trap is used by this rendezvous. Each CPU must
    // observe >=128 changing values written by the other CPU's ring-3 loop.
    while changed < 128 || load(5 - c) < 128 {
        word(2 + c).fetch_add(1, Ordering::AcqRel);
        let peer = load(3 - c);
        if peer != previous {
            changed += 1;
            previous = peer;
            store(4 + c, changed);
        }
        if deadline().wrapping_sub(begin) > 1 << 34 {
            return Err("no concurrent user progress");
        }
        core::hint::spin_loop();
    }
    require(test(1, c as u64, changed) == 0, "overlap oracle")
}
/// Runs two CPU1 loops with no syscall, yield, or other voluntary trap. The
/// timer must switch A->B->A->B while preserving the live integer and SSE
/// sentinels in each task's saved context.
fn timer_preempt(role_b: bool) -> Result<(), &'static str> {
    let (own_progress, peer_progress, own_done, peer_done, peer_verified, own_verified) = if role_b
    {
        (67, 66, 71, 70, 72, 73)
    } else {
        (66, 67, 70, 71, 73, 72)
    };
    let own_progress = word(own_progress) as *const AtomicU64 as *mut u64;
    let peer_progress = word(peer_progress) as *const AtomicU64 as *mut u64;
    let own_done = word(own_done) as *const AtomicU64 as *mut u64;
    let peer_done = word(peer_done) as *const AtomicU64 as *mut u64;
    let own_verified = word(own_verified) as *const AtomicU64 as *mut u64;
    let peer_verified = word(peer_verified) as *const AtomicU64 as *mut u64;
    let xmm_sentinel = XMM_SENTINELS[role_b as usize].as_ptr();
    let mut intact: u64;
    unsafe {
        core::arch::asm!(
            "cmp r10, 0",
            "jne 21f",
            "mov r12, 0x1122334455667788",
            "mov r13, 0x8877665544332211",
            "jmp 22f",
            "21:",
            "mov r12, 0xabcdef0123456789",
            "mov r13, 0x76543210fedcba98",
            "22:",
            "movdqu xmm15, xmmword ptr [r11]",
            "mov qword ptr [{started}], 1",
            "2:",
            "inc qword ptr [rdi]",
            // Neither task may retire its progress producer before both
            // counters satisfy the peer's threshold. A timer can otherwise
            // switch after A's first increment and let B reach 128 first.
            "cmp qword ptr [rdi], 128",
            "jb 2b",
            "cmp qword ptr [rsi], 128",
            "jb 2b",
            "cmp r10, 0",
            "jne 5f",
            // A publishes its progress phase, then waits for B's phase.
            "mov qword ptr [rdx], 1",
            "3:",
            "cmp qword ptr [rcx], 0",
            "je 3b",
            "jmp 7f",
            // B also waits for A's phase before publishing its own.
            "5:",
            "cmp qword ptr [rcx], 1",
            "jne 2b",
            "mov qword ptr [rdx], 1",
            "6:",
            "cmp qword ptr [r8], 0",
            "je 6b",
            "7:",
            "cmp r10, 0",
            "jne 23f",
            "mov r14, 0x1122334455667788",
            "cmp r12, r14",
            "jne 9f",
            "mov r14, 0x8877665544332211",
            "cmp r13, r14",
            "jne 9f",
            "jmp 24f",
            "23:",
            "mov r14, 0xabcdef0123456789",
            "cmp r12, r14",
            "jne 9f",
            "mov r14, 0x76543210fedcba98",
            "cmp r13, r14",
            "jne 9f",
            "24:",
            "movdqu xmm14, xmmword ptr [r11]",
            "pcmpeqb xmm15, xmm14",
            "pmovmskb r14d, xmm15",
            "cmp r14d, 0xffff",
            "jne 9f",
            "mov qword ptr [r9], 1",
            "cmp r10, 0",
            "jne 8f",
            "21:",
            "cmp qword ptr [r8], 1",
            "jne 21b",
            "8:",
            "mov {intact}, 1",
            "jmp 20f",
            "9:",
            "mov {intact}, 0",
            "20:",
            in("rdi") own_progress,
            in("rsi") peer_progress,
            in("rdx") own_done,
            in("rcx") peer_done,
            in("r8") peer_verified,
            in("r9") own_verified,
            in("r10") role_b as u64,
            in("r11") xmm_sentinel,
            started = in(reg) word(if role_b { 65 } else { 64 }),
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("xmm14") _,
            out("xmm15") _,
            intact = lateout(reg) intact,
            options(nostack),
        );
    }
    require(intact == 1, "timer context sentinel")
}
fn case(id: u64) -> Result<(), &'static str> {
    require(test(2, id, 0) == 0, "case record")
}
fn stop(role: u64, handle: u64) -> Result<(), &'static str> {
    stop_at(role, handle, None)
}
fn stop_at(role: u64, handle: u64, round: Option<u64>) -> Result<(), &'static str> {
    store(20, 0);
    let child = spawn(role, handle)?;
    let pid = info(Some(child)).map_err(|_| "child info")?.pid;
    poll(20, pid)?;
    if let Some(round) = round {
        if round % 2 == 0 {
            let before = test(11, 0, 0);
            let begin = deadline();
            while test(11, 0, 0) == before {
                require(
                    deadline().wrapping_sub(begin) < 1 << 34,
                    "victim not timer-preempted",
                )?;
            }
        }
        let begin = deadline();
        let delay = (1 + (round * 13) % 16) << 17;
        while deadline().wrapping_sub(begin) < delay {
            core::hint::spin_loop();
        }
    }
    kill(child).map_err(|_| "kill")?;
    require(
        wait(Some(child)).map_err(|_| "kill wait")? == Outcome::Killed,
        "kill outcome",
    )?;
    require(wait(Some(child)).is_err(), "duplicate outcome")
}
fn benchmark_root() -> Result<(), &'static str> {
    for phase in 1..=3 {
        for i in 110..120 {
            store(i, 0);
        }
        let cell = if phase == 3 {
            Some(Cell::create(0).map_err(|_| "bench cell")?)
        } else {
            None
        };
        let handle = cell.map_or(0, Cell::raw);
        let first = spawn(48 + 2 * phase, handle)?;
        let second = spawn(49 + 2 * phase, handle)?;
        let begin = deadline();
        while load(110) == 0 || load(111) == 0 {
            require(deadline().wrapping_sub(begin) < 1 << 34, "bench readiness")?;
            yield_now();
        }
        require(test(17, phase, 0) == 0, "bench start")?;
        store(112, 1);
        exited(first, 7)?;
        exited(second, 7)?;
        if let Some(cell) = cell {
            require(
                cell.read().map_err(|_| "bench result")? == (4000, 4000),
                "bench exact transitions",
            )?;
            close(cell.raw()).map_err(|_| "bench close")?;
        }
        require(test(18, phase, 0) == 0, "bench done")?;
    }
    Ok(())
}
fn benchmark_actor(start: Start) -> Result<(), &'static str> {
    let index = (start.arg & 1) as usize;
    store(110 + index, 1);
    while load(112) == 0 {
        yield_now();
    }
    let units = match start.arg {
        50 | 51 => {
            let n = 1u64 << 26;
            let checksum: u64;
            unsafe {
                core::arch::asm!(
                    "2:", "add rax, rcx", "inc rcx", "dec rdx", "jnz 2b",
                    inout("rax") index as u64 => checksum,
                    inout("rcx") 0u64 => _, inout("rdx") n => _, options(nostack),
                );
            }
            require(checksum == n * (n - 1) / 2 + index as u64, "bench checksum")?;
            store(118 + index, checksum);
            n
        }
        52 | 53 => {
            let pid = getpid();
            for _ in 0..10_000 {
                require(getpid() == pid, "bench PID")?;
            }
            10_000
        }
        54 | 55 => {
            let cell = Cell::from_raw(start.handle);
            for round in 0..2_000 {
                let target = 2 * round + index as u64;
                loop {
                    let (version, value) = cell.read().map_err(|_| "bench read")?;
                    if value == target {
                        require(
                            cell.transition(version, target + 1)
                                .map_err(|_| "bench transition")?
                                == target + 1,
                            "bench version",
                        )?;
                        break;
                    }
                    require(value < target, "bench overwritten value")?;
                    cell.wait_change(version).map_err(|_| "bench wake")?;
                }
            }
            2_000
        }
        _ => return Err("bench role"),
    };
    store(116 + index, units);
    Ok(())
}
fn benchmark_scale_root() -> Result<(), &'static str> {
    require(cpu() == 0, "scale controller placement")?;
    for phase in 1..=3 {
        for i in 110..=136 {
            store(i, 0);
        }
        let cells: [Option<Cell>; 3] = if phase == 3 {
            [
                Some(Cell::create(0).map_err(|_| "scale cell")?),
                Some(Cell::create(0).map_err(|_| "scale cell")?),
                Some(Cell::create(0).map_err(|_| "scale cell")?),
            ]
        } else {
            [None; 3]
        };
        let mut children: [Option<Child>; 6] = [None; 6];
        for index in 0..6 {
            let handle = cells[index / 2].map_or(0, Cell::raw);
            children[index] = Some(spawn(300 + (phase - 1) * 6 + index as u64, handle)?);
        }

        let begin = deadline();
        while (0..6).any(|index| load(110 + index) == 0) {
            require(deadline().wrapping_sub(begin) < 1 << 34, "scale readiness")?;
            yield_now();
        }
        require(test(17, phase, 0) == 0, "scale phase start")?;
        store(118, 1);
        for child in children.into_iter().flatten() {
            exited(child, 7)?;
        }

        if phase == 3 {
            for cell in cells.into_iter().flatten() {
                require(
                    cell.read().map_err(|_| "scale cell read")? == (4000, 4000),
                    "scale exact transitions",
                )?;
                close(cell.raw()).map_err(|_| "scale cell close")?;
            }
        }
        require(test(18, phase, 0) == 0, "scale phase done")?;
    }
    Ok(())
}
fn benchmark_scale_actor(start: Start) -> Result<(), &'static str> {
    let offset = start.arg - 300;
    let phase = offset / 6 + 1;
    let index = (offset % 6) as usize;
    let cpus = test(40, 0, 0);
    require(matches!(cpus, 1 | 2 | 4 | 6), "scale CPU count")?;
    require(cpu() == index as u64 % cpus as u64, "scale actor placement")?;
    require(test(41, 0, 0) == 0, "scale actor registration")?;
    let expected_pid = if phase == 2 { getpid() } else { 0 };
    let shortened = phase == 2 && index == 5 && test(39, 0, 0) == 1;

    store(110 + index, 1);
    while load(118) == 0 {
        yield_now();
    }
    let units = match phase {
        1 => {
            let n = 1u64 << 26;
            let checksum: u64;
            unsafe {
                core::arch::asm!(
                    "2:", "add rax, rcx", "inc rcx", "dec rdx", "jnz 2b",
                    inout("rax") index as u64 => checksum,
                    inout("rcx") 0u64 => _, inout("rdx") n => _, options(nostack),
                );
            }
            require(checksum == n * (n - 1) / 2 + index as u64, "scale checksum")?;
            store(130 + index, checksum);
            n
        }
        2 => {
            let count = if shortened { 9_999 } else { 10_000 };
            for _ in 0..count {
                require(getpid() == expected_pid, "scale PID")?;
            }
            count
        }
        3 => {
            let cell = Cell::from_raw(start.handle);
            let parity = (index % 2) as u64;
            for round in 0..2_000 {
                let target = 2 * round + parity;
                loop {
                    let (version, value) = cell.read().map_err(|_| "scale cell read")?;
                    if value == target {
                        require(
                            cell.transition(version, target + 1)
                                .map_err(|_| "scale transition")?
                                == target + 1,
                            "scale cell version",
                        )?;
                        break;
                    }
                    require(value < target, "scale cell overwritten")?;
                    cell.wait_change(version).map_err(|_| "scale cell wake")?;
                }
            }
            2_000
        }
        _ => return Err("scale actor phase"),
    };
    store(120 + index, units);
    Ok(())
}
fn root() -> Result<(), &'static str> {
    require(cpu() == 0, "controller placement")?;
    let child = spawn(1, 0)?;
    overlap()?;
    require(test(4, 0, 0) == 0, "bounded BKL hold")?;
    for n in 0..3000 {
        require(getpid() == 1, "BSP syscall")?;
        if n % 16 == 0 {
            yield_now();
        }
    }
    exited(child, 7)?;
    case(1)?;

    let pipe = Pipe::create().map_err(|_| "pipe")?;
    let peer = spawn(3, pipe.raw())?;
    let peer_pid = info(Some(peer)).map_err(|_| "pipe peer")?.pid;
    let mut byte = [0u8; 1];
    for _ in 0..128 {
        poll(30, peer_pid)?;
        pipe.write_once(b"a").map_err(|_| "BSP pipe write")?;
        store(30, 0);
        require(
            pipe.read_once(&mut byte).map_err(|_| "BSP pipe read")? == 1 && byte == *b"b",
            "pipe result",
        )?;
    }
    exited(peer, 7)?;
    close(pipe.raw()).map_err(|_| "pipe close")?;
    case(2)?;

    for _ in 0..32 {
        exited(spawn(7, 0)?, 7)?;
    }
    case(3)?;
    exited(spawn(5, 0)?, 7)?;
    case(4)?;
    let fault = spawn(9, 0)?;
    require(
        matches!(
            wait(Some(fault)).map_err(|_| "AP fault wait")?,
            Outcome::Faulted { vector: 14, .. }
        ),
        "AP fault containment",
    )?;
    require(getpid() == 1, "BSP after AP fault")?;
    case(5)?;
    exited(spawn(27, 0)?, 7)?;
    case(6)?;

    stop(11, 0)?;
    case(7)?;
    stop(13, 0)?;
    case(8)?;
    stop(15, 0)?;
    case(9)?;
    stop(17, 0)?;
    case(10)?;
    let cell = Cell::create(7).map_err(|_| "cell")?;
    stop(19, cell.raw())?;
    require(
        cell.read().map_err(|_| "mutating result")? == (1, 99),
        "bounded mutation retirement",
    )?;
    close(cell.raw()).map_err(|_| "cell close")?;
    case(11)?;
    stop(21, 0)?;
    case(12)?;
    stop(23, 0)?;
    case(13)?;
    exited(spawn(25, 0)?, 7)?;
    case(14)?;
    let cell = Cell::create(0).map_err(|_| "storm cell")?;
    let peer = spawn(29, cell.raw())?;
    for _ in 0..1000 {
        let (version, _) = cell.read().map_err(|_| "storm read")?;
        let _ = cell.transition(version, version + 1);
        yield_now();
    }
    exited(peer, 7)?;
    close(cell.raw()).map_err(|_| "storm close")?;
    case(15)?;
    // Allow AP to enter the no-work idle path before a new publication wakes it.
    sleep(5);
    exited(spawn(7, 0)?, 7)?;
    case(16)?;
    // The BSP remains in userspace after waking a halted AP. A missing remote
    // wake IPI cannot be hidden by the BSP scheduler's idle scan.
    store(40, 0);
    let pipe = Pipe::create().map_err(|_| "idle pipe")?;
    let peer = spawn(3, pipe.raw())?;
    let pid = info(Some(peer)).map_err(|_| "idle peer")?.pid;
    poll(30, pid)?;
    let begin = deadline();
    while test(6, 0, 0) != 1 {
        require(
            deadline().wrapping_sub(begin) < 1 << 34,
            "AP failed to idle",
        )?;
    }
    require(test(7, 0, 0) == 0, "idle witness")?;
    pipe.write_once(b"x").map_err(|_| "idle wake write")?;
    poll(40, 1)?;
    exited(peer, 7)?;
    close(pipe.raw()).map_err(|_| "idle pipe close")?;
    case(17)?;
    if test(8, 0, 0) == 1 {
        for i in 66..=73 {
            store(i, 0);
        }
        require(test(9, 0, 0) == 0, "timer probe arm")?;
        let a = spawn(33, 0)?;
        let b = spawn(35, 0)?;
        let begin = deadline();
        let complete = loop {
            if load(72) == 1 && load(73) == 1 {
                break true;
            }
            if deadline().wrapping_sub(begin) > 1 << 34 {
                break false;
            }
            core::hint::spin_loop();
        };
        // Keep the kernel oracle unconditional: an incomplete handshake must
        // fail at the private qualification boundary, not silently skip it.
        require(test(10, load(72), load(73)) == 0, "timer switch oracle")?;
        require(complete, "timer switch rendezvous")?;
        exited(a, 7)?;
        exited(b, 7)?;
        case(18)?;
        for round in 0..128 {
            stop_at(11, 0, Some(round))?;
        }
        case(19)?;
        let mut peers = [None; 8];
        for (n, peer) in peers.iter_mut().enumerate() {
            *peer = Some(spawn(37 + n as u64, 0)?);
        }
        let begin = deadline();
        while (96..104).any(|i| load(i) != 1) && deadline().wrapping_sub(begin) < 1 << 34 {
            core::hint::spin_loop();
        }
        require(test(13, 0, 0) == 0, "fairness accounting")?;
        for peer in peers {
            exited(peer.unwrap(), 7)?;
        }
        case(20)?;
        for round in 0..16 {
            store(104, round);
            let victim = spawn(47, 0)?;
            require(
                matches!(
                    wait(Some(victim)).map_err(|_| "timer fault wait")?,
                    Outcome::Faulted { vector: 14, .. }
                ),
                "timer fault outcome",
            )?;
            exited(spawn(49, 0)?, 7)?;
            require(getpid() == 1, "BSP continued after timer fault")?;
        }
        require(test(14, 0, 0) == 0, "timer terminal accounting")?;
        case(21)?;
    }
    if test(19, 0, 0) == 1 {
        modern_root()?;
    }
    Ok(())
}
fn modern_ready() -> Result<(), &'static str> {
    let begin = deadline();
    while load(200) != 1 {
        require(
            deadline().wrapping_sub(begin) < 1 << 34,
            "migration initial readiness",
        )?;
        yield_now();
    }
    Ok(())
}
fn modern_move(pid: u64, to: u64) -> Result<(), &'static str> {
    require(test(20, pid, to) == 0, "migration request")
}
fn modern_root() -> Result<(), &'static str> {
    for _ in 0..32 {
        store(200, 0);
        store(201, 0);
        let pipe = Pipe::create().map_err(|_| "migration pipe")?;
        let child = spawn(56, pipe.raw())?;
        let pid = info(Some(child)).map_err(|_| "migration child")?.pid;
        modern_ready()?;
        require(test(26, pid, 0) == 0, "arm block cancellation")?;
        modern_move(pid, 1)?;
        store(201, 1);
        poll(200, 2)?;
        let begin = deadline();
        while info(Some(child))
            .map_err(|_| "migration blocked info")?
            .state
            != absd_user::INFO_STATE_WAITING
        {
            require(
                deadline().wrapping_sub(begin) < 1 << 34,
                "migration block deadline",
            )?;
            yield_now();
        }
        require(
            test(20, pid, 0) == absd_abi::syscall::ERROR_AGAIN,
            "blocked migration refusal",
        )?;
        pipe.write_once(b"m").map_err(|_| "migration wake")?;
        poll(200, 3)?;
        modern_move(pid, 0)?;
        store(201, 2);
        exited(child, 7)?;
        require(
            wait(Some(child)) == Err(absd_user::Error::BadHandle),
            "migration stale wait",
        )?;
        close(pipe.raw()).map_err(|_| "migration close")?;
    }
    case(22)?;
    for _ in 0..16 {
        store(200, 0);
        store(201, 0);
        let child = spawn(58, 0)?;
        let pid = info(Some(child)).map_err(|_| "migration victim")?.pid;
        modern_ready()?;
        modern_move(pid, 1)?;
        store(201, 1);
        poll(200, 2)?;
        require(test(24, pid, 0) == 0, "arm stop cancellation")?;
        kill(child).map_err(|_| "migrated stop")?;
        require(
            wait(Some(child)).map_err(|_| "migrated fence")? == Outcome::Killed,
            "migrated stop outcome",
        )?;
    }
    case(23)?;
    for _ in 0..16 {
        store(200, 0);
        store(201, 0);
        let child = spawn(59, 0)?;
        let pid = info(Some(child)).map_err(|_| "migration fault child")?.pid;
        modern_ready()?;
        modern_move(pid, 1)?;
        store(201, 1);
        poll(200, 2)?;
        store(201, 2);
        require(
            matches!(
                wait(Some(child)).map_err(|_| "migration fault wait")?,
                Outcome::Faulted { vector: 14, .. }
            ),
            "migration fault containment",
        )?;
        require(getpid() == 1, "CPU0 after migrated fault")?;
    }
    case(24)?;
    for _ in 0..16 {
        store(200, 0);
        store(201, 0);
        let child = spawn(60, 0)?;
        let pid = info(Some(child)).map_err(|_| "steal child")?.pid;
        modern_ready()?;
        require(test(21, pid, 0) == 0, "idle steal arm")?;
        store(201, 1);
        poll(200, 2)?;
        exited(child, 7)?;
    }
    case(25)?;
    require(test(23, 0, 0) == 0, "modern queue oracle")
}
fn migration_yields(command: u64, ready: u64, destination: u64) -> Result<(), &'static str> {
    let intact: u64;
    unsafe {
        core::arch::asm!(
            "mov r12,0x13579bdf2468ace0", "mov r13,0xfedcba9876543210",
            "movdqu xmm15,xmmword ptr [r8]",
            // Publish readiness only after the live sentinels exist.
            "mov qword ptr [r10],r11",
            "rdtsc","shl rdx,32","or rax,rdx","mov r15,rax",
            "2:","mov rax,2","int 0x80",
            "rdtsc","shl rdx,32","or rax,rdx","sub rax,r15",
            "mov rcx,0x400000000","cmp rax,rcx","ja 3f",
            "cmp qword ptr [rdi],rsi","jb 2b",
            // Keep sentinels live until the destination CPU is observed.
            "push rbx","mov eax,1","cpuid","shr ebx,24","mov ecx,ebx","pop rbx",
            "cmp rcx,r9","jne 2b",
            "mov r14,0x13579bdf2468ace0","cmp r12,r14","jne 3f",
            "mov r14,0xfedcba9876543210","cmp r13,r14","jne 3f",
            "movdqu xmm14,xmmword ptr [r8]","pcmpeqb xmm14,xmm15","pmovmskb eax,xmm14",
            "cmp eax,65535","jne 3f","mov rax,1","jmp 4f",
            "3:","xor eax,eax","4:",
            in("rdi") word(201) as *const AtomicU64,in("rsi") command,
            in("r8") XMM_SENTINELS[0].as_ptr(),in("r9") destination,
            in("r10") word(200) as *const AtomicU64,in("r11") ready,
            lateout("rax") intact,out("rcx") _,out("rdx") _,
            out("r12") _,out("r13") _,out("r14") _,out("r15") _,out("xmm14") _,out("xmm15") _,
        );
    }
    require(intact == 1, "migration integer/SSE context and destination")
}
fn modern_actor(start: Start) -> Result<(), &'static str> {
    require(
        cpu() == 0 && test(22, 0, 0) == 0,
        "migration source user witness",
    )?;
    migration_yields(1, 1, 1)?;
    require(test(22, 1, 0) == 1, "migration destination user witness")?;
    store(200, 2);
    match start.arg {
        56 => {
            let pipe = Pipe::from_raw(start.handle);
            let mut byte = [0u8; 1];
            require(
                pipe.read_once(&mut byte).map_err(|_| "migrated read")? == 1 && byte == *b"m",
                "migrated wake result",
            )?;
            require(cpu() == 1, "blocked owner changed")?;
            migration_yields(2, 3, 0)?;
            require(
                cpu() == 0 && test(22, 2, 0) == 0,
                "return migration user witness",
            )?;
        }
        58 => loop {
            core::hint::spin_loop();
        },
        59 => {
            while load(201) != 2 {
                core::hint::spin_loop();
            }
            unsafe {
                (0x10_0000 as *mut u64).write_volatile(1);
            }
            return Err("migrated fault returned");
        }
        60 => {}
        _ => return Err("unknown modern role"),
    }
    Ok(())
}
fn actor(start: Start) -> Result<(), &'static str> {
    require(test(0, 0, 0) == cpu() as i64, "kernel/user CPU mismatch")?;
    if (200..=209).contains(&start.arg) {
        require(
            cpu() == (start.arg - 200) / 2 + 1,
            "multicore pressure placement",
        )?;
    }
    require(
        (start.arg >= 56 && test(19, 0, 0) == 1)
            || cpu()
                == if test(16, 0, 0) == 1 {
                    0
                } else {
                    start.arg & 1
                },
        "fixed actor placement",
    )?;
    match start.arg {
        56..=60 => modern_actor(start)?,
        50..=55 => benchmark_actor(start)?,
        1 => {
            overlap()?;
            poll(21, 1)?;
            for n in 0..3000 {
                getpid();
                if n % 16 == 0 {
                    yield_now();
                }
            }
        }
        3 => {
            let pipe = Pipe::from_raw(start.handle);
            let mut byte = [0u8; 1];
            for _ in 0..128 {
                store(30, 0);
                require(
                    pipe.read_once(&mut byte).map_err(|_| "AP pipe read")? == 1,
                    "AP pipe result",
                )?;
                if byte == *b"x" {
                    store(40, 1);
                    return Ok(());
                }
                require(byte == *b"a", "AP pipe value")?;
                poll(30, 1)?;
                pipe.write_once(b"b").map_err(|_| "AP pipe write")?;
            }
        }
        5 => {
            for _ in 0..32 {
                exited(spawn(6, 0)?, 7)?;
            }
        }
        6 | 7 => {
            yield_now();
            sleep(1);
            yield_now();
        }
        8 | 9 => {
            unsafe {
                (0x10_0000 as *mut u64).write_volatile(1);
            }
            return Err("fault resumed");
        }
        10 | 11 => {
            store(20, getpid());
            loop {
                core::hint::black_box(0x1234u64.wrapping_mul(deadline()));
                core::hint::spin_loop();
            }
        }
        13 => {
            test(5, 0, 0);
            return Err("killed handler returned");
        }
        15 => {
            test(3, 0xffff, 0);
            spawn(7, 0)?;
            return Err("Created spawner returned");
        }
        17 => {
            test(3, absd_abi::syscall::SYS_MAP, 0);
            map(1).map_err(|_| "killed map")?;
            return Err("mapping returned");
        }
        19 => {
            test(3, absd_abi::syscall::SYS_CELL_TRANSITION, 0);
            Cell::from_raw(start.handle)
                .transition(0, 99)
                .map_err(|_| "killed cell")?;
            return Err("mutation returned");
        }
        21 => {
            test(3, u64::MAX, 0);
            sleep(100);
            return Err("blocked victim returned");
        }
        23 => {
            test(3, absd_abi::syscall::SYS_GETPID, 0);
            getpid();
            return Err("read-only victim returned");
        }
        25 => {
            stop(10, 0)?;
        }
        27 => {
            for _ in 0..32 {
                exited(spawn(6, 0)?, 7)?;
                let f = spawn(8, 0)?;
                require(
                    matches!(
                        wait(Some(f)).map_err(|_| "BSP fault wait")?,
                        Outcome::Faulted { vector: 14, .. }
                    ),
                    "BSP fault containment",
                )?;
            }
            // Exercise local mappings under concurrent ownership on the AP.
            let page = map(1).map_err(|_| "AP mapping")?;
            unsafe {
                page.write_volatile(55);
            }
            require(unsafe { page.read_volatile() } == 55, "AP map contents")?;
            unmap(page, 1).map_err(|_| "AP unmap")?;
        }
        29 => {
            let cell = Cell::from_raw(start.handle);
            for _ in 0..1000 {
                let (version, _) = cell.read().map_err(|_| "AP storm read")?;
                let _ = cell.transition(version, version + 1);
                yield_now();
            }
        }
        31 | 200 | 202 | 204 | 206 | 208 => {
            while load(32) == 0 {
                getpid();
                yield_now();
            }
            if start.arg == 31 {
                require(test(15, 0, 0) != 1, "startup negative outcome")?;
            }
        }
        37..=44 => {
            let index = (start.arg - 37) as usize;
            while (80..88).any(|i| load(i) < 128) {
                word(80 + index).fetch_add(1, Ordering::AcqRel);
                if index == 0 {
                    getpid();
                } // No yield: syscalls must not reset the slice.
                if index % 4 == 2 {
                    yield_now();
                }
                if index % 4 == 3 {
                    sleep(1);
                }
            }
            for n in 0..256 {
                word(80 + index).fetch_add(1, Ordering::AcqRel);
                if index % 4 == 2 && n % 16 == 0 {
                    yield_now();
                }
                if index % 4 == 3 && n % 32 == 0 {
                    sleep(1);
                }
            }
            store(96 + index, 1);
        }
        45 | 201 | 203 | 205 | 207 | 209 => {
            if start.arg != 45 {
                pressure_preemption(start.arg)?;
            }
            let mut rounds = 0;
            while load(32) == 0 {
                let begin = deadline();
                while deadline().wrapping_sub(begin) < 1 << 24 {
                    core::hint::spin_loop();
                }
                getpid();
                yield_now();
                rounds += 1;
                if rounds % 4 == 0 {
                    sleep(1);
                }
            }
        }
        47 | 49 => {
            let before = test(11, 0, 0);
            let begin = deadline();
            while deadline().wrapping_sub(begin) < 1 << 24 {
                core::hint::spin_loop();
            }
            require(
                test(11, 0, 0) > before,
                "terminal fixture lacked timer interrupt",
            )?;
            let begin = deadline();
            while deadline().wrapping_sub(begin) < (1 + load(104) * 17 % 16) << 15 {
                core::hint::spin_loop();
            }
            if start.arg == 47 {
                unsafe {
                    (0x10_0000 as *mut u64).write_volatile(1);
                }
                return Err("timer fault resumed");
            }
        }
        33 => timer_preempt(false)?,
        35 => timer_preempt(true)?,
        _ => return Err("unknown fixture role"),
    }
    Ok(())
}

/// This interval cannot yield before a calibrated slice expires. The kernel
/// publishes completion only after saving this actor's live integer/SSE frame;
/// the actor checks restoration before returning to ordinary pressure work.
fn pressure_preemption(role: u64) -> Result<(), &'static str> {
    let c = cpu();
    let completion = word(460 + c as usize - 1) as *const AtomicU64;
    let xmm = XMM_SENTINELS[((c - 1) & 1) as usize].as_ptr();
    let intact: u64;
    unsafe {
        core::arch::asm!(
            "rdtsc", "shl rdx, 32", "or rax, rdx", "mov r8, rax",
            "mov r12, rsi",
            "movdqu xmm15, xmmword ptr [r11]",
            "2:",
            "rdtsc", "shl rdx, 32", "or rax, rdx", "sub rax, r8",
            "cmp rax, r9", "jae 4f",
            "cmp qword ptr [rdi], 1", "je 3f",
            "pause", "jmp 2b",
            "3:",
            "cmp r12, rsi", "jne 4f",
            "movdqu xmm14, xmmword ptr [r11]",
            "pcmpeqb xmm15, xmm14", "pmovmskb edx, xmm15",
            "cmp edx, 0xffff", "jne 4f",
            "mov eax, 1", "jmp 5f",
            "4:", "xor eax, eax",
            "5:",
            in("rdi") completion,
            in("rsi") 0x1122_3344_5566_7788u64 ^ role,
            in("r11") xmm,
            in("r9") 1u64 << 34,
            lateout("rax") intact,
            lateout("rdx") _,
            out("r8") _,
            out("r12") _,
            out("xmm14") _,
            out("xmm15") _,
        );
    }
    require(intact == 1, "pressure timer frame/resume or deadline")?;
    require(test(37, 0, 0) == 0, "pressure timer resume witness")
}
#[repr(C, align(16))]
struct FpuConfig {
    mxcsr: u32,
    fcw: u16,
    padding: [u8; 10],
    xmm0: [u64; 2],
    xmm7: [u64; 2],
    observed_mxcsr: u32,
    observed_fcw: u16,
    padding2: [u8; 10],
}
fn fpu_config(peer: bool) -> FpuConfig {
    FpuConfig {
        mxcsr: if peer { 0x5fa0 } else { 0x3fa0 },
        fcw: if peer { 0x0b7f } else { 0x077f },
        padding: [0; 10],
        xmm0: XMM_SENTINELS[usize::from(peer)],
        xmm7: XMM_SENTINELS[usize::from(!peer)],
        observed_mxcsr: 0,
        observed_fcw: 0,
        padding2: [0; 10],
    }
}
fn fpu_migrate_phase(command: u64, ready: u64, destination: u64) -> Result<(), &'static str> {
    let mut config = fpu_config(false);
    let intact: u64;
    unsafe {
        core::arch::asm!(
            "ldmxcsr [r8]", "fldcw [r8+4]",
            "movdqu xmm0,xmmword ptr [r8+16]", "movdqu xmm7,xmmword ptr [r8+32]",
            "mov qword ptr [r10],r11",
            "rdtsc", "shl rdx,32", "or rax,rdx", "mov r15,rax", "mov qword ptr [r12],rax",
            // No voluntary trap until enough time has passed for both CPUs'
            // local preemption; state remains live during that interval.
            "2:", "rdtsc", "shl rdx,32", "or rax,rdx", "sub rax,r15",
            "mov rcx,0x400000000", "cmp rax,rcx", "ja 3f",
            "cmp rax,0x20000000", "jb 2b",
            "mov eax,2", "int 0x80",
            "cmp qword ptr [rdi],rsi", "jb 2b",
            "push rbx", "mov eax,1", "cpuid", "shr ebx,24", "mov ecx,ebx", "pop rbx",
            "cmp rcx,r9", "jne 2b",
            "stmxcsr [r8+48]", "fnstcw [r8+52]",
            "mov eax,[r8+48]", "cmp eax,[r8]", "jne 3f",
            "mov ax,[r8+52]", "cmp ax,[r8+4]", "jne 3f",
            "movdqu xmm3,xmmword ptr [r8+16]", "pcmpeqb xmm3,xmm0", "pmovmskb eax,xmm3", "cmp eax,65535", "jne 3f",
            "movdqu xmm3,xmmword ptr [r8+32]", "pcmpeqb xmm3,xmm7", "pmovmskb eax,xmm3", "cmp eax,65535", "jne 3f",
            // 2.5 rounds down to2 under this task's MXCSR. Precision status
            // was seeded, so arithmetic does not alter the expected image.
            "mov eax,0x40200000", "movd xmm2,eax", "cvtss2si eax,xmm2", "cmp eax,2", "jne 3f",
            // Kernel records the live FXSAVE contents at the same CPL3 trap.
            "mov esi,2", "sub rsi,r9", "mov edi,28", "xor edx,edx", "mov eax,0x7fff", "int 0x80",
            "cmp rax,1", "jne 3f", "mov eax,1", "jmp 4f", "3:", "xor eax,eax", "4:",
            inlateout("rdi") word(201) as *const AtomicU64 => _,inlateout("rsi") command => _,
            in("r8") &mut config as *mut FpuConfig,in("r9") destination,
            in("r10") word(200) as *const AtomicU64,in("r11") ready,
            in("r12") word(202) as *const AtomicU64,
            lateout("rax") intact,out("rcx") _,out("rdx") _,
            out("r15") _,out("xmm0") _,out("xmm7") _,out("xmm2") _,out("xmm3") _,
        );
    }
    require(
        intact == 1,
        "FPU migration live control/arithmetic/XMM state",
    )
}
fn fpu_peer() -> Result<(), &'static str> {
    let mut config = fpu_config(true);
    let intact: u64;
    unsafe {
        core::arch::asm!(
            "ldmxcsr [r8]", "fldcw [r8+4]",
            "movdqu xmm0,xmmword ptr [r8+16]", "movdqu xmm7,xmmword ptr [r8+32]",
            "mov edi,28", "mov esi,4", "xor edx,edx", "mov eax,0x7fff", "int 0x80", "cmp rax,1", "jne 3f",
            "mov qword ptr [r10],1",
            "2:", "stmxcsr [r8+48]", "fnstcw [r8+52]",
            "mov eax,[r8+48]", "cmp eax,[r8]", "jne 3f",
            "mov ax,[r8+52]", "cmp ax,[r8+4]", "jne 3f",
            "movdqu xmm3,xmmword ptr [r8+16]", "pcmpeqb xmm3,xmm0", "pmovmskb eax,xmm3", "cmp eax,65535", "jne 3f",
            "movdqu xmm3,xmmword ptr [r8+32]", "pcmpeqb xmm3,xmm7", "pmovmskb eax,xmm3", "cmp eax,65535", "jne 3f",
            "mov eax,0x40200000", "movd xmm2,eax", "cvtss2si eax,xmm2", "cmp eax,3", "jne 3f",
            "lock inc qword ptr [r12]", "pause", "jmp 2b",
            // Any contamination is a contained user fault and the controller
            // must reject its outcome; only a remote kill is acceptable.
            "3:", "mov qword ptr [r11],1", "ud2",
            in("r8") &mut config as *mut FpuConfig,
            in("r10") word(220) as *const AtomicU64,in("r11") word(222) as *const AtomicU64,
            in("r12") word(221) as *const AtomicU64,
            lateout("rax") intact,out("rdi") _,out("rsi") _,out("rdx") _,
            out("xmm0") _,out("xmm7") _,out("xmm2") _,out("xmm3") _,
        );
    }
    let _ = intact;
    Err("FPU peer unexpectedly returned")
}
fn fpu_root() -> Result<(), &'static str> {
    store(220, 0);
    store(221, 0);
    store(222, 0);
    let peer = spawn(62, 0)?;
    poll(220, 1)?;
    for _ in 0..16 {
        store(200, 0);
        store(201, 0);
        store(202, 0);
        let child = spawn(61, 0)?;
        let pid = info(Some(child)).map_err(|_| "FPU migrant info")?.pid;
        modern_ready()?;
        modern_move(pid, 1)?;
        store(201, 1);
        poll(200, 3)?;
        modern_move(pid, 0)?;
        store(201, 2);
        exited(child, 7)?;
        require(load(222) == 0, "FPU peer contamination")?;
    }
    // Dirty ordinary AP exit, then clean-default successor.
    exited(spawn(65, 0)?, 7)?;
    exited(spawn(63, 0)?, 7)?;
    let fault = spawn(64, 0)?;
    require(
        matches!(
            wait(Some(fault)).map_err(|_| "AP XM wait")?,
            Outcome::Faulted {
                vector: 19,
                error: 0,
                ..
            }
        ),
        "AP XM containment",
    )?;
    exited(spawn(63, 0)?, 7)?;
    let before = load(221);
    let begin = deadline();
    while load(221) <= before {
        require(
            deadline().wrapping_sub(begin) < 1 << 34,
            "FPU peer post-fault progress",
        )?;
        core::hint::spin_loop();
    }
    require(
        load(222) == 0 && test(29, before, 0) == 1,
        "FPU peer survived AP fault",
    )?;
    kill(peer).map_err(|_| "FPU peer stop")?;
    require(
        wait(Some(peer)).map_err(|_| "FPU peer fence")? == Outcome::Killed,
        "FPU peer killed outcome",
    )?;
    exited(spawn(63, 0)?, 7)?;
    require(test(23, 0, 0) == 0, "FPU migration queue proof")?;
    case(1)
}
fn fpu_actor(start: Start) -> Result<(), &'static str> {
    match start.arg {
        61 => {
            require(cpu() == 0 && test(22, 0, 0) == 0, "FPU migration source")?;
            fpu_migrate_phase(1, 1, 1)?;
            require(test(22, 1, 0) == 1, "FPU migration remote")?;
            store(200, 2);
            fpu_migrate_phase(2, 3, 0)?;
            require(test(22, 2, 0) == 0, "FPU migration returned")?;
        }
        62 => return fpu_peer(),
        63 => {
            require(test(28, 3, 0) == 1, "fresh FPU control defaults")?;
        }
        64 => unsafe {
            let mxcsr = 0x1d80u32;
            core::arch::asm!("ldmxcsr [{mx}]","mov eax,0x3f800000","movd xmm2,eax","xorps xmm3,xmm3","divss xmm2,xmm3",mx=in(reg)&mxcsr,out("eax")_,out("xmm2")_,out("xmm3")_);
            return Err("AP XM not delivered");
        },
        65 => unsafe {
            let config = fpu_config(false);
            core::arch::asm!("ldmxcsr [{p}]","fldcw [{p}+4]","movdqu xmm0,xmmword ptr [{p}+16]","movdqu xmm7,xmmword ptr [{p}+32]",p=in(reg)&config,out("xmm0")_,out("xmm7")_);
        },
        _ => return Err("unknown FPU migration role"),
    }
    Ok(())
}

include!("../smp_nway.rs");

fn main(start: Start) -> i32 {
    // The private syscall refuses before touching the scratch mapping in a
    // normal boot, so invoking this catalog program there is side-effect free.
    if test(0, 0, 0) < 0 {
        return 86;
    }
    let nway = test(30, 0, 0) > 0;
    let result = if test(42, 0, 0) == 6 {
        app_scale::run(start)
    } else if nway && start.arg == 120 {
        nway_root()
    } else if nway {
        nway_actor(start)
    } else if (300..=317).contains(&start.arg) {
        if test(38, 0, 0) == 6 {
            benchmark_scale_actor(start)
        } else {
            Err("scale benchmark mode")
        }
    } else if start.arg == 66 && test(27, 0, 0) == 1 {
        fpu_root()
    } else if (61..=65).contains(&start.arg) && test(27, 0, 0) == 1 {
        fpu_actor(start)
    } else if start.arg == 0 {
        if test(16, 0, 0) > 0 {
            match test(38, 0, 0) {
                2 => benchmark_root(),
                6 => benchmark_scale_root(),
                _ => Err("benchmark mode"),
            }
        } else {
            root()
        }
    } else {
        actor(start)
    };
    match result {
        Ok(()) => {
            if start.arg == 120
                || start.arg == 0
                || start.arg == 66
                || start.arg == 31
                || start.arg == 45
                || (200..=209).contains(&start.arg)
                || (350..=355).contains(&start.arg)
            {
                0
            } else {
                7
            }
        }
        Err(error) => {
            // The closed controller failure is terminal in its first syscall.
            // Returning through a deliberately broken user gate between
            // console output, a mode query and op34 can strand the receipt.
            if start.arg == 120 && nway {
                test(34, u64::from(error == "N-way all-worker progress"), 0);
            }
            let _ = start.console.line(format_args!(
                "SMP USER FIXTURE FAILED role={} error={}\n",
                start.arg, error
            ));
            87
        }
    }
}
