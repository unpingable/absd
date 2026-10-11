//! Calls every syscall with pseudo-random arguments from a fixed seed. The
//! kernel must refuse or serve each one without harm; nothing here may
//! block forever, so waits carry timeouts and console reads are avoided.
//! Children it happens to start are killed and reaped before it exits.
#![no_std]
#![no_main]

use absd_abi::layout::{USER_ADDRESS_LIMIT, USER_HEAP_BASE, USER_STACK_TOP};
use absd_abi::syscall::{
    SYS_CELL_CREATE, SYS_CELL_READ, SYS_CELL_TRANSITION, SYS_CELL_WAIT, SYS_CLOSE, SYS_DUPLICATE,
    SYS_EXIT, SYS_INFO, SYS_KILL, SYS_MAP, SYS_PIPE_CREATE, SYS_READ, SYS_SLEEP, SYS_SPAWN,
    SYS_SPAWN_MANY_COPY, SYS_TRANSFER, SYS_UNMAP, SYS_WAIT, SYS_WRITE,
};
use absd_user::{
    Cell, Child, Error, MAX_SPAWN_HANDLES, Outcome, RIGHT_READ, RIGHT_WRITE, SpawnHandleCopy,
    Start, close, cprintln, duplicate, info, kill, program, spawn_many_copy, spawn_many_copy_raw,
    syscall3, wait_timeout,
};

absd_user::entry!(main);

const ROUNDS: u32 = 4000;
const MAX_CHILDREN: usize = 6;

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        // xorshift64*: deterministic, good enough to spread arguments.
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn expect_exit(child: Child, status: i32) -> Result<(), &'static str> {
    match wait_timeout(Some(child), 500) {
        Ok(Outcome::Exited(actual)) if actual == status => Ok(()),
        _ => Err("spawn child outcome"),
    }
}

/// A deterministic transaction matrix for syscall 22. Besides checking each
/// refusal, the successful spawn after the late destination-capacity failure
/// must receive the immediately following PID and observe intact parent
/// sources. The fuzz boot's final zero-resource assertion then proves that no
/// hidden child, object reference, frame, or process slot survived rollback.
fn verify_spawn_handle_fuzz(console: absd_user::Console) -> Result<(), &'static str> {
    let cell = Cell::create(41).map_err(|_| "create spawn fuzz cell")?;
    let readonly = duplicate(cell.raw(), RIGHT_READ).map_err(|_| "duplicate spawn fuzz cell")?;

    // Count zero is valid and must not inspect even a nonsensical pointer.
    let zero = spawn_many_copy_raw(program::MULTI_HANDLE, u64::MAX, 0)
        .map_err(|_| "zero descriptor spawn")?;
    expect_exit(zero, 88)?;

    let one = [SpawnHandleCopy::new(cell.raw(), RIGHT_READ)];
    expect_exit(
        spawn_many_copy(program::MULTI_HANDLE, &one).map_err(|_| "one descriptor spawn")?,
        88,
    )?;

    // Duplicate sources are legal. These three records also prove narrowing,
    // ordered delivery, and an optional console replacement in one spawn.
    let good = [
        SpawnHandleCopy::new(cell.raw(), RIGHT_READ),
        SpawnHandleCopy::new(cell.raw(), RIGHT_WRITE),
        SpawnHandleCopy::console(console.raw(), RIGHT_WRITE),
    ];
    let first =
        spawn_many_copy(program::MULTI_HANDLE, &good).map_err(|_| "several descriptor spawn")?;
    let first_pid = info(Some(first))
        .map_err(|_| "first descriptor child info")?
        .pid;
    expect_exit(first, 0)?;
    if cell.read() != Ok((1, 42)) || Cell::from_raw(readonly).read() != Ok((1, 42)) {
        return Err("copy sources did not survive successful spawn");
    }

    let mixed = [
        SpawnHandleCopy::new(cell.raw(), RIGHT_READ),
        SpawnHandleCopy::new(u64::MAX, RIGHT_READ),
        SpawnHandleCopy::console(console.raw(), RIGHT_WRITE),
    ];
    if spawn_many_copy(program::MULTI_HANDLE, &mixed) != Err(Error::BadHandle) {
        return Err("mixed bad source accepted");
    }
    if spawn_many_copy(
        program::MULTI_HANDLE,
        &[SpawnHandleCopy::new(readonly, RIGHT_READ | RIGHT_WRITE)],
    ) != Err(Error::Rights)
    {
        return Err("rights escalation accepted");
    }
    if spawn_many_copy_raw(program::MULTI_HANDLE, USER_ADDRESS_LIMIT, 1) != Err(Error::Fault) {
        return Err("invalid descriptor pointer accepted");
    }
    // The first word is mapped, but the complete 24-byte record crosses the
    // top of the reserved stack into an unmapped page.
    if spawn_many_copy_raw(program::MULTI_HANDLE, USER_STACK_TOP - 8, 1) != Err(Error::Fault) {
        return Err("partial descriptor pointer accepted");
    }
    if spawn_many_copy_raw(
        program::MULTI_HANDLE,
        good.as_ptr() as u64,
        MAX_SPAWN_HANDLES as u64 + 1,
    ) != Err(Error::Invalid)
    {
        return Err("over-bound descriptor count accepted");
    }

    close(readonly).map_err(|_| "close spawn fuzz readonly")?;
    if spawn_many_copy(
        program::MULTI_HANDLE,
        &[SpawnHandleCopy::new(readonly, RIGHT_READ)],
    ) != Err(Error::BadHandle)
    {
        return Err("disappeared source accepted");
    }

    // The default console occupies one destination slot. Sixty-four ordinary
    // copies therefore fail only after a nearly complete batch insertion.
    let exhaust = [SpawnHandleCopy::new(cell.raw(), RIGHT_READ); MAX_SPAWN_HANDLES];
    if spawn_many_copy(program::MULTI_HANDLE, &exhaust) != Err(Error::TooManyHandles) {
        return Err("destination capacity exhaustion accepted");
    }
    if cell.read() != Ok((1, 42)) {
        return Err("failed spawn changed source state");
    }

    let second =
        spawn_many_copy(program::MULTI_HANDLE, &good).map_err(|_| "spawn after rollback")?;
    if info(Some(second))
        .map_err(|_| "second descriptor child info")?
        .pid
        != first_pid + 1
    {
        return Err("failed spawn consumed pid");
    }
    expect_exit(second, 0)?;
    if cell.read() != Ok((2, 43)) {
        return Err("source unusable after rollback");
    }

    // Recursive userspace probes exercise every supported chain depth through
    // five processes. Each hop verifies that its inherited read-only rights
    // cannot strengthen and that a closed opaque value stays stale when a
    // fresh handle is issued.
    let chain = [SpawnHandleCopy::new(cell.raw(), RIGHT_READ); 8];
    for depth in 4..=chain.len() {
        expect_exit(
            spawn_many_copy(program::MULTI_HANDLE, &chain[..depth])
                .map_err(|_| "rights chain spawn")?,
            0,
        )?;
    }
    close(cell.raw()).map_err(|_| "close spawn fuzz cell")?;
    Ok(())
}

fn main(start: Start) -> i32 {
    let console = start.console;
    if let Err(reason) = verify_spawn_handle_fuzz(console) {
        let _ = cprintln!(console, "fuzz: spawn handle check failed: {reason}");
        return 85;
    }
    let _ = cprintln!(console, "SPAWN HANDLE FUZZ OK");
    let _ = cprintln!(console, "RIGHTS CHAIN FUZZ OK");
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let mut handles = [0u64; 16];
    let mut children: [Option<Child>; MAX_CHILDREN] = [None; MAX_CHILDREN];
    handles[0] = console.raw();
    let mut scratch = [0u64; 8];
    let mut spawn_records = [SpawnHandleCopy::new(0, 0); 4];
    let mut served = 0u64;
    let mut refused = 0u64;
    for _ in 0..ROUNDS {
        let number = random.below(24);
        if number == SYS_EXIT || number == SYS_READ {
            continue;
        }
        // Arguments: mostly plausible objects and addresses, sometimes junk.
        let pick = |random: &mut Random, handles: &[u64; 16]| match random.below(6) {
            0 => 0,
            1 => handles[random.below(16) as usize],
            2 => scratch.as_ptr() as u64,
            3 => USER_HEAP_BASE + random.below(64) * 4096,
            4 => USER_STACK_TOP - random.below(8192),
            _ => random.next(),
        };
        let mut a0 = pick(&mut random, &handles);
        let mut a1 = pick(&mut random, &handles);
        let mut a2 = pick(&mut random, &handles);
        match number {
            // Anything that could wait must be bounded.
            SYS_SLEEP => a0 = random.below(4),
            SYS_WAIT | SYS_CELL_WAIT => a2 = 1 + random.below(3),
            SYS_TRANSFER => {
                scratch[0] = pick(&mut random, &handles);
                scratch[1] = random.below(300);
                scratch[2] = 1 + random.below(3);
                a1 = scratch.as_ptr() as u64;
                a2 = random.below(3);
            }
            SYS_WRITE => a2 = random.below(300),
            SYS_MAP => a0 = random.below(70),
            SYS_UNMAP => a1 = random.below(70),
            SYS_SPAWN => {
                // Explicit safe catalog: special entry ABIs and
                // authority-dependent workers never become eligible merely
                // because the global catalog grows.
                let safe = &absd_abi::program::FUZZ_LEGACY_PROGRAMS;
                let legacy = safe[random.below(safe.len() as u64) as usize];
                a0 = legacy | (random.below(2) << 32);
                a2 = random.below(8);
            }
            SYS_SPAWN_MANY_COPY => {
                a0 = absd_abi::program::MULTI_HANDLE;
                // Keep arrays small enough that random successes remain
                // collectible. Structured modes guarantee real valid arrays
                // alongside mixed live/stale/junk sources and arbitrary
                // rights; the deterministic prelude covers the full bound.
                let count = match random.below(6) {
                    0 => 0,
                    1 => {
                        spawn_records[0] = SpawnHandleCopy::new(console.raw(), RIGHT_WRITE);
                        1
                    }
                    2 => {
                        spawn_records[0] = SpawnHandleCopy::new(console.raw(), RIGHT_READ);
                        spawn_records[1] = SpawnHandleCopy::new(console.raw(), RIGHT_WRITE);
                        spawn_records[2] = SpawnHandleCopy::console(console.raw(), RIGHT_WRITE);
                        3
                    }
                    _ => {
                        let count = 1 + random.below(spawn_records.len() as u64) as usize;
                        for record in &mut spawn_records[..count] {
                            let source = if random.below(3) == 0 {
                                handles[random.below(handles.len() as u64) as usize]
                            } else {
                                random.next()
                            };
                            *record = SpawnHandleCopy::new(source, random.below(8));
                        }
                        count
                    }
                };
                a1 = spawn_records.as_ptr() as u64;
                a2 = count as u64;
            }
            _ => {}
        }
        // The console is the fuzzer's own voice: never close it.
        if number == SYS_CLOSE && a0 == console.raw() {
            continue;
        }
        let result = unsafe { syscall3(number, a0, a1, a2) };
        if result < 0 {
            refused += 1;
            continue;
        }
        served += 1;
        // Remember handles so later rounds can use, duplicate, and close
        // them; keep every child so it can be ended before we leave.
        let value = result as u64;
        match number {
            SYS_SPAWN | SYS_SPAWN_MANY_COPY => {
                let child = Child::from_raw(value);
                if let Some(slot) = children.iter_mut().find(|slot| slot.is_none()) {
                    *slot = Some(child);
                } else {
                    let _ = kill(child);
                    let _ = wait_timeout(Some(child), 50);
                }
            }
            SYS_CELL_CREATE | SYS_PIPE_CREATE | SYS_DUPLICATE => {
                let slot = 1 + random.below(15) as usize;
                if handles[slot] != 0 {
                    let _ = unsafe { syscall3(SYS_CLOSE, handles[slot], 0, 0) };
                }
                handles[slot] = value;
            }
            _ => {}
        }
        let _ = (SYS_CELL_READ, SYS_CELL_TRANSITION, SYS_INFO, SYS_KILL);
    }
    // A child may already have been reaped by a random wait, which leaves
    // its handle stale; only a child that refuses to end is a failure.
    for child in children.into_iter().flatten() {
        let _ = kill(child);
        if let Err(Error::Timeout) = wait_timeout(Some(child), 200) {
            let _ = cprintln!(console, "fuzz: a child could not be collected");
            return 84;
        }
    }
    let _ = cprintln!(
        console,
        "fuzz: {ROUNDS} rounds, {served} served, {refused} refused"
    );
    0
}
