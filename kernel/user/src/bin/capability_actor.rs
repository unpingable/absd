//! Ring-3 Cell authority fixture. Role/input words arrive as pipe bytes;
//! only spawn's explicit copy records convey authority.
#![no_std]
#![no_main]

use absd_user::{
    Cell, Error, MultiStart, Outcome, Pipe, RIGHT_READ, RIGHT_WRITE, SpawnHandleCopy, close,
    duplicate, info, spawn_image, wait_timeout,
};

absd_user::multi_entry!(main);

const TICKS: u64 = 5_000;
const VALUE: u64 = 0xc311_0000_0000_0042;
const DECOY: u64 = 0xd3c0_0000_0000_0011;
static LEAF: &[u8] = include_bytes!(env!("ABSD_CAPABILITY_ACTOR_EMBED"));

fn read_words(pipe: Pipe) -> Result<[u64; 4], ()> {
    let mut bytes = [0u8; 32];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = pipe
            .read_timeout(&mut bytes[offset..], TICKS)
            .map_err(|_| ())?;
        if count == 0 {
            return Err(());
        }
        offset += count;
    }
    let mut words = [0; 4];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().map_err(|_| ())?);
    }
    Ok(words)
}

fn send(pipe: Pipe, bytes: &[u8]) -> Result<(), ()> {
    if pipe.write_timeout(bytes, TICKS) != Ok(bytes.len()) {
        return Err(());
    }
    Ok(())
}

fn eof(pipe: Pipe) -> bool {
    pipe.read_timeout(&mut [0u8; 1], TICKS) == Ok(0)
}

fn unchanged(cell: Cell) -> bool {
    cell.read() == Ok((1, VALUE))
}

fn main(start: MultiStart<'_>) -> i32 {
    // Leaf for allowed onward RO delegation. Its valid image is also used
    // for the refused RW spawn; an invalid image/no-spawn flag cannot mask it.
    if let [cell] = start.handles {
        let cell = Cell::from_raw(*cell);
        return if unchanged(cell)
            && cell.transition(1, 9) == Err(Error::Rights)
            && duplicate(cell.raw(), RIGHT_READ | RIGHT_WRITE) == Err(Error::Rights)
        {
            0
        } else {
            90
        };
    }
    let [control, report, rest @ ..] = start.handles else {
        return 91;
    };
    let control = Pipe::from_raw(*control);
    let report = Pipe::from_raw(*report);
    let Ok(words) = read_words(control) else {
        return 92;
    };
    match words[0] {
        1 => unauthorized(start, control, report, words[1]),
        2 if rest.len() == 1 => attenuated(Cell::from_raw(rest[0])),
        3..=6 if rest.len() == 2 => {
            let cell = Cell::from_raw(rest[0]);
            let gate = Pipe::from_raw(rest[1]);
            if words[0] != 3 && (!unchanged(cell) || send(report, &[1]).is_err()) {
                return 93;
            }
            if !eof(gate) || !unchanged(cell) {
                return 94;
            }
            if words[0] == 6 {
                unsafe { core::arch::asm!("ud2", options(noreturn)) };
            }
            if words[0] == 5 {
                return 95; // kill case must terminate while gate still has a writer.
            }
            if send(report, &[2]).is_err() {
                return 96;
            }
            // Retain cell/gate/report until process termination: kernel
            // death cleanup, rather than explicit fixture closes, is tested.
            0
        }
        7 if rest.is_empty() => grantor(report),
        8 if rest.len() == 2 => {
            if !eof(Pipe::from_raw(rest[1])) || !unchanged(Cell::from_raw(rest[0])) {
                return 97;
            }
            if send(report, &[2]).is_err() {
                return 98;
            }
            // The host binds the emitted PID to USER EXIT status=0. ACK/EOF
            // alone is deliberately not treated as proof of exit status.
            0
        }
        _ => 99,
    }
}

fn unauthorized(start: MultiStart<'_>, control: Pipe, report: Pipe, token: u64) -> i32 {
    let target_slot = token & 0xff;
    let mut report = report;
    // Make the exact numeric slot live with a RW Cell, even if the initial
    // startup pipe happens to occupy it. Never infer isolation from emptiness.
    if report.raw() & 0xff == target_slot {
        let Ok(replacement) = duplicate(report.raw(), RIGHT_WRITE) else {
            return 100;
        };
        if close(report.raw()).is_err() {
            return 101;
        }
        report = Pipe::from_raw(replacement);
    } else if control.raw() & 0xff == target_slot {
        if close(control.raw()).is_err() {
            return 102;
        }
    } else if start.console.raw() & 0xff == target_slot && close(start.console.raw()).is_err() {
        return 103;
    }
    let mut decoy = None;
    for _ in 0..64 {
        let Ok(cell) = Cell::create(DECOY) else {
            return 104;
        };
        if cell.raw() & 0xff == target_slot {
            decoy = Some(cell);
            break;
        }
    }
    let Some(decoy) = decoy else {
        return 105;
    };
    let supplied = Cell::from_raw(token);
    if token == decoy.raw()
        || supplied.read() != Err(Error::BadHandle)
        || supplied.transition(0, 99) != Err(Error::BadHandle)
        || duplicate(token, RIGHT_READ) != Err(Error::BadHandle)
        || close(token) != Err(Error::BadHandle)
        || decoy.read() != Ok((0, DECOY))
        || send(report, &[1]).is_err()
    {
        return 106;
    }
    0
}

fn attenuated(cell: Cell) -> i32 {
    if LEAF.is_empty() || !unchanged(cell) {
        return 110;
    }
    if cell.transition(1, 99) != Err(Error::Rights) {
        return 111;
    }
    if duplicate(cell.raw(), RIGHT_READ | RIGHT_WRITE) != Err(Error::Rights) {
        return 112;
    }
    if spawn_image(
        LEAF,
        &[SpawnHandleCopy::new(cell.raw(), RIGHT_READ | RIGHT_WRITE)],
        0,
    ) != Err(Error::Rights)
    {
        return 113;
    }
    let Ok(narrow) = duplicate(cell.raw(), RIGHT_READ) else {
        return 114;
    };
    if !unchanged(Cell::from_raw(narrow)) {
        return 115;
    }
    let Ok(child) = spawn_image(LEAF, &[SpawnHandleCopy::new(narrow, RIGHT_READ)], 0) else {
        return 116;
    };
    if wait_timeout(Some(child), TICKS) != Ok(Outcome::Exited(0)) || close(narrow).is_err() {
        return 117;
    }
    let Ok(fresh) = duplicate(cell.raw(), RIGHT_READ) else {
        return 118;
    };
    if narrow == fresh
        || (narrow & 0xff) != (fresh & 0xff)
        || Cell::from_raw(narrow).read() != Err(Error::BadHandle)
        || duplicate(narrow, RIGHT_READ) != Err(Error::BadHandle)
        || !unchanged(Cell::from_raw(fresh))
        || close(fresh).is_err()
        || !unchanged(cell)
    {
        return 119;
    }
    0
}

fn grantor(report: Pipe) -> i32 {
    let Ok(cell) = Cell::create(0) else {
        return 120;
    };
    if cell.transition(0, VALUE) != Ok(1) {
        return 121;
    }
    let (Ok(control), Ok(gate)) = (Pipe::create(), Pipe::create()) else {
        return 122;
    };
    let copies = [
        SpawnHandleCopy::new(control.raw(), RIGHT_READ),
        SpawnHandleCopy::new(report.raw(), RIGHT_WRITE),
        SpawnHandleCopy::new(cell.raw(), RIGHT_READ),
        SpawnHandleCopy::new(gate.raw(), RIGHT_READ),
    ];
    let Ok(child) = spawn_image(LEAF, &copies, 0) else {
        return 123;
    };
    let Ok(child_info) = info(Some(child)) else {
        return 124;
    };
    let mut role = [0u8; 32];
    role[..8].copy_from_slice(&8u64.to_le_bytes());
    if send(control, &role).is_err()
        || close(control.raw()).is_err()
        || send(report, &child_info.pid.to_le_bytes()).is_err()
    {
        return 125;
    }
    // Deliberately leave cell and gate open. Only grantor process death
    // removes the final gate writer, allowing the leaf to read afterwards.
    0
}
