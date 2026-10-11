//! Syscall information-disclosure probe (docs/SYSCALL-DISCLOSURE.md). Checks
//! only what source inspection does not settle on its own:
//!
//! - coverage: every fixed-size output record is written completely (two
//!   runs with different prefills agree byte for byte) and nothing past it;
//! - refusal: a record that straddles into an unmapped page, or lies in
//!   read-only memory, is refused with nothing written and nothing consumed;
//! - reuse: a stale process, cell, or pipe handle never reaches the object
//!   that replaced it, and a reused object carries none of its predecessor's
//!   state;
//! - entry state: a child starts with zero GPRs and XMM registers and the
//!   default MXCSR although its parent spawned it with every register full;
//! - fault records: what a parent learns from a child's fault.
//!
//! Run as the external workload by `scripts/disclosure-probe-test.sh`.
#![no_std]
#![no_main]

use absd_abi::layout::{USER_HEAP_BASE, USER_HEAP_END, USER_IMAGE_MAX, USER_IMAGE_MIN};
use absd_abi::syscall::{
    BOOT_ID_BYTES, CELL_RECORD_BYTES, ERROR_NOT_IMPLEMENTED, FRAME_STATS_BYTES, INFO_BYTES,
    OUTCOME_BYTES, PIPE_INFO_BYTES, RESOURCE_CENSUS_BYTES, SYS_BOOT_ID, SYS_CELL_CREATE,
    SYS_CELL_READ, SYS_CLOSE, SYS_FRAME_STATS, SYS_INFO, SYS_PIPE_CREATE, SYS_PIPE_INFO, SYS_READ,
    SYS_RESOURCE_CENSUS, SYS_SPAWN_IMAGE, SYS_WAIT, SYS_WRITE, SpawnImageRequest,
};
use absd_user::{MultiStart, RIGHT_WAIT, SpawnHandleCopy, map, syscall3, unmap};
use core::arch::asm;
use core::fmt::Write as _;

absd_user::multi_entry!(main);

const BASE: u64 = USER_IMAGE_MIN;
const CODE: usize = 120;

/// A one-segment R+X image at `BASE` whose code starts at file offset 120.
fn image(code: &[u8], out: &mut [u8; 512]) -> usize {
    let length = CODE + code.len();
    out.fill(0);
    out[0..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    let mut put = |at: usize, value: &[u8]| out[at..at + value.len()].copy_from_slice(value);
    put(16, &2u16.to_le_bytes());
    put(18, &62u16.to_le_bytes());
    put(20, &1u32.to_le_bytes());
    put(24, &(BASE + CODE as u64).to_le_bytes());
    put(32, &64u64.to_le_bytes());
    put(52, &64u16.to_le_bytes());
    put(54, &56u16.to_le_bytes());
    put(56, &1u16.to_le_bytes());
    put(64, &1u32.to_le_bytes());
    put(68, &5u32.to_le_bytes());
    put(80, &BASE.to_le_bytes());
    put(88, &BASE.to_le_bytes());
    put(96, &(length as u64).to_le_bytes());
    put(104, &(length as u64).to_le_bytes());
    put(112, &0x1000u64.to_le_bytes());
    out[CODE..length].copy_from_slice(code);
    length
}

/// `mov edi, 42; exit`.
const EXIT42: [u8; 12] = [0xbf, 42, 0, 0, 0, 0xb8, 3, 0, 0, 0, 0xcd, 0x80];

/// `mov rax, address; mov eax, [rax]; exit 42` (faults first).
fn touch(address: u64) -> [u8; 24] {
    let mut code = [0u8; 24];
    code[0..2].copy_from_slice(&[0x48, 0xb8]);
    code[2..10].copy_from_slice(&address.to_le_bytes());
    code[10..12].copy_from_slice(&[0x8b, 0x00]);
    code[12..24].copy_from_slice(&EXIT42);
    code
}

/// Exits 42 if every GPR the entry does not define (all but RDI, RSP, RIP)
/// is zero, every XMM register is zero, and MXCSR is 0x1f80; otherwise 1,
/// 2, or 3 for the group that is not.
fn entry_state(out: &mut [u8; 192]) -> usize {
    let mut n = 0;
    let mut emit = |bytes: &[u8], n: &mut usize| {
        out[*n..*n + bytes.len()].copy_from_slice(bytes);
        *n += bytes.len();
    };
    let mut jumps = [0usize; 3];
    // or rax with rbx, rcx, rdx, rsi, rbp, then r8-r15.
    for modrm in [0xd8u8, 0xc8, 0xd0, 0xf0, 0xe8] {
        emit(&[0x48, 0x09, modrm], &mut n);
    }
    for modrm in [0xc0u8, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0, 0xf8] {
        emit(&[0x4c, 0x09, modrm], &mut n);
    }
    emit(&[0xbf, 1, 0, 0, 0], &mut n); // mov edi, 1 (flags kept)
    emit(&[0x48, 0x85, 0xc0], &mut n); // test rax, rax
    jumps[0] = n;
    emit(&[0x75, 0], &mut n); // jnz exit
    // por xmm0 with xmm1-xmm15, then both quadwords of xmm0 into rax.
    for register in 1u8..8 {
        emit(&[0x66, 0x0f, 0xeb, 0xc0 | register], &mut n);
    }
    for register in 0u8..8 {
        emit(&[0x66, 0x41, 0x0f, 0xeb, 0xc0 | register], &mut n);
    }
    emit(&[0x66, 0x48, 0x0f, 0x7e, 0xc0], &mut n); // movq rax, xmm0
    emit(&[0x66, 0x0f, 0x6d, 0xc0], &mut n); // punpckhqdq xmm0, xmm0
    emit(&[0x66, 0x48, 0x0f, 0x7e, 0xc3], &mut n); // movq rbx, xmm0
    emit(&[0x48, 0x09, 0xd8], &mut n); // or rax, rbx
    emit(&[0xbf, 2, 0, 0, 0], &mut n);
    jumps[1] = n;
    emit(&[0x75, 0], &mut n);
    emit(&[0x0f, 0xae, 0x5c, 0x24, 0xf8], &mut n); // stmxcsr [rsp-8]
    emit(&[0x8b, 0x44, 0x24, 0xf8], &mut n); // mov eax, [rsp-8]
    emit(&[0xbf, 3, 0, 0, 0], &mut n);
    emit(&[0x3d, 0x80, 0x1f, 0, 0], &mut n); // cmp eax, 0x1f80
    jumps[2] = n;
    emit(&[0x75, 0], &mut n);
    emit(&[0xbf, 42, 0, 0, 0], &mut n);
    let exit = n;
    emit(&[0xb8, 3, 0, 0, 0, 0xcd, 0x80], &mut n);
    for at in jumps {
        out[at + 1] = (exit - (at + 2)) as u8;
    }
    n
}

fn raw(number: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    unsafe { syscall3(number, a0, a1, a2) }
}

fn spawn(code: &[u8]) -> i64 {
    let mut bytes = [0u8; 512];
    let length = image(code, &mut bytes);
    let request = SpawnImageRequest {
        image: bytes.as_ptr() as u64,
        image_bytes: length as u64,
        handles: 0,
        handle_count: 0,
    };
    raw(SYS_SPAWN_IMAGE, &request as *const _ as u64, 0, 0)
}

fn wait_words(child: u64) -> [u64; 4] {
    let mut record = [0u64; 4];
    let code = raw(SYS_WAIT, child, record.as_mut_ptr() as u64, 0);
    if code < 0 {
        return [u64::MAX; 4];
    }
    record
}

/// A read-only target: in the image's R+X text, not writable by anyone.
static READONLY: [u8; 64] = [0x3c; 64];

struct Probe {
    console: absd_user::Console,
    page: *mut u8,
    failures: u32,
}

impl Probe {
    fn bytes(&mut self, at: usize, length: usize) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.page.add(at), length) }
    }

    fn report(&mut self, name: &str, ok: bool, detail: core::fmt::Arguments<'_>) {
        if !ok {
            self.failures += 1;
        }
        let verdict = if ok { "ok" } else { "FAILED" };
        let _ = writeln!(self.console, "DISCLOSE {name} {verdict} {detail}");
    }

    /// Runs `call` into a record at page+64 twice, prefilled with 0xa5 and
    /// then 0x5a, with 16 guard bytes either side. Every record byte must be
    /// the same in both runs and every guard byte untouched.
    fn coverage(&mut self, name: &str, length: usize, mut call: impl FnMut(u64) -> i64) {
        let mut seen = [[0u8; 64]; 2];
        let mut codes = [0i64; 2];
        let mut guards = true;
        for (run, fill) in [0xa5u8, 0x5a].into_iter().enumerate() {
            self.bytes(0, 256).fill(fill);
            codes[run] = call(self.page as u64 + 64);
            seen[run][..length].copy_from_slice(self.bytes(64, length));
            guards &= self.bytes(48, 16).iter().all(|&b| b == fill)
                && self.bytes(64 + length, 16).iter().all(|&b| b == fill);
        }
        if codes[0] == ERROR_NOT_IMPLEMENTED && codes[1] == ERROR_NOT_IMPLEMENTED {
            let untouched = seen[0][..length].iter().all(|&b| b == 0xa5)
                && seen[1][..length].iter().all(|&b| b == 0x5a);
            self.report(
                name,
                untouched && guards,
                format_args!("unsupported=-38 untouched={untouched}"),
            );
            return;
        }
        let unwritten = (0..length).filter(|&i| seen[0][i] != seen[1][i]).count();
        let ok = codes[0] >= 0 && codes[1] >= 0 && unwritten == 0 && guards;
        self.report(
            name,
            ok,
            format_args!("bytes={length} unwritten={unwritten} guards={guards}"),
        );
    }

    /// A refused call: the record straddles from the last 8 bytes of a
    /// mapped page into an unmapped one, or lies in read-only text. The
    /// mapped bytes must be unchanged.
    fn refusal(&mut self, name: &str, mut call: impl FnMut(u64) -> i64) {
        let straddle = self.page as u64 + 4096 - 8;
        self.bytes(4096 - 8, 8).fill(0xc3);
        let code = call(straddle);
        let kept = self.bytes(4096 - 8, 8).iter().all(|&b| b == 0xc3);
        let readonly = call(READONLY.as_ptr() as u64);
        let intact = READONLY.iter().all(|&b| b == 0x3c);
        self.report(
            name,
            code == -14 && kept && readonly == -14 && intact,
            format_args!("straddle={code} kept={kept} readonly={readonly}"),
        );
    }
}

fn main(start: MultiStart<'_>) -> i32 {
    let mut console = start.console;
    match run(start.console) {
        Ok(0) => {
            let _ = writeln!(console, "DISCLOSE OK");
            0
        }
        Ok(failures) => {
            let _ = writeln!(console, "DISCLOSE FAILED count={failures}");
            1
        }
        Err(step) => {
            let _ = writeln!(console, "DISCLOSE FAILED at {step}");
            1
        }
    }
}

fn run(console: absd_user::Console) -> Result<u32, &'static str> {
    // Page 0 holds the records; page 1 is unmapped again so a record can
    // straddle into it. Nothing below maps memory, so the hole stays.
    let page = map(2).map_err(|_| "map")?;
    let address = page as u64;
    let in_heap = (USER_HEAP_BASE..USER_HEAP_END).contains(&address);
    unmap(unsafe { page.add(4096) }, 1).map_err(|_| "unmap")?;
    let mut probe = Probe {
        console,
        page,
        failures: 0,
    };
    probe.report("map-address", in_heap, format_args!("user-heap={in_heap}"));

    let cell = raw(SYS_CELL_CREATE, 0x0102_0304_0506_0708, 0, 0);
    let pipe = raw(SYS_PIPE_CREATE, 0, 0, 0);
    let child = spawn(&EXIT42);
    if cell < 0 || pipe < 0 || child < 0 {
        return Err("objects");
    }
    let (cell, pipe, child) = (cell as u64, pipe as u64, child as u64);

    // Coverage of every fixed-size output record.
    probe.coverage("info-self", INFO_BYTES, |at| raw(SYS_INFO, 0, at, 0));
    probe.coverage("info-child", INFO_BYTES, |at| raw(SYS_INFO, child, at, 0));
    probe.coverage("cell-read", CELL_RECORD_BYTES, |at| {
        raw(SYS_CELL_READ, cell, at, 0)
    });
    probe.coverage("pipe-info", PIPE_INFO_BYTES, |at| {
        raw(SYS_PIPE_INFO, pipe, at, 0)
    });
    probe.coverage("frame-stats", FRAME_STATS_BYTES, |at| {
        raw(SYS_FRAME_STATS, at, 0, 0)
    });
    probe.coverage("resource-census", RESOURCE_CENSUS_BYTES, |at| {
        raw(SYS_RESOURCE_CENSUS, at, 0, 0)
    });
    probe.coverage("boot-id", BOOT_ID_BYTES, |at| raw(SYS_BOOT_ID, at, 0, 0));
    // Two identical children per outcome kind, one wait record each.
    for (name, code) in [
        ("wait-exited", &EXIT42[..]),
        ("wait-faulted", &touch(0x10_0000)[..]),
    ] {
        probe.coverage(name, OUTCOME_BYTES, |at| {
            let child = spawn(code);
            if child < 0 {
                return child;
            }
            let pid = raw(SYS_WAIT, child as u64, at, 0);
            // The PID differs between the two children; the record must not.
            if pid < 0 { pid } else { 0 }
        });
    }

    // Refusals write nothing, and a refused pipe read consumes nothing.
    probe.refusal("info-refused", |at| raw(SYS_INFO, 0, at, 0));
    probe.refusal("cell-read-refused", |at| raw(SYS_CELL_READ, cell, at, 0));
    probe.refusal("pipe-info-refused", |at| raw(SYS_PIPE_INFO, pipe, at, 0));
    probe.refusal("frame-stats-refused", |at| raw(SYS_FRAME_STATS, at, 0, 0));
    probe.refusal("census-refused", |at| raw(SYS_RESOURCE_CENSUS, at, 0, 0));
    probe.refusal("wait-refused", |at| raw(SYS_WAIT, child, at, 0));
    let mut info = [0u64; 4];
    let alive = raw(SYS_INFO, child, info.as_mut_ptr() as u64, 0);
    probe.report(
        "wait-refused-keeps-child",
        alive == 0,
        format_args!("info-after={alive}"),
    );
    let secret = *b"pipe bytes kept!";
    let written = raw(SYS_WRITE, pipe, secret.as_ptr() as u64, 16);
    probe.refusal("pipe-read-refused", |at| raw(SYS_READ, pipe, at, 16));
    let mut status = [0u64; 4];
    raw(SYS_PIPE_INFO, pipe, status.as_mut_ptr() as u64, 0);
    probe.report(
        "pipe-read-refused-consumes-nothing",
        written == 16 && status[0] == 16,
        format_args!("available={}", status[0]),
    );

    // A process handle is never inherited.
    let copies = [SpawnHandleCopy::new(child, RIGHT_WAIT)];
    let mut bytes = [0u8; 512];
    let length = image(&EXIT42, &mut bytes);
    let request = SpawnImageRequest {
        image: bytes.as_ptr() as u64,
        image_bytes: length as u64,
        handles: copies.as_ptr() as u64,
        handle_count: 1,
    };
    let inherited = raw(SYS_SPAWN_IMAGE, &request as *const _ as u64, 0, 0);
    probe.report(
        "process-handle-not-inherited",
        inherited < 0,
        format_args!("spawn={inherited}"),
    );

    // Reuse. A reaped child's handle does not name its successor. Each
    // successor must take its predecessor's slot (low byte) so that only the
    // tag tells them apart; otherwise these checks prove nothing.
    let old_pid = {
        raw(SYS_INFO, child, info.as_mut_ptr() as u64, 0);
        info[0]
    };
    let reaped = wait_words(child);
    let successor = spawn(&EXIT42);
    let stale_info = raw(SYS_INFO, child, info.as_mut_ptr() as u64, 0);
    let stale_wait = raw(SYS_WAIT, child, info.as_mut_ptr() as u64, 0);
    let fresh = raw(SYS_INFO, successor as u64, info.as_mut_ptr() as u64, 0);
    let fresh_pid = info[0];
    wait_words(successor as u64);
    probe.report(
        "stale-process-handle",
        reaped[0] == 1
            && stale_info == -9
            && stale_wait == -9
            && fresh == 0
            && fresh_pid != old_pid
            && (successor as u64 & 0xff) == (child & 0xff),
        format_args!("info={stale_info} wait={stale_wait} successor-info={fresh}"),
    );
    // A freed cell's successor starts at version 0 with its own value.
    let mut record = [0u64; 2];
    raw(SYS_CLOSE, cell, 0, 0);
    let next = raw(SYS_CELL_CREATE, 7, 0, 0) as u64;
    let stale = raw(SYS_CELL_READ, cell, record.as_mut_ptr() as u64, 0);
    let read = raw(SYS_CELL_READ, next, record.as_mut_ptr() as u64, 0);
    probe.report(
        "stale-cell-handle",
        stale == -9 && read == 0 && record == [0, 7] && (next & 0xff) == (cell & 0xff),
        format_args!("stale={stale} successor=({},{})", record[0], record[1]),
    );
    // The cell successor stays open so the pipe successor reuses the pipe's
    // slot rather than this lower one.
    let next_cell = next;
    // A pipe freed with unread bytes: its successor holds none of them.
    raw(SYS_CLOSE, pipe, 0, 0);
    let next = raw(SYS_PIPE_CREATE, 0, 0, 0) as u64;
    let stale = raw(SYS_PIPE_INFO, pipe, status.as_mut_ptr() as u64, 0);
    let fresh = raw(SYS_PIPE_INFO, next, status.as_mut_ptr() as u64, 0);
    probe.report(
        "stale-pipe-handle",
        stale == -9 && fresh == 0 && status[0] == 0 && (next & 0xff) == (pipe & 0xff),
        format_args!("stale={stale} successor-available={}", status[0]),
    );
    raw(SYS_CLOSE, next, 0, 0);
    raw(SYS_CLOSE, next_cell, 0, 0);

    // Entry state: the parent fills every GPR it can and all sixteen XMM
    // registers with a pattern, then spawns through `int 0x80` directly.
    let mut entry_code = [0u8; 192];
    let entry_length = entry_state(&mut entry_code);
    let length = image(&entry_code[..entry_length], &mut bytes);
    let request = SpawnImageRequest {
        image: bytes.as_ptr() as u64,
        image_bytes: length as u64,
        handles: 0,
        handle_count: 0,
    };
    let pattern = [0x5a5a_a5a5_dead_beefu64; 2];
    let result: i64;
    unsafe {
        asm!(
            "push rbx",
            "push rbp",
            "mov rbx, r9",
            "mov rbp, r9",
            "mov r8, r9",
            "mov r10, r9",
            "mov r11, r9",
            "mov r12, r9",
            "mov r13, r9",
            "mov r14, r9",
            "mov r15, r9",
            "mov rcx, r9",
            "movdqu xmm0, [rsi]",
            "movdqu xmm1, [rsi]",
            "movdqu xmm2, [rsi]",
            "movdqu xmm3, [rsi]",
            "movdqu xmm4, [rsi]",
            "movdqu xmm5, [rsi]",
            "movdqu xmm6, [rsi]",
            "movdqu xmm7, [rsi]",
            "movdqu xmm8, [rsi]",
            "movdqu xmm9, [rsi]",
            "movdqu xmm10, [rsi]",
            "movdqu xmm11, [rsi]",
            "movdqu xmm12, [rsi]",
            "movdqu xmm13, [rsi]",
            "movdqu xmm14, [rsi]",
            "movdqu xmm15, [rsi]",
            "xor edx, edx",
            "xor esi, esi",
            "int 0x80",
            "pop rbp",
            "pop rbx",
            inout("rax") SYS_SPAWN_IMAGE as i64 => result,
            in("rdi") &request as *const _ as u64,
            inout("rsi") pattern.as_ptr() as u64 => _,
            inout("r9") pattern[0] => _,
            out("rcx") _, out("rdx") _, out("r8") _, out("r10") _, out("r11") _,
            out("r12") _, out("r13") _, out("r14") _, out("r15") _,
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
        );
    }
    let outcome = if result < 0 {
        [u64::MAX; 4]
    } else {
        wait_words(result as u64)
    };
    probe.report(
        "child-entry-registers",
        outcome[0] == 1 && outcome[1] == 42,
        format_args!("spawn={} exit={}", (result >= 0) as u8, outcome[1] as i64),
    );

    // Fault records: vector, address, error code the parent receives.
    for (name, target) in [
        ("fault-identity-map", 0x10_0000u64),
        ("fault-user-gap", 0x0000_0081_0000_0000),
        ("fault-kernel-half", 0xffff_8000_0000_0000),
        ("fault-noncanonical", 0x8000_0000_0000_0000),
    ] {
        let child = spawn(&touch(target));
        let words = if child < 0 {
            [u64::MAX; 4]
        } else {
            wait_words(child as u64)
        };
        // Page faults report the address the child chose; a #GP reports
        // the child's own instruction pointer. Neither is a kernel value.
        let user_value = if words[1] == 14 {
            words[2] == target
        } else {
            (USER_IMAGE_MIN..USER_IMAGE_MAX).contains(&words[2])
        };
        probe.report(
            name,
            words[0] == 2 && user_value,
            format_args!(
                "vector={} address={:#x} error={:#x}",
                words[1], words[2], words[3]
            ),
        );
    }
    Ok(probe.failures)
}
