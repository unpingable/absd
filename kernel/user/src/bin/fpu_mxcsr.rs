//! FPU/MXCSR state-isolation probe (docs/HOSTILE-USERSPACE.md). The start
//! argument selects the role:
//!
//! - `0`/`1` — isolation tasks A and B: install distinct MXCSR configs
//!   (rounding control, FTZ, DAZ when the CPU model's MXCSR_MASK allows it)
//!   and distinct XMM0/XMM7 sentinels, then verify all of it across hundreds
//!   of yields and timer preemptions. A `cvtss2si` pair whose answer depends
//!   on the task's own rounding mode, plus an exactly-representable `addss`,
//!   prove the state stays usable, not merely equal.
//! - `2` — unmask the SSE divide-by-zero exception and trigger it: the kernel
//!   must report #XM (vector 19) and reap the task as faulted.
//! - `3` — witness: a fresh task must observe the kernel's default control
//!   state (MXCSR `0x1f80`, x87 FCW `0x037f`), never a predecessor's.
//! - `4`/`5` — teardown variants: exit normally, or loop until killed, while
//!   holding distinctive MXCSR/XMM state.
//!
//! Control-state loops run inside single asm blocks (as `fpu.rs` does) so the
//! compiler cannot reorder XMM/MXCSR access across the checks.
#![no_std]
#![no_main]

use absd_abi::syscall::SYS_YIELD;
use absd_user::{Start, cprintln};

absd_user::entry!(main);

/// MXCSR as a fresh process receives it: all six SSE exceptions masked,
/// round-to-nearest, no FTZ/DAZ (`FpuState::INITIAL` in `src/process.rs`).
const MXCSR_DEFAULT: u32 = 0x1f80;
const MXCSR_RC_DOWN: u32 = 0x2000;
const MXCSR_RC_UP: u32 = 0x4000;
const MXCSR_RC_ZERO: u32 = 0x6000;
const MXCSR_DAZ: u32 = 0x0040;
const MXCSR_FTZ: u32 = 0x8000;
const ROUNDS: u32 = 400;

/// The architectural default when FXSAVE reports a zero MXCSR_MASK.
const MXCSR_MASK_DEFAULT: u32 = 0x0000_ffbf;

#[repr(align(16))]
struct FxsaveImage([u8; 512]);

/// The implemented MXCSR bits, from FXSAVE's MXCSR_MASK field.
fn mxcsr_mask() -> u32 {
    let mut image = FxsaveImage([0; 512]);
    unsafe {
        core::arch::asm!("fxsave [{p}]", p = in(reg) &mut image, options(nostack));
    }
    let mask = u32::from_le_bytes(image.0[28..32].try_into().unwrap());
    if mask == 0 { MXCSR_MASK_DEFAULT } else { mask }
}

fn main(start: Start) -> i32 {
    let console = start.console;
    match start.arg {
        0 | 1 => isolation_task(console, start.arg),
        2 => xm_fault_case(console),
        3 => witness(console),
        4 => dirty_exit(console),
        5 => dirty_loop(console),
        _ => 99,
    }
}

/// Tasks A (arg 0) and B (arg 1): distinct MXCSR configs and sentinels held
/// across ROUNDS yield+spin rounds. A runs round-toward-zero with FTZ; B runs
/// round-down with DAZ when the model exposes it. The two `cvtss2si`
/// expectations follow each task's own rounding mode, so a control-state leak
/// from the peer changes an arithmetic result, not just a compared bit.
fn isolation_task(console: absd_user::Console, which: u64) -> i32 {
    let mask = mxcsr_mask();
    if mask & 0x6000 != 0x6000 {
        let _ = cprintln!(
            console,
            "fpu-mxcsr: rounding control unsupported mask=0x{mask:08x}"
        );
        return 3;
    }
    let (name, desired, sentinel0, convert_pos, convert_neg) = match which {
        0 => (
            "A",
            MXCSR_DEFAULT | MXCSR_RC_ZERO | MXCSR_FTZ,
            0x0a0a_0a0a_0a0a_0a0a_u64,
            1,
            -1,
        ),
        _ => (
            "B",
            MXCSR_DEFAULT | MXCSR_RC_DOWN | MXCSR_DAZ,
            0x0b0b_0b0b_0b0b_0b0b_u64,
            1,
            -2,
        ),
    };
    let config = desired & mask;
    let sentinel1 = !sentinel0;
    let mut readback: u32 = 0;
    let status: u32;
    let round_left: u32;
    unsafe {
        core::arch::asm!(
            "ldmxcsr [{cfg}]",
            "mov rax, {s0}",
            "movq xmm0, rax",
            "mov rax, {s1}",
            "movq xmm7, rax",
            "mov r14d, {rounds}",
            "2:",
            // This task's MXCSR control state must be exactly its own after
            // every switch. The six exception status flags (bits 0-5) are
            // cleared from the comparison: the positive-control arithmetic
            // below legitimately sets the precision flag, and the kernel
            // correctly preserves it, so only the control bits (rounding,
            // masks, FTZ/DAZ) are a stable cross-task isolation witness.
            "stmxcsr [{scratch}]",
            "mov eax, [{scratch}]",
            "and eax, 0xffffffc0",
            "cmp eax, [{cfg}]",
            "jne 12f",
            "movq rax, xmm0",
            "cmp rax, {s0}",
            "jne 13f",
            "movq rax, xmm7",
            "cmp rax, {s1}",
            "jne 14f",
            // Positive control: conversions whose result depends on MXCSR.RC.
            "mov eax, 0x3fc00000", // +1.5f
            "movd xmm2, eax",
            "cvtss2si eax, xmm2",
            "cmp eax, {rcpos:e}",
            "jne 15f",
            "mov eax, 0xbfc00000", // -1.5f
            "movd xmm2, eax",
            "cvtss2si eax, xmm2",
            "cmp eax, {rcneg:e}",
            "jne 16f",
            // Positive control: exactly representable arithmetic.
            "mov eax, 0x3fa00000", // 1.25f
            "movd xmm3, eax",
            "mov eax, 0x40200000", // 2.5f
            "movd xmm4, eax",
            "addss xmm3, xmm4",
            "movd eax, xmm3",
            "cmp eax, 0x40700000", // 3.75f
            "jne 17f",
            "mov rax, {yield_nr}",
            "int 0x80",
            "mov ecx, 20000",
            "3:",
            "pause",
            "loop 3b",
            "dec r14d",
            "jnz 2b",
            "xor eax, eax",
            "jmp 20f",
            "12:",
            "mov eax, 1",
            "jmp 20f",
            "13:",
            "mov eax, 2",
            "jmp 20f",
            "14:",
            "mov eax, 3",
            "jmp 20f",
            "15:",
            "mov eax, 4",
            "jmp 20f",
            "16:",
            "mov eax, 5",
            "jmp 20f",
            "17:",
            "mov eax, 6",
            "20:",
            "mov {status:e}, eax",
            "mov {round_left:e}, r14d",
            cfg = in(reg) &config,
            scratch = in(reg) &mut readback,
            s0 = in(reg) sentinel0,
            s1 = in(reg) sentinel1,
            rcpos = in(reg) convert_pos,
            rcneg = in(reg) convert_neg,
            rounds = const ROUNDS,
            yield_nr = const SYS_YIELD,
            status = out(reg) status,
            round_left = out(reg) round_left,
            out("rax") _,
            out("rcx") _,
            out("r14") _,
            out("xmm0") _,
            out("xmm2") _,
            out("xmm3") _,
            out("xmm4") _,
            out("xmm7") _,
            options(nostack),
        );
    }
    if status != 0 {
        let _ = cprintln!(
            console,
            "fpu-mxcsr: task {name} CORRUPTED check={status} round={} mxcsr=0x{readback:08x}",
            ROUNDS - round_left,
        );
        return 97;
    }
    let _ = cprintln!(
        console,
        "fpu-mxcsr: task {name} preserved rounds={ROUNDS} mxcsr=0x{config:08x}"
    );
    0
}

/// Unmask the SSE divide-by-zero exception and divide 1.0 by zero. The
/// architecturally appropriate delivery under this kernel is a ring-3 #XM
/// fault: the kernel reports `USER FAULT ... vector=19 ... error=0x0` and
/// reaps the task. Surviving the divide is the failure this case detects.
fn xm_fault_case(console: absd_user::Console) -> i32 {
    let config = (MXCSR_DEFAULT & !0x0200) | MXCSR_RC_UP | MXCSR_FTZ;
    let _ = cprintln!(
        console,
        "fpu-mxcsr: xm fault case armed mxcsr=0x{config:08x}"
    );
    unsafe {
        core::arch::asm!(
            "ldmxcsr [{cfg}]",
            "mov rax, {junk}",
            "movq xmm0, rax",
            "mov eax, 0x3f800000", // 1.0f
            "movd xmm1, eax",
            "pxor xmm2, xmm2",     // 0.0f
            "divss xmm1, xmm2",
            cfg = in(reg) &config,
            junk = in(reg) 0xdead_beef_dead_beef_u64,
            out("rax") _,
            out("xmm0") _,
            out("xmm1") _,
            out("xmm2") _,
            options(nostack),
        );
    }
    let _ = cprintln!(console, "fpu-mxcsr: XM NOT DELIVERED");
    98
}

/// A task spawned after another task ended must see the kernel-defined
/// initial control state, not its predecessor's. Only MXCSR and the x87 FCW
/// are checked: a Rust prologue may legally touch XMM data registers before
/// this probe's first instruction, so data-register content is not a valid
/// witness check.
fn witness(console: absd_user::Console) -> i32 {
    let mut mxcsr: u32 = 0;
    let mut fcw: u16 = 0;
    unsafe {
        core::arch::asm!(
            "stmxcsr [{mxcsr_p}]",
            "fnstcw [{fcw_p}]",
            mxcsr_p = in(reg) &mut mxcsr,
            fcw_p = in(reg) &mut fcw,
            options(nostack),
        );
    }
    if mxcsr != MXCSR_DEFAULT || fcw != 0x037f {
        let _ = cprintln!(
            console,
            "fpu-mxcsr: witness CONTAMINATED mxcsr=0x{mxcsr:08x} fcw=0x{fcw:04x}"
        );
        return 97;
    }
    let _ = cprintln!(
        console,
        "fpu-mxcsr: witness default state mxcsr=0x{mxcsr:08x} fcw=0x{fcw:04x}"
    );
    0
}

/// Teardown variant: hold distinctive state and exit normally.
fn dirty_exit(console: absd_user::Console) -> i32 {
    let config = MXCSR_DEFAULT | MXCSR_RC_UP | MXCSR_FTZ;
    let _ = cprintln!(console, "fpu-mxcsr: dirty exit mxcsr=0x{config:08x}");
    unsafe {
        core::arch::asm!(
            "ldmxcsr [{cfg}]",
            "mov rax, {junk}",
            "movq xmm3, rax",
            "not rax",
            "movq xmm5, rax",
            cfg = in(reg) &config,
            junk = in(reg) 0x5a5a_5a5a_5a5a_5a5a_u64,
            out("rax") _,
            out("xmm3") _,
            out("xmm5") _,
            options(nostack),
        );
    }
    0
}

/// Teardown variant: hold distinctive state and yield until init kills the
/// task. The loop never returns; a kernel that resumed a killed task would
/// surface the escape line below.
fn dirty_loop(console: absd_user::Console) -> i32 {
    let config = MXCSR_DEFAULT | MXCSR_RC_DOWN | MXCSR_FTZ;
    let _ = cprintln!(console, "fpu-mxcsr: dirty loop armed mxcsr=0x{config:08x}");
    unsafe {
        core::arch::asm!(
            "ldmxcsr [{cfg}]",
            "mov rax, {junk}",
            "movq xmm1, rax",
            "not rax",
            "movq xmm6, rax",
            "2:",
            "mov rax, {yield_nr}",
            "int 0x80",
            "jmp 2b",
            cfg = in(reg) &config,
            junk = in(reg) 0x6b6b_6b6b_6b6b_6b6b_u64,
            yield_nr = const SYS_YIELD,
            out("rax") _,
            out("xmm1") _,
            out("xmm6") _,
            options(nostack),
        );
    }
    let _ = cprintln!(console, "fpu-mxcsr: dirty loop ESCAPED");
    99
}
