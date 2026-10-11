//! Closed FXSAVE migration composition fixture; no production placement change.
use absd_kernel::process::{FpuState, MAX_PROCESSES, Process};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
static ENABLED: AtomicBool = AtomicBool::new(false);
static MUTANT: AtomicU8 = AtomicU8::new(0);
static mut MIGRATED: [u64; MAX_PROCESSES] = [0; MAX_PROCESSES];
static mut PEER: Option<FpuState> = None;
static mut PREEMPTS: [u64; 4] = [0; 4];
static mut LIVE_PREEMPT: [[bool; 2]; MAX_PROCESSES] = [[false; 2]; MAX_PROCESSES];
static mut MASKS: [Option<u32>; 2] = [None; 2];
static mut CHECKS: [u64; 4] = [0; 4];
const A: [u64; 2] = [0x1357_9bdf_2468_ace0, 0xfedc_ba98_7654_3210];
const B: [u64; 2] = [0x0246_8ace_1357_9bdf, 0x0123_4567_89ab_cdef];
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
pub fn configure(mutant: u8) {
    assert!(
        crate::modern_smp::enabled() && crate::smp_user::standalone() && crate::cpu::count() == 2,
        "FPU fixture requires two admitted CPUs"
    );
    assert!(mutant <= 2 && !ENABLED.swap(true, Ordering::AcqRel));
    MUTANT.store(mutant, Ordering::Release);
}
fn role(slot: usize) -> u64 {
    crate::smp_user::fixture_role(slot)
}
pub fn migrated(slot: usize, pid: u64) {
    if enabled() && role(slot) == 61 {
        unsafe {
            MIGRATED[slot] = pid;
        }
    }
}
fn corrupting(p: &Process) -> bool {
    enabled() && crate::cpu::id() == 1 && unsafe { MIGRATED[crate::cpu::current()] == p.pid }
}
pub fn skip_restore(p: &Process) -> bool {
    let skip = corrupting(p) && MUTANT.load(Ordering::Acquire) == 1;
    if skip {
        crate::serial::write("SMP FPU INJECT skip-restore=1 migrated=1\n");
    }
    skip
}
pub fn restore_negative(p: &Process) {
    if corrupting(p) && MUTANT.load(Ordering::Acquire) == 2 {
        unsafe {
            let peer = PEER.expect("missing distinct FPU peer image");
            assert!(
                u32_at(&peer, 24) == 0x5fa0
                    && u16_at(&peer, 0) == 0x0b7f
                    && xmm(&peer, 0) == B
                    && xmm(&peer, 7) == A
            );
            crate::serial::write("SMP FPU INJECT crosswire=1 peer-distinct=1\n");
            crate::cpu::user_fpu().write_volatile(peer);
        }
    }
}
pub fn saved(slot: usize, p: &Process, preempted: bool) {
    if !enabled() {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    capture_mask(&p.task.fpu);
    let role = role(slot);
    if role == 62
        && u32_at(&p.task.fpu, 24) == 0x5fa0
        && u16_at(&p.task.fpu, 0) == 0x0b7f
        && xmm(&p.task.fpu, 0) == B
        && xmm(&p.task.fpu, 7) == A
    {
        unsafe {
            PEER = Some(p.task.fpu);
        }
    }
    if preempted
        && role == 61
        && crate::smp_user::fpu_nonvoluntary_interval()
        && u32_at(&p.task.fpu, 24) == 0x3fa0
        && u16_at(&p.task.fpu, 0) == 0x077f
        && xmm(&p.task.fpu, 0) == A
        && xmm(&p.task.fpu, 7) == B
    {
        let cpu = crate::cpu::id() as usize;
        unsafe {
            if !LIVE_PREEMPT[slot][cpu] {
                LIVE_PREEMPT[slot][cpu] = true;
                crate::serial::write("SMP FPU PREEMPT pid=");
                crate::serial::decimal(p.pid);
                crate::serial::write(" generation=");
                crate::serial::decimal(crate::modern_smp::generation(slot));
                crate::serial::write(" cpu=");
                crate::serial::decimal(cpu as u64);
                crate::serial::write(" count=1 interval=nonvoluntary live-asm=1\n");
            }
        }
    }
    if preempted && matches!(role, 61 | 62) {
        unsafe {
            PREEMPTS[usize::from(role == 62) * 2 + crate::cpu::id() as usize] += 1;
        }
    }
}
fn u16_at(image: &FpuState, offset: usize) -> u16 {
    u16::from_le_bytes(image.0[offset..offset + 2].try_into().unwrap())
}
fn u32_at(image: &FpuState, offset: usize) -> u32 {
    u32::from_le_bytes(image.0[offset..offset + 4].try_into().unwrap())
}
fn xmm(image: &FpuState, n: usize) -> [u64; 2] {
    let offset = 160 + n * 16;
    [
        u64::from_le_bytes(image.0[offset..offset + 8].try_into().unwrap()),
        u64::from_le_bytes(image.0[offset + 8..offset + 16].try_into().unwrap()),
    ]
}
pub fn observe(slot: usize, stage: u64) -> i64 {
    assert!(enabled());
    crate::kernel_lock::assert_current_owner();
    let cpu = crate::cpu::id();
    let p = &unsafe { crate::sched::table() }.entries[slot];
    assert_eq!(p.cpu_owner.unwrap().cpu, cpu);
    let image = unsafe { crate::cpu::user_fpu().read_volatile() };
    capture_mask(&image);
    let r = role(slot);
    let (mx, fcw, a, b) = if r == 63 {
        assert!(stage == 3 && cpu == 1);
        (0x1f80, 0x037f, [0; 2], [0; 2])
    } else if r == 62 {
        assert!(stage == 4 && cpu == 1);
        (0x5fa0, 0x0b7f, B, A)
    } else {
        assert!(r == 61 && (stage == 1 || stage == 2));
        assert_eq!(cpu, u8::from(stage == 1));
        (0x3fa0, 0x077f, A, B)
    };
    assert_eq!(u32_at(&image, 24), mx, "FPU migration MXCSR restore");
    assert_eq!(u16_at(&image, 0), fcw, "FPU migration x87 FCW restore");
    if r != 63 {
        assert_eq!(xmm(&image, 0), a, "FPU migration XMM0 restore");
        assert_eq!(xmm(&image, 7), b, "FPU migration XMM7 restore");
    }
    unsafe {
        CHECKS[(stage - 1) as usize] += 1;
    }
    crate::serial::write("SMP FPU USER pid=");
    crate::serial::decimal(p.pid);
    crate::serial::write(" generation=");
    crate::serial::decimal(crate::modern_smp::generation(slot));
    crate::serial::write(" cpu=");
    crate::serial::decimal(u64::from(cpu));
    crate::serial::write(" stage=");
    crate::serial::decimal(stage);
    crate::serial::write(" mxcsr=");
    crate::serial::decimal(u64::from(mx));
    crate::serial::write(" fcw=");
    crate::serial::decimal(u64::from(fcw));
    crate::serial::write(if r == 63 {
        " xmm0=0 xmm7=0 cpl=3\n"
    } else {
        " xmm0=1 xmm7=1 cpl=3\n"
    });
    1
}
pub fn finish() {
    if !enabled() {
        return;
    }
    unsafe {
        migration_compatible();
        assert_eq!({ CHECKS }, [16, 16, 3, 1]);
        assert!(
            PREEMPTS[0] >= 16 && PREEMPTS[1] >= 16 && PREEMPTS[3] > 0,
            "FPU migration lacked involuntary pressure"
        );
        crate::serial::write(
            "SMP FPU PROOF roundtrips=16 peers=1 defaults=3 faults=1 kills=1 preempts0=",
        );
        crate::serial::decimal(PREEMPTS[0]);
        crate::serial::write(" preempts1=");
        crate::serial::decimal(PREEMPTS[1]);
        crate::serial::write(" peer-preempts=");
        crate::serial::decimal(PREEMPTS[3]);
        crate::serial::write("\n");
    }
}

pub fn removed(slot: usize) {
    if enabled() {
        unsafe {
            if role(slot) == 61 {
                assert_eq!(
                    LIVE_PREEMPT[slot],
                    [true, true],
                    "migrant missing per-CPU live timer save"
                );
            }
            MIGRATED[slot] = 0;
            LIVE_PREEMPT[slot] = [false; 2];
        }
    }
}
pub fn continued(before: u64) -> i64 {
    assert!(enabled() && role(crate::cpu::current()) == 66);
    let progress = crate::smp_user::fpu_peer_progress();
    assert!(unsafe { crate::sched::stats() }.faults == 1 && progress > before);
    crate::serial::write("SMP FPU PEER POSTFAULT progress=");
    crate::serial::decimal(progress);
    crate::serial::write(" controls-checked=1\n");
    1
}

fn capture_mask(image: &FpuState) {
    let raw = u32_at(image, 28);
    let mask = if raw == 0 { 0xffbf } else { raw };
    assert_eq!(0x7fa0 & !mask, 0, "unsupported fixture MXCSR controls");
    unsafe {
        let slot = &mut MASKS[crate::cpu::id() as usize];
        if let Some(previous) = slot {
            assert_eq!(*previous, mask);
        } else {
            *slot = Some(mask);
        }
    }
}
pub fn migration_compatible() {
    if enabled() {
        unsafe {
            assert!(
                MASKS[0].is_some() && MASKS[1].is_some(),
                "FPU masks not captured before migration"
            );
            assert_eq!(MASKS[0], MASKS[1], "cross-CPU FXSAVE/MXCSR mask mismatch");
        }
    }
}
