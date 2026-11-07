//! COM1 diagnostics, mirrored to the framebuffer console when one exists.

use absd_kernel::console_input::{Input, Source};
use core::arch::asm;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const COM1: u16 = 0x3f8;
/// A missing or non-progressing UART must not hold kernel serialization
/// indefinitely. The bound counts port polls, not elapsed wall time.
const TX_READY_POLLS: usize = 100_000;
static TX_DROPPED: AtomicU64 = AtomicU64::new(0);
// A transiently blocked emulator backend must not discard a diagnostic byte.
// Current ordinary nonfatal paths serialize this boot-local FIFO. BSP/BKL
// owner checks alone do not exclude same-CPU terminal reentry; fatal raw
// output is independent of the FIFO and digest.
const TX_CAPACITY: usize = 256;
static mut TX_BYTES: [u8; TX_CAPACITY] = [0; TX_CAPACITY];
static mut TX_HEAD: usize = 0;
static mut TX_LEN: usize = 0;
// Rounds that exhausted their polling budget with bytes still pending. This
// is deferred work, not loss; keep it distinct from TX_DROPPED.
static TX_DEFERRED: AtomicU64 = AtomicU64::new(0);
// Only root init can request managed ownership. Retention remains independent.
static MANAGED_PRESENTATION: AtomicBool = AtomicBool::new(false);

pub(crate) fn presentation_request(
    pid: u64,
    parent: u64,
    program: usize,
    handles: &absd_kernel::handle::HandleTable,
    console: u64,
    mode: u64,
    reserved: u64,
) -> Result<(), absd_kernel::console_presentation::RequestError> {
    let managed = absd_kernel::console_presentation::request(
        pid, parent, program, handles, console, mode, reserved,
    )?;
    // Old queued diagnostics must finish or be accounted before a UI starts.
    if managed {
        finish_output();
    }
    MANAGED_PRESENTATION.store(managed, Ordering::Release);
    Ok(())
}

/// Terminal kernel paths restore detailed fatal output, never normal UI work.
pub(crate) fn emergency_presentation() {
    MANAGED_PRESENTATION.store(false, Ordering::Release);
}

pub(crate) fn presenter_ended(pid: u64, parent: u64, program: usize) {
    if absd_kernel::kernel_log::root_init_role(pid, parent, program) {
        emergency_presentation();
    }
}

/// Bytes omitted because the pending FIFO was full or the final bounded
/// drain could not transmit them. An exhausted ordinary polling round retains
/// bytes for the next call. Not verified UART acceptance: an absent UART reads
/// the line status as 0xff (THRE set), so its bytes count as sent. The
/// `EVIDENCE DIGEST` line reports this as `tx-dropped`.
pub fn tx_dropped() -> u64 {
    TX_DROPPED.load(Ordering::Relaxed)
}

fn assert_tx_owner() {
    if crate::smp_user::enabled() {
        crate::kernel_lock::assert_current_owner();
    } else {
        crate::kernel_lock::assert_bsp_device_access();
    }
}

/// Returns the unused portion of one bounded polling round. Pending bytes
/// retain their order across calls; a failed round changes no byte's custody.
fn drain_pending(mut polls: usize) -> usize {
    unsafe {
        while TX_LEN != 0 && polls != 0 {
            polls -= 1;
            if inb(COM1 + 5) & 0x20 != 0 {
                outb(COM1, TX_BYTES[TX_HEAD]);
                TX_HEAD = (TX_HEAD + 1) % TX_CAPACITY;
                TX_LEN -= 1;
            } else {
                core::hint::spin_loop();
            }
        }
    }
    polls
}

/// Terminal transition: retry pending output once, then account every byte
/// still unwritten as lost. No queue or unbounded wait survives this boundary.
pub fn finish_output() {
    assert_tx_owner();
    drain_pending(TX_READY_POLLS);
    unsafe {
        TX_DROPPED.fetch_add(TX_LEN as u64, Ordering::Relaxed);
        TX_LEN = 0;
        TX_HEAD = 0;
    }
}

/// No-UART evidence (docs/hardware/NO-UART-EVIDENCE.md): a running
/// FNV-1a-64 digest and count of bytes passed to [`display_byte_out`], in
/// order, from the first byte of the boot. Retained-only diagnostics during
/// managed presentation are excluded; userspace display bytes are included.
/// A host recomputes it over the captured serial log; a screen photograph of the line that prints it
/// names that log. A byte counts whether or not the transmit wait ran out
/// ([`tx_dropped`]).
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
static DIGEST: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static DIGEST_BYTES: AtomicU64 = AtomicU64::new(0);

/// `(bytes, FNV-1a-64)` of the console stream so far.
pub fn evidence() -> (u64, u64) {
    // Make pending prefix bytes either transmitted or explicitly lost before
    // a digest record describes that prefix.
    finish_output();
    (
        DIGEST_BYTES.load(Ordering::Relaxed),
        DIGEST.load(Ordering::Relaxed),
    )
}

pub fn init() {
    unsafe {
        // Select the receive buffer (DLAB clear) and bank a byte that may
        // already be waiting from before the kernel ran, before the FIFO
        // reset below would discard it. No UART at all reads as 0xff.
        outb(COM1 + 3, 0x03);
        if inb(COM1 + 5) != 0xff {
            drain_input();
        }
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x80);
        outb(COM1, 0x03);
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03);
        outb(COM1 + 2, 0xc7);
        outb(COM1 + 4, 0x0b);
    }
}

/// Turns on the receive-data interrupt (IRQ4). Call once the IDT and PIC
/// are ready; bytes that arrived earlier wait in the UART FIFO.
pub fn enable_input() {
    unsafe {
        outb(COM1 + 1, 0x01);
    }
}

/// The Console stream, filled by COM1 IRQ or the BSP keyboard pump and
/// drained by Console reads, always with IF clear on the BSP.
static mut INPUT: Input = Input::new();
// AP readiness checks must not borrow the BSP-owned FIFO, which a BSP IRQ
// may update while that AP owns kernel serialization. Only the level crosses
// CPUs; consuming input remains the existing BSP Console operation.
static INPUT_READABLE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn input_readable() -> bool {
    INPUT_READABLE.load(core::sync::atomic::Ordering::Acquire)
}

/// Moves every byte the UART holds into the input ring. Called from the
/// COM1 interrupt stub; bytes beyond the ring's capacity are dropped and
/// counted rather than blocking the interrupt. The loop is bounded by the
/// UART's 16-byte FIFO so a stuck status line cannot hang the kernel.
pub unsafe fn drain_input() {
    unsafe {
        let ring = &mut *core::ptr::addr_of_mut!(INPUT);
        for _ in 0..16 {
            let status = inb(COM1 + 5);
            if status == 0xff || status & 0x01 == 0 {
                break;
            }
            let byte = inb(COM1);
            ring.push(Source::Serial, byte);
        }
        INPUT_READABLE.store(ring.available() != 0, core::sync::atomic::Ordering::Release);
    }
}

/// Takes up to `buffer.len()` received bytes in arrival order.
pub fn take_input(buffer: &mut [u8]) -> usize {
    unsafe {
        let ring = &mut *core::ptr::addr_of_mut!(INPUT);
        ring.report_loss(crate::sched::now(), &absd_kernel::kernel_log::LOG);
        let count = ring.take(buffer);
        INPUT_READABLE.store(ring.available() != 0, core::sync::atomic::Ordering::Release);
        count
    }
}

pub fn input_available() -> usize {
    unsafe { (*core::ptr::addr_of!(INPUT)).available() }
}

/// Bytes discarded because the ring was full.
pub fn input_dropped() -> u64 {
    unsafe { (*core::ptr::addr_of!(INPUT)).total_dropped() }
}

/// One report's translated bytes. The small ISR never enters this path.
pub fn keyboard_input(bytes: &[u8]) -> usize {
    crate::debug_assert_interrupts_disabled();
    crate::kernel_lock::assert_bsp_device_access();
    crate::kernel_lock::assert_held(crate::kernel_lock::BSP);
    assert!(bytes.len() <= 6);
    unsafe {
        let ring = &mut *core::ptr::addr_of_mut!(INPUT);
        let count = bytes
            .iter()
            .filter(|&&byte| ring.push(Source::Keyboard, byte))
            .count();
        INPUT_READABLE.store(ring.available() != 0, core::sync::atomic::Ordering::Release);
        count
    }
}

pub fn input_counts(source: Source) -> (u64, u64) {
    unsafe {
        let ring = &*core::ptr::addr_of!(INPUT);
        (ring.accepted(source), ring.dropped(source))
    }
}

pub fn write(s: &str) {
    for byte in s.bytes() {
        byte_out(byte);
    }
}

/// Last-resort operator refusal only: caller is the BSP with IF clear and
/// must halt afterward. BKL may be retained by a failed AP. No ownership
/// assertions, framebuffer, digest state, allocation or unbounded UART wait.
pub(crate) fn fatal_raw(bytes: &[u8]) {
    absd_kernel::kernel_log::LOG.emit(b"fatal", 2, None, bytes, absd_kernel::kernel_log::EMERGENCY);
    // Absolute per-call work bound, including a failed UART.
    for &byte in bytes.iter().take(1024) {
        for _ in 0..TX_READY_POLLS {
            unsafe {
                if inb(COM1 + 5) & 0x20 != 0 {
                    outb(COM1, byte);
                    break;
                }
            }
            core::hint::spin_loop();
        }
    }
}

/// Set while a serial-only record is written (`record_only`).
static mut SCREEN_MUTED: bool = false;

/// One console byte: COM1 first, then the framebuffer console when one is
/// active. A machine without a UART reads the line status as 0xff, so the
/// wait falls through and only the framebuffer shows the byte.
pub fn byte_out(byte: u8) {
    absd_kernel::kernel_log::LOG.byte(
        byte,
        absd_kernel::kernel_log::timestamp(crate::sched::now()),
    );
    if !MANAGED_PRESENTATION.load(Ordering::Acquire) {
        display_byte_out(byte);
    }
}

/// Console userspace output is a display consumer, never a kernel producer.
pub fn display_byte_out(byte: u8) {
    // Qualification TX shares the BKL; RX IRQ ownership remains BSP.
    assert_tx_owner();
    // The load/store relies on ordinary nonfatal caller serialization,
    // as does the FIFO; complete NMI, kernel-fault and panic traces are not promised.
    DIGEST.store(
        (DIGEST.load(Ordering::Relaxed) ^ u64::from(byte)).wrapping_mul(FNV_PRIME),
        Ordering::Relaxed,
    );
    DIGEST_BYTES.fetch_add(1, Ordering::Relaxed);
    let mut polls = TX_READY_POLLS;
    unsafe {
        if TX_LEN == TX_CAPACITY {
            polls = drain_pending(polls);
        }
        if TX_LEN == TX_CAPACITY {
            TX_DROPPED.fetch_add(1, Ordering::Relaxed);
        } else {
            TX_BYTES[(TX_HEAD + TX_LEN) % TX_CAPACITY] = byte;
            TX_LEN += 1;
        }
    }
    drain_pending(polls);
    if unsafe { TX_LEN != 0 } {
        TX_DEFERRED.fetch_add(1, Ordering::Relaxed);
    }
    if !unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SCREEN_MUTED)) } {
        if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SCREEN_DEFERRED)) } {
            unsafe { (*core::ptr::addr_of_mut!(DEFERRED)).push(byte) };
        } else {
            crate::framebuffer::put(byte);
        }
    }
}

/// While set, screen bytes wait in [`DEFERRED`]. Set before the IOMMU comes up in
/// a `dma-contain` boot, so drawing does not lengthen the uncontained window.
static mut SCREEN_DEFERRED: bool = false;
static mut DEFERRED: absd_kernel::defer_log::DeferLog<32768> =
    absd_kernel::defer_log::DeferLog::EMPTY;

pub fn defer_screen() {
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(SCREEN_DEFERRED), true) };
}

/// Draws what was held back and goes back to drawing as bytes arrive. Also the
/// fatal paths' way to show the log, so a crash before the sweep is not silent.
pub fn flush_screen() {
    unsafe {
        if !core::ptr::read_volatile(core::ptr::addr_of!(SCREEN_DEFERRED)) {
            return;
        }
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SCREEN_DEFERRED), false);
        (*core::ptr::addr_of_mut!(DEFERRED)).drain(crate::framebuffer::put);
        let dropped = (*core::ptr::addr_of!(DEFERRED)).dropped();
        if dropped != 0 {
            // Serial and the digest have these bytes; the screen does not.
            let _ = core::fmt::Write::write_fmt(
                &mut Serial,
                format_args!("CONSOLE SCREEN-DROPPED bytes={dropped}\n"),
            );
        }
    }
}

/// Runs `write` with the framebuffer muted: its bytes reach COM1 only.
/// Used for whole `RECORD ...` lines, which the screen oracles skip.
pub fn record_only(write: impl FnOnce()) {
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(SCREEN_MUTED), true) };
    write();
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(SCREEN_MUTED), false) };
}

pub fn hex(value: u64) {
    write("0x");
    for shift in (0..16).rev() {
        let digit = ((value >> (shift * 4)) & 0xf) as u8;
        byte_out(if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        });
    }
}

/// The low `digits` hex digits of `value`, without a prefix.
pub fn hex_digits(value: u64, digits: u32) {
    for shift in (0..digits).rev() {
        let digit = ((value >> (shift * 4)) & 0xf) as u8;
        byte_out(if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        });
    }
}

pub fn decimal(value: u64) {
    if value >= 10 {
        decimal(value / 10);
    }
    byte_out(b'0' + (value % 10) as u8);
}

pub fn signed(value: i32) {
    if value < 0 {
        byte_out(b'-');
        decimal(value.unsigned_abs() as u64);
    } else {
        decimal(value as u64);
    }
}

/// `core::fmt` sink, used for panic messages and other rare formatted output.
pub struct Serial;

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write(s);
        Ok(())
    }
}

pub unsafe fn outb(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags));
    }
    value
}
