//! COM1 diagnostics, mirrored to the framebuffer console when one exists.

use core::arch::asm;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

const COM1: u16 = 0x3f8;
/// A missing or non-progressing UART must not hold kernel serialization
/// indefinitely. The bound counts port polls, not elapsed wall time.
const TX_READY_POLLS: usize = 100_000;
static TX_DROPPED: AtomicU64 = AtomicU64::new(0);

pub fn tx_dropped() -> u64 {
    TX_DROPPED.load(Ordering::Relaxed)
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

const INPUT_CAPACITY: usize = 256;

/// Bytes received from COM1 and not yet read by a process. Filled from the
/// interrupt handler, drained by the console read path; both run with
/// interrupts disabled on the single CPU, so no other synchronisation.
struct InputRing {
    bytes: [u8; INPUT_CAPACITY],
    head: usize,
    len: usize,
    dropped: u64,
}

static mut INPUT: InputRing = InputRing {
    bytes: [0; INPUT_CAPACITY],
    head: 0,
    len: 0,
    dropped: 0,
};

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
            if ring.len == INPUT_CAPACITY {
                ring.dropped += 1;
                continue;
            }
            ring.bytes[(ring.head + ring.len) % INPUT_CAPACITY] = byte;
            ring.len += 1;
        }
    }
}

/// Takes up to `buffer.len()` received bytes in arrival order.
pub fn take_input(buffer: &mut [u8]) -> usize {
    unsafe {
        let ring = &mut *core::ptr::addr_of_mut!(INPUT);
        let count = buffer.len().min(ring.len);
        for slot in buffer[..count].iter_mut() {
            *slot = ring.bytes[ring.head];
            ring.head = (ring.head + 1) % INPUT_CAPACITY;
        }
        ring.len -= count;
        count
    }
}

pub fn input_available() -> usize {
    unsafe { (*core::ptr::addr_of!(INPUT)).len }
}

/// Bytes discarded because the ring was full.
pub fn input_dropped() -> u64 {
    unsafe { (*core::ptr::addr_of!(INPUT)).dropped }
}

pub fn write(s: &str) {
    for byte in s.bytes() {
        byte_out(byte);
    }
}

/// Set while a serial-only record is written (`record_only`).
static mut SCREEN_MUTED: bool = false;

/// One console byte: COM1 first, then the framebuffer console when one is
/// active. A machine without a UART reads the line status as 0xff, so the
/// wait falls through and only the framebuffer shows the byte.
pub fn byte_out(byte: u8) {
    if crate::smp_user::enabled() {
        // Qualification TX shares the BKL; RX IRQ ownership remains BSP.
        crate::kernel_lock::assert_current_owner();
    } else {
        crate::kernel_lock::assert_bsp_device_access();
    }
    let mut sent = false;
    unsafe {
        for _ in 0..TX_READY_POLLS {
            if inb(COM1 + 5) & 0x20 != 0 {
                outb(COM1, byte);
                sent = true;
                break;
            }
            core::hint::spin_loop();
        }
    }
    if !sent {
        TX_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
    if !unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SCREEN_MUTED)) } {
        crate::framebuffer::put(byte);
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
