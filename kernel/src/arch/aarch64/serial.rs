pub fn write(s: &str) {
    crate::out(s)
}
pub fn byte_out(b: u8) {
    unsafe {
        while crate::read32(crate::UART + 0x18) & (1 << 5) != 0 {
            core::hint::spin_loop();
        }
        crate::write32(crate::UART, b as u32);
    }
}
pub fn decimal(v: u64) {
    crate::number(v)
}
pub fn signed(v: i32) {
    if v < 0 {
        write("-");
    }
    decimal(v.unsigned_abs() as u64)
}
pub fn hex(v: u64) {
    write("0x");
    hex_digits(v, 16);
}
pub fn hex_digits(v: u64, n: u32) {
    for shift in (0..n).rev() {
        byte_out(b"0123456789abcdef"[((v >> (shift * 4)) & 15) as usize]);
    }
}
pub fn input_available() -> usize {
    0
}
pub fn input_dropped() -> u64 {
    0
}
pub fn take_input(_: &mut [u8]) -> usize {
    0
}
pub fn record_only(f: impl FnOnce()) {
    f();
}
