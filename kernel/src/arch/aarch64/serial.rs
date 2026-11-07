// ARM has no physical-input/presentation owner yet. Validate the shared
// request, then refuse it explicitly instead of pretending to claim the UART.
pub(crate) fn presentation_request(
    pid: u64,
    parent: u64,
    program: usize,
    handles: &absd_kernel::handle::HandleTable,
    console: u64,
    mode: u64,
    reserved: u64,
) -> Result<(), absd_kernel::console_presentation::RequestError> {
    absd_kernel::console_presentation::request(
        pid, parent, program, handles, console, mode, reserved,
    )?;
    Err(absd_kernel::console_presentation::RequestError::Unsupported)
}

pub(crate) fn presenter_ended(_: u64, _: u64, _: usize) {
    // No request can acquire presentation ownership on this backend.
}

pub fn write(s: &str) {
    for b in s.bytes() {
        byte_out(b);
    }
}
pub fn byte_out(b: u8) {
    absd_kernel::kernel_log::LOG.byte(b, absd_kernel::kernel_log::timestamp(crate::sched::now()));
    display_byte_out(b);
}
pub fn display_byte_out(b: u8) {
    crate::uart_put(b);
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
pub fn input_readable() -> bool {
    input_available() != 0
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
