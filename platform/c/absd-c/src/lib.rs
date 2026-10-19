//! libabs: the ABSD runtime packaged for C. The runtime supplies `_start`,
//! the startup record, the allocator, the file-server client and the
//! `__absd_std_*` hooks; this crate adds only what a link without Rust
//! `std` is missing: the panic handler. Everything else the C side needs
//! is C (`c/libabs/*.c`).
#![no_std]

extern crate absd_runtime;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;
    struct Stderr;
    impl Write for Stderr {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let bytes = text.as_bytes();
            let mut written = 0;
            while written < bytes.len() {
                let n = unsafe { absd_runtime::__absd_std_stderr_write(bytes[written..].as_ptr(), bytes.len() - written) };
                if n <= 0 {
                    break;
                }
                written += n as usize;
            }
            Ok(())
        }
    }
    let _ = writeln!(Stderr, "panic: {info}");
    absd_runtime::__absd_std_exit(101)
}

/// Linked by `crt0.c` so the archive member holding `_start` is always pulled.
#[unsafe(no_mangle)]
pub extern "C" fn __absd_c_anchor() {}
