//! Host exercise of the actual ARM UART backend; no emulated hardware claim.
use absd_kernel::{
    console_presentation::RequestError,
    handle::{HandleTable, Object, RIGHT_WRITE},
};
use std::sync::Mutex;
#[allow(dead_code)]
#[path = "../src/arch/aarch64/serial.rs"]
mod serial;
mod sched {
    pub fn now() -> u64 {
        42
    }
}
static UART: Mutex<Vec<u8>> = Mutex::new(Vec::new());
fn uart_put(byte: u8) {
    UART.lock().unwrap().push(byte);
}
fn number(value: u64) {
    for byte in value.to_string().bytes() {
        uart_put(byte);
    }
}
fn main() {
    let mut handles = HandleTable::new(1);
    let console = handles.insert(Object::Console, RIGHT_WRITE).unwrap();
    let init = absd_abi::program::INIT as usize;
    let parent = absd_kernel::process::KERNEL_PARENT;
    assert_eq!(
        serial::presentation_request(1, parent, init, &handles, console, 1, 0),
        Err(RequestError::Unsupported)
    );
    assert_eq!(
        serial::presentation_request(1, parent, init, &handles, console, 0, 0),
        Err(RequestError::Unsupported)
    );
    assert_eq!(
        serial::presentation_request(2, parent, init, &handles, console, 1, 0),
        Err(RequestError::Rights)
    );
    assert_eq!(
        serial::presentation_request(1, parent, init, &handles, console, 2, 0),
        Err(RequestError::Invalid)
    );
    assert!(matches!(
        serial::presentation_request(1, parent, init, &handles, 0, 1, 0),
        Err(RequestError::Handle(_))
    ));
    serial::write("before");
    serial::presenter_ended(1, parent, init);
    serial::write(" after\n");
    assert_eq!(*UART.lock().unwrap(), b"before after\n");
    println!(
        "ARM presentation: valid requests refuse; authority/argument checks and UART output retained"
    );
}
