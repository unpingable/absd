// Exercise the production maintenance state machine with the actual kernel
// producer encoding and the same first-party decoder used by platform dmesg.
use crate::local_console_text as console_text;
#[path = "../user/src/kernel_log_wire.rs"]
mod log;
#[path = "../user/src/console_snapshot.rs"]
mod snapshot;

#[test]
fn snapshot_reader_request_matches_the_actual_kernel_request_parser() {
    let initial = log::Cursor::new();
    assert_eq!(initial.next(), 0);
    assert_eq!(
        crate::kernel_log::read_request(&log::request(initial), 0),
        Ok(0)
    );
    let later = log::Cursor::at(17);
    assert_eq!(later.next(), 17);
    assert_eq!(
        crate::kernel_log::read_request(&log::request(later), 0),
        Ok(17)
    );
}
