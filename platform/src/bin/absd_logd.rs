#![cfg_attr(target_os = "absd", feature(restricted_std))]
//! Separately supervised collector: all filesystem transport has deadlines.
#[cfg(target_os = "absd")]
#[path = "../../ssh/src/service_journal.rs"]
mod collector;
#[cfg(target_os = "absd")]
fn main() {
    absd_runtime::link_anchor();
    use absd_fsd::journal_rpc::RpcStore;
    let raw = absd_runtime::boot_id().unwrap_or_else(|e| {
        eprintln!("LOGD FAILED boot identity {e}");
        std::process::exit(3)
    });
    let id: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let boot: [u8; 32] = id.as_bytes().try_into().expect("boot hex");
    let deadline = std::rc::Rc::new(std::cell::Cell::new(
        absd_runtime::ticks().saturating_add(4000),
    ));
    let rpc_deadline = deadline.clone();
    let mut store = RpcStore::new(move |frame| {
        let now = absd_runtime::ticks();
        let end = rpc_deadline.get();
        absd_fsd::journal_rpc::bounded_request(frame, now, end, |frame, ticks| {
            absd_runtime::fsd::request_on_within(0, frame, ticks)
        })
    });
    if let Err(e) = store.begin() {
        eprintln!("LOGD FAILED channel begin {e:?}");
        std::process::exit(if store.needs_reattachment() {
            absd_fsd::journal_rpc::REATTACH_EXIT_STATUS
        } else {
            3
        })
    }
    let mut collector = collector::Collector::new(&mut store, boot);
    check_attachment(&store);
    println!(
        "LOGD READY boot={id} {}",
        collector.journal.health().trim_end()
    );
    let input = absd_runtime::standard_stream_handles().0;
    loop {
        absd_runtime::liveness_beat();
        let mut command = [0u8; 1];
        match absd_runtime::read_within(input, &mut command, 1) {
            Ok(0) | Ok(1) if command[0] == 0 || command[0] == b'S' => {
                deadline.set(absd_runtime::ticks().saturating_add(1000));
                collector.drain(&mut store);
                let status = if collector.journal.sink_error.is_none()
                    && collector.journal.sink_lost == 0
                    && collector.journal.pending() == 0
                {
                    0
                } else {
                    4
                };
                // Retire this generation's server-side handles before EOF.
                let _ = store.begin();
                std::process::exit(status);
            }
            Ok(_) | Err(-110) => {}
            Err(e) => {
                eprintln!("LOGD FAILED stop pipe {e}");
                std::process::exit(3)
            }
        }
        // Bound the complete pass, including reopen scans and legacy lines.
        // A per-request bound alone cannot protect init's 5000-tick watchdog.
        deadline.set(absd_runtime::ticks().saturating_add(4000));
        collector.poll(&mut store);
        if let Some(notice) = collector.confirmed_acquisition_notice(&mut store) {
            print!("{notice}");
        }
        check_attachment(&store);
        absd_runtime::sleep_ticks(10);
    }
}
#[cfg(not(target_os = "absd"))]
fn main() {
    eprintln!("absd-logd requires an init-provisioned private FSD channel and Diagnostics grant");
    std::process::exit(2)
}

#[cfg(target_os = "absd")]
fn check_attachment<F: FnMut(Vec<u8>) -> Result<(i64, Vec<u8>), i64>>(
    store: &absd_fsd::journal_rpc::RpcStore<F>,
) {
    if store.needs_reattachment() {
        eprintln!(
            "LOGD TRANSIENT attachment outcome unknown or handle quota exhausted; exact generation must be reaped before LOGGER_BEGIN"
        );
        std::process::exit(absd_fsd::journal_rpc::REATTACH_EXIT_STATUS);
    }
}
