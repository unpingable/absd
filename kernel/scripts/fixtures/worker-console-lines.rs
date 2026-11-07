// Actual init publisher/module; only finite console and pipe transport is adapted.
fn external_abort(_: u64, _: Pipe, _: bool, _: Pipe) {
    panic!("unexpected abort in the successful stream-flush fixture");
}
fn actual_stderr_read_error(worker_output: &mut worker_console::Output) -> Result<(), &'static str> {
    struct Guard(bool);
    impl Guard { fn close(&mut self) { self.0 = true; } }
    let mut stderr_guard = Guard(false);
    let mut stderr_open = true;
    let (child, input_writer, writer_open, output_reader) = (0u64, Pipe(3), false, Pipe(4));
    assert!(stderr_open && !stderr_guard.0);
    @STDERR_READ_ERROR@
    assert!(stderr_guard.0 && !stderr_open);
    Ok(())
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = &args[1];
    let out = std::path::Path::new(&args[2]);
    let mut output = worker_console::Output::new(Console, 0, 0x811c9dc5);
    Console.write_str("ABSD KERNEL BOOT\nEXTERNAL OUTPUT BEGIN encoding=hex\n").unwrap();
    let mut expected = Vec::new();
    let mut complete = true;
    match mode.as_str() {
        "observed" => {
            let key = std::fs::read(out.join("key.input")).unwrap();
            let mount = std::fs::read(out.join("mount.input")).unwrap();
            let cut: usize = std::fs::read_to_string(out.join("cut.input")).unwrap().trim().parse().unwrap();
            for (stream, bytes) in [(1, &key[..cut]), (0, &mount[..96]), (1, &key[cut..]), (0, &mount[96..])] {
                external_worker_chunk(Console, None, &mut output, stream, bytes).unwrap();
            }
            expected.extend_from_slice(&key); expected.extend_from_slice(&mount);
        }
        "concurrent" => {
            let (sender, receiver) = std::sync::mpsc::sync_channel(2);
            let mut threads = Vec::new();
            for stream in 0..2 {
                let sender = sender.clone();
                threads.push(std::thread::spawn(move || {
                    for n in 0..16 {
                        let line = format!("stream={stream} line={n:02} {}\n", "x".repeat(600));
                        for chunk in line.as_bytes().chunks(if stream == 0 { 96 } else { 53 }) {
                            sender.send((stream, chunk.to_vec())).unwrap(); std::thread::yield_now();
                        }
                    }
                }));
            }
            drop(sender);
            for (stream, bytes) in receiver { external_worker_chunk(Console, None, &mut output, stream, &bytes).unwrap(); }
            for thread in threads { thread.join().unwrap(); }
        }
        "binary" | "long" | "cap-newline" | "tail" => {
            let bytes = match mode.as_str() {
                "binary" => (0..4353).map(|i| (i % 256) as u8).collect::<Vec<_>>(),
                "long" => [vec![b'x'; worker_console::LINE_BYTES + 17], b"\n".to_vec()].concat(),
                "cap-newline" => [vec![b'x'; worker_console::LINE_BYTES - 1], b"\n".to_vec()].concat(),
                _ => b"unterminated tail".to_vec(),
            };
            for chunk in bytes.chunks(37) { external_worker_chunk(Console, None, &mut output, 0, chunk).unwrap(); }
            output.finish_stream(0).unwrap(); output.finish_stream(1).unwrap();
            expected = bytes;
        }
        "abort" => {
            external_worker_chunk(Console, None, &mut output, 0, b"stdout tail").unwrap();
            external_worker_chunk(Console, None, &mut output, 1, b"stderr tail").unwrap();
            drop(output);
            std::fs::write(out.join("serial.log"), serial()).unwrap();
            std::fs::write(out.join("expected.bin"), b"stdout tailstderr tail").unwrap();
            return;
        }
        "write-failure" => {
            FAIL_SERIAL.with(|v| v.set(true));
            assert!(external_worker_chunk(Console, None, &mut output, 0, b"refused\n").is_err());
            FAIL_SERIAL.with(|v| v.set(false));
            assert!(output.push(0, b"must not resume\n").is_err());
            drop(output);
            assert_eq!(serial(), b"ABSD KERNEL BOOT\nEXTERNAL OUTPUT BEGIN encoding=hex\n");
            std::fs::write(out.join("serial.log"), serial()).unwrap();
            return;
        }
        "read-error" => {
            external_worker_chunk(Console, None, &mut output, 1, b"stderr read tail").unwrap();
            actual_stderr_read_error(&mut output).unwrap();
            expected.extend_from_slice(b"stderr read tail");
        }
        "partial-write" => {
            let bytes = [vec![b'x'; 300], b"\n".to_vec()].concat();
            FAIL_AFTER_WRITE.with(|v| v.set(true));
            assert!(output.push(0, &bytes).is_err());
            FAIL_SERIAL.with(|v| v.set(false));
            let before = serial();
            assert!(output.push(0, b"must not resume\n").is_err());
            drop(output);
            assert_eq!(serial(), before, "indeterminate frame publication was retried");
            std::fs::write(out.join("serial.log"), serial()).unwrap();
            std::fs::write(out.join("expected.bin"), &bytes[..96]).unwrap();
            return;
        }
        "offset-overflow" => {
            drop(output);
            let mut output = worker_console::Output::new(Console, usize::MAX, 0x811c9dc5);
            assert!(output.push(0, b"\n").is_err());
            assert!(output.push(0, b"must stay refused").is_err(), "offset overflow did not retire publication");
            drop(output);
            std::fs::write(out.join("serial.log"), serial()).unwrap();
            return;
        }

        "fsd-interleaved" => {
            unsafe { FSD_LOG_READERS = [1, 2]; }
            queue(1, b"out-a"); queue(2, b"err-a\n"); assert!(!drain_fsd_logs(Console));
            queue(1, b"b\n"); queue(2, b"err-b\n"); assert!(!drain_fsd_logs(Console));
            assert!(drain_fsd_logs(Console));
            let shown = String::from_utf8(serial()).unwrap();
            assert!(shown.contains("out-ab\n"));
            assert!(shown.find("err-a\n").unwrap() < shown.find("err-b\n").unwrap());
            external_worker_chunk(Console, None, &mut output, 0, b"worker\n").unwrap();
            expected.extend_from_slice(b"worker\n");
        }
        "fsd-boundary" | "fsd-eof" | "fsd-error" | "fsd-close" => {
            unsafe { FSD_LOG_READERS = [1, 2]; }
            let tail = b"RECOVERY WRITABLE RESUMED id=partial";
            queue(1, tail); assert!(!drain_fsd_logs(Console));
            assert!(!console_lines::source_boundary(console_lines::FSD_STDOUT));
            if mode == "fsd-eof" { EOF_PIPE.with(|v| v.set(1)); }
            if mode == "fsd-error" { ERROR_PIPE.with(|v| v.set(1)); }
            if mode == "fsd-close" { finish_fsd_logs(Console); }
            else if mode != "fsd-boundary" { assert!(!drain_fsd_logs(Console)); }
            external_worker_chunk(Console, None, &mut output, 0, b"worker\n").unwrap();
            assert!(!console_lines::source_boundary(console_lines::FSD_STDOUT), "presentation supplied a source newline");
            assert!(!drain_fsd_logs(Console));
            assert!(serial().windows(b"id=partial [console partial]\n".len()).any(|w| w == b"id=partial [console partial]\n"));
            assert!(RETAINED.with(|v| v.borrow().as_slice() == tail));
            if mode == "fsd-boundary" {
                queue(1, b" suffix\n"); assert!(!drain_fsd_logs(Console));
                assert!(drain_fsd_logs(Console));
            }
            expected.extend_from_slice(b"worker\n");
        }
        "maintenance-boundary" => {
            let mut terminal = local_console::Terminal::new().unwrap();
            console_lines::forward(Console, console_lines::LOGD, b"pending logger").unwrap();
            let before = serial(); terminal.step(Console, Pipe(3));
            assert_eq!(serial(), before, "ordinary polls must coalesce pending lines");
            INPUT.with(|q| q.borrow_mut().extend(b"\x1dk"));
            terminal.step(Console, Pipe(3));
            let log = String::from_utf8(serial()).unwrap();
            assert!(log.find("pending logger [console partial]\n").unwrap() < log.find("ABSD kernel maintenance").unwrap());
            assert!(!local_console::startup_capture_closed());
        }
        "maintenance-poisoned" => {
            let mut terminal = local_console::Terminal::new().unwrap();
            FAIL_SERIAL.with(|v| v.set(true));
            assert!(console_lines::forward(Console, console_lines::LOGD, &[b'x'; 224]).is_err());
            FAIL_SERIAL.with(|v| v.set(false));
            SNAPSHOT_ENABLED.with(|v| v.set(true));
            INPUT.with(|q| q.borrow_mut().extend(b"\x1dk"));
            terminal.step(Console, Pipe(3));
            let shown = String::from_utf8(serial()).unwrap();
            assert!(shown.contains("ABSD kernel maintenance"), "poisoned arbiter suppressed the maintenance banner");
            assert!(shown.contains("[seq=1 ticks=123 severity=4 source=kernel flags=0] read-only snapshot survives\n"), "poisoned arbiter suppressed the actual snapshot");
            assert!(SNAPSHOT_READS.with(Cell::get) >= 2);
            assert!(!local_console::startup_capture_closed());
            let before = serial();
            assert!(external_worker_chunk(Console, None, &mut output, 0, b"still refused\n").is_err());
            assert_eq!(serial(), before, "read-only diagnostics revived framed publication");
            complete = false;
        }
        "pre-prompt" => {
            unsafe { FSD_LOG_READERS = [1, 2]; }
            queue(1, b"RECOVERY WRITABLE RESUMED id=0123456789abcdef0123456789abcdef previous=failed fs_seq=1926 ledger_seq=2\nRELEASE OK release=fixture\n");
            let mut terminal = local_console::Terminal::new().unwrap();
            queue(terminal.writer(), b"LOCAL LOGIN FIXTURE\n"); terminal.spawned();
            external_worker_chunk(Console, Some(&mut terminal), &mut output, 0, b"pending startup").unwrap();
            let ready = b"SSH LISTENING port=22 authorized_keys=1 preauth_per_source=2\n";
            external_worker_chunk(Console, Some(&mut terminal), &mut output, 1, ready).unwrap();
            assert!(terminal.startup_ready());
            assert!(!local_console::startup_capture_closed());
            external_worker_startup(Console, &mut terminal, &mut output, Pipe(3), drain_fsd_logs(Console)).unwrap();
            assert!(local_console::startup_capture_closed());
            let before = serial();
            external_worker_chunk(Console, Some(&mut terminal), &mut output, 0, b"runtime hidden\n").unwrap();
            assert_eq!(serial(), before, "runtime output crossed the owned prompt");
            expected.extend_from_slice(ready); expected.extend_from_slice(b"pending startup");
            output.finish().unwrap();
            let (offset, digest) = output.position();
            external_output_end(Console, true, offset, digest).unwrap();
            complete = false;
        }
        _ => panic!("unknown fixture mode"),
    }
    if complete {
        output.finish().unwrap();
        let (offset, digest) = output.position();
        external_output_end(Console, false, offset, digest).unwrap();
    }
    std::fs::write(out.join("serial.log"), serial()).unwrap();
    if mode != "concurrent" { std::fs::write(out.join("expected.bin"), expected).unwrap(); }
}
