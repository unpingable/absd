#![feature(restricted_std)]
//! Native stream and DNS fallback consumer. Only one owner-issued channel;
//! no NIC/spawn authority. stderr carries bounded human-readable results.
use absd_net::{
    datagram::{
        self as d,
        channel::{KernelPipe, Pipe, transact},
    },
    dns, stream as s,
};
// Keep the actual pipe owned here until the successful DNS exchange can
// explicitly CLOSE. Dropping the paired channel instead requests owner abort.
struct BorrowedPipe<'a>(&'a mut KernelPipe);
impl Pipe for BorrowedPipe<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        self.0.read(bytes)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        self.0.write(bytes)
    }
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }
}

fn finish_dns(pipe: &mut KernelPipe, peer: d::Address) -> Result<(), String> {
    let mut request = [0; 12];
    request[0] = s::VERSION;
    request[1] = s::CLOSE;
    request[4..8].copy_from_slice(&peer.ip);
    request[8..10].copy_from_slice(&peer.port.to_be_bytes());
    let mut reply = [0; d::MAX_MESSAGE];
    let n =
        transact(pipe, &request, &mut reply, 1000).map_err(|e| format!("DNS close channel {e}"))?;
    if n != 12 || reply[..12] != request {
        return Err("DNS close reply".into());
    }
    eprintln!("TCP DNS CLOSE status=0");
    Ok(())
}

fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let (input, output) = absd_runtime::standard_stream_handles();
    let mut boot = [0; 7];
    let mut at = 0;
    while at < boot.len() {
        let n = absd_runtime::read_within(input, &mut boot[at..], 1000)
            .map_err(|e| format!("bootstrap {e}"))?;
        if n == 0 {
            return Err("bootstrap EOF".into());
        }
        at += n;
    }
    if absd_runtime::nic::handle() != 0 || absd_runtime::nic::info(input).is_ok() {
        return Err("unexpected NIC authority".into());
    }
    let mode = boot[0];
    if mode == 10 {
        absd_runtime::write_within(output, &[0], 50).map_err(|e| format!("partial {e}"))?;
        absd_runtime::sleep_ticks(600);
        return Ok(());
    }
    let peer = d::Address {
        ip: boot[1..5].try_into().unwrap(),
        port: u16::from_be_bytes([boot[5], boot[6]]),
    };
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    let mut wrong = [0u8; 12];
    wrong[0] = 1;
    wrong[1] = s::CONNECT;
    wrong[4..8].copy_from_slice(&peer.ip);
    wrong[8..10].copy_from_slice(&peer.port.wrapping_add(1).to_be_bytes());
    let mut reply = [0; d::MAX_MESSAGE];
    transact(&mut pipe, &wrong, &mut reply, 1000).map_err(|e| format!("denial {e}"))?;
    if reply[2] != s::Error::Denied.code() {
        return Err("peer authority expanded".into());
    }
    if mode >= 4 && mode <= 9 {
        let mut resolver = dns::Resolver::with_entropy(
            dns::tcp::DatagramTcp::new(BorrowedPipe(&mut pipe), peer, absd_runtime::sleep_ticks),
            getrandom_0_2::getrandom,
        )
        .map_err(|error| format!("DNS entropy {error}"))?;
        let cases: &[(&str, Option<dns::Error>)] = match mode {
            4 => &[
                ("a.example", None),
                ("tc.example", None),
                ("tcpbig.example", None),
            ],
            5 => &[("tcshort.example", Some(dns::Error::Malformed))],
            6 => &[("tcoversize.example", Some(dns::Error::TooLarge))],
            7 => &[("tceof.example", Some(dns::Error::Stream(s::Error::Eof)))],
            8 => &[("tcmatch.example", None)],
            _ => &[("tcsilent.example", Some(dns::Error::Timeout))],
        };
        for (name, expected) in cases {
            let result = resolver.lookup(name);
            eprintln!("TCP DNS LOOKUP mode={mode} name={name} result={result:?}");
            match (result, *expected) {
                (Ok(answer), None)
                    if answer.count == 1 && answer.addresses[0] == [192, 0, 2, 9] => {}
                (Err(actual), Some(expected)) if actual == expected => {}
                _ => return Err(format!("DNS result {name}")),
            }
        }
        if mode == 9 && resolver.lookup("a.example") != Err(dns::Error::Transport(d::Error::Stale))
        {
            return Err("timeout resolver revived".into());
        }
        drop(resolver);
        if mode == 4 || mode == 8 {
            finish_dns(&mut pipe, peer)?;
        }
        return Ok(());
    }
    let mut client = s::Client::new(pipe, peer, absd_runtime::sleep_ticks);
    let deadline = absd_runtime::boot_millis() + 8000;
    if mode == 3 {
        let result = client.connect(deadline);
        eprintln!("TCP REFUSED result={result:?}");
        if result != Err(s::Error::Closed) {
            return Err("connect refusal".into());
        }
        return Ok(());
    }
    if mode == 2 {
        let result = client.connect(deadline).and_then(|_| {
            let mut b = [0; 1];
            loop {
                match client.read(&mut b, deadline) {
                    Err(s::Error::Again) => absd_runtime::sleep_ticks(5),
                    other => break other.map(|_| ()),
                }
            }
        });
        eprintln!("TCP RESET result={result:?}");
        if result != Err(s::Error::Closed) {
            return Err("reset outcome".into());
        }
        return Ok(());
    }
    client
        .connect(deadline)
        .map_err(|e| format!("connect {e:?}"))?;
    if mode == 11 {
        client
            .write_all(b"interrupted request", deadline)
            .map_err(|e| format!("write {e:?}"))?;
        absd_runtime::sleep_ticks(5000);
        return Err("kill did not arrive".into());
    }
    if mode == 1 {
        client
            .write_all(b"request", deadline)
            .map_err(|e| format!("write {e:?}"))?;
        client
            .shutdown_write(deadline)
            .map_err(|e| format!("half-close {e:?}"))?;
        if client.write(b"late", deadline) != Err(s::Error::WriteClosed) {
            return Err("write half revived".into());
        }
        let mut answer = [0; 9];
        client
            .read_exact(&mut answer, deadline)
            .map_err(|e| format!("after-fin {e:?}"))?;
        if &answer != b"after-fin" {
            return Err("after-fin bytes".into());
        }
    } else {
        for round in 0usize..32 {
            let data: Vec<u8> = (0usize..997)
                .map(|i| ((i + round * 997).wrapping_mul(131) ^ (i >> 7)) as u8)
                .collect();
            client
                .write_all(&data, deadline)
                .map_err(|e| format!("write {e:?}"))?;
            let mut got = vec![0; data.len()];
            client
                .read_exact(&mut got, deadline)
                .map_err(|e| format!("echo {e:?}"))?;
            if data != got {
                return Err("echo bytes".into());
            }
        }
        client
            .shutdown_write(deadline)
            .map_err(|e| format!("half-close {e:?}"))?;
    }
    let mut b = [0; 1];
    loop {
        match client.read(&mut b, deadline) {
            Err(s::Error::Again) => absd_runtime::sleep_ticks(5),
            Err(s::Error::Eof) => break,
            other => return Err(format!("EOF {other:?}")),
        }
    }
    client.close(deadline).map_err(|e| format!("close {e:?}"))?;
    if client.write(b"stale", deadline) != Err(s::Error::Stale) {
        return Err("closed client revived".into());
    }
    eprintln!("TCP CLIENT OK mode={mode}");
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("TCP CLIENT ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
