//! Shared bounded acquisition used by the native command and host path cases.
use absd_fsd::net_status::{self as sample, Record, View};
use absd_fsd::recovery;
use std::io::{self, Read};

pub struct Retained {
    pub record: Record,
    pub age: u64,
}

fn bounded(path: &std::path::Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized observation",
        ));
    }
    Ok(bytes)
}

fn current_recovery(directory: &std::path::Path, boot: &[u8; 32]) -> Result<u64, &'static str> {
    let name = std::path::Path::new(recovery::PROJECTION)
        .file_name()
        .expect("fixed recovery filename");
    let bytes = bounded(&directory.join(name), recovery::LEDGER_BYTES)
        .map_err(|_| "recovery_unavailable")?;
    if bytes.len() != recovery::LEDGER_BYTES {
        return Err("recovery_malformed");
    }
    let ledger = recovery::parse_ledger(&bytes)
        .filter(|ledger| ledger.seq != 0)
        .ok_or("recovery_malformed")?;
    if &ledger.boot != boot {
        return Err("recovery_wrong_boot");
    }
    Ok(ledger.seq)
}

pub fn acquire(
    directory: &std::path::Path,
    boot: &[u8; 32],
    start: u64,
    end: impl FnOnce() -> u64,
) -> Result<Retained, &'static str> {
    let before = current_recovery(directory, boot)?;
    let bytes = bounded(
        &directory.join(
            std::path::Path::new(sample::PATH)
                .file_name()
                .expect("fixed sample filename"),
        ),
        sample::BYTES,
    )
    .map_err(|_| "sample_unavailable")?;
    let record = Record::parse(&bytes).ok_or("sample_malformed")?;
    let after = current_recovery(directory, boot)?;
    if before != after {
        return Err("recovery_changed_during_acquisition");
    }
    let age = match record.bind(Some(boot), Some(after), start, end()) {
        View::Retained { age } => age,
        View::Stale => return Err("stale"),
        View::WrongBoot => return Err("wrong_boot"),
        View::MalformedInterval => return Err("invalid_interval"),
        _ => return Err("binding_unavailable"),
    };
    Ok(Retained { record, age })
}
