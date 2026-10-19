//! Fixed health projection. No runtime calls or filesystem I/O here: collection
//! owns its existing rights, while this module preserves explicit source errors.
use absd_fsd::{log, version::Refusal};
use serde_json::{Value, json};
use std::io::ErrorKind;

pub const SCHEMA: &str = "absd.observation_health.v1";
pub const MAX_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Issue {
    pub availability: &'static str,
    pub reason: &'static str,
}
impl Issue {
    pub const fn unavailable(reason: &'static str) -> Self {
        Self {
            availability: "unavailable",
            reason,
        }
    }
    pub const fn malformed(reason: &'static str) -> Self {
        Self {
            availability: "malformed",
            reason,
        }
    }
}

pub fn version_issue(refusal: Refusal) -> Issue {
    match refusal {
        Refusal::NoAnswer => Issue::unavailable("no_answer"),
        Refusal::NoServer(-13 | -1) | Refusal::Refused(-13 | -1) => Issue {
            availability: "denied",
            reason: "fsd_refused",
        },
        Refusal::Refused(-95) => Issue {
            availability: "unsupported",
            reason: "unsupported",
        },
        Refusal::NoServer(_) => Issue::unavailable("io_error"),
        Refusal::Refused(_) => Issue::unavailable("fsd_refused"),
        Refusal::Malformed => Issue::malformed("malformed"),
        Refusal::Protocol { .. } => Issue::malformed("protocol_mismatch"),
        Refusal::Release { .. } => Issue::malformed("release_mismatch"),
    }
}

fn read_issue(kind: ErrorKind) -> Issue {
    match kind {
        ErrorKind::NotFound => Issue::unavailable("recovery_not_retained"),
        ErrorKind::PermissionDenied => Issue {
            availability: "denied",
            reason: "fsd_refused",
        },
        _ => Issue::unavailable("io_error"),
    }
}

pub fn recovery(
    boot: &str,
    current: Result<Vec<u8>, ErrorKind>,
    rotated: Result<Vec<u8>, ErrorKind>,
) -> Result<log::Generation, Issue> {
    let current = current.map_err(read_issue)?;
    let rotated = match rotated {
        Ok(bytes) => bytes,
        Err(ErrorKind::NotFound) => Vec::new(),
        Err(kind) => return Err(read_issue(kind)),
    };
    log::generation(&rotated, &current, boot).map_err(|why| match why {
        log::Unknown::NoBootLine | log::Unknown::NoRecoveryLine => {
            Issue::unavailable("recovery_not_retained")
        }
        log::Unknown::Malformed => Issue::malformed("recovery_malformed"),
    })
}

pub struct Sample {
    pub start: u64,
    pub end: u64,
    pub ticks: u64,
    pub pid: Option<u32>,
    pub boot: Result<[u8; 16], i64>,
    pub release: Result<Vec<u8>, Issue>,
    pub recovery: Result<log::Generation, Issue>,
}

fn fact(
    id: &str,
    owner: &str,
    subject: &str,
    source: &str,
    result: Result<Value, Issue>,
    lifetime: Option<String>,
    historical: bool,
) -> Value {
    let (availability, value, reason, freshness, lifetime) = match result {
        Ok(value) => (
            "known",
            value,
            None,
            if historical {
                "record_for_current_boot"
            } else {
                "sampled_during_interval"
            },
            lifetime,
        ),
        Err(issue) => (
            issue.availability,
            Value::Null,
            Some(issue.reason),
            "unknown",
            None,
        ),
    };
    json!({"id":id,"owner":owner,"subject":subject,"source":source,
        "availability":availability,"value":value,"reason":reason,
        "loss":if historical {"unknown"} else {"not_applicable"},
        "lifetime_ref":lifetime,"implementation_ref":null,"freshness":freshness})
}

/// A refused acquisition interval yields no document, never a fabricated order.
/// Returned status is exclusively about the fixed four facts.
pub fn render(sample: Sample) -> Result<(String, i32), &'static str> {
    if !(sample.start <= sample.ticks && sample.ticks <= sample.end) {
        return Err("invalid acquisition interval");
    }
    let boot = sample
        .boot
        .ok()
        .map(|id| id.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let boot_lifetime = boot.as_ref().map(|id| format!("boot:{id}"));
    let boot_value = boot
        .as_ref()
        .map(|id| json!(id))
        .ok_or(Issue::unavailable("boot_id_refused"));
    let release = sample.release.and_then(|bytes| {
        if !absd_release::valid_id(&bytes) {
            return Err(Issue::malformed("field_out_of_bounds"));
        }
        String::from_utf8(bytes)
            .map(|s| json!(s))
            .map_err(|_| Issue::malformed("field_out_of_bounds"))
    });
    let (recovery_value, recovery_lifetime) = match &boot {
        None => (Err(Issue::unavailable("boot_id_unavailable")), None),
        Some(id) => match sample.recovery {
            Ok(g) if ["none", "ended", "failed", "not_ready"].contains(&g.previous) => {
                let lifetime = Some(format!("boot:{id}/recovery:{}", g.seq));
                (
                    Ok(
                        json!({"boot_id":id,"seq":g.seq.to_string(),"streak":g.streak.to_string(),"previous":g.previous}),
                    ),
                    lifetime,
                )
            }
            Ok(_) => (Err(Issue::malformed("recovery_malformed")), None),
            Err(issue) => (Err(issue), None),
        },
    };
    let facts = vec![
        fact(
            "boot.id",
            "kernel",
            "boot",
            "kernel_boot_id",
            boot_value,
            boot_lifetime.clone(),
            false,
        ),
        fact(
            "boot.ticks",
            "kernel",
            "boot",
            "kernel_ticks",
            Ok(json!(sample.ticks.to_string())),
            boot_lifetime,
            false,
        ),
        fact(
            "fsd.release",
            "fsd",
            "held-fsd",
            "fsd_version",
            release,
            None,
            false,
        ),
        fact(
            "fsd.recovery",
            "fsd",
            "held-fsd",
            "fsd_log_current_and_rotated",
            recovery_value,
            recovery_lifetime,
            true,
        ),
    ];
    let complete = facts.iter().all(|f| f["availability"] == "known");
    let mut doc = json!({"schema":SCHEMA,"scope":"health","status":if complete {"complete"} else {"partial"},
        "boot_id":boot,"interval":{"clock":"kernel_ticks","start":sample.start.to_string(),"end":sample.end.to_string()},
        "producer":{"role":"health","pid":sample.pid.map(|pid|pid.to_string()),"implementation_ref":null},"facts":facts});
    // Explicit even if a future workspace enables serde_json preserve_order.
    doc.sort_all_objects();
    let text = serde_json::to_string(&doc).map_err(|_| "JSON rendering failed")?;
    // Include the command's terminating newline in the wire bound.
    if text.len() + 1 > MAX_BYTES {
        return Err("health document exceeds bound");
    }
    Ok((text, if complete { 0 } else { 1 }))
}
