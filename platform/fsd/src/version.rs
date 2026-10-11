//! The client's side of `op::VERSION` (`docs/RELEASE.md` section 3, item
//! 5): what the reply says and whether this build may talk to the server
//! that sent it. The runtime asks once per process, on its own channel,
//! before `main`, and refuses the process (status 104) with
//! [`Refusal::line`] on the console; sshd asks the same on its control
//! channel and also requires the server's release to be its own.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::Reader;

/// How long a client waits for the answer, in ticks (about 5 s). A server
/// that cannot parse the frame never answers, so only that case waits the
/// whole bound; a busy server of this protocol answers well within it.
pub const ANSWER_TICKS: u64 = 5000;
/// Exit status of a process refused here.
pub const REFUSED_STATUS: i32 = 104;
/// The kernel's timeout code: what a bounded wait that ran out returns.
pub const TIMEOUT: i64 = -110;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub fsd_protocol: u32,
    pub fs_format: u32,
    pub release: Vec<u8>,
}

/// The reply payload, or `None` unless it is exactly the three fields and
/// the id follows the release id grammar.
pub fn decode(payload: &[u8]) -> Option<Version> {
    let mut reader = Reader(payload);
    let fsd_protocol = reader.u32()?;
    let fs_format = reader.u32()?;
    let length = reader.u16()? as usize;
    let release = reader.take(length)?.to_vec();
    if !reader.0.is_empty() || !absd_release::valid_id(&release) {
        return None;
    }
    Some(Version { fsd_protocol, fs_format, release })
}

/// The payload this build's server answers with.
pub fn encode(version: &Version) -> Vec<u8> {
    let mut payload = Vec::with_capacity(10 + version.release.len());
    payload.extend_from_slice(&version.fsd_protocol.to_le_bytes());
    payload.extend_from_slice(&version.fs_format.to_le_bytes());
    payload.extend_from_slice(&(version.release.len() as u16).to_le_bytes());
    payload.extend_from_slice(&version.release);
    payload
}

/// This build's identity as a VERSION answer.
pub fn compiled() -> Version {
    Version {
        fsd_protocol: absd_release::FSD_PROTOCOL,
        fs_format: absd_release::FS_FORMAT,
        release: absd_release::RELEASE_ID.as_bytes().to_vec(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No reply within [`ANSWER_TICKS`] (the kernel's `-110`).
    NoAnswer,
    /// The channel failed: the server is gone, or the request could not be
    /// written.
    NoServer(i64),
    /// The server refused the request (`-95` from a server without the op).
    Refused(i64),
    /// A reply that is not a VERSION answer.
    Malformed,
    Protocol { server: u32 },
    Release { server: Vec<u8> },
}

impl Refusal {
    /// The console line (no newline).
    pub fn line(&self) -> String {
        match self {
            Refusal::NoAnswer => "FSD PROTOCOL REFUSED reason=no_answer".into(),
            Refusal::NoServer(code) => format!("FSD PROTOCOL REFUSED reason=no_server status={code}"),
            Refusal::Refused(code) => format!("FSD PROTOCOL REFUSED reason=refused status={code}"),
            Refusal::Malformed => "FSD PROTOCOL REFUSED reason=malformed_answer".into(),
            Refusal::Protocol { server } => format!(
                "FSD PROTOCOL REFUSED server={server} required={}",
                absd_release::FSD_PROTOCOL
            ),
            Refusal::Release { server } => format!(
                "FSD PROTOCOL REFUSED server_release={} required_release={}",
                String::from_utf8_lossy(server),
                absd_release::RELEASE_ID
            ),
        }
    }
}

/// Judges one exchange's outcome: `Ok((status, payload))` as the reply
/// came, `Err(code)` when none came (`-110` for the timeout). The
/// protocol must equal this build's; with `require_release` (sshd) the
/// release must too.
pub fn check(answer: Result<(i64, Vec<u8>), i64>, require_release: bool) -> Result<Version, Refusal> {
    let (status, payload) = match answer {
        Ok(reply) => reply,
        Err(TIMEOUT) => return Err(Refusal::NoAnswer),
        Err(code) => return Err(Refusal::NoServer(code)),
    };
    if status < 0 {
        return Err(Refusal::Refused(status));
    }
    let version = decode(&payload).ok_or(Refusal::Malformed)?;
    if version.fsd_protocol != absd_release::FSD_PROTOCOL {
        return Err(Refusal::Protocol { server: version.fsd_protocol });
    }
    if require_release && version.release != absd_release::RELEASE_ID.as_bytes() {
        return Err(Refusal::Release { server: version.release });
    }
    Ok(version)
}
