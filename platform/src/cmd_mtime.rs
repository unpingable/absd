//! Native command presentation of the filesystem's modification time.
use std::io::{self, ErrorKind};
use std::time::UNIX_EPOCH;

pub fn display(meta: &std::fs::Metadata, detailed: bool) -> io::Result<String> {
    let time = match meta.modified() {
        Ok(time) => time,
        Err(error) if error.kind() == ErrorKind::Unsupported => {
            return Ok(if detailed { "unknown" } else { "-" }.to_owned());
        }
        Err(error) => return Err(error),
    };
    let seconds = time.duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "modification time precedes Unix epoch"))?.as_secs();
    Ok(if detailed {
        absd_fsd::civil::Utc::from_unix(seconds).iso().to_string()
    } else {
        absd_fsd::civil::mtime_column(seconds)
    })
}
