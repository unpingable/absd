//! Which release the file server serves (`docs/RELEASE.md` sections 2 and
//! 3): the selection `/absd/selected` names one tree under `/releases/`,
//! whose record must state exactly this build's identity. The server then
//! binds `/bin` and `/share` to that tree (`Server::bind_release`).

use alloc::vec::Vec;

use absd_fs::{Device, Error, Fs, OpenFlags};
use absd_release::{Record, Refusal};

/// The selection file: one release id and at most one newline.
pub const SELECTED: &[u8] = b"/absd/selected";
/// The directory holding the selection. No channel ever sees or reaches
/// it: only an importer boot changes which release is selected.
pub const SELECTION: &[u8] = b"/absd";
/// Where release trees live. No channel ever sees or reaches it.
pub const RELEASES: &[u8] = b"/releases";
/// The roots no channel sees, reaches, or binds: [`RELEASES`] and
/// [`SELECTION`].
pub const HIDDEN: [&[u8]; 2] = [RELEASES, SELECTION];

/// `path` is one of the [`HIDDEN`] roots or below one.
pub fn hidden(path: &[u8]) -> bool {
    HIDDEN.iter().any(|root| crate::proto::within(path, root))
}
/// Logical roots served from the selected tree.
pub const BOUND: [&[u8]; 2] = [b"/bin", b"/share"];
/// Largest selection or record file read; longer is malformed.
const MAX_FILE: u64 = 1024;

/// The whole file at `path`, at most [`MAX_FILE`] bytes: `Ok(None)` when it
/// does not exist, `Err(())` when it is not a readable file of that size.
fn small_file<D: Device>(fs: &mut Fs<D>, path: &[u8]) -> Result<Option<Vec<u8>>, ()> {
    let attr = match fs.stat(path) {
        Ok(attr) => attr,
        Err(Error::NotFound) => return Ok(None),
        Err(_) => return Err(()),
    };
    if attr.kind != absd_fs::Kind::File || attr.size > MAX_FILE {
        return Err(());
    }
    let flags = OpenFlags { read: true, write: false, create: false, create_new: false, truncate: false };
    let handle = fs.open(path, flags).map_err(|_| ())?;
    let mut bytes = alloc::vec![0u8; attr.size as usize];
    let mut filled = 0;
    let outcome = loop {
        if filled == bytes.len() {
            break Ok(());
        }
        match fs.read_at(handle, filled as u64, &mut bytes[filled..]) {
            Ok(0) | Err(_) => break Err(()),
            Ok(count) => filled += count,
        }
    };
    let _ = fs.close(handle);
    outcome.map(|()| Some(bytes))
}

/// `/releases/<id>/<below>`.
pub fn tree_path(id: &[u8], below: &[u8]) -> Vec<u8> {
    let mut path = RELEASES.to_vec();
    path.push(b'/');
    path.extend_from_slice(id);
    path.extend_from_slice(below);
    path
}

/// Reads the selection and the selected record and checks the record
/// against `mine`; the selected id when every field matches. A selection
/// or record that exists but cannot be read whole is reported as
/// malformed (the reasons are a closed list).
pub fn select<D: Device>(fs: &mut Fs<D>, mine: &Record) -> Result<Vec<u8>, Refusal> {
    let selected = small_file(fs, SELECTED)
        .map_err(|()| Refusal::MalformedSelected)?
        .ok_or(Refusal::NoSelectedRelease)?;
    let id = absd_release::parse_selected(&selected)?.to_vec();
    let record = small_file(fs, &tree_path(&id, b"/release"))
        .map_err(|()| Refusal::MalformedRecord)?
        .ok_or(Refusal::NoReleaseTree)?;
    absd_release::verify(&record, mine)?;
    Ok(id)
}
