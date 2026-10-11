// ABSD: named temporary files over the ABSD filesystem. Creation is
// exclusive (`create_new`); no-clobber persistence is the filesystem's
// atomic `rename_noreplace`; identity is the filesystem object serial.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::absd::fs::{MetadataExt, rename_noreplace};
use std::path::Path;

use crate::util;

pub fn create_named(
    path: &Path,
    open_options: &mut OpenOptions,
    permissions: Option<&std::fs::Permissions>,
) -> io::Result<File> {
    let file = open_options.read(true).write(true).create_new(true).open(path)?;
    if let Some(permissions) = permissions {
        file.set_permissions(permissions.clone())?;
    }
    Ok(file)
}

pub fn create(dir: &Path) -> io::Result<File> {
    util::create_helper(dir, OsStr::new(".tmp"), OsStr::new(""), crate::NUM_RAND_CHARS, |path| {
        let file = create_named(&path, &mut OpenOptions::new(), None)?;
        // An unlinked open object lives until its last handle closes.
        let _ = fs::remove_file(&path);
        Ok(file)
    })
}

pub fn reopen(file: &File, path: &Path) -> io::Result<File> {
    let new_file = OpenOptions::new().read(true).write(true).open(path)?;
    let (old, new) = (file.metadata()?, new_file.metadata()?);
    if old.filesystem_id() != new.filesystem_id() || old.object_serial() != new.object_serial() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "original tempfile has been replaced"));
    }
    Ok(new_file)
}

pub fn persist(old_path: &Path, new_path: &Path, overwrite: bool) -> io::Result<()> {
    if overwrite { fs::rename(old_path, new_path) } else { rename_noreplace(old_path, new_path) }
}

pub fn keep(_: &Path) -> io::Result<()> {
    Ok(())
}
