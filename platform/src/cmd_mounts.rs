#![allow(dead_code)]
//! Shared by the /bin commands that report where a path sits in this
//! process's file server binding (`stat`, `rm`, `mv`).

use absd_fsd::proto::Mount;

/// `path` made absolute against the working directory and normalized
/// lexically, as the runtime resolves it.
pub fn absolute(path: &str) -> Option<String> {
    let joined = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("{}/{path}", std::env::current_dir().ok()?.to_str()?)
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

/// The mount of this process's binding that holds `path`, if this process
/// reaches the filesystem through the file server and one does.
pub fn mount_of(path: &str) -> Option<Mount> {
    if !absd_runtime::fsd::active() {
        return None;
    }
    let absolute = absolute(path)?.into_bytes();
    absd_runtime::fsd::mounts()
        .ok()?
        .into_iter()
        .filter(|m| {
            absolute.starts_with(&m.path) && (absolute.len() == m.path.len() || absolute[m.path.len()] == b'/')
        })
        .max_by_key(|m| m.path.len())
}

/// Whether `path` is itself one of this binding's mount points (which the
/// file server refuses to remove or rename).
pub fn is_mount_point(path: &str) -> bool {
    let Some(absolute) = absolute(path) else { return false };
    mount_of(path).is_some_and(|m| m.path == absolute.as_bytes())
}

/// Whether a mount point of this binding lies strictly below `path`.
/// Removing the tree under such a path would empty the mount (it is
/// writable) before the file server refused to remove the mount point
/// itself, so `rm -r` refuses it up front. `None` when the answer is not
/// known: the file server serves this process but its mount list, or the
/// working directory, could not be read.
pub fn holds_mount(path: &str) -> Option<bool> {
    if !absd_runtime::fsd::active() {
        return Some(false);
    }
    let absolute = absolute(path)?;
    let prefix = if absolute == "/" { absolute } else { format!("{absolute}/") };
    let below = |m: &Mount| m.path.len() > prefix.len() && m.path.starts_with(prefix.as_bytes());
    Some(absd_runtime::fsd::mounts().ok()?.iter().any(below))
}
