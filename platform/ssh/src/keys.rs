//! Host key and authorized keys.
//!
//! The host key is an ed25519 seed (32 bytes) generated once from the
//! system entropy source (`getrandom`; on ABSD its RDRAND backend) and kept
//! in a file. It is replaced only when the operator asks for it explicitly.
//! Authorized keys are `ssh-ed25519` lines of an OpenSSH `authorized_keys`
//! file; options and other key types are refused, not ignored.

use std::fs;
use std::io;
use std::path::Path;

use base64::Engine;
use sha2::{Digest, Sha256};
use sunset::SignKey;
use sunset::ed25519_dalek::SigningKey;

pub const SEED_BYTES: usize = 32;

pub struct HostKey {
    pub key: SignKey,
    pub public: [u8; 32],
    pub generated: bool,
}

impl HostKey {
    /// The OpenSSH wire blob of the public key.
    pub fn blob(&self) -> Vec<u8> {
        public_blob(&self.public)
    }

    /// `ssh-ed25519 <base64>` as in a known_hosts line.
    pub fn openssh_public(&self) -> String {
        format!("ssh-ed25519 {}", base64::engine::general_purpose::STANDARD.encode(self.blob()))
    }

    /// `SHA256:<base64 without padding>` as `ssh-keygen -l` prints it.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.blob());
        format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest))
    }
}

pub fn public_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(51);
    for part in [&b"ssh-ed25519"[..], &public[..]] {
        blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
        blob.extend_from_slice(part);
    }
    blob
}

fn from_seed(seed: [u8; SEED_BYTES], generated: bool) -> HostKey {
    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key().to_bytes();
    HostKey { key: SignKey::Ed25519(signing), public, generated }
}

/// Loads the host key seed at `path`, or creates it when the file does not
/// exist (or when `regenerate` is set). A file of any other length is
/// refused, never overwritten.
///
/// A new seed is written to `<path>.new` (create-new), synced, and renamed
/// over `path` by `install`, then the directory is synced where the
/// platform can.
#[cfg_attr(target_os = "absd", allow(dead_code))]
pub fn load_or_create(
    path: &Path,
    regenerate: bool,
    install: impl Fn(&Path, &Path) -> io::Result<()>,
) -> io::Result<HostKey> {
    if !regenerate {
        match fs::read(path) {
            Ok(bytes) => {
                let seed: [u8; SEED_BYTES] = bytes.as_slice().try_into().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("host key {} is {} bytes, not {SEED_BYTES}", path.display(), bytes.len()),
                    )
                })?;
                return Ok(from_seed(seed, false));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let mut seed = [0u8; SEED_BYTES];
    getrandom::fill(&mut seed).map_err(|error| io::Error::other(format!("entropy: {error}")))?;
    let staging = path.with_extension("new");
    match fs::remove_file(&staging) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&staging)?;
    file.write_all(&seed)?;
    file.sync_all()?;
    drop(file);
    install(&staging, path)?;
    Ok(from_seed(seed, true))
}

/// Loads an existing host key seed (on ABSD the file server creates it;
/// sshd only reads it). A file of any other length is refused.
#[cfg_attr(unix, allow(dead_code))]
pub fn load(path: &Path) -> io::Result<HostKey> {
    let bytes = fs::read(path)?;
    let seed: [u8; SEED_BYTES] = bytes.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("host key {} is {} bytes, not {SEED_BYTES}", path.display(), bytes.len()),
        )
    })?;
    Ok(from_seed(seed, false))
}

/// The ed25519 public keys of an `authorized_keys` file. Blank lines and
/// `#` comments are skipped; any other line must be `ssh-ed25519 <base64>
/// [comment]`, or the whole file is refused.
pub fn load_authorized(path: &Path) -> io::Result<Vec<[u8; 32]>> {
    let text = fs::read_to_string(path)?;
    parse_authorized(&text).map_err(|message| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{}: {message}", path.display()))
    })
}

pub fn parse_authorized(text: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut keys = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let kind = words.next().unwrap_or_default();
        if kind != "ssh-ed25519" {
            return Err(format!("line {}: only plain ssh-ed25519 keys are accepted", number + 1));
        }
        let blob = words
            .next()
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .ok_or_else(|| format!("line {}: key is not base64", number + 1))?;
        if blob.len() != 51 || blob[..19] != public_blob(&[0; 32])[..19] {
            return Err(format!("line {}: not an ssh-ed25519 key blob", number + 1));
        }
        keys.push(blob[19..].try_into().unwrap());
    }
    if keys.is_empty() {
        return Err("no keys".into());
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_parse() {
        let key = [7u8; 32];
        let line = format!(
            "ssh-ed25519 {} op@host\n",
            base64::engine::general_purpose::STANDARD.encode(public_blob(&key))
        );
        assert_eq!(parse_authorized(&format!("# c\n\n{line}")).unwrap(), vec![key]);
        assert!(parse_authorized("").is_err());
        assert!(parse_authorized(&format!("command=\"x\" {line}")).is_err());
        assert!(parse_authorized("ssh-rsa AAAA x").is_err());
        assert!(parse_authorized("ssh-ed25519 AAAA x").is_err());
    }
}
