//! Static login art, with the served release identity supplied by the backend.

use crate::conn::Command;

const ART: &str = include_str!("../motd.txt");

/// Only an interactive shell gets a banner. An exec remains quiet even if
/// it has a PTY or happens to run a shell. A backend without an installed
/// ABSD release (the Linux reference server) supplies no identity or banner.
pub fn for_session(command: &Command, terminal: bool, release: Option<&str>) -> Vec<u8> {
    match (command, terminal, release) {
        (Command::Shell, true, Some(release)) => {
            format!("{ART}Release: {release}\nAuthority is not ambient.\n\n").into_bytes()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactive_banner_names_the_supplied_release() {
        assert!(ART.is_ascii());
        assert!(ART.ends_with('\n'));
        // The release grammar permits at most 64 bytes, including in a
        // development build. No branch or host status is inferred here.
        for release in ["dev", "2026.10.18-rc1", &"a".repeat(64)] {
            let banner = for_session(&Command::Shell, true, Some(release));
            assert!(banner.starts_with(ART.as_bytes()));
            let suffix = format!("Release: {release}\nAuthority is not ambient.\n\n");
            assert!(banner.ends_with(suffix.as_bytes()));
            assert!(banner.len() < 512);
        }
    }

    #[test]
    fn command_and_nonterminal_sessions_add_no_bytes() {
        for terminal in [false, true] {
            for text in ["echo exact", "cat > file", "/bin/absd-sh", "shutdown", ""] {
                assert!(for_session(&Command::Exec(text.into()), terminal, Some("dev")).is_empty());
            }
        }
        assert!(for_session(&Command::Shell, false, Some("dev")).is_empty());
        assert!(for_session(&Command::Shell, true, None).is_empty());
    }
}
