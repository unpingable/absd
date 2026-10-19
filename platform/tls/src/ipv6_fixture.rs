//! Compile-selected addresses for the private IPv6 HTTPS fixture.
//! These describe construction by the NIC owner; they grant no authority.
use absd_net::ipv6::Address;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub local: [u8; 16],
    pub peer: Address,
    pub router: Option<[u8; 16]>,
}

pub const ON_LINK: Profile = Profile {
    local: [0xfd, 0, 0xab, 0x5d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x15],
    peer: Address {
        ip: [0xfd, 0, 0xab, 0x5d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        scope: 1,
        port: 4443,
    },
    router: None,
};

pub const ROUTED: Profile = Profile {
    local: [0xfd, 0, 0xab, 0x5d, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x15],
    peer: Address {
        ip: [0xfd, 0, 0xab, 0x5d, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
        scope: 1,
        port: 4443,
    },
    router: Some([0xfd, 0, 0xab, 0x5d, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
};

pub fn named(name: &str) -> Result<Profile, &'static str> {
    match name {
        "on-link" => Ok(ON_LINK),
        "routed" => Ok(ROUTED),
        _ => Err("unknown private IPv6 HTTPS profile"),
    }
}

pub fn selected() -> Result<Profile, &'static str> {
    named(option_env!("ABSD_TLS_IPV6_PROFILE").unwrap_or("on-link"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_profiles_keep_peer_scope_port_and_distinct_local_prefixes() {
        assert_eq!(named("on-link"), Ok(ON_LINK));
        assert_eq!(named("routed"), Ok(ROUTED));
        assert_eq!((ROUTED.peer.scope, ROUTED.peer.port), (1, 4443));
        assert_eq!(ROUTED.local[..8], ROUTED.router.unwrap()[..8]);
        assert_ne!(ROUTED.local[..8], ROUTED.peer.ip[..8]);
        assert_eq!(ON_LINK.local[..8], ON_LINK.peer.ip[..8]);
        assert_eq!(ON_LINK.router, None);
    }

    #[test]
    fn an_unknown_profile_never_selects_a_route_or_default() {
        for name in ["", "default", "Routed", "routed ", "fd00:ab5d:2::9"] {
            assert!(named(name).is_err());
        }
    }
}
