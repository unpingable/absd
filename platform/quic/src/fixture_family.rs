//! Explicit family selection for the private native consumer, never a grant.
use absd_net::{datagram as d, ipv6 as v6};

pub const IPV6_LOCAL: [u8; 16] = [0xfd, 0, 0xab, 0x5d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x15];
pub const IPV6_PEER: v6::Address = v6::Address {
    ip: [0xfd, 0, 0xab, 0x5d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
    scope: 1,
    port: 4443,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Ipv4,
    Ipv6,
}
impl Family {
    pub fn parse(value: Option<&str>) -> Result<Self, &'static str> {
        match value {
            None | Some("ipv4") => Ok(Self::Ipv4),
            Some("ipv6") => Ok(Self::Ipv6),
            _ => Err("unknown explicit QUIC family"),
        }
    }
    pub fn selected() -> Result<Self, &'static str> {
        Self::parse(option_env!("ABSD_QUIC_FAMILY"))
    }
    pub fn check_case(self, case: &str) -> Result<(), &'static str> {
        if self == Self::Ipv6 && !matches!(case, "Q01" | "Q08" | "Q17") {
            Err("unreviewed private IPv6 consumer case")
        } else {
            Ok(())
        }
    }
    pub fn header(self) -> usize {
        match self {
            Self::Ipv4 => 12,
            Self::Ipv6 => v6::session::HEADER,
        }
    }
    pub fn version(self) -> u8 {
        match self {
            Self::Ipv4 => d::VERSION,
            Self::Ipv6 => v6::session::VERSION,
        }
    }
    pub fn wire_family(self) -> u8 {
        match self {
            Self::Ipv4 => 0,
            Self::Ipv6 => v6::session::FAMILY,
        }
    }
    pub fn length(self, body: &[u8]) -> Option<usize> {
        let at = self.header().checked_sub(2)?;
        Some(u16::from_be_bytes(body.get(at..at + 2)?.try_into().ok()?) as usize)
    }
    pub fn peer_text(self, body: &[u8]) -> Option<(String, u32, u16)> {
        match self {
            Self::Ipv4 => Some((
                std::net::Ipv4Addr::from(<[u8; 4]>::try_from(body.get(4..8)?).ok()?).to_string(),
                0,
                u16::from_be_bytes(body.get(8..10)?.try_into().ok()?),
            )),
            Self::Ipv6 => Some((
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(body.get(4..20)?).ok()?).to_string(),
                u32::from_be_bytes(body.get(20..24)?.try_into().ok()?),
                u16::from_be_bytes(body.get(24..26)?.try_into().ok()?),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_is_ipv4_and_ipv6_is_explicit_without_other_spellings() {
        assert_eq!(Family::parse(None), Ok(Family::Ipv4));
        assert_eq!(Family::parse(Some("ipv4")), Ok(Family::Ipv4));
        assert_eq!(Family::parse(Some("ipv6")), Ok(Family::Ipv6));
        for value in ["", "6", "IPv6", "auto", "ipv6,ipv4"] {
            assert!(Family::parse(Some(value)).is_err());
        }
        for case in ["Q01", "Q08", "Q17"] {
            assert!(Family::Ipv6.check_case(case).is_ok());
        }
        for case in ["Q03", "Q09", "Q19", "Q31", ""] {
            assert!(Family::Ipv6.check_case(case).is_err());
        }
    }
    #[test]
    fn literal_v2_observation_keeps_scope_and_full_peer() {
        let mut header = vec![2, 2, 0, 6];
        header.extend_from_slice(&IPV6_PEER.ip);
        header.extend_from_slice(&1u32.to_be_bytes());
        header.extend_from_slice(&4443u16.to_be_bytes());
        header.extend_from_slice(&1200u16.to_be_bytes());
        assert_eq!(Family::Ipv6.length(&header), Some(1200));
        assert_eq!(
            Family::Ipv6.peer_text(&header),
            Some(("fd00:ab5d::2".into(), 1, 4443))
        );
        for end in 0..26 {
            assert!(Family::Ipv6.peer_text(&header[..end]).is_none());
        }
    }
}
