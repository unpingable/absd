//! Private paired-route startup v2; bytes describe the owner's existing grant.
#[path = "ipv6_route_fixture.rs"]
mod base;
pub use base::{
    BOOTSTRAP_LEN, Budget, Error, LOCAL, LOCAL_PORT, PEER, PORT, ROUTER, SCOPE, TOTAL_MS,
};
/// Private build selector, resolved before constructing the owner or its NIC.
/// This is configuration, not a received MTU or a new child grant field.
pub fn ip_mtu(value: Option<&str>) -> Result<usize, &'static str> {
    match value {
        None | Some("1500") => Ok(1500),
        Some("1280") => Ok(1280),
        _ => Err("route TCP IP MTU must be 1280 or 1500"),
    }
}
pub fn bootstrap(start: u64) -> Result<[u8; BOOTSTRAP_LEN], &'static str> {
    let mut b = base::bootstrap(start)?;
    b[..4].copy_from_slice(&[2, 6, 1, 0]);
    Ok(b)
}
pub fn decode(b: &[u8; BOOTSTRAP_LEN], start: u64, stop: u64) -> Result<(), &'static str> {
    if *b != bootstrap(start)? || u64::from_be_bytes(b[40..48].try_into().unwrap()) != stop {
        return Err("paired bootstrap policy/startup disagreement");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_mtu_selector_defaults_to_1500_and_refuses_other_values() {
        assert_eq!(ip_mtu(None), Ok(1500));
        assert_eq!(ip_mtu(Some("1500")), Ok(1500));
        assert_eq!(ip_mtu(Some("1280")), Ok(1280));
        for value in ["", "0", "1279", "1281", "1499", "1501", "1280 ", "01280"] {
            assert!(ip_mtu(Some(value)).is_err(), "{value}");
        }
    }
    #[test]
    fn literal_paired_bootstrap_binds_version_mode_peer_and_original_deadline() {
        let golden = [
            2, 6, 1, 0, 253, 0, 171, 93, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 1, 164, 26,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 47, 68,
        ];
        assert_eq!(bootstrap(100).unwrap(), golden);
        assert_eq!(decode(&golden, 100, 12100), Ok(()));
        for i in 0..BOOTSTRAP_LEN {
            let mut changed = golden;
            changed[i] ^= 1;
            assert!(decode(&changed, 100, 12100).is_err(), "{i}");
        }
        assert!(decode(&base::bootstrap(100).unwrap(), 100, 12100).is_err());
    }
    #[test]
    fn changed_start_stop_and_overflow_never_renew_paired_authority() {
        let b = bootstrap(100).unwrap();
        assert!(decode(&b, 101, 12101).is_err());
        assert!(decode(&b, 100, 12101).is_err());
        assert!(bootstrap(u64::MAX).is_err());
    }
}
